/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Olivier Cochard <olivier@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * cbmc(1) harness for ip_fragment(), sys/netinet/ip_output.c: split an IPv4
 * packet too large for the outgoing MTU into fragments.  The fragments must
 * tile the original payload exactly: contiguous 8-aligned offsets covering
 * [hlen, ip_len), each payload at most the MTU payload size, every fragment
 * but the last carrying the More-Fragments bit.  A wrong offset or length,
 * or a missed/extra MF bit, corrupts the datagram at the receiver.
 *
 * Not a program: run.sh compiles it with SOURCE naming ip_output.c or a
 * mutant of it, included whole.  The fragments it builds are collected off
 * the original's m_nextpkt chain and their (ip_off, ip_len) checked.  The
 * per-fragment mbuf helpers (m_gethdr via the UMA model, m_dup_pkthdr,
 * m_copym, in_cksum, ip_optcopy) are modelled; the packet carries no header
 * options (hlen = 20) and no delayed checksum.  ip_len and mtu are constants
 * per job (a symbolic length makes the fragment loop unbounded); the jobs
 * sweep an exact multiple, a remainder, and a single fragment.
 *
 * The entry point, for --function:
 *
 *   proof_fragment	ip_fragment() of an IPLEN-byte packet at MTU: the
 *			first fragment plus the chained ones tile [hlen, ip_len)
 *			with 8-aligned contiguous offsets, each payload <= the
 *			MTU payload, and the MF bit set on all but the last.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* The payload mbuf m_copym() hands back for each fragment (contents unused). */
static struct mbuf g_payload;
struct mbuf *
cbmc_m_copym(struct mbuf *m, int off0, int len, int wait)
{
	return (&g_payload);		/* non-NULL: copy succeeds */
}
int cbmc_m_dup_pkthdr(struct mbuf *to, const struct mbuf *from, int how)
{
	return (1);
}
int ip_optcopy(struct ip *ip, struct ip *jp) { return (0); }	/* no options */
int cbmc_in_cksum(struct mbuf *m, int len) { return (0); }
void m_freem(struct mbuf *m) { }
int m_pkthdr_init(struct mbuf *m, int how) { return (0); }

/* Largest link-level header; a small constant leaves room for the IP header
 * in the fragment mbuf's MHLEN data area. */
u_int max_linkhdr = 16;
void
m_adj(struct mbuf *mp, int req_len)
{
	if (mp != NULL)
		mp->m_len += req_len;	/* req_len is negative here (trim) */
}

#ifndef IPLEN
#define	IPLEN	100		/* total IP packet length */
#endif
#ifndef MTU
#define	MTU	48		/* outgoing MTU (payload = (MTU-20)&~7) */
#endif

static struct mbuf g_m0;
static union {
	struct ip ip;
	char b[1500];
} g_pkt;

void
proof_fragment(void)
{
	struct mbuf *fp, *mfrag;
	int error, hlen, payload, off, prev_end, nseen;

	hlen = sizeof(struct ip);
	bzero(&g_pkt, sizeof(g_pkt));
	g_pkt.ip.ip_v = IPVERSION;
	g_pkt.ip.ip_hl = hlen >> 2;		/* 20, no options */
	g_pkt.ip.ip_len = htons((u_short)IPLEN);
	g_pkt.ip.ip_off = 0;			/* no DF */

	bzero(&g_m0, sizeof(g_m0));
	g_m0.m_data = (caddr_t)&g_pkt;
	g_m0.m_len = IPLEN;
	g_m0.m_flags = M_PKTHDR;
	g_m0.m_pkthdr.len = IPLEN;
	g_m0.m_pkthdr.csum_flags = 0;		/* no delayed checksum */
	g_m0.m_next = NULL;
	g_m0.m_nextpkt = NULL;
	bzero(&g_payload, sizeof(g_payload));

	mfrag = &g_m0;
	error = ip_fragment(&g_pkt.ip, &mfrag, MTU, 0);
	(void)error;

	payload = (MTU - hlen) & ~7;
	/*
	 * Walk the fragment chain (the first fragment is m0 itself, the rest
	 * hang off m_nextpkt) and check the tiling.  Offsets are in 8-byte
	 * units in ip_off (network order); convert back.
	 */
	/* First fragment: m0, payload = firstlen = its trimmed length - hlen. */
	prev_end = 0;
	nseen = 0;
	for (fp = &g_m0; fp != NULL && nseen < 16; fp = fp->m_nextpkt, nseen++) {
		struct ip *fip = mtod(fp, struct ip *);
		int foff = (ntohs(fip->ip_off) & IP_OFFMASK) << 3;
		int flen = ntohs(fip->ip_len) - (fip->ip_hl << 2);
		int mf = (ntohs(fip->ip_off) & IP_MF) != 0;

		__CPROVER_assert(foff == prev_end,
		    "fragment offsets are contiguous");
		__CPROVER_assert((foff & 7) == 0,
		    "fragment offsets are 8-byte aligned");
		__CPROVER_assert(flen <= payload,
		    "each fragment payload is within the MTU payload");
		off = foff + flen;
		if (off < IPLEN - hlen)
			__CPROVER_assert(mf,
			    "a non-final fragment has the More-Fragments bit");
		prev_end = off;
	}
	__CPROVER_assert(prev_end == IPLEN - hlen,
	    "the fragments cover the whole payload");
}
