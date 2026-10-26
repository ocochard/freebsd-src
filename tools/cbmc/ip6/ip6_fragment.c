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
 * cbmc(1) harness for ip6_fragment(), sys/netinet6/ip6_output.c: split an
 * IPv6 packet into fragments of a given fragment length.  The fragments must
 * tile the payload exactly: contiguous 8-aligned offsets covering [hlen,
 * tlen), each of the given fraglen, every fragment but the last carrying the
 * More-Fragments bit.  The IPv6 counterpart of ip_fragment().
 *
 * Not a program: run.sh compiles it with SOURCE naming ip6_output.c or a
 * mutant of it, included whole.  The fragments it builds are collected off
 * the original's m_nextpkt chain and their fragment-header (ip6f_offlg) and
 * payload length checked.  The per-fragment helpers (m_gethdr via the UMA
 * model, m_dup_pkthdr, ip6_insertfraghdr, m_copym, m_cat) are modelled; the
 * fragment header is placed in a harness buffer so the offlg writes are
 * bounds-checked.  tlen and fraglen are constants per job (a symbolic length
 * makes the loop unbounded); the jobs sweep an exact multiple and a
 * remainder.
 *
 * The entry point, for --function:
 *
 *   proof_ip6_fragment	ip6_fragment() of a TLEN-byte packet at FRAGLEN: the
 *			fragments tile [hlen, tlen) with 8-aligned contiguous
 *			offsets, each payload <= fraglen, MF set on all but the
 *			last, together covering the whole payload.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#define	NFRAG	16

/*
 * The real (static) ip6_insertfraghdr() runs: with hlen == sizeof(ip6_hdr)
 * it places the ip6_frag header in the fragment mbuf's trailing space, right
 * after the copied IPv6 header (m_len == sizeof(ip6_hdr)).  The proof reads
 * each fragment's header from there.  (It is static, so --replace-calls
 * cannot redirect it; letting it run keeps the proof on the real code.)
 */
static struct mbuf g_part;
struct mbuf *
cbmc_m_copym(struct mbuf *m, int off0, int len, int wait)
{
	return (&g_part);
}
int cbmc_m_dup_pkthdr(struct mbuf *to, const struct mbuf *from, int how)
{
	return (1);
}
void cbmc_m_cat(struct mbuf *m, struct mbuf *n) { }
void m_freem(struct mbuf *m) { }
int m_pkthdr_init(struct mbuf *m, int how) { return (0); }

u_int max_linkhdr = 16;

#ifndef TLEN
#define	TLEN	160		/* total packet length */
#endif
#ifndef FRAGLEN
#define	FRAGLEN	24		/* payload per fragment (multiple of 8) */
#endif

static struct mbuf g_m0;
static union {
	struct ip6_hdr ip6;
	char b[1500];
} g_pkt;

void
proof_ip6_fragment(void)
{
	struct mbuf *fp;
	int error, hlen, prev_end, nseen;

	hlen = sizeof(struct ip6_hdr);		/* 40, no extension headers */
	bzero(&g_pkt, sizeof(g_pkt));
	bzero(&g_m0, sizeof(g_m0));
	g_m0.m_data = (caddr_t)&g_pkt;
	g_m0.m_len = TLEN;
	g_m0.m_flags = M_PKTHDR;
	g_m0.m_pkthdr.len = TLEN;
	g_m0.m_next = NULL;
	g_m0.m_nextpkt = NULL;
	bzero(&g_part, sizeof(g_part));

	error = ip6_fragment(NULL, &g_m0, hlen, IPPROTO_UDP, FRAGLEN, 0);
	(void)error;

	/*
	 * Walk the fragment chain (built off m0->m_nextpkt) and check the
	 * tiling via each fragment's ip6_frag header offset and MF bit.
	 */
	prev_end = 0;
	nseen = 0;
	for (fp = g_m0.m_nextpkt; fp != NULL && nseen < NFRAG;
	    fp = fp->m_nextpkt, nseen++) {
		/* ip6_insertfraghdr placed the header after the IPv6 header.
		 * Decode offset and MF exactly as frag6_input() does: mask the
		 * raw (network-order) offlg, then ntohs the offset. */
		struct ip6_hdr *fip6 = mtod(fp, struct ip6_hdr *);
		struct ip6_frag *fh = (struct ip6_frag *)(mtod(fp, char *) +
		    sizeof(struct ip6_hdr));
		int foff = ntohs(fh->ip6f_offlg & IP6F_OFF_MASK);
		int mf = (fh->ip6f_offlg & IP6F_MORE_FRAG) != 0;
		/* The fragment's own payload length, from ip6_plen. */
		int flen = ntohs(fip6->ip6_plen) - sizeof(struct ip6_frag);

		__CPROVER_assert(foff == prev_end,
		    "fragment offsets are contiguous");
		__CPROVER_assert((foff & 7) == 0,
		    "fragment offsets are 8-byte aligned");
		__CPROVER_assert(flen >= 0 && flen <= FRAGLEN,
		    "each fragment payload is at most fraglen");
		prev_end = foff + flen;
		if (prev_end < TLEN - hlen)
			__CPROVER_assert(mf,
			    "a non-final fragment has the More-Fragments bit");
		else
			__CPROVER_assert(!mf,
			    "the final fragment has no More-Fragments bit");
	}
	__CPROVER_assert(prev_end == TLEN - hlen,
	    "the fragments cover the whole payload");
}
