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
 * cbmc(1) harness for icmp_input(), sys/netinet/ip_icmp.c: check and act on
 * an ICMP message a peer sent (RFC 792, RFC 1122 3.2.2, RFC 1812).
 *
 * Not a program: run.sh compiles it with SOURCE naming ip_icmp.c or a
 * mutant of it, included whole.  The datagram is an IP header without
 * options and ICMPLEN bytes of ICMP, all of them free, in one mbuf, as
 * ip_input() hands it over (ip_len the datagram's length, the packet
 * header length the same).  Its bytes are an object of exactly that size,
 * so a read past the ICMP message is a read out of bounds.  ICMPLEN is a
 * constant per job.  The sysctls that select the paths are free.  Lengths
 * from 20 to 27 are left out: cbmc bounds-checks the whole icmp_dun union
 * (20 bytes at offset 8) at the timestamp reply's writes, which the
 * ICMP_TSLEN check keeps within the message.
 * icmp_reflect(), the redirect gateway check, the rate limit, rip_input(),
 * the routing calls and the checksum are modelled.
 *
 * Properties, from RFC 792 and the comments of icmp_input():
 * - no read outside the ICMP message, on any path;
 * - an error (unreachable, time exceeded, parameter problem) reaches the
 *   protocol's ctlinput only with the quoted IP header and 8 bytes of its
 *   payload in the message, and with the outer header, the ICMP header,
 *   the quoted header and min(the message, ICMP_ADVLENPREF) contiguous;
 * - the mbuf is consumed once: freed, reflected or handed to rip_input();
 *   a message shorter than ICMP_MINLEN is freed.
 *
 * The entry point, for --function:
 *
 *   proof_icmp	icmp_input() of an ICMPLEN-byte message.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#ifndef ICMPLEN
#define	ICMPLEN		8
#endif

struct icmp_pkt {
	struct ip	ip;
	uint8_t		icmp[ICMPLEN];
};

static struct mbuf *g_m;
static struct icmp_pkt *g_p;
static int g_consumed, g_ctl, g_freed;

static void
icmp_consume(struct mbuf *m)
{
	__CPROVER_assert(m == g_m, "the message's mbuf");
	__CPROVER_assert(g_consumed == 0, "the mbuf is consumed once");
	g_consumed++;
}

int
in_epoch(epoch_t epoch)
{
	return (1);
}

void
m_freem(struct mbuf *m)
{
	icmp_consume(m);
	g_freed = 1;
}

/* One mbuf holds the whole datagram: no pullup has to copy. */
struct mbuf *
__m_pullup(struct mbuf *m, int len)
{
	__CPROVER_assert(0, "model: the datagram is contiguous");
	return (NULL);
}

u_short
in_cksum_skip(struct mbuf *m, int len, int skip)
{
	__CPROVER_assert(len >= 0 && m->m_len >= skip + len,
	    "the checksum covers the message");
	return (nondet_bool());
}

/* No options in the outer header: nothing to strip. */
void
ip_stripoptions(struct mbuf *m)
{
	__CPROVER_assert(mtod(m, struct ip *)->ip_hl == 5,
	    "model: no outer options");
}

int
rip_input(struct mbuf **mp, int *offp, int proto)
{
	icmp_consume(*mp);
	*mp = NULL;
	return (IPPROTO_DONE);
}

void
cbmc_icmp_reflect(struct mbuf *m)
{
	icmp_consume(m);
}

int
cbmc_icmp_verify_redirect_gateway(struct sockaddr_in *src,
    struct sockaddr_in *dst, struct sockaddr_in *gateway, u_int fibnum)
{
	return (nondet_int());
}

int
cbmc_badport_bandlim(int which)
{
	return (nondet_bool() ? -1 : 0);
}

uint32_t
cbmc_iptime(void)
{
	return (nondet_uint());
}

/*
 * The address an address mask request is answered from.  For a message of
 * 12 to 27 bytes none: cbmc bounds-checks the whole of the icmp_dun union
 * (20 bytes at offset 8) at a write of icmp_mask, a false alarm there.
 */
static struct ifnet g_ifp;
static struct in_ifaddr g_ia;

struct ifaddr *
ifaof_ifpforaddr(const struct sockaddr *addr, if_t ifp)
{
#if ICMPLEN < 12 || ICMPLEN >= 28
	if (nondet_bool()) {
		g_ia.ia_ifp = &g_ifp;
		g_ifp.if_flags = nondet_int();
		return ((struct ifaddr *)&g_ia);
	}
#endif
	return (NULL);
}

int
rib_add_redirect(u_int fibnum, struct sockaddr *dst, struct sockaddr *gateway,
    struct sockaddr *author, struct ifnet *ifp, int flags, int lifetime_sec)
{
	return (0);
}

/*
 * The protocol's ctlinput: what icmp_input() promises it, as its comment
 * states (an upper layer handler can rely on ...).
 */
static void
icmp_ctl(struct icmp *icp)
{
	int icmplen = ICMPLEN, pref;

	g_ctl = 1;
	__CPROVER_assert((uint8_t *)icp == g_p->icmp &&
	    mtod(g_m, struct ip *) == &g_p->ip, "the message in place");
	__CPROVER_assert(icmplen >= ICMP_ADVLEN(icp) &&
	    icp->icmp_ip.ip_hl >= 5,
	    "the quoted header and 8 bytes of its payload are in the message");
	pref = sizeof(struct ip) + imin(icmplen, ICMP_ADVLENPREF(icp));
	__CPROVER_assert(g_m->m_len >= pref,
	    "contiguous to ICMP_ADVLENPREF");
}

ipproto_ctlinput_t *ip_ctlprotox[IPPROTO_MAX];
VNET_DEFINE(int, ipforwarding);

void
proof_icmp(void)
{
	struct icmp_pkt *p;
	struct mbuf *m, *mm;
	int off, ret;

	p = __CPROVER_allocate(sizeof(*p), 0);
	m = __CPROVER_allocate(sizeof(*m), 1);
	p->ip.ip_v = IPVERSION;
	p->ip.ip_hl = sizeof(struct ip) >> 2;
	p->ip.ip_len = htons(sizeof(*p));
	p->ip.ip_p = IPPROTO_ICMP;
	m->m_data = (caddr_t)p;
	m->m_len = sizeof(*p);
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = m->m_len;
	g_m = m;
	g_p = p;
	ip_ctlprotox[IPPROTO_TCP] = icmp_ctl;

	V_log_redirect = nondet_bool();
	V_drop_redirect = nondet_bool();
	V_ipforwarding = nondet_bool();
	V_icmpbmcastecho = nondet_bool();
	V_icmptstamprepl = nondet_bool();
	V_icmpmaskrepl = nondet_bool();

	mm = m;
	off = sizeof(struct ip);
	ret = icmp_input(&mm, &off, IPPROTO_ICMP);

	__CPROVER_assert(ret == IPPROTO_DONE && mm == NULL,
	    "the message is consumed");
	__CPROVER_assert(g_consumed == 1, "consumed once");
	if (ICMPLEN < ICMP_MINLEN)
		__CPROVER_assert(g_freed && !g_ctl,
		    "a message shorter than ICMP_MINLEN is dropped");
}
