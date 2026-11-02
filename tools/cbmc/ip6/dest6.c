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
 * cbmc(1) harness for dest6_input(), sys/netinet6/dest6.c: walk the
 * options of a Destination Options header a peer sent (RFC 8200 section
 * 4.6, options as in section 4.2).
 *
 * Not a program: run.sh compiles it with SOURCE naming dest6.c or a mutant
 * of it, included whole.  One mbuf holds the IPv6 header and DLEN bytes of
 * the Destination Options header, all of them free: its length byte may
 * claim more than the mbuf holds, and m_pullup() then fails (__m_pullup()
 * frees the mbuf, as the real one does for a chain too short).
 * ip6_unknown_opt(), in ip6_input.c, is modelled by what the hopopts.c
 * proofs show it does; icmp6_error() and m_freem() consume the mbuf.
 *
 * Properties: no read outside the header; the mbuf consumed exactly when
 * IPPROTO_DONE is returned, else handed back with the offset past the
 * header and its Next Header returned; and the outcome a walk of the
 * options gives: a header longer than the packet dropped; Pad1 and PadN
 * skipped; an option the header has no room for, its data included,
 * dropped; an unknown option acted on by its two top type bits.
 *
 * The entry point, for --function:
 *
 *   proof_dest6	dest6_input() of a DLEN-byte header after the IPv6
 *			header.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#ifndef DLEN
#define	DLEN		8
#endif

struct dest6_pkt {
	struct ip6_hdr	ip6;
	uint8_t		dest[DLEN];
};

static struct mbuf *g_m;
static int g_consumed, g_icmp, g_param, g_code;

static void
dest6_consume(struct mbuf *m)
{
	__CPROVER_assert(m == g_m, "the packet's mbuf");
	__CPROVER_assert(g_consumed == 0, "the mbuf is consumed once");
	g_consumed++;
}

void
icmp6_error(struct mbuf *m, int type, int code, int param)
{
	dest6_consume(m);
	__CPROVER_assert(type == ICMP6_PARAM_PROB, "a parameter problem");
	g_icmp = 1;
	g_code = code;
	g_param = param;
}

void
m_freem(struct mbuf *m)
{
	dest6_consume(m);
}

/* The chain holds no more than the mbuf: the pullup fails, freeing it. */
struct mbuf *
__m_pullup(struct mbuf *m, int len)
{
	__CPROVER_assert(len > m->m_len, "model: pulled up only when short");
	dest6_consume(m);
	return (NULL);
}

/* As the hopopts.c proofs show ip6_unknown_opt() does. */
int
ip6_unknown_opt(uint8_t *optp, struct mbuf *m, int off)
{
	struct ip6_hdr *ip6;

	switch (IP6OPT_TYPE(*optp)) {
	case IP6OPT_TYPE_SKIP:
		return (optp[1]);
	case IP6OPT_TYPE_DISCARD:
		m_freem(m);
		return (-1);
	case IP6OPT_TYPE_FORCEICMP:
		icmp6_error(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_OPTION, off);
		return (-1);
	default:
		ip6 = mtod(m, struct ip6_hdr *);
		if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
		    (m->m_flags & (M_BCAST | M_MCAST)))
			m_freem(m);
		else
			icmp6_error(m, ICMP6_PARAM_PROB,
			    ICMP6_PARAMPROB_OPTION, off);
		return (-1);
	}
}

#define	V_ACCEPT	0
#define	V_DROP		1
#define	V_ICMP		2

void
proof_dest6(void)
{
	struct dest6_pkt *p;
	struct mbuf *m, *mm;
	int i, n, t, len, off, ret, verdict, wparam;
	bool mcast;

	p = __CPROVER_allocate(sizeof(*p), 0);
	m = __CPROVER_allocate(sizeof(*m), 1);
	m->m_data = (caddr_t)p;
	m->m_len = sizeof(*p);
	m->m_flags = M_PKTHDR | (nondet_bool() ? M_MCAST : 0);
	m->m_pkthdr.len = m->m_len;
	g_m = m;
	mcast = IN6_IS_ADDR_MULTICAST(&p->ip6.ip6_dst) ||
	    (m->m_flags & (M_BCAST | M_MCAST)) != 0;

	mm = m;
	off = sizeof(struct ip6_hdr);
	ret = dest6_input(&mm, &off, IPPROTO_DSTOPTS);

	/* The walk, as the RFC has it. */
	len = (p->dest[1] + 1) << 3;
	verdict = V_ACCEPT;
	wparam = 0;
	if (len > DLEN)
		verdict = V_DROP;
	for (i = sizeof(struct ip6_dest); i < len && verdict == V_ACCEPT;
	    i += n) {
		t = p->dest[i];
		if (t == IP6OPT_PAD1) {
			n = 1;
			continue;
		}
		if (len - i < IP6OPT_MINLEN || p->dest[i + 1] + 2 > len - i) {
			verdict = V_DROP;
			break;
		}
		n = p->dest[i + 1] + 2;
		if (t == IP6OPT_PADN)
			continue;
		switch (t & 0xc0) {
		case 0x00:
			break;
		case 0x40:
			verdict = V_DROP;
			break;
		default:
			if ((t & 0xc0) == 0xc0 && mcast) {
				verdict = V_DROP;
				break;
			}
			verdict = V_ICMP;
			wparam = sizeof(struct ip6_hdr) + i;
			break;
		}
	}

	__CPROVER_assert((ret == IPPROTO_DONE) == (g_consumed == 1) &&
	    (mm == NULL) == (g_consumed == 1),
	    "IPPROTO_DONE exactly when the mbuf is consumed");
	__CPROVER_assert((verdict == V_ACCEPT) == (ret != IPPROTO_DONE),
	    "the options accepted as the RFC accepts them");
	__CPROVER_assert((verdict == V_ICMP) == (g_icmp != 0),
	    "an ICMPv6 error exactly where the RFC sends one");
	if (verdict == V_ICMP)
		__CPROVER_assert(g_param == wparam &&
		    g_code == ICMP6_PARAMPROB_OPTION,
		    "the ICMPv6 error points at the option");
	if (verdict == V_ACCEPT)
		__CPROVER_assert(mm == m && ret == p->dest[0] &&
		    off == sizeof(struct ip6_hdr) + len,
		    "the next header, the offset past the header");
}
