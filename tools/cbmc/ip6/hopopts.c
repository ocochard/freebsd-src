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
 * cbmc(1) harness for ip6_process_hopopts() and ip6_unknown_opt(),
 * sys/netinet6/ip6_input.c: walk the options of a Hop-by-Hop Options
 * header a peer sent (RFC 8200 section 4.2; Router Alert, RFC 2711).
 *
 * Not a program: run.sh compiles it with SOURCE naming ip6_input.c or a
 * mutant of it, included whole.  The header follows the IPv6 header, as
 * ip6_hopopts_input() has it (pulled up, contiguous); its option bytes are
 * free, its length HBHLEN a constant per job.  icmp6_error() and m_freem()
 * are modelled: each consumes the mbuf, recorded.
 *
 * Properties: no read outside the option area; the mbuf consumed exactly
 * when -1 is returned; and the outcome a walk of the options per RFC 8200
 * gives: Pad1 and PadN skipped; an unknown option acted on by its two top
 * type bits (skip, discard, ICMPv6 Parameter Problem code 2 pointing at
 * the option, the same unless the destination is multicast); Jumbo
 * refused (not supported); a Router Alert of length 2 reported, of another
 * length an ICMPv6 error at its length byte; an option the header has no
 * room for (its type and length bytes, or the 4 bytes of a Router Alert)
 * dropped.  With -DSTRICT, an option whose data runs past the header is
 * dropped too, as dest6_input() does: the question job.
 *
 * The entry point, for --function:
 *
 *   proof_hopopts	ip6_process_hopopts() of HBHLEN option bytes.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#ifndef HBHLEN
#define	HBHLEN		6
#endif

struct hbh_pkt {
	struct ip6_hdr	ip6;
	struct ip6_hbh	hbh;
	uint8_t		opt[HBHLEN];
};

static struct mbuf *g_m;
static int g_consumed, g_icmp, g_param, g_code;

static void
hbh_consume(struct mbuf *m)
{
	__CPROVER_assert(m == g_m, "the packet's mbuf");
	__CPROVER_assert(g_consumed == 0, "the mbuf is consumed once");
	g_consumed++;
}

void
icmp6_error(struct mbuf *m, int type, int code, int param)
{
	hbh_consume(m);
	__CPROVER_assert(type == ICMP6_PARAM_PROB, "a parameter problem");
	g_icmp = 1;
	g_code = code;
	g_param = param;
}

void
m_freem(struct mbuf *m)
{
	hbh_consume(m);
}

/* The outcome of the options per RFC 8200 4.2. */
#define	V_ACCEPT	0
#define	V_DROP		1
#define	V_ICMP		2

void
proof_hopopts(void)
{
	struct hbh_pkt *p;
	struct mbuf *m;
	uint32_t rtalert, wrt;
	int i, n, t, ret, verdict, wparam, wcode;
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

	rtalert = wrt = 0xffffffff;
	ret = ip6_process_hopopts(m, p->opt, HBHLEN, &rtalert);

	/* The walk, as the RFC has it. */
	verdict = V_ACCEPT;
	wparam = wcode = 0;
	for (i = 0; i < HBHLEN && verdict == V_ACCEPT; i += n) {
		t = p->opt[i];
		if (t == IP6OPT_PAD1) {
			n = 1;
			continue;
		}
		if (HBHLEN - i < IP6OPT_MINLEN) {
			verdict = V_DROP;
			break;
		}
		n = p->opt[i + 1] + 2;
#ifdef STRICT
		if (n > HBHLEN - i) {
			verdict = V_DROP;
			break;
		}
#endif
		switch (t) {
		case IP6OPT_PADN:
			break;
		case IP6OPT_ROUTER_ALERT:
			if (HBHLEN - i < IP6OPT_RTALERT_LEN)
				verdict = V_DROP;
			else if (p->opt[i + 1] != IP6OPT_RTALERT_LEN - 2) {
				verdict = V_ICMP;
				wcode = ICMP6_PARAMPROB_HEADER;
				wparam = sizeof(struct ip6_hdr) +
				    sizeof(struct ip6_hbh) + i + 1;
			} else
				wrt = (p->opt[i + 2] << 8) | p->opt[i + 3];
			break;
		case IP6OPT_JUMBO:
			verdict = V_DROP;
			break;
		default:
			switch (t & 0xc0) {
			case 0x00:
				break;
			case 0x40:
				verdict = V_DROP;
				break;
			case 0x80:
			case 0xc0:
				if ((t & 0xc0) == 0xc0 && mcast) {
					verdict = V_DROP;
					break;
				}
				verdict = V_ICMP;
				wcode = ICMP6_PARAMPROB_OPTION;
				wparam = sizeof(struct ip6_hdr) +
				    sizeof(struct ip6_hbh) + i;
				break;
			}
		}
	}

	__CPROVER_assert((ret == 0) == (g_consumed == 0) &&
	    (ret == 0 || ret == -1), "-1 exactly when the mbuf is consumed");
	__CPROVER_assert((verdict == V_ACCEPT) == (ret == 0),
	    "the options accepted as the RFC accepts them");
	__CPROVER_assert((verdict == V_ICMP) == (g_icmp != 0),
	    "an ICMPv6 error exactly where the RFC sends one");
	if (verdict == V_ICMP)
		__CPROVER_assert(g_param == wparam && g_code == wcode,
		    "the ICMPv6 error points at the offending byte");
	if (verdict == V_ACCEPT)
		__CPROVER_assert(rtalert == wrt,
		    "the last Router Alert value reported");
}
