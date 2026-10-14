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
 * cbmc(1) harness for sbappend_ktls_rx(), sys/kern/uipc_sockbuf.c, built
 * with KERN_TLS: how TCP data lands in a TLS receive buffer, and its
 * check for packets coming in on another interface than the session's
 * receive tag, the caller of ktls_input_ifp_mismatch().
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_sockbuf.c or
 * a mutant of it, included whole.  ktls_check_rx() and
 * ktls_input_ifp_mismatch(), in uipc_ktls.c and proven by ktls.c, are
 * modelled by what they are given; so is sbcompress_ktls_rx(), which
 * run.sh replaces: its coalescing of bytes is not what is proven here.
 * The one entry point, for --function:
 *
 *   proof_rx_append	sbappend_ktls_rx() on a chain of packets, each in
 *			on an interface and decrypted by the NIC or not:
 *			every mbuf loses its packet header and is marked
 *			not ready, and decrypted as its packet was; the
 *			chain is appended, then ktls_check_rx() run; and
 *			ktls_input_ifp_mismatch() told of the interface
 *			the last packet came in on, when it is not the
 *			session's
 */

#include SOURCE

#include <sys/vnode.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include <sys/refcount.h>
#include "kern.h"

#define	NM	3	/* mbufs in the chain */

static struct socket g_so;
static struct ktls_session g_tls;
static struct ifnet g_ifp, g_ifp2;
static struct mbuf *g_m[NM];
static struct mbuf *g_appended;
static struct ifnet *g_mismatch;
static int g_nappend, g_ncheck, g_nmismatch;

/* m_demote_pkthdr(), uipc_mbuf.c, for mbufs with no tag. */
void
m_demote_pkthdr(struct mbuf *m)
{
	__CPROVER_assert((m->m_flags & M_PKTHDR) != 0,
	    "demotes a packet header");
	m->m_flags &= ~M_PKTHDR;
	memset(&m->m_pkthdr, 0, sizeof(struct pkthdr));
}

/* sbcompress_ktls_rx(): run.sh replaces calls to it. */
void
cbmc_sbcompress_ktls_rx(struct sockbuf *sb, struct mbuf *m, struct mbuf *n)
{
	__CPROVER_assert(sb == &g_so.so_rcv && g_ncheck == 0,
	    "the chain is appended, before the check");
	g_appended = m;
	g_nappend++;
}

void
ktls_check_rx(struct sockbuf *sb)
{
	__CPROVER_assert(sb == &g_so.so_rcv, "checks the receive buffer");
	g_ncheck++;
}

void
ktls_input_ifp_mismatch(struct sockbuf *sb, struct ifnet *ifp)
{
	__CPROVER_assert(sb == &g_so.so_rcv, "of the receive buffer");
	g_mismatch = ifp;
	g_nmismatch++;
}

void
proof_rx_append(void)
{
	struct sockbuf *sb = &g_so.so_rcv;
	struct mbuf *m;
	struct ifnet *last;
	bool dec[NM], pkt;
	int i, n;

	g_tls.rx_ifp = nondet_bool() ? NULL : nondet_bool() ? &g_ifp : &g_ifp2;
	sb->sb_tls_info = &g_tls;
	sb->sb_flags = SB_TLS_RX;
	n = nondet_int();
	__CPROVER_assume(n >= 1 && n <= NM);
	last = NULL;
	for (i = 0; i < NM; i++) {
		if (i >= n)
			break;
		m = __CPROVER_allocate(sizeof(struct mbuf), 1);
		m->m_type = MT_DATA;
		m->m_flags = nondet_int() & ~(M_PKTHDR | M_NOTREADY |
		    M_DECRYPTED);
		pkt = i == 0 || nondet_bool();
		if (pkt) {
			m->m_flags |= M_PKTHDR;
			m->m_pkthdr.leaf_rcvif = nondet_bool() ? &g_ifp :
			    &g_ifp2;
			m->m_pkthdr.csum_flags = nondet_bool() ?
			    CSUM_TLS_DECRYPTED : 0;
			last = m->m_pkthdr.leaf_rcvif;
		}
		/* An mbuf is decrypted as the packet it is part of. */
		dec[i] = pkt ? m->m_pkthdr.csum_flags == CSUM_TLS_DECRYPTED :
		    dec[i - 1];
		g_m[i] = m;
		if (i > 0)
			g_m[i - 1]->m_next = m;
	}

	sbappend_ktls_rx(sb, g_m[0]);

	for (i = 0; i < NM; i++) {
		if (i >= n)
			break;
		m = g_m[i];
		__CPROVER_assert((m->m_flags & M_PKTHDR) == 0 &&
		    (m->m_flags & M_NOTREADY) != 0 &&
		    ((m->m_flags & M_DECRYPTED) != 0) == dec[i] &&
		    (m->m_flags & ~(M_DEMOTEFLAGS | M_NOTREADY |
		    M_DECRYPTED)) == 0,
		    "a pure data chain, not ready, decrypted as its packet");
	}
	__CPROVER_assert(g_nappend == 1 && g_appended == g_m[0] &&
	    g_ncheck == 1, "appended, then checked once");
	if (g_tls.rx_ifp != NULL && last != g_tls.rx_ifp)
		__CPROVER_assert(g_nmismatch == 1 && g_mismatch == last,
		    "the session is told the last packet came in elsewhere");
	else
		__CPROVER_assert(g_nmismatch == 0,
		    "and not told when it came in on its interface");
}
