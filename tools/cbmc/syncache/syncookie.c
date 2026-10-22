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
 *
 * cbmc(1) harness for the TCP SYN cookie, sys/netinet/tcp_syncache.c:
 * syncookie_generate() packs a connection's MSS, window scale and SACK
 * state plus a MAC into the 32-bit initial sequence number sent in a
 * SYN-ACK; syncookie_expand() unpacks the ACK the peer echoes back,
 * checks the MAC and restores those values.  The pair must round-trip: a
 * cookie this host generated decodes to the same MSS, window scale and
 * SACK; and a forged ACK (wrong MAC) is rejected.
 *
 * Not a program: run.sh compiles it with SOURCE naming tcp_syncache.c or
 * a mutant of it, included whole.  syncookie_mac() (SIPHASH, a byte loop)
 * is replaced by a deterministic model: the round-trip then depends only
 * on the kernel's own bit packing and unpacking, which is what is proven.
 * The 3-bit mss_idx and wscale_idx index the 8-entry tcp_sc_msstab and
 * tcp_sc_wstab, so the decode is in bounds by construction, which CBMC
 * also checks.
 *
 * The entry point, for --function:
 *
 *   proof_roundtrip	syncookie_generate() then syncookie_expand() on the
 *			sequence numbers it produced: the MSS index, window
 *			scale and SACK flag are restored to what was encoded.
 *
 * Not proven here: that a forged ACK is rejected.  That is a property of
 * the MAC's collision resistance (SIPHASH), not of this code's packing,
 * and a modelled MAC cannot establish it.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* sb_max, an extern the window-scale recompute reads. */
u_long sb_max = 2 * 1024 * 1024;

/*
 * syncookie_mac(): a deterministic stand-in for SIPHASH.  It need not be
 * cryptographic; it must only be a pure function of the inputs that both
 * generate and expand feed it, so that a genuine cookie's MAC recomputes
 * and a forgery's does not.  secmod (the bucket pointer) is constant here.
 */
uint32_t
cbmc_syncookie_mac(struct in_conninfo *inc, tcp_seq irs, uint8_t flags,
    uint8_t *secbits, uintptr_t secmod)
{
	uint32_t h;

	/*
	 * Multiplier-free so the SAT back end handles it trivially: a pure
	 * function of irs and flags is all the round-trip needs (inc and the
	 * secret are identical across the matching generate/expand pair).
	 */
	h = irs ^ ((irs << 13) | (irs >> 19));		/* rotate-mix irs */
	h ^= (uint32_t)flags << 11;
	h ^= (uint32_t)flags;
	return (h);
}

/* A listen socket, for the ttl/tos and window the expand reads. */
static struct socket g_lso;
static struct inpcb g_inp;
static struct syncache_head g_sch;

static void
setup(struct syncache *sc)
{
	bzero(sc, sizeof(*sc));
	sc->sc_irs = nondet_uint();
	sc->sc_inc.inc_flags = 0;			/* IPv4 */
	/*
	 * The MSS and window scale are constants per job (PMSS, WSCALE): the
	 * encode walks the index tables and a symbolic value over the full
	 * uint16 range is slow; the jobs sweep the table boundaries instead.
	 * WSCALE < 0 means the window-scale option was not received.
	 */
	sc->sc_peer_mss = PMSS;
	if (WSCALE >= 0) {
		sc->sc_flags |= SCF_WINSCALE;
		sc->sc_requested_s_scale = WSCALE;
	}
	if (nondet_bool())
		sc->sc_flags |= SCF_SACK;

	V_tcp_syncache.secret.oddeven = nondet_uint();
	g_lso.so_pcb = (caddr_t)&g_inp;
	g_lso.sol_sbrcv_hiwat = nondet_int();
}

void
proof_roundtrip(void)
{
	struct syncache sc, scs;
	struct tcphdr th;
	struct tcpopt to;
	tcp_seq iss;
	u_int gen_mss_idx, i;

	setup(&sc);
	iss = syncookie_generate(&g_sch, &sc);

	/* The MSS index generate chose, to compare after the round-trip. */
	for (i = nitems(tcp_sc_msstab) - 1;
	    tcp_sc_msstab[i] > sc.sc_peer_mss && i > 0; i--)
		;
	gen_mss_idx = i;

	/* The peer echoes the ISS as the ACK, advanced by one, and the SYN
	 * sequence it saw as the sequence, advanced by one (as the stack
	 * does on a SYN-ACK). */
	bzero(&th, sizeof(th));
	bzero(&to, sizeof(to));
	th.th_ack = iss + 1;
	th.th_seq = sc.sc_irs + 1;

	if (!syncookie_expand(&sc.sc_inc, &g_sch, &scs, &th, &to, &g_lso, 0)) {
		/* A cookie this host just generated must be accepted. */
		__CPROVER_assert(0, "a genuine cookie is accepted");
		return;
	}
	/* The MSS maps back to the same table entry. */
	__CPROVER_assert(scs.sc_peer_mss == tcp_sc_msstab[gen_mss_idx],
	    "the MSS round-trips to its table entry");
	/* The SACK flag round-trips. */
	__CPROVER_assert((scs.sc_flags & SCF_SACK) == (sc.sc_flags & SCF_SACK),
	    "the SACK flag round-trips");
	/* The window scale round-trips to the table entry generate chose. */
	if (sc.sc_flags & SCF_WINSCALE) {
		for (i = nitems(tcp_sc_wstab) - 1;
		    tcp_sc_wstab[i] > sc.sc_requested_s_scale && i > 0; i--)
			;
		if (i > 0)
			__CPROVER_assert(scs.sc_requested_s_scale ==
			    tcp_sc_wstab[i],
			    "the window scale round-trips to its table entry");
	}
}
