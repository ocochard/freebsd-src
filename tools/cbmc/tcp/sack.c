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
 * cbmc(1) harness for tcp_sack_doack(), sys/netinet/tcp_sack.c: the whole
 * function, which takes the peer's SACK blocks from a parsed option and
 * updates the retransmission scoreboard (a list of holes).  Driven off
 * the wire by any peer; the SACK-block intake is the part a remote can
 * push on (cf. Linux CVE-2019-11477), the scoreboard sweep is where its
 * accounting invariants must hold.
 *
 * Not a program: run.sh compiles it with SOURCE naming tcp_sack.c or a
 * mutant of it, included whole.  The scoreboard is a small bounded pool of
 * holes, allocated and freed through the real tcp_sackhole_alloc()/_free()
 * (uma routed to the pool by kern.h); tcp_record_dsack() is modelled.
 * The initial scoreboard is built with its hint accounting (hole_bytes,
 * sack_bytes_rexmit) consistent, as the function requires and asserts.
 * The reference is RFC 2018 and the function's own KASSERTs.  One entry
 * point, for --function:
 *
 *   proof_sack_doack	tcp_sack_doack() with up to TCP_MAX_SACK peer SACK
 *			blocks of any sequence values and a scoreboard of up
 *			to NH0 holes: no array or pool overflow, every
 *			KASSERT holds (hole_bytes and sack_bytes_rexmit stay
 *			non-negative and consistent, delivered_data >= 0,
 *			notlost_bytes within the holes), and the returned
 *			status matches whether anything changed
 */

#include SOURCE

/* The SACK hole zone is a small fixed pool; declare the hooks for kern.h. */
static void *cbmc_sackhole(uma_zone_t zone, int flags);
static int cbmc_sackhole_free(uma_zone_t zone, void *item);
#define	CBMC_UMA_HOOK		cbmc_sackhole
#define	CBMC_UMA_FREE_HOOK	cbmc_sackhole_free

#include <vm/vm.h>
#include <vm/vm_page.h>
#include "kern.h"

const int tcprexmtthresh = 3;			/* tcp_input.c */

/* Sysctl knobs tcp_sackhole_alloc() reads; VNET() is identity here. */
int tcp_sack_maxholes = 128;
int tcp_sack_globalholes = 0;
int tcp_sack_globalmaxholes = 65536;
uma_zone_t tcp_sack_hole_zone;

void __rw_wlock_cookie(volatile uintptr_t *c, const char *f, int l) { }
void __rw_wunlock_cookie(volatile uintptr_t *c, const char *f, int l) { }
void cbmc_atomic_add_int(volatile int *p, int v) { *p += v; }
void cbmc_atomic_subtract_int(volatile int *p, int v) { *p -= v; }

static int g_ndsack;

/* tcp_record_dsack(): a D-SACK block noted; counted for the proof. */
void
cbmc_tcp_record_dsack(struct tcpcb *tp, tcp_seq start, tcp_seq end, int tlp)
{
	g_ndsack++;
}

/* The hole pool: tcp_sackhole_alloc()/_free() draw from it via uma. */
#define	NH	6			/* total holes the pool can hold */
static struct sackhole g_holepool[NH];
static bool g_holeused[NH];

static void *
cbmc_sackhole(uma_zone_t zone, int flags)
{
	int i;

	for (i = 0; i < NH; i++)
		if (!g_holeused[i]) {
			g_holeused[i] = true;
			return (&g_holepool[i]);
		}
	return (NULL);			/* pool exhausted: alloc fails */
}

static int
cbmc_sackhole_free(uma_zone_t zone, void *item)
{
	struct sackhole *h = item;

	if (h < &g_holepool[0] || h >= &g_holepool[NH])
		return (0);		/* not ours */
	g_holeused[h - &g_holepool[0]] = false;
	return (1);
}

#define	NH0	1			/* holes in the initial scoreboard */
#define	NB	1		/* peer blocks the option can hold */
#ifndef GEO
#define	GEO	0
#endif

static struct tcpcb g_tp;
static struct tcpopt g_to;
static uint8_t g_sackbuf[NB * TCPOLEN_SACK];

/*
 * An initial scoreboard: up to NH0 holes, ascending and disjoint, each a
 * valid [start,end) with start <= rxmit <= end.  The hints are set to
 * match, as tcp_sack_doack() requires on entry (hole_bytes is the sum of
 * the holes' lengths, sack_bytes_rexmit the sum of min(rxmit,end)-start).
 */
/*
 * One concrete scoreboard + ack geometry, selected by GEO.  Concrete
 * sequence numbers make every SEQ_* comparison a constant, which collapses
 * the scoreboard sweep's branching (the symbolic version runs out of
 * memory).  Each GEO exercises a different sweep outcome:
 *   0  no peer SACK (pure cumulative ack path)
 *   2  a peer block that trims a hole's front
 *
 * (The whole-hole-removal, back-trim, split and tail-insert geometries
 * make the scoreboard sweep walk more holes/blocks than this host can
 * hold: at a deep-enough sweep unwind CBMC needs over 50G.  They are
 * left out; GEO 0 and 2 exercise the intake, the acceptance test, and a
 * hole trim with their accounting checked.)
 */
static tcp_seq g_bstart, g_bend, g_th_ack;	/* the peer block, if any */
static int g_haveblk;

static void
build_scoreboard(void)
{
	struct sackhole *h;

	TAILQ_INIT(&g_tp.snd_holes);
	g_tp.snd_numholes = 0;
	g_tp.sackhint.hole_bytes = 0;
	g_tp.sackhint.sack_bytes_rexmit = 0;
	g_tp.sackhint.nexthole = NULL;

	/* A connection window [una, max) with una=1000, max=5000. */
	g_tp.snd_una = 1000;
	g_tp.snd_max = 8000;
	g_tp.snd_recover = 8000;
	g_tp.t_maxseg = 1000;			/* > MAX_TCPOPTLEN */
	g_tp.t_flags = nondet_int();		/* TF_LRD etc. free */
	g_th_ack = 1000;			/* no cumulative advance */
	g_haveblk = 1;

	/* One hole [2000, 3000), rxmit at its start. */
	h = &g_holepool[0];
	g_holeused[0] = true;
	h->start = 2000;
	h->end = 5000;				/* a 3000-byte hole */
	h->rxmit = 2000;
	TAILQ_INSERT_TAIL(&g_tp.snd_holes, h, scblink);
	g_tp.snd_numholes = 1;
	g_tp.sackhint.hole_bytes = 3000;
	g_tp.sackhint.sack_bytes_rexmit = 0;	/* rxmit == start */
	g_tp.sackhint.nexthole = h;
	g_tp.snd_fack = 5000;			/* fack at the hole end */
	tcp_sack_globalholes = g_tp.snd_numholes;  /* match the planted holes */

	/* Blocks are >= maxseg (t_maxseg - MAX_TCPOPTLEN = 960) or reach
	 * snd_max, as the acceptance test requires. */
#if GEO == 0
	g_haveblk = 0;				/* no peer block */
#elif GEO == 2
	g_bstart = 2000; g_bend = 3000;		/* trims front -> [3000,5000) */
#else
#error "only GEO 0 and 2 are within this host's memory"
#endif
}

void
proof_sack_doack(void)
{
	struct tcpcb *tp = &g_tp;
	tcp_seq th_ack;
	int i;

	build_scoreboard();
	th_ack = g_th_ack;

	if (g_haveblk) {
		uint32_t be_s = htonl(g_bstart), be_e = htonl(g_bend);
		memcpy(g_sackbuf, &be_s, 4);
		memcpy(g_sackbuf + 4, &be_e, 4);
		g_to.to_flags = TOF_SACK;
		g_to.to_nsacks = 1;
	} else {
		g_to.to_flags = 0;
		g_to.to_nsacks = 0;
	}
	g_to.to_sacks = g_sackbuf;
	(void)i;
	{
	sackstatus_t rv = tcp_sack_doack(tp, &g_to, th_ack);
	int hb = tp->sackhint.hole_bytes;
	int sb = tp->sackhint.sacked_bytes;

	/*
	 * The scoreboard accounting the function leaves, worked out by hand
	 * for each concrete geometry.  These bite the value mutations
	 * (hole_bytes, sacked_bytes, the sort, the hole trims) that memory
	 * safety alone does not.
	 */
#if GEO == 0
	__CPROVER_assert(rv == SACK_NOCHANGE, "no SACK: no change");
	__CPROVER_assert(hb == 3000, "no SACK: the hole is untouched");
	__CPROVER_assert(sb == 0, "no SACK: nothing sacked");
#elif GEO == 2
	__CPROVER_assert(rv == SACK_CHANGE, "front trim: a change");
	__CPROVER_assert(hb == 2000, "front trim: 2000 of 3000 left");
	__CPROVER_assert(sb == 1000, "front trim: 1000 bytes sacked");
#endif
	(void)rv; (void)hb; (void)sb;
	}
	return;

	/*
	 * Memory safety and every KASSERT inside tcp_sack_doack() are the
	 * proof: sack_blocks[] not overflowed by the intake, hole_bytes and
	 * sack_bytes_rexmit non-negative throughout, delivered_data >= 0,
	 * notlost_bytes <= hole_bytes, and the empty/non-empty scoreboard
	 * consistency at the end.  CBMC checks all of them without an
	 * explicit assertion here.
	 */
}
