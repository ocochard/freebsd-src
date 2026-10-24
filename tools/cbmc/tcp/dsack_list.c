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
 * cbmc(1) harness for tcp_update_dsack_list(), sys/netinet/tcp_sack.c: the
 * receiver's DSACK-block list maintenance, the companion to
 * tcp_update_sack_list().  It folds a duplicate (DSACK) range and the
 * existing SACK blocks into saved_blks[] and writes them back to sackblks[],
 * capped at MAX_SACK_BLKS.  The array bound is the security property:
 * rcv_numsacks never exceeds MAX_SACK_BLKS and no sackblks[] write runs past
 * the array.  (The sibling tcp_update_sack_list() has a zero-length path
 * that skips its cap; this one caps inside the loop condition, so the
 * proof checks whether the DSACK variant is likewise bounded.)
 *
 * Not a program: run.sh compiles it with SOURCE naming tcp_sack.c or a
 * mutant of it, included whole.  The tcpcb's sackblks[] and rcv_numsacks are
 * nondeterministic within their valid ranges, and the received range is
 * nondeterministic (start < end, per the function's KASSERT); so every fold
 * case is explored, and a write past sackblks[] is an out-of-bounds access.
 *
 * The entry point, for --function:
 *
 *   proof_dsack_list	tcp_update_dsack_list() on any starting list and
 *			received range: rcv_numsacks stays within MAX_SACK_BLKS
 *			and no sackblks[] access runs past the array.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static struct tcpcb g_tp;

void
proof_dsack_list(void)
{
	tcp_seq rcv_start, rcv_end;
	int i, n;

	bzero(&g_tp, sizeof(g_tp));

	/* A valid starting SACK list the receiver keeps: non-empty, ordered,
	 * non-overlapping, above rcv_nxt. */
	n = nondet_int();
	__CPROVER_assume(n >= 0 && n <= MAX_SACK_BLKS);
	g_tp.rcv_numsacks = n;
	g_tp.rcv_nxt = nondet_uint();
	for (i = 0; i < MAX_SACK_BLKS; i++) {
		g_tp.sackblks[i].start = nondet_uint();
		g_tp.sackblks[i].end = nondet_uint();
		if (i < n) {
			__CPROVER_assume(SEQ_LT(g_tp.rcv_nxt,
			    g_tp.sackblks[i].start));
			__CPROVER_assume(SEQ_LT(g_tp.sackblks[i].start,
			    g_tp.sackblks[i].end));
			if (i > 0)
				__CPROVER_assume(SEQ_LT(g_tp.sackblks[i - 1].end,
				    g_tp.sackblks[i].start));
		}
	}

	/* The DSACK range: non-empty, as the function's KASSERT requires. */
	rcv_start = nondet_uint();
	rcv_end = nondet_uint();
	__CPROVER_assume(SEQ_LT(rcv_start, rcv_end));

	tcp_update_dsack_list(&g_tp, rcv_start, rcv_end);

	__CPROVER_assert(g_tp.rcv_numsacks >= 0 &&
	    g_tp.rcv_numsacks <= MAX_SACK_BLKS,
	    "the DSACK block count stays within the array");
}
