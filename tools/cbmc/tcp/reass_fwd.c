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
 * cbmc(1) harness for tcp_reass_merge_forward(), sys/netinet/tcp_reass.c:
 * after a segment ent is placed in the reassembly queue, this walks the
 * segments after it and coalesces every one that ent overlaps forward --
 * freeing a segment ent fully covers, or trimming a partially overlapping
 * one and merging it in.  This is the multi-segment overlap resolution; a
 * wrong trim double-counts or loses sequence-space bytes, or leaves an
 * overlap behind.
 *
 * Not a program: run.sh compiles it with SOURCE naming tcp_reass.c or a
 * mutant of it, included whole.  A queue of ent plus a few following
 * segments of a concrete per-job geometry is built (a symbolic queue's
 * overlap combinatorics blow up); tcp_reass_merge_forward() runs on it.
 * m_adj()/m_freem() and uma_zfree() are modelled; the stat macros are
 * compiled out.
 *
 * The entry point, for --function:
 *
 *   proof_merge_fwd	tcp_reass_merge_forward() on ent and its successors:
 *			afterwards ent spans up to the furthest merged end with
 *			no byte double-counted, no following segment still
 *			overlaps ent, and the queue stays sorted.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

void
m_adj(struct mbuf *mp, int req_len)
{
	if (mp != NULL)
		mp->m_len -= req_len;
}
void m_freem(struct mbuf *m) { }

/*
 * Concrete geometries (GEO) for the queue after ent.  ent is [0,16).  The
 * successors' (start,len) are constants per job.  0: a gap, no overlap.
 * 1: one partially overlapping successor (trim).  2: one fully covered
 * successor (consume).  3: two successors, one consumed then one trimmed.
 */
#if GEO == 0
static const int g_soff[] = { 32 };
static const int g_slen[] = { 16 };
#elif GEO == 1
static const int g_soff[] = { 8 };
static const int g_slen[] = { 16 };
#elif GEO == 2
static const int g_soff[] = { 4 };
static const int g_slen[] = { 8 };
#elif GEO == 3
static const int g_soff[] = { 4, 12 };
static const int g_slen[] = { 8, 16 };
#endif

#define	NSEG	((int)nitems(g_soff))

static struct tcpcb g_tp;
static struct tseg_qent g_ent;
static struct tseg_qent *g_seg[8];
static struct mbuf g_entm, g_segm[8];

void
proof_merge_fwd(void)
{
	struct tseg_qent *q;
	tcp_seq entend;
	int i, prevend;

	bzero(&g_tp, sizeof(g_tp));
	TAILQ_INIT(&g_tp.t_segq);

	/* ent, at [0, 16). */
	bzero(&g_ent, sizeof(g_ent));
	bzero(&g_entm, sizeof(g_entm));
	g_ent.tqe_start = 0;
	g_ent.tqe_len = 16;
	g_ent.tqe_m = &g_entm;
	g_ent.tqe_last = &g_entm;
	TAILQ_INSERT_TAIL(&g_tp.t_segq, &g_ent, tqe_q);

	/* The following segments, sorted by start. */
	for (i = 0; i < NSEG; i++) {
		g_seg[i] = __CPROVER_allocate(sizeof(struct tseg_qent), 1);
		bzero(&g_segm[i], sizeof(g_segm[i]));
		g_seg[i]->tqe_start = g_soff[i];
		g_seg[i]->tqe_len = g_slen[i];
		g_seg[i]->tqe_m = &g_segm[i];
		g_seg[i]->tqe_last = &g_segm[i];
		TAILQ_INSERT_TAIL(&g_tp.t_segq, g_seg[i], tqe_q);
	}
	g_tp.t_segqlen = NSEG + 1;

	/*
	 * The expected end after coalescing: ent's end extended over every
	 * successor that overlaps the growing run (contiguous or overlapping
	 * from ent->start), i.e. the furthest end reachable without a gap.
	 */
	{
		tcp_seq exp = g_ent.tqe_start + g_ent.tqe_len;
		int pass;

		/* Extend over successors to a fixpoint (segments are sorted). */
		for (pass = 0; pass < NSEG; pass++)
			for (i = 0; i < NSEG; i++)
				if (SEQ_LEQ((tcp_seq)g_soff[i], exp) &&
				    SEQ_GT((tcp_seq)(g_soff[i] + g_slen[i]), exp))
					exp = g_soff[i] + g_slen[i];

		tcp_reass_merge_forward(&g_tp, &g_ent);

		/*
		 * ent now spans exactly up to that furthest merged end: the
		 * overlap was trimmed exactly, no sequence-space byte
		 * double-counted or lost.
		 */
		__CPROVER_assert(g_ent.tqe_start + g_ent.tqe_len == exp,
		    "ent spans up to the furthest merged end");
	}

	/*
	 * After the forward merge, no segment following ent still overlaps it:
	 * every remaining successor starts at or after ent's end.  And the
	 * queue stays sorted.
	 */
	entend = g_ent.tqe_start + g_ent.tqe_len;
	prevend = -1;
	i = 0;
	TAILQ_FOREACH(q, &g_tp.t_segq, tqe_q) {
		if (q == &g_ent) {
			__CPROVER_assert((int)q->tqe_start >= prevend,
			    "the queue stays sorted");
			prevend = q->tqe_start + q->tqe_len;
			continue;
		}
		__CPROVER_assert(SEQ_GEQ(q->tqe_start, entend),
		    "no following segment still overlaps ent");
		__CPROVER_assert((int)q->tqe_start >= prevend,
		    "the queue stays sorted");
		prevend = q->tqe_start + q->tqe_len;
		if (++i > NSEG)
			break;
	}
}
