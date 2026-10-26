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
 * cbmc(1) harness for m_getptr(), sys/kern/uipc_mbuf.c: find the mbuf and
 * in-mbuf offset of byte position loc in a chain, used by IPsec and the
 * multicast code to locate a split point before reading or writing there.
 * Callers index mtod(m) + *off right after, so the contract that matters is:
 * on a non-NULL return, *off is a valid index into the returned mbuf's data
 * (0 <= *off <= m_len), and it locates exactly byte loc of the chain.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  The chain is real struct mbufs; m_getptr
 * only reads m_len and walks m_next, so no copy model is needed.  The
 * per-mbuf lengths are a concrete geometry per job and loc is
 * nondeterministic, so every position (in range, at a boundary, and past the
 * end) is covered.
 *
 * The entry point, for --function:
 *
 *   proof_getptr	m_getptr() for any loc: a non-NULL return hands back an
 *			offset within the returned mbuf (0 <= off <= m_len),
 *			and the skipped lengths plus off equal loc.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/*
 * Geometries (GEO): the chain's per-mbuf lengths.  0: a single mbuf.  1: a
 * two-mbuf chain.  2: three mbufs including an empty one (a zero-length mbuf
 * the walk must step over).
 */
#if GEO == 0
static const int g_lens[] = { 8 };
#elif GEO == 1
static const int g_lens[] = { 8, 6 };
#elif GEO == 2
static const int g_lens[] = { 4, 0, 10 };
#endif

#define	NMBUF	((int)nitems(g_lens))

static struct mbuf *g_chain[4];

void
proof_getptr(void)
{
	struct mbuf *m, *r;
	int i, loc, off, skipped, total;

	for (i = 0; i < NMBUF; i++) {
		g_chain[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_chain[i]->m_data = &g_chain[i]->m_dat[0];
		g_chain[i]->m_len = g_lens[i];
		g_chain[i]->m_flags = 0;
		g_chain[i]->m_type = MT_DATA;
	}
	for (i = 0; i < NMBUF; i++)
		g_chain[i]->m_next = (i + 1 < NMBUF) ? g_chain[i + 1] : NULL;

	total = 0;
	for (i = 0; i < NMBUF; i++)
		total += g_lens[i];

	loc = nondet_int();
	__CPROVER_assume(loc >= 0 && loc <= total);

	off = -1;
	r = m_getptr(g_chain[0], loc, &off);

	if (r == NULL)
		return;			/* loc past the end: nothing located */
	/*
	 * The returned offset is a valid index into the returned mbuf's data,
	 * so a caller's mtod(r) + off read stays within the mbuf.  (The walk
	 * may return off == m_len at the very end of the last mbuf, pointing
	 * one past the valid data, which is a valid end position.)
	 */
	__CPROVER_assert(off >= 0 && off <= r->m_len,
	    "the returned offset is within the returned mbuf");
	__CPROVER_assert(off <= M_SIZE(r),
	    "the returned offset is within the mbuf storage");
	/*
	 * off == m_len (one past the data) is valid only at the very end of the
	 * chain, on the last mbuf.  A mid-chain off == m_len would be a position
	 * past that mbuf's data that a caller indexing mtod(r) + off reads out
	 * of bounds while the next mbuf holds the byte.
	 */
	if (r->m_next != NULL)
		__CPROVER_assert(off < r->m_len,
		    "a mid-chain offset is strictly within the mbuf");
	/*
	 * The returned (mbuf, off) locates exactly byte loc: the lengths of the
	 * mbufs before r, plus off, equal loc.
	 */
	skipped = 0;
	for (m = g_chain[0]; m != NULL && m != r; m = m->m_next)
		skipped += m->m_len;
	__CPROVER_assert(skipped + off == loc,
	    "the returned position is byte loc of the chain");
}
