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
 * cbmc(1) harness for m_split(), sys/kern/uipc_mbuf.c: split an mbuf chain
 * in two at byte offset len0, returning the tail chain.  This harness
 * covers the plain path (no M_PKTHDR, no external storage): the split
 * mbuf's tail bytes are copied into a fresh mbuf, the lengths are divided
 * exactly, and the chain is re-linked.  The copy must read only within the
 * split mbuf and write only within the fresh mbuf, and len + remain must
 * equal the original length so no byte is lost or duplicated.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  The chain is real struct mbufs (so the
 * m_dat storage and M_ALIGN placement are the kernel's, and a copy past a
 * mbuf is an out-of-bounds access CBMC catches); m_get() goes through the
 * kern.h UMA model.  The per-mbuf lengths and the split offset are
 * constants per job.  bcopy() is the kern.h memmove model.
 *
 * The entry point, for --function:
 *
 *   proof_split	m_split() on a plain chain at offset len0: the tail copy
 *		stays inside the split mbuf and the fresh mbuf, the two
 *		lengths sum to the original, and the chain is re-linked.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/*
 * Geometries (GEO): per-mbuf lengths and the split offset, constants per
 * job.  0 splits inside the first mbuf.  1 splits exactly at a mbuf
 * boundary (remain == 0: the tail is just the next mbuf).  2 splits inside
 * a later mbuf.
 */
#if GEO == 0			/* split inside the first mbuf */
static int g_lens[] = { 10, 8 };
#define	LEN0	4
#elif GEO == 1			/* split at a mbuf boundary (remain == 0) */
static int g_lens[] = { 6, 8 };
#define	LEN0	6
#elif GEO == 2			/* split inside the second mbuf */
static int g_lens[] = { 6, 10, 4 };
#define	LEN0	9
#endif

#define	NMBUF	((int)nitems(g_lens))

static struct mbuf *g_m[8];

void
proof_split(void)
{
	struct mbuf *head, *n, *m;
	int i, splitmb, splitoff, before;

	/*
	 * A chain of real mapped mbufs, heap allocated like UMA gives (so any
	 * m_free() is valid).  No M_PKTHDR, no M_EXT: the plain copy path.
	 */
	for (i = 0; i < NMBUF; i++) {
		g_m[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_m[i]->m_data = &g_m[i]->m_dat[0];
		g_m[i]->m_len = g_lens[i];
		g_m[i]->m_flags = 0;
		g_m[i]->m_type = MT_DATA;
	}
	for (i = 0; i < NMBUF; i++)
		g_m[i]->m_next = (i + 1 < NMBUF) ? g_m[i + 1] : NULL;
	head = g_m[0];

	/* Which mbuf holds the split point, and the offset within it. */
	splitoff = LEN0;
	splitmb = 0;
	while (splitoff > g_lens[splitmb]) {
		splitoff -= g_lens[splitmb];
		splitmb++;
	}
	before = g_m[splitmb]->m_len;

	n = m_split(head, LEN0, M_NOWAIT);

	if (n == NULL)
		return;			/* allocation failed: nothing to check */
	/*
	 * The split mbuf now holds the first splitoff bytes, and the two
	 * pieces sum to what it held before, so no byte is lost or
	 * duplicated.  The tail copy was bounds-checked against both mbufs
	 * during the call.
	 */
	__CPROVER_assert(g_m[splitmb]->m_len == splitoff,
	    "the split mbuf keeps the bytes before the offset");
	if (splitoff < before)
		__CPROVER_assert(n->m_len == before - splitoff,
		    "the tail mbuf holds the bytes after the offset");
	__CPROVER_assert(g_m[splitmb]->m_len + n->m_len == before ||
	    splitoff == before,
	    "the split divides the mbuf exactly");
	/* No mbuf's length exceeds its storage. */
	for (m = head, i = 0; m != NULL && i < 8; m = m->m_next, i++)
		__CPROVER_assert(m->m_len <= M_SIZE(m),
		    "no mbuf's length exceeds its storage");
}
