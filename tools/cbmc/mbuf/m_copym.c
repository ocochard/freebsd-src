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
 * cbmc(1) harness for m_copym(), sys/kern/uipc_mbuf.c: copy len bytes
 * starting at offset off of an mbuf chain into a freshly allocated chain,
 * used all over the stack to duplicate a run of packet data.  This harness
 * covers the plain (non-external, non-header) path: each new mbuf is filled
 * from the matching run of the source with min(len, m_len - off) bytes.  The
 * per-mbuf copy must read only within the source mbuf and write only within
 * the fresh mbuf, and the whole len must be copied.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  The source chain and the fresh mbufs are
 * real struct mbufs (the latter through the UMA model, whose header-mbuf
 * m_data now starts at M_START), so the bcopy of each run is bounds-checked
 * against both.  m_get() allocates through the model; m_freem() is modelled.
 * The per-mbuf lengths and (off, len) are a concrete geometry per job.
 *
 * The entry point, for --function:
 *
 *   proof_copym	m_copym() of len bytes at off: each per-mbuf copy stays
 *		within the source and the fresh mbuf, and on success the copied
 *		chain's lengths sum to len.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

void m_freem(struct mbuf *m) { }

/*
 * Geometries (GEO): the source chain's per-mbuf lengths and the (off, len)
 * to copy.  0: a copy inside the first mbuf.  1: a copy starting mid-mbuf.
 * 2: a copy spanning three mbufs.
 */
#if GEO == 0
static const int g_lens[] = { 16, 8 };
#define	OFF	2
#define	LEN	8
#elif GEO == 1
static const int g_lens[] = { 16, 8 };
#define	OFF	10
#define	LEN	10
#elif GEO == 2
static const int g_lens[] = { 6, 10, 8 };
#define	OFF	3
#define	LEN	16
#elif GEO == 3			/* source near full: a too-long copy overruns it */
static const int g_lens[] = { MLEN - 2, 8 };
#define	OFF	(MLEN - 4)
#define	LEN	10
#endif

#define	NMBUF	((int)nitems(g_lens))

static struct mbuf *g_src[8];

void
proof_copym(void)
{
	struct mbuf *top, *n;
	int i, total, cnt;

	/*
	 * A source chain of real plain mapped mbufs (no M_PKTHDR, no M_EXT),
	 * each a separate CBMC object so that an over-read of one mbuf's data is
	 * an out-of-bounds access, not one masked by an adjacent array element.
	 */
	for (i = 0; i < NMBUF; i++) {
		g_src[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_src[i]->m_data = &g_src[i]->m_dat[0];
		g_src[i]->m_len = g_lens[i];
		g_src[i]->m_flags = 0;
		g_src[i]->m_type = MT_DATA;
	}
	for (i = 0; i < NMBUF; i++)
		g_src[i]->m_next = (i + 1 < NMBUF) ? g_src[i + 1] : NULL;

	top = m_copym(g_src[0], OFF, LEN, M_NOWAIT);

	if (top == NULL)
		return;			/* ENOBUFS: nothing to check */
	/*
	 * On success the copied chain holds exactly LEN bytes: each per-mbuf
	 * bcopy was bounds-checked against the source and the fresh mbuf during
	 * the call, and the lengths sum to the requested length.
	 */
	total = 0;
	cnt = 0;
	for (n = top; n != NULL && cnt < 8; n = n->m_next, cnt++) {
		__CPROVER_assert(n->m_len >= 0 && n->m_len <= M_SIZE(n),
		    "each copied mbuf's length is within its storage");
		total += n->m_len;
	}
	__CPROVER_assert(total == LEN, "the copied chain holds exactly len bytes");
}
