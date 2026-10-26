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
 * cbmc(1) harness for m_append(), sys/kern/uipc_mbuf.c: append len bytes of
 * cp to the end of an mbuf chain, used across the stack to grow a packet.
 * It fills the trailing space of the last mbuf first (up to M_TRAILINGSPACE),
 * then allocates fresh mbufs for the remainder, min(MLEN, remainder) bytes
 * each.  Each copy must read only within the source buffer and write only
 * within the destination mbuf; the trailing fill must never exceed the last
 * mbuf's storage.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  The source buffer is a CBMC object of
 * exactly LEN bytes, so a copy that reads past it is an out-of-bounds read;
 * each mbuf is a separate object, so a write past one is caught.  m_get()
 * allocates through the UMA model; bcopy is cbmc's own (the copy sizes are
 * bounded by LEN, kept small per job).  The destination chain's lengths and
 * LEN are a concrete geometry per job.
 *
 * The entry point, for --function:
 *
 *   proof_append	m_append() of LEN bytes onto the chain: every copy
 *			stays within the source buffer and the destination
 *			mbuf, and on success (return 1) the whole LEN was
 *			appended.
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
 * Geometries (GEO): the destination chain's per-mbuf used lengths and LEN,
 * the number of bytes to append.  0: fits in the last mbuf's trailing space.
 * 1: trailing space of 2, the rest spills to a fresh mbuf.  2: the last mbuf
 * is full (no trailing space), all bytes go to a fresh mbuf.  3: a two-mbuf
 * destination, the append spills off the end into a fresh mbuf.
 */
#if GEO == 0
static const int g_lens[] = { 4 };
#define	LEN	6
#elif GEO == 1
static const int g_lens[] = { MLEN - 2 };
#define	LEN	10
#elif GEO == 2
static const int g_lens[] = { MLEN };
#define	LEN	8
#elif GEO == 3
static const int g_lens[] = { 8, MLEN - 3 };
#define	LEN	9
#endif

#define	CNT	((int)nitems(g_lens))

static struct mbuf *g_dst[4];
static char g_src[LEN == 0 ? 1 : LEN];

void
proof_append(void)
{
	struct mbuf *m, *n;
	int i, total, cnt, ret;

	/*
	 * A destination chain of plain mapped mbufs (no M_PKTHDR, no M_EXT),
	 * each a separate CBMC object so an over-write of one mbuf's storage is
	 * an out-of-bounds access, not one masked by an adjacent element.
	 */
	for (i = 0; i < CNT; i++) {
		g_dst[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_dst[i]->m_data = &g_dst[i]->m_dat[0];
		g_dst[i]->m_len = g_lens[i];
		g_dst[i]->m_flags = 0;
		g_dst[i]->m_type = MT_DATA;
	}
	for (i = 0; i < CNT; i++)
		g_dst[i]->m_next = (i + 1 < CNT) ? g_dst[i + 1] : NULL;

	ret = m_append(g_dst[0], LEN, g_src);

	/*
	 * Every bcopy was bounds-checked against g_src (LEN bytes) and each
	 * destination mbuf during the call.  On success the whole LEN was
	 * appended, so the chain's used lengths grew by exactly LEN; a short
	 * allocation returns 0 and appends a prefix, which is still in bounds.
	 */
	total = 0;
	cnt = 0;
	for (m = g_dst[0]; m != NULL && cnt < 8; m = m->m_next, cnt++) {
		__CPROVER_assert(m->m_len >= 0 && m->m_len <= M_SIZE(m),
		    "each mbuf's length is within its storage");
		total += m->m_len;
		n = m;
	}
	if (ret == 1) {
		int base = 0;
		for (i = 0; i < CNT; i++)
			base += g_lens[i];
		__CPROVER_assert(total == base + LEN,
		    "on success the whole length was appended");
	}
}
