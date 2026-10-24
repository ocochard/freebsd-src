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
 * cbmc(1) harness for m_pulldown(), sys/kern/uipc_mbuf2.c: make len bytes
 * starting at offset off contiguous in a single mbuf, gathering a head
 * piece from the mbuf holding off and a tail piece from the next, used by
 * every protocol that parses a header spanning mbufs.  On success it
 * returns the mbuf (and, via offp, the offset) where the len contiguous
 * bytes live; the gathering copies must stay within each mbuf's storage.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf2.c or a
 * mutant of it, included whole.  The chain is real struct mbufs, so the
 * storage bounds and M_TRAILINGSPACE/M_LEADINGSPACE are the kernel's, and a
 * gather past an mbuf is an out-of-bounds access CBMC catches.  m_get()/
 * m_dup1() allocate through the kern.h UMA model; m_copydata() is modelled.
 * off, len and the per-mbuf lengths are a concrete geometry per job, with
 * len <= MLEN so the single-mbuf allocation path is taken (the cluster path
 * is the same logic at a larger size).
 *
 * The entry point, for --function:
 *
 *   proof_pulldown	m_pulldown() for len bytes at off: the gather copies
 *			stay within the mbufs, and on a non-NULL return the
 *			result mbuf holds len contiguous bytes at the returned
 *			offset.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* m_copydata(): the tail gather copies one or more mbufs' bytes out. */
void
m_copydata(const struct mbuf *m, int off, int len, caddr_t cp)
{
	const struct mbuf *n = m;
	int o = off, l = len;

	while (l > 0 && n != NULL) {
		int c = n->m_len - o;

		if (c > l)
			c = l;
		if (c > 0) {
			cbmc_memmove(cp, mtod((struct mbuf *)n, char *) + o, c);
			cp += c;
			l -= c;
		}
		o = 0;
		n = n->m_next;
	}
}

void m_freem(struct mbuf *m) { }
void
m_adj(struct mbuf *mp, int req_len)
{
	/* Drops req_len bytes off the front; the harness tracks lengths. */
	if (mp != NULL) {
		mp->m_data += req_len;
		mp->m_len -= req_len;
	}
}

/*
 * Geometries (GEO): the chain's per-mbuf lengths and the (off, len) to pull.
 * 0: the bytes are already contiguous in the first mbuf (early ok).  1: a
 * pull inside one mbuf but at a non-zero off (chop via m_dup1).  2: a pull
 * spanning the head mbuf's tail and the next, gathered into fresh space.
 */
#if GEO == 0
static const int g_lens[] = { 16, 8 };
#define	OFF	2
#define	LEN	8
#elif GEO == 1
static const int g_lens[] = { 16, 8 };
#define	OFF	4
#define	LEN	10
#elif GEO == 2
static const int g_lens[] = { 10, 10, 8 };
#define	OFF	4
#define	LEN	12
#endif

#define	NMBUF	((int)nitems(g_lens))

static struct mbuf *g_m[8];

void
proof_pulldown(void)
{
	struct mbuf *r;
	int i, offp, total;

	for (i = 0; i < NMBUF; i++) {
		g_m[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_m[i]->m_data = &g_m[i]->m_dat[0];
		g_m[i]->m_len = g_lens[i];
		g_m[i]->m_flags = 0;
		g_m[i]->m_type = MT_DATA;
	}
	for (i = 0; i < NMBUF; i++)
		g_m[i]->m_next = (i + 1 < NMBUF) ? g_m[i + 1] : NULL;

	offp = -1;
	r = m_pulldown(g_m[0], OFF, LEN, &offp);

	if (r == NULL)
		return;			/* too short / ENOBUFS: nothing to check */
	/*
	 * On success the result mbuf holds the requested len contiguous bytes
	 * starting at the returned offset: offp + len fits within r's m_len,
	 * and that stays within r's storage.  The gather copies were
	 * bounds-checked against the mbufs during the call.
	 */
	__CPROVER_assert(offp >= 0 && offp + LEN <= r->m_len,
	    "len contiguous bytes live at the returned offset");
	__CPROVER_assert(r->m_len <= M_SIZE(r),
	    "the result mbuf's length is within its storage");
	(void)total;
}
