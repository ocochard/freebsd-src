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
 * cbmc(1) harness for sbcompress(), sys/kern/uipc_sockbuf.c: appends an
 * mbuf chain to a socket buffer's tail, coalescing a small mbuf into the
 * previous one's trailing space when it fits, else linking it in.  Hit by
 * every protocol's receive path.  The coalescing copy must stay within the
 * tail mbuf's storage, and the buffer's byte count (sb_ccc) must end equal
 * to the data actually in the buffer.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_sockbuf.c or a
 * mutant of it, included whole.  The tail and the appended mbufs are real
 * struct mbufs (so the storage bounds and M_TRAILINGSPACE are the
 * kernel's, and a coalesce copy past the tail is an out-of-bounds write);
 * m_copydata() and m_free() are modelled; sballoc() runs for real.  The
 * per-mbuf lengths are a concrete geometry per job.
 *
 * The entry point, for --function:
 *
 *   proof_sbcompress	sbcompress() appending a chain to a buffer: the
 *			coalesce copy stays within the tail mbuf, and sb_ccc
 *			grows by exactly the bytes appended.
 */

#include SOURCE

#include <sys/vnode.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* m_copydata(): the coalesce copies one mbuf's bytes into n's tail. */
void
m_copydata(const struct mbuf *m, int off, int len, caddr_t cp)
{
	__CPROVER_assert(off == 0 && len == m->m_len,
	    "sbcompress copies an mbuf's bytes, all of them");
	cbmc_memmove(cp, mtod((struct mbuf *)m, char *), len);
}

/* sblastmbufchk(): a debug consistency walk; not the property under test. */
void
sblastmbufchk(struct sockbuf *sb, const char *file, int line) { }

/*
 * Geometries (GEO): the tail mbuf's length then the appended mbufs'
 * lengths, constants per job.  0: a small appendee that coalesces into the
 * tail.  1: an appendee too big to coalesce (linked).  2: two appendees.
 */
#if GEO == 0
static const int g_tail = 8;
static const int g_app[] = { 4 };
#elif GEO == 1				/* tail near full: no trailing room */
static const int g_tail = (MLEN - 6);
static const int g_app[] = { 10 };	/* 10 > 6 room: cannot coalesce */
#elif GEO == 2
static const int g_app[] = { 4, 6 };
static const int g_tail = 8;
#endif

#define	NAPP	((int)nitems(g_app))

static struct socket g_so;
static struct mbuf g_tm;		/* the buffer's existing tail */
static struct mbuf *g_am[8];		/* the appended chain */

void
proof_sbcompress(void)
{
	struct sockbuf *sb;
	struct mbuf *m, *chain;
	uint64_t pre_ccc, appended;
	int i;

	bzero(&g_so, sizeof(g_so));
	sb = &g_so.so_rcv;

	/* The buffer with one tail mbuf already in it. */
	bzero(&g_tm, sizeof(g_tm));
	g_tm.m_data = &g_tm.m_dat[0];
	g_tm.m_len = g_tail;
	g_tm.m_flags = 0;
	g_tm.m_type = MT_DATA;
	g_tm.m_next = NULL;
	sb->sb_mb = &g_tm;
	sb->sb_mbtail = &g_tm;
	sb->sb_lastrecord = &g_tm;
	sballoc(sb, &g_tm);		/* account the tail, as the buffer did */
	pre_ccc = sb->sb_ccc;

	/* The chain to append; each a real mbuf with its own storage. */
	appended = 0;
	chain = NULL;
	for (i = NAPP - 1; i >= 0; i--) {
		g_am[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_am[i]->m_data = &g_am[i]->m_dat[0];
		g_am[i]->m_len = g_app[i];
		g_am[i]->m_flags = 0;
		g_am[i]->m_type = MT_DATA;
		g_am[i]->m_next = chain;
		chain = g_am[i];
		appended += g_app[i];
	}

	sbcompress(sb, chain, sb->sb_mbtail);

	/*
	 * Every byte appended is accounted in sb_ccc, whether it was coalesced
	 * into the tail or linked in; none is lost or double-counted.  The
	 * coalesce copy was bounds-checked against the tail's storage during
	 * the call.
	 */
	__CPROVER_assert(sb->sb_ccc == pre_ccc + appended,
	    "sb_ccc grows by exactly the bytes appended");
	/* The total data walking the buffer equals sb_ccc. */
	{
		uint64_t total = 0;
		int cnt = 0;

		for (m = sb->sb_mb; m != NULL && cnt < 8; m = m->m_next, cnt++)
			total += m->m_len;
		__CPROVER_assert(total == sb->sb_ccc,
		    "the buffer's bytes match sb_ccc");
	}
}
