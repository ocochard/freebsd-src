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
 * cbmc(1) harness for m_pullup(), sys/kern/uipc_mbuf.c: rearrange an mbuf
 * chain so that its first len bytes are contiguous in the head mbuf,
 * gathering them from the following mbufs.  Every protocol parser calls
 * it and then reads len bytes from the head, so the contract matters: on
 * success the head holds at least len contiguous bytes, the gather never
 * writes past the head mbuf's storage, and never reads past a source
 * mbuf.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  The chain is real struct mbufs (so the
 * m_dat storage and its bounds are the kernel's, and a gather past the
 * head is an out-of-bounds write CBMC catches); m_get() allocates through
 * the kern.h UMA model (which may fail), and m_freem() is modelled.  The
 * per-mbuf lengths and len are constants per job.  bcopy() is the kern.h
 * memmove model.
 *
 * The entry point, for --function:
 *
 *   proof_pullup	m_pullup() on a chain gathering len bytes into the
 *			head: the gather stays within the head mbuf's storage
 *			and within each source mbuf, and on a non-NULL return
 *			the head holds at least len contiguous bytes.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* m_freem(): walk and free the leftover chain (not in this TU). */
void
m_freem(struct mbuf *m)
{
	while (m != NULL)
		m = m_free(m);
}

/*
 * Geometries (GEO): per-mbuf lengths and the pull length, constants per
 * job.  0 pulls within the head (early return).  1 pulls across two
 * mbufs in place (the head has no cluster and room).  2 forces the
 * allocate-a-new-head path with a small len.  3 asks for more than MHLEN
 * on the allocate path (must fail cleanly).
 */
#if GEO == 0			/* len already contiguous: early return */
static int g_lens[] = { 20, 10 };
#define	LEN	12
#elif GEO == 1			/* pull a few bytes up from the second mbuf */
static int g_lens[] = { 6, 10 };
#define	LEN	12
#elif GEO == 2			/* gather across three mbufs in place */
static int g_lens[] = { 4, 6, 8 };
#define	LEN	16
#elif GEO == 3			/* alloc path, more than MHLEN: clean failure */
static int g_lens[] = { 2 };	/* single mbuf: no m_next, takes else */
#define	LEN	(MHLEN + 1)
#endif

#define	NMBUF	((int)nitems(g_lens))

static struct mbuf *g_m[8];

void
proof_pullup(void)
{
	struct mbuf *r, *m, *head;
	int i;

	/*
	 * A chain of real mapped mbufs, each heap allocated like the UMA
	 * allocator gives, so m_pullup()'s m_free() of a consumed mbuf is a
	 * valid deallocation.  m_data is the mbuf's own m_dat, so the
	 * gather's write bound is the kernel's own storage.  No M_PKTHDR, no
	 * M_EXT.
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

	r = m_pullup(head, LEN);

	if (r == NULL)
		return;			/* a clean failure: nothing to check */
	/*
	 * On success the head holds at least len contiguous bytes, which is
	 * what callers read, and its length never exceeds its storage.  The
	 * gather writes were bounds-checked against the head's m_dat during
	 * the call.
	 */
	__CPROVER_assert(r->m_len >= LEN,
	    "the head holds at least len contiguous bytes");
	for (m = r, i = 0; m != NULL && i < 8; m = m->m_next, i++)
		__CPROVER_assert(m->m_len <= M_SIZE(m),
		    "no mbuf's length exceeds its storage");
}
