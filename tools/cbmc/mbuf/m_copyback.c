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
 * cbmc(1) harness for m_copyback(), sys/kern/uipc_mbuf.c: write len bytes
 * at offset off into an mbuf chain, extending the chain with freshly
 * allocated mbufs when off or len runs past the end.  Unlike m_copydata()
 * this writes, grows a mbuf into its trailing space, and allocates new
 * ones, so the write must stay within each mbuf's storage, the growth
 * must never pass the trailing room, and an allocation failure must stop
 * cleanly.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  The chain is real struct mbufs (so
 * M_START/M_SIZE/M_TRAILINGSPACE and the m_dat storage are the kernel's
 * own, and a write past m_dat is an out-of-bounds write CBMC catches),
 * and m_get() allocates a fresh one through the kern.h UMA model, which
 * may fail (M_NOWAIT).  off and len are constants per job.  bcopy() is
 * the kern.h memmove model.
 *
 * The entry point, for --function:
 *
 *   proof_copyback	m_copyback() writing len bytes at off into a chain:
 *			every write stays inside a mbuf's storage, a mbuf is
 *			grown only within its trailing room, and a failed
 *			allocation stops the walk without a write past the
 *			end.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/*
 * The chain geometries (GEO): the first mbuf's length, off and len are
 * constants per job.  GEO exercises a write inside the first mbuf, a
 * write that grows the first mbuf into its trailing room, a write past
 * the end that allocates a new mbuf, and an off past the end that
 * allocates while skipping.
 */
#if GEO == 0			/* write wholly inside the first mbuf */
#define	M0LEN	40
#define	OFF	4
#define	LEN	8
#elif GEO == 1			/* write grows the mbuf into trailing room */
#define	M0LEN	40
#define	OFF	36
#define	LEN	8
#elif GEO == 2			/* write past the end allocates a new mbuf */
#define	M0LEN	8
#define	OFF	4
#define	LEN	12
#elif GEO == 3			/* off past the end allocates while skipping */
#define	M0LEN	8
#define	OFF	20
#define	LEN	4
#elif GEO == 4			/* write at the mbuf tail: the trailing-room cap binds */
#define	M0LEN	(MLEN - 4)
#define	OFF	(MLEN - 4)
#define	LEN	12
#endif

#define	NMBUF_MAX	8		/* cap the post-walk over the chain */

static struct mbuf g_m0;
static char g_src[LEN > 0 ? LEN : 1];	/* the bytes to write in */

void
proof_copyback(void)
{
	int i;

	/*
	 * The first mbuf is a real struct mbuf with its own MLEN storage, so
	 * M_SIZE/M_TRAILINGSPACE and the bounds of the write are the
	 * kernel's.  m_get() allocates any further mbufs through the UMA
	 * model (which may return NULL, exercising the allocation-failure
	 * stop).
	 */
	bzero(&g_m0, sizeof(g_m0));
	g_m0.m_data = &g_m0.m_dat[0];		/* a plain mbuf's own storage */
	g_m0.m_len = M0LEN;
	g_m0.m_flags = 0;			/* mapped, writable, no PKTHDR */
	g_m0.m_type = MT_DATA;
	g_m0.m_next = NULL;

	for (i = 0; i < LEN; i++)
		g_src[i] = nondet_char();

	m_copyback(&g_m0, OFF, LEN, g_src);

	/*
	 * Each bcopy() destination dereference is bounds-checked against the
	 * mbuf storage, so a write past a mbuf fails during the call.  In
	 * addition, no mbuf's m_len may exceed its storage: a growth past the
	 * trailing room would leave m_len > M_SIZE(m), which a later reader
	 * trusting m_len would turn into an out-of-bounds access.
	 */
	{
		struct mbuf *m;

		for (m = &g_m0, i = 0; m != NULL && i < NMBUF_MAX;
		    m = m->m_next, i++)
			__CPROVER_assert(m->m_len <= M_SIZE(m),
			    "a mbuf's length never exceeds its storage");
	}
}
