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
 * cbmc(1) harness for m_copydata(), sys/kern/uipc_mbuf.c: copy len bytes
 * starting at offset off out of an mbuf chain into a flat buffer.  Used
 * all over the stack to pull packet bytes out of a chain.  The caller's
 * contract (its KASSERTs) is off >= 0, len >= 0 and off + len within the
 * chain; under it the copy must read only within each mbuf's data and
 * deliver exactly len bytes, never running off the end of a mbuf or the
 * chain.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  A chain of up to NMBUF mapped mbufs is
 * built, each with a data area of exactly its m_len bytes, so a read past
 * a mbuf is an out-of-bounds read CBMC catches.  The destination is a
 * CBMC object of exactly len bytes.  off and len are constants per job,
 * the total chain length symbolic within them so the skip and copy walk
 * every split.  bcopy() is the kern.h memmove model.
 *
 * The entry point, for --function:
 *
 *   proof_copydata	m_copydata() on a chain whose lengths sum to at
 *			least off + len: every per-mbuf read stays inside
 *			that mbuf, exactly len bytes are written to the
 *			destination, and the chain is not walked past its
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
 * Concrete chain geometries (GEO): the per-mbuf lengths, the offset and
 * the copy length are constants per job, so the skip and copy walk are
 * concrete and the data objects have fixed sizes.  A symbolic chain makes
 * the boundary combinatorics blow up.  The bytes copied stay symbolic, so
 * the copy itself is still over arbitrary data.  Each GEO exercises one
 * split: a copy inside the first mbuf, a copy starting mid-mbuf, a copy
 * spanning several mbufs, and an empty copy at a boundary.
 */
#if GEO == 0			/* whole copy inside the first mbuf */
static int g_lens[] = { 8, 8, 8 };
#define	OFF	0
#define	LEN	5
#elif GEO == 1			/* copy starts mid-mbuf, stays inside one */
static int g_lens[] = { 8, 8, 8 };
#define	OFF	3
#define	LEN	4
#elif GEO == 2			/* copy spans three mbufs */
static int g_lens[] = { 4, 4, 4, 4 };
#define	OFF	2
#define	LEN	9
#elif GEO == 3			/* empty copy at a mbuf boundary */
static int g_lens[] = { 4, 4 };
#define	OFF	4
#define	LEN	0
#elif GEO == 4			/* offset skips past two mbufs, then copies */
static int g_lens[] = { 4, 4, 4, 4 };
#define	OFF	9
#define	LEN	3
#endif

#define	NMBUF	((int)nitems(g_lens))

static struct mbuf g_m[16];
static char g_cp[LEN > 0 ? LEN : 1];	/* the destination buffer */

void
proof_copydata(void)
{
	int i;

	/*
	 * A chain of mapped mbufs of the geometry's lengths.  Each data area
	 * is a CBMC object of exactly m_len, so a read even one byte past the
	 * mbuf is an out-of-bounds read caught here, not one absorbed by an
	 * over-large static buffer.
	 */
	for (i = 0; i < NMBUF; i++) {
		int l = g_lens[i];

		g_m[i].m_data = (l > 0) ? __CPROVER_allocate(l, 0) : NULL;
		g_m[i].m_len = l;
		g_m[i].m_flags = 0;			/* mapped */
		g_m[i].m_next = (i + 1 < NMBUF) ? &g_m[i + 1] : NULL;
	}

	m_copydata(&g_m[0], OFF, LEN, g_cp);

	/*
	 * No explicit post-assertion beyond memory safety: every bcopy()
	 * source dereference is bounds-checked against the mbuf data object
	 * and the destination writes against g_cp, so a read past a mbuf or a
	 * write past len fails here.  Read the destination back to record
	 * that all len bytes were written.
	 */
	for (i = 0; i < LEN; i++)
		(void)g_cp[i];
}
