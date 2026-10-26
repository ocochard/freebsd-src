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
 * cbmc(1) harness for m_apply(), sys/kern/uipc_mbuf.c: call a function f on
 * len bytes of an mbuf chain starting off bytes in, used by the checksum and
 * crypto paths to run over a run of packet data in place.  It skips to the
 * mbuf holding byte off, then for each mbuf hands f the sub-run
 * [m_data + off, +min(m_len - off, len)).  That range must stay within the
 * mbuf's data, so f never reads past it.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  The chain is real struct mbufs, each a
 * separate CBMC object, so a range past one mbuf's data is caught.  f is
 * pinned to the harness callback (--restrict-function-pointer), which checks
 * the run it is handed lies within the mbuf and counts the bytes covered.
 * The plain (non-M_EXTPG) path is driven; the per-mbuf lengths and (off, len)
 * are a concrete geometry per job.
 *
 * The entry point, for --function:
 *
 *   proof_apply	m_apply() over (off, len): each sub-run handed to f lies
 *		within the mbuf's data, and the runs cover exactly len bytes.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/*
 * Geometries (GEO): the chain's per-mbuf lengths and the (off, len) to apply.
 * 0: a run inside the first mbuf.  1: a run starting mid-mbuf.  2: a run
 * spanning three mbufs.  3: off and len reaching the last byte of the chain.
 */
#if GEO == 0
static const int g_lens[] = { 16, 8 };
#define	OFF	2
#define	APLEN	8
#elif GEO == 1
static const int g_lens[] = { 16, 8 };
#define	OFF	10
#define	APLEN	10
#elif GEO == 2
static const int g_lens[] = { 6, 10, 8 };
#define	OFF	3
#define	APLEN	16
#elif GEO == 3
static const int g_lens[] = { 8, 8 };
#define	OFF	4
#define	APLEN	12
#elif GEO == 4			/* first mbuf near MLEN: a too-long run overruns it */
static const int g_lens[] = { MLEN - 2, 8 };
#define	OFF	(MLEN - 4)
#define	APLEN	10
#endif

#define	NMBUF	((int)nitems(g_lens))

static struct mbuf *g_chain[8];
static int g_covered;		/* bytes f was handed, summed */

/*
 * The callback m_apply runs.  It is handed p = m_data + off and the sub-run
 * length; touch the first and last byte so CBMC bounds-checks the run against
 * the mbuf object, and count the bytes.
 */
static int
cbmc_apply_f(void *arg, void *p, u_int len)
{
	if (len != 0) {
		((volatile char *)p)[0];
		((volatile char *)p)[len - 1];
	}
	g_covered += (int)len;
	return (0);
}

void
proof_apply(void)
{
	int i, rval;

	/*
	 * A chain of plain mapped mbufs (no M_PKTHDR, no M_EXT, no M_EXTPG),
	 * each a separate CBMC object so an over-read of one mbuf's data is an
	 * out-of-bounds access, not one masked by an adjacent element.
	 */
	for (i = 0; i < NMBUF; i++) {
		g_chain[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_chain[i]->m_data = &g_chain[i]->m_dat[0];
		g_chain[i]->m_len = g_lens[i];
		g_chain[i]->m_flags = 0;
		g_chain[i]->m_type = MT_DATA;
	}
	for (i = 0; i < NMBUF; i++)
		g_chain[i]->m_next = (i + 1 < NMBUF) ? g_chain[i + 1] : NULL;

	g_covered = 0;
	rval = m_apply(g_chain[0], OFF, APLEN, cbmc_apply_f, NULL);

	/*
	 * Each sub-run handed to f was bounds-checked against its mbuf during
	 * the call.  f never fails here, so m_apply returns 0 and the sub-runs
	 * cover exactly APLEN bytes.
	 */
	__CPROVER_assert(rval == 0, "the walk completes");
	__CPROVER_assert(g_covered == APLEN,
	    "the sub-runs cover exactly len bytes");
}
