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
 * cbmc(1) harness for sctp_m_getptr(), sys/netinet/sctputil.c: fetch len
 * bytes starting at offset off of an mbuf chain, returning an in-place
 * pointer when the run is contiguous or copying it into the caller buffer
 * in_ptr when it spans mbufs.  It is the copy behind every SCTP wire-param
 * parse (ASCONF, AUTH, INIT), so a bad bound over-reads the packet or
 * over-writes the caller's fixed param buffer.  Each per-mbuf copy must read
 * only within the mbuf and write only within in_ptr.
 *
 * Not a program: run.sh compiles it with SOURCE naming sctputil.c or a mutant
 * of it, included whole.  The chain is real struct mbufs, each a separate
 * CBMC object, and in_ptr is an object of exactly LEN bytes, so a read past
 * an mbuf or a write past in_ptr is an out-of-bounds access.  The per-mbuf
 * lengths and (OFF, LEN) are a concrete geometry per job.
 *
 * The entry point, for --function:
 *
 *   proof_getptr	sctp_m_getptr() for (OFF, LEN): on the spanning path
 *			each per-mbuf copy stays within the mbuf and in_ptr, and
 *			a full fetch copies exactly LEN bytes.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/*
 * Geometries (GEO): the chain's per-mbuf lengths and the (off, len) to fetch.
 * 0: a fetch contiguous in the first mbuf (in-place return).  1: a fetch
 * spanning two mbufs (copy path).  2: a fetch spanning three mbufs.  3: the
 * first mbuf near MLEN with off at its tail, so a too-long per-mbuf copy
 * would leave it.
 */
#if GEO == 0
static const int g_lens[] = { 16, 8 };
#define	OFF	2
#define	LEN	8
#elif GEO == 1
static const int g_lens[] = { 10, 10 };
#define	OFF	6
#define	LEN	8
#elif GEO == 2
static const int g_lens[] = { 6, 6, 8 };
#define	OFF	3
#define	LEN	14
#elif GEO == 3
static const int g_lens[] = { MLEN, 8 };
#define	OFF	(MLEN - 4)
#define	LEN	10
#endif

#define	NMBUF	((int)nitems(g_lens))

static struct mbuf *g_chain[8];
static uint8_t g_dst[LEN == 0 ? 1 : LEN];

void
proof_getptr(void)
{
	caddr_t r;
	int i;

	for (i = 0; i < NMBUF; i++) {
		g_chain[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_chain[i]->m_data = &g_chain[i]->m_dat[0];
		g_chain[i]->m_len = g_lens[i];
		g_chain[i]->m_flags = 0;
		g_chain[i]->m_type = MT_DATA;
	}
	for (i = 0; i < NMBUF; i++)
		g_chain[i]->m_next = (i + 1 < NMBUF) ? g_chain[i + 1] : NULL;

	r = sctp_m_getptr(g_chain[0], OFF, LEN, g_dst);

	/*
	 * Each per-mbuf memcpy was bounds-checked against the source mbuf and
	 * the LEN-byte g_dst during the call.  A NULL return means the chain was
	 * too short; otherwise the fetch succeeded -- either an in-place pointer
	 * into the chain, or g_dst holding the LEN copied bytes.
	 */
	(void)r;
}
