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
 * cbmc(1) harness for sctp_unpack_auth_chunks(), sys/netinet/sctp_auth.c:
 * unpack a peer's AUTH "chunk list" parameter (from an INIT/INIT-ACK) into
 * the chklist bitmap.  Two forms by num_chunks: a flat list of num_chunks
 * bytes read one each, or (num_chunks > 32) a fixed 32-byte bitfield.  Each
 * byte read must stay within the wire buffer, and every chunk type it marks
 * (sctp_auth_add_chunk -> list->chunks[chunk]) must index the 256-entry
 * array in bounds.
 *
 * Not a program: run.sh compiles it with SOURCE naming sctp_auth.c or a
 * mutant of it, included whole.  The wire buffer is a CBMC object of exactly
 * the bytes the chosen form reads (NUM_CHUNKS bytes for the flat form, 32 for
 * the bitfield), so a read past it is an out-of-bounds read; the chklist is a
 * real sctp_auth_chklist_t, so a write past chunks[256] is caught.
 * NUM_CHUNKS is a constant per job.
 *
 * The entry point, for --function:
 *
 *   proof_unpack_auth	sctp_unpack_auth_chunks() for a given num_chunks:
 *			every byte read stays within the wire buffer and every
 *			marked chunk indexes chunks[256] in bounds.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/*
 * The wire buffer: exactly the bytes the chosen form reads.  The flat form
 * (num_chunks <= 32) reads num_chunks bytes; the bitfield form reads 32.
 */
#define	NREAD	(NUM_CHUNKS <= 32 ? NUM_CHUNKS : 32)
static uint8_t g_wire[NREAD == 0 ? 1 : NREAD];
static sctp_auth_chklist_t g_list;

void
proof_unpack_auth(void)
{
	int i;

	g_list.num_chunks = 0;
	for (i = 0; i < 256; i++)
		g_list.chunks[i] = 0;

	/*
	 * Each byte of the wire buffer is nondeterministic, so every chunk type
	 * (and bitfield pattern) is covered.  CBMC bounds-checks the reads of
	 * g_wire and the writes to g_list.chunks during the call.
	 */
	(void)sctp_unpack_auth_chunks(g_wire, (uint8_t)NUM_CHUNKS, &g_list);
}
