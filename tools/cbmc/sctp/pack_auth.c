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
 * cbmc(1) harness for sctp_serialize_auth_chunks() and
 * sctp_pack_auth_chunks(), sys/netinet/sctp_auth.c: write the chklist bitmap
 * out to a caller buffer for an outgoing INIT/INIT-ACK AUTH parameter.
 * serialize writes one byte per set chunk (the caller gives room for up to
 * 256).  pack writes one byte per set chunk when num_chunks <= 32, else a
 * fixed 32-byte bitfield.  Each write must stay within the caller buffer.
 *
 * The chklist invariant sctp_auth_add_chunk() maintains is num_chunks ==
 * (number of set entries in chunks[]).  Under it, the flat pack form writes
 * exactly num_chunks <= 32 bytes, so a 32-byte buffer suffices.  This harness
 * builds the list with that invariant and sizes the pack buffer to 32; a
 * mutant that lets num_chunks understate the set count overruns it.
 *
 * Not a program: run.sh compiles it with SOURCE naming sctp_auth.c or a
 * mutant of it, included whole.  The output buffer is a CBMC object of
 * exactly its contract size (256 for serialize, 32 for pack), so a write
 * past it is an out-of-bounds write.  WHICH selects the routine; the chunk
 * bitmap is nondeterministic.
 *
 * The entry points, for --function:
 *
 *   proof_serialize	sctp_serialize_auth_chunks() into a 256-byte buffer:
 *			every write stays within it.
 *   proof_pack	sctp_pack_auth_chunks() into a buffer of its contract size:
 *			every write stays within it, given the chklist invariant.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static sctp_auth_chklist_t g_list;

/*
 * Fill chunks[] nondeterministically and set num_chunks to the true count of
 * set entries, as sctp_auth_add_chunk() maintains it.
 */
static void
build_list(void)
{
	int i, n;

	n = 0;
	for (i = 0; i < 256; i++) {
		g_list.chunks[i] = nondet_bool() ? 1 : 0;
		if (g_list.chunks[i] != 0)
			n++;
	}
	/*
	 * num_chunks is a uint8_t counting the set entries, so the invariant
	 * num_chunks == set count holds only while the count fits a uint8_t.
	 * sctp_auth_add_chunk() rejects the restricted chunk types, so not every
	 * entry can be set and the count never reaches 256 (where the uint8_t
	 * would wrap to 0 and mis-select the flat path); assume that bound.
	 */
	__CPROVER_assume(n <= 255);
	g_list.num_chunks = (uint8_t)n;
}

#ifdef SERIALIZE
/* serialize may write up to 256 bytes (one per set chunk). */
static uint8_t g_out[256];

void
proof_serialize(void)
{
	build_list();
	(void)sctp_serialize_auth_chunks(&g_list, g_out);
}
#endif

#ifdef PACK
/*
 * pack writes num_chunks bytes on the flat path (num_chunks <= 32) or a
 * 32-byte bitfield, so a 32-byte buffer is the contract size for both.
 *
 * NSET is a concrete count of set chunks per job (a fully symbolic 256-bit
 * bitmap makes the popcount reasoning blow up SAT).  The set entries are the
 * first NSET indices, and num_chunks is NSET, keeping the chklist invariant.
 * NSET sweeps the flat path (few, and the 32 boundary) and the bitfield path
 * (> 32).
 */
static uint8_t g_out[32];

void
proof_pack(void)
{
	int i;

	for (i = 0; i < 256; i++)
		g_list.chunks[i] = (i < NSET) ? 1 : 0;
	g_list.num_chunks = (uint8_t)NSET;

	(void)sctp_pack_auth_chunks(&g_list, g_out);
}
#endif
