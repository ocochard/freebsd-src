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
 * cbmc(1) harness for sctp_serialize_hmaclist(), sys/netinet/sctp_auth.c:
 * write the local HMAC-id list out to a caller buffer for an outgoing
 * REQUESTED-HMAC-ALGO parameter.  It reads hmac[0 .. num_algo) and writes two
 * bytes each.  The read must stay within the list's max_algo-entry array
 * (num_algo <= max_algo), and the write must stay within the caller buffer
 * (num_algo * 2 bytes).
 *
 * Not a program: run.sh compiles it with SOURCE naming sctp_auth.c or a
 * mutant of it, included whole.  The list is a CBMC object of exactly
 * sizeof(sctp_hmaclist_t) + MAXALGO * sizeof(uint16_t) and the output buffer
 * of MAXALGO * 2 bytes, so a read past the array or a write past the buffer
 * is an out-of-bounds access.  num_algo is nondeterministic within [0,
 * max_algo].  MAXALGO is a constant per job.
 *
 * The entry point, for --function:
 *
 *   proof_serialize_hmac  sctp_serialize_hmaclist() on a list at any fill
 *			level: the reads stay within the hmac array and the
 *			writes within the caller buffer.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static sctp_hmaclist_t *g_list;
static uint8_t g_out[MAXALGO * 2];

void
proof_serialize_hmac(void)
{
	uint16_t num_algo;
	int i;

	g_list = __CPROVER_allocate(sizeof(sctp_hmaclist_t) +
	    MAXALGO * sizeof(uint16_t), 0);
	g_list->max_algo = MAXALGO;

	num_algo = nondet_ushort();
	/*
	 * The list invariant is num_algo <= max_algo (sctp_auth_add_hmacid()
	 * never grows num_algo past max_algo).  For the proof jobs assume it; the
	 * precondition job (NOINV) drops it to show the read would leave the
	 * array without it.
	 */
#ifndef NOINV
	__CPROVER_assume(num_algo <= MAXALGO);
#else
	__CPROVER_assume(num_algo <= MAXALGO + 4);
#endif
	g_list->num_algo = num_algo;
	/* Only MAXALGO entries are backed; fill those. */
	for (i = 0; i < MAXALGO; i++)
		g_list->hmac[i] = nondet_ushort();

	(void)sctp_serialize_hmaclist(g_list, g_out);
	/*
	 * Each iteration read hmac[i] (i < num_algo <= max_algo, within the
	 * array) and wrote two bytes at ptr (advancing by 2 per id, so
	 * num_algo * 2 bytes total, within the MAXALGO * 2 buffer); CBMC
	 * bounds-checks both against their objects during the call.
	 */
}
