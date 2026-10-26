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
 * cbmc(1) harness for sctp_auth_add_hmacid(), sys/netinet/sctp_auth.c: append
 * an HMAC algorithm id to the hmaclist, used when building the local list and
 * when accepting a peer's.  The list holds a flexible hmac[] array of
 * max_algo entries; the append writes hmac[num_algo++], guarded by a full
 * check (num_algo == max_algo).  The write must stay within the max_algo
 * entries allocated.
 *
 * Not a program: run.sh compiles it with SOURCE naming sctp_auth.c or a
 * mutant of it, included whole.  The list is a CBMC object of exactly
 * sizeof(sctp_hmaclist_t) + MAXALGO * sizeof(uint16_t), so a write past
 * hmac[MAXALGO) is an out-of-bounds write.  num_algo is nondeterministic
 * within [0, max_algo] and the existing ids are nondeterministic, so every
 * fill level and dup state is covered.  MAXALGO is a constant per job.
 *
 * The entry point, for --function:
 *
 *   proof_add_hmacid	sctp_auth_add_hmacid() on a list at any fill level:
 *			the append writes within the max_algo-entry array.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static sctp_hmaclist_t *g_list;

void
proof_add_hmacid(void)
{
	uint16_t num_algo, hmac_id;
	int i;

	/*
	 * A list with hmac[] backed for exactly MAXALGO entries, so a write past
	 * the array is an out-of-bounds access.
	 */
	g_list = __CPROVER_allocate(sizeof(sctp_hmaclist_t) +
	    MAXALGO * sizeof(uint16_t), 0);
	g_list->max_algo = MAXALGO;

	num_algo = nondet_ushort();
	__CPROVER_assume(num_algo <= MAXALGO);
	g_list->num_algo = num_algo;
	for (i = 0; i < num_algo; i++)
		g_list->hmac[i] = nondet_ushort();

	hmac_id = nondet_ushort();

	(void)sctp_auth_add_hmacid(g_list, hmac_id);
	/*
	 * If the append happened it wrote hmac[old num_algo], which the full
	 * check kept below max_algo; CBMC bounds-checks that write against the
	 * MAXALGO-entry object during the call.
	 */
}
