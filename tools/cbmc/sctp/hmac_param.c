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
 * cbmc(1) harness for sctp_verify_hmac_param(), sys/netinet/sctp_auth.c: the
 * scan of a peer's HMAC-algorithm list (from an INIT/INIT-ACK parameter) for
 * the mandatory SHA1.  The caller derives num_hmacs from the parameter length
 * plen as (plen - sizeof(*hmacs)) / sizeof(hmac_ids[0]); the scan then reads
 * hmac_ids[0..num_hmacs), which must stay within the plen-byte parameter
 * buffer.
 *
 * Not a program: run.sh compiles it with SOURCE naming sctp_auth.c or a
 * mutant of it, included whole.  The parameter buffer is a CBMC object of
 * exactly PLEN bytes, so a read past it is an out-of-bounds read.  PLEN is a
 * constant per job, with num_hmacs derived from it exactly as the caller
 * does.  The caller's guard plen >= sizeof(struct sctp_paramhdr) (which
 * equals sizeof(*hmacs), so plen - sizeof(*hmacs) does not underflow) is
 * reproduced here for the proof jobs.
 *
 * The entry point, for --function:
 *
 *   proof_hmac_param	sctp_verify_hmac_param() over a PLEN-byte parameter:
 *			the hmac_ids scan stays within the buffer.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static uint8_t g_store[PLEN == 0 ? 1 : PLEN];

void
proof_hmac_param(void)
{
	struct sctp_auth_hmac_algo *hmacs;
	int num_hmacs;

	hmacs = (struct sctp_auth_hmac_algo *)g_store;
	/*
	 * The caller's length arithmetic, verbatim.  PLEN >= sizeof(*hmacs) by
	 * the caller's paramhdr guard, so this does not underflow.
	 */
	num_hmacs = (PLEN - sizeof(*hmacs)) / sizeof(hmacs->hmac_ids[0]);

	(void)sctp_verify_hmac_param(hmacs, num_hmacs);
	/*
	 * The scan reads hmac_ids[0 .. num_hmacs), i.e. bytes
	 * [sizeof(*hmacs), sizeof(*hmacs) + 2 * num_hmacs) of g_store, which is
	 * within the PLEN-byte object; CBMC bounds-checks each hmac_ids[i] read
	 * during the call.
	 */
}
