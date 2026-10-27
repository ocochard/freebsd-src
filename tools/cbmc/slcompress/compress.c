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
 * cbmc(1) harness for the TYPE_COMPRESSED_TCP path of
 * sl_uncompress_tcp_core(), sys/net/slcompress.c: the Van Jacobson
 * compressed-header decompressor, reached from SLIP/PPP and ng_vjc receive.
 * It walks the compressed header in the wire buffer with cp, reading 1 to 3
 * bytes per changed field through the DECODE macros, and validates the
 * consumed length only afterward (vjlen = cp - buf; if (buflen < 0) bad).
 * Every cp read must stay within the wire buffer.
 *
 * Not a program: run.sh compiles it with SOURCE naming slcompress.c or a
 * mutant of it, included whole.  The wire buffer is a CBMC object of exactly
 * BUFLEN bytes, so a cp read past it is an out-of-bounds read.  The buffer
 * bytes (changes mask, state index, field encodings) are nondeterministic,
 * so every combination of changed fields and escape encodings is covered.
 * The stored cstate has a valid IPv4 header length so the th writes land in
 * the MAX_HDR store.  BUFLEN is a constant per job.
 *
 * The entry point, for --function:
 *
 *   proof_compress	sl_uncompress_tcp_core() on a compressed packet: the
 *			cp reads over the DECODE walk stay within the BUFLEN
 *			wire buffer.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static u_char g_buf[BUFLEN == 0 ? 1 : BUFLEN];
static struct slcompress g_comp;

void
proof_compress(void)
{
	struct cstate *cs;
	u_char *hdr;
	u_int hlen;
	int i, r;

	for (i = 0; i < BUFLEN; i++)
		g_buf[i] = nondet_char();
	/*
	 * Pin the changes mask (first byte) to a concrete value per job: a fully
	 * symbolic mask makes the switch/if branching over every field
	 * combination blow up.  The field-encoding bytes that follow stay
	 * nondeterministic, which is where the DECODE over-read lives.  CHANGES
	 * selects which fields are present (NEW_C for an explicit state index,
	 * the SPECIALS/NEW_* bits for the decoded fields).
	 */
	g_buf[0] = CHANGES;

	/*
	 * A well-formed stored state for the implicit/explicit connection: a
	 * minimal IPv4 header length (5 words = 20 bytes) so th lands inside the
	 * MAX_HDR store and cs_hlen is sane.  The compressed path reads the
	 * connection state, not the wire, for the header geometry.
	 */
	for (i = 0; i < MAX_STATES; i++) {
		cs = &g_comp.rstate[i];
		cs->cs_ip.ip_hl = 5;
		cs->cs_hlen = 20;
	}
	g_comp.flags = 0;
	g_comp.last_recv = 0;

	hdr = NULL;
	hlen = 0;

	r = sl_uncompress_tcp_core(g_buf, BUFLEN, BUFLEN, TYPE_COMPRESSED_TCP,
	    &g_comp, &hdr, &hlen);

	/*
	 * CBMC bounds-checks every cp read of g_buf during the call.  A return
	 * of -1 (SLF_TOSS / buflen < 0) is the rejection path; a non-negative
	 * return is a decoded packet.  Either way, if any DECODE read ran past
	 * g_buf, CBMC flags it.
	 */
	(void)r;
}
