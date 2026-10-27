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
 * cbmc(1) harness for the TYPE_UNCOMPRESSED_TCP path of
 * sl_uncompress_tcp_core(), sys/net/slcompress.c: the Van Jacobson TCP/IP
 * header decompressor, reached from the SLIP/PPP and ng_vjc receive paths.
 * The uncompressed path reads the IP/TCP header length from the wire buffer,
 * guards it against the buffer and the state's MAX_HDR store, then copies the
 * header into the per-connection cstate.  The length read, the th_off read,
 * and the copy must all stay within the wire buffer and the MAX_HDR store.
 *
 * Not a program: run.sh compiles it with SOURCE naming slcompress.c or a
 * mutant of it, included whole.  The wire buffer is a CBMC object of exactly
 * BUFLEN bytes, so a read past it is an out-of-bounds read; the cstate's
 * header store is MAX_HDR bytes, so a copy past it is an out-of-bounds write.
 * The header bytes are nondeterministic (so ip_hl and th_off take any value);
 * BUFLEN is a constant per job.
 *
 * The entry point, for --function:
 *
 *   proof_uncompress	sl_uncompress_tcp_core() on an uncompressed packet:
 *			the header-length read and the header copy stay within
 *			the wire buffer and the MAX_HDR store.
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
proof_uncompress(void)
{
	struct ip *ip;
	u_char *hdr;
	u_int hlen;
	int i, r;

	for (i = 0; i < BUFLEN; i++)
		g_buf[i] = nondet_char();

	/*
	 * The IP version/type byte is forced to a sane IPv4 header-length nibble
	 * range by leaving it nondeterministic; sl_uncompress_tcp_core reads
	 * ip_p (the state index) and ip_hl from it.  comp is zeroed so the state
	 * array is well-formed.
	 */
	ip = (struct ip *)g_buf;
	hdr = NULL;
	hlen = 0;

	r = sl_uncompress_tcp_core(g_buf, BUFLEN, BUFLEN, TYPE_UNCOMPRESSED_TCP,
	    &g_comp, &hdr, &hlen);

	/*
	 * On success the reads of ip_hl / th_off and the BCOPY of hlen bytes
	 * from g_buf were bounds-checked against the BUFLEN buffer, and the copy
	 * into cs_hdr against the MAX_HDR store, during the call.  The returned
	 * hlen is within the store.
	 */
	if (r == 0)
		__CPROVER_assert(hlen <= MAX_HDR,
		    "the stored header length is within the MAX_HDR store");
}
