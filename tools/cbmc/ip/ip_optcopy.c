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
 * cbmc(1) harness for ip_optcopy(), sys/netinet/ip_options.c: copy the
 * "copied" IP options from one header to another, used when building
 * fragments.  It walks the source options (already validated by
 * ip_dooptions, so well-formed) and bcopy()s each IPOPT_COPIED option into
 * the destination option area, then pads to a 4-byte boundary.  Both the
 * source reads and the destination writes must stay within the 40-byte
 * option areas.
 *
 * Not a program: run.sh compiles it with SOURCE naming ip_options.c or a
 * mutant of it, included whole.  The source and destination headers each own
 * exactly MAX_IPOPTLEN option bytes as CBMC objects, so a read or write past
 * the option area is an out-of-bounds access CBMC catches.  The source
 * options are a well-formed concrete layout per job (as ip_dooptions would
 * have accepted); their data bytes stay nondeterministic.
 *
 * The entry point, for --function:
 *
 *   proof_optcopy	ip_optcopy() on a well-formed source option area: every
 *			source read and destination write stays within the
 *			option area, and the returned length is at most
 *			MAX_IPOPTLEN.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* Source and destination packets: an IP header then MAX_IPOPTLEN option
 * bytes, each a CBMC object sized to exactly the header plus option area. */
static union { struct ip ip; char b[sizeof(struct ip) + MAX_IPOPTLEN]; } g_s;
static union { struct ip ip; char b[sizeof(struct ip) + MAX_IPOPTLEN]; } g_d;

void
proof_optcopy(void)
{
	u_char *opt;
	int i, len;

	bzero(&g_s, sizeof(g_s));
	bzero(&g_d, sizeof(g_d));
	opt = (u_char *)(&g_s.ip + 1);

	/*
	 * A well-formed source option layout (OPTLEN total, 4-aligned as ip_hl
	 * requires), as ip_dooptions would have left it: one option of length
	 * OPTLEN filling the area, a "copied" type so it is copied.  Its payload
	 * bytes are nondeterministic.  (OPTLEN in {4, 8, 40}.)
	 */
	opt[IPOPT_OPTVAL] = IPOPT_SSRR;		/* 0x89: IPOPT_COPIED set */
	opt[IPOPT_OLEN] = OPTLEN;
	for (i = 2; i < OPTLEN; i++)
		opt[i] = nondet_char();
	g_s.ip.ip_hl = (sizeof(struct ip) + OPTLEN) >> 2;

	len = ip_optcopy(&g_s.ip, &g_d.ip);

	/*
	 * Every bcopy(cp, dp, optlen) source read and destination write was
	 * bounds-checked against the option-area objects during the call.  The
	 * returned length never exceeds the destination option area.
	 */
	__CPROVER_assert(len >= 0 && len <= MAX_IPOPTLEN,
	    "the copied option length fits the option area");
}
