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
 * cbmc(1) harness for tcp_addoptions(), sys/netinet/tcp_output.c: the TCP
 * option writer, the complement to tcp_dooptions().  It assembles the
 * requested options (MSS, window scale, SACK-permitted, timestamp,
 * signature, SACK blocks, TFO cookie) into the fixed TCP_MAXOLEN-byte
 * option area, padding with NOPs for alignment, and returns the length.
 * Every write must stay within the option area; the per-option room checks
 * and the SACK-block clamp are the guard.
 *
 * Not a program: run.sh compiles it with SOURCE naming tcp_output.c or a
 * mutant of it, included whole.  The option area is a CBMC object of exactly
 * TCP_MAXOLEN bytes, so a write past it is an out-of-bounds write CBMC
 * catches.  The requested option set (to_flags) and the attacker-influenced
 * counts (to_nsacks, to_tfo_len) are nondeterministic, so every option
 * combination is explored.  bcopy() is the kern.h model.
 *
 * The entry point, for --function:
 *
 *   proof_addoptions	tcp_addoptions() for any requested option set: every
 *			write stays within the TCP_MAXOLEN option area and the
 *			returned length is at most TCP_MAXOLEN.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static u_char g_optp[TCP_MAXOLEN];	/* the option area: exactly MAXOLEN */
static struct sackblk g_sacks[TCP_MAX_SACK];
static uint8_t g_tfo[TCP_FASTOPEN_MAX_COOKIE_LEN];

void
proof_addoptions(void)
{
	struct tcpopt to;
	int optlen;

	bzero(&to, sizeof(to));
	/*
	 * Any subset of the defined option flags the writer handles.  The
	 * reserved bits in the TOF_ space have no case and hit the default
	 * panic; the callers never set them, so restrict to the real flags.
	 */
	to.to_flags = nondet_uint() & (TOF_MSS | TOF_SCALE | TOF_SACKPERM |
	    TOF_TS | TOF_SIGNATURE | TOF_SACK | TOF_FASTOPEN);
	to.to_mss = nondet_ushort();
	to.to_wscale = nondet_uint();
	to.to_tsval = nondet_uint();
	to.to_tsecr = nondet_uint();
	to.to_sacks = (u_char *)g_sacks;
	to.to_nsacks = nondet_uint();		/* attacker-influenced count */
	/*
	 * to_nsacks is bounded by TCP_MAX_SACK upstream (tcp_dooptions holds
	 * to_nsacks <= 4, proved separately), and to_sacks points at that many
	 * blocks.  Without this the harness would read past g_sacks.
	 */
	__CPROVER_assume(to.to_nsacks <= TCP_MAX_SACK);
	to.to_tfo_cookie = g_tfo;
	to.to_tfo_len = nondet_uint();		/* attacker-influenced length */
	/* The TFO cookie length cannot exceed its buffer. */
	__CPROVER_assume(to.to_tfo_len <= sizeof(g_tfo));

	optlen = tcp_addoptions(&to, g_optp);

	/*
	 * No explicit assertion beyond memory safety and the function's own
	 * KASSERT(optlen <= TCP_MAXOLEN): every *optp++ and bcopy(..., optp, n)
	 * is bounds-checked against g_optp, so a write past the option area
	 * fails here.  Record the length.
	 */
	__CPROVER_assert(optlen >= 0 && optlen <= TCP_MAXOLEN,
	    "the option length never exceeds the option area");
}
