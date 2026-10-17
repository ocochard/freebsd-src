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
 * cbmc(1) harness for tcp_dooptions(), sys/netinet/tcp_input.c: the
 * parser of a TCP segment's options, driven straight off the wire by any
 * remote peer.
 *
 * Not a program: run.sh compiles it with SOURCE naming tcp_input.c or a
 * mutant of it, included whole; CBMC drives only tcp_dooptions().  The
 * reference is RFC 9293 3.1 (option format), RFC 7323 (window scale,
 * timestamps), RFC 2018 (SACK) and the callers' contract: cnt is
 * (th_off << 2) - sizeof(struct tcphdr), so 0..40, and cp points at that
 * many peer-controlled bytes.  The one entry point, for --function:
 *
 *   proof_dooptions	tcp_dooptions() on an option buffer of CNT bytes
 *			(a constant per job, 0..40), SYN or not: no read
 *			outside the buffer, and
 *			every TOF_* flag set implies an option of the right
 *			length whose saved pointer (SACK, signature, TFO
 *			cookie) lies within the buffer
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include "kern.h"

#define	OPTMAX	40		/* MAX_TCPOPTLEN */
#ifndef CNT
#define	CNT	OPTMAX		/* option bytes: a constant per job, as a
				   symbolic 0..40 stream ran past 40 minutes */
#endif

/* The sysctls the parser reads; VNET() is identity without VIMAGE. */
int tcp_do_sack = 1;
unsigned int tcp_fastopen_client_enable = 1;
unsigned int tcp_fastopen_server_enable = 1;

static u_char g_opt[OPTMAX];

/*
 * The front option fills the buffer: its optlen (NOP aside) equals cnt, so
 * nothing after it can set or clear the same flag, and the value asserted
 * is this option's.
 */
static int
first_opt_clean(int cnt)
{
	return (g_opt[0] == TCPOPT_NOP ? 0 :
	    (cnt >= 2 && g_opt[1] == cnt));
}

void
proof_dooptions(void)
{
	struct tcpopt to;
	int cnt, flags, i;

	cnt = CNT;
	for (i = 0; i < OPTMAX; i++)
		g_opt[i] = nondet_int();
	flags = nondet_int();

	tcp_dooptions(&to, g_opt, cnt, flags);

	/*
	 * A single well-formed option at the front: tcp_dooptions() parses
	 * its value exactly as the bytes say.  (cnt and the bytes are still
	 * free; this keys off what the option header holds.)
	 */
	if (cnt >= 4 && g_opt[0] == TCPOPT_MAXSEG && g_opt[1] == TCPOLEN_MAXSEG &&
	    (flags & TO_SYN) && first_opt_clean(cnt))
		__CPROVER_assert((to.to_flags & TOF_MSS) &&
		    to.to_mss == (uint16_t)((g_opt[2] << 8) | g_opt[3]),
		    "MSS is the two option bytes, network order");
	if (cnt >= 3 && g_opt[0] == TCPOPT_WINDOW && g_opt[1] == TCPOLEN_WINDOW &&
	    (flags & TO_SYN) && first_opt_clean(cnt))
		__CPROVER_assert((to.to_flags & TOF_SCALE) &&
		    to.to_wscale == ulmin(g_opt[2], TCP_MAX_WINSHIFT),
		    "window scale is min(byte, 14)");
	if (cnt >= 2 && g_opt[0] == TCPOPT_SACK && g_opt[1] >= 2 + TCPOLEN_SACK &&
	    g_opt[1] <= cnt && (g_opt[1] - 2) % TCPOLEN_SACK == 0 &&
	    !(flags & TO_SYN) && first_opt_clean(cnt))
		__CPROVER_assert((to.to_flags & TOF_SACK) &&
		    to.to_nsacks == (g_opt[1] - 2) / TCPOLEN_SACK,
		    "the SACK block count is (optlen - 2) / 8");
	if (cnt >= 2 && g_opt[0] == TCPOPT_FAST_OPEN && g_opt[1] >= 2 &&
	    g_opt[1] <= cnt && (flags & TO_SYN) && first_opt_clean(cnt))
		__CPROVER_assert((to.to_flags & TOF_FASTOPEN) &&
		    to.to_tfo_len == g_opt[1] - 2,
		    "the TFO cookie length is optlen - 2");
	/* An option stream that starts with EOL yields no flags. */
	if (cnt >= 1 && g_opt[0] == TCPOPT_EOL)
		__CPROVER_assert(to.to_flags == 0,
		    "EOL ends the options before any is parsed");
	/*
	 * A front MSS option whose length is not TCPOLEN_MAXSEG is not
	 * accepted: the option-length check rejects it.  (A later option
	 * cannot set TOF_MSS: only MSS does, and the front one fills the
	 * buffer.)
	 */
	if (cnt >= 2 && g_opt[0] == TCPOPT_MAXSEG && g_opt[1] >= 2 &&
	    g_opt[1] != TCPOLEN_MAXSEG && g_opt[1] == cnt && (flags & TO_SYN))
		__CPROVER_assert((to.to_flags & TOF_MSS) == 0,
		    "an MSS option of the wrong length is rejected");

	/* Every pointer saved lies within the bytes the peer sent. */
	if (to.to_flags & TOF_SACK) {
		__CPROVER_assert(to.to_nsacks >= 1 &&
		    to.to_sacks >= g_opt &&
		    to.to_sacks + (size_t)to.to_nsacks * TCPOLEN_SACK <=
		    g_opt + cnt, "SACK blocks lie within the options");
	}
	if (to.to_flags & TOF_SIGNATURE)
		__CPROVER_assert(to.to_signature >= g_opt &&
		    to.to_signature + 16 <= g_opt + cnt,
		    "the signature lies within the options");
	if (to.to_flags & TOF_FASTOPEN)
		__CPROVER_assert(to.to_tfo_cookie == NULL ||
		    (to.to_tfo_cookie >= g_opt &&
		    to.to_tfo_cookie + to.to_tfo_len <= g_opt + cnt),
		    "the TFO cookie lies within the options");
	if (to.to_flags & TOF_MSS)
		__CPROVER_assert((flags & TO_SYN) != 0,
		    "MSS only from a SYN");
	if (to.to_flags & TOF_SCALE)
		__CPROVER_assert((flags & TO_SYN) != 0 &&
		    to.to_wscale <= TCP_MAX_WINSHIFT,
		    "window scale only from a SYN, within its max");
}
