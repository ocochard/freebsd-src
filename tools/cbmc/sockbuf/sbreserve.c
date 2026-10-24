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
 * cbmc(1) harness for sbreserve_locked_limit(), sys/kern/uipc_sockbuf.c: the
 * socket-buffer sizing used by setsockopt(SO_RCVBUF/SO_SNDBUF) and the
 * protocols.  A requested byte count cc is capped against BUF_MAX_ADJ(buf_max)
 * so that cc * sb_efficiency cannot overflow, then the mbuf-count ceiling
 * sb_mbmax is set to min(cc * sb_efficiency, buf_max).  The cap is the
 * overflow guard; without it the mbmax multiply wraps.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_sockbuf.c or a
 * mutant of it, included whole.  cc and buf_max are nondeterministic u_long,
 * so the cap is exercised over the whole range.  chgsbsize() and lim_cur()
 * are modelled.
 *
 * The entry point, for --function:
 *
 *   proof_sbreserve	sbreserve_locked_limit() on any cc and buf_max: an
 *			accepted request has cc within the cap, its
 *			cc * sb_efficiency does not overflow, and the resulting
 *			sb_mbmax is at most buf_max; sb_lowat stays <= sb_hiwat.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* chgsbsize(): charges the uid's sb size and sets *hiwat to `to` on success. */
static int g_chg_ok;
int
chgsbsize(struct uidinfo *uip, u_int *hiwat, u_int to, rlim_t maxval)
{
	if (g_chg_ok) {
		*hiwat = to;
		return (1);
	}
	return (0);
}
/* lim_cur() is a macro and is only reached with td != NULL; the proof passes
 * td == NULL, so it needs no model. */

static struct socket g_so;
static struct ucred g_cred;
static struct uidinfo g_ui;

void
proof_sbreserve(void)
{
	u_long cc, buf_max;
	struct sockbuf *sb;
	bool r;

	cc = nondet_ulong();
	buf_max = nondet_ulong();
	/*
	 * buf_max is sb_max, a bounded sysctl (default SB_MAX = 8 MB); it is
	 * never near ULONG_MAX, where BUF_MAX_ADJ's own buf_max * MCLBYTES would
	 * overflow.  cc stays fully symbolic -- it is the attacker-chosen
	 * SO_RCVBUF value the cap must contain.
	 */
	__CPROVER_assume(buf_max <= SB_MAX);
	g_chg_ok = nondet_bool();

	bzero(&g_so, sizeof(g_so));
	bzero(&g_cred, sizeof(g_cred));
	bzero(&g_ui, sizeof(g_ui));
	g_cred.cr_uidinfo = &g_ui;
	g_so.so_cred = &g_cred;
	sb = &g_so.so_rcv;
	sb->sb_lowat = nondet_int();
	__CPROVER_assume(sb->sb_lowat >= 0);

	r = sbreserve_locked_limit(&g_so, SO_RCV, cc, buf_max, NULL);

	if (!r)
		return;			/* refused: nothing to check */
	/*
	 * Accepted: cc was within the cap, so cc * sb_efficiency did not
	 * overflow (cbmc's unsigned-overflow check on line 668 covers the
	 * multiply), and the resulting ceiling is at most buf_max.
	 */
	__CPROVER_assert(cc <= BUF_MAX_ADJ(buf_max),
	    "an accepted request is within the overflow cap");
	__CPROVER_assert(sb->sb_mbmax <= buf_max,
	    "the mbuf ceiling never exceeds buf_max");
	__CPROVER_assert(sb->sb_hiwat == cc,
	    "the high-water is the requested count");
	__CPROVER_assert(sb->sb_lowat <= sb->sb_hiwat,
	    "the low-water never exceeds the high-water");
}
