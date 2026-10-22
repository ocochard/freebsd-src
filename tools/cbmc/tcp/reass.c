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
 * cbmc(1) harness for the TCP reassembly accounting helpers of
 * sys/netinet/tcp_reass.c: tcp_reass_prepend(), which splices a new
 * segment in front of an existing out-of-order segment and trims the
 * overlap, and tcp_reass_append(), which tacks a new segment onto the end
 * of one.  These maintain each queued segment's (start, len) over the
 * sequence space; a wrong trim double-counts or loses bytes.
 *
 * Not a program: run.sh compiles it with SOURCE naming tcp_reass.c or a
 * mutant of it, included whole.  m_adj() is modelled (it only trims the
 * mbuf, whose byte contents the accounting does not depend on); the stat
 * macros are compiled out.  The sequence numbers and lengths are
 * nondeterministic, bounded so the trim arithmetic cannot wrap.
 *
 * The entry points, for --function:
 *
 *   proof_prepend	tcp_reass_prepend() in front of a segment: afterwards
 *			the segment starts at the new sequence and still ends
 *			where the two together reach, with the overlap trimmed
 *			exactly once.
 *   proof_append	tcp_reass_append() onto a segment: afterwards its
 *			length grew by exactly the appended length and its
 *			start is unchanged.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* m_adj(): drops req_len bytes off the front; the accounting tracks len. */
void
m_adj(struct mbuf *mp, int req_len)
{
	if (mp != NULL)
		mp->m_len -= req_len;
}

static struct tcpcb g_tp;
static struct tseg_qent g_ent;
static struct mbuf g_em;		/* the queued segment's mbuf */
static struct mbuf g_nm, g_nmlast;	/* the incoming segment's mbufs */
static struct tcphdr g_th;

void
proof_prepend(void)
{
	tcp_seq oldstart, newseq;
	int oldlen, tlen, lenofoh;
	tcp_seq oldend;

	oldstart = nondet_uint();
	oldlen = nondet_int();
	newseq = nondet_uint();
	tlen = nondet_int();
	lenofoh = nondet_int();
	/*
	 * A well-formed incoming segment that prepends: it starts at or before
	 * the existing one, and the lengths are bounded so start + len does
	 * not wrap the sequence space (the caller guarantees this).
	 */
	__CPROVER_assume(oldlen > 0 && oldlen <= 1000);
	__CPROVER_assume(tlen > 0 && tlen <= 1000);
	__CPROVER_assume(lenofoh >= 0 && lenofoh <= 1000);
	__CPROVER_assume(SEQ_LEQ(newseq, oldstart));
	__CPROVER_assume(SEQ_LEQ(newseq, newseq + tlen));
	__CPROVER_assume(SEQ_LEQ(oldstart, oldstart + oldlen));
	/* The new data reaches the old (contiguous or overlapping). */
	__CPROVER_assume(SEQ_GEQ(newseq + tlen, oldstart));

	oldend = oldstart + oldlen;

	bzero(&g_tp, sizeof(g_tp));
	bzero(&g_ent, sizeof(g_ent));
	bzero(&g_em, sizeof(g_em));
	bzero(&g_nm, sizeof(g_nm));
	bzero(&g_nmlast, sizeof(g_nmlast));
	bzero(&g_th, sizeof(g_th));
	g_ent.tqe_m = &g_em;
	g_ent.tqe_last = &g_em;
	g_ent.tqe_start = oldstart;
	g_ent.tqe_len = oldlen;
	g_em.m_len = oldlen;
	g_th.th_seq = newseq;

	tcp_reass_prepend(&g_tp, &g_ent, &g_nm, &g_th, tlen, &g_nmlast,
	    lenofoh);

	/* The segment now starts at the new sequence. */
	__CPROVER_assert(g_ent.tqe_start == newseq,
	    "prepend starts the segment at the new sequence");
	/*
	 * And it still ends where the two together reach: the overlap was
	 * trimmed exactly, so no byte of the sequence space is double-counted
	 * or lost.  The combined end is the larger of the two ends.
	 */
	__CPROVER_assert(g_ent.tqe_start + g_ent.tqe_len == oldend,
	    "prepend preserves the segment's end, trimming the overlap once");
}

void
proof_append(void)
{
	tcp_seq oldstart;
	int oldlen, tlen, lenofoh;

	oldstart = nondet_uint();
	oldlen = nondet_int();
	tlen = nondet_int();
	lenofoh = nondet_int();
	__CPROVER_assume(oldlen > 0 && oldlen <= 1000);
	__CPROVER_assume(tlen > 0 && tlen <= 1000);
	__CPROVER_assume(lenofoh >= 0 && lenofoh <= 1000);

	bzero(&g_tp, sizeof(g_tp));
	bzero(&g_ent, sizeof(g_ent));
	bzero(&g_em, sizeof(g_em));
	bzero(&g_nm, sizeof(g_nm));
	bzero(&g_nmlast, sizeof(g_nmlast));
	bzero(&g_th, sizeof(g_th));
	g_ent.tqe_m = &g_em;
	g_ent.tqe_last = &g_em;
	g_ent.tqe_start = oldstart;
	g_ent.tqe_len = oldlen;
	g_em.m_pkthdr.len = oldlen;

	tcp_reass_append(&g_tp, &g_ent, &g_nm, &g_th, tlen, &g_nmlast,
	    lenofoh);

	__CPROVER_assert(g_ent.tqe_len == oldlen + tlen,
	    "append grows the length by exactly the appended length");
	__CPROVER_assert(g_ent.tqe_start == oldstart,
	    "append leaves the start unchanged");
}
