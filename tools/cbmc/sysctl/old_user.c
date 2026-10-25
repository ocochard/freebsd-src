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
 * cbmc(1) harness for sysctl_old_user(), sys/kern/kern_sysctl.c: the
 * copy-out helper every sysctl(2) read goes through.  It copies a chunk of
 * the result to the user's buffer at the running offset, clamped to the
 * validated buffer length, and accounts the total requested in oldidx.  The
 * copy must never write past the user buffer, and a truncated read must be
 * reported ENOMEM.
 *
 * Not a program: run.sh compiles it with SOURCE naming kern_sysctl.c or a
 * mutant of it, included whole.  The user buffer is a CBMC object of exactly
 * validlen bytes, so a copy-out past it is an out-of-bounds write CBMC
 * catches; copyout() is the harness model.  The chunk length, the running
 * offset and validlen are nondeterministic within a small bound.
 *
 * The entry point, for --function:
 *
 *   proof_old_user	sysctl_old_user() for a chunk of length l at offset
 *			oldidx into a validlen-byte buffer: the copy-out stays
 *			within the buffer, oldidx advances by l, and a chunk
 *			that did not fully fit returns ENOMEM.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#ifndef CAP
#define	CAP	24		/* bound on validlen / oldidx / l */
#endif

static char g_ubuf[CAP];	/* the user buffer: exactly validlen used */
static const char g_src[CAP];	/* the chunk source */
static size_t g_copied_to_off;	/* dest offset of the copy-out */
static size_t g_copied_len;
static int g_did_copy;

int
cbmc_copyout(const void *kaddr, void *uaddr, size_t len)
{
	g_copied_to_off = (char *)uaddr - g_ubuf;
	g_copied_len = len;
	g_did_copy = 1;
	/* Touch the ends; CBMC bounds-checks against g_ubuf's extent. */
	if (len > 0) {
		((volatile char *)uaddr)[0] = ((const char *)kaddr)[0];
		((volatile char *)uaddr)[len - 1] = ((const char *)kaddr)[len - 1];
	}
	return (0);
}

void
proof_old_user(void)
{
	struct sysctl_req req;
	size_t l, oldidx, validlen;
	int error;

	l = nondet_ulong();
	oldidx = nondet_ulong();
	validlen = nondet_ulong();
	__CPROVER_assume(l <= CAP && oldidx <= CAP && validlen <= CAP);

	bzero(&req, sizeof(req));
	req.oldptr = g_ubuf;
	req.oldidx = oldidx;
	req.validlen = validlen;
	req.lock = REQ_UNWIRED;		/* uses copyout, not copyout_nofault */
	g_did_copy = 0;

	error = sysctl_old_user(&req, g_src, l);

	/* oldidx always advances by the full requested chunk length. */
	__CPROVER_assert(req.oldidx == oldidx + l,
	    "oldidx accounts the whole requested length");
	if (g_did_copy) {
		/*
		 * Whatever was copied out lies wholly within the user buffer's
		 * validated length: offset + len <= validlen, so no write past
		 * oldptr + validlen (the copy itself was bounds-checked too).
		 */
		__CPROVER_assert(g_copied_to_off + g_copied_len <= validlen,
		    "the copy-out stays within the validated buffer");
	}
	/*
	 * A non-empty chunk that did not fully fit is reported truncated.
	 * (For l == 0 nothing is copied and the call succeeds even if the
	 * offset is already past the buffer.)
	 */
	if (req.oldptr != NULL && l > 0 && oldidx + l > validlen)
		__CPROVER_assert(error == ENOMEM,
		    "a truncated read returns ENOMEM");
}
