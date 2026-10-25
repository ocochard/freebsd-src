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
 * cbmc(1) harness for sysctl_new_user(), sys/kern/kern_sysctl.c: the
 * copy-in helper every sysctl(2) write goes through, the companion to
 * sysctl_old_user().  It reads a chunk of the user's new buffer at the
 * running offset into a kernel buffer, refusing with EINVAL if the chunk
 * does not fit the remaining new length, and accounts it in newidx.  The
 * copy-in must never read past the user buffer.
 *
 * Not a program: run.sh compiles it with SOURCE naming kern_sysctl.c or a
 * mutant of it, included whole.  The user new buffer is a CBMC object of
 * exactly newlen bytes, so a copy-in past it is an out-of-bounds read CBMC
 * catches; copyin() is the harness model.  The chunk length, offset and
 * newlen are nondeterministic within a small bound, with newidx <= newlen
 * maintained as the function itself keeps it.
 *
 * The entry point, for --function:
 *
 *   proof_new_user	sysctl_new_user() for a chunk of length l at offset
 *			newidx into a newlen-byte buffer: a chunk past the
 *			remaining length is refused with EINVAL and no read;
 *			else the copy-in stays within the buffer and newidx
 *			advances by l, staying within newlen.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#ifndef CAP
#define	CAP	24		/* bound on newlen / newidx / l */
#endif

static char g_nbuf[CAP];	/* the user new buffer: exactly newlen used */
static char g_dst[CAP];		/* the kernel destination */
static size_t g_read_from_off;
static size_t g_read_len;
static int g_did_copy;

int
cbmc_copyin(const void *uaddr, void *kaddr, size_t len)
{
	g_read_from_off = (const char *)uaddr - g_nbuf;
	g_read_len = len;
	g_did_copy = 1;
	if (len > 0) {
		((volatile char *)kaddr)[0] = ((const volatile char *)uaddr)[0];
		((volatile char *)kaddr)[len - 1] =
		    ((const volatile char *)uaddr)[len - 1];
	}
	return (0);
}

void
proof_new_user(void)
{
	struct sysctl_req req;
	size_t l, newidx, newlen;
	int error;

	l = nondet_ulong();
	newidx = nondet_ulong();
	newlen = nondet_ulong();
	__CPROVER_assume(l <= CAP && newlen <= CAP);
	/* newidx <= newlen is the invariant sysctl_new_user itself maintains. */
	__CPROVER_assume(newidx <= newlen);

	bzero(&req, sizeof(req));
	req.newptr = g_nbuf;
	req.newidx = newidx;
	req.newlen = newlen;
	g_did_copy = 0;

	error = sysctl_new_user(&req, g_dst, l);

	if (newlen - newidx < l) {
		__CPROVER_assert(error == EINVAL,
		    "a chunk past the remaining length is refused");
		__CPROVER_assert(!g_did_copy, "and nothing is read");
		__CPROVER_assert(req.newidx == newidx,
		    "and newidx is unchanged");
		return;
	}
	/*
	 * Accepted: the copy-in read lies wholly within the user buffer's
	 * length (offset + len <= newlen), and newidx advanced by l, staying
	 * within newlen.
	 */
	if (g_did_copy)
		__CPROVER_assert(g_read_from_off + g_read_len <= newlen,
		    "the copy-in stays within the user buffer");
	__CPROVER_assert(req.newidx == newidx + l,
	    "newidx advances by the chunk length");
	__CPROVER_assert(req.newidx <= newlen,
	    "newidx stays within newlen");
}
