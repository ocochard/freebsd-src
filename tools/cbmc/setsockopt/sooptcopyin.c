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
 * cbmc(1) harness for sooptcopyin(), sys/kern/uipc_socket.c: the copy-in
 * of a socket option value, used by setsockopt(2) through sosetopt() and
 * by every protocol pr_ctloutput().  The user controls sopt_valsize; the
 * function must refuse less than the caller's minimum, clamp more than
 * the caller's buffer, and copy only what fits, never past the buffer.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_socket.c or
 * a mutant of it, included whole.  The caller's buffer is a CBMC object
 * of exactly len bytes, so a copy past it is an out-of-bounds write CBMC
 * catches.  copyin() is the kern.h model, which faults or not; the kernel
 * path (sopt_td == NULL) copies with memcpy.
 *
 * The entry point, for --function:
 *
 *   proof_sooptcopyin	sooptcopyin() on a sopt_valsize of any size_t
 *			value against a caller len and minlen: a valsize
 *			below minlen refused with EINVAL and no copy; a
 *			valsize above len clamped to len; the copy exactly
 *			min(valsize, len) bytes into a buffer that holds
 *			them; sopt_valsize left at what was retrieved.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* The user option value, the copyin/memcpy source. */
static char g_uval[LEN + 1];
static int g_copied;		/* bytes the copy was asked to move */
static int g_fault;

int
cbmc_copyin(const void *uaddr, void *kaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	g_copied = len;
	cbmc_memmove(kaddr, uaddr, len);
	return (0);
}

void
proof_sooptcopyin(void)
{
	struct sockopt sopt;
	struct thread td;
	char buf[LEN];		/* the caller's buffer: exactly len bytes */
	size_t minlen;
	int error;

	minlen = nondet_ulong();
	__CPROVER_assume(minlen <= LEN);	/* a caller asks for at most len */
	sopt.sopt_valsize = VALSIZE;
	sopt.sopt_val = g_uval;
	sopt.sopt_td = nondet_bool() ? &td : NULL;
	g_fault = 0;
	g_copied = -1;

	error = sooptcopyin(&sopt, buf, LEN, minlen);

	if ((size_t)VALSIZE < minlen) {
		__CPROVER_assert(error == EINVAL,
		    "a value below the minimum is refused");
		__CPROVER_assert(sopt.sopt_valsize == (size_t)VALSIZE,
		    "and sopt_valsize untouched");
		return;
	}
	if (sopt.sopt_td != NULL && g_fault) {
		__CPROVER_assert(error == EFAULT, "a fault reported");
		return;
	}
	/* Success: the copy ran (never past buf, which CBMC bounds-checks). */
	__CPROVER_assert(error == 0, "no error on success");
	if ((size_t)VALSIZE > LEN)
		__CPROVER_assert(sopt.sopt_valsize == (size_t)LEN,
		    "an over-long value is clamped to the buffer");
	else
		__CPROVER_assert(sopt.sopt_valsize == (size_t)VALSIZE,
		    "sopt_valsize is what was retrieved");
	/*
	 * On the user path the copyin model records the length; the kernel
	 * path copies with memcpy, whose write into the LEN-byte buf is
	 * bounds-checked by CBMC.
	 */
	if (sopt.sopt_td != NULL) {
		__CPROVER_assert(g_copied == (int)sopt.sopt_valsize,
		    "exactly the retrieved length is copied");
		__CPROVER_assert(g_copied <= LEN, "never more than the buffer");
	}
}
