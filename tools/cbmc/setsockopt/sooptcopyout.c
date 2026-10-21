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
 * cbmc(1) harness for sooptcopyout(), sys/kern/uipc_socket.c: the
 * copy-out of a socket option value, used by getsockopt(2) through
 * sogetopt() and by every protocol pr_ctloutput().  The caller hands a
 * kernel buffer of len bytes; the function must copy out no more than
 * that, clamped to the user's buffer, and never read past the kernel
 * buffer, which would leak adjacent kernel memory to user space.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_socket.c or
 * a mutant of it, included whole.  The kernel source buffer is a CBMC
 * object of exactly len bytes, so a copyout that reads past it is an
 * out-of-bounds read CBMC catches.  copyout() is modelled; the kernel
 * path (sopt_td == NULL) copies with memcpy.
 *
 * The entry point, for --function:
 *
 *   proof_sooptcopyout	sooptcopyout() on a user sopt_valsize of any
 *			size_t value against a kernel buffer of len bytes:
 *			the copy is only ever min(len, sopt_valsize) bytes,
 *			read from the kernel buffer, never past it; and
 *			sopt_valsize is set to what was copied.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* The kernel source buffer: a CBMC object of exactly LEN bytes. */
static char g_kbuf[LEN];
/* The user destination, large enough for any clamped copy. */
static char g_uval[LEN];
static int g_copied;		/* bytes the copy was asked to move */
static int g_fault;

int
cbmc_copyout(const void *kaddr, void *uaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	g_copied = len;
	cbmc_memmove(uaddr, kaddr, len);
	return (0);
}

void
proof_sooptcopyout(void)
{
	struct sockopt sopt;
	struct thread td;
	int error;

	/*
	 * sopt_valsize (the user's buffer size) is a constant per job
	 * (VALSIZE): the copy is a byte loop, and a symbolic size runs out of
	 * memory.  The jobs sweep an empty user buffer, one short of the
	 * kernel buffer, the kernel buffer, and larger than it (the clamp).
	 */
	sopt.sopt_valsize = VALSIZE;
	sopt.sopt_val = nondet_bool() ? g_uval : NULL;
	sopt.sopt_td = nondet_bool() ? &td : NULL;
	g_fault = 0;
	g_copied = -1;

	error = sooptcopyout(&sopt, g_kbuf, LEN);

	if (sopt.sopt_val != NULL && sopt.sopt_td != NULL && g_fault) {
		__CPROVER_assert(error == EFAULT, "a fault reported");
		return;
	}
	__CPROVER_assert(error == 0, "no error otherwise");
	/* The copied size is min(len, the user's size). */
	if ((size_t)VALSIZE < LEN)
		__CPROVER_assert(sopt.sopt_valsize == (size_t)VALSIZE,
		    "a small user buffer bounds the copy");
	else
		__CPROVER_assert(sopt.sopt_valsize == (size_t)LEN,
		    "the copy is clamped to the kernel buffer");
	/*
	 * On the user path the copyout model records the length; it is read
	 * from g_kbuf, whose extent CBMC bounds-checks, so it can never run
	 * past the LEN-byte kernel buffer and leak adjacent memory.
	 */
	if (sopt.sopt_val != NULL && sopt.sopt_td != NULL) {
		__CPROVER_assert(g_copied == (int)sopt.sopt_valsize,
		    "exactly the reported length is copied");
		__CPROVER_assert(g_copied <= LEN,
		    "never read past the kernel buffer");
	}
}
