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
 * cbmc(1) harness for copyinuio(), sys/kern/subr_uio.c: the iovec
 * copy-in that readv(2), writev(2), preadv(2) and pwritev(2) use to turn
 * a process's struct iovec array into a struct uio.  The iovcnt and the
 * iov_len fields come from userspace, so the total length must not
 * overflow.
 *
 * Not a program: run.sh compiles it with SOURCE naming subr_uio.c or a
 * mutant of it, included whole.  copyin() and the allocator are modelled;
 * the reference is readv(2) (EINVAL for iovcnt > UIO_MAXIOV or a total
 * past IOSIZE_MAX, EFAULT for an unreadable array).  The one entry point,
 * for --function:
 *
 *   proof_copyinuio	copyinuio() on any iovcnt and any iov_len values:
 *			iovcnt > UIO_MAXIOV refused, each length checked so
 *			the running total never passes IOSIZE_MAX, a fault
 *			propagated with nothing left allocated; else a uio
 *			whose resid is the exact sum of the lengths
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#define	NIOV	4		/* iovecs the model copies in */

static struct iovec g_uiov[NIOV];	/* the process's iovec array */
static int g_fault;

/* iosize_max(), sys_generic.c: INT_MAX on ILP32 or when clamped, else
 * SSIZE_MAX.  A constant per run covers both. */
static size_t g_iosize_max;

size_t
iosize_max(void)
{
	return (g_iosize_max);
}

/* copyin(9): the process's iovecs, or EFAULT. */
int
cbmc_copyin(const void *udaddr, void *kaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	memcpy(kaddr, udaddr, len);
	return (0);
}


void
proof_copyinuio(void)
{
	struct uio *uio;
	u_int iovcnt;
	int error, i;
	ssize_t sum;
	bool overflow;

	g_iosize_max = nondet_bool() ? INT_MAX : SSIZE_MAX;
	iovcnt = nondet_u_int();
	__CPROVER_assume(iovcnt <= NIOV);	/* bound the modelled array */
	for (i = 0; i < NIOV; i++) {
		g_uiov[i].iov_base = (void *)(uintptr_t)nondet_long();
		g_uiov[i].iov_len = nondet_long();
	}

	error = copyinuio(g_uiov, iovcnt, &uio);

	if (error == EFAULT) {
		__CPROVER_assert(g_fault && uio == NULL,
		    "a fault returns no uio");
		return;
	}
	if (error != 0) {
		__CPROVER_assert(error == EINVAL && uio == NULL,
		    "refused with EINVAL, no uio");
		return;
	}
	/* Success: iovcnt within bounds, resid the exact non-overflowing sum. */
	__CPROVER_assert(iovcnt <= UIO_MAXIOV, "iovcnt within UIO_MAXIOV");
	__CPROVER_assert(uio->uio_iovcnt == (int)iovcnt,
	    "the uio has the iovec count");
	sum = 0;
	overflow = false;
	for (i = 0; i < NIOV; i++) {
		if ((u_int)i >= iovcnt)
			break;
		if (uio->uio_iov[i].iov_len > IOSIZE_MAX - sum)
			overflow = true;
		else
			sum += uio->uio_iov[i].iov_len;
	}
	__CPROVER_assert(!overflow,
	    "a success never had a length overflow the total");
	__CPROVER_assert(uio->uio_resid == sum,
	    "resid is the exact sum of the iovec lengths");
	freeuio(uio);
}
