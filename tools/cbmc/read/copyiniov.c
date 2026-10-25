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
 * cbmc(1) harness for copyiniov(), sys/kern/subr_uio.c: copy a user iovec
 * array into a freshly allocated kernel array, the low-level helper behind
 * readv(2)/writev(2) and sendmsg/recvmsg iovec handling.  The count is
 * capped at UIO_MAXIOV so iovcnt * sizeof(struct iovec) cannot overflow;
 * the copyin then fills a buffer of exactly that size, or frees it on a
 * fault and returns NULL.
 *
 * Not a program: run.sh compiles it with SOURCE naming subr_uio.c or a
 * mutant of it, included whole.  malloc(M_IOV) is modelled by a CBMC object
 * of exactly iovlen bytes, so a copyin past it is an out-of-bounds write
 * CBMC catches; copyin() is the kern.h model, which faults or not.  iovcnt
 * is nondeterministic over the whole u_int range, so the cap is exercised.
 *
 * The entry point, for --function:
 *
 *   proof_copyiniov	copyiniov() on any iovcnt: a count past UIO_MAXIOV is
 *			refused with no array; an accepted count has iovcnt *
 *			sizeof(struct iovec) not overflow, the copyin fills a
 *			buffer that holds it, and a fault frees it and yields
 *			NULL.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
static void *cbmc_iov_malloc(size_t size, struct malloc_type *type, int flags);
static int cbmc_iov_free(void *addr, struct malloc_type *type);
#define	CBMC_MALLOC_HOOK	cbmc_iov_malloc
#define	CBMC_FREE_HOOK	cbmc_iov_free
#include "kern.h"

/* The M_IOV buffer: a CBMC object of exactly iovlen bytes. */
static void *g_iov;
static size_t g_cap;
static int g_freed;

static void *
cbmc_iov_malloc(size_t size, struct malloc_type *type, int flags)
{
	if (type != M_IOV)
		return (NULL);		/* let the bucket model serve others */
	g_cap = size;
	g_iov = __CPROVER_allocate(size, 0);
	g_freed = 0;
	return (g_iov);
}

static int
cbmc_iov_free(void *addr, struct malloc_type *type)
{
	if (type != M_IOV)
		return (0);
	__CPROVER_assert(addr == g_iov && !g_freed, "the array freed once");
	g_freed = 1;
	__CPROVER_deallocate(g_iov);
	return (1);
}

static int g_fault;
int
cbmc_copyin(const void *uaddr, void *kaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	/*
	 * Touch the first and last byte rather than loop: the write extent is
	 * what must stay inside kaddr (and the read inside uaddr), and CBMC
	 * bounds-checks each dereference, so the two ends settle the whole
	 * range without a 16 KB byte loop.
	 */
	if (len > 0) {
		((volatile char *)kaddr)[0] = ((const volatile char *)uaddr)[0];
		((volatile char *)kaddr)[len - 1] =
		    ((const volatile char *)uaddr)[len - 1];
	}
	return (0);
}

/* The user iovec source: a buffer large enough for the capped count. */
static struct iovec g_uiov[UIO_MAXIOV];

void
proof_copyiniov(void)
{
	struct iovec *iov = (void *)1;	/* poison; must be set to NULL/array */
	u_int iovcnt;
	int error;

	/*
	 * iovcnt is a constant per job (the copyin is a byte loop; a symbolic
	 * count runs out of memory): the jobs sweep across the UIO_MAXIOV cap.
	 */
	iovcnt = IOVCNT;
	g_fault = 0;
	g_cap = 0;

	error = copyiniov(g_uiov, iovcnt, &iov, EINVAL);

	if (iovcnt > UIO_MAXIOV) {
		__CPROVER_assert(error == EINVAL, "a count past the cap is refused");
		__CPROVER_assert(iov == NULL, "and no array handed back");
		return;
	}
	if (error != 0) {
		__CPROVER_assert(g_fault, "an error only from the fault");
		__CPROVER_assert(iov == NULL, "no array on an error");
		__CPROVER_assert(g_freed, "the array freed on an error");
		return;
	}
	/*
	 * Success: iovcnt is within the cap, so iovcnt * sizeof(struct iovec)
	 * did not overflow, and the copyin filled a buffer that holds it (the
	 * copy is bounds-checked against g_iov during the call).
	 */
	__CPROVER_assert(iov == g_iov, "the array handed back");
	__CPROVER_assert(g_cap == (size_t)iovcnt * sizeof(struct iovec),
	    "the array is sized for the count, no overflow");
}
