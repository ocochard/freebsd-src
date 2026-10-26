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
 * cbmc(1) harness for uiomove() (through uiomove_faultflag()),
 * sys/kern/subr_uio.c: the kernel's copy of n bytes between a kernel buffer
 * cp and a user scatter/gather list (uio), the workhorse behind read(2),
 * write(2) and most of the device and socket I/O paths.  The loop copies
 * min(iov_len, remaining n) bytes per iovec, advancing cp and shrinking n;
 * each copy must stay within the n-byte kernel buffer and within the iovec.
 *
 * Not a program: run.sh compiles it with SOURCE naming subr_uio.c or a
 * mutant of it, included whole.  The kernel buffer is a CBMC object of
 * exactly N bytes and each iovec points at its own user-buffer object, so a
 * copy past either end is an out-of-bounds access.  copyin()/copyout() are
 * modelled to bounds-check both ends by touching the first and last byte of
 * each range; the user path (UIO_USERSPACE) drives them.  The iovec lengths
 * and N are a concrete geometry per job.
 *
 * The entry point, for --function:
 *
 *   proof_uiomove	uiomove() of N bytes over the iovec list, read or
 *			write: every copy stays within the kernel buffer and
 *			the addressed iovec, and uio_resid is drawn down by
 *			exactly the bytes moved.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* subr_uio.c helpers the copy loop calls; no-ops for the proof. */
void maybe_yield(void) { }

/*
 * Geometries (GEO): the iovec lengths and N, the kernel-buffer size / byte
 * count to move.  0: one iovec, an exact fit.  1: two iovecs, the second
 * clamped by the remaining count.  2: a leading empty iovec that is skipped.
 * 3: one iovec larger than N, so the per-step count is clamped to N (the
 * kernel buffer bound).
 */
#if GEO == 0
static const size_t g_iovlen[] = { 8 };
#define	N	8
#elif GEO == 1
static const size_t g_iovlen[] = { 4, 8 };
#define	N	10
#elif GEO == 2
static const size_t g_iovlen[] = { 0, 8 };
#define	N	6
#elif GEO == 3
static const size_t g_iovlen[] = { 20 };
#define	N	8
#endif

#define	CNT	((int)nitems(g_iovlen))

/* The kernel buffer: a CBMC object of exactly N bytes. */
static char g_cp[N == 0 ? 1 : N];
/* Each iovec's user buffer: its own object, sized to the iovec. */
static char g_ubuf[CNT][64];
static struct iovec g_iov[CNT];

static size_t g_koff;		/* running kernel-buffer offset */
static int g_fault;

static void
touch(const volatile char *p, size_t len)
{
	if (len == 0)
		return;
	(void)p[0];
	(void)p[len - 1];
}

/*
 * The kernel side (cp) advances across the single N-byte buffer; record the
 * running offset and assert the copy stays within N.  The user side is
 * bounds-checked by the touch against the iovec's own object.
 */
static void
step(const char *kaddr, const char *uaddr, size_t len)
{
	__CPROVER_assert(g_koff + len <= (size_t)N,
	    "the copy stays within the kernel buffer");
	touch((const volatile char *)kaddr, len);
	touch((const volatile char *)uaddr, len);
	g_koff += len;
}

int
cbmc_copyin(const void *uaddr, void *kaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	step(kaddr, uaddr, len);	/* write: user -> kernel */
	return (0);
}

int
cbmc_copyout(const void *kaddr, void *uaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	step(kaddr, uaddr, len);	/* read: kernel -> user */
	return (0);
}

void
proof_uiomove(void)
{
	struct uio uio;
	int i, error;
	size_t total;

	for (i = 0; i < CNT; i++) {
		g_iov[i].iov_base = g_ubuf[i];
		g_iov[i].iov_len = g_iovlen[i];
	}

	total = 0;
	for (i = 0; i < CNT; i++)
		total += g_iovlen[i];

	uio.uio_iov = g_iov;
	uio.uio_iovcnt = CNT;
	uio.uio_offset = 0;
	uio.uio_resid = (ssize_t)total;
	uio.uio_segflg = UIO_USERSPACE;
	uio.uio_rw = nondet_bool() ? UIO_READ : UIO_WRITE;
	uio.uio_td = &cbmc_thread;
	g_koff = 0;
	g_fault = 0;

	error = uiomove(g_cp, N, &uio);

	/*
	 * Each copy was bounds-checked against the kernel buffer (step) and the
	 * iovec (touch) as the loop ran.  On a clean return the residual was
	 * drawn down by exactly what was moved: resid started at total and the
	 * loop stops at n == 0 or resid == 0, having moved min(N, total) bytes.
	 */
	if (error == 0 && !g_fault) {
		size_t moved = (N < (int)total) ? (size_t)N : total;
		__CPROVER_assert(uio.uio_resid == (ssize_t)(total - moved),
		    "resid is drawn down by the bytes moved");
		__CPROVER_assert(g_koff == moved,
		    "exactly the moved bytes touched the kernel buffer");
	}
}
