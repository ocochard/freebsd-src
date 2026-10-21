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
 * cbmc(1) harness for getsockaddr(), sys/kern/uipc_syscalls.c: the
 * copy-in of a socket address from user space, used by bind(2),
 * connect(2), sendto(2) and sendmsg(2) for the destination name.  The
 * user passes a length; the function must refuse a length too large for
 * sa_len (one byte) or too small for the fixed header, and on an
 * accepted one copy exactly that many bytes into a buffer of that size
 * and stamp sa_len.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_syscalls.c
 * or a mutant of it, included whole.  malloc(M_SONAME) is modelled by a
 * CBMC object of exactly len bytes, so the copyin's write is
 * bounds-checked against the real allocation.  copyin() is the kern.h
 * model, which faults or not.
 *
 * The entry point, for --function:
 *
 *   proof_getsockaddr	getsockaddr() on a len of any size_t value: a
 *			length past SOCK_MAXADDRLEN refused with
 *			ENAMETOOLONG and no name; a length below the header
 *			refused with EINVAL; a faulting copyin reported with
 *			the buffer freed; else a name of sa_len == len, len
 *			bytes copied into a buffer that holds them.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
static void *cbmc_soname(size_t size, struct malloc_type *type, int flags);
static int cbmc_soname_free(void *addr, struct malloc_type *type);
#define	CBMC_MALLOC_HOOK	cbmc_soname
#define	CBMC_FREE_HOOK	cbmc_soname_free
#include "kern.h"

/*
 * The M_SONAME buffer: a CBMC object of exactly len bytes, so a copyin
 * that writes past len is an out-of-bounds write CBMC catches.
 */
static void *g_sa;
static int g_safree;		/* the buffer freed (fault path) */
static size_t g_cap;		/* the buffer size malloc() gave */
static int g_copied;		/* bytes the copyin was asked to move */
static int g_fault;

static void *
cbmc_soname(size_t size, struct malloc_type *type, int flags)
{
	if (type != M_SONAME)
		return (NULL);		/* let the bucket model serve others */
	g_cap = size;
	g_sa = __CPROVER_allocate(size, 0);
	g_safree = 0;
	return (g_sa);
}

static int
cbmc_soname_free(void *addr, struct malloc_type *type)
{
	if (type != M_SONAME)
		return (0);
	__CPROVER_assert(addr == g_sa && !g_safree, "the buffer freed once");
	g_safree = 1;
	__CPROVER_deallocate(g_sa);
	return (1);
}

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
proof_getsockaddr(void)
{
	struct sockaddr *namp = NULL;
	char ubuf[SOCK_MAXADDRLEN];
	size_t len;
	int error;

	/*
	 * len is a constant per job (LEN): the copyin is a byte loop, and a
	 * symbolic length runs out of memory.  The run.sh jobs sweep the
	 * boundaries (below the header, the header, SOCK_MAXADDRLEN, one
	 * past it).
	 */
	len = LEN;
	g_fault = 0;
	g_copied = -1;
	g_cap = 0;

	error = getsockaddr(&namp, (const struct sockaddr *)ubuf, len);

	if (len > SOCK_MAXADDRLEN) {
		__CPROVER_assert(error == ENAMETOOLONG,
		    "a length past the cap is refused");
		__CPROVER_assert(namp == NULL, "and no name handed back");
		return;
	}
	if (len < offsetof(struct sockaddr, sa_data[0])) {
		__CPROVER_assert(error == EINVAL,
		    "a length below the header is refused");
		__CPROVER_assert(namp == NULL, "and no name handed back");
		return;
	}
	if (error != 0) {
		__CPROVER_assert(g_fault, "an error only from the fault");
		__CPROVER_assert(namp == NULL, "no name on an error");
		__CPROVER_assert(g_safree, "the buffer freed on an error");
		return;
	}
	/* Success. */
	__CPROVER_assert(namp == g_sa, "the name handed back");
	__CPROVER_assert(!g_safree, "not freed on success");
	__CPROVER_assert(g_copied == (int)len, "exactly len bytes copied in");
	__CPROVER_assert(len <= g_cap, "the buffer holds them");
	__CPROVER_assert(namp->sa_len == len,
	    "the name's sa_len is the length");
}
