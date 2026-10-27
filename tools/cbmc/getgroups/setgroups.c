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
 * cbmc(1) harness for sys_setgroups(), sys/kern/kern_prot.c: the setgroups(2)
 * syscall copies a user group array into a kernel buffer before handing it to
 * kern_setgroups().  It sanity-checks gidsetsize, then uses an on-stack
 * smallgroups[CRED_SMALLGROUPS_NB] array for a small set or a malloc'd buffer
 * for a larger one, and copies gidsetsize entries in.  The copy-in must fit
 * whichever buffer was chosen.
 *
 * Not a program: run.sh compiles it with SOURCE naming kern_prot.c or a
 * mutant of it, included whole.  The malloc model sizes the buffer to the
 * request, so the large-set copy-in is bounds-checked; the on-stack
 * smallgroups array is CRED_SMALLGROUPS_NB entries, so a copy-in past it is
 * an out-of-bounds write.  gidsetsize is nondeterministic within [0,
 * ngroups_max], so both the small and large branches are covered.
 * kern_setgroups() is stubbed (--replace-calls); copyin() is modelled.
 *
 * The entry point, for --function:
 *
 *   proof_setgroups	sys_setgroups() for any gidsetsize: the copy-in of
 *			gidsetsize entries fits the buffer the size branch chose.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>

/* malloc returns a buffer of exactly the requested size, so the copy-in is
 * bounds-checked against the real allocation. */
static void *cbmc_setgroups_malloc(size_t size, struct malloc_type *t, int fl);
#define	CBMC_MALLOC_HOOK	cbmc_setgroups_malloc
#include "kern.h"

static void *
cbmc_setgroups_malloc(size_t size, struct malloc_type *t, int fl)
{
	return (__CPROVER_allocate(size == 0 ? 1 : size, 0));
}

/* kern_setgroups() does the cred work; stub it so only the copy-in is proven. */
int
cbmc_kern_setgroups(struct thread *td, int *ngrpp, gid_t *groups,
    bool includes_egid)
{
	return (0);
}

/* The system-wide supplementary-group cap, read by sys_setgroups. */
int ngroups_max;

/* The user source, sized to the request so an over-read is caught too. */
static gid_t *g_src;

int
cbmc_copyin(const void *uaddr, void *kaddr, size_t len)
{
	if (nondet_bool())
		return (EFAULT);
	if (len != 0) {
		((const volatile char *)uaddr)[0];
		((const volatile char *)uaddr)[len - 1];
		((volatile char *)kaddr)[0];
		((volatile char *)kaddr)[len - 1];
	}
	return (0);
}

void
proof_setgroups(void)
{
	struct setgroups_args ua;
	int gidsetsize;

	ngroups_max = NMAX;

	gidsetsize = nondet_int();
	/*
	 * gidsetsize is the caller's claimed count; the source buffer is that
	 * many entries (an honest caller).  The sanity check in sys_setgroups
	 * refuses < 0 or > ngroups_max, so bound it here only enough to size the
	 * source object (NMAX, a small stand-in for the system cap, chosen to
	 * straddle CRED_SMALLGROUPS_NB so both buffer branches are covered).
	 */
	__CPROVER_assume(gidsetsize >= 0 && gidsetsize <= NMAX);
	g_src = __CPROVER_allocate(gidsetsize == 0 ? 1 :
	    gidsetsize * sizeof(gid_t), 0);

	ua.gidsetsize = gidsetsize;
	ua.gidset = g_src;

	(void)sys_setgroups(&cbmc_thread, &ua);
	/*
	 * The copy-in of gidsetsize entries was bounds-checked against the
	 * chosen buffer (the CRED_SMALLGROUPS_NB on-stack array for a small set,
	 * or the request-sized malloc for a larger one) in the copyin model.
	 */
}
