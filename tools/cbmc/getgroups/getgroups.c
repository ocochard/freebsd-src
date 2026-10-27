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
 * cbmc(1) harness for sys_getgroups(), sys/kern/kern_prot.c: the getgroups(2)
 * syscall copies the credential's group array out to a user buffer sized by
 * the gidsetsize argument.  It guards gidsetsize < ngrp with EINVAL, then
 * copies ngrp entries.  The copy-out must read only within cr_groups (which
 * holds cr_ngroups entries) and write only within the user buffer (which
 * holds gidsetsize entries).
 *
 * Not a program: run.sh compiles it with SOURCE naming kern_prot.c or a
 * mutant of it, included whole.  cr_groups is a CBMC object of exactly
 * cr_ngroups entries and the user buffer of GIDSETSIZE entries, so a read or
 * write past either is an out-of-bounds access.  cr_ngroups is a constant
 * per job (NGROUPS) and gidsetsize nondeterministic, so the guard is
 * exercised over every requested size.  copyout() is modelled.
 *
 * The entry point, for --function:
 *
 *   proof_getgroups	sys_getgroups() for any gidsetsize: the copy-out reads
 *			within cr_groups and writes within the user buffer.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static struct ucred g_cred;
static gid_t g_groups[NGROUPS == 0 ? 1 : NGROUPS];
static int g_copied;		/* bytes the copyout was asked to move */

int
cbmc_copyout(const void *kaddr, void *uaddr, size_t len)
{
	if (nondet_bool())
		return (EFAULT);
	/*
	 * Touch the first and last byte of both the kernel source and the user
	 * destination so CBMC bounds-checks the copy against cr_groups and the
	 * user buffer.
	 */
	if (len != 0) {
		((const volatile char *)kaddr)[0];
		((const volatile char *)kaddr)[len - 1];
		((volatile char *)uaddr)[0];
		((volatile char *)uaddr)[len - 1];
	}
	g_copied = (int)len;
	return (0);
}

void
proof_getgroups(void)
{
	struct getgroups_args ua;
	int error;

	g_cred.cr_ngroups = NGROUPS;
	g_cred.cr_groups = g_groups;
	cbmc_thread.td_ucred = &g_cred;

	/*
	 * An honest caller's buffer is exactly gidsetsize entries, so model the
	 * user buffer as a CBMC object of that size.  gidsetsize is
	 * nondeterministic (bounded so the object stays small), so the guard is
	 * exercised over every requested size; the guard gidsetsize < ngrp is
	 * what keeps the copy from overrunning a buffer smaller than ngrp.
	 */
	ua.gidsetsize = nondet_int();
	__CPROVER_assume(ua.gidsetsize >= 0 && ua.gidsetsize <= NGROUPS + 2);
	ua.gidset = __CPROVER_allocate(ua.gidsetsize * sizeof(gid_t), 0);

	error = sys_getgroups(&cbmc_thread, &ua);
	(void)error;
	/*
	 * If the copy ran it moved ngrp entries, read from the NGROUPS-entry
	 * cr_groups and written to the gidsetsize-entry user buffer; both were
	 * bounds-checked in the copyout model during the call.
	 */
}
