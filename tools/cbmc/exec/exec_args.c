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
 * cbmc(1) harness for the argument-string accounting of execve(2),
 * sys/kern/kern_exec.c: each exec_args_add_arg()/_env() copies one user
 * string into the buffer against a running budget (stringspace) and
 * advances the end pointer.  The budget must never let a copy run past
 * the buffer, and must never underflow.
 *
 * Not a program: run.sh compiles it with SOURCE naming kern_exec.c or a
 * mutant of it, included whole.  exec_args_add_str() is driven directly,
 * with a small synthetic budget (BUDGET) and a buffer of exactly that
 * many bytes: the accounting is the same at any size, and the real
 * ARG_MAX (256K) would need a 256K symbolic object that runs the solver
 * out of memory.  copyinstr() is modelled: it returns a length no greater
 * than the room it was given, as copyinstr(9) guarantees, and faults or
 * not.  The buffer being exactly BUDGET bytes makes an endp that runs
 * past it an out-of-bounds write CBMC catches.
 *
 * The entry point, for --function:
 *
 *   proof_exec_args	NADD arg/env appends of user strings of any length
 *			onto a BUDGET-byte buffer: at every step the end
 *			pointer stays inside the buffer, the budget stays in
 *			[0, BUDGET], a copy that does not fit is refused with
 *			E2BIG, and the end pointer tracks the consumed budget.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* The string buffer, a CBMC object of exactly the budget. */
static char g_buf[BUDGET];

/* vm_init.c sets this; a KASSERT elsewhere in the file reads it. */
u_int exec_map_entry_size = PATH_MAX + ARG_MAX;

/*
 * copyinstr(9): copies at most maxlen bytes of a NUL-terminated string,
 * sets *done to the number copied including the NUL (1..maxlen), or
 * returns ENAMETOOLONG if the string does not fit, or EFAULT.  The bytes
 * are nondeterministic; the write into kaddr is bounds-checked by CBMC.
 */
int
cbmc_copyinstr(const void *uaddr, void *kaddr, size_t maxlen, size_t *done)
{
	size_t n;

	if (maxlen == 0)
		return (ENAMETOOLONG);
	if (nondet_bool())
		return (EFAULT);
	if (nondet_bool())
		return (ENAMETOOLONG);
	n = nondet_ulong();
	__CPROVER_assume(n >= 1 && n <= maxlen);
	/*
	 * Touch the first and last byte written rather than loop: the write
	 * extent is what must stay inside kaddr, and CBMC bounds-checks each
	 * dereference, so the two ends settle the whole range.
	 */
	((volatile char *)kaddr)[0] = 0;
	((volatile char *)kaddr)[n - 1] = 0;
	if (done != NULL)
		*done = n;
	return (0);
}

void
proof_exec_args(void)
{
	struct image_args args;
	int error, i, g_split;

	g_split = nondet_int();
	__CPROVER_assume(g_split >= 0 && g_split <= NADD);
	/* Start as exec_args_add_fname() leaves it: endp at begin_argv, a
	 * budget of BUDGET bytes, a buffer of exactly that many bytes. */
	bzero(&args, sizeof(args));
	args.buf = g_buf;
	args.endp = g_buf;
	args.begin_argv = g_buf;
	args.stringspace = BUDGET;

	/*
	 * The caller appends all args, then all envs; add_arg() KASSERTs that
	 * no env came first.  A prefix of the appends are args, the rest envs,
	 * which covers both wrappers in a legal order.
	 */
	for (i = 0; i < NADD; i++) {
		error = i < g_split ?
		    exec_args_add_arg(&args, (const char *)&args,
			UIO_USERSPACE) :
		    exec_args_add_env(&args, (const char *)&args,
			UIO_USERSPACE);
		if (error != 0) {
			__CPROVER_assert(error == E2BIG || error == EFAULT,
			    "a string that does not fit is E2BIG, else the "
			    "fault");
			continue;
		}
		__CPROVER_assert(args.stringspace >= 0,
		    "the budget never underflows");
		__CPROVER_assert(args.stringspace <= BUDGET,
		    "the budget never grows past its start");
		__CPROVER_assert(args.endp >= args.begin_argv &&
		    args.endp <= g_buf + sizeof(g_buf),
		    "endp inside the buffer after an append");
		/*
		 * endp has advanced by exactly the bytes charged against the
		 * budget: the string just copied sits between begin_argv and
		 * endp, and the budget is what is left.
		 */
		__CPROVER_assert(args.endp - args.begin_argv ==
		    BUDGET - args.stringspace,
		    "endp tracks the consumed budget");
	}
}
