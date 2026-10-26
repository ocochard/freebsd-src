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
 * cbmc(1) harness for bpf_validate(), sys/net/bpf_filter.c: the kernel's
 * check of a classic-BPF program before it is installed on a descriptor
 * (BIOCSETF) and later run by bpf_filter() on every captured packet.  A
 * program that passes validation must be safe to interpret: its jumps must
 * stay within the instruction array (so bpf_filter's program counter never
 * runs off the end), its scratch-memory indices must be < BPF_MEMWORDS, and
 * it must end in a return.  This harness drives validation over a program of
 * nondeterministic instructions and checks that guarantee.
 *
 * Not a program: run.sh compiles it with SOURCE naming bpf_filter.c or a
 * mutant of it, included whole.  The instruction array is a CBMC object of
 * exactly LEN instructions with nondeterministic fields, so bpf_validate's
 * own reads of f[i] and f[len-1] are bounds-checked.  LEN is a constant per
 * job.
 *
 * The entry point, for --function:
 *
 *   proof_bpf_validate	bpf_validate() over a LEN-instruction program: it
 *			reads only within the array, and when it accepts the
 *			program every forward jump target stays within the
 *			array, every memory index is < BPF_MEMWORDS, and the
 *			last instruction is a return.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static struct bpf_insn g_prog[LEN];

void
proof_bpf_validate(void)
{
	int i, ok;

	/*
	 * A program of LEN instructions, each field nondeterministic, as a
	 * single CBMC object so bpf_validate's f[i] reads are bounds-checked.
	 */
	for (i = 0; i < LEN; i++) {
		g_prog[i].code = nondet_short();
		g_prog[i].jt = nondet_char();
		g_prog[i].jf = nondet_char();
		g_prog[i].k = nondet_uint();
	}

	ok = bpf_validate(g_prog, LEN);

	if (!ok)
		return;			/* rejected: nothing guaranteed */
	/*
	 * Accepted.  The guarantee bpf_filter() relies on: every jump lands
	 * within the array (the target index i + offset + 1 is <= len - 1, so
	 * the interpreter's pc cannot leave f[0..len)), every scratch index is
	 * within BPF_MEMWORDS, and the last instruction returns.
	 */
	for (i = 0; i < LEN; i++) {
		const struct bpf_insn *p = &g_prog[i];

		if (BPF_CLASS(p->code) == BPF_JMP) {
			u_int offset;

			if (p->code == (BPF_JMP | BPF_JA))
				offset = p->k;
			else
				offset = p->jt > p->jf ? p->jt : p->jf;
			__CPROVER_assert(offset < (u_int)(LEN - i) - 1,
			    "an accepted jump stays within the program");
			__CPROVER_assert((size_t)i + offset + 1 <= (size_t)(LEN - 1),
			    "an accepted jump target is a valid instruction");
		}
		if (p->code == BPF_ST || p->code == BPF_STX ||
		    p->code == (BPF_LD | BPF_MEM) ||
		    p->code == (BPF_LDX | BPF_MEM))
			__CPROVER_assert(p->k < BPF_MEMWORDS,
			    "an accepted memory index is within BPF_MEMWORDS");
	}
	__CPROVER_assert(BPF_CLASS(g_prog[LEN - 1].code) == BPF_RET,
	    "an accepted program ends in a return");
}
