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
 * cbmc(1) harness for bpf_filter(), sys/net/bpf_filter.c: the classic-BPF
 * interpreter run on every captured packet.  Its packet loads (BPF_LD of a
 * word, half or byte, by absolute or X-indexed offset) each guard the access
 * against buflen before reading p[k]; a wrong guard reads past the packet
 * buffer and leaks adjacent kernel memory into the filter's accumulator.
 * This harness drives one load against a buffer of exactly buflen bytes and
 * lets CBMC bounds-check the read.
 *
 * Not a program: run.sh compiles it with SOURCE naming bpf_filter.c or a
 * mutant of it, included whole.  The packet p is a CBMC object of exactly
 * BUFLEN bytes, so any in-buffer load past it is an out-of-bounds read CBMC
 * catches.  buflen is kept non-zero, so the mbuf fallback (m_xword/m_xhalf,
 * taken only when buflen == 0) is not the subject.  A short program -- an
 * X seed, the load under test, and a return -- drives the one load; the
 * X-register value and the instruction's k are nondeterministic.  LOAD
 * selects the load (W/H/B, ABS/IND) per job.
 *
 * The entry point, for --function:
 *
 *   proof_bpf_filter	bpf_filter() running one packet load against a
 *			BUFLEN-byte buffer: the in-buffer read stays within the
 *			buffer for any X and k.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* The load under test (LOAD): the BPF_LD code for one job. */
#if LOAD == 0
#define	LDCODE	(BPF_LD | BPF_W | BPF_ABS)
#elif LOAD == 1
#define	LDCODE	(BPF_LD | BPF_H | BPF_ABS)
#elif LOAD == 2
#define	LDCODE	(BPF_LD | BPF_B | BPF_ABS)
#elif LOAD == 3
#define	LDCODE	(BPF_LD | BPF_W | BPF_IND)
#elif LOAD == 4
#define	LDCODE	(BPF_LD | BPF_H | BPF_IND)
#elif LOAD == 5
#define	LDCODE	(BPF_LD | BPF_B | BPF_IND)
#endif

static u_char g_pkt[BUFLEN == 0 ? 1 : BUFLEN];

void
proof_bpf_filter(void)
{
	struct bpf_insn prog[3];

	/*
	 * prog[0] seeds X with a nondeterministic value (BPF_LDX|BPF_IMM sets
	 * X = k), so the X-indexed loads are driven over any X.  prog[1] is the
	 * load under test with a nondeterministic k.  prog[2] returns.
	 */
	prog[0].code = BPF_LDX | BPF_IMM;
	prog[0].jt = 0;
	prog[0].jf = 0;
	prog[0].k = nondet_uint();

	prog[1].code = LDCODE;
	prog[1].jt = 0;
	prog[1].jf = 0;
	prog[1].k = nondet_uint();

	prog[2].code = BPF_RET | BPF_K;
	prog[2].jt = 0;
	prog[2].jf = 0;
	prog[2].k = 0;

	/*
	 * buflen == wirelen == BUFLEN (non-zero), so the load takes the direct
	 * p[k] path, not the mbuf fallback.  If the guard is correct the read
	 * stays within g_pkt; CBMC bounds-checks the dereference against the
	 * BUFLEN-byte object.
	 */
	(void)bpf_filter(prog, g_pkt, BUFLEN, BUFLEN);
}
