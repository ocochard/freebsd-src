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
 * cbmc(1) harness for the length/offset validation of kern_mmap(),
 * sys/vm/vm_mmap.c: mmap(2) adds the page offset to the requested length and
 * rounds up to a page, then guards against the sum wrapping to zero.  A
 * wrapped size would map fewer pages than asked, an overflow bug class.
 * This harness drives the anonymous path and checks that the size actually
 * passed on to the mapping is never smaller than the requested length and is
 * page-aligned.
 *
 * Not a program: run.sh compiles it with SOURCE naming vm_mmap.c or a mutant
 * of it, included whole.  len and pos are nondeterministic, so the rounding
 * and the wrap guard are exercised over the whole range.  vm_mmap_object()
 * is intercepted to observe the size handed to it; kern_mmap_maxprot() and
 * the racct hook are modelled.
 *
 * The entry point, for --function:
 *
 *   proof_mmap_len	kern_mmap() for an anonymous mapping of any len and
 *			pos: if it reaches the mapping, the size passed is at
 *			least len and page-aligned (the wrap guard held).
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* The size handed to the mapping, recorded by the interceptor. */
static vm_size_t g_map_size;
static vm_size_t g_req_len;
static int g_mapped;

int
cbmc_vm_mmap_object(vm_map_t map, vm_offset_t *addr, vm_size_t size,
    vm_prot_t prot, vm_prot_t maxprot, int flags, vm_object_t object,
    vm_ooffset_t foff, boolean_t writecounted, struct thread *td)
{
	g_map_size = size;
	g_mapped = 1;
	/*
	 * The size that reaches the mapping must cover the requested length
	 * and be a whole number of pages: a wrap in len + pageoff / round_page
	 * would violate this and map too little.
	 */
	__CPROVER_assert(size >= g_req_len,
	    "the mapped size is at least the requested length");
	__CPROVER_assert((size & PAGE_MASK) == 0,
	    "the mapped size is page-aligned");
	return (0);
}

int cbmc_kern_mmap_maxprot(struct proc *p, int prot) { return (VM_PROT_ALL); }
rlim_t lim_max(struct thread *td, int which) { return (nondet_long()); }
int
exterr_set(int eerror, int category, const char *mmsg, uint64ptr_t p1,
    uint64ptr_t p2, int lno)
{
	return (eerror);
}

extern struct thread cbmc_thread;	/* the curthread model's thread */
extern struct proc cbmc_proc;
static struct vmspace g_vms;
static struct sysentvec g_sv;

void
proof_mmap_len(void)
{
	struct mmap_req mr;
	vm_size_t len;
	off_t pos;

	len = nondet_ulong();
	pos = nondet_long();

	/*
	 * Drive with the curthread model's thread, which SV_CURPROC_FLAG also
	 * reads; give its proc a vmspace and a sysentvec (no SV_AOUT).
	 */
	cbmc_thread.td_proc = &cbmc_proc;
	cbmc_proc.p_vmspace = &g_vms;
	cbmc_proc.p_sysent = &g_sv;
	g_sv.sv_flags = 0;

	bzero(&mr, sizeof(mr));
	mr.mr_hint = 0;
	mr.mr_len = len;
	mr.mr_prot = VM_PROT_READ | VM_PROT_WRITE;
	mr.mr_flags = MAP_ANON | MAP_PRIVATE;	/* anonymous: no file, no FIXED */
	mr.mr_fd = -1;
	mr.mr_pos = pos;
	mr.mr_check_fp_fn = NULL;
	g_req_len = len;
	g_mapped = 0;

	(void)kern_mmap(&cbmc_thread, &mr);

	/* If the mapping ran, the size invariant was checked at the interceptor.
	 * If not, the request was rejected (e.g. ENOMEM on the wrap guard),
	 * which is the safe outcome. */
}
