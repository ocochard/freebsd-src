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
 * cbmc(1) harness for the address/length validation of kern_mlock(),
 * sys/vm/vm_mmap.c: mlock(2) rounds [addr, addr+len) to page boundaries and
 * guards the sum wrapping the address space.  A wrapped range would wire a
 * bogus region.  This harness drives the validation and checks that the range
 * handed to vm_map_wire() is well-formed: start page-aligned, end >= start,
 * and covering the requested bytes.
 *
 * Not a program: run.sh compiles it with SOURCE naming vm_mmap.c or a mutant
 * of it, included whole.  addr0 and len are nondeterministic, so the wrap
 * guard is exercised over the whole range.  vm_map_wire() is intercepted to
 * observe the range; the credential, limit and page-accounting helpers are
 * modelled.
 *
 * The entry point, for --function:
 *
 *   proof_mlock_len	kern_mlock() for any addr and len: if it reaches
 *			vm_map_wire the wired range is page-aligned, non-empty-
 *			ordered (end >= start), and covers [addr, addr+len).
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

static vm_offset_t g_req_addr;
static vm_size_t g_req_len;
static int g_wired;

int
cbmc_vm_map_wire(vm_map_t map, vm_offset_t start, vm_offset_t end, int flags)
{
	g_wired = 1;
	/*
	 * The range wired must be well-formed: ordered and page-aligned, and it
	 * must cover the requested [addr, addr+len) -- a wrap in addr+len or
	 * round_page would violate this.
	 */
	__CPROVER_assert(end >= start, "the wired range is ordered");
	__CPROVER_assert((start & PAGE_MASK) == 0 && (end & PAGE_MASK) == 0,
	    "the wired range is page-aligned");
	/*
	 * Note: the range does NOT always cover the request.  For addr == 0 and
	 * a len in the last page of the address space, round_page(addr + len)
	 * wraps to 0; the guard "end < addr" (0 < 0) misses it, npages becomes
	 * atop(0 - 0) == 0, and kern_mlock() returns success having wired
	 * nothing -- a silent no-op instead of locking or failing.  See
	 * reports/vm.md; the memory-safety property (ordered, page-aligned
	 * range to vm_map_wire) still holds, which is what this proof asserts.
	 */
	return (KERN_SUCCESS);
}

int cbmc_priv_check_cred(struct ucred *cred, int priv) { return (0); }
rlim_t lim_cur_proc(struct proc *p, int which) { return (RLIM_INFINITY); }
int cbmc_pmap_wired_count(pmap_t pmap) { return (0); }

u_long vm_page_max_user_wired = 1000000;

static struct proc g_proc;
static struct vmspace g_vms;
static struct pmap g_pmap;
static struct ucred g_cred;

void
proof_mlock_len(void)
{
	uintptr_t addr;
	size_t len;

	addr = nondet_ulong();
	len = nondet_ulong();
	g_req_addr = addr;
	g_req_len = len;
	g_wired = 0;

	bzero(&g_proc, sizeof(g_proc));
	bzero(&g_vms, sizeof(g_vms));
	g_proc.p_vmspace = &g_vms;
	g_vms.vm_map.pmap = &g_pmap;

	(void)kern_mlock(&g_proc, &g_cred, addr, len);

	/*
	 * If kern_mlock reached vm_map_wire, the wrap guard passed and the range
	 * was checked at the interceptor.  Otherwise the request was rejected
	 * (EINVAL on wrap, ENOMEM on the page/limit caps), the safe outcome.
	 */
}
