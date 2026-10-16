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
 * cbmc(1) harness for vnode_pager_generic_getpages(), sys/vm/vnode_pager.c,
 * as ffs_getpages_async() calls it for sendfile(2) on UFS: the pager the
 * sendfile proofs model by what they take it to do.
 *
 * Not a program: run.sh compiles it with SOURCE naming vnode_pager.c or a
 * mutant of it, included whole.  The block map (VOP_BMAP), the page cache
 * around the run (vm_object_prepare_buf_pages()) and the disk are
 * modelled by what they give.  The reference is the contract of
 * VOP_GETPAGES_ASYNC as its wrappers, ffs_getpages_async() and
 * vnode_pager_local_getpages_async(), take it, and as the sendfile model
 * (sendfile/sendfile.c, vm_pager_get_pages_async()) assumes it: success,
 * and the completion runs once, now or when the read is done, on the run
 * it was given; an error, and it has not run, the wrapper running it.
 * On a completion without error the run's pages are valid up to the end
 * of the file; read-behind and read-ahead pages are freed or handed to
 * the page queues; the pages the caller busied stay busied.  The one
 * entry point, for --function:
 *
 *   proof_getpages	a run of up to NR pages of a file of NP, from
 *			vm_pager_assert_in(): consecutive, busied, not all
 *			valid, the bogus page inside it; read-behind and
 *			read-ahead asked for or not, a block of BSIZE, any
 *			block map and sector size, the read failing or not.
 *			-DUFS keeps to what UFS gives: a block map, blocks
 *			of at least a page, no hole where vm_pager_has_page()
 *			found a block.  -DLASTVALID lets the run end on the
 *			file's last page valid up to its end, which
 *			sendfile_swapin() never passes
 */

#include SOURCE

#include <sys/mbuf.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <vm/uma.h>

static void *cbmc_uma(uma_zone_t zone, int flags);
static void cbmc_uma_free(uma_zone_t zone, void *item);
#define	CBMC_UMA_HOOK		cbmc_uma
#define	CBMC_UMA_FREE_HOOK	cbmc_uma_free
#include "kern.h"

#define	NP	4		/* pages of the file */
#ifndef BSIZE
#define	BSIZE	PAGE_SIZE	/* the file system's block: a constant, as
				   CBMC unrolls 64-bit division by a variable
				   into a formula past 40G */
#endif
#define	NR	3		/* pages of the run */
#define	NX	2		/* read-behind and read-ahead pages, each */

static struct vm_object g_obj;
static struct vnode g_vp;
static struct mount g_mnt;
static struct bufobj g_bo;
static struct buf_ops g_bops;
static struct vm_page g_pg[NP];		/* the run's pages, by index */
static vm_page_t g_run[NR];
static struct vm_page g_bogus;
static int g_count, g_p0;

/* The completion: how often, on what, with what. */
static int g_ndone, g_dcount, g_derror;
static vm_page_t g_dpg[NR];		/* the pages it was given */
static void *g_arg = &g_arg;

static void
cbmc_iodone(void *arg, vm_page_t *m, int count, int error)
{
	__CPROVER_assert(arg == g_arg, "completes to the caller's argument");
	g_ndone++;
	for (int i = 0; i < NR; i++)
		if (i < count)
			g_dpg[i] = m[i];
	g_dcount = count;
	g_derror = error;
}

/* VOP_BMAP(): where the block is, and how many follow and precede it. */
static int g_bmap_err;
static daddr_t g_blkno;

int
VOP_BMAP_APV(const struct vop_vector *vop, struct vop_bmap_args *a)
{
	int ppb = BSIZE / PAGE_SIZE, poff, after, before;

	if (g_bmap_err != 0)
		return (g_bmap_err);
	*a->a_bop = &g_bo;
	*a->a_bnp = g_blkno;
	after = nondet_int();
	before = nondet_int();
	__CPROVER_assume(after >= 0 && after <= NP && before >= 0 &&
	    before <= NP);
	/*
	 * What vm_pager_has_page() told the caller: the blocks of the run
	 * are there, contiguous.
	 */
	poff = ppb == 0 ? 0 : g_p0 % ppb;
	__CPROVER_assume(ppb == 0 ||
	    after * ppb + ppb - (poff + 1) >= g_count - 1);
	if (a->a_runp != NULL)
		*a->a_runp = after;
	if (a->a_runb != NULL)
		*a->a_runb = before;
	return (0);
}

/* The pager buffer: B_MAXPHYS, room for the pages. */
static char g_kva[(NR + 2 * NX) * PAGE_SIZE];
static struct buf *g_bp;
static int g_bpfree;
struct pbuf {
	struct buf b;
	vm_page_t pages[NR + 2 * NX];	/* b_pages[] */
};

static void *
cbmc_uma(uma_zone_t zone, int flags)
{
	struct pbuf *pb;
	struct buf *bp;

	__CPROVER_assert(zone == vnode_pbuf_zone && g_bp == NULL,
	    "one pager buffer");
	pb = __CPROVER_allocate(sizeof(*pb), 1);	/* typed */
	bp = &pb->b;
	bp->b_flags = B_MAXPHYS;
	bp->b_rcred = bp->b_wcred = NOCRED;
	bp->b_kvabase = (caddr_t)&g_kva;
	g_bp = bp;
	return (bp);
}

/* Read-behind and read-ahead pages, new, busied. */
#define	PG_NEW		1
#define	PG_FREED	2
#define	PG_QUEUED	3
static struct vm_page g_xpg[2 * NX];
static int g_xst[2 * NX], g_nx, g_nb, g_na;

void
vm_object_prepare_buf_pages(vm_object_t object, vm_page_t *ma_dst,
    int count, int *rbehind, int *rahead, vm_page_t *ma_src)
{
	int b, a, i;

	__CPROVER_assert(object == &g_obj && ma_src == g_run &&
	    count <= g_count, "the run's pages");
	b = nondet_int();
	a = nondet_int();
	/* As many as are not cached already, up to what is asked. */
	__CPROVER_assume(b >= 0 && b <= *rbehind && a >= 0 && a <= *rahead);
	__CPROVER_assume(b <= NX && a <= NX);
	for (i = 0; i < NX; i++)
		if (i < b) {
			g_xpg[g_nx].pindex = ma_src[0]->pindex - b + i;
			g_xpg[g_nx].valid = 0;
			g_xst[g_nx] = PG_NEW;
			ma_dst[i] = &g_xpg[g_nx++];
		}
	for (i = 0; i < NR; i++)
		if (i < count)
			ma_dst[b + i] = ma_src[i];
	for (i = 0; i < NX; i++)
		if (i < a) {
			g_xpg[g_nx].pindex = ma_src[0]->pindex + count + i;
			g_xpg[g_nx].valid = 0;
			g_xst[g_nx] = PG_NEW;
			ma_dst[b + count + i] = &g_xpg[g_nx++];
		}
	*rbehind = b;
	*rahead = a;
	g_nb = b;
	g_na = a;
}

static int
xidx(vm_page_t m)
{
	__CPROVER_assert(m >= &g_xpg[0] && m < &g_xpg[g_nx],
	    "a read-behind or read-ahead page");
	return (m - &g_xpg[0]);
}

static bool
is_run(vm_page_t m)
{
	return (m >= &g_pg[0] && m < &g_pg[NP]);
}

void
vm_page_free_invalid(vm_page_t m)
{
	int i = xidx(m);

	__CPROVER_assert(g_xst[i] == PG_NEW, "a new page freed once");
	g_xst[i] = PG_FREED;
}

void
vm_page_readahead_finish(vm_page_t m)
{
	int i = xidx(m);

	__CPROVER_assert(g_xst[i] == PG_NEW, "a new page queued once");
	g_xst[i] = PG_QUEUED;
}

void
vm_page_valid(vm_page_t m)
{
	__CPROVER_assert(m != bogus_page, "the bogus page is never written");
	m->valid = VM_PAGE_BITS_ALL;
}

/* Blocks [0, size) valid, the partial last one zeroed and included. */
void
vm_page_set_valid_range(vm_page_t m, int base, int size)
{
	int nb;

	__CPROVER_assert(m != bogus_page && base == 0 && size > 0 &&
	    size < PAGE_SIZE, "the part of a page the file holds");
	nb = howmany(size, DEV_BSIZE);
	m->valid |= (vm_page_bits_t)((1u << nb) - 1);
}

void pmap_zero_page(vm_page_t m) { }
bool pmap_page_is_mapped(vm_page_t m) { return (false); }
void _lockmgr_disown(struct lock *lk, const char *file, int line) { }

/* vm_page.c: the blocks of [base, base + size). */
vm_page_bits_t
vm_page_bits(int base, int size)
{
	__CPROVER_assert(base == 0 && size > 0 && size <= PAGE_SIZE,
	    "bits of part of a page");
	return ((vm_page_bits_t)((1u << howmany(size, DEV_BSIZE)) - 1));
}
void _rw_wlock_cookie(volatile uintptr_t *c, const char *file, int line) { }
void _rw_wunlock_cookie(volatile uintptr_t *c, const char *file, int line) { }
void pmap_qenter(void *va, vm_page_t *ma, int count) { }
void pmap_qremove(void *va, int count) { }
struct ucred *crhold(struct ucred *cr) { return (cr); }
void pbgetbo(struct bufobj *bo, struct buf *bp) { bp->b_bufobj = bo; }
void pbrelbo(struct buf *bp) { }
long runningbufclaim(struct buf *bp, int space) { return (0); }
void runningbufwakeup(struct buf *bp) { }

static void
cbmc_uma_free(uma_zone_t zone, void *item)
{
	__CPROVER_assert(item == g_bp && !g_bpfree,
	    "the pager buffer freed once");
	g_bpfree = 1;
}

/* The disk: the read is queued, and completes after the call. */
static struct buf *g_io;

static void
cbmc_strategy(struct bufobj *bo, struct buf *bp)
{
	off_t foff, left, start;

	__CPROVER_assert(bo == &g_bo && g_io == NULL &&
	    (bp->b_flags & B_ASYNC) != 0 && bp->b_iocmd == BIO_READ,
	    "one asynchronous read");
	__CPROVER_assert(bp->b_npages <= g_nb + g_count + g_na &&
	    bp->b_pages[g_nb] == g_run[0],
	    "of the run, behind and ahead pages around it");
	/*
	 * The file's bytes in those pages, whole sectors: from the disk
	 * where the block map put them, its run of blocks contiguous.
	 */
	foff = ptoa(bp->b_pages[0]->pindex);
	left = g_obj.un_pager.vnp.vnp_size - foff;
	if (left > ptoa(bp->b_npages))
		left = ptoa(bp->b_npages);
	__CPROVER_assert(bp->b_bcount % bo->bo_bsize == 0 &&
	    bp->b_bcount >= left &&
	    bp->b_bcount < left + bo->bo_bsize,
	    "the file's bytes in the pages, in whole sectors, no more");
	start = (ptoa(g_p0) / BSIZE) * BSIZE;
	__CPROVER_assert(bp->b_iooffset == dbtob(g_blkno) + foff - start,
	    "from where the block map puts them");
	g_io = bp;
}

/*
 * The old way, VOP_READ() a page at a time, and the small block one:
 * run.sh replaces their calls; each page read, or an error.
 */
int
cbmc_vnode_pager_input(vm_object_t object, vm_page_t m)
{
	if (nondet_bool())
		return (VM_PAGER_ERROR);
	m->valid = VM_PAGE_BITS_ALL;
	return (VM_PAGER_OK);
}

void
proof_getpages(void)
{
	vm_page_t *m = g_run;
	int count, error, i, rb, ra, *rbp, *rap, bsize, ndone;
	off_t size;
	bool bogus[NR];

	bogus_page = &g_bogus;

	/* The file and its vnode. */
	size = nondet_int();
	__CPROVER_assume(size > ptoa(NP - 1) && size <= ptoa(NP));
	g_obj.type = OBJT_VNODE;
	g_obj.size = NP;
	g_obj.un_pager.vnp.vnp_size = size;
	g_obj.handle = &g_vp;
	g_vp.v_object = &g_obj;
	g_vp.v_mount = &g_mnt;
	g_vp.v_type = VREG;
	g_vp.v_irflag = nondet_bool() ? VIRF_DOOMED : 0;
	bsize = BSIZE;
	g_mnt.mnt_stat.f_iosize = bsize;
	g_mnt.mnt_kern_flag = nondet_bool() ? MNTK_UNMAPPED_BUFS : 0;
	g_bo.bo_bsize = nondet_bool() ? DEV_BSIZE : PAGE_SIZE;
	g_bo.bo_ops = &g_bops;
	g_bops.bop_strategy = cbmc_strategy;
	g_bmap_err = nondet_bool() ? 0 : (nondet_bool() ? EIO : EOPNOTSUPP);
	g_blkno = nondet_bool() ? -1 : 64;
#ifdef UFS
	__CPROVER_assume(bsize >= PAGE_SIZE && g_bmap_err != EOPNOTSUPP &&
	    g_blkno != -1);
#endif

	/* The run, as vm_pager_assert_in() takes it. */
	count = nondet_int();
	__CPROVER_assume(count >= 1 && count <= NR);
	g_p0 = nondet_int();
	__CPROVER_assume(g_p0 >= 0 && g_p0 < NP && g_p0 + count <= NP);
	g_count = count;
	/*
	 * What vnode_pager_generic_getpages() states of the page cache: a
	 * page is partly valid only past the end of the file, valid up to
	 * it.  The run's pages are not all valid: so the file's last page
	 * may be valid up to its end, the others none.
	 */
	for (i = 0; i < NP; i++) {
		g_pg[i].pindex = i;
		g_pg[i].object = &g_obj;
		g_pg[i].valid = 0;
		g_pg[i].dirty = 0;
	}
	if (nondet_bool())
		g_pg[NP - 1].valid = (vm_page_bits_t)((1u <<
		    howmany(size - ptoa(NP - 1), DEV_BSIZE)) - 1);
	__CPROVER_assume(g_pg[NP - 1].valid != VM_PAGE_BITS_ALL);
	for (i = 0; i < NR; i++) {
		bogus[i] = i > 0 && i < count - 1 && nondet_bool();
		if (i < count)
			m[i] = bogus[i] ? bogus_page : &g_pg[g_p0 + i];
	}
#ifndef LASTVALID
	/*
	 * And sendfile_swapin() ends a run on a page not valid over the
	 * bytes it sends, which on the file's last page are those valid:
	 * none valid.
	 */
	__CPROVER_assume(vm_page_none_valid(m[count - 1]));
#endif
	/* A hole, where vm_pager_has_page() was not asked: one page only. */
	__CPROVER_assume(g_blkno != -1 || count == 1);
	rb = nondet_int();
	ra = nondet_int();
	__CPROVER_assume(rb >= 0 && rb <= NX && ra >= 0 && ra <= NX);
	rbp = nondet_bool() ? &rb : NULL;
	rap = nondet_bool() ? &ra : NULL;

	error = vnode_pager_generic_getpages(&g_vp, m, count, rbp, rap,
	    cbmc_iodone, g_arg);

	ndone = g_ndone;
	if (error != VM_PAGER_OK) {
		/*
		 * On any error the generic routine runs no completion: the
		 * wrapper (ffs_getpages_async, vnode_pager_local_getpages_
		 * async) calls iodone on its error return, so a completion
		 * here would be a second call.  This holds for the BMAP hard
		 * error, the doomed vnode, and the no-I/O paths that fail.
		 */
		__CPROVER_assert(g_io == NULL && ndone == 0,
		    "an error, and no completion here: the wrapper runs it");
		__CPROVER_assert(g_bp == NULL || g_bpfree,
		    "the pager buffer freed");
		return;
	}
	/* The read completes, with an error or not. */
	if (g_io != NULL) {
		__CPROVER_assert(ndone == 0, "the completion waits for the read");
		if (nondet_bool()) {
			g_io->b_ioflags |= BIO_ERROR;
			g_io->b_error = EIO;
		}
		g_io->b_iodone(g_io);
	}
	__CPROVER_assert(g_ndone == 1,
	    "success, and the completion runs once");
	__CPROVER_assert(g_dcount == count, "on the run it was given");
	for (i = 0; i < NR; i++)
		if (i < count)
			__CPROVER_assert(g_dpg[i] == m[i],
			    "on the run it was given");
	__CPROVER_assert(g_bp == NULL || g_bpfree, "the pager buffer freed");
	for (i = 0; i < 2 * NX; i++)
		if (i < g_nx)
			__CPROVER_assert(g_xst[i] ==
			    (g_derror == 0 ? PG_QUEUED : PG_FREED),
			    "read-behind and read-ahead pages queued, or freed "
			    "on an error");
	if (g_io != NULL) {
		__CPROVER_assert(rbp == NULL || rb == g_nb,
		    "the read-behind done reported");
		__CPROVER_assert(rap == NULL || ra == g_na,
		    "the read-ahead done reported");
	}
	if (g_derror == 0)
		for (i = 0; i < NR; i++)
			if (i < count && !bogus[i]) {
				off_t left = size - ptoa(g_p0 + i);
				int nb = left >= PAGE_SIZE ? PAGE_SIZE /
				    DEV_BSIZE : howmany(left, DEV_BSIZE);

				__CPROVER_assert((m[i]->valid &
				    ((1u << nb) - 1)) == ((1u << nb) - 1),
				    "each page of the run valid up to the end "
				    "of the file");
			}
}
