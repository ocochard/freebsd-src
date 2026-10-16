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
 * cbmc(1) harness for close(2) and close_range(2), sys/kern/kern_descrip.c:
 * kern_close(), closefp(), closef() and kern_close_range(), on a
 * descriptor table of NF slots.
 *
 * Not a program: run.sh compiles it with SOURCE naming kern_descrip.c or
 * a mutant of it, included whole.  A file's last close (_fdrop() and its
 * fo_close()) and filecaps_free(), which run.sh replaces, knote_fdclose()
 * and VOP_ADVLOCK() are modelled by what
 * they are given; the table is the kernel's own.  The references are the
 * manual pages, lib/libsys/close.2 and closefrom.2.  A table shared by
 * process leaders (p_fdtol) is not covered.  The entry points, for
 * --function:
 *
 *   proof_close	close(2) of any descriptor, open or not, its file
 *			shared with other slots and references or not: EBADF
 *			and the table as it was, or the slot freed, its file's
 *			reference dropped once and the file deactivated on
 *			the last one, its knotes and the process's POSIX
 *			locks released, the error EINTR for ERESTART, every
 *			other slot as it was
 *   proof_close_range	close_range(2) on any range and flags: EINVAL and
 *			nothing done, or every open descriptor in the range,
 *			clamped to the table, closed or flagged
 *			close-on-exec or close-on-fork, the others as they
 *			were, 0 returned
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include <sys/event.h>
#include <sys/eventvar.h>
#include "kern.h"

#define	NF	4		/* slots in the table */

static struct {
	struct fdescenttbl t;
	struct filedescent e[NF];
} g_tbl;
static NDSLOTTYPE g_map[NDSLOTS(NF)];
static struct filedesc g_fdp;
static struct proc g_proc, g_leader;
static struct file g_f[NF];
static struct fileops g_ops[2];
static struct vnode g_vn;
static struct kqueue g_kqdummy;

/* What the table held, and what happened to each file. */
static struct file *g_was[NF];
static uint8_t g_wasflags[NF];
static int g_wascount[NF], g_lastclose[NF], g_fdclosed[NF], g_kn[NF];
static int g_unlock[NF], g_capsfreed[NF], g_xlock;
static int g_closeerr;

/* The table's lock. */
int
_sx_xlock(struct sx *sx, int opts, const char *file, int line)
{
	__CPROVER_assert(sx == &g_fdp.fd_sx && g_xlock == 0,
	    "the table locked, once");
	g_xlock = 1;
	return (0);
}

void
_sx_xunlock(struct sx *sx, const char *file, int line)
{
	__CPROVER_assert(sx == &g_fdp.fd_sx && g_xlock == 1,
	    "the table unlocked when locked");
	g_xlock = 0;
}

void
_sx_assert(const struct sx *sx, int what, const char *file, int line)
{
	if (sx == &g_fdp.fd_sx && (what & SX_XLOCKED) != 0)
		__CPROVER_assert(g_xlock == 1, "the table locked");
}

static int
fidx(struct file *fp)
{
	__CPROVER_assert(fp >= &g_f[0] && fp < &g_f[NF], "a file of the table");
	return (fp - &g_f[0]);
}

/* A file's last reference: deactivated, with fo_close()'s error. */
int
cbmc_fdrop(struct file *fp, struct thread *td)
{
	int i = fidx(fp);

	__CPROVER_assert(fp->f_count == 0 && g_lastclose[i] == 0,
	    "a file deactivated once, on its last reference");
	g_lastclose[i] = 1;
	g_closeerr = nondet_bool() ? 0 :
	    (nondet_bool() ? ERESTART : (nondet_bool() ? EINTR : ENOSPC));
	return (g_closeerr);
}

static void
cbmc_fdclose(struct file *fp, int fd, struct thread *td)
{
	__CPROVER_assert(fd >= 0 && fd < NF && g_was[fd] == fp,
	    "fo_fdclose() for the descriptor's file");
	g_fdclosed[fd]++;
}

void
knote_fdclose(struct thread *td, int fd)
{
	__CPROVER_assert(fd >= 0 && fd < NF && g_xlock == 1,
	    "the descriptor's knotes dropped, the table locked");
	g_kn[fd]++;
}

int
VOP_ADVLOCK_APV(const struct vop_vector *vop, struct vop_advlock_args *a)
{
	__CPROVER_assert(a->a_vp == &g_vn && a->a_id == (caddr_t)&g_leader &&
	    a->a_op == F_UNLCK && a->a_flags == F_POSIX &&
	    a->a_fl->l_start == 0 && a->a_fl->l_len == 0,
	    "all the process's POSIX locks on the file released");
	g_unlock[0]++;
	return (0);
}

void
cbmc_filecaps_free(struct filecaps *fcaps)
{
	int i;

	for (i = 0; i < NF; i++)
		if (fcaps == &g_tbl.e[i].fde_caps)
			g_capsfreed[i]++;
}

void wakeup(const void *chan) { }

uintptr_t
cbmc_atomic_load_ptr(const volatile uintptr_t *p)
{
	return (*p);
}

static void
setup(void)
{
	struct thread *td = curthread;
	int i, k;

	g_tbl.t.fdt_nfiles = NF;
	g_fdp.fd_files = &g_tbl.t;
	g_fdp.fd_map = g_map;
	TAILQ_INIT(&g_fdp.fd_kqlist);
	if (nondet_bool())
		TAILQ_INSERT_HEAD(&g_fdp.fd_kqlist, &g_kqdummy, kq_list);
	td->td_proc = &g_proc;
	g_proc.p_fd = &g_fdp;
	g_proc.p_fdtol = NULL;
	g_proc.p_leader = &g_leader;
	g_leader.p_flag = nondet_bool() ? P_ADVLOCK : 0;
	g_ops[0].fo_fdclose = NULL;
	g_ops[1].fo_fdclose = cbmc_fdclose;
	for (i = 0; i < NF; i++) {
		g_f[i].f_count = nondet_bool() ? 1 : 0;	/* elsewhere too */
		g_f[i].f_type = nondet_bool() ? DTYPE_VNODE : DTYPE_SOCKET;
		g_f[i].f_vnode = &g_vn;
		g_f[i].f_ops = &g_ops[nondet_bool() ? 1 : 0];
	}
	for (i = 0; i < NF; i++) {
		g_tbl.e[i].fde_flags = nondet_int();
		if (nondet_bool()) {
			k = nondet_int();
			__CPROVER_assume(k >= 0 && k < NF);
			g_tbl.e[i].fde_file = &g_f[k];
			g_f[k].f_count++;
			g_map[NDSLOT(i)] |= NDBIT(i);
		} else
			g_tbl.e[i].fde_file = NULL;
		g_was[i] = g_tbl.e[i].fde_file;
		g_wasflags[i] = g_tbl.e[i].fde_flags;
	}
	g_fdp.fd_freefile = nondet_int();
	__CPROVER_assume(g_fdp.fd_freefile >= 0 && g_fdp.fd_freefile <= NF);
	for (i = 0; i < NF; i++)
		if (i < g_fdp.fd_freefile)
			__CPROVER_assume(g_was[i] != NULL);
	for (i = 0; i < NF; i++)
		g_wascount[i] = g_f[i].f_count;
}

/* The slots closed: their files' references and what follows. */
static void
check_closed(bool closed[NF])
{
	int drops[NF], i, j;
	bool any_kq = !TAILQ_EMPTY(&g_fdp.fd_kqlist);

	for (j = 0; j < NF; j++)
		drops[j] = 0;
	for (i = 0; i < NF; i++) {
		if (closed[i]) {
			__CPROVER_assert(g_tbl.e[i].fde_file == NULL &&
			    (g_map[NDSLOT(i)] & NDBIT(i)) == 0 &&
			    g_capsfreed[i] == 1 && g_fdp.fd_freefile <= i,
			    "the descriptor freed, its capabilities too");
			__CPROVER_assert(g_kn[i] == (any_kq ? 1 : 0),
			    "its knotes dropped");
			__CPROVER_assert(g_fdclosed[i] ==
			    (g_was[i]->f_ops->fo_fdclose != NULL ? 1 : 0),
			    "the file told of the descriptor's close");
			drops[fidx(g_was[i])]++;
		} else {
			__CPROVER_assert(g_tbl.e[i].fde_file == g_was[i] &&
			    ((g_map[NDSLOT(i)] & NDBIT(i)) != 0) ==
			    (g_was[i] != NULL) && g_capsfreed[i] == 0 &&
			    g_kn[i] == 0 && g_fdclosed[i] == 0,
			    "every other descriptor as it was");
		}
	}
	for (j = 0; j < NF; j++) {
		__CPROVER_assert(g_f[j].f_count == g_wascount[j] - drops[j],
		    "a reference dropped per descriptor closed");
		__CPROVER_assert(g_lastclose[j] ==
		    (drops[j] > 0 && g_f[j].f_count == 0 ? 1 : 0),
		    "the file deactivated on its last reference only");
	}
	__CPROVER_assert(g_xlock == 0, "the table unlocked");
}

void
proof_close(void)
{
	struct close_args uap;
	bool closed[NF];
	int error, fd, i, nlocks;

	setup();
	fd = nondet_int();
	__CPROVER_assume(fd >= -1 && fd <= NF);
	uap.fd = fd;

	error = sys_close(curthread, &uap);

	for (i = 0; i < NF; i++)
		closed[i] = i == fd && g_was[i] != NULL;
	if (fd < 0 || fd >= NF || g_was[fd] == NULL) {
		__CPROVER_assert(error == EBADF,
		    "EBADF: not an active descriptor");
		check_closed(closed);
		return;
	}
	check_closed(closed);
	nlocks = g_was[fd]->f_type == DTYPE_VNODE &&
	    (g_leader.p_flag & P_ADVLOCK) != 0;
	__CPROVER_assert(g_unlock[0] == nlocks,
	    "the process's POSIX locks released on a file, on any close");
	if (g_lastclose[fidx(g_was[fd])])
		__CPROVER_assert(error ==
		    (g_closeerr == ERESTART ? EINTR : g_closeerr),
		    "the close's error, EINTR for a restart");
	else
		__CPROVER_assert(error == 0, "no error but the last close's");
}

void
proof_close_range(void)
{
	struct close_range_args uap;
	bool closed[NF];
	u_int lo, hi;
	int error, i, flags;

	setup();
	lo = nondet_u_int();
	hi = nondet_u_int();
	__CPROVER_assume(lo <= NF + 1 || lo >= INT_MAX);
	__CPROVER_assume(hi <= NF + 1 || hi >= INT_MAX);
	flags = nondet_int();
	uap.lowfd = lo;
	uap.highfd = hi;
	uap.flags = flags;

	error = sys_close_range(curthread, &uap);

	for (i = 0; i < NF; i++)
		closed[i] = false;
	if ((flags & ~(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_CLOFORK)) != 0 ||
	    hi < lo) {
		__CPROVER_assert(error == EINVAL,
		    "EINVAL: an invalid flag, or highfd below lowfd");
		check_closed(closed);
		for (i = 0; i < NF; i++)
			__CPROVER_assert(g_tbl.e[i].fde_flags == g_wasflags[i],
			    "nothing done");
		return;
	}
	__CPROVER_assert(error == 0, "0 returned, close errors ignored");
	if ((flags & (CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_CLOFORK)) != 0) {
		check_closed(closed);
		for (i = 0; i < NF; i++) {
			uint8_t want = g_wasflags[i];

			if ((u_int)i >= lo && (u_int)i <= hi &&
			    g_was[i] != NULL) {
				if (flags & CLOSE_RANGE_CLOEXEC)
					want |= UF_EXCLOSE;
				if (flags & CLOSE_RANGE_CLOFORK)
					want |= UF_FOCLOSE;
			}
			__CPROVER_assert(g_tbl.e[i].fde_flags == want,
			    "the open descriptors in the range flagged, only");
		}
		return;
	}
	for (i = 0; i < NF; i++)
		closed[i] = (u_int)i >= lo && (u_int)i <= hi && g_was[i] != NULL;
	check_closed(closed);
}
