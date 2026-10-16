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
 * cbmc(1) harness for the SCM_RIGHTS control messages of Unix sockets,
 * sys/kern/uipc_usrreq.c: unp_internalize(), which turns a sender's
 * file descriptors into file references, and unp_externalize(), which
 * installs them in the receiver's descriptor table.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_usrreq.c or
 * a mutant of it, included whole.  The descriptor table (fget_noref(),
 * fhold(), filecaps_copy(), fdallocn(), _finstall()), the control mbufs
 * (sbcreatecontrol()) and the file garbage collector (unp_discard(),
 * closef_nothread(), unp_internalize_fp(), unp_externalize_fp()) are
 * modelled by what they do, recorded in ghost state.  The files passed
 * are regular files, not sockets, so no unpcb message count is touched;
 * the reference is unix.4 and recv.2.  The entry points, for --function:
 *
 *   proof_internalize	unp_internalize() on a control buffer of one
 *			SCM_RIGHTS message of up to NF descriptors, open or
 *			not, passable or not: every descriptor checked, each
 *			file held once, or the whole operation rejected with
 *			every hold rolled back, nothing left referenced
 *   proof_externalize	unp_externalize() on the internalized message:
 *			a descriptor allocated and the file installed for
 *			each, its reference handed on, or on failure every
 *			file discarded once, no reference leaked, the array
 *			freed
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
static void *cbmc_umalloc(size_t size, struct malloc_type *type, int flags);
static int cbmc_ufree(void *addr, struct malloc_type *type);
#define	CBMC_MALLOC_HOOK	cbmc_umalloc
#define	CBMC_FREE_HOOK	cbmc_ufree
#include "kern.h"

#define	NF	3		/* descriptors in the message */
#ifndef NFDS
#define	NFDS	2
#endif

/* The M_FILECAPS fdep array: counted, to catch a leak or double free. */
static int g_arrays;
static char g_arrbuf[NF * 64];
static int g_arrused;

static void *
cbmc_umalloc(size_t size, struct malloc_type *type, int flags)
{
	__CPROVER_assert(size <= sizeof(g_arrbuf), "model: array fits");
	g_arrays++;
	g_arrused = 1;
	return (g_arrbuf);
}

static struct filedescent g_fdev[NF];	/* externalize's message array */

static int
cbmc_ufree(void *addr, struct malloc_type *type)
{
	if (addr != g_arrbuf && addr != g_fdev)
		return (0);			/* not ours */
	__CPROVER_assert(g_arrays > 0, "the array freed no more than allocated");
	g_arrays--;
	return (1);
}

static struct {
	struct fdescenttbl t;
	struct filedescent e[NF];
} g_tbl;
static struct filedesc g_fdp;
static struct proc g_proc;
static struct thread *g_td;
static struct file g_file[NF];
static struct fileops g_ops, g_ops_np;
static struct ucred g_cred;
static struct prison g_prison;

/* Each file: held and released counts, and whether it was discarded. */
static int g_hold[NF], g_intfp[NF], g_extfp[NF], g_discard[NF], g_installed[NF];
static int g_rights;		/* unp_rights, net references outstanding */
static int g_basecount;		/* total f_count before the call */

static int
fidx(struct file *fp)
{
	__CPROVER_assert(fp >= &g_file[0] && fp < &g_file[NF],
	    "a file of the table");
	return (fp - &g_file[0]);
}

/* fget_noref(): the descriptor's file, or NULL. */
struct file *
fget_noref(struct filedesc *fdp, int fd)
{
	__CPROVER_assert(fdp == &g_fdp, "the process's table");
	if (fd < 0 || fd >= NF)
		return (NULL);
	return (g_tbl.e[fd].fde_file);
}

bool
fhold(struct file *fp)
{
	int i = fidx(fp);

	if (fp->f_count == 0 || nondet_bool())	/* may be closing */
		return (false);
	fp->f_count++;
	g_hold[i]++;
	return (true);
}

int
_fdrop(struct file *fp, struct thread *td)
{
	int i = fidx(fp);

	__CPROVER_assert(fp->f_count == 0, "dropped on the last reference");
	g_discard[i]++;
	return (0);
}

void
filecaps_copy_finish(const struct filecaps *src, struct filecaps *dst,
    u_long *ioctls)
{
}

bool
filecaps_copy(const struct filecaps *src, struct filecaps *dst, bool locked)
{
	memset(dst, 0, sizeof(*dst));
	return (true);
}

void filecaps_free(struct filecaps *fcaps) { }
void filecaps_move(struct filecaps *src, struct filecaps *dst) { }
void filecaps_fill(struct filecaps *fcaps) { }
void filecaps_validate_(const struct filecaps *fc, const char *f) { }

/* unp_internalize_fp(): a reference taken for the message. */
void
cbmc_unp_internalize_fp(struct file *fp)
{
	g_intfp[fidx(fp)]++;
	g_rights++;
}

/* unp_externalize_fp(): a reference handed back. */
int
cbmc_unp_externalize_fp(struct file *fp)
{
	g_extfp[fidx(fp)]++;
	g_rights--;
	return (0);		/* not a socket: no deferred close */
}

/* unp_discard(): a file no longer passed; its reference let go. */
static int g_released[NF];

void
cbmc_unp_discard(struct file *fp)
{
	g_released[fidx(fp)]++;
	(void)cbmc_unp_externalize_fp(fp);
	if (refcount_release(&fp->f_count))
		(void)_fdrop(fp, g_td);
}

/* sbcreatecontrol(): a control mbuf with room for a cmsghdr and size. */
static struct mbuf g_cmbuf[NF + 2];
static int g_ncmbuf;
static char g_cdata[NF + 2][CMSG_SPACE(sizeof(struct cmsgcred))];

struct mbuf *
sbcreatecontrol(const void *p, u_int size, int type, int level, int wait)
{
	struct mbuf *m;
	struct cmsghdr *cp;

	__CPROVER_assert(g_ncmbuf < NF + 2, "model: control mbufs");
	__CPROVER_assert(CMSG_SPACE(size) <= sizeof(g_cdata[0]),
	    "model: control data fits");
	m = &g_cmbuf[g_ncmbuf];
	m->m_data = g_cdata[g_ncmbuf];
	g_ncmbuf++;
	m->m_len = CMSG_SPACE(size);
	m->m_next = NULL;
	m->m_type = MT_CONTROL;
	m->m_flags = 0;
	cp = mtod(m, struct cmsghdr *);
	memset(cp, 0, CMSG_SPACE(size));
	if (p != NULL)
		memcpy(CMSG_DATA(cp), p, size);
	cp->cmsg_len = CMSG_LEN(size);
	cp->cmsg_level = level;
	cp->cmsg_type = type;
	return (m);
}

void
m_chtype(struct mbuf *m, short type)
{
	m->m_type = type;
}

/* fdallocn(): n new descriptors, or EMFILE. */
static int g_nextfd;

int
fdallocn(struct thread *td, int minfd, int *fds, int n)
{
	int i;

	if (nondet_bool())
		return (EMFILE);
	for (i = 0; i < NF; i++)
		if (i < n)
			fds[i] = g_nextfd++;
	return (0);
}

/* _finstall(): the file placed at fd, its reference now the table's. */
void
_finstall(struct filedesc *fdp, struct file *fp, int fd, int flags,
    struct filecaps *fcaps)
{
	__CPROVER_assert(fdp == &g_fdp, "the receiver's table");
	g_installed[fidx(fp)]++;
}

void
closef_nothread(struct file *fp)
{
	(void)_fdrop(fp, g_td);
}

/* The locks unp_internalize_fp() and friends take. */
void microtime(struct timeval *tv) { }
void bintime(struct bintime *bt) { }
void nanotime(struct timespec *ts) { }
void nanouptime(struct timespec *ts) { }

void _rw_wlock_cookie(volatile uintptr_t *c, const char *f, int l) { }
void _rw_wunlock_cookie(volatile uintptr_t *c, const char *f, int l) { }
int _sx_slock_int(struct sx *sx, int opts) { return (0); }
void _sx_sunlock_int(struct sx *sx) { }
int _sx_slock(struct sx *sx, int o, const char *f, int l) { return (0); }
void _sx_sunlock(struct sx *sx, const char *f, int l) { }
int _sx_xlock(struct sx *sx, int o, const char *f, int l) { return (0); }
void _sx_xunlock(struct sx *sx, const char *f, int l) { }

static void
setup(void)
{
	int i, k;

	g_td = curthread;
	g_td->td_proc = &g_proc;
	g_td->td_ucred = &g_cred;
	g_proc.p_fd = &g_fdp;
	g_proc.p_pid = 1;
	g_cred.cr_prison = &g_prison;
	g_ops.fo_flags = DFLAG_PASSABLE;
	g_ops_np.fo_flags = 0;			/* not passable */
	for (i = 0; i < NF; i++) {
		g_file[i].f_count = 1;		/* the sender's descriptor */
#ifdef UNIFORM
		g_file[i].f_ops = &g_ops;
#else
		g_file[i].f_ops = nondet_bool() ? &g_ops : &g_ops_np;
#endif
		g_file[i].f_type = DTYPE_PIPE;	/* not a socket */
		g_file[i].f_cred = &g_cred;
	}
	/* The sender's table: each slot open or not, any file. */
	for (i = 0; i < NF; i++) {
		if (nondet_bool()) {
			k = nondet_int();
			__CPROVER_assume(k >= 0 && k < NF);
			g_tbl.e[i].fde_file = &g_file[k];
			g_file[k].f_count++;
		} else
			g_tbl.e[i].fde_file = NULL;
	}
	g_tbl.t.fdt_nfiles = NF;
	g_fdp.fd_files = &g_tbl.t;
	for (i = 0; i < NF; i++)
		g_basecount += g_file[i].f_count;
}

/* A control buffer: a cmsghdr, SCM_RIGHTS, then nfds ints of fd values. */
static char g_ctl[sizeof(struct cmsghdr) + NF * sizeof(int) + 8];
static struct mbuf g_control;

/* m_freem(): the control buffer, or a control mbuf of the chain. */
void
m_freem(struct mbuf *m)
{
	while (m != NULL) {
		__CPROVER_assert(m == &g_control || (m >= &g_cmbuf[0] &&
		    m < &g_cmbuf[NF + 2]), "a control mbuf of the harness");
		m = m->m_next;
	}
}

static int
build_control(int nfds, int level, int type)
{
	struct cmsghdr *cm = (struct cmsghdr *)g_ctl;
	int *fdp = (int *)CMSG_DATA(cm);
	int i;

	cm->cmsg_len = CMSG_LEN(nfds * sizeof(int));
	cm->cmsg_level = level;
	cm->cmsg_type = type;
	for (i = 0; i < NF; i++)
		if (i < nfds) {
			fdp[i] = nondet_int();
			__CPROVER_assume(fdp[i] >= -1 && fdp[i] <= NF);
		}
	g_control.m_data = g_ctl;
	/* Maybe a trailing byte past the message: unp_internalize rejects it. */
	{
		/* A trailer of up to a cmsghdr less one byte: too short to be
		 * another message, so unp_internalize leaves clen > 0. */
		int extra = nondet_int();
		__CPROVER_assume(extra >= 0 && extra < (int)sizeof(*cm));
		g_control.m_len = CMSG_SPACE(nfds * sizeof(int)) + extra;
		g_control.m_next = NULL;
		g_control.m_type = MT_CONTROL;
		return (extra);
	}
}

/*
 * The total of every file's reference count, against the baseline taken
 * before the call: it rose by one per file reference the message now
 * holds (unp_rights), no reference lost or leaked.
 */
static void
check_balance(void)
{
	int i, total;

	for (i = 0, total = 0; i < NF; i++)
		total += g_file[i].f_count;
	for (i = 0; i < NF; i++)
		total -= g_installed[i];	/* now the receiver table's */
	__CPROVER_assert(total == g_basecount + g_rights,
	    "every reference accounted: the baseline, the rights held, and "
	    "those handed to the table");
	for (i = 0; i < NF; i++)
		__CPROVER_assert(g_file[i].f_count > 0,
		    "no file over-released");
}

void
proof_internalize(void)
{
	struct mchain mc;
	int error, i, nfds, needsopts, level, type, bad;
#define	EBADF_NONE	0

	setup();
	nfds = NFDS;
	level = nondet_bool() ? SOL_SOCKET : 0;
	type = nondet_int();
	__CPROVER_assume(type == SCM_RIGHTS || type == SCM_CREDS ||
	    type == SCM_TIMESTAMP);
	(void)build_control(nfds, level, type);

	/* What the sender's message asks of each passed descriptor. */
	bad = EBADF_NONE;
	if (level == SOL_SOCKET && type == SCM_RIGHTS)
		for (i = 0; i < NF; i++)
			if (i < nfds && bad == EBADF_NONE) {
				int fd = ((int *)CMSG_DATA((struct cmsghdr *)
				    g_ctl))[i];
				struct file *fp = (fd >= 0 && fd < NF) ?
				    g_tbl.e[fd].fde_file : NULL;

				/* First failing descriptor in order wins. */
				if (fp == NULL)
					bad = EBADF;
				else if ((fp->f_ops->fo_flags &
				    DFLAG_PASSABLE) == 0)
					bad = EOPNOTSUPP;
			}
	needsopts = 0;

	error = unp_internalize(&g_control, &mc, g_td, &needsopts);

	if (level == SOL_SOCKET && type == SCM_RIGHTS && nfds > 0 && bad != 0)
		__CPROVER_assert(error == bad,
		    "the first missing or non-passable descriptor is rejected");


	if (error == 0 && level == SOL_SOCKET && type == SCM_RIGHTS &&
	    nfds > 0) {
		__CPROVER_assert((needsopts & SO_PASSRIGHTS) != 0,
		    "SCM_RIGHTS asks for SO_PASSRIGHTS");
		for (i = 0; i < NF; i++)
			if (i < nfds) {
				struct file *fp = g_tbl.e[0].fde_file;
				(void)fp;
			}
		for (i = 0; i < NF; i++)
			__CPROVER_assert(g_hold[i] == g_intfp[i],
			    "each file held is internalized once");
	}
	if (error != 0)
		__CPROVER_assert(g_rights == 0,
		    "on an error every reference taken is rolled back");
	if (error != 0)
		__CPROVER_assert(g_arrays == 0,
		    "on an error every fdep array is freed");
	check_balance();
}

/*
 * unp_externalize() on a control mbuf as unp_internalize() builds it: a
 * SCM_RIGHTS message whose data is NFDS filedescent pointers, each file
 * holding a reference for the message.  A descriptor is allocated and the
 * file installed for each, the message's reference handed to the table;
 * or on a failure every file is discarded once, no reference leaked, and
 * the fdep array is freed.  so_options may lack SO_PASSRIGHTS, or
 * controlp be NULL: then the files are freed, none installed.
 */
static struct socket g_so;
static struct filedescent *g_fdep[NF];
static struct mbuf g_xctl;
static char g_xdata[CMSG_SPACE(NF * sizeof(void *))];

void
proof_externalize(void)
{
	struct cmsghdr *cm;
	struct filedescent **fdepp;
	struct mbuf *cp;
	int error, i, nfds, pass, wantfds, flags;

	setup();
	nfds = NFDS;
	/*
	 * The message unp_internalize() made: its data an array of
	 * filedescent pointers, each file referenced for the message.
	 */
	g_basecount = 0;
	for (i = 0; i < NF; i++)
		g_basecount += g_file[i].f_count;	/* before message refs */
	if (nfds > 0)
		g_arrays = 1;			/* the message's fdep array */
	for (i = 0; i < NF; i++)
		if (i < nfds) {
			g_fdev[i].fde_file = &g_file[i];
			memset(&g_fdev[i].fde_caps, 0, sizeof(g_fdev[i].fde_caps));
			g_fdep[i] = &g_fdev[i];
			g_file[i].f_count++;		/* the message's ref */
			g_rights++;
		}
	g_xctl.m_data = g_xdata;
	g_xctl.m_len = CMSG_SPACE(nfds * sizeof(void *));
	g_xctl.m_next = NULL;
	g_xctl.m_type = MT_CONTROL;
	cm = mtod(&g_xctl, struct cmsghdr *);
	cm->cmsg_len = CMSG_LEN(nfds * sizeof(void *));
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	fdepp = (struct filedescent **)CMSG_DATA(cm);
	for (i = 0; i < NF; i++)
		if (i < nfds)
			fdepp[i] = g_fdep[i];
	pass = nondet_bool();
	g_so.so_options = pass ? SO_PASSRIGHTS : 0;
	flags = nondet_int();
	wantfds = nondet_bool();

	cp = NULL;
	error = unp_externalize(&g_so, &g_xctl,
	    wantfds ? &cp : NULL, flags);

	/*
	 * The message always consumes its references: installed in the
	 * table (handed on), or discarded.  Descriptor allocation may fail
	 * (EMFILE), and then the files are discarded, not installed.
	 */
	__CPROVER_assert(error == 0 || error == EMFILE,
	    "externalize succeeds or fails only to allocate descriptors");
	for (i = 0; i < NF; i++)
		if (i < nfds) {
			if (wantfds && pass && error == 0)
				__CPROVER_assert(g_installed[i] == 1 &&
				    g_released[i] == 0 && g_extfp[i] == 1,
				    "each file installed, once, its reference "
				    "handed to the table");
			else
				__CPROVER_assert(g_installed[i] == 0 &&
				    g_released[i] == 1,
				    "else each file's message reference "
				    "released, once");
		}
	check_balance();
	__CPROVER_assert(g_rights == 0,
	    "the message holds no reference after externalize");
	__CPROVER_assert(g_arrays == 0,
	    "the fdep array is freed, installed or not");
}
