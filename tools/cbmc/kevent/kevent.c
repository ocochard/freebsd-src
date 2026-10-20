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
 * cbmc(1) harness for kevent(2), sys/kern/kern_event.c: sys_kevent(),
 * kern_kevent(), kern_kevent_fp() and kqueue_kevent(), the layer between
 * the process's change and event lists and the kqueue.
 *
 * Not a program: run.sh compiles it with SOURCE naming kern_event.c or a
 * mutant of it, included whole.  kqueue_register() and kqueue_scan(),
 * which run.sh replaces, are modelled by what they are given and return;
 * fget() and the copies by the descriptor and the process's memory.  The
 * reference is the manual page, lib/libsys/kqueue.2.  The one entry
 * point, for --function:
 *
 *   proof_kevent	kevent(2) on a kqueue or not, up to NC changes and
 *			NE events, a timeout or none, any registration
 *			results and faults: every change applied in order
 *			before any event is read, an error or EV_RECEIPT
 *			reported as an EV_ERROR event where there is room,
 *			the call failing with the error where not and the
 *			changes after it left; the count returned, the
 *			events read only when no change reported one.
 *			-DNEGEVENTS lets nevents be negative (EINVAL);
 *			-DZEROFILTER a change have filter 0, -DOUTFAULT
 *			the EV_ERROR copy fault: the manual's EINVAL and
 *			EFAULT, open questions
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include <sys/refcount.h>
#include "kern.h"

#ifndef NC
#define	NC	3		/* changes */
#endif
#define	NE	3		/* events */

static struct file g_kqfp, g_otherfp;
static bool g_gotkq;
static struct kqueue g_kq;
static struct kevent g_uchg[NC], g_uev[NE];
static struct timespec g_uts;
static int g_nevents0;

/* fget(): the kqueue's file, another, or EBADF. */
int
fget(struct thread *td, int fd, const cap_rights_t *rightsp,
    struct file **fpp)
{
	if (fd < 0 || nondet_bool())
		return (EBADF);
	*fpp = nondet_bool() ? &g_kqfp : &g_otherfp;
	g_gotkq = *fpp == &g_kqfp;
	(*fpp)->f_count++;
	return (0);
}

void wakeup(const void *chan) { }

int
_fdrop(struct file *fp, struct thread *td)
{
	__CPROVER_assert(0, "the descriptor keeps its reference");
	return (0);
}

/* The process's memory: the lists and the timeout, or faults. */
static int g_infault, g_tsfault;

int
cbmc_copyin(const void *udaddr, void *kaddr, size_t len)
{
	if (udaddr == &g_uts) {
		__CPROVER_assert(len == sizeof(g_uts), "reads the timeout");
		if (nondet_bool()) {
			g_tsfault = 1;
			return (EFAULT);
		}
		memcpy(kaddr, udaddr, len);
		return (0);
	}
	__CPROVER_assert((char *)udaddr >= (char *)g_uchg &&
	    (char *)udaddr + len <= (char *)&g_uchg[NC],
	    "reads only the change list");
	if (nondet_bool()) {
		g_infault = 1;
		return (EFAULT);
	}
	memcpy(kaddr, udaddr, len);
	return (0);
}

static int g_nout, g_outfault;

int
cbmc_copyout(const void *kaddr, void *udaddr, size_t len)
{
	__CPROVER_assert(g_nevents0 >= 0 &&
	    (char *)udaddr >= (char *)g_uev &&
	    (char *)udaddr + len <= (char *)&g_uev[g_nevents0],
	    "writes within the event list's nevents entries");
#ifdef OUTFAULT
	if (nondet_bool()) {
		g_outfault = 1;
		return (EFAULT);
	}
#endif
	memcpy(udaddr, kaddr, len);
	g_nout += len / sizeof(struct kevent);
	return (0);
}

/*
 * kqueue_register(): each change it is given, in order, and the error
 * it returns for it.
 */
static int g_nreg, g_regerr[NC], g_regidx[NC];
static bool g_scanned;

static int
next_change(int k)
{
	int i, j = 0;

	for (i = 0; i < NC; i++)
		if (i < k)
			j++;
	return (j);
}

int
cbmc_kqueue_register(struct kqueue *kq, struct kevent *kev, struct thread *td,
    int mflag)
{
	int e;

	__CPROVER_assert(kq == &g_kq && !g_scanned,
	    "changes applied to the kqueue before any event is read");
	__CPROVER_assert(g_nreg < NC, "model: changes");
	__CPROVER_assert((kev->flags & EV_SYSFLAGS) == 0,
	    "the system's flags cleared");
	e = nondet_bool() ? 0 : (nondet_bool() ? ENOENT : EBADF);
	g_regerr[g_nreg] = e;
	g_regidx[g_nreg] = kev->ident;	/* the change's ident: its index */
	g_nreg++;
	return (e);
}

/* kqueue_scan(): up to maxevents events read, or an error. */
static int g_scanmax, g_scanret, g_scanerr;
static bool g_scants;
static struct timespec g_scantsv;

int
cbmc_kqueue_scan(struct kqueue *kq, int maxevents,
    struct kevent_copyops *k_ops, const struct timespec *tsp,
    struct kevent *keva, struct thread *td)
{
	__CPROVER_assert(kq == &g_kq && !g_scanned, "reads events once");
	g_scanned = true;
	g_scanmax = maxevents;
	g_scants = tsp != NULL;
	if (tsp != NULL)
		g_scantsv = *tsp;
	if (maxevents < 0) {
		g_scanerr = EINVAL;
		return (EINVAL);
	}
	if (nondet_bool()) {
		g_scanerr = nondet_bool() ? EINTR : EINVAL;
		return (g_scanerr);
	}
	g_scanret = nondet_int();
	__CPROVER_assume(g_scanret >= 0 && g_scanret <= maxevents);
	td->td_retval[0] = g_scanret;
	return (0);
}

void
proof_kevent(void)
{
	struct thread *td = curthread;
	struct kevent_args uap;
	struct timespec ts;
	int error, i, nchanges, nevents, out, k, e, expect;
	bool stopped, tsset, receipt;

	g_kqfp.f_type = DTYPE_KQUEUE;
	g_kqfp.f_data = &g_kq;
	g_kqfp.f_count = 1;
	g_otherfp.f_type = DTYPE_VNODE;
	g_otherfp.f_count = 1;
	g_kq.kq_refcnt = 1;
	g_kq.kq_state = 0;
	for (i = 0; i < NC; i++) {
		g_uchg[i].ident = i;
		g_uchg[i].filter = nondet_int();
		g_uchg[i].flags = nondet_int();
		g_uchg[i].data = nondet_int();
#ifndef ZEROFILTER
		__CPROVER_assume(g_uchg[i].filter != 0);
#endif
	}
	nchanges = nondet_int();
	nevents = nondet_int();
	__CPROVER_assume(nchanges >= -1 && nchanges <= NC);
#ifdef NEGEVENTS
	__CPROVER_assume(nevents >= -1 && nevents <= NE);
#else
	__CPROVER_assume(nevents >= 0 && nevents <= NE);
#endif
	g_nevents0 = nevents;
	tsset = nondet_bool();
	uap.fd = nondet_int();
	uap.changelist = g_uchg;
	uap.nchanges = nchanges;
	uap.eventlist = g_uev;
	uap.nevents = nevents;
	uap.timeout = tsset ? &g_uts : NULL;
	td->td_retval[0] = -1;

	error = sys_kevent(td, &uap);

	__CPROVER_assert(g_kqfp.f_count == 1 && g_otherfp.f_count == 1 &&
	    g_kq.kq_refcnt == 1, "the descriptor and kqueue references "
	    "let go");
	if (g_tsfault)
		__CPROVER_assert(error == EFAULT && g_nreg == 0 && !g_scanned,
		    "EFAULT: the timeout could not be read, nothing done");
	if (nchanges < 0 && g_gotkq)
		__CPROVER_assert(error == EINVAL && g_nreg == 0 && !g_scanned,
		    "EINVAL: the change list's length is negative");
	if (nevents < 0 && g_gotkq)
		__CPROVER_assert(error == EINVAL && g_nreg == 0 && !g_scanned,
		    "EINVAL: the event list's length is negative, nothing done");
	if (g_infault)
		__CPROVER_assert(error == EFAULT,
		    "EFAULT: the change list could not be read");
	if (g_outfault)
		__CPROVER_assert(error == EFAULT,
		    "EFAULT: the event list could not be written");
	if (!g_scanned && g_nreg == 0 && (error == EBADF || error == EFAULT ||
	    error == EINVAL))
		return;			/* refused before any change */
	if (nchanges < 0)
		return;

	/*
	 * The manual's account of the change list, replayed.  When a copyout
	 * of an EV_ERROR event faults, the fixed kevent() returns EFAULT at
	 * that point (asserted above); the event-by-event accounting below
	 * models the fault-free path, so skip it then.
	 */
	if (g_outfault)
		return;
	out = 0;
	k = 0;
	stopped = false;
	expect = -1;
	for (i = 0; i < NC; i++) {
		if (i >= nchanges || stopped || g_infault)
			break;
		if (g_uchg[i].filter == 0) {
			__CPROVER_assert(error == EINVAL,
			    "EINVAL: a change's filter is invalid");
			continue;
		}
		__CPROVER_assert(k < g_nreg && g_regidx[k] == i,
		    "each change applied, in order");
		e = g_regerr[k++];
		receipt = (g_uchg[i].flags & EV_RECEIPT) != 0;
		if (e == 0 && !receipt)
			continue;
		if (out == nevents) {
			/* No room: the error, and no change after it. */
			stopped = true;
			expect = e;
			continue;
		}
		__CPROVER_assert(g_uev[out].ident == g_uchg[i].ident &&
		    g_uev[out].filter == g_uchg[i].filter &&
		    g_uev[out].flags == EV_ERROR && g_uev[out].data == e,
		    "an error or EV_RECEIPT reported as an EV_ERROR event");
		out++;
	}
	if (g_infault)
		return;
	__CPROVER_assert(g_nreg == k, "no change applied after the one "
	    "with no room for its EV_ERROR");
	if (stopped) {
		__CPROVER_assert(error == expect && !g_scanned,
		    "no room: the call fails with the change's error");
		return;
	}
	if (out > 0) {
		__CPROVER_assert(error == 0 && td->td_retval[0] == out &&
		    !g_scanned, "the EV_ERROR events counted, no event read");
		return;
	}
	__CPROVER_assert(g_scanned && g_scanmax == nevents &&
	    (tsset ? g_scants && g_scantsv.tv_sec == g_uts.tv_sec &&
	    g_scantsv.tv_nsec == g_uts.tv_nsec : !g_scants),
	    "then the events read, up to nevents, with the timeout given");
	__CPROVER_assert(error == g_scanerr &&
	    (error != 0 || td->td_retval[0] == g_scanret),
	    "and their count returned");
}
