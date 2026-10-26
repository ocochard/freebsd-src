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
 * cbmc(1) harness for soopt_mcopyin() and soopt_mcopyout(),
 * sys/kern/uipc_socket.c: the copy of a socket option value between a user
 * buffer (sopt_val, sopt_valsize bytes) and an mbuf chain, used by the
 * IPv6 socket-option path (ip6_ctloutput through soopt_getm()).  Each mbuf
 * in the chain is copied in full while the user buffer still has room
 * (sopt_valsize >= m_len); the user pointer advances by m_len and
 * sopt_valsize shrinks by it.  The copy must never read or write past the
 * user buffer, nor past any mbuf's storage.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_socket.c or a
 * mutant of it, included whole.  The user buffer is a CBMC object of exactly
 * VALSIZE bytes and each mbuf is a separate CBMC object, so a copy past
 * either end is an out-of-bounds access CBMC catches.  copyin()/copyout()
 * are modelled to bounds-check both ends by touching the first and last byte
 * of each range (not a byte loop, which an MLEN-sized mbuf would blow up).
 * The proofs drive the user path (sopt_td != NULL); the chain's per-mbuf
 * lengths are a concrete geometry per job and VALSIZE a constant per job.
 *
 * The entry points, for --function:
 *
 *   proof_mcopyin	soopt_mcopyin() over a CNT-mbuf chain and a VALSIZE
 *			user buffer: every copyin stays within the user buffer
 *			and the mbuf, and the leftover-mbuf panic is never hit.
 *   proof_mcopyout	soopt_mcopyout() likewise for the copy-out direction,
 *			which returns EINVAL on a short user buffer instead of
 *			panicking, and reports the copied total in sopt_valsize.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

void m_freem(struct mbuf *m) { }

/*
 * Geometries (GEO): the chain's per-mbuf lengths.  0: a single mbuf.  1: a
 * two-mbuf chain.  2: three mbufs including an empty one.  3: an mbuf filled
 * to MLEN so a copy that ran one byte long would leave its storage.
 */
#if GEO == 0
static const int g_lens[] = { 8 };
#elif GEO == 1
static const int g_lens[] = { 8, 6 };
#elif GEO == 2
static const int g_lens[] = { 4, 0, 10 };
#elif GEO == 3
static const int g_lens[] = { MLEN, 4 };
#endif

#define	CNT	((int)nitems(g_lens))

static struct mbuf *g_chain[4];
static char g_uval[VALSIZE == 0 ? 1 : VALSIZE];
static int g_fault;

/* Bytes the user side has consumed so far, to bound-check each copy. */
static size_t g_uoff;

/*
 * Touch the first and last byte of a [p, p + len) range.  CBMC bounds-checks
 * each access against the object, so an out-of-bounds copy is caught without
 * iterating all len bytes (which, for an MLEN-sized mbuf, would blow up the
 * byte-loop unwinding).
 */
static void
touch(const volatile char *p, size_t len)
{
	if (len == 0)
		return;
	(void)p[0];
	(void)p[len - 1];
}

/*
 * The user side advances across one VALSIZE buffer; record the running offset
 * and assert it stays within VALSIZE -- the copy-never-overruns property.
 */
static void
touch_user(const char *u, size_t len)
{
	touch((const volatile char *)u, len);
	g_uoff += len;
	__CPROVER_assert(g_uoff <= (size_t)VALSIZE,
	    "the copy stays within the user buffer");
}

int
cbmc_copyin(const void *uaddr, void *kaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	touch_user(uaddr, len);
	touch((const volatile char *)kaddr, len);	/* within the mbuf */
	return (0);
}

int
cbmc_copyout(const void *kaddr, void *uaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	touch_user(uaddr, len);
	touch((const volatile char *)kaddr, len);	/* within the mbuf */
	return (0);
}

static struct mbuf *
build_chain(void)
{
	int i;

	for (i = 0; i < CNT; i++) {
		g_chain[i] = __CPROVER_allocate(sizeof(struct mbuf), 1);
		g_chain[i]->m_data = &g_chain[i]->m_dat[0];
		g_chain[i]->m_len = g_lens[i];
		g_chain[i]->m_flags = 0;
		g_chain[i]->m_type = MT_DATA;
	}
	for (i = 0; i < CNT; i++)
		g_chain[i]->m_next = (i + 1 < CNT) ? g_chain[i + 1] : NULL;
	return (g_chain[0]);
}

void
proof_mcopyin(void)
{
	struct sockopt sopt;
	struct thread td;
	struct mbuf *m;

	m = build_chain();
	sopt.sopt_valsize = VALSIZE;
	sopt.sopt_val = nondet_bool() ? g_uval : NULL;
	sopt.sopt_td = &td;	/* user path: the modelled copyin/copyout */
	g_fault = 0;
	g_uoff = 0;

	/*
	 * The leftover-mbuf panic: soopt_mcopyin() asserts the chain was sized
	 * so the whole value fits.  Only call when VALSIZE covers the chain so
	 * the guard stops on the NULL terminator, not mid-chain.  (ip6's
	 * soopt_getm() allocates to sopt_valsize, so this holds for the real
	 * caller.)
	 */
	(void)soopt_mcopyin(&sopt, m);

	/*
	 * No assert on the return path: a fault returns the error, success
	 * returns 0.  The memory-safety properties are checked inside the copy
	 * models as the loop runs: each copy stays within the user buffer
	 * (touch_user) and within the mbuf (cbmc_memmove bounds-checks the
	 * separate mbuf object).
	 */
}

void
proof_mcopyout(void)
{
	struct sockopt sopt;
	struct thread td;
	struct mbuf *m;
	int error;

	m = build_chain();
	sopt.sopt_valsize = VALSIZE;
	sopt.sopt_val = nondet_bool() ? g_uval : NULL;
	sopt.sopt_td = &td;	/* user path: the modelled copyin/copyout */
	g_fault = 0;
	g_uoff = 0;

	error = soopt_mcopyout(&sopt, m);

	if (sopt.sopt_val == NULL) {
		__CPROVER_assert(error == 0, "a NULL value is a no-op");
		return;
	}
	if (g_fault) {
		__CPROVER_assert(error == EFAULT, "a fault is reported");
		return;
	}
	/*
	 * No fault: either every mbuf fit (error 0, sopt_valsize is the copied
	 * total) or the user buffer was too short for some mbuf (error EINVAL).
	 * In both cases the copy stayed within the buffer, checked in the model.
	 */
	__CPROVER_assert(error == 0 || error == EINVAL,
	    "success or a short-buffer EINVAL");
	if (error == 0)
		__CPROVER_assert(sopt.sopt_valsize == g_uoff,
		    "the reported total is what was copied");
}
