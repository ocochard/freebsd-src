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
 * cbmc(1) harness for the control-message copy-out of recvmsg(2),
 * sys/kern/uipc_syscalls.c: kern_recvit() receives a chain of control
 * mbufs from soreceive(), then copies them out to the user's msg_control
 * buffer one mbuf at a time while they fit, accumulating msg_controllen
 * and setting MSG_CTRUNC when the chain does not fit.  The copy-out must
 * never write past the user buffer, and the reported length must be the
 * bytes actually copied.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_syscalls.c or
 * a mutant of it, included whole.  The work before the loop is modelled
 * away: getsock() returns a file, soreceive() returns a nondeterministic
 * control chain and no address, and the iovec list is empty so no data is
 * received.  The user msg_control buffer is a CBMC object of exactly
 * msg_controllen bytes, so a copy-out past it is an out-of-bounds write
 * CBMC catches.  copyout() is the harness model, which faults or not.
 *
 * The entry point, for --function:
 *
 *   proof_recvit	kern_recvit() on a control chain of up to NMBUF
 *			mbufs of any length against a user buffer of any
 *			size: each mbuf copied out only while it fits, the
 *			copy never past the buffer, msg_controllen the exact
 *			bytes copied, MSG_CTRUNC set iff the chain did not
 *			all fit.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#ifndef NMBUF
#define	NMBUF	3
#endif

/* The file getsock() hands back, and the socket behind it. */
static struct socket g_so;
static struct file g_fp;

int
cbmc_getsock(struct thread *td, int fd, const cap_rights_t *rightsp,
    struct file **fpp)
{
	g_fp.f_data = &g_so;
	/*
	 * Two references: fdrop()'s inline refcount_release() then sees it is
	 * not the last and does not reach _fdrop(), as getsock() took a hold.
	 */
	refcount_init(&g_fp.f_count, 2);
	*fpp = &g_fp;
	return (0);
}

/* The leftover chain on truncation: a safe walk, modelled as a no-op. */
static int g_disposed;
void
cbmc_dispose(struct mbuf *m)
{
	g_disposed = 1;
}

/* m_freem(): the control chain, freed once the copy-out is done. */
static struct mbuf g_m[NMBUF];
void
m_freem(struct mbuf *m)
{
	while (m != NULL) {
		__CPROVER_assert(m >= &g_m[0] && m < &g_m[NMBUF],
		    "a control mbuf of the harness");
		m = m->m_next;
	}
}

/* The control chain soreceive() builds, and its ghost record. */
static char g_mdat[NMBUF][64];
static int g_nm;		/* mbufs in the chain */
static size_t g_total;		/* sum of their m_len */

int
soreceive(struct socket *so, struct sockaddr **paddr, struct uio *uio,
    struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	int i, len;

	if (paddr != NULL)
		*paddr = NULL;		/* no address */
	g_nm = nondet_int();
	__CPROVER_assume(g_nm >= 0 && g_nm <= NMBUF);
	g_total = 0;
	for (i = 0; i < NMBUF; i++) {
		if (i >= g_nm)
			break;
		len = nondet_int();
		__CPROVER_assume(len >= 0 && len <= (int)sizeof(g_mdat[i]));
		g_m[i].m_data = g_mdat[i];
		g_m[i].m_len = len;
		g_m[i].m_next = (i + 1 < g_nm) ? &g_m[i + 1] : NULL;
		g_total += len;
	}
	if (controlp != NULL)
		*controlp = (g_nm > 0) ? &g_m[0] : NULL;
	return (0);
}

/* copyout(): the user msg_control buffer, bounds-checked by CBMC. */
static int g_fault;
static size_t g_out;		/* bytes copied out in all */
static char *g_ubase;		/* the user buffer start */
static int g_contig;		/* each copy landed right after the last */

int
cbmc_copyout(const void *kaddr, void *uaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	/* The next copy must start exactly where the last one ended. */
	if ((char *)uaddr != g_ubase + g_out)
		g_contig = 0;
	g_out += len;
	cbmc_memmove(uaddr, kaddr, len);
	return (0);
}

void
proof_recvit(void)
{
	struct thread td;
	struct msghdr mp;
	char ubuf[CLEN];	/* the user msg_control buffer: CLEN bytes */
	int error;

	bzero(&td, sizeof(td));
	bzero(&mp, sizeof(mp));
	mp.msg_name = NULL;		/* no name to copy out */
	mp.msg_iov = NULL;
	mp.msg_iovlen = 0;		/* no data: soreceive resid 0 */
	mp.msg_control = ubuf;
	mp.msg_controllen = CLEN;
	mp.msg_flags = 0;
	g_fault = 0;
	g_out = 0;
	g_disposed = 0;
	g_ubase = ubuf;
	g_contig = 1;

	error = kern_recvit(&td, 0, &mp, UIO_USERSPACE, NULL);

	if (g_fault) {
		__CPROVER_assert(error == EFAULT, "a fault is reported");
		return;
	}
	__CPROVER_assert(error == 0, "no error otherwise");
	/*
	 * msg_controllen is the bytes actually copied out, which never exceed
	 * the user buffer; the copy-out into ubuf is bounds-checked by CBMC,
	 * so it can never write past CLEN.
	 */
	__CPROVER_assert(mp.msg_controllen <= (socklen_t)CLEN,
	    "the reported length never exceeds the user buffer");
	__CPROVER_assert((size_t)mp.msg_controllen == g_out,
	    "the reported length is the bytes copied out");
	__CPROVER_assert(g_contig,
	    "each mbuf is copied right after the previous one");
	/*
	 * MSG_CTRUNC is set exactly when the whole chain did not fit: the
	 * copied total is less than the chain's total.
	 */
	if (g_total > (size_t)CLEN || g_out < g_total)
		__CPROVER_assert((mp.msg_flags & MSG_CTRUNC) != 0,
		    "truncation is flagged when the chain does not all fit");
}
