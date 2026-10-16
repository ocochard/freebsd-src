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
 * cbmc(1) harness for accept(2) and accept4(2), sys/kern/uipc_syscalls.c:
 * sys_accept(), sys_accept4(), accept1() and kern_accept4().
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_syscalls.c or
 * a mutant of it, included whole.  The descriptor table (fget_cap(),
 * falloc_caps(), fdclose(), fdrop()), the listen queue
 * (solisten_dequeue()), the protocol (soaccept()) and the socket's ioctls
 * (soo_ioctl()) are modelled by what they do, recorded in ghost state.
 * The reference is the manual page, lib/libsys/accept.2.  The entry
 * points, for --function:
 *
 *   proof_accept	accept(2) on any descriptor, a listening socket or
 *   proof_accept4	not, a connection or an error from the queue, an
 *			address buffer of any length or none, accept4(2)
 *			with any flags: refused with the manual's errors,
 *			nothing left behind; or a new descriptor for the
 *			connection, its O_NONBLOCK, O_ASYNC and signal
 *			destination inherited (accept) or set from the flags
 *			and cleared (accept4), close-on-exec and close-on-fork
 *			from the flags, the socket's state in step, the
 *			address copied out to the length given and its own
 *			length returned
 */

#include SOURCE

#include <sys/filedesc.h>
#include <sys/sigio.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include <sys/refcount.h>
#include "kern.h"

static struct file g_headfp, g_nfp, g_vnfp;
static struct socket g_head, g_so;
static int g_headref, g_caps, g_inst, g_fd, g_fdflags, g_nfpalloc;
static int g_dequeued, g_pgid, g_setown, g_setown_pgid;

/* fget_cap(): a referenced file and its capabilities, or EBADF. */
int
fget_cap(struct thread *td, int fd, const cap_rights_t *needrightsp,
    uint8_t *flagsp, struct file **fpp, struct filecaps *havecapsp)
{
	if (fd < 0 || nondet_bool())
		return (EBADF);
	*fpp = nondet_bool() ? &g_headfp : &g_vnfp;
	(*fpp)->f_count++;
	g_headref++;
	if (havecapsp != NULL) {
		memset(havecapsp, 0, sizeof(*havecapsp));
		g_caps = 1;
	}
	return (0);
}

void
filecaps_free(struct filecaps *fcaps)
{
	__CPROVER_assert(g_caps == 1, "capabilities freed once, when held");
	g_caps = 0;
}

/* The last reference: only the new file's, closed on an error. */
static int g_nfpfreed;

int
_fdrop(struct file *fp, struct thread *td)
{
	__CPROVER_assert(fp == &g_nfp && !g_inst && !g_nfpfreed,
	    "only the new file, closed, is freed, once");
	g_nfpfreed = 1;
	return (0);
}

/* falloc_caps(): a file and a descriptor for it, the caps installed. */
int
falloc_caps(struct thread *td, struct file **resultfp, int *resultfd,
    int flags, struct filecaps *fcaps)
{
	__CPROVER_assert(g_caps == 1 && fcaps != NULL,
	    "the listening socket's capabilities for the new descriptor");
	if (nondet_bool())
		return (nondet_bool() ? EMFILE : ENFILE);
	g_caps = 0;			/* now the descriptor's */
	g_nfp.f_count = 2;		/* the table's, and one for us */
	g_nfp.f_type = DTYPE_NONE;
	g_nfpalloc = 1;
	g_inst = 1;
	g_fd = nondet_int();
	__CPROVER_assume(g_fd >= 0);
	g_fdflags = flags;
	*resultfp = &g_nfp;
	*resultfd = g_fd;
	return (0);
}

void
fdclose(struct thread *td, struct file *fp, int idx)
{
	__CPROVER_assert(fp == &g_nfp && idx == g_fd && g_inst,
	    "closes the new descriptor, once");
	g_inst = 0;
	fp->f_count--;
}

void
finit(struct file *fp, u_int flag, short type, void *data,
    const struct fileops *ops)
{
	fp->f_data = data;
	fp->f_flag = flag;
	fp->f_type = type;
	fp->f_ops = ops;
}

/*
 * solisten_dequeue(), uipc_socket.c: the listen queue's first
 * connection, its state the listening socket's as solisten_clone() copied
 * it, SS_NBIO added as the flags say; or the error that ends the wait.
 * It drops the socket lock.
 */
int
solisten_dequeue(struct socket *head, struct socket **ret, int flags)
{
	__CPROVER_assert(head == &g_head,
	    "dequeues from the listening socket");
	if ((head->so_state & SS_NBIO) != 0 && nondet_bool())
		return (EWOULDBLOCK);
	if (nondet_bool())
		return (nondet_bool() ? EINTR : ECONNABORTED);
	g_so.so_state = head->so_state;
	if (flags & ACCEPT4_INHERIT)
		g_so.so_state |= (head->so_state & SS_NBIO);
	else
		g_so.so_state |= (flags & SOCK_NONBLOCK) ? SS_NBIO : 0;
	g_dequeued = 1;
	*ret = &g_so;
	return (0);
}

pid_t
fgetown(struct sigio **sigiop)
{
	__CPROVER_assert(sigiop == &g_head.so_sigio,
	    "the listening socket's signal destination");
	return (g_pgid);
}

int
fsetown(pid_t pgid, struct sigio **sigiop)
{
	__CPROVER_assert(sigiop == &g_so.so_sigio, "for the new socket");
	g_setown++;
	g_setown_pgid = pgid;
	return (0);
}

void knote(struct knlist *list, long hint, int lockflags) { }

/* soo_ioctl(), sys_socket.c, for FIONBIO and FIOASYNC. */
static int
cbmc_soo_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
	struct socket *so = fp->f_data;

	__CPROVER_assert(so == &g_so && (cmd == FIONBIO || cmd == FIOASYNC),
	    "the new socket's blocking and async state");
	if (cmd == FIONBIO) {
		if (*(int *)data)
			so->so_state |= SS_NBIO;
		else
			so->so_state &= ~SS_NBIO;
	} else {
		if (*(int *)data)
			so->so_state |= SS_ASYNC;
		else
			so->so_state &= ~SS_ASYNC;
	}
	return (0);
}

struct fileops socketops = { .fo_ioctl = cbmc_soo_ioctl };

/* soaccept(): the peer's address, no longer than the room given, or the
 * connection gone. */
static uint8_t g_peer[sizeof(struct sockaddr_storage)];
static int g_peerlen;

int
soaccept(struct socket *so, struct sockaddr *sa)
{
	int i;

	__CPROVER_assert(so == &g_so && sa->sa_len ==
	    sizeof(struct sockaddr_storage), "the room for the address");
	if (nondet_bool())
		return (ECONNABORTED);
	g_peerlen = nondet_int();
	__CPROVER_assume(g_peerlen >= 2 && g_peerlen <= sa->sa_len);
	for (i = 0; i < (int)sizeof(g_peer); i++)
		if (i < g_peerlen)
			((uint8_t *)sa)[i] = g_peer[i] = nondet_int();
	sa->sa_len = g_peerlen;
	g_peer[0] = g_peerlen;
	return (0);
}

/* The process's memory: a length and an address buffer, or faults. */
static socklen_t g_ulen;
static uint8_t g_ubuf[sizeof(struct sockaddr_storage) + 8];
static int g_copied;

int
cbmc_copyin(const void *udaddr, void *kaddr, size_t len)
{
	__CPROVER_assert(udaddr == &g_ulen && len == sizeof(socklen_t),
	    "reads the address length");
	if (nondet_bool())
		return (EFAULT);
	memcpy(kaddr, udaddr, len);
	return (0);
}

int
cbmc_copyout(const void *kaddr, void *udaddr, size_t len)
{
	if (nondet_bool())
		return (EFAULT);
	if (udaddr == g_ubuf) {
		__CPROVER_assert(len <= sizeof(g_ubuf), "model: buffer");
		memcpy(udaddr, kaddr, len);
		g_copied = len;
		return (0);
	}
	__CPROVER_assert(udaddr == &g_ulen && len == sizeof(socklen_t),
	    "writes the address length");
	memcpy(udaddr, kaddr, len);
	return (0);
}

static void
setup(void)
{
	g_headfp.f_type = DTYPE_SOCKET;
	g_headfp.f_data = &g_head;
	g_headfp.f_count = 1;
	g_headfp.f_flag = nondet_int();
	g_vnfp.f_type = DTYPE_VNODE;
	g_vnfp.f_count = 1;
	g_head.so_options = nondet_bool() ? SO_ACCEPTCONN : 0;
	g_head.so_state = nondet_int();
	g_pgid = nondet_int();
	g_ulen = nondet_int();
	__CPROVER_assume(g_ulen <= sizeof(g_ubuf));
}

/*
 * What both calls promise.  flags are accept4(2)'s, or ACCEPT4_INHERIT
 * for accept(2).
 */
static void
check(int error, int flags, bool named, socklen_t ulen0)
{
	struct thread *td = curthread;
	u_int hf = g_headfp.f_flag;
	int i;

	__CPROVER_assert(g_headfp.f_count == 1 && g_vnfp.f_count == 1,
	    "the listening socket's reference dropped");
	__CPROVER_assert(g_caps == 0, "its capabilities freed or installed");
	if (g_headref > 0 && g_headfp.f_type == DTYPE_SOCKET && error != ENOTSOCK &&
	    (g_head.so_options & SO_ACCEPTCONN) == 0)
		__CPROVER_assert(error == EINVAL && !g_dequeued,
		    "EINVAL: listen(2) has not been called on the socket");
	if (error != 0) {
		__CPROVER_assert(!g_inst && (!g_nfpalloc || g_nfp.f_count == 0),
		    "on an error, no new descriptor left");
		if (!g_nfpalloc || !g_dequeued)
			__CPROVER_assert(g_setown == 0, "nor signal set up");
		return;
	}
	__CPROVER_assert(g_headfp.f_type == DTYPE_SOCKET &&
	    (g_head.so_options & SO_ACCEPTCONN) != 0,
	    "a descriptor only from a listening socket");
	__CPROVER_assert(g_dequeued && g_inst && g_nfp.f_count == 1 &&
	    td->td_retval[0] == g_fd, "a new descriptor, returned, the table's");
	__CPROVER_assert(g_nfp.f_type == DTYPE_SOCKET && g_nfp.f_data == &g_so &&
	    g_nfp.f_ops == &socketops, "for the connection's socket");
	if (flags & ACCEPT4_INHERIT) {
		__CPROVER_assert((g_nfp.f_flag & (FNONBLOCK | FASYNC)) ==
		    (hf & (FNONBLOCK | FASYNC)),
		    "accept: O_NONBLOCK and O_ASYNC inherited");
		__CPROVER_assert(g_pgid == 0 ? g_setown == 0 :
		    g_setown == 1 && g_setown_pgid == g_pgid,
		    "accept: the signal destination inherited");
	} else {
		__CPROVER_assert(((g_nfp.f_flag & FNONBLOCK) != 0) ==
		    ((flags & SOCK_NONBLOCK) != 0) &&
		    (g_nfp.f_flag & FASYNC) == 0,
		    "accept4: O_NONBLOCK from the flags, O_ASYNC cleared");
		__CPROVER_assert(g_setown == 0,
		    "accept4: the signal destination cleared");
	}
	__CPROVER_assert((g_nfp.f_flag & ~(FNONBLOCK | FASYNC)) ==
	    (hf & ~(FNONBLOCK | FASYNC)), "the other file flags inherited");
	__CPROVER_assert(((g_fdflags & O_CLOEXEC) != 0) ==
	    ((flags & SOCK_CLOEXEC) != 0) &&
	    ((g_fdflags & O_CLOFORK) != 0) == ((flags & SOCK_CLOFORK) != 0),
	    "close-on-exec and close-on-fork from the flags");
	__CPROVER_assert(((g_so.so_state & SS_NBIO) != 0) ==
	    ((g_nfp.f_flag & FNONBLOCK) != 0) &&
	    ((g_so.so_state & SS_ASYNC) != 0) ==
	    ((g_nfp.f_flag & FASYNC) != 0),
	    "the socket's state in step with its file");
	if (named) {
		int n = ulen0 < (socklen_t)g_peerlen ? ulen0 : g_peerlen;

		__CPROVER_assert(g_copied == n,
		    "the address copied out, to the room given");
		for (i = 0; i < (int)sizeof(g_peer); i++)
			if (i < n)
				__CPROVER_assert(g_ubuf[i] == g_peer[i],
				    "the peer's address");
		__CPROVER_assert(g_ulen == (socklen_t)g_peerlen,
		    "its own length returned");
	} else
		__CPROVER_assert(g_copied == 0, "no address asked, none copied");
}

static void
check_flags(int error, int flags)
{
	if ((flags & ~(SOCK_CLOEXEC | SOCK_CLOFORK | SOCK_NONBLOCK)) != 0)
		__CPROVER_assert(error == EINVAL && g_headref == 0,
		    "accept4: invalid flags refused");
}

static void
check_errors(int error)
{
	if (g_headref > 0 && g_headfp.f_count == 1 && error == ENOTSOCK)
		return;
	if (error == 0)
		return;
	__CPROVER_assert(error == EBADF || error == ENOTSOCK ||
	    error == EINVAL || error == EMFILE || error == ENFILE ||
	    error == EINTR || error == EWOULDBLOCK || error == ECONNABORTED ||
	    error == EFAULT, "an error of the manual's");
}

void
proof_accept(void)
{
	struct accept_args uap;
	bool named;
	socklen_t ulen0;
	int error;

	setup();
	named = nondet_bool();
	uap.s = nondet_int();
	uap.name = named ? (struct sockaddr *)g_ubuf : NULL;
	uap.anamelen = named || nondet_bool() ? &g_ulen : NULL;
	ulen0 = g_ulen;

	error = sys_accept(curthread, &uap);

	check(error, ACCEPT4_INHERIT, named, ulen0);
	check_errors(error);
}

void
proof_accept4(void)
{
	struct accept4_args uap;
	bool named;
	socklen_t ulen0;
	int error;

	setup();
	named = nondet_bool();
	uap.s = nondet_int();
	uap.name = named ? (struct sockaddr *)g_ubuf : NULL;
	uap.anamelen = named || nondet_bool() ? &g_ulen : NULL;
	uap.flags = nondet_int();
	ulen0 = g_ulen;

	error = sys_accept4(curthread, &uap);

	check(error, uap.flags, named, ulen0);
	check_flags(error, uap.flags);
	check_errors(error);
}
