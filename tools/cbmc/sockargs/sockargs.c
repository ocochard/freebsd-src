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
 * cbmc(1) harness for sockargs(), sys/kern/uipc_syscalls.c: the copy-in
 * of a socket name or control buffer into an mbuf, shared by sendto(2),
 * sendmsg(2), bind(2), connect(2) and their kin.  The user passes a
 * length; the function must refuse what will not fit, and on what does,
 * copy exactly that many bytes into an mbuf large enough to hold them.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_syscalls.c
 * or a mutant of it, included whole.  m_get2() is modelled by what it
 * does for a length already capped at MCLBYTES: an mbuf whose data area
 * is a buffer of the fitting size class (MLEN, else MCLBYTES), so the
 * copyin's write is bounds-checked against the real capacity.  copyin()
 * is the kern.h model, which faults or not.
 *
 * The entry point, for --function:
 *
 *   proof_sockargs	sockargs() on a buflen of any socklen_t value and
 *			a type of MT_SONAME or MT_DATA: a length past the
 *			cap refused with EMSGSIZE and no mbuf; a faulting
 *			copyin reported with the mbuf freed and no mbuf
 *			handed back; otherwise an mbuf of m_len == buflen,
 *			buflen bytes copied into a data area that holds
 *			them, and for MT_SONAME an sa_len of buflen.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
static void cbmc_mbuf_free(uma_zone_t zone, void *item);
#define	CBMC_UMA_FREE_HOOK	cbmc_mbuf_free
#include "kern.h"

/*
 * The one mbuf m_get2() hands back.  Its data area is a CBMC object of
 * the exact size class that fits the request, allocated with the
 * primitive rather than the fixed-bucket malloc model, so a copyin that
 * writes past that capacity is an out-of-bounds write CBMC catches, not
 * a write swallowed by an over-large static buffer.
 */
static struct mbuf *g_m;
static int g_mfree;		/* the mbuf freed (fault path) */
static int g_cap;		/* the data area m_get2() gave */

/* copyin()'s source: the user buffer, recorded for the length check. */
static int g_copied;		/* bytes the copyin was asked to move */

struct mbuf *
m_get2(int size, int how, short type, int flags)
{
	/* sockargs() has already refused size > MCLBYTES. */
	__CPROVER_assert(size >= 0 && size <= MCLBYTES,
	    "m_get2 within the cap");
	g_cap = (size <= MHLEN || (size <= MLEN && (flags & M_PKTHDR) == 0)) ?
	    MLEN : MCLBYTES;
	g_m = __CPROVER_allocate(sizeof(struct mbuf), 1);
	g_m->m_data = __CPROVER_allocate(g_cap, 0);
	g_m->m_type = type;
	g_mfree = 0;
	return (g_m);
}

/* m_free() is a header inline; a plain mbuf reaches uma_zfree(). */
static void
cbmc_mbuf_free(uma_zone_t zone, void *item)
{
	__CPROVER_assert(item == g_m && !g_mfree, "the mbuf freed once");
	g_mfree = 1;
	__CPROVER_deallocate(g_m->m_data);
}

/*
 * copyin(): the kern.h model faults or not; on success it writes buflen
 * bytes to the mbuf data area, which CBMC bounds-checks against g_mdat.
 */
static int g_fault;

int
cbmc_copyin(const void *uaddr, void *kaddr, size_t len)
{
	if (nondet_bool()) {
		g_fault = 1;
		return (EFAULT);
	}
	g_copied = len;
	cbmc_memmove(kaddr, uaddr, len);
	return (0);
}

void
proof_sockargs(void)
{
	struct mbuf *mp = NULL;
	char ubuf[MCLBYTES];
	socklen_t buflen;
	int type, error;

	/*
	 * buflen is a constant per job (LEN): the copyin is a byte loop, and
	 * a symbolic length over all of socklen_t puts it out of memory.  The
	 * run.sh jobs sweep the boundaries (0, MLEN, MLEN+1, MCLBYTES,
	 * MCLBYTES+1) so the size-class split and the EMSGSIZE cap are both
	 * exercised.
	 */
	buflen = LEN;
	type = nondet_bool() ? MT_SONAME : MT_DATA;
	g_fault = 0;
	g_copied = -1;
	g_cap = -1;

	error = sockargs(&mp, ubuf, buflen, type);

	if (buflen > MCLBYTES) {
		__CPROVER_assert(error == EMSGSIZE,
		    "a length past the cap is refused");
		__CPROVER_assert(mp == NULL, "and no mbuf handed back");
		return;
	}
	if (error != 0) {
		__CPROVER_assert(g_fault, "an error only from the fault");
		__CPROVER_assert(mp == NULL, "no mbuf on an error");
		__CPROVER_assert(g_mfree, "the mbuf freed on an error");
		return;
	}
	/* Success. */
	__CPROVER_assert(mp == g_m, "the mbuf handed back");
	__CPROVER_assert(!g_mfree, "not freed on success");
	__CPROVER_assert(mp->m_len == (int)buflen,
	    "m_len is the length asked for");
	__CPROVER_assert(g_copied == (int)buflen,
	    "exactly buflen bytes copied in");
	__CPROVER_assert(buflen <= (socklen_t)g_cap,
	    "the data area holds them");
	if (type == MT_SONAME) {
		struct sockaddr *sa = mtod(mp, struct sockaddr *);

		/*
		 * sa_len is a u_char: the length is stored in one byte.  The
		 * only in-tree caller passes control data, not a name, so a
		 * name longer than 255 is not reached; the field holds the low
		 * byte of buflen.
		 */
		__CPROVER_assert(sa->sa_len == (u_char)buflen,
		    "a name's sa_len is the length stored");
	}
}
