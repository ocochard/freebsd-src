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
 * cbmc(1) harness for sbcreatecontrol(), sys/kern/uipc_sockbuf.c: build a
 * control-message (cmsg) mbuf of size bytes of payload, used by the socket
 * layer to hand ancillary data (SCM_RIGHTS, SCM_CREDS, IPV6 options, ...) to
 * recvmsg(2).  It sizes the mbuf by CMSG_SPACE(size), zeroes it, copies size
 * bytes of payload in, and sets the cmsg header.  The zero and the payload
 * copy must stay within the mbuf's storage.
 *
 * This harness covers the plain-mbuf path (CMSG_SPACE(size) <= MLEN), where
 * the mbuf is an MLEN object from the UMA model.  The MLEN data area is a
 * real object, so a zero or copy past it is an out-of-bounds access.  The
 * payload copy is modelled by touching the first and last byte of the
 * destination range (not a byte loop).  size is a constant per job: small
 * payloads and the value where _ALIGN(size) wraps u_int to a small
 * CMSG_SPACE while the payload copy still uses the full size.
 *
 * The entry point, for --function:
 *
 *   proof_sbcreatecontrol  sbcreatecontrol() for a given size on the MLEN
 *			path: the CMSG_SPACE zero and the size-byte payload
 *			copy stay within the mbuf's MLEN storage.
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
 * The mbuf's MLEN data area, a real object so a write past it is caught.
 * The default UMA model hands back a struct mbuf whose m_data is &m_dat[0];
 * that inline m_dat array is MLEN bytes, which is exactly the plain-mbuf
 * data area, so no separate allocation is needed here.
 */

static struct cmsghdr *g_cp;		/* mtod(m) once built */

/*
 * memset/memcpy touch models (replacing the kern.h byte-loop versions for
 * this harness via --replace-calls): bounds-check the first and last byte of
 * each range instead of iterating, so a size near UINT_MAX does not blow up
 * the unwinding.  sbcreatecontrol's bzero(cp, CMSG_SPACE(size)) and
 * memcpy(CMSG_DATA(cp), p, size) are the only calls.
 */
void *
cbmc_sb_memset(void *b, int c, size_t len)
{
	if (len != 0) {
		((volatile char *)b)[0];
		((volatile char *)b)[len - 1];
	}
	return (b);
}

void *
cbmc_sb_memcpy(void *dst, const void *src, size_t len)
{
	/*
	 * Bounds-check only the destination (the mbuf): sbcreatecontrol's
	 * safety is whether the payload fits the mbuf it sized.  The source is
	 * the caller's buffer, whose extent is the caller's concern, so it is
	 * not touched here (a size near UINT_MAX has no real source object to
	 * check against anyway).
	 */
	if (len != 0) {
		((volatile char *)dst)[0];
		((volatile char *)dst)[len - 1];
	}
	return (dst);
}

/* The payload source: a small object, enough for the modelled sizes. */
static char g_payload[64];

void
proof_sbcreatecontrol(void)
{
	struct mbuf *m;
	const void *p;

	/*
	 * SIZE is a constant per job.  p may be NULL (no payload copy) or the
	 * payload buffer.  Only the MLEN path is driven; a job whose
	 * CMSG_SPACE(SIZE) exceeds MLEN would take the cluster path, not
	 * modelled here, so those jobs are chosen to stay within MLEN -- except
	 * the wrap job, where _ALIGN(SIZE) wraps u_int and CMSG_SPACE(SIZE)
	 * collapses below MLEN while the payload copy still uses the full SIZE.
	 */
	p = nondet_bool() ? (const void *)g_payload : NULL;

	m = sbcreatecontrol(p, (u_int)SIZE, SCM_RIGHTS, SOL_SOCKET, M_NOWAIT);

	if (m == NULL)
		return;			/* CMSG_SPACE > MCLBYTES, or ENOBUFS */
	/*
	 * The bzero and the payload memcpy were bounds-checked against the MLEN
	 * mbuf storage during the call.  On the plain path the mbuf length is
	 * CMSG_SPACE(SIZE), which must fit MLEN.
	 */
	g_cp = mtod(m, struct cmsghdr *);
	__CPROVER_assert(m->m_len >= 0 && m->m_len <= M_SIZE(m),
	    "the control mbuf length is within its storage");
}
