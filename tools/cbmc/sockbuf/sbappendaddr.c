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
 * cbmc(1) harness for sbappendaddr_locked(), sys/kern/uipc_sockbuf.c: the
 * datagram receive append, used by UDP and Unix-domain datagram sockets.
 * It assembles a record of (sockaddr, optional control, optional data) and
 * puts it on the receive buffer if the buffer has room.  The address copy
 * must stay within its mbuf, the space check must refuse a record that does
 * not fit, and on acceptance the byte count must grow by exactly the
 * record length.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_sockbuf.c or a
 * mutant of it, included whole.  The sockaddr-carrying mbuf is a real
 * struct mbuf allocated by the UMA model, so the bcopy of the address is
 * bounds-checked against its storage; the data mbuf is real too; sballoc()
 * and the space check run for real.  m_length(), the tag/kmsan helpers are
 * modelled.  The address length and data length are constants per job.
 *
 * The entry point, for --function:
 *
 *   proof_addr	sbappendaddr_locked() of a (sockaddr, data) record: a record
 *		over the buffer's space is refused; an accepted one grows
 *		sb_ccc by exactly the address plus data length; the address
 *		copy stays within its mbuf.
 */

#include SOURCE

#include <sys/vnode.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* Helpers the reached path calls, outside this file.  (kmsan_check_mbuf is
 * a no-op macro without KMSAN, so it needs no model.) */
void m_tag_delete_chain(struct mbuf *m, struct m_tag *t) { }
u_int
m_length(struct mbuf *m0, struct mbuf **last)
{
	struct mbuf *m;
	u_int len = 0;

	for (m = m0; m != NULL; m = m->m_next) {
		len += m->m_len;
		if (m->m_next == NULL && last != NULL)
			*last = m;
	}
	if (m0 == NULL && last != NULL)
		*last = NULL;
	return (len);
}

#ifndef SALEN
#define	SALEN	16		/* the sockaddr length */
#endif
#ifndef DLEN
#define	DLEN	20		/* the data length (0 = no data mbuf) */
#endif
#ifndef HIWAT
#define	HIWAT	64		/* the buffer's byte high-water */
#endif

static struct socket g_so;
static struct sockaddr g_sa;
static struct mbuf g_dm;		/* the data mbuf */

void
proof_addr(void)
{
	struct sockbuf *sb;
	struct mbuf *m0;
	long space_before;
	uint64_t pre_ccc;
	int r, reclen;

	bzero(&g_so, sizeof(g_so));
	sb = &g_so.so_rcv;
	sb->sb_hiwat = HIWAT;
	sb->sb_mbmax = 1 << 20;		/* mbuf accounting not the limit here */
	sb->sb_ccc = 0;
	sb->sb_mbcnt = 0;

	bzero(&g_sa, sizeof(g_sa));
	g_sa.sa_len = SALEN;
	g_sa.sa_family = AF_INET;

	if (DLEN > 0) {
		bzero(&g_dm, sizeof(g_dm));
		g_dm.m_data = &g_dm.m_dat[0];
		g_dm.m_len = DLEN;
		g_dm.m_flags = M_PKTHDR;
		g_dm.m_type = MT_DATA;
		g_dm.m_next = NULL;
		g_dm.m_pkthdr.len = DLEN;
		m0 = &g_dm;
	} else
		m0 = NULL;

	reclen = SALEN + DLEN;			/* control is NULL */
	space_before = sbspace(sb);
	pre_ccc = sb->sb_ccc;

	r = sbappendaddr_locked(sb, &g_sa, m0, NULL);

	if (r == 0) {
		/* Refused: the model's m_get never fails, so only on no space. */
		__CPROVER_assert(reclen > space_before,
		    "a record is refused only when it does not fit");
		__CPROVER_assert(sb->sb_ccc == pre_ccc,
		    "a refused record leaves the byte count unchanged");
		return;
	}
	/*
	 * Accepted: it fit, and the byte count grew by exactly the record
	 * length (address + data).  The address copy was bounds-checked
	 * against its mbuf during the call.
	 */
	__CPROVER_assert(reclen <= space_before,
	    "an accepted record fit the buffer");
	__CPROVER_assert(sb->sb_ccc == pre_ccc + (uint64_t)reclen,
	    "sb_ccc grows by exactly the record length");
}
