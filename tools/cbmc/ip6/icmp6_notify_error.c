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
 * cbmc(1) harness for icmp6_notify_error(), sys/netinet6/icmp6.c: walk the
 * extension headers of the packet quoted in an ICMPv6 error (RFC 4443
 * section 2.4 (c): as much of the invoking packet as fits) to find its
 * upper-layer protocol and, for a type 0 routing header, its final
 * destination, then hand both to the protocol's ctlinput.  The quoted
 * packet comes from the peer that sent the error, so every byte of it is
 * free; the walk must read only bytes m_pullup() has made contiguous in the
 * mbuf the chain now starts with.
 *
 * Not a program: run.sh compiles it with SOURCE naming icmp6.c or a mutant
 * of it, included whole.  The packet is a chain of two real mbufs, the
 * first a cluster as a NIC gives it (M_EXT, a heap buffer of its own) and
 * the second a plain mbuf: a reassembled packet (frag6.c) or a driver
 * that splits headers is such a chain.  The split is HEADLEN bytes into
 * the packet, a constant per job, and falls inside the quoted routing
 * header, so the routing branch's second m_pullup() must relocate and free
 * the cluster head.  The quoted packet's first extension header is a type 0
 * routing header with segments left and RTLEN (its ip6r_len) a constant per
 * job; its own ip6r_nxt is IPPROTO_NONE so the walk ends after one pass (a
 * free header chain makes the walk's later iterations branch into every
 * header type at once, past the SAT solver's memory).
 *
 * __m_pullup() here is a model, not uipc_mbuf.c's code (see below): its byte
 * copy turns the gathered-into mbuf into a symbolic array and the whole-
 * function proof outgrew the solver (10^10 VCC terms); its copy's
 * correctness is proven on its own by the mbuf/m_pullup.c jobs.  The model
 * keeps the lifetime effect the bug turns on: the allocate path frees the
 * old cluster head.  mb_free_ext() frees a cluster nobody else references,
 * the way kern_mbuf.c does for a refcount of one.  in6_setscope() and the
 * notify-tail TCP host-cache MTU helpers are stubbed (cbmc returns free
 * values), and ip6_ctlprotox[] has no handler, so the proof runs the walk,
 * the sockaddrs built from it, and the Packet-Too-Big MTU path.
 *
 * The entry point, for --function:
 *
 *   proof_notify_error	icmp6_notify_error() on a chain of a cluster and an
 *			mbuf holding a free ICMPv6 error: every read of the
 *			quoted headers is within a live mbuf (no read through
 *			a pointer into an mbuf m_pullup() has freed), and the
 *			chain is either handed back or freed.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#ifndef HEADLEN
#define	HEADLEN	96	/* outer IPv6, ICMPv6, inner IPv6, 8 bytes of more */
#endif
#ifndef TAILLEN
#define	TAILLEN	16	/* the rest of the routing header */
#endif
#ifndef RTLEN
#define	RTLEN	2	/* one address: 24 bytes */
#endif
#define	PKTLEN	(HEADLEN + TAILLEN)
#define	EOFF	(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + \
	    sizeof(struct ip6_hdr))	/* the quoted packet's first ext header */

u_int max_protohdr = 60;
ip6proto_ctlinput_t *ip6_ctlprotox[IPPROTO_MAX];

/*
 * Callees the notify tail reaches once the fix lets execution past the
 * routing branch.  They do nothing this proof checks (scope assignment and
 * the TCP host-cache MTU update); model them so a bodiless call is not read
 * as a failed property.  in6_setscope() may fail, which the caller handles,
 * so it returns a free value.
 */
int
in6_setscope(struct in6_addr *addr, struct ifnet *ifp, u_int32_t *ret_id)
{
	int r;
	return (r);
}
uint32_t tcp_hc_getmtu(const struct in_conninfo *inc) { uint32_t r; return (r); }
uint32_t tcp_maxmtu6(struct in_conninfo *inc, struct tcp_ifcap *cap)
{
	uint32_t r;
	return (r);
}
void tcp_hc_updatemtu(const struct in_conninfo *inc, uint32_t mtu) { }

void
m_freem(struct mbuf *m)
{
	while (m != NULL)
		m = m_free(m);
}

/* kern_mbuf.c, for a cluster with one reference: free both. */
void
mb_free_ext(struct mbuf *m)
{
	__CPROVER_deallocate(m->m_ext.ext_buf);
	__CPROVER_deallocate(m);
}

/* uipc_mbuf.c: what the pull needs of the header move. */
void
m_move_pkthdr(struct mbuf *to, struct mbuf *from)
{
	to->m_flags = (from->m_flags & M_COPYFLAGS) |
	    (to->m_flags & (M_EXT | M_EXTPG));
	if ((to->m_flags & M_EXT) == 0)
		to->m_data = to->m_pktdat;
	to->m_pkthdr = from->m_pkthdr;
	from->m_flags &= ~M_PKTHDR;
}

/*
 * A model of __m_pullup() (sys/kern/uipc_mbuf.c), not its code: the byte
 * copy there turns the gathered-into mbuf into a symbolic array and the
 * whole-function proof outgrew the SAT solver (dynamic_object$2 at 10
 * billion VCC terms).  Its copy's correctness is proven on its own by the
 * mbuf/m_pullup.c jobs; what this proof needs of it is only its effect on
 * object lifetime, which is what makes the later rth read a use-after-free.
 *
 * The model keeps the two outcomes a caller sees, and the free that the
 * bug turns on:
 *   - len already contiguous in the head: return the head unchanged.
 *   - the gather allocates a new head (M_EXT head, or no room), copies the
 *     first len bytes into it and frees every source mbuf it drains,
 *     including the old head.  A failed allocation frees the chain and
 *     returns NULL.
 * It writes the first len bytes of the new head from the old chain so the
 * parser still reads real header values, but through a small typed buffer,
 * not a symbolic array.
 */
static union {
	char		buf[MHLEN];
	struct ip6_hdr	ip6;
} g_pullbuf;

struct mbuf *
__m_pullup(struct mbuf *n, int len)
{
	struct mbuf *m, *p;
	int got, take;

	if (n->m_len >= len && (n->m_flags & M_EXT) == 0)
		return (n);			/* already contiguous */
	if (len > MHLEN) {
		m_freem(n);
		return (NULL);			/* cannot fit on the alloc path */
	}
	m = m_get(M_NOWAIT, n->m_type);
	if (m == NULL) {
		m_freem(n);
		return (NULL);
	}
	if (n->m_flags & M_PKTHDR)
		m_move_pkthdr(m, n);

	/* Gather the first len bytes into g_pullbuf, draining source mbufs. */
	m->m_data = g_pullbuf.buf;
	got = 0;
	while (got < len && n != NULL) {
		take = n->m_len;
		if (take > len - got)
			take = len - got;
		(memcpy)(g_pullbuf.buf + got, mtod(n, char *), (u_int)take);
		got += take;
		n->m_len -= take;
		if (n->m_len)
			n->m_data += take;
		else
			n = m_free(n);		/* frees the old head here */
	}
	if (got < len) {
		(void)m_free(m);
		m_freem(n);
		return (NULL);
	}
	m->m_len = len;
	m->m_next = n;
	return (m);
}

void
proof_notify_error(void)
{
	struct mbuf *head, *tail, *m;
	char *clust;
	int i, ret;

	clust = __CPROVER_allocate(HEADLEN, 0);
	((struct ip6_hdr *)(clust + EOFF - sizeof(struct ip6_hdr)))->ip6_nxt =
	    IPPROTO_ROUTING;
	((struct ip6_rthdr *)(clust + EOFF))->ip6r_len = RTLEN;
	((struct ip6_rthdr *)(clust + EOFF))->ip6r_type = IPV6_RTHDR_TYPE_0;
	((struct ip6_rthdr *)(clust + EOFF))->ip6r_segleft = 1;
	/*
	 * The routing header's own next header ends the walk after one pass
	 * (the default case: goto notify).  It is the byte this proof is
	 * about: it is read as nxt = rth->ip6r_nxt after the second pullup.
	 * Left free, the walk's second iteration branches into every header
	 * type at once and the formula outgrows the SAT solver's memory; the
	 * UAF read this proof checks is on the first pass, so one pass is
	 * enough.
	 */
	((struct ip6_rthdr *)(clust + EOFF))->ip6r_nxt = IPPROTO_NONE;
	head = __CPROVER_allocate(sizeof(struct mbuf), 1);
	head->m_flags = M_PKTHDR | M_EXT;
	head->m_type = MT_DATA;
	head->m_data = clust;
	head->m_len = HEADLEN;
	head->m_ext.ext_buf = clust;
	head->m_ext.ext_size = HEADLEN;
	head->m_pkthdr.len = PKTLEN;
	head->m_pkthdr.csum_flags = 0;
	head->m_pkthdr.rcvif = NULL;

	tail = __CPROVER_allocate(sizeof(struct mbuf), 1);
	tail->m_flags = 0;
	tail->m_type = MT_DATA;
	tail->m_data = tail->m_dat;
	tail->m_len = TAILLEN;
	tail->m_next = NULL;
	head->m_next = tail;

	/* icmp6_input() hands over the outer header's length and the rest. */
	m = head;
	ret = icmp6_notify_error(&m, sizeof(struct ip6_hdr),
	    PKTLEN - sizeof(struct ip6_hdr));
	__CPROVER_assert(ret == 0 ? m != NULL : m == NULL,
	    "the chain is handed back on success only");
}
