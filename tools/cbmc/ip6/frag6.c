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
 * cbmc(1) harness for frag6_input(), sys/netinet6/frag6.c: reassemble an
 * IPv6 fragment into its per-datagram reassembly queue (RFC 8200 section
 * 4.5).  The fragments come from the peer.
 *
 * Not a program: run.sh compiles it with SOURCE naming frag6.c, its 1024
 * reassembly buckets cut to one, or a mutant of it, included whole.  The queue already holding fragments is concrete
 * per job (GEO); one incoming fragment, its offset, length and
 * More-Fragments bit symbolic and bounded, goes through frag6_input().  A
 * symbolic queue's overlap combinatorics are out of reach (the tcp_reass
 * proofs met the same wall).  The locks, the hash, malloc/free,
 * icmp6_error() and the mbuf tail (m_adj, m_cat) are modelled; ip6q and
 * ip6asfrag are allocated typed through the malloc hook, and either may
 * fail.  No extension header before the fragment header (unfrglen 0), ECN
 * Not-ECT on every fragment, no receive interface.
 *
 * Properties, from RFC 8200 section 4.5 and the comments of frag6_input():
 * - a fragment with M set and a length not a multiple of 8, or of length
 *   0, is dropped; offset 0 with M clear is an atomic fragment, handed up
 *   without its fragment header (RFC 6946);
 * - a fragment overlapping a queued one discards the whole datagram; an
 *   exact duplicate is dropped alone and the queue is left as it was;
 * - otherwise it is queued, and the datagram is handed up exactly when the
 *   fragments tile [0, P) and the last has M clear, with payload length P;
 * - a queue stays sorted by offset, without overlap, its count right;
 * - every mbuf ends in a queue, handed up, or freed once; every ip6q and
 *   ip6asfrag is in the bucket or freed once; the bucket, packet and
 *   fragment counters match what is queued.
 *
 * The entry point, for --function:
 *
 *   proof_frag6	frag6_input() of one symbolic fragment into the
 *			queue GEO.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>

#include "kern.h"

static int g_qalloc, g_qfree, g_afalloc, g_affree;
static bool g_nomem;

/*
 * malloc(9) and free(9) of frag6.c, through run.sh's call replacement (a
 * NULL from kern.h's malloc hook means "not mine", not a failure): ip6q
 * and ip6asfrag, typed, either may fail; each freed once.
 */
void *
frag6_malloc(size_t size, struct malloc_type *type, int flags)
{
	void *p;

	__CPROVER_assert(size == sizeof(struct ip6q) ||
	    size == sizeof(struct ip6asfrag), "model: only frag6 objects");
	__CPROVER_assert((flags & M_WAITOK) == 0, "model: M_NOWAIT");
	if (nondet_bool()) {
		g_nomem = true;
		return (NULL);
	}
	p = __CPROVER_allocate(size, (flags & M_ZERO) != 0);
	if (size == sizeof(struct ip6q))
		g_qalloc++;
	else
		g_afalloc++;
	return (p);
}

void
frag6_free(void *addr, struct malloc_type *type)
{
	__CPROVER_assert(__CPROVER_r_ok(addr, 1),
	    "free of a live object (no double free)");
	if (__CPROVER_OBJECT_SIZE(addr) == sizeof(struct ip6q))
		g_qfree++;
	else
		g_affree++;
	__CPROVER_deallocate(addr);
}

void
cbmc_atomic_add_int(volatile u_int *p, u_int v)
{
	*p += v;
}

void
cbmc_atomic_subtract_int(volatile u_int *p, u_int v)
{
	*p -= v;
}

/*
 * ip6_deletefraghdr() moves the IPv6 header up over the fragment header,
 * a copy onto itself that kern.h's forward cbmc_memmove() refuses; run.sh
 * replaces it with this one, backward when the copy overlaps forward.
 */
void *
frag6_memmove(void *dst, const void *src, size_t len)
{
	char *d = dst;
	const char *s = src;
	size_t i;

	if (__CPROVER_same_object(d, s) && s < d && d < s + len) {
		for (i = len; i > 0; i--)
			d[i - 1] = s[i - 1];
	} else {
		for (i = 0; i < len; i++)
			d[i] = s[i];
	}
	return (dst);
}

/* IN6_ARE_ADDR_EQUAL(), byte by byte. */
int
cbmc_memcmp(const void *b1, const void *b2, size_t len)
{
	const uint8_t *p1 = b1, *p2 = b2;
	size_t i;

	for (i = 0; i < len; i++)
		if (p1[i] != p2[i])
			return (p1[i] - p2[i]);
	return (0);
}

/* jenkins_hash32() returns 0: every packet lands in bucket 0. */
uint32_t
jenkins_hash32(const uint32_t *key, size_t len, uint32_t seed)
{
	return (0);
}

/* No address of ours: dstifp stays NULL, in6_ifstat_inc() a no-op. */
struct in6_ifaddr *
in6ifa_ifwithaddr(const struct in6_addr *addr, uint32_t zoneid, bool ref)
{
	return (NULL);
}

/*
 * The queued fragments: offset, length and M bit of each, in order.
 * GEO 0: no queue.  GEO 1: [0,16) M.  GEO 2: [0,16) M, [32,48) last.
 * GEO 3: [16,32) last, the first missing.
 */
#if GEO == 0
#define	NQ	0
static int g_off[1], g_len[1], g_mff[1];
#elif GEO == 1
#define	NQ	1
static int g_off[] = { 0 }, g_len[] = { 16 }, g_mff[] = { 1 };
#elif GEO == 2
#define	NQ	2
static int g_off[] = { 0, 32 }, g_len[] = { 16, 16 }, g_mff[] = { 1, 0 };
#elif GEO == 3
#define	NQ	1
static int g_off[] = { 16 }, g_len[] = { 16 }, g_mff[] = { 0 };
#endif

/*
 * The mbufs: NQ queued ones and the incoming one, last.  Each is live,
 * freed (m_freem() or icmp6_error()), or appended to the reassembled
 * datagram (m_cat()).
 */
#define	MB_LIVE		0
#define	MB_FREED	1
#define	MB_CAT		2
#define	NMB		(NQ + 1)
static struct mbuf *g_mb[NMB];
static int g_mbstate[NMB];

static int
frag6_mbidx(struct mbuf *m)
{
	int i;

	for (i = 0; i < NMB; i++)
		if (g_mb[i] == m)
			return (i);
	__CPROVER_assert(0, "an mbuf of the harness");
	return (0);
}

static void
frag6_mbdone(struct mbuf *m, int state)
{
	int i = frag6_mbidx(m);

	__CPROVER_assert(g_mbstate[i] == MB_LIVE,
	    "an mbuf is freed or appended once");
	g_mbstate[i] = state;
	if (state == MB_FREED) {
		__CPROVER_deallocate(m->m_data);
		__CPROVER_deallocate(m);
	}
}

void
icmp6_error(struct mbuf *m, int type, int code, int param)
{
	frag6_mbdone(m, MB_FREED);
}

/* The chains are one mbuf each until m_cat(), which only records. */
void
m_freem(struct mbuf *m)
{
	if (m != NULL) {
		__CPROVER_assert(m->m_next == NULL, "model: one-mbuf chain");
		frag6_mbdone(m, MB_FREED);
	}
}

void
m_cat(struct mbuf *m, struct mbuf *n)
{
	frag6_mbdone(n, MB_CAT);
}

/*
 * The harness's mbufs hold the fragment header: m_pullup() does not call
 * this.  Left undefined, its pointer would be any object, and cbmc 6.11
 * stops in symbolic execution (l2_rename_rvalues case `struct').
 */
struct mbuf *
__m_pullup(struct mbuf *m, int len)
{
	__CPROVER_assert(0, "model: the fragment header is contiguous");
	return (NULL);
}

void m_adj(struct mbuf *m, int req_len) { }
void m_demote_pkthdr(struct mbuf *m) { }

void
m_copyback(struct mbuf *m, int off, int len, const void *cp)
{
	__CPROVER_assert(off >= 0 && len == 1 && off + len <= m->m_len,
	    "next header write within the mbuf");
}

int
ip6_get_prevhdr(const struct mbuf *m, int off)
{
	return (offsetof(struct ip6_hdr, ip6_nxt));
}

/* Bounds of the incoming fragment: offset in 8-byte units, length. */
#define	MAXOFF8		8
#define	MAXLEN		40

/*
 * A packet's bytes are a typed object: through a plain byte array cbmc
 * cannot fold the header fields it reads, and explores every branch on
 * them.
 */
struct frag6_pkt {
	struct ip6_hdr	ip6;
	struct ip6_frag	fh;
	uint8_t		payload[MAXLEN];
};

static struct mbuf *
frag6_mbuf(int fragoff, int frglen, bool mff)
{
	struct mbuf *m;
	struct frag6_pkt *p;
	int len = sizeof(struct ip6_hdr) + sizeof(struct ip6_frag) + frglen;

	m = __CPROVER_allocate(sizeof(struct mbuf), 1);
	p = __CPROVER_allocate(sizeof(*p), 1);
	m->m_data = (caddr_t)p;
	m->m_len = len;
	m->m_next = NULL;
	m->m_flags = M_PKTHDR;
	m->m_type = MT_DATA;
	m->m_pkthdr.len = len;

	p->ip6.ip6_flow = htonl(IPV6_VERSION << 24);	/* Not-ECT */
	p->ip6.ip6_nxt = IPPROTO_FRAGMENT;
	p->ip6.ip6_plen = htons(sizeof(struct ip6_frag) + frglen);
	p->fh.ip6f_nxt = IPPROTO_UDP;
	p->fh.ip6f_offlg = htons(fragoff) | (mff ? IP6F_MORE_FRAG : 0);
	p->fh.ip6f_ident = htonl(0x1234);
	return (m);
}

void
proof_frag6(void)
{
	struct ip6q *q6, *qq;
	struct ip6asfrag *af6;
	struct mbuf *m, *min;
	struct ip6_hdr *ip6;
	int i, off, ret, inoff, inlen, nq, nf, prev_end;
	int dup, overlap, tile, end, maxend, lastmff;
	bool inmff, queued;

	/* Only bucket 0 is used: jenkins_hash32() returns 0. */
	TAILQ_INIT(&V_ip6qb[0].packets);
	V_ip6qb[0].count = 0;
	V_ip6_maxfragsperpacket = 64;
	V_ip6_maxfragpackets = 64;
	V_ip6_maxfragbucketsize = 64;
	ip6_maxfrags = 1024;
	frag6_nfrags = NQ;
	V_frag6_nfragpackets = NQ > 0;

	if (NQ > 0) {
		q6 = __CPROVER_allocate(sizeof(*q6), 1);
		TAILQ_INIT(&q6->ip6q_frags);
		q6->ip6q_ident = htonl(0x1234);
		q6->ip6q_unfrglen = g_off[0] == 0 ? 0 : -1;
		q6->ip6q_nxt = IPPROTO_UDP;
		q6->ip6q_nfrag = NQ;
		for (i = 0; i < NQ; i++) {
			af6 = __CPROVER_allocate(sizeof(*af6), 1);
			af6->ip6af_off = g_off[i];
			af6->ip6af_frglen = g_len[i];
			af6->ip6af_mff = g_mff[i] != 0;
			af6->ip6af_offset = sizeof(struct ip6_hdr) +
			    sizeof(struct ip6_frag);
			g_mb[i] = af6->ip6af_m = frag6_mbuf(g_off[i], g_len[i],
			    g_mff[i] != 0);
			TAILQ_INSERT_TAIL(&q6->ip6q_frags, af6, ip6af_tq);
		}
		TAILQ_INSERT_HEAD(&V_ip6qb[0].packets, q6, ip6q_tq);
		V_ip6qb[0].count = 1;
	}

	/* The incoming fragment. */
	inoff = nondet_int();
	inlen = nondet_int();
	inmff = nondet_bool();
	__CPROVER_assume(inoff >= 0 && inoff <= MAXOFF8);
	__CPROVER_assume(inlen >= 0 && inlen <= MAXLEN);
	inoff *= 8;
	min = m = g_mb[NQ] = frag6_mbuf(inoff, inlen, inmff);
	off = sizeof(struct ip6_hdr);

	ret = frag6_input(&m, &off, IPPROTO_FRAGMENT);

	/* Every queue sorted, without overlap, its count right; the counters. */
	nq = nf = 0;
	TAILQ_FOREACH(qq, &V_ip6qb[0].packets, ip6q_tq) {
		prev_end = 0;
		i = 0;
		TAILQ_FOREACH(af6, &qq->ip6q_frags, ip6af_tq) {
			__CPROVER_assert(af6->ip6af_off >= prev_end,
			    "queued fragments are sorted and do not overlap");
			prev_end = af6->ip6af_off + af6->ip6af_frglen;
			i++;
		}
		__CPROVER_assert(i == qq->ip6q_nfrag,
		    "nfrag is the length of the fragment list");
		nq++;
		nf += i;
	}
	__CPROVER_assert(V_ip6qb[0].count == nq, "bucket count");
	__CPROVER_assert(V_frag6_nfragpackets == nq, "packet count");
	__CPROVER_assert(frag6_nfrags == nf, "fragment count");
	__CPROVER_assert(g_qalloc - g_qfree + (NQ > 0) == nq,
	    "every ip6q is queued or freed");
	__CPROVER_assert(g_afalloc - g_affree + NQ == nf,
	    "every ip6asfrag is queued or freed");

	/* The incoming mbuf is queued, handed up, or freed. */
	queued = false;
	TAILQ_FOREACH(qq, &V_ip6qb[0].packets, ip6q_tq)
		TAILQ_FOREACH(af6, &qq->ip6q_frags, ip6af_tq)
			if (af6->ip6af_m == min)
				queued = true;
	__CPROVER_assert((ret == IPPROTO_DONE) == (m == NULL),
	    "a datagram handed up with its next header");

	/* The spec, for the rest. */
	if (inmff && (inlen & 7) != 0) {
		__CPROVER_assert(m == NULL && g_mbstate[NQ] == MB_FREED,
		    "M set and length not a multiple of 8: dropped");
		return;
	}
	if (inoff == 0 && !inmff) {
		/* Atomic: handed up without the fragment header. */
		__CPROVER_assert(m == min && ret == IPPROTO_UDP,
		    "atomic fragment handed up");
		ip6 = mtod(m, struct ip6_hdr *);
		__CPROVER_assert(ntohs(ip6->ip6_plen) == inlen &&
		    m->m_len == sizeof(*ip6) + inlen &&
		    m->m_pkthdr.len == m->m_len,
		    "atomic fragment loses its fragment header");
		__CPROVER_assert(nq == (NQ > 0) && nf == NQ,
		    "atomic fragment leaves the queue alone");
		return;
	}
	if (inlen == 0) {
		__CPROVER_assert(m == NULL && g_mbstate[NQ] == MB_FREED,
		    "empty fragment dropped");
		return;
	}
	if (g_nomem) {
		__CPROVER_assert(m == NULL && g_mbstate[NQ] == MB_FREED,
		    "out of memory: fragment dropped");
		return;
	}
	dup = overlap = 0;
	for (i = 0; i < NQ; i++) {
		if (g_off[i] == inoff && g_len[i] == inlen)
			dup = 1;
		else if (inoff < g_off[i] + g_len[i] &&
		    g_off[i] < inoff + inlen)
			overlap = 1;
	}
	if (overlap) {
		for (i = 0; i < NMB; i++)
			__CPROVER_assert(g_mbstate[i] == MB_FREED,
			    "overlap: every fragment of the datagram dropped");
		__CPROVER_assert(m == NULL && nq == 0,
		    "overlap: datagram discarded");
		return;
	}
	if (dup) {
		__CPROVER_assert(m == NULL && g_mbstate[NQ] == MB_FREED,
		    "duplicate dropped");
		for (i = 0; i < NQ; i++)
			__CPROVER_assert(g_mbstate[i] == MB_LIVE,
			    "duplicate: the queue is kept");
		__CPROVER_assert(nq == 1 && nf == NQ,
		    "duplicate: the queue is unchanged");
		return;
	}

	/* Queued: do the fragments now tile [0, maxend), M clear last? */
	maxend = inoff + inlen;
	for (i = 0; i < NQ; i++)
		if (g_off[i] + g_len[i] > maxend)
			maxend = g_off[i] + g_len[i];
	end = 0;
	lastmff = 1;
	for (;;) {
		int found = 0;

		if (inoff == end) {
			found = 1;
			end += inlen;
			lastmff = inmff;
		}
		for (i = 0; i < NQ && !found; i++)
			if (g_off[i] == end) {
				found = 1;
				end += g_len[i];
				lastmff = g_mff[i];
			}
		if (!found)
			break;
	}
	tile = !lastmff && end == maxend;
	if (tile) {
		__CPROVER_assert(m == g_mb[inoff == 0 ? NQ : 0] &&
		    ret == IPPROTO_UDP, "complete datagram handed up");
		for (i = 0; i < NMB; i++)
			__CPROVER_assert(g_mb[i] == m ||
			    g_mbstate[i] == MB_CAT,
			    "complete: every fragment appended once");
		ip6 = mtod(m, struct ip6_hdr *);
		__CPROVER_assert(ntohs(ip6->ip6_plen) == end,
		    "complete: payload length is the tiled length");
		__CPROVER_assert(nq == 0, "complete: queue removed");
	} else {
		__CPROVER_assert(m == NULL && queued,
		    "incomplete: fragment queued");
		__CPROVER_assert(nq == 1 && nf == NQ + 1,
		    "incomplete: one more fragment in the queue");
		for (i = 0; i < NQ; i++)
			__CPROVER_assert(g_mbstate[i] == MB_LIVE,
			    "incomplete: the queue is kept");
	}
}
