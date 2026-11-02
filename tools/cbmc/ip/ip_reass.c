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
 * cbmc(1) harness for ip_reass(), sys/netinet/ip_reass.c: reassemble a
 * peer's IPv4 fragment into its datagram's queue (RFC 791, RFC 815).  A
 * fragment overlapping the one before is trimmed at its front; the ones
 * after it overlaps are trimmed at their front or, covered, freed.
 *
 * Not a program: run.sh compiles it with SOURCE naming ip_reass.c or a
 * mutant of it, included whole.  The queue already holding fragments is
 * concrete per job (GEO); one incoming fragment, its offset, length and MF
 * bit symbolic and bounded, goes through ip_reass().  One hash bucket
 * (V_ipq_hashsize 1), the hash 0.  The zone, m_adj() (a front trim of a
 * one-mbuf chain), m_freem(), m_cat() and the callouts are modelled.  No IP
 * options (hlen 20), ECN Not-ECT throughout, the caller's contract as
 * ip_input() keeps it: offset or MF non-zero, the header in the mbuf.
 *
 * Each fragment's payload is a typed object; where an mbuf's data starts in
 * it, plus the offset the fragment was sent at, is the datagram offset of
 * its first byte.  Properties, from RFC 791 and the comments of ip_reass():
 * - a fragment of length 0, or with MF and a length not a multiple of 8,
 *   is dropped; so is one its predecessor covers, the queue unchanged;
 * - a queued fragment's ip_off and ip_len are where its bytes sit in the
 *   datagram and how many: trimming moves the data with the header;
 * - the queue is sorted by offset, without overlap, and covers exactly the
 *   bytes of the fragments accepted so far;
 * - the datagram is handed up when the queue tiles [0, next) with MF clear
 *   on the last fragment, and only then: its pieces in order, each at its
 *   offset, ip_len the header plus next;
 * - every mbuf is queued, handed up or freed once; every ipq queued or
 *   freed once; ipq_nfrags, the global count and the bucket count match.
 *
 * The entry point, for --function:
 *
 *   proof_reass	ip_reass() of one symbolic fragment into the queue
 *			GEO.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

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

uint32_t
jenkins_hash32(const uint32_t *key, size_t len, uint32_t seed)
{
	return (0);
}

/* The bucket timer: armed or stopped, nothing more. */
int
callout_reset_sbt_on(struct callout *c, sbintime_t sbt, sbintime_t prec,
    void (*ftn)(void *), void *arg, int cpu, int flags)
{
	c->c_flags |= CALLOUT_ACTIVE;
	return (0);
}

int
_callout_stop_safe(struct callout *c, int flags)
{
	c->c_flags &= ~CALLOUT_ACTIVE;
	return (0);
}

/* The ipq zone, by run.sh's call replacement: it may fail; freed once. */
static int g_qalloc, g_qfree;
static bool g_nomem;

void *
ipr_zalloc(uma_zone_t zone, void *arg, int flags)
{
	__CPROVER_assert(zone == V_ipq_zone, "model: only the ipq zone");
	if (nondet_bool()) {
		g_nomem = true;
		return (NULL);
	}
	g_qalloc++;
	return (__CPROVER_allocate(sizeof(struct ipq), 0));
}

void
ipr_zfree(uma_zone_t zone, void *item, void *udata)
{
	__CPROVER_assert(zone == V_ipq_zone, "model: only the ipq zone");
	__CPROVER_assert(__CPROVER_r_ok(item, sizeof(struct ipq)),
	    "free of a live ipq (no double free)");
	g_qfree++;
	__CPROVER_deallocate(item);
}

/*
 * The queued fragments: offset, length and MF bit of each, in order.
 * GEO 0: no queue.  GEO 1: [0,16) MF.  GEO 2: [0,16) MF, [32,48) last.
 * GEO 3: [16,32) MF, the first missing.  GEO 4: [16,20) last, an end not a
 * multiple of 8.
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
static int g_off[] = { 16 }, g_len[] = { 16 }, g_mff[] = { 1 };
#elif GEO == 4
#define	NQ	1
static int g_off[] = { 16 }, g_len[] = { 4 }, g_mff[] = { 0 };
#endif

/* Bounds of the incoming fragment: offset in 8-byte units, length. */
#define	MAXOFF8		8
#define	MAXLEN		40
#define	MAXEND		(MAXOFF8 * 8 + MAXLEN)

/*
 * A fragment's bytes, a typed object: through a plain byte array cbmc
 * cannot fold the header fields it reads.
 */
struct ipr_pkt {
	struct ip	ip;
	uint8_t		payload[MAXLEN];
};

/*
 * The mbufs: NQ queued ones and the incoming one, last.  Each is live,
 * freed, or appended to the reassembled datagram (m_cat(), in g_cat order).
 */
#define	MB_LIVE		0
#define	MB_FREED	1
#define	MB_CAT		2
#define	NMB		(NQ + 1)
static struct mbuf *g_mb[NMB];
static struct ipr_pkt *g_pkt[NMB];
static int g_sent[NMB];		/* the offset each fragment was sent at */
static int g_mbstate[NMB];
static int g_cat[NMB], g_ncat;

static int
ipr_mbidx(struct mbuf *m)
{
	int i;

	for (i = 0; i < NMB; i++)
		if (g_mb[i] == m)
			return (i);
	__CPROVER_assert(0, "an mbuf of the harness");
	return (0);
}

/* Datagram offset of the first byte of mbuf i's data. */
static int
ipr_pos(int i)
{
	__CPROVER_assert(__CPROVER_same_object(g_mb[i]->m_data, g_pkt[i]),
	    "an mbuf's data stays in its fragment");
	return ((int)__CPROVER_POINTER_OFFSET(g_mb[i]->m_data) -
	    (int)offsetof(struct ipr_pkt, payload) + g_sent[i]);
}

static void
ipr_mbdone(struct mbuf *m, int state)
{
	int i = ipr_mbidx(m);

	__CPROVER_assert(g_mbstate[i] == MB_LIVE,
	    "an mbuf is freed or appended once");
	g_mbstate[i] = state;
	if (state == MB_FREED) {
		__CPROVER_deallocate(g_pkt[i]);
		__CPROVER_deallocate(m);
	} else
		g_cat[g_ncat++] = i;
}

void
m_freem(struct mbuf *m)
{
	if (m != NULL) {
		__CPROVER_assert(m->m_next == NULL, "model: one-mbuf chain");
		ipr_mbdone(m, MB_FREED);
	}
}

/* Each fragment is one mbuf: m_cat() of its (empty) tail does nothing. */
void
m_cat(struct mbuf *m, struct mbuf *n)
{
	if (n != NULL)
		ipr_mbdone(n, MB_CAT);
}

/* A front trim, all ip_reass() asks: it must leave data in the mbuf. */
void
m_adj(struct mbuf *m, int req_len)
{
	__CPROVER_assert(req_len > 0 && req_len < m->m_len,
	    "a trim leaves part of the fragment");
	m->m_data += req_len;
	m->m_len -= req_len;
	if (m->m_flags & M_PKTHDR)
		m->m_pkthdr.len -= req_len;
}

void m_demote_pkthdr(struct mbuf *m) { }
u_int m_fixhdr(struct mbuf *m) { return (0); }

static struct mbuf *
ipr_mbuf(int i, int off, int len, bool mff, bool queued)
{
	struct mbuf *m;
	struct ipr_pkt *p;

	m = __CPROVER_allocate(sizeof(struct mbuf), 1);
	p = __CPROVER_allocate(sizeof(*p), 1);
	g_mb[i] = m;
	g_pkt[i] = p;
	g_sent[i] = off;

	p->ip.ip_v = IPVERSION;
	p->ip.ip_hl = sizeof(struct ip) >> 2;
	p->ip.ip_tos = 0;			/* Not-ECT */
	p->ip.ip_id = htons(0x1234);
	p->ip.ip_p = IPPROTO_UDP;
	p->ip.ip_src.s_addr = htonl(0x0a000001);
	p->ip.ip_dst.s_addr = htonl(0x0a000002);
	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_type = MT_DATA;
	m->m_flags = M_PKTHDR;
	if (queued) {
		/* As ip_reass() leaves it: header out, offset in bytes. */
		p->ip.ip_len = htons(len);
		p->ip.ip_off = htons(off);
		m->m_data = (caddr_t)p->payload;
		m->m_len = len;
		if (mff)
			m->m_flags |= M_IP_FRAG;
	} else {
		p->ip.ip_len = htons(sizeof(struct ip) + len);
		p->ip.ip_off = htons((off >> 3) | (mff ? IP_MF : 0));
		m->m_data = (caddr_t)&p->ip;
		m->m_len = sizeof(struct ip) + len;
	}
	m->m_pkthdr.len = m->m_len;
	m->m_pkthdr.PH_loc.ptr = &p->ip;
	return (m);
}

static struct ipqbucket g_bucket;

void
proof_reass(void)
{
	struct ipq *fp, *qq;
	struct mbuf *m, *r, *q, *last;
	struct ip *ip;
	int i, j, k, x, inoff, inlen, nq, nf, next, pos, maxoff, pend;
	int qoff[NMB], qlen[NMB], nl;
	bool inmff, covered, conflict, dropped, want, have;

	V_ipq = &g_bucket;
	V_ipq_hashsize = 1;
	TAILQ_INIT(&V_ipq[0].head);
	V_ipq[0].count = 0;
	V_ipreass_maxbucketsize = 64;
	V_maxfragsperpacket = 16;
	V_noreass = 0;
	maxfrags = 1024;
	nfrags = NQ;
	time_uptime = 100;

	maxoff = -1;
	if (NQ > 0) {
		fp = __CPROVER_allocate(sizeof(*fp), 1);
		fp->ipq_nfrags = NQ;
		fp->ipq_p = IPPROTO_UDP;
		fp->ipq_id = htons(0x1234);
		fp->ipq_src.s_addr = htonl(0x0a000001);
		fp->ipq_dst.s_addr = htonl(0x0a000002);
		fp->ipq_expire = time_uptime + V_ipfragttl;
		last = NULL;
		for (i = 0; i < NQ; i++) {
			m = ipr_mbuf(i, g_off[i], g_len[i], g_mff[i] != 0, true);
			if (last == NULL)
				fp->ipq_frags = m;
			else
				last->m_nextpkt = m;
			last = m;
			if (!g_mff[i])
				maxoff = g_off[i] + g_len[i];
		}
		fp->ipq_maxoff = maxoff;
		TAILQ_INSERT_HEAD(&V_ipq[0].head, fp, ipq_list);
		V_ipq[0].count = 1;
		V_ipq[0].timer.c_flags = CALLOUT_ACTIVE;
	}

	/* The incoming fragment, as ip_input() hands it over. */
	inoff = nondet_int();
	inlen = nondet_int();
	inmff = nondet_bool();
	__CPROVER_assume(inoff >= 0 && inoff <= MAXOFF8);
	__CPROVER_assume(inlen >= 0 && inlen <= MAXLEN);
	inoff *= 8;
	__CPROVER_assume(inoff != 0 || inmff);
	m = ipr_mbuf(NQ, inoff, inlen, inmff, false);

	r = ip_reass(m);

	/* Each queue: sorted, no overlap, data where ip_off says, counts. */
	nq = nf = 0;
	nl = 0;
	TAILQ_FOREACH(qq, &V_ipq[0].head, ipq_list) {
		pend = 0;
		k = 0;
		for (q = qq->ipq_frags; q != NULL; q = q->m_nextpkt) {
			ip = (struct ip *)q->m_pkthdr.PH_loc.ptr;
			i = ipr_mbidx(q);
			__CPROVER_assert(g_mbstate[i] == MB_LIVE,
			    "a queued mbuf is live");
			__CPROVER_assert(ntohs(ip->ip_off) >= pend,
			    "queued fragments are sorted and do not overlap");
			__CPROVER_assert(ipr_pos(i) == ntohs(ip->ip_off) &&
			    q->m_len == ntohs(ip->ip_len) &&
			    ntohs(ip->ip_len) > 0,
			    "a queued fragment's data is at its ip_off, "
			    "ip_len long");
			__CPROVER_assert(ipr_pos(i) + q->m_len <=
			    g_sent[i] + (i == NQ ? inlen : g_len[i]),
			    "a queued fragment's data is within what was sent");
			pend = ntohs(ip->ip_off) + ntohs(ip->ip_len);
			if (nl < NMB) {
				qoff[nl] = ntohs(ip->ip_off);
				qlen[nl] = ntohs(ip->ip_len);
			}
			nl++;
			k++;
		}
		__CPROVER_assert(k == qq->ipq_nfrags,
		    "ipq_nfrags is the length of the fragment list");
		nq++;
		nf += k;
	}
	__CPROVER_assert(V_ipq[0].count == nq, "bucket count");
	__CPROVER_assert(nfrags == nf, "fragment count");
	__CPROVER_assert(g_qalloc - g_qfree + (NQ > 0) == nq,
	    "every ipq is queued or freed");
	k = 0;
	for (i = 0; i < NMB; i++) {
		__CPROVER_assert(g_mbstate[i] != MB_CAT || r != NULL,
		    "an mbuf appended only to a datagram handed up");
		if (g_mbstate[i] == MB_LIVE)
			k++;
	}
	__CPROVER_assert(k == nf + (r != NULL),
	    "every live mbuf is queued or handed up");

	/* Handed up: the pieces in order, each at its offset, tiling. */
	if (r != NULL) {
		ip = mtod(r, struct ip *);
		i = ipr_mbidx(r);
		__CPROVER_assert(g_mbstate[i] == MB_LIVE &&
		    (caddr_t)ip == (caddr_t)&g_pkt[i]->ip,
		    "the datagram starts at its first fragment's header");
		next = r->m_len - sizeof(struct ip);
		__CPROVER_assert(ipr_pos(i) + (int)sizeof(struct ip) == 0,
		    "the first piece is at offset 0");
		for (k = 0; k < g_ncat; k++) {
			j = g_cat[k];
			__CPROVER_assert(ipr_pos(j) == next,
			    "each piece follows the one before");
			next += g_mb[j]->m_len;
			last = g_mb[j];
		}
		if (g_ncat == 0)
			last = r;
		__CPROVER_assert((last->m_flags & M_IP_FRAG) == 0,
		    "the last piece has MF clear");
		__CPROVER_assert(ntohs(ip->ip_len) == sizeof(struct ip) + next,
		    "ip_len is the header plus the payload");
		for (k = 0; k < NMB; k++)
			__CPROVER_assert(k == i || g_mbstate[k] != MB_LIVE,
			    "every fragment appended or freed");
		__CPROVER_assert(nq == 0, "the queue is gone");
		return;
	}

	/* Not handed up: the queue does not tile with MF clear last. */
	if (nq == 1 && nl <= NMB) {
		TAILQ_FOREACH(qq, &V_ipq[0].head, ipq_list) {
			next = 0;
			want = true;
			for (q = qq->ipq_frags; q != NULL; q = q->m_nextpkt) {
				ip = (struct ip *)q->m_pkthdr.PH_loc.ptr;
				if (ntohs(ip->ip_off) != next)
					want = false;
				next += ntohs(ip->ip_len);
				last = q;
			}
			__CPROVER_assert(!want ||
			    (last->m_flags & M_IP_FRAG) != 0,
			    "a complete datagram is handed up");
		}
	}

	/* Dropped: malformed, covered, or past the last fragment. */
	covered = false;
	for (i = 0; i < NQ; i++)
		if (g_off[i] <= inoff &&
		    (i == NQ - 1 || g_off[i + 1] > inoff) &&
		    g_off[i] + g_len[i] >= inoff + inlen)
			covered = true;
	conflict = maxoff > 0 && ((inmff && inoff + inlen >= maxoff) ||
	    (!inmff && inoff + inlen != maxoff));
	if (inlen == 0 || (inmff && (inlen & 7) != 0) || covered ||
	    conflict) {
		__CPROVER_assert(g_mbstate[NQ] == MB_FREED,
		    "malformed, covered or past the end: dropped");
		for (i = 0; i < NQ; i++)
			__CPROVER_assert(g_mbstate[i] == MB_LIVE,
			    "a dropped fragment leaves the queue's mbufs");
	}
	dropped = g_mbstate[NQ] == MB_FREED;

	/*
	 * The queue covers exactly the bytes of the fragments accepted: the
	 * ones queued before, and the incoming one unless dropped.
	 */
	if (nq == 1 && nl <= NMB) {
		for (x = 0; x < MAXEND; x++) {
			want = !dropped && inoff <= x && x < inoff + inlen;
			for (i = 0; i < NQ; i++)
				if (g_off[i] <= x && x < g_off[i] + g_len[i])
					want = true;
			have = false;
			for (i = 0; i < nl; i++)
				if (qoff[i] <= x && x < qoff[i] + qlen[i])
					have = true;
			__CPROVER_assert(want == have,
			    "the queue holds every byte accepted, no other");
		}
	}
}
