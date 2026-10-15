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
 * cbmc(1) harness for sbcompress_ktls_rx(), sys/kern/uipc_sockbuf.c, on
 * top of ktls_sb.c.  A harness of its own as ktls_sb.c's proof has run.sh
 * replace sbcompress_ktls_rx(), which this one proves.  The one entry
 * point, for --function:
 *
 *   proof_rx_compress	sbcompress_ktls_rx() appending a chain to the TLS
 *			chain's tail: the bytes, in order, after those
 *			there; none moved between decrypted and encrypted
 *			data; empty mbufs dropped, small ones copied into a
 *			writable tail where they fit unless coalescing is
 *			off; the counts and the tail kept
 *

 *   proof_rx_record	sbappendcontrol_locked(), as ktls_decrypt() hands
 *			it a decrypted record: the control message, then
 *			the payload, linked as the last record and counted
 *			ready, the TLS data left alone
 *   proof_rx_cut	sbcut_internal() on a TLS receive buffer: decrypted
 *			records, the one being decrypted, the TLS chain;
 *			the bytes cut leave each part's count, the mbufs cut
 *			come back once, the rest is kept
 *
 * The mbufs hold their data, as small receive mbufs do; a few bytes each.
 */

#include "ktls_sb.c"

#define	CB	6			/* bytes an mbuf holds at most */
#define	CN	3			/* the tail, then two appended */
#define	CL	(CN * CB)

static uint8_t g_byte[CL];		/* the stream, the tail's first */
static bool g_dec[CL];			/* each byte decrypted or not */
static struct mbuf *g_cm[CN];

/* Byte k of a chain, and whether its mbuf is marked decrypted. */
static bool
cbyte(struct mbuf *m, int k, uint8_t *b, bool *dec)
{
	int i;

	for (i = 0; i < CN + 1 && m != NULL; i++) {
		if (k < m->m_len) {
			*b = mtod(m, uint8_t *)[k];
			*dec = (m->m_flags & M_DECRYPTED) != 0;
			return (true);
		}
		k -= m->m_len;
		m = m->m_next;
	}
	return (false);
}

/* m_copydata(), uipc_mbuf.c: for one mbuf, all sbcompress copies. */
void
m_copydata(const struct mbuf *m, int off, int len, caddr_t cp)
{
	__CPROVER_assert(off == 0 && len == m->m_len,
	    "copies an mbuf's bytes, all of them");
	memcpy(cp, mtod(m, char *), len);
}

void
proof_rx_compress(void)
{
	struct sockbuf *sb = &g_so.so_rcv;
	struct mbuf *m, *n, *last;
	u_int ccc, tlscc, mbcnt;
	uint8_t b;
	bool d, tail, rdonly, nocoal;
	int full, tlen;
	int i, k, len, off, total, mlen;

	tail = nondet_bool();
	total = 0;
	for (i = 0; i < CN; i++) {
		m = __CPROVER_allocate(sizeof(struct mbuf), 1);
		m->m_type = MT_DATA;
		m->m_flags = M_NOTREADY | (nondet_bool() ? M_DECRYPTED : 0);
		if (i == 0 && nondet_bool())
			m->m_flags |= M_RDONLY;
		len = nondet_int();
		__CPROVER_assume(len >= (i == 0 ? 1 : 0) && len <= CB);
		/* The tail's data where it leaves some room, or none. */
		off = i == 0 ? MLEN - len - nondet_u_int() % 8 : 0;
		m->m_data = m->m_dat + off;
		m->m_len = len;
		for (k = 0; k < CB; k++)
			if (k < len) {
				b = nondet_int();
				m->m_dat[m->m_data - m->m_dat + k] = b;
				g_byte[total + k] = b;
				g_dec[total + k] =
				    (m->m_flags & M_DECRYPTED) != 0;
			}
		total += len;
		g_cm[i] = m;
		if (i > 1)
			g_cm[i - 1]->m_next = m;
	}
	sb->sb_flags = SB_TLS_RX | (nondet_bool() ? SB_NOCOALESCE : 0);
	n = tail ? g_cm[0] : NULL;
	sb->sb_mtls = sb->sb_mtlstail = n;
	sb->sb_tlscc = tail ? g_cm[0]->m_len : 0;
	sb->sb_ccc = ccc = sb->sb_tlscc + nondet_u_int() % 4096;
	sb->sb_mbcnt = mbcnt = (tail ? MSIZE : 0) + nondet_u_int() % 4096;
	tlscc = sb->sb_tlscc;
	mlen = total - g_cm[0]->m_len;
	rdonly = (g_cm[0]->m_flags & M_RDONLY) != 0;
	tlen = g_cm[0]->m_len;
	full = (g_cm[1]->m_len > 0) + (g_cm[2]->m_len > 0);
	nocoal = (sb->sb_flags & SB_NOCOALESCE) != 0;

	sbcompress_ktls_rx(sb, g_cm[1], n);

	/* The stream: the tail's bytes, if any, then those appended. */
	k = tail ? 0 : g_cm[0]->m_len;
	for (i = 0; i < CL; i++) {
		if (i >= total - k)
			break;
		__CPROVER_assert(cbyte(sb->sb_mtls, i, &b, &d) &&
		    b == g_byte[k + i] && d == g_dec[k + i],
		    "the bytes, in order, each as decrypted as it was");
	}
	__CPROVER_assert(!cbyte(sb->sb_mtls, total - k, &b, &d),
	    "and no more");
	__CPROVER_assert(sb->sb_tlscc == tlscc + mlen &&
	    sb->sb_ccc == ccc + mlen, "counted as appended");
	last = NULL;
	for (m = sb->sb_mtls, i = 0; i < CN + 1 && m != NULL;
	    i++, m = m->m_next) {
		__CPROVER_assert(m->m_len > 0, "no empty mbuf is kept");
		last = m;
	}
	__CPROVER_assert(m == NULL && sb->sb_mtlstail == last &&
	    (last == NULL || last->m_next == NULL),
	    "the tail is the chain's last");
	__CPROVER_assert(sb->sb_mbcnt == mbcnt + MSIZE * (i - (tail ? 1 : 0)),
	    "sb_mbcnt counts the mbufs kept");
	if (tail && rdonly)
		__CPROVER_assert(g_cm[0]->m_len == tlen,
		    "a read-only tail is not written to");
	if (nocoal)
		__CPROVER_assert(i == (tail ? 1 : 0) + full,
		    "with coalescing off, each mbuf with data is kept");
}

/*
 * sbcut_internal() on a TLS receive buffer, as soreceive() and the flushes
 * of sbdrop() and sbflush() call it: two decrypted records in sb_mb, of an
 * mbuf each, data or control (ktls_decrypt() appends the TLS_GET_RECORD
 * control message and its data); a record being decrypted, counted in
 * sb_tlsdcc; the TLS chain of two mbufs not ready.  The cut is any length
 * within the records, as soreceive() takes, or one that ends past the
 * record being decrypted on an mbuf of the TLS chain, a flush whole:
 * sbcut_internal() asserts it is given no other.  Four mbufs, not two
 * records of two: cbmc takes each pointer the walk reads from an mbuf's
 * union to be any mbuf, and six went past half an hour.
 */
#define	XN	4	/* two records, two mbufs of the TLS chain */
#define	XR	2	/* the records' */

void
proof_rx_cut(void)
{
	struct sockbuf *sb = &g_so.so_rcv;
	struct mbuf *m, *mfree, *x[XN];
	u_int ccc, acc, ctl, tlscc, mbcnt, dcc;
	int cut[XN], olen[XN], i, j, k, len, mb, ctlcut, tlscut, nfree;
	char *odata[XN];
	bool freed[XN];

	for (i = 0; i < XN; i++) {
		m = __CPROVER_allocate(sizeof(struct mbuf), 1);
		m->m_len = nondet_int();
		__CPROVER_assume(m->m_len >= 1 && m->m_len <= 64);
		m->m_data = m->m_dat;
		m->m_type = i < XR && nondet_bool() ? MT_CONTROL : MT_DATA;
		m->m_flags = i >= XR ? M_NOTREADY : 0;
		olen[i] = m->m_len;
		odata[i] = m->m_data;
		x[i] = m;
	}
	x[0]->m_nextpkt = x[1];
	x[2]->m_next = x[3];
	sb->sb_mb = x[0];
	sb->sb_lastrecord = x[1];
	sb->sb_mbtail = x[1];
	sb->sb_mtls = x[2];
	sb->sb_mtlstail = x[3];
	sb->sb_fnrdy = NULL;
	sb->sb_sndptr = NULL;
	sb->sb_sndptroff = 0;
	dcc = nondet_u_int() % 64;
	sb->sb_tlsdcc = dcc;
	mb = x[0]->m_len + x[1]->m_len;
	sb->sb_tlscc = tlscc = x[2]->m_len + x[3]->m_len;
	sb->sb_acc = acc = mb;
	sb->sb_ctl = ctl = (x[0]->m_type == MT_CONTROL ? x[0]->m_len : 0) +
	    (x[1]->m_type == MT_CONTROL ? x[1]->m_len : 0);
	sb->sb_ccc = ccc = mb + dcc + tlscc;
	sb->sb_mbcnt = mbcnt = XN * MSIZE;
	sb->sb_flags = SB_TLS_RX;

	len = nondet_int();
	__CPROVER_assume((len >= 0 && len <= mb) ||
	    len == mb + dcc + x[2]->m_len || len == ccc);

	mfree = sbcut_internal(sb, len);

	__CPROVER_assert(sb->sb_ccc == ccc - len, "sb_ccc loses the cut");
	/* What each mbuf lost, in order: the records, then the TLS chain. */
	k = len < mb ? len : mb;
	ctlcut = 0;
	for (i = 0; i < XR; i++) {
		cut[i] = k < olen[i] ? k : olen[i];
		k -= cut[i];
		if (x[i]->m_type == MT_CONTROL)
			ctlcut += cut[i];
	}
	k = len > mb + (int)dcc ? len - mb - (int)dcc : 0;
	for (i = XR; i < XN; i++) {
		cut[i] = k < olen[i] ? k : olen[i];
		k -= cut[i];
	}
	__CPROVER_assert(sb->sb_acc == acc - (len < mb ? len : mb) &&
	    sb->sb_ctl == ctl - ctlcut,
	    "sb_acc and sb_ctl lose what the records lost");
	if (len <= mb) {
		__CPROVER_assert(sb->sb_tlsdcc == dcc && sb->sb_tlscc == tlscc &&
		    sb->sb_mtls == x[2] && sb->sb_mtlstail == x[3],
		    "a cut within the records leaves the TLS data alone");
	} else {
		tlscut = len - mb - dcc;
		__CPROVER_assert(sb->sb_tlsdcc == 0,
		    "the record being decrypted is let go, so its worker "
		    "frees it");
		__CPROVER_assert(sb->sb_tlscc == tlscc - tlscut &&
		    sb->sb_mb == NULL && sb->sb_lastrecord == NULL &&
		    sb->sb_mbtail == NULL,
		    "the records are gone, the TLS chain counted as cut");
		__CPROVER_assert(len == ccc ? sb->sb_mtls == NULL &&
		    sb->sb_mtlstail == NULL :
		    sb->sb_mtls == x[3] && sb->sb_mtlstail == x[3],
		    "the TLS chain starts after the cut, its tail kept");
	}
	/* The mbufs cut whole are handed back, once each; the rest kept. */
	for (i = 0; i < XN; i++)
		freed[i] = false;
	nfree = 0;
	for (m = mfree, j = 0; j < XN + 1 && m != NULL; j++, m = m->m_next) {
		for (i = 0; i < XN; i++)
			if (m == x[i]) {
				__CPROVER_assert(!freed[i],
				    "an mbuf is handed back once");
				freed[i] = true;
			}
		nfree++;
	}
	__CPROVER_assert(m == NULL, "the free list ends");
	k = 0;
	for (i = 0; i < XN; i++) {
		__CPROVER_assert(freed[i] == (cut[i] == olen[i]),
		    "an mbuf is handed back when cut whole, else kept");
		if (!freed[i])
			__CPROVER_assert(x[i]->m_len == olen[i] - cut[i] &&
			    x[i]->m_data == odata[i] + cut[i],
			    "an mbuf cut in part keeps the rest");
		if (freed[i])
			k++;
	}
	__CPROVER_assert(nfree == k, "only mbufs of the buffer come back");
	__CPROVER_assert(sb->sb_mbcnt == mbcnt - MSIZE * nfree,
	    "sb_mbcnt counts the mbufs kept");
	if (len < mb)
		__CPROVER_assert(sb->sb_mb == (cut[0] < olen[0] ? x[0] : x[1]) &&
		    sb->sb_lastrecord == x[1] && sb->sb_mbtail == x[1],
		    "the records left start where the cut ended");
}

/*
 * sbappendcontrol_locked(), as ktls_decrypt() appends a decrypted record:
 * its TLS_GET_RECORD control message, then its payload, ready, none for
 * an empty record (sbcreatecontrol() and ktls_decrypt(), flags 0), to a
 * TLS receive buffer with a record or none before it, the record being
 * decrypted counted out already (sb_tlsdcc), and the TLS chain.
 */
void
proof_rx_record(void)
{
	struct sockbuf *sb = &g_so.so_rcv;
	struct mbuf *prev, *ctl, *d[2], *tls, *m, *data;
	u_int ccc, acc, sctl, mbcnt, tlscc, dcc;
	int i, nd, len, pflags[2];

	prev = nondet_bool() ? __CPROVER_allocate(sizeof(struct mbuf), 1) :
	    NULL;
	if (prev != NULL) {
		prev->m_type = MT_DATA;
		prev->m_len = nondet_int();
		__CPROVER_assume(prev->m_len >= 1 && prev->m_len <= 64);
	}
	tls = __CPROVER_allocate(sizeof(struct mbuf), 1);
	tls->m_type = MT_DATA;
	tls->m_flags = M_NOTREADY;
	tls->m_len = nondet_int();
	__CPROVER_assume(tls->m_len >= 1 && tls->m_len <= 64);
	ctl = __CPROVER_allocate(sizeof(struct mbuf), 1);
	ctl->m_type = MT_CONTROL;
	ctl->m_len = sizeof(struct cmsghdr) + sizeof(struct tls_get_record);
	nd = nondet_int();
	__CPROVER_assume(nd >= 0 && nd <= 2);
	len = 0;
	for (i = 0; i < 2; i++) {
		d[i] = NULL;
		if (i >= nd)
			continue;
		m = __CPROVER_allocate(sizeof(struct mbuf), 1);
		m->m_type = MT_DATA;
		/* Ready, as ktls_decrypt() leaves it; any other flag. */
		m->m_flags = nondet_int() & ~(M_NOTREADY | M_DECRYPTED |
		    M_PKTHDR | M_EXT | M_EXTPG);
		pflags[i] = m->m_flags;
		m->m_len = nondet_int();
		__CPROVER_assume(m->m_len >= 1 && m->m_len <= 64);
		len += m->m_len;
		d[i] = m;
		if (i > 0)
			d[i - 1]->m_next = m;
	}
	data = d[0];
	sb->sb_mb = sb->sb_lastrecord = sb->sb_mbtail = prev;
	sb->sb_mtls = sb->sb_mtlstail = tls;
	sb->sb_fnrdy = NULL;
	dcc = 0;
	sb->sb_tlsdcc = dcc;
	sb->sb_tlscc = tlscc = tls->m_len;
	sb->sb_acc = acc = prev != NULL ? prev->m_len : 0;
	sb->sb_ctl = sctl = 0;
	sb->sb_ccc = ccc = acc + tlscc;
	sb->sb_mbcnt = mbcnt = (prev != NULL ? 2 : 1) * MSIZE;
	sb->sb_flags = SB_TLS_RX;

	sbappendcontrol_locked(sb, data, ctl, 0);

	__CPROVER_assert(prev != NULL ? sb->sb_mb == prev &&
	    prev->m_nextpkt == ctl : sb->sb_mb == ctl,
	    "the record is linked after the last one, or is the first");
	__CPROVER_assert(sb->sb_lastrecord == ctl && ctl->m_nextpkt == NULL,
	    "and is the last record");
	__CPROVER_assert(ctl->m_next == data &&
	    (nd < 2 || d[0]->m_next == d[1]) &&
	    sb->sb_mbtail == (nd == 0 ? ctl : d[nd - 1]) &&
	    sb->sb_mbtail->m_next == NULL,
	    "the control message, then the payload, its tail the last mbuf");
	__CPROVER_assert(sb->sb_ccc == ccc + ctl->m_len + len &&
	    sb->sb_acc == acc + ctl->m_len + len &&
	    sb->sb_ctl == sctl + ctl->m_len &&
	    sb->sb_mbcnt == mbcnt + MSIZE * (1 + nd) && sb->sb_fnrdy == NULL,
	    "counted, all of it ready to read");
	for (i = 0; i < 2; i++)
		if (i < nd)
			__CPROVER_assert(d[i]->m_flags ==
			    (pflags[i] & ~M_PROTOFLAGS),
			    "the payload loses its protocol flags only");
	__CPROVER_assert(sb->sb_mtls == tls && sb->sb_mtlstail == tls &&
	    sb->sb_tlscc == tlscc && sb->sb_tlsdcc == dcc &&
	    tls->m_flags == M_NOTREADY && tls->m_next == NULL,
	    "the TLS data is left alone");
}
