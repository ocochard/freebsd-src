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
