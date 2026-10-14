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
 * cbmc(1) harness for ktls_decrypt(), sys/kern/uipc_ktls.c, on top of
 * ktls.c, whose models and receive chains it takes.  A harness of its
 * own for the m_free() model run.sh puts in for it, which the transmit
 * proofs were not proven with.  The one entry point, for --function:
 *
 *   proof_rx_decrypt	ktls_decrypt() on the TLS chain: a record whose
 *			header the session takes is decrypted with its
 *			sequence number and appended as a TLS_GET_RECORD
 *			control message and its payload, no more, or
 *			dropped with an error; a header refused drops the
 *			connection; a partial record waits
 *
 * A whole proof over a byte stream is past 80G, so run.sh proves it on
 * fixed shapes (RX_*): one session, one record of RX_LEN bytes, in one
 * mbuf, decrypted by the NIC (RX_NIC) or not.
 */

#include "ktls.c"


void	mb_free_ext(struct mbuf *);

/*
 * m_free(), mbuf.h, for mbufs with no packet header, as these proofs'
 * are; run.sh replaces calls to it.  Its packet header branch handed
 * m_snd_tag_rele() a tag pointer read from the mbuf's union, which cbmc
 * cannot place, and the write through it went to every object.
 */
struct mbuf *
cbmc_m_free(struct mbuf *m)
{
	struct mbuf *n = m->m_next;

	__CPROVER_assert((m->m_flags & M_PKTHDR) == 0,
	    "model: an mbuf with no packet header");
	if (m->m_flags & M_EXTPG)
		mb_free_extpg(m);
	else if (m->m_flags & M_EXT)
		mb_free_ext(m);
	else
		__CPROVER_deallocate(m);
	return (n);
}


/*
 * ktls_decrypt(), which the queue's thread runs on a socket ktls_check_rx()
 * queued: from the stream of bytes in the TLS chain, each record whose
 * header the session accepts is decrypted, with its sequence number, and
 * appended to the socket buffer as a TLS_GET_RECORD control message with
 * its type, version and payload length, and the payload, no more; one
 * that fails is dropped with an error on the socket, and decryption goes
 * on; a header the session refuses drops the connection.  A partial
 * record stays.  Decryption is modelled by its contract: in place, and on
 * success a trailer that fits the record past its header.
 */
static int g_ndec, g_rwakeups, g_nappend, g_ctl, g_rfree;
static uint64_t g_seq0;
static struct tls_get_record g_tgr;
static struct mbuf *g_adata, *g_actl;
static int g_trail;

int
ktls_ocf_decrypt(struct ktls_session *tls, const struct tls_record_layer *hdr,
    struct mbuf *m, uint64_t seqno, int *trailer_len)
{
	int len = sizeof(*hdr) + ntohs(hdr->tls_length);

	__CPROVER_assert(seqno == g_seq0 + g_ndec,
	    "each record is decrypted with its sequence number");
	g_ndec++;
	if (nondet_bool())
		return (EBADMSG);
	*trailer_len = nondet_int();
	__CPROVER_assume(*trailer_len >= 1 &&
	    *trailer_len <= len - tls->params.tls_hlen);
	g_trail = *trailer_len;
	return (0);
}

int
ktls_ocf_recrypt(struct ktls_session *tls, const struct tls_record_layer *hdr,
    struct mbuf *m, uint64_t seqno)
{
	__CPROVER_assert(seqno == g_seq0 + g_ndec,
	    "a record is recrypted with its sequence number");
	return (nondet_bool() ? 0 : EBADMSG);
}

struct mbuf *
sbcreatecontrol(const void *p, u_int size, int type, int level, int wait)
{
	__CPROVER_assert(size == sizeof(struct tls_get_record) &&
	    type == TLS_GET_RECORD && level == IPPROTO_TCP,
	    "a TLS_GET_RECORD control message");
	memcpy(&g_tgr, p, sizeof(g_tgr));
	g_ctl++;
	return (__CPROVER_allocate(sizeof(struct mbuf), 1));
}

void
sbappendcontrol_locked(struct sockbuf *sb, struct mbuf *m0,
    struct mbuf *control, int flags)
{
	__CPROVER_assert(g_nappend == 0, "model: one record");
	g_nappend++;
	g_adata = m0;
	g_actl = control;
}

void
sorwakeup_locked(struct socket *so)
{
	g_rwakeups++;
}

void
mb_free_ext(struct mbuf *m)
{
	g_rfree++;
	__CPROVER_deallocate(m);
}

void
m_freem(struct mbuf *m)
{
	int i;

	for (i = 0; i < RMBUF + 2 && m != NULL; i++)
		m = m_free(m);
	__CPROVER_assert(m == NULL, "model: chain freed");
}

/* run.sh replaces calls to ktls_resync_ifnet(): there is no NIC here. */
int
cbmc_ktls_resync_ifnet(struct socket *so, uint32_t tls_len,
    uint64_t tls_rcd_num)
{
	return (EINVAL);
}

void
proof_rx_decrypt(void)
{
	struct sockbuf *sb = &g_so.so_rcv;
	struct ktls_session *tls = &g_session;
	struct mbuf *m;
	bool tls13, ok;
	int cipher, hlen, i, k, L, len, plen, tlen;
	uint8_t b, vminor;

	setup();
	/* The sessions ktls_create_session() makes for receive. */
#ifdef RX_CIPHER
	/* One session, one record shape, for constants cbmc can fold. */
	cipher = RX_CIPHER;
	vminor = RX_VMINOR;
#else
	cipher = nondet_int();
	vminor = nondet_int();
#endif
	__CPROVER_assume((cipher == CRYPTO_AES_NIST_GCM_16 ||
	    cipher == CRYPTO_CHACHA20_POLY1305) &&
	    (vminor == TLS_MINOR_VER_TWO || vminor == TLS_MINOR_VER_THREE) ||
	    cipher == CRYPTO_AES_CBC && (vminor == TLS_MINOR_VER_ONE ||
	    vminor == TLS_MINOR_VER_TWO));
	tls13 = vminor == TLS_MINOR_VER_THREE;
	hlen = 5 + (cipher == CRYPTO_AES_NIST_GCM_16 && !tls13 ? 8 :
	    cipher == CRYPTO_AES_CBC ? 16 : 0);
	tlen = cipher == CRYPTO_AES_CBC ? 16 + 20 : 16 + (tls13 ? 1 : 0);
	tls->params.cipher_algorithm = cipher;
	tls->params.tls_vmajor = TLS_MAJOR_VER_ONE;
	tls->params.tls_vminor = vminor;
	tls->params.tls_hlen = hlen;
	tls->params.tls_tlen = tlen;

	/* A byte stream: a record, if its header says so, then more. */
	L = nondet_int();
	__CPROVER_assume(L >= 0 && L <= RLEN);
	for (k = 0; k < RLEN; k++)
		g_rbytes[k] = nondet_int();
#ifdef RX_LEN
	/* A record of RX_LEN bytes, its header one the session takes. */
	L = RX_LEN;
	g_rbytes[1] = TLS_MAJOR_VER_ONE;
	g_rbytes[2] = tls13 ? TLS_MINOR_VER_TWO : vminor;
	if (tls13)
		g_rbytes[0] = TLS_RLTYPE_APP;
	g_rbytes[3] = (RX_LEN - 5) >> 8;
	g_rbytes[4] = (RX_LEN - 5) & 0xff;
#endif
	sb->sb_mtls = L > 0 ? rx_chain(L) : NULL;
	sb->sb_mtlstail = L > 0 ? g_rm[RMBUF - 1] : NULL;
	for (i = 0; i < RMBUF; i++)
#ifdef RX_NIC
		if (L > 0)
#else
		if (L > 0 && nondet_bool())
#endif
			g_rm[i]->m_flags |= M_DECRYPTED;
	sb->sb_tlscc = L;
	sb->sb_ccc = L;
	sb->sb_tlsdcc = 0;
	sb->sb_tls_info = tls;
	sb->sb_flags = SB_TLS_RX | SB_TLS_RX_RUNNING;
	sb->sb_state = nondet_bool() ? SBS_CANTRCVMORE : 0;
	g_seq0 = sb->sb_tls_seqno = nondet_int();
	g_so.so_count = 2;
	g_so.so_error = 0;
	len = L >= hlen ? 5 + (g_rbytes[3] << 8 | g_rbytes[4]) : 0;
	/* What the header must say. */
	ok = L >= hlen && g_rbytes[1] == TLS_MAJOR_VER_ONE &&
	    g_rbytes[2] == (tls13 ? TLS_MINOR_VER_TWO : vminor) &&
	    (!tls13 || g_rbytes[0] == TLS_RLTYPE_APP) &&
	    len >= hlen && len <= hlen + 16384 + tlen;
	/*
	 * RX_RECORD: the chain holds one record exactly, which spares the
	 * proof the split ktls_detach_record() makes, proven on its own;
	 * else none: a header refused, or a record not all in.  Both in one
	 * proof, over a byte stream, went past 80G: every read of a byte
	 * goes through m_data, which cbmc takes to be any pointer in the
	 * mbuf's union.
	 */
#ifdef RX_RECORD
	__CPROVER_assume(ok && len == L);
#else
	__CPROVER_assume(!ok || len > L);
#endif

	ktls_decrypt(&g_so);

	__CPROVER_assert(g_so.so_count == 1,
	    "the worker's socket reference is dropped");
	if (L < hlen || (ok && len > L)) {
		__CPROVER_assert(g_ndec == 0 && g_nappend == 0 &&
		    g_dropped == 0 && sb->sb_tlscc == L,
		    "a partial record waits");
		__CPROVER_assert((sb->sb_flags & SB_TLS_RX_RUNNING) == 0 &&
		    g_so.so_error == ((sb->sb_state & SBS_CANTRCVMORE) &&
		    L > 0 ? EMSGSIZE : 0),
		    "decryption stops, an error if nothing more can come");
		return;
	}
	if (!ok) {
		__CPROVER_assert(g_dropped == 1 && g_nappend == 0 &&
		    (g_droperr == EINVAL || g_droperr == EMSGSIZE),
		    "a header the session refuses drops the connection");
		return;
	}
	/* The record went out, decrypted or not; what follows stays. */
	__CPROVER_assert(sb->sb_tls_seqno == g_seq0 + 1,
	    "the next record has the next sequence number");
	__CPROVER_assert(sb->sb_tlscc == L - len && sb->sb_tlsdcc == 0 &&
	    sb->sb_ccc == L - len, "the record leaves the TLS accounting");
	if (g_nappend == 0) {
		__CPROVER_assert(g_so.so_error == EBADMSG ||
		    g_so.so_error == EMSGSIZE,
		    "a record that fails is an error on the socket");
		return;
	}
	plen = (g_tgr.tls_length >> 8 | g_tgr.tls_length << 8) & 0xffff;
	__CPROVER_assert(g_tgr.tls_type == (tls13 ? g_tgr.tls_type :
	    g_rbytes[0]) && g_tgr.tls_vmajor == g_rbytes[1] &&
	    g_tgr.tls_vminor == g_rbytes[2],
	    "the control message has the record's type and version");
	__CPROVER_assert(plen <= len - hlen,
	    "the payload is within the record");
	if (plen == 0)
		__CPROVER_assert(g_adata == NULL, "an empty record has no data");
	else {
		__CPROVER_assert(m_length(g_adata, &m) == plen &&
		    (m->m_flags & M_EOR) != 0,
		    "the payload, and no more, its last mbuf ending a record");
		for (k = 0; k < RLEN; k++)
			if (k < plen)
				__CPROVER_assert(chain_byte(g_adata, k, &b) &&
				    b == g_rbytes[hlen + k],
				    "the payload is the bytes past the header");
		for (m = g_adata, i = 0; i < RMBUF + 1 && m != NULL;
		    i++, m = m->m_next)
			__CPROVER_assert((m->m_flags &
			    (M_NOTREADY | M_DECRYPTED)) == 0,
			    "the payload is ready");
	}
}
