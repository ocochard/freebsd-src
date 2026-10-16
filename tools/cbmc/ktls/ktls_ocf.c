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
 * cbmc(1) harness for the KTLS receive decryption of
 * sys/opencrypto/ktls_ocf.c: the parsers of every record decrypted in
 * software, whose lengths come from the peer's record header.
 *
 * Not a program: run.sh compiles it with SOURCE naming ktls_ocf.c or a
 * mutant of it, included whole.  The crypto framework is modelled by
 * what it is asked: ktls_ocf_dispatch() checks every request stays
 * inside its buffer and succeeds or fails; the bytes it decrypts are
 * free already.  The reference is the TLS record layer: RFC 5246 6.2.3.2
 * (CBC), RFC 5288 (AES-GCM), RFC 7905 (ChaCha20-Poly1305), RFC 8446 5.2.
 * The entry points, for --function:
 *
 *   proof_cbc_decrypt	ktls_ocf_tls_cbc_decrypt() on a TLS 1.1 or 1.2
 *			record of any bytes: refused when too short or not
 *			whole blocks, or its padding wrong; else, any
 *			padding RFC 5246 allows, its MAC checked over what
 *			precedes it, the trailer within the record
 *   proof_aead12_decrypt ktls_ocf_tls12_aead_decrypt(), AES-GCM or
 *			ChaCha20-Poly1305: refused when too short, else
 *			decrypted and its tag checked, the trailer the tag
 *   proof_aead13_decrypt ktls_ocf_tls13_aead_decrypt(), the same for
 *			TLS 1.3, the content type left before the tag
 *   proof_recrypt	the recrypt of a record the NIC decrypted in part:
 *			the ciphertext back in the decrypted mbufs only
 */

#include SOURCE

#include <sys/vnode.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/refcount.h>
#include "kern.h"

/*
 * A record of RLEN bytes after its header, over up to two mbufs: a
 * constant per job, as CBMC unrolls the padding walk at offsets it
 * cannot settle otherwise.
 */
#ifndef RLEN
#define	RLEN	64
#endif
#define	RN	2

static uint8_t g_rec[5 + RLEN];
static struct mbuf *g_m[RN];
static struct ktls_session g_tls;
static struct ktls_ocf_session g_os;
static int g_rlen;			/* the chain's bytes */
static int g_dlen;			/* a MAC or tag's bytes */
static uint8_t g_out[RLEN];		/* what a recrypt request gives */

/* Byte k of the chain. */
static uint8_t
cbyte(struct mbuf *m, int k)
{
	int i;

	for (i = 0; i < RN; i++) {
		if (k < m->m_len)
			return (mtod(m, uint8_t *)[k]);
		k -= m->m_len;
		m = m->m_next;
	}
	__CPROVER_assert(0, "a byte of the record");
	return (0);
}

/* m_copydata(), uipc_mbuf.c. */
void
m_copydata(const struct mbuf *m, int off, int len, caddr_t cp)
{
	int i;

	__CPROVER_assert(off >= 0 && len >= 0 && off + len <= g_rlen,
	    "copies bytes of the record");
	for (i = 0; i < 8; i++)
		if (i < len)
			cp[i] = cbyte((struct mbuf *)m, off + i);
	__CPROVER_assert(len <= 8, "model: a few bytes copied");
}

/* m_apply(), uipc_mbuf.c, for mbufs with their data mapped. */
int
m_apply(struct mbuf *m, int off, int len, int (*f)(void *, void *, u_int),
    void *arg)
{
	u_int count;
	int i, rval;

	__CPROVER_assert(off >= 0 && len >= 0 && off + len <= g_rlen,
	    "applies to bytes of the record");
	for (i = 0; i < RN && off > 0; i++) {
		if (off < m->m_len)
			break;
		off -= m->m_len;
		m = m->m_next;
	}
	for (i = 0; i < RN && len > 0; i++) {
		count = min(m->m_len - off, len);
		rval = f(arg, mtod(m, char *) + off, count);
		if (rval)
			return (rval);
		len -= count;
		off = 0;
		m = m->m_next;
	}
	return (0);
}

void
crypto_initreq(struct cryptop *crp, crypto_session_t cses)
{
	memset(crp, 0, sizeof(*crp));
	crp->crp_session = cses;
}

void crypto_destroyreq(struct cryptop *crp) { }

/*
 * ktls_ocf_dispatch(): run.sh replaces calls to it.  A request reads and
 * writes inside its buffer only: the record for an mbuf, the iovecs for a
 * uio, and writes its output buffer within its payload's length.  What
 * was asked is kept for the proof.  It fails with ENXIO, an
 * error the code does not return itself.
 */
#define	NREQ	2
static struct {
	int op, iv, start, len, digest, aadlen;
} g_req[NREQ];
static int g_nreq;

int
cbmc_ktls_ocf_dispatch(struct ktls_ocf_session *os, struct cryptop *crp)
{
	struct uio *uio;
	char *obuf;
	int buflen, digest, i, n;

	__CPROVER_assert(g_nreq < NREQ, "model: requests");
	if (crp->crp_buf.cb_type == CRYPTO_BUF_MBUF)
		buflen = g_rlen;
	else {
		__CPROVER_assert(crp->crp_buf.cb_type == CRYPTO_BUF_UIO,
		    "an mbuf or a uio");
		uio = crp->crp_buf.cb_uio;
		buflen = uio->uio_resid;
		for (i = 0, n = 0; i < RN + 1; i++)
			if (i < uio->uio_iovcnt)
				n += uio->uio_iov[i].iov_len;
		__CPROVER_assert(uio->uio_iovcnt <= RN + 1 && n == buflen,
		    "the uio's iovecs hold its bytes");
	}
	digest = (crp->crp_op & CRYPTO_OP_VERIFY_DIGEST) != 0 ? g_dlen : 0;
	__CPROVER_assert(crp->crp_payload_start >= 0 &&
	    crp->crp_payload_length >= 0 &&
	    crp->crp_payload_start + crp->crp_payload_length <= buflen,
	    "the payload is inside the buffer");
	__CPROVER_assert((crp->crp_op & CRYPTO_OP_DECRYPT) == 0 ||
	    (crp->crp_flags & CRYPTO_F_IV_SEPARATE) != 0 ||
	    crp->crp_iv_start + AES_BLOCK_LEN <= crp->crp_payload_start,
	    "the IV is in the buffer, before the payload");
	__CPROVER_assert(digest == 0 || (crp->crp_digest_start >=
	    crp->crp_payload_start + crp->crp_payload_length &&
	    crp->crp_digest_start + digest <= buflen),
	    "the MAC follows the payload, inside the buffer");
	g_req[g_nreq].op = crp->crp_op;
	g_req[g_nreq].iv = crp->crp_iv_start;
	g_req[g_nreq].start = crp->crp_payload_start;
	g_req[g_nreq].len = crp->crp_payload_length;
	g_req[g_nreq].digest = crp->crp_digest_start;
	g_nreq++;
	if (crp->crp_obuf.cb_type != CRYPTO_BUF_NONE) {
		__CPROVER_assert(crp->crp_obuf.cb_type == CRYPTO_BUF_CONTIG,
		    "a buffer for output");
		obuf = crp->crp_obuf.cb_buf;
		__CPROVER_assert(crp->crp_payload_length <=
		    crp->crp_obuf.cb_buf_len,
		    "the output buffer holds the payload");
		__CPROVER_havoc_object(g_out);
		for (i = 0; i < RLEN; i++)
			if (i < crp->crp_payload_length)
				obuf[i] = g_out[i];
	}
	return (nondet_bool() ? 0 : ENXIO);
}

/*
 * A record as the peer sends it: header, then tls_length bytes, any of
 * them, over one or two mbufs whose data lie in buffers of their own.
 */
static struct mbuf *
record(int len)
{
	struct mbuf *m;
	int cut, i, off;

	__CPROVER_havoc_object(g_rec);
	g_rec[3] = len >> 8;
	g_rec[4] = len & 0xff;
	g_rlen = 5 + len;
	off = 0;
	for (i = 0; i < RN; i++) {
		m = __CPROVER_allocate(sizeof(struct mbuf), 1);
		m->m_flags = M_EXT;
		m->m_data = (char *)g_rec + off;
		cut = nondet_int();
		__CPROVER_assume(cut >= 0 && cut <= g_rlen - off);
		if (i == RN - 1)
			cut = g_rlen - off;
		m->m_len = cut;
		off += cut;
		g_m[i] = m;
		if (i > 0)
			g_m[i - 1]->m_next = m;
	}
	return (g_m[0]);
}

/*
 * ktls_ocf_tls_cbc_decrypt(), against RFC 5246 6.2.3.2: the record is an
 * explicit IV, then content, MAC and padding, whole blocks; the last byte
 * gives the padding's length, and every padding byte holds that value,
 * up to 255 of them.  A record too short or not whole blocks is refused
 * (EMSGSIZE), and so is one whose padding does not fit after the IV and
 * MAC or is not all of its length (EBADMSG); any other goes on to the MAC,
 * checked over the content, and the trailer is the MAC and padding.
 */
void
proof_cbc_decrypt(void)
{
	struct ktls_session *tls = &g_tls;
	struct mbuf *m;
	int error, i, len, mac, pad, trailer, valid;

	mac = nondet_int();
	__CPROVER_assume(mac == SHA1_HASH_LEN || mac == SHA2_256_HASH_LEN ||
	    mac == SHA2_384_HASH_LEN);
	g_os.mac_len = mac;
	g_dlen = mac;
	tls->ocf_session = &g_os;
	tls->params.cipher_algorithm = CRYPTO_AES_CBC;
	tls->params.tls_vminor = nondet_bool() ? TLS_MINOR_VER_ONE :
	    TLS_MINOR_VER_TWO;
	tls->params.tls_hlen = 5 + AES_BLOCK_LEN;
	len = RLEN;
	m = record(len);
	trailer = -1;

	error = ktls_ocf_tls_cbc_decrypt(tls,
	    (const struct tls_record_layer *)g_rec, m, nondet_int(), &trailer);

	if (len % AES_BLOCK_LEN != 0 ||
	    len < AES_BLOCK_LEN + roundup2(mac + 1, AES_BLOCK_LEN)) {
		__CPROVER_assert(error == EMSGSIZE && g_nreq == 0,
		    "a record too short or not whole blocks is refused");
		return;
	}
	__CPROVER_assert(g_nreq >= 1 && g_req[0].op == CRYPTO_OP_DECRYPT &&
	    g_req[0].iv == 5 && g_req[0].start == 5 + AES_BLOCK_LEN &&
	    g_req[0].len == len - AES_BLOCK_LEN,
	    "the record is decrypted after its IV");
	if (g_nreq == 1 && error == ENXIO)
		return;			/* the decryption failed */
	pad = g_rec[5 + len - 1];
	valid = AES_BLOCK_LEN + mac + pad + 1 <= len;
	for (i = 0; i < 256; i++)
		if (i <= pad && valid && g_rec[5 + len - 1 - i] != pad)
			valid = 0;
	if (!valid) {
		__CPROVER_assert(error == EBADMSG && g_nreq == 1,
		    "a padding that does not fit or is not all its length "
		    "is refused");
		return;
	}
	__CPROVER_assert(g_nreq == 2,
	    "any padding RFC 5246 allows goes on to the MAC");
	__CPROVER_assert(g_req[1].op == CRYPTO_OP_VERIFY_DIGEST &&
	    g_req[1].len == (int)sizeof(struct tls_mac_data) + len -
	    AES_BLOCK_LEN - mac - pad - 1,
	    "the MAC is checked over the content");
	__CPROVER_assert(trailer == mac + pad + 1 &&
	    tls->params.tls_hlen + trailer <= 5 + len,
	    "the trailer is the MAC and padding, inside the record");
}

/*
 * An AEAD session of TLS 1.2 or 1.3, as ktls_create_session() sets it
 * up: AES-GCM, with an explicit nonce in TLS 1.2, or ChaCha20-Poly1305;
 * a 16-byte tag, and in TLS 1.3 the content type after the content.
 */
static void
aead_session(int vminor)
{
	struct ktls_session *tls = &g_tls;

	tls->ocf_session = &g_os;
	tls->params.tls_vminor = vminor;
	tls->params.cipher_algorithm = nondet_bool() ?
	    CRYPTO_AES_NIST_GCM_16 : CRYPTO_CHACHA20_POLY1305;
	tls->params.tls_hlen = sizeof(struct tls_record_layer);
	tls->params.tls_tlen = AES_GMAC_HASH_LEN;
	if (tls->params.cipher_algorithm == CRYPTO_AES_NIST_GCM_16) {
		tls->params.iv_len = vminor == TLS_MINOR_VER_THREE ?
		    TLS_1_3_GCM_IV_LEN : TLS_AEAD_GCM_LEN;
		if (vminor != TLS_MINOR_VER_THREE)
			tls->params.tls_hlen += sizeof(uint64_t);
	} else
		tls->params.iv_len = TLS_CHACHA20_IV_LEN;
	if (vminor == TLS_MINOR_VER_THREE)
		tls->params.tls_tlen += sizeof(uint8_t);
	g_dlen = AES_GMAC_HASH_LEN;
}

/*
 * ktls_ocf_tls12_aead_decrypt(), against RFC 5288 3 and RFC 7905 2: the
 * record is the explicit nonce (AES-GCM only), the content and a 16-byte
 * tag.  A record too short for them is refused (EMSGSIZE); any other is
 * decrypted and its tag checked in one request, the content after the
 * header and nonce, the tag the record's last bytes, and the trailer is
 * the tag.
 */
void
proof_aead12_decrypt(void)
{
	struct ktls_session *tls = &g_tls;
	struct mbuf *m;
	int error, len, nonce, trailer;

	aead_session(TLS_MINOR_VER_TWO);
	nonce = tls->params.tls_hlen - sizeof(struct tls_record_layer);
	len = nondet_int();
	__CPROVER_assume(len >= 0 && len <= RLEN);
	m = record(len);
	trailer = -1;

	error = ktls_ocf_tls12_aead_decrypt(tls,
	    (const struct tls_record_layer *)g_rec, m, nondet_int(), &trailer);

	if (len < nonce + AES_GMAC_HASH_LEN) {
		__CPROVER_assert(error == EMSGSIZE && g_nreq == 0,
		    "a record too short for its nonce and tag is refused");
		return;
	}
	__CPROVER_assert(g_nreq == 1 && g_req[0].op ==
	    (CRYPTO_OP_DECRYPT | CRYPTO_OP_VERIFY_DIGEST),
	    "the record is decrypted and its tag checked");
	__CPROVER_assert(g_req[0].start == tls->params.tls_hlen &&
	    g_req[0].len == len - nonce - AES_GMAC_HASH_LEN &&
	    g_req[0].digest + AES_GMAC_HASH_LEN == 5 + len,
	    "the content follows the nonce, the tag ends the record");
	__CPROVER_assert(trailer == AES_GMAC_HASH_LEN &&
	    tls->params.tls_hlen + trailer <= 5 + len,
	    "the trailer is the tag, inside the record");
}

/*
 * ktls_ocf_tls13_aead_decrypt(), against RFC 8446 5.2: the record is the
 * encrypted inner plaintext, at least its content type, then a 16-byte
 * tag.  A record too short for them is refused (EMSGSIZE); any other is
 * decrypted and its tag checked in one request, the tag the record's
 * last bytes, and the trailer is the tag; the content type stays for
 * ktls_decrypt() to read.
 */
void
proof_aead13_decrypt(void)
{
	struct ktls_session *tls = &g_tls;
	struct mbuf *m;
	int error, len, trailer;

	aead_session(TLS_MINOR_VER_THREE);
	len = nondet_int();
	__CPROVER_assume(len >= 0 && len <= RLEN);
	m = record(len);
	trailer = -1;

	error = ktls_ocf_tls13_aead_decrypt(tls,
	    (const struct tls_record_layer *)g_rec, m, nondet_int(), &trailer);

	if (len < 1 + AES_GMAC_HASH_LEN) {
		__CPROVER_assert(error == EMSGSIZE && g_nreq == 0,
		    "a record too short for its content type and tag is "
		    "refused");
		return;
	}
	__CPROVER_assert(g_nreq == 1 && g_req[0].op ==
	    (CRYPTO_OP_DECRYPT | CRYPTO_OP_VERIFY_DIGEST),
	    "the record is decrypted and its tag checked");
	__CPROVER_assert(g_req[0].start == tls->params.tls_hlen &&
	    g_req[0].len == len - AES_GMAC_HASH_LEN &&
	    g_req[0].digest + AES_GMAC_HASH_LEN == 5 + len,
	    "the content and its type follow the header, the tag ends the "
	    "record");
	__CPROVER_assert(trailer == AES_GMAC_HASH_LEN &&
	    tls->params.tls_hlen + trailer + 1 <= 5 + len,
	    "the trailer is the tag, the content type before it");
}

/*
 * ktls_ocf_tls12_aead_recrypt() and ktls_ocf_tls13_aead_recrypt(), for
 * ktls_decrypt() of a record the NIC decrypted in part (AES-GCM only):
 * the decrypted mbufs get back their ciphertext, so the record can be
 * decrypted whole.  The contract is the record layout of RFC 5288 and
 * RFC 8446 5.2: a record too short for its nonce and tag, or content
 * type and tag, is refused (EMSGSIZE) and left as it is; any other has
 * the keystream for its content asked for, and each byte of the content
 * in a decrypted mbuf replaced by the output's byte for it; bytes in the
 * other mbufs, the header, nonce and tag stay as they were.  The
 * version (VMINOR) and the record's length are constants per job: CBMC
 * checks each byte of it.
 */
#ifndef VMINOR
#define	VMINOR	TLS_MINOR_VER_THREE
#endif
static uint8_t g_old[5 + RLEN];

void
proof_recrypt(void)
{
	struct ktls_session *tls = &g_tls;
	struct mbuf *m;
	int dec, end, error, i, j, k, len, min, start;

	aead_session(VMINOR);
	__CPROVER_assume(tls->params.cipher_algorithm ==
	    CRYPTO_AES_NIST_GCM_16);
	len = RLEN;
	m = record(len);
	for (i = 0; i < RN; i++)
		if (nondet_bool())
			g_m[i]->m_flags |= M_DECRYPTED;
	memcpy(g_old, g_rec, sizeof(g_rec));

	if (tls->params.tls_vminor == TLS_MINOR_VER_TWO) {
		min = sizeof(uint64_t) + AES_GMAC_HASH_LEN;
		error = ktls_ocf_tls12_aead_recrypt(tls,
		    (const struct tls_record_layer *)g_rec, m, nondet_int());
	} else {
		min = AES_GMAC_HASH_LEN + 1;
		error = ktls_ocf_tls13_aead_recrypt(tls,
		    (const struct tls_record_layer *)g_rec, m, nondet_int());
	}

	if (len < min) {
		__CPROVER_assert(error == EMSGSIZE && g_nreq == 0,
		    "a record too short for its nonce and tag is refused");
	} else {
		__CPROVER_assert(g_nreq == 1 &&
		    g_req[0].op == CRYPTO_OP_ENCRYPT &&
		    g_req[0].start == tls->params.tls_hlen &&
		    g_req[0].start + g_req[0].len + AES_GMAC_HASH_LEN == 5 + len,
		    "the keystream is asked for the content");
	}
	start = tls->params.tls_hlen;
	end = 5 + len - AES_GMAC_HASH_LEN;
	for (k = 0, i = 0, j = 0; k < 5 + RLEN; k++) {
		if (k >= g_rlen)
			break;
		while (j >= g_m[i]->m_len) {	/* the mbuf of byte k */
			j = 0;
			i++;
		}
		dec = (g_m[i]->m_flags & M_DECRYPTED) != 0;
		if (error == 0 && dec && k >= start && k < end)
			__CPROVER_assert(g_rec[k] == g_out[k - start],
			    "a decrypted byte of the content gets its ciphertext");
		else
			__CPROVER_assert(g_rec[k] == g_old[k],
			    "any other byte stays");
		j++;
	}
}
