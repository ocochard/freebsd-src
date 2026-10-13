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
 * cbmc(1) harness for ktls_frame() and ktls_enqueue(),
 * sys/kern/uipc_ktls.c, built with KERN_TLS.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_ktls.c or a
 * mutant of it, included whole.  proof_frame's sessions are made by the
 * kernel's own ktls_create_session(), from any struct tls_enable it
 * accepts; the others start from the state it proves they leave.  The
 * reference for a record is the TLS record layer: RFC 2246 6.2.3 (TLS
 * 1.0), RFC 4346 6.2.3 (1.1), RFC 5246 6.2 (1.2), RFC 5288 3 (AES-GCM),
 * RFC 7905 2 (ChaCha20-Poly1305) and RFC 8446 5.2 (1.3); for the queue,
 * what sendfile(2) and sosend() expect of it.  Each proof is an entry
 * point for --function:
 *
 *   proof_frame	ktls_frame() on a chain of records: every record
 *			has the header and trailer its cipher and version
 *			take, a header naming its type, version and length,
 *			a nonce never used before or a random IV, a
 *			session reference, and, with software encryption,
 *			its pages counted as left to encrypt
 *   proof_enqueue	one ktls_enqueue() of records ktls_frame() made:
 *			the batch is queued to its session's queue, the
 *			queue's thread woken when idle, or for TLS 1.0,
 *			whose records have to be encrypted in turn, kept
 *			waiting when out of turn
 *   proof_enqueue_turn	TLS 1.0 records completing in any order, as
 *			sendfile(2) I/O does, by induction: each is queued
 *			once, in sequence, as soon as those before it are
 *   proof_encrypt	the worker, ktls_encrypt(), on a batch: each record
 *   proof_encrypt_async encrypted once over its payload and trailer, and
 *			readied, or the connection dropped and the batch
 *			freed, without a page, buffer or reference left
 *			behind; and ktls_encrypt_async() with completions
 */

#include SOURCE

#include <sys/endian.h>

static void	*cbmc_uma(uma_zone_t, int);
static void	 cbmc_uma_free(uma_zone_t, void *);
static void	*cbmc_malloc(size_t, struct malloc_type *, int);
static void	 cbmc_counter(counter_u64_t, int64_t);
#define	CBMC_UMA_HOOK		cbmc_uma
#define	CBMC_UMA_FREE_HOOK	cbmc_uma_free
#define	CBMC_MALLOC_HOOK	cbmc_malloc
#define	CBMC_COUNTER_HOOK	cbmc_counter
#include "kern.h"

/* Records in a chain. */
#ifndef MAXREC
#define	MAXREC	3
#endif
#if MAXREC > 3
#error "proof_enqueue_turn names three records at most"
#endif

static struct socket g_so;
static struct inpcb g_inp;
static char g_session_zone;

static void *
cbmc_uma(uma_zone_t zone, int flags)
{
	if (zone != ktls_session_zone)
		return (NULL);
	return (__CPROVER_allocate(sizeof(struct ktls_session),
	    (flags & M_ZERO) != 0));
}

/* What the counters of pending and queued records count. */
static int64_t g_pending, g_queued;

static void
cbmc_counter(counter_u64_t c, int64_t inc)
{
	if (c == ktls_cnt_tx_pending)
		g_pending += inc;
	else if (c == ktls_cnt_tx_queued)
		g_queued += inc;
}

/* arc4rand(9): random bytes, and where they were asked for. */
#define	NRAND	(MAXREC + 1)
static uint8_t *g_rand[NRAND];
static u_int g_randlen[NRAND];
static int g_nrand;

void
arc4rand(void *ptr, u_int len, int reseed)
{
	__CPROVER_assert(g_nrand < NRAND, "model: arc4rand calls");
	g_rand[g_nrand] = ptr;
	g_randlen[g_nrand++] = len;
	__CPROVER_havoc_slice(ptr, len);
}

static bool
randomized(uint8_t *p, u_int len)
{
	int i;

	for (i = 0; i < g_nrand; i++)
		if (g_rand[i] == p && g_randlen[i] == len)
			return (true);
	return (false);
}

void in_pcbref(struct inpcb *inp) { }

/* wakeup(9): which channel, how often. */
static const void *g_woken;
static int g_nwakeups;

void
wakeup(const void *chan)
{
	g_woken = chan;
	g_nwakeups++;
}

/*
 * The state ktls_init() leaves: the threads started, with their queue, and
 * the counters.  One thread, as MAXCPU is 1 without SMP: a queue picked by
 * an index cbmc cannot settle made each write to it one through an unknown
 * offset, and the single call proof took over 30G.  kern.ipc.tls.maxlen is
 * any multiple of the page size, as ktls_buffer_import() asserts.
 */
static struct ktls_wq g_wq;

static void
setup(void)
{
	u_int pages;

	ktls_init_state = 1;
	ktls_session_zone = (uma_zone_t)&g_session_zone;
	ktls_number_threads = 1;
	ktls_cpuid_lookup[0] = 0;
	ktls_wq = &g_wq;
	STAILQ_INIT(&g_wq.m_head);
	g_wq.running = nondet_bool();
	ktls_cnt_tx_pending = counter_u64_alloc(M_WAITOK);
	ktls_cnt_tx_queued = counter_u64_alloc(M_WAITOK);
	ktls_offload_active = counter_u64_alloc(M_WAITOK);
	ktls_cbc_enable = nondet_bool();
	pages = nondet_u_int();
	__CPROVER_assume(pages >= 1 && pages <= 8);
	ktls_maxlen = pages * PAGE_SIZE;
}

/*
 * A transmit session from any parameters ktls_create_session() accepts:
 * the cipher, MAC, version and IV length are free, the key lengths within
 * a bound that keeps them to the modelled malloc(9) bucket (they change
 * nothing in a record), and so is the mode it ends in.
 */
static uint8_t g_key[64], g_iv[TLS_CBC_IMPLICIT_IV_LEN];
static uint64_t g_seqno;	/* the sequence number of the first record */

static struct ktls_session *
session(void)
{
	struct tls_enable en;
	struct ktls_session *tls;
	int i;

	memset(&en, 0, sizeof(en));
	en.cipher_key = g_key;
	en.auth_key = g_key;
	en.iv = g_iv;
	en.cipher_algorithm = nondet_int();
	en.auth_algorithm = nondet_int();
	en.cipher_key_len = nondet_int();
	en.auth_key_len = nondet_int();
	en.iv_len = nondet_int();
	en.tls_vmajor = nondet_int();
	en.tls_vminor = nondet_int();
	for (i = 0; i < 8; i++)
		en.rec_seq[i] = nondet_int();
	g_seqno = be64dec(en.rec_seq);
	__CPROVER_assume(en.cipher_key_len > 0 && en.cipher_key_len <= 64);
	__CPROVER_assume(en.auth_key_len >= 0 && en.auth_key_len <= 64);
	__CPROVER_assume(en.iv_len >= 0 && en.iv_len <= sizeof(g_iv));
	g_inp.inp_flowid = nondet_u_int();
	g_so.so_pcb = &g_inp;
	__CPROVER_assume(ktls_create_session(&g_so, &en, &tls, KTLS_TX) == 0);
	tls->mode = nondet_int();
	__CPROVER_assume(tls->mode == TCP_TLS_MODE_SW ||
	    tls->mode == TCP_TLS_MODE_IFNET || tls->mode == TCP_TLS_MODE_TOE);
	return (tls);
}

/*
 * A chain of n records as sosend() and vn_sendfile() pass them: unmapped
 * mbufs, each no longer than a frame, empty only where TLS 1.0 CBC allows
 * an empty fragment, over at most a full mbuf of pages.
 */
static struct mbuf *g_rec[MAXREC];
static int g_len[MAXREC];

static int
records(struct ktls_session *tls)
{
	struct mbuf *m;
	int i, n;

	n = nondet_int();
	__CPROVER_assume(n >= 1 && n <= MAXREC);
	for (i = 0; i < n; i++) {
		m = __CPROVER_allocate(sizeof(struct mbuf), 1);
		m->m_flags = M_EXT | M_EXTPG;
		m->m_len = nondet_int();
		__CPROVER_assume(m->m_len >= 0 &&
		    m->m_len <= tls->params.max_frame_len);
		__CPROVER_assume(m->m_len > 0 ||
		    ktls_permit_empty_frames(tls));
		m->m_epg_npgs = nondet_int();
		__CPROVER_assume(m->m_epg_npgs <= MBUF_PEXT_MAX_PGS);
		__CPROVER_assume(m->m_epg_npgs > 0 || m->m_len == 0);
		g_len[i] = m->m_len;
		g_rec[i] = m;
		if (i > 0)
			g_rec[i - 1]->m_next = m;
	}
	return (n);
}

/*
 * The header and trailer of a record by the RFCs: an explicit nonce of 8
 * bytes for AES-GCM in TLS 1.2, an explicit IV of a block for CBC from
 * TLS 1.1 on; the AEAD tag of 16 bytes, or the MAC and from 1 to a block
 * of padding for CBC; and in TLS 1.3 the content type, encrypted.
 */
static int
mac_len(struct ktls_session *tls)
{
	switch (tls->params.auth_algorithm) {
	case CRYPTO_SHA1_HMAC:
		return (20);
	case CRYPTO_SHA2_256_HMAC:
		return (32);
	case CRYPTO_SHA2_384_HMAC:
		return (48);
	}
	__CPROVER_assert(0, "a CBC session has a MAC");
	return (0);
}

static void
check_record(struct ktls_session *tls, struct mbuf *m, int len,
    uint8_t rtype, uint64_t nonce)
{
	uint8_t *hdr = (uint8_t *)m->m_epg_hdr;
	int cipher = tls->params.cipher_algorithm;
	int vminor = tls->params.tls_vminor;
	bool tls13 = vminor == TLS_MINOR_VER_THREE;
	int hlen, tlen, pad;

	__CPROVER_assert(m->m_epg_tls == tls, "the record holds its session");

	/* The header and trailer the cipher and version take. */
	hlen = 5;
	if (cipher == CRYPTO_AES_NIST_GCM_16 && !tls13)
		hlen += 8;
	if (cipher == CRYPTO_AES_CBC && vminor >= TLS_MINOR_VER_ONE)
		hlen += 16;
	__CPROVER_assert(m->m_epg_hdrlen == hlen,
	    "the header has the length the cipher and version take");
	__CPROVER_assert(m->m_epg_hdrlen <= MBUF_PEXT_HDR_LEN,
	    "the header fits the mbuf");
	if (cipher == CRYPTO_AES_CBC) {
		tlen = mac_len(tls);
		pad = m->m_epg_trllen - tlen;
		__CPROVER_assert(pad >= 1 && pad <= 16,
		    "CBC: from one byte to a block of padding");
		__CPROVER_assert((len + m->m_epg_trllen) % 16 == 0,
		    "CBC: what is encrypted fills whole blocks");
	} else {
		tlen = 16 + (tls13 ? 1 : 0);
		__CPROVER_assert(m->m_epg_trllen == tlen,
		    "AEAD: the trailer is the tag, and the type in TLS 1.3");
	}
	__CPROVER_assert(m->m_epg_trllen <= MBUF_PEXT_TRAIL_LEN,
	    "the trailer fits the mbuf");
	__CPROVER_assert(m->m_len == len + m->m_epg_hdrlen + m->m_epg_trllen,
	    "the record is the payload with its header and trailer");

	/* The header: type, version, length. */
	__CPROVER_assert(hdr[1] == TLS_MAJOR_VER_ONE, "major version 3");
	if (tls13) {
		__CPROVER_assert(hdr[0] == TLS_RLTYPE_APP &&
		    hdr[2] == TLS_MINOR_VER_TWO,
		    "TLS 1.3: an application data record of TLS 1.2");
		__CPROVER_assert((uint8_t)m->m_epg_trail[0] == rtype &&
		    m->m_epg_record_type == rtype,
		    "TLS 1.3: the real type is in the trailer");
	} else
		__CPROVER_assert(hdr[0] == rtype && hdr[2] == vminor,
		    "the header names the type and version");
	__CPROVER_assert(be16dec(hdr + 3) == m->m_len - 5,
	    "the header gives the length of what follows it");
	__CPROVER_assert(len <= 16384, "the plaintext fits a record");
	__CPROVER_assert(be16dec(hdr + 3) <= 16384 + (tls13 ? 256 : 2048),
	    "the ciphertext fits a record");

	/* What makes each record's encryption unique. */
	if (cipher == CRYPTO_AES_NIST_GCM_16 && !tls13)
		__CPROVER_assert(be64dec(hdr + 5) == nonce,
		    "GCM: the explicit nonce is the next of the session");
	if (cipher == CRYPTO_AES_CBC && vminor >= TLS_MINOR_VER_ONE)
		__CPROVER_assert(randomized(hdr + 5, 16),
		    "CBC: the explicit IV is random");

	/* Software encryption: the pages are left to encrypt. */
	if (tls->mode == TCP_TLS_MODE_SW) {
		__CPROVER_assert((m->m_flags & M_NOTREADY) != 0,
		    "SW: the record is not ready");
		__CPROVER_assert(m->m_epg_nrdy ==
		    (len == 0 ? 1 : m->m_epg_npgs),
		    "SW: every page is left to encrypt, one for an empty "
		    "record");
	} else
		__CPROVER_assert((m->m_flags & M_NOTREADY) == 0,
		    "NIC and TOE: the record is ready");
}

void
proof_frame(void)
{
	struct ktls_session *tls;
	uint64_t *noncep, nonce;
	u_int refs;
	uint8_t rtype;
	int enq, i, n, pages;

	setup();
	tls = session();
	n = records(tls);
	noncep = (uint64_t *)(tls->params.iv + 8);
	nonce = *noncep;
	refs = tls->refcount;
	rtype = nondet_int();

	ktls_frame(g_rec[0], tls, &enq, rtype);

	pages = 0;
	for (i = 0; i < n; i++) {
		check_record(tls, g_rec[i], g_len[i], rtype, nonce + i);
		pages += g_rec[i]->m_epg_nrdy;
	}
	__CPROVER_assert(tls->refcount == refs + n,
	    "a session reference for each record");
	if (tls->params.cipher_algorithm == CRYPTO_AES_NIST_GCM_16 &&
	    tls->params.tls_vminor == TLS_MINOR_VER_TWO)
		__CPROVER_assert(*noncep == nonce + n,
		    "GCM: the session's nonce is past every record's");
	__CPROVER_assert(enq == (tls->mode == TCP_TLS_MODE_SW ? pages : 0),
	    "the pages to encrypt are counted");

	/*
	 * A TLS 1.0 CBC record's IV is the last block of the record before
	 * it (RFC 2246 6.2.3.2), so records are encrypted in turn, from the
	 * first one's sequence number on: what sw_session() takes.
	 */
	__CPROVER_assert(tls->sequential_records ==
	    (tls->params.cipher_algorithm == CRYPTO_AES_CBC &&
	    tls->params.tls_vminor == TLS_MINOR_VER_ZERO),
	    "TLS 1.0 CBC records are encrypted in sequence");
	if (tls->sequential_records)
		__CPROVER_assert(tls->next_seqno == g_seqno &&
		    STAILQ_EMPTY(&tls->pending_records),
		    "TLS 1.0: none pending, the first record is next");
}

/*
 * The state of a software session ktls_enqueue() reads, as proof_frame
 * shows ktls_create_session() leaves it: records encrypted in turn only
 * for TLS 1.0 CBC, from any sequence number, none waiting.  Not the
 * session ktls_create_session() returns: its key copies left the formula
 * of a ktls_enqueue() of two records at 16 million variables.
 */
static struct ktls_session g_session;

static struct ktls_session *
sw_session(bool tls10)
{
	struct ktls_session *tls = &g_session;

	tls->mode = TCP_TLS_MODE_SW;
	tls->refcount = 1;
	tls->params.max_frame_len = ktls_maxlen < 16384 ? ktls_maxlen : 16384;
	if (tls10) {
		tls->params.cipher_algorithm = CRYPTO_AES_CBC;
		tls->params.tls_vminor = TLS_MINOR_VER_ZERO;
		tls->sequential_records = true;
		tls->next_seqno = nondet_int();
		STAILQ_INIT(&tls->pending_records);
	} else
		tls->params.tls_vminor = TLS_MINOR_VER_TWO;
	tls->wq_index = 0;
	return (tls);
}

/*
 * The socket ktls_enqueue() is given, which it only saves: a token, not
 * g_so.  cbmc takes a pointer read from a union, as the m_epg_ fields of
 * an mbuf are, to be any pointer written to it, so each access through
 * the session ktls_enqueue() reads back was also one to the socket saved
 * beside it, and a struct socket made those the bulk of the formula.
 */
static char g_sotoken;
#define	SO	((struct socket *)&g_sotoken)

/*
 * What ktls_frame() leaves of n records with software encryption, by
 * proof_frame, appended to the socket buffer in order, so numbered from
 * seqno0 on (ktls_seq()).  A sequence number does not wrap: it "may not
 * exceed 2^64-1" (RFC 2246 6.1).  Past it, nothing in KTLS stops a TLS
 * 1.0 record numbered 0 from being kept waiting before one numbered
 * 2^64-1, which then waits for good, but only a session given a sequence
 * number that close to the end can get there, and it breaks the protocol.
 */
static void
framed(struct ktls_session *tls, int n, uint64_t seqno0)
{
	int i;

	__CPROVER_assume(seqno0 <= UINT64_MAX - n);

	for (i = 0; i < n; i++) {
		g_rec[i]->m_flags |= M_NOTREADY;
		g_rec[i]->m_epg_tls = tls;
		g_rec[i]->m_epg_nrdy = g_len[i] == 0 ? 1 :
		    g_rec[i]->m_epg_npgs;
		g_rec[i]->m_epg_seqno = seqno0 + i;
	}
}

/*
 * One ktls_enqueue() of the first k records, as sosend() makes it of all
 * it framed and sendfile(2) of one I/O's, on a new session: the batch
 * goes to the session's queue, or for TLS 1.0 when it is not the next in
 * sequence waits for those before it.
 */
void
proof_enqueue(void)
{
	struct ktls_session *tls;
	struct ktls_wq *wq;
	uint64_t next;
	bool running;
	int cnt, i, k, n;

	setup();
	tls = sw_session(nondet_bool());
	n = records(tls);
	framed(tls, n, nondet_int());
	k = nondet_int();
	__CPROVER_assume(k >= 1 && k <= n);
	cnt = 0;
	for (i = 0; i < k; i++)
		cnt += g_rec[i]->m_epg_nrdy;
	wq = &ktls_wq[tls->wq_index];
	running = wq->running;
	next = tls->next_seqno;

	ktls_enqueue(g_rec[0], SO, cnt);

	__CPROVER_assert(g_rec[0]->m_epg_enc_cnt == cnt &&
	    g_rec[0]->m_epg_so == SO,
	    "the batch keeps its page count and socket");
	if (tls->sequential_records && g_rec[0]->m_epg_seqno != next) {
		__CPROVER_assert(STAILQ_EMPTY(&wq->m_head) &&
		    STAILQ_FIRST(&tls->pending_records) == g_rec[0] &&
		    STAILQ_NEXT(g_rec[0], m_epg_stailq) == NULL,
		    "TLS 1.0: a batch out of turn waits");
		__CPROVER_assert(g_pending == 1 && g_queued == 0 &&
		    g_nwakeups == 0, "TLS 1.0: it is counted pending");
		__CPROVER_assert(tls->next_seqno == next,
		    "TLS 1.0: the next sequence number stays");
		return;
	}
	__CPROVER_assert(STAILQ_FIRST(&wq->m_head) == g_rec[0] &&
	    STAILQ_NEXT(g_rec[0], m_epg_stailq) == NULL,
	    "the batch is queued");
	__CPROVER_assert(g_queued == 1 && g_pending == 0,
	    "it is counted queued");
	__CPROVER_assert(running ? g_nwakeups == 0 :
	    g_nwakeups == 1 && g_woken == wq,
	    "an idle queue's thread is woken");
	if (tls->sequential_records)
		__CPROVER_assert(tls->next_seqno == next + k &&
		    STAILQ_EMPTY(&tls->pending_records),
		    "TLS 1.0: the next sequence number is past the batch");
}

/*
 * TLS 1.0, one record per batch, by induction on the batches completed:
 * in a state the queue may be in, the records from the session's next
 * sequence number on, some of those after it waiting in sequence, one not
 * waiting completes.  In turn, it is queued with the run of waiting ones
 * behind it, and the next sequence number is the first after that run;
 * out of turn, it waits, in sequence.  Either way the state is again one
 * the queue may be in, so batches completing in any order are queued in
 * sequence.  One call rather than one per batch, as cbmc takes a pointer
 * read from the mbuf's union to be any written to it, which made a proof
 * of two batches completing in turn over 40G.
 */
void
proof_enqueue_turn(void)
{
	struct ktls_session *tls;
	struct ktls_wq *wq;
	struct mbuf *m;
	uint64_t next;
	bool waits[MAXREC];
	int c, i, k, n, np;

	setup();
	tls = sw_session(true);
	next = tls->next_seqno;
	n = records(tls);
	framed(tls, n, next);
	wq = &ktls_wq[tls->wq_index];
	np = 0;
	for (i = 0; i < n; i++) {
		waits[i] = i > 0 && nondet_bool();
		if (waits[i]) {
			/* What ktls_enqueue() left of it. */
			g_rec[i]->m_epg_enc_cnt = g_rec[i]->m_epg_nrdy;
			g_rec[i]->m_epg_so = SO;
			STAILQ_INSERT_TAIL(&tls->pending_records, g_rec[i],
			    m_epg_stailq);
			np++;
		}
	}
	g_pending = np;
	c = nondet_int();
	__CPROVER_assume(c >= 0 && c < n && !waits[c]);

	switch (c) {
	case 0:
		ktls_enqueue(g_rec[0], SO, g_rec[0]->m_epg_nrdy);
		break;
#if MAXREC > 1
	case 1:
		ktls_enqueue(g_rec[1], SO, g_rec[1]->m_epg_nrdy);
		break;
#endif
#if MAXREC > 2
	case 2:
		ktls_enqueue(g_rec[2], SO, g_rec[2]->m_epg_nrdy);
		break;
#endif
	}

	if (c == 0) {
		/* In turn: queued, with the run waiting behind it. */
		m = STAILQ_FIRST(&wq->m_head);
		for (k = 0; k < n && (k == 0 || waits[k]); k++) {
			__CPROVER_assert(m == g_rec[k],
			    "TLS 1.0: in turn, queued with the run behind it");
			m = STAILQ_NEXT(m, m_epg_stailq);
		}
		__CPROVER_assert(m == NULL, "TLS 1.0: nothing out of turn queued");
		__CPROVER_assert(tls->next_seqno == next + k,
		    "TLS 1.0: next is the first after the run");
		__CPROVER_assert(g_queued == k, "the queued are counted");
		waits[0] = false;
		for (i = 1; i < k; i++)
			waits[i] = false;
	} else {
		/* Out of turn: waits. */
		__CPROVER_assert(STAILQ_EMPTY(&wq->m_head) && g_queued == 0,
		    "TLS 1.0: out of turn, nothing queued");
		__CPROVER_assert(tls->next_seqno == next,
		    "TLS 1.0: next stays");
		waits[c] = true;
		k = 0;
	}
	/* The others wait, in sequence, and are counted so. */
	np = 0;
	m = STAILQ_FIRST(&tls->pending_records);
	for (i = 0; i < n; i++) {
		if (waits[i]) {
			__CPROVER_assert(m == g_rec[i],
			    "TLS 1.0: those not queued wait in sequence");
			m = STAILQ_NEXT(m, m_epg_stailq);
			np++;
		}
	}
	__CPROVER_assert(m == NULL, "TLS 1.0: nothing else waits");
	__CPROVER_assert(g_pending == np, "the waiting are counted");
}

/*
 * The worker: ktls_encrypt() and ktls_encrypt_async(), which the queue's
 * thread runs on each batch ktls_enqueue() queued, against what their
 * callers take of them.  A batch of n records, all left to encrypt, then
 * a record appended after it, which the walk of m_next must not reach.
 * Encryption, by ktls_ocf_encrypt(), is modelled by what it is given: the
 * record in place when its pages are anonymous (sosend()'s), else new
 * pages or a contiguous buffer covering the payload, then the trailer;
 * it fails, or succeeds, and for an asynchronous backend completes after
 * the worker moved on.
 */
#ifndef WREC
#define	WREC	2
#endif
#define	WPAGES	(WREC * MBUF_PEXT_MAX_PGS)

vm_paddr_t dmaplimit = ~0UL;	/* a direct map over every address */
struct kva_layout_s kva_layout = { .dmap_low = 0, .dmap_high = ~0UL };

static struct protosw g_proto;
static char g_buffer_zone;
static struct mbuf *g_w[WREC + 1];	/* the batch, then the next record */
static int g_wn;			/* records in the batch */
static int g_enc[WREC], g_ready[WREC], g_freed[WREC], g_srcfree[WREC];
static bool g_file[WREC];		/* a record of file pages */
static int g_dropped, g_nbuf, g_nbuffree;
static struct ktls_ocf_encrypt_state *g_deferred[WREC];
static int g_ndeferred;

static int
widx(struct mbuf *m)
{
	int i;

	for (i = 0; i < WREC; i++)
		if (i < g_wn && m == g_w[i])
			return (i);
	__CPROVER_assert(0, "a record of the batch");
	return (0);
}

/* A record's payload: on one page, m_epg_last_len counts from the offset. */
static int
payload(struct mbuf *m)
{
	if (m->m_epg_npgs <= 1)
		return (m->m_epg_last_len);
	return (ptoa(m->m_epg_npgs - 1) + m->m_epg_last_len -
	    m->m_epg_1st_off);
}

/* New pages: a page each, wired, at an address no file page has. */
static struct vm_page *g_pg[WPAGES];
static bool g_pgfreed[WPAGES];
static int g_npg;
#define	NEWPA(i)	((vm_paddr_t)(1UL << 40) + ptoa(i))

vm_page_t
vm_page_alloc_noobj(int req)
{
	vm_page_t pg;

	__CPROVER_assert(g_npg < WPAGES, "model: pages allocated");
	pg = __CPROVER_allocate(sizeof(struct vm_page), 1);
	pg->phys_addr = NEWPA(g_npg);
	pg->ref_count = 1;
	g_pg[g_npg++] = pg;
	return (pg);
}

/* By arithmetic: a loop here, at each of its many calls, cost 3600 steps. */
static int
pgidx(vm_paddr_t pa)
{
	__CPROVER_assert(pa >= NEWPA(0) && pa < NEWPA(g_npg) &&
	    (pa & PAGE_MASK) == 0, "a page the worker allocated");
	return ((pa - NEWPA(0)) >> PAGE_SHIFT);
}

vm_page_t
PHYS_TO_VM_PAGE(vm_paddr_t pa)
{
	return (g_pg[pgidx(pa)]);
}

bool
vm_page_unwire_noq(vm_page_t pg)
{
	__CPROVER_assert(pg->ref_count == 1, "a new page is unwired once");
	pg->ref_count = 0;
	return (true);
}

void
vm_page_free(vm_page_t pg)
{
	int i = pgidx(pg->phys_addr);

	__CPROVER_assert(pg->ref_count == 0 && !g_pgfreed[i],
	    "a new page is freed once, unwired");
	g_pgfreed[i] = true;
}

/*
 * ktls_buffer_alloc() by its contract: no buffer for two pages or fewer,
 * else a contiguous one of kern.ipc.tls.maxlen bytes, or none.  run.sh
 * replaces calls to it: it reads the domain through %gs.
 */
void *
cbmc_ktls_buffer_alloc(struct ktls_wq *wq, struct mbuf *m)
{
	void *buf;

	if (m->m_epg_npgs <= 2 || nondet_bool())
		return (NULL);
	g_nbuf++;
	buf = __CPROVER_allocate(ktls_maxlen, 0);
	/* Pages of the direct map, as ktls_buffer_import() takes. */
	__CPROVER_assume((uintptr_t)buf < dmaplimit);
	return (buf);
}

static void
cbmc_uma_free(uma_zone_t zone, void *item)
{
	if (zone == ktls_buffer_zone)
		g_nbuffree++;
}

/* The asynchronous state, typed, as it is larger than the bucket. */
static void *
cbmc_malloc(size_t size, struct malloc_type *type, int flags)
{
	if (size != sizeof(struct ktls_ocf_encrypt_state))
		return (NULL);
	return (__CPROVER_allocate(size, (flags & M_ZERO) != 0));
}

/* The file's pages a sendfile(2) record holds, released. */
static void
cbmc_file_free(struct mbuf *m)
{
	g_srcfree[widx(m)]++;
}

/*
 * The socket's pr_ready(): what it is given is whole records of the
 * batch, encrypted, unready, and no longer holding a session.
 */
static int
cbmc_pr_ready(struct socket *so, struct mbuf *m, int count)
{
	int c, i, r;

	__CPROVER_assert(so == &g_so, "readies the socket's records");
	c = count;
	for (i = 0; i < WREC && c > 0; i++) {
		r = widx(m);
		__CPROVER_assert(g_enc[r] == 1 && g_ready[r] == 0 &&
		    g_freed[r] == 0, "readies a record encrypted, once");
		__CPROVER_assert((m->m_flags & (M_NOTREADY | M_RDONLY)) ==
		    (M_NOTREADY | M_RDONLY) && m->m_epg_tls == NULL &&
		    (m->m_epg_flags & EPG_FLAG_ANON) != 0,
		    "an encrypted record is read-only, anonymous, sessionless");
		g_ready[r] = 1;
		c -= m->m_epg_nrdy;
		m = m->m_next;
	}
	__CPROVER_assert(c == 0, "readies whole records");
	return (0);
}

void
cbmc_ktls_drop(struct socket *so, int error)
{
	__CPROVER_assert(so == &g_so && error == EIO,
	    "a failed encryption drops the connection with EIO");
	g_dropped++;
}

/* run.sh replaces calls to ktls_destroy(): never reached, it is large. */
void
cbmc_ktls_destroy(struct ktls_session *tls)
{
	__CPROVER_assert(0, "the socket keeps its session reference");
}

void
sorele_locked(struct socket *so)
{
	__CPROVER_assert(0, "the socket keeps its owner's reference");
}

/* mb_free_extpg(), kern_mbuf.c: the storage, then the session. */
void
mb_free_extpg(struct mbuf *m)
{
	int i, r = widx(m);

	__CPROVER_assert(g_freed[r] == 0, "a record is freed once");
	g_freed[r] = 1;
	if (m->m_ext.ext_free == cbmc_file_free)
		g_srcfree[r]++;
	else if (m->m_ext.ext_free == mb_free_mext_pgs) {
		for (i = 0; i < MBUF_PEXT_MAX_PGS; i++)
			if (i < m->m_epg_npgs &&
			    (m->m_epg_flags & EPG_FLAG_ANON) != 0 &&
			    m->m_epg_pa[i] >= NEWPA(0)) {
				(void)vm_page_unwire_noq(
				    PHYS_TO_VM_PAGE(m->m_epg_pa[i]));
				vm_page_free(PHYS_TO_VM_PAGE(m->m_epg_pa[i]));
			}
	} else {
		__CPROVER_assert(m->m_ext.ext_free == ktls_free_mext_contig,
		    "a record's pages have a free routine of theirs");
		g_nbuffree++;
	}
	if (m->m_epg_tls != NULL &&
	    !refcount_release_if_not_last(&m->m_epg_tls->refcount))
		__CPROVER_assert(0, "the socket keeps its session reference");
}

/* mb_free_notready(), kern_mbuf.c. */
void
mb_free_notready(struct mbuf *m, int count)
{
	int i;

	for (i = 0; i < WREC * MBUF_PEXT_MAX_PGS + 1 && i < count &&
	    m != NULL; i++) {
		if ((m->m_flags & M_EXTPG) != 0) {
			m->m_epg_nrdy--;
			if (m->m_epg_nrdy != 0)
				continue;
		}
		m = m_free(m);
	}
	__CPROVER_assert(i == count, "frees as many pages as asked");
}

int
ktls_ocf_encrypt(struct ktls_ocf_encrypt_state *state,
    struct ktls_session *tls, struct mbuf *m, struct iovec *outiov,
    int outiovcnt)
{
	uintptr_t base;
	int i, len, r = widx(m);

	__CPROVER_assert(g_enc[r] == 0, "each record is encrypted once");
	__CPROVER_assert(m->m_epg_tls == tls &&
	    (m->m_flags & M_NOTREADY) != 0,
	    "encrypts an unready record with its session");
	g_enc[r] = 1;
	if ((m->m_epg_flags & EPG_FLAG_ANON) != 0)
		__CPROVER_assert(outiov == NULL,
		    "anonymous pages are encrypted in place");
	else {
		__CPROVER_assert(outiov != NULL && outiovcnt >= 2 &&
		    outiov[outiovcnt - 1].iov_base == m->m_epg_trail &&
		    outiov[outiovcnt - 1].iov_len == m->m_epg_trllen,
		    "the output ends with the trailer");
		len = 0;
		for (i = 0; i < MBUF_PEXT_MAX_PGS; i++) {
			if (i >= outiovcnt - 1)
				break;
			base = (uintptr_t)outiov[i].iov_base;
			if (state->cbuf != NULL)
				__CPROVER_assert(outiovcnt == 2 &&
				    outiov[0].iov_base == (char *)state->cbuf +
				    m->m_epg_1st_off,
				    "into the buffer, at the payload's offset");
			else
				__CPROVER_assert(outiovcnt == m->m_epg_npgs + 1 &&
				    pgidx(state->parray[i]) == g_npg -
				    m->m_epg_npgs + i &&
				    base == state->parray[i] +
				    (i == 0 ? m->m_epg_1st_off : 0) &&
				    outiov[i].iov_len == m_epg_pagelen(m, i,
				    i == 0 ? m->m_epg_1st_off : 0),
				    "into new pages, each as the file page it "
				    "replaces");
			len += outiov[i].iov_len;
		}
		__CPROVER_assert(len == payload(m),
		    "the output holds the payload");
	}
	if (nondet_bool())
		return (nondet_bool() ? EIO : ENOMEM);
	if (!tls->sync_dispatch) {
		/*
		 * Its callback runs after the worker is done.  Running it
		 * at once instead changes nothing the worker reads: the
		 * callback touches its record, the socket's counts and a
		 * session reference, and the worker past this record only
		 * the records after it and the same counts.  Running it
		 * at both points doubled the proof, past 120G.
		 */
		__CPROVER_assert(state->m == m && state->so == &g_so,
		    "the callback gets its record and socket");
		g_deferred[g_ndeferred++] = state;
	}
	return (0);
}

/*
 * A batch of n records as ktls_enqueue() queued it: from sendfile(2),
 * file pages, from sosend(), anonymous ones, which an empty TLS 1.0
 * record has none of; each no more pages than a frame, holding a session
 * reference; the socket's reference donated with the batch.
 */
static struct ktls_session *
batch(bool sync)
{
	struct ktls_session *tls;
	struct mbuf *m;
	int i, n, total;

	setup();
	ktls_buffer_zone = (uma_zone_t)&g_buffer_zone;
	tls = sw_session(nondet_bool());
	tls->sync_dispatch = sync;
	g_proto.pr_ready = cbmc_pr_ready;
	g_so.so_proto = &g_proto;
	g_so.so_count = 2;
	n = nondet_int();
	__CPROVER_assume(n >= 1 && n <= WREC);
	g_wn = n;
	total = 0;
	for (i = 0; i <= n; i++) {
		m = __CPROVER_allocate(sizeof(struct mbuf), 1);
		m->m_flags = M_EXT | M_EXTPG | M_NOTREADY;
		m->m_ext.ext_flags = EXT_FLAG_EMBREF;
		m->m_ext.ext_count = 1;
		m->m_epg_tls = tls;
		tls->refcount++;
		m->m_epg_npgs = nondet_int();
		__CPROVER_assume(m->m_epg_npgs <= MBUF_PEXT_MAX_PGS &&
		    ptoa(m->m_epg_npgs) <= ktls_maxlen);
		if (nondet_bool()) {
			m->m_epg_flags = EPG_FLAG_ANON;
			m->m_ext.ext_free = mb_free_mext_pgs;
		} else {
			__CPROVER_assume(m->m_epg_npgs > 0);
			m->m_ext.ext_free = cbmc_file_free;
			if (i < n)
				g_file[i] = true;
		}
		m->m_epg_nrdy = m->m_epg_npgs == 0 ? 1 : m->m_epg_npgs;
		m->m_epg_1st_off = nondet_int();
		m->m_epg_last_len = nondet_int();
		__CPROVER_assume(m->m_epg_npgs == 0 ? m->m_epg_1st_off == 0 &&
		    m->m_epg_last_len == 0 :
		    m->m_epg_1st_off < PAGE_SIZE && m->m_epg_last_len > 0 &&
		    m->m_epg_last_len <= PAGE_SIZE &&
		    (m->m_epg_npgs > 1 ||
		    m->m_epg_1st_off + m->m_epg_last_len <= PAGE_SIZE));
		m->m_epg_hdrlen = nondet_int();
		m->m_epg_trllen = nondet_int();
		__CPROVER_assume(m->m_epg_hdrlen <= MBUF_PEXT_HDR_LEN &&
		    m->m_epg_trllen <= MBUF_PEXT_TRAIL_LEN);
		m->m_len = m->m_epg_hdrlen + payload(m) + m->m_epg_trllen;
		if (i < n)
			total += m->m_epg_nrdy;
		g_w[i] = m;
		if (i > 0)
			g_w[i - 1]->m_next = m;
	}
	g_w[0]->m_epg_enc_cnt = total;
	g_w[0]->m_epg_so = &g_so;
	return (tls);
}

/*
 * After the batch: encrypted and readied whole, or with the connection
 * dropped and all of it freed; every page the worker took either holds
 * an encrypted record or is freed; the file's pages are let go once;
 * the session and socket references the batch held are dropped; the
 * next record untouched.
 */
static void
check_batch(struct ktls_session *tls)
{
	int i, j, live, ok;
	struct mbuf *m;

	live = ok = 0;
	for (i = 0; i < WREC; i++) {
		if (i >= g_wn)
			break;
		__CPROVER_assert(g_ready[i] + g_freed[i] == 1,
		    "each record is readied or freed");
		ok += g_ready[i];
		if (g_freed[i] == 0) {
			m = g_w[i];
			__CPROVER_assert(m->m_ext.ext_free ==
			    mb_free_mext_pgs ||
			    m->m_ext.ext_free == ktls_free_mext_contig,
			    "a readied record frees its own pages");
		}
		__CPROVER_assert(g_srcfree[i] == (g_file[i] ? 1 : 0),
		    "the file's pages are let go once");
		if (g_freed[i] == 0 &&
		    g_w[i]->m_ext.ext_free == ktls_free_mext_contig)
			live++;
	}
	__CPROVER_assert(g_nbuf == g_nbuffree + live,
	    "a buffer holds a record or is freed");
	__CPROVER_assert(ok == g_wn || g_dropped == 1,
	    "a batch not readied whole drops the connection");
	__CPROVER_assert(g_dropped <= 1 || !tls->sync_dispatch,
	    "dropped once");
	for (j = 0; j < WPAGES; j++) {
		if (j >= g_npg)
			break;
		live = 0;
		for (i = 0; i < WREC; i++)
			if (i < g_wn && g_freed[i] == 0 &&
			    g_w[i]->m_ext.ext_free == mb_free_mext_pgs &&
			    g_w[i]->m_epg_npgs > 0 &&
			    g_w[i]->m_epg_pa[0] <= NEWPA(j) &&
			    NEWPA(j) < g_w[i]->m_epg_pa[0] +
			    ptoa(g_w[i]->m_epg_npgs))
				live = 1;
		__CPROVER_assert(live != g_pgfreed[j],
		    "a new page holds a record or is freed");
	}
	__CPROVER_assert(tls->refcount == 2,
	    "the session keeps the socket's and the next record's");
	__CPROVER_assert(g_so.so_count == 1,
	    "the socket keeps its owner's reference only");
	__CPROVER_assert((g_w[g_wn]->m_flags & M_NOTREADY) != 0 &&
	    g_w[g_wn]->m_epg_tls == tls, "the next record is untouched");
}

void
proof_encrypt(void)
{
	struct ktls_session *tls;

	tls = batch(true);
	ktls_encrypt(&g_wq, g_w[0]);
	check_batch(tls);
}

void
proof_encrypt_async(void)
{
	struct ktls_session *tls;
	int i;

	tls = batch(false);
	ktls_encrypt_async(&g_wq, g_w[0]);
	/* The requests still running complete. */
	for (i = 0; i < WREC; i++)
		if (i < g_ndeferred)
			ktls_encrypt_cb(g_deferred[i], nondet_bool() ? 0 : EIO);
	check_batch(tls);
}
