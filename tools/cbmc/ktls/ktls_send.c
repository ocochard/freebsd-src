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
 * cbmc(1) harness for the TLS branch of sosend_generic_locked(),
 * sys/kern/uipc_socket.c, built with KERN_TLS: how write(2), writev(2)
 * and sendmsg(2) on a socket with a TLS send session cut the user's
 * data into records, frame them and hand them to TCP and the KTLS
 * worker.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_socket.c or
 * a mutant of it, included whole.  ktls_frame() and ktls_enqueue(),
 * proven by ktls.c, m_uiotombuf() and TCP's pr_send are modelled by
 * what they are given and their contract.  The reference is ktls(4): a
 * TLS_SET_RECORD_TYPE control message carries one byte, the type of the
 * records of that send.  The one entry point, for --function:
 *
 *   proof_send		one send of up to NB bytes, with or without a
 *			control message, on a session in software or NIC
 *			mode: the record type read from the control
 *			message's byte only and for that send only; every
 *			chain cut from the user's data framed, and handed
 *			once to TCP, then to the worker, or freed; the
 *			control message freed once; the session and socket
 *			references balanced
 */

#include SOURCE

#include <sys/vnode.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include <sys/refcount.h>
#include <opencrypto/cryptodev.h>
#include "kern.h"

#ifndef NB
#define	NB	3	/* bytes the user sends */
#endif
#define	NC	(NB + 1)	/* chains: at most a byte each, or one empty */

/* The send lock, held by sosend_generic(). */
void _sx_assert(const struct sx *sx, int what, const char *file, int line) { }

static struct socket g_so;
static struct protosw g_proto;
static struct ktls_session g_tls;
static struct uio g_uio;
static struct mbuf *g_ctl;
static int g_ctlfreed, g_ctlsent;

/* Each chain cut from the user's data, and what became of it. */
#define	CH_LIVE		1
#define	CH_FREED	2
#define	CH_SENT		3	/* in the send buffer */
static struct mbuf *g_ch[NC];
static int g_chst[NC], g_chtype[NC], g_chframed[NC], g_chq[NC];
static int g_nch, g_nbytes, g_nenq, g_nwait;

static int
chain(struct mbuf *m)
{
	int i;

	for (i = 0; i < NC; i++)
		if (i < g_nch && g_ch[i] == m)
			return (i);
	__CPROVER_assert(0, "a chain cut from the user's data");
	return (0);
}

/*
 * m_uiotombuf(), uipc_mbuf.c: up to len bytes of the uio (all if len is
 * 0) into a chain of unmapped mbufs, one here, or NULL when a copy
 * faults, part of the uio then consumed.
 */
struct mbuf *
m_uiotombuf(struct uio *uio, int how, int len, int lspace, int flags)
{
	struct mbuf *m;
	ssize_t n;

	__CPROVER_assert(flags & M_EXTPG, "unmapped mbufs for TLS");
	__CPROVER_assert(lspace == g_tls.params.max_frame_len,
	    "records of at most the session's frame length");
	__CPROVER_assert(g_nch < NC, "model: chains");
	n = uio->uio_resid;
	if (len > 0 && n > len)
		n = len;
	if (nondet_bool()) {
		n = nondet_int();
		__CPROVER_assume(n >= 0 && n <= uio->uio_resid);
		uio->uio_resid -= n;
		return (NULL);
	}
	uio->uio_resid -= n;
	g_nbytes += n;
	m = __CPROVER_allocate(sizeof(struct mbuf), 1);
	m->m_flags = M_EXTPG | (flags & M_EOR);
	m->m_len = n;
	g_ch[g_nch] = m;
	g_chst[g_nch] = CH_LIVE;
	g_nch++;
	return (m);
}

/* ktls_frame(), uipc_ktls.c: frames the chain's records. */
void
ktls_frame(struct mbuf *top, struct ktls_session *tls, int *enq_cnt,
    uint8_t record_type)
{
	int c = chain(top);

	__CPROVER_assert(tls == &g_tls, "the socket's session");
	__CPROVER_assert(g_chst[c] == CH_LIVE && !g_chframed[c],
	    "a chain framed once, before it is sent");
	g_chframed[c] = 1;
	g_chtype[c] = record_type;
	*enq_cnt = nondet_int();
	__CPROVER_assume(*enq_cnt >= 1 && *enq_cnt <= 2);
	g_chq[c] = *enq_cnt;
}

/* ktls_enqueue(), uipc_ktls.c: the worker takes the chain to encrypt. */
void
ktls_enqueue(struct mbuf *m, struct socket *so, int page_count)
{
	int c = chain(m);

	__CPROVER_assert(g_tls.mode == TCP_TLS_MODE_SW,
	    "only software sessions queue records");
	__CPROVER_assert(g_chst[c] == CH_SENT && so == &g_so,
	    "the worker gets a chain TCP holds, with its socket");
	__CPROVER_assert(page_count == g_chq[c],
	    "with the pages ktls_frame() counted");
	g_nenq++;
}

void
ktls_destroy(struct ktls_session *tls)
{
	__CPROVER_assert(0, "the socket's session outlives the send");
}

bool
ktls_permit_empty_frames(struct ktls_session *tls)
{
	return (tls->params.cipher_algorithm == CRYPTO_AES_CBC &&
	    tls->params.tls_vminor == TLS_MINOR_VER_ZERO);
}

/* m_freem(), kern_mbuf.c, on a chain or the control message. */
void
m_freem(struct mbuf *m)
{
	int c;

	if (m == NULL)
		return;
	if (m == g_ctl) {
		__CPROVER_assert(!g_ctlfreed && !g_ctlsent,
		    "the control message freed once, not sent");
		g_ctlfreed = 1;
		return;
	}
	c = chain(m);
	__CPROVER_assert(g_chst[c] == CH_LIVE, "a chain freed once, not sent");
	g_chst[c] = CH_FREED;
}

/* sbwait(), uipc_sockbuf.c: room is made, or a signal comes. */
int
sbwait(struct socket *so, sb_which which)
{
	__CPROVER_assume(g_nwait < 1);
	g_nwait++;
	so->so_snd.sb_ccc = 0;
	so->so_snd.sb_mbcnt = 0;
	return (nondet_bool() ? 0 : EINTR);
}

/*
 * tcp_usr_send(), for a connected socket: the data goes to the send
 * buffer, not ready when the session encrypts in software, or an error
 * comes before.  The control message is TCP's, freed; data not taken is
 * freed too, unless not ready: then the caller frees it.
 */
int
cbmc_pr_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *nam, struct mbuf *control, struct thread *td)
{
	int c, error;

	c = chain(m);
	__CPROVER_assert(g_chst[c] == CH_LIVE && g_chframed[c],
	    "a chain sent is framed, sent once");
	__CPROVER_assert(((flags & PRUS_NOTREADY) != 0) ==
	    (g_tls.mode == TCP_TLS_MODE_SW),
	    "not ready only for software encryption");
	if (control != NULL) {
		__CPROVER_assert(control == g_ctl && !g_ctlfreed,
		    "the control message sent once");
		g_ctlsent = 1;
	}
	error = control != NULL && control->m_len > 0 ? EINVAL :
	    (nondet_bool() ? 0 : ECONNRESET);
	if (error == 0)
		g_chst[c] = CH_SENT;
	else if ((flags & PRUS_NOTREADY) == 0)
		g_chst[c] = CH_FREED;
	return (error);
}

/*
 * A control message of clen bytes, exactly, as sockargs() copies it in
 * from the user: any header and payload.
 */
static struct mbuf *
control(int clen)
{
	struct mbuf *m;

	m = __CPROVER_allocate(sizeof(struct mbuf), 1);
	m->m_data = __CPROVER_allocate(clen, 0);
	m->m_len = clen;
	m->m_next = NULL;
	return (m);
}

void
proof_send(void)
{
	struct socket *so = &g_so;
	struct ktls_session *tls = &g_tls;
	struct cmsghdr *cm;
	int clen, error, flags, i, ref, resid, rtype, settype, soref0;

	so->so_proto = &g_proto;
	so->so_type = SOCK_STREAM;
	so->so_state = SS_ISCONNECTED | (nondet_bool() ? SS_NBIO : 0);
	so->so_error = 0;
	so->so_snd.sb_state = 0;
	so->so_snd.sb_hiwat = nondet_int();
	__CPROVER_assume(so->so_snd.sb_hiwat >= 0 &&
	    so->so_snd.sb_hiwat <= NB + 1);
	so->so_snd.sb_mbmax = 8 * (NB + 1);
	so->so_snd.sb_lowat = nondet_int();
	__CPROVER_assume(so->so_snd.sb_lowat >= 0 &&
	    so->so_snd.sb_lowat <= NB + 1);
	so->so_snd.sb_ccc = nondet_int();
	__CPROVER_assume(so->so_snd.sb_ccc <= NB + 1);
	so->so_snd.sb_mbcnt = 0;
	so->so_count = soref0 = 1;
	g_proto.pr_flags = PR_CONNREQUIRED;
	g_proto.pr_send = cbmc_pr_send;

	tls->mode = nondet_bool() ? TCP_TLS_MODE_SW : TCP_TLS_MODE_IFNET;
	tls->params.cipher_algorithm = nondet_bool() ? CRYPTO_AES_CBC :
	    CRYPTO_AES_NIST_GCM_16;
	tls->params.tls_vminor = nondet_bool() ? TLS_MINOR_VER_ZERO :
	    TLS_MINOR_VER_TWO;
	tls->params.max_frame_len = TLS_MAX_MSG_SIZE_V10_2;
	tls->refcount = ref = 1;
	so->so_snd.sb_tls_info = tls;

	g_uio.uio_resid = nondet_int();
	__CPROVER_assume(g_uio.uio_resid >= 0 && g_uio.uio_resid <= NB);
	resid = g_uio.uio_resid;

	/*
	 * A control message, maybe: a cmsghdr, then maybe its byte.  Its
	 * level and length fields are not checked: ktls(4) names neither.
	 */
	g_ctl = NULL;
	settype = 0;
	rtype = TLS_RLTYPE_APP;
	if (nondet_bool()) {
		clen = nondet_int();
		__CPROVER_assume(clen >= sizeof(struct cmsghdr) &&
		    clen <= CMSG_SPACE(1));
		g_ctl = control(clen);
		cm = mtod(g_ctl, struct cmsghdr *);
		if (cm->cmsg_type == TLS_SET_RECORD_TYPE) {
			if (clen >= CMSG_LEN(1)) {
				settype = 1;
				rtype = *(uint8_t *)CMSG_DATA(cm);
			} else
				settype = -1;	/* no byte: ktls(4) silent */
		}
	}
	flags = nondet_bool() ? MSG_DONTWAIT : 0;

	error = sosend_generic_locked(so, NULL, &g_uio, NULL, g_ctl, flags,
	    NULL);

	__CPROVER_assert(tls->refcount == ref,
	    "the send holds the session for its duration");
	if (resid == 0 && !ktls_permit_empty_frames(tls))
		__CPROVER_assert(error == EINVAL,
		    "an empty write is refused unless TLS 1.0 CBC allows it");
	for (i = 0; i < NC; i++) {
		if (i >= g_nch)
			break;
		__CPROVER_assert(g_chst[i] != CH_LIVE,
		    "every chain is sent or freed");
		__CPROVER_assert(g_chst[i] != CH_FREED || error != 0,
		    "a chain is freed only on an error");
		if (settype == 1)
			__CPROVER_assert(g_chtype[i] == (i == 0 ? rtype :
			    TLS_RLTYPE_APP),
			    "the record type from the control message, for "
			    "its send only");
		else if (settype == 0)
			__CPROVER_assert(g_chtype[i] == TLS_RLTYPE_APP,
			    "application data otherwise");
	}
	__CPROVER_assert(g_ctl == NULL || g_ctlfreed || g_ctlsent,
	    "the control message is freed or sent");
	if (tls->mode == TCP_TLS_MODE_SW) {
		int nsent = 0;

		for (i = 0; i < NC; i++)
			if (i < g_nch && g_chst[i] == CH_SENT)
				nsent++;
		__CPROVER_assert(g_nenq == nsent &&
		    so->so_count == soref0 + nsent,
		    "each chain TCP takes goes to the worker, with a socket "
		    "reference");
	} else
		__CPROVER_assert(g_nenq == 0 && so->so_count == soref0,
		    "NIC sessions queue nothing");
	__CPROVER_assert(error != 0 || g_uio.uio_resid == 0,
	    "a send that succeeds sends all");
}
