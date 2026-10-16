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
 * cbmc(1) harness for setsockopt(2) TCP_TXTLS_ENABLE and TCP_RXTLS_ENABLE,
 * sys/kern/uipc_ktls.c, built with KERN_TLS: ktls_copyin_tls_enable(),
 * which copies a process's struct tls_enable and its keys in, then
 * ktls_enable_tx() and ktls_enable_rx(), which give the socket a session.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_ktls.c or a
 * mutant of it, included whole.  ktls_create_session() and
 * ktls_try_ifnet(), proven by ktls.c, are modelled by their contract, as
 * run.sh replaces their calls; so are ktls_check_rx() and
 * ktls_destroy().  The references: tcp_setsockopt(), which frees the
 * copied keys after a successful copy only; ktls(4); and 1000cc4a0d39,
 * which refuses a session on a spliced socket with EINVAL.  The entry
 * points, for --function:
 *
 *   proof_copyin	ktls_copyin_tls_enable() on an option of any size,
 *			from a process or the kernel, any lengths and key
 *			pointers: a key the length given in a kernel buffer
 *			holding the process's bytes, or the error and
 *			nothing allocated
 *   proof_enable_tx	ktls_enable_tx() and ktls_enable_rx() on a TCP
 *   proof_enable_rx	socket or another, with a session or not, spliced or
 *			not, racing another enable: the session installed
 *			with its sequence number, or the error ktls(4) and
 *			1000cc4a0d39 give with the session freed and the
 *			socket left as it was
 */

#include SOURCE

#include <sys/vnode.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/refcount.h>

/* What malloc(9) gives and zfree(9) takes back: counted, for leaks. */
static int g_nalloc;
static void *cbmc_kmalloc(size_t size, struct malloc_type *type, int flags);
#define	CBMC_MALLOC_HOOK	cbmc_kmalloc
#include "kern.h"

void
zfree(void *addr, struct malloc_type *mtp)
{
	if (addr != NULL)
		g_nalloc--;
	free(addr, mtp);
}

static void *
cbmc_kmalloc(size_t size, struct malloc_type *type, int flags)
{
	g_nalloc++;
	return (__CPROVER_allocate(size, 0));
}

static int g_optfault;		/* the option itself faulted */
static union tls_option {
	struct tls_enable en;
	struct tls_enable_v0 v0;
	char more[sizeof(struct tls_enable) + 8];	/* a larger option */
} g_uopt;

/* copyin(9): the process's bytes, or EFAULT where it maps none. */
int
cbmc_copyin(const void *udaddr, void *kaddr, size_t len)
{
	if (!__CPROVER_r_ok(udaddr, len) || nondet_bool()) {
		if (udaddr == &g_uopt)
			g_optfault = 1;
		return (EFAULT);
	}
	memcpy(kaddr, udaddr, len);
	return (0);
}

/* sooptcopyin(), uipc_socket.c. */
int
sooptcopyin(struct sockopt *sopt, void *buf, size_t len, size_t minlen)
{
	size_t valsize;

	if ((valsize = sopt->sopt_valsize) < minlen)
		return (EINVAL);
	if (valsize > len)
		sopt->sopt_valsize = valsize = len;
	if (sopt->sopt_td != NULL)
		return (copyin(sopt->sopt_val, buf, valsize));
	memcpy(buf, sopt->sopt_val, valsize);
	return (0);
}

/* A process's option and keys. */
#define	KL	4		/* key bytes, at most, in the model */
static uint8_t g_ukey[KL], g_uiv[KL], g_uauth[KL];

static const uint8_t *
user_ptr(uint8_t *buf)
{
	switch (nondet_int()) {
	case 0:
		return (NULL);
	case 1:
		return (buf + 1);	/* one byte short of KL */
	default:
		return (buf);
	}
}

/* Any length: past its bound, or one the buffers hold. */
static int
bounded(int max)
{
	int len = nondet_int();

	__CPROVER_assume(len <= KL || len > max);
	return (len);
}
#define	IVMAX	sizeof(((struct ktls_session *)NULL)->params.iv)

static int
same(const uint8_t *k, const uint8_t *u, int len)
{
	int i;

	for (i = 0; i < 8; i++)
		if (i < len && k[i] != u[i])
			return (0);
	return (1);
}

void
proof_copyin(void)
{
	struct sockopt sopt;
	struct tls_enable en, *u = &g_uopt.en;
	struct tls_enable_v0 *u0 = &g_uopt.v0;
	int alen, error, i, ilen, klen, ktd, v0;

	__CPROVER_havoc_object(&g_uopt);
	memset(&sopt, 0, sizeof(sopt));
	sopt.sopt_val = &g_uopt;
	sopt.sopt_valsize = nondet_int();
	__CPROVER_assume(sopt.sopt_valsize <= sizeof(g_uopt));
	sopt.sopt_td = nondet_bool() ? curthread : NULL;
	v0 = sopt.sopt_valsize == sizeof(struct tls_enable_v0);
	/* A kernel caller passes its own keys, a process any pointer. */
	ktd = sopt.sopt_td == NULL;
	if (v0) {
		u0->cipher_key = ktd ? g_ukey : user_ptr(g_ukey);
		u0->iv = ktd ? g_uiv : user_ptr(g_uiv);
		u0->auth_key = ktd ? g_uauth : user_ptr(g_uauth);
		u0->cipher_key_len = bounded(TLS_MAX_PARAM_SIZE);
		u0->iv_len = bounded(IVMAX);
		u0->auth_key_len = bounded(TLS_MAX_PARAM_SIZE);
	} else {
		u->cipher_key = ktd ? g_ukey : user_ptr(g_ukey);
		u->iv = ktd ? g_uiv : user_ptr(g_uiv);
		u->auth_key = ktd ? g_uauth : user_ptr(g_uauth);
		u->cipher_key_len = bounded(TLS_MAX_PARAM_SIZE);
		u->iv_len = bounded(IVMAX);
		u->auth_key_len = bounded(TLS_MAX_PARAM_SIZE);
	}

	error = ktls_copyin_tls_enable(&sopt, &en);

	klen = v0 ? u0->cipher_key_len : u->cipher_key_len;
	ilen = v0 ? u0->iv_len : u->iv_len;
	alen = v0 ? u0->auth_key_len : u->auth_key_len;
	if (sopt.sopt_valsize >= sizeof(en) || v0)
		if (klen <= 0 || klen > TLS_MAX_PARAM_SIZE || ilen < 0 ||
		    ilen > IVMAX || alen < 0 || alen > TLS_MAX_PARAM_SIZE)
			__CPROVER_assert(error == EINVAL ||
			    (error == EFAULT && g_optfault),
			    "a length past its bound, or no cipher key, is "
			    "refused");
	if (error != 0) {
		__CPROVER_assert(g_nalloc == 0,
		    "on an error nothing is left for the caller to free");
		return;
	}
	__CPROVER_assert(v0 || sopt.sopt_valsize == sizeof(en),
	    "the option is a struct tls_enable or the old one");
	__CPROVER_assert(en.cipher_key_len > 0 &&
	    en.cipher_key_len <= TLS_MAX_PARAM_SIZE &&
	    en.auth_key_len >= 0 && en.auth_key_len <= TLS_MAX_PARAM_SIZE &&
	    en.iv_len >= 0 && en.iv_len <=
	    sizeof(((struct ktls_session *)NULL)->params.iv),
	    "lengths in their bounds, a cipher key");
	__CPROVER_assert(__CPROVER_r_ok(en.cipher_key, en.cipher_key_len) &&
	    __CPROVER_POINTER_OFFSET(en.cipher_key) == 0 &&
	    __CPROVER_OBJECT_SIZE(en.cipher_key) == en.cipher_key_len &&
	    same(en.cipher_key, v0 ? u0->cipher_key : u->cipher_key,
	    en.cipher_key_len),
	    "the cipher key in a kernel buffer of its length, the process's");
	__CPROVER_assert(en.iv_len == 0 ? en.iv == NULL :
	    __CPROVER_OBJECT_SIZE(en.iv) == en.iv_len &&
	    __CPROVER_POINTER_OFFSET(en.iv) == 0 &&
	    same(en.iv, v0 ? u0->iv : u->iv, en.iv_len),
	    "the IV in a kernel buffer of its length, or none");
	__CPROVER_assert(en.auth_key_len == 0 ? en.auth_key == NULL :
	    __CPROVER_OBJECT_SIZE(en.auth_key) == en.auth_key_len &&
	    __CPROVER_POINTER_OFFSET(en.auth_key) == 0 &&
	    same(en.auth_key, v0 ? u0->auth_key : u->auth_key,
	    en.auth_key_len),
	    "the MAC key in a kernel buffer of its length, or none");
	__CPROVER_assert(g_nalloc == (en.cipher_key_len != 0) +
	    (en.iv_len != 0) + (en.auth_key_len != 0),
	    "no buffer but the three");
	if (v0) {
		for (i = 0; i < 8; i++)
			__CPROVER_assert(en.rec_seq[i] == 0,
			    "the old option starts at sequence number 0");
		__CPROVER_assert(en.cipher_algorithm ==
		    u0->cipher_algorithm && en.auth_algorithm ==
		    u0->auth_algorithm && en.flags == u0->flags &&
		    en.tls_vmajor == u0->tls_vmajor &&
		    en.tls_vminor == u0->tls_vminor,
		    "the old option's fields kept");
	} else
		__CPROVER_assert(en.cipher_algorithm == u->cipher_algorithm &&
		    en.auth_algorithm == u->auth_algorithm &&
		    en.flags == u->flags && en.tls_vmajor == u->tls_vmajor &&
		    en.tls_vminor == u->tls_vminor &&
		    same(en.rec_seq, u->rec_seq, 8),
		    "the option's fields kept");
	ktls_cleanup_tls_enable(&en);
	__CPROVER_assert(g_nalloc == 0, "the caller's cleanup frees them");
}

/*
 * The socket, its session if any, and the one ktls_create_session()
 * gives.
 */
static struct socket g_so;
static struct protosw g_proto;
static struct tcpcb g_tp;
static struct tcp_function_block g_fb;
static struct ktls_session g_new, g_old, g_other;
static int g_gotlock, g_created, g_destroyed, g_ionlock, g_checked, g_marked, g_hwtls;
static bool g_inpwl;
static int g_dir;

/* ktls_create_session(): a session with a reference, or an error. */
int
cbmc_ktls_create_session(struct socket *so, struct tls_enable *en,
    struct ktls_session **tlsp, int direction)
{
	__CPROVER_assert(direction == g_dir, "a session for its direction");
	if (nondet_bool())
		return (nondet_bool() ? EINVAL : EPROTONOSUPPORT);
	g_new.refcount = 1;
	g_new.mode = TCP_TLS_MODE_NONE;
	*tlsp = &g_new;
	g_created = 1;
	return (0);
}

/* ktls_try_ifnet(): offloaded to the NIC, or not. */
int
cbmc_ktls_try_ifnet(struct socket *so, struct ktls_session *tls,
    int direction, bool force)
{
	__CPROVER_assert(tls == &g_new && !force,
	    "the new session, offloaded where it can");
	if (nondet_bool())
		return (EOPNOTSUPP);
	tls->mode = TCP_TLS_MODE_IFNET;
	return (0);
}

static int g_ocf_err;

int
ktls_ocf_try(struct ktls_session *tls, int direction)
{
	return (g_ocf_err);
}

void
cbmc_ktls_destroy(struct ktls_session *tls)
{
	__CPROVER_assert(tls == &g_new && tls->refcount == 0 &&
	    !g_destroyed, "the new session freed once, its last reference");
	g_destroyed = 1;
}

void
cbmc_ktls_check_rx(struct sockbuf *sb)
{
	__CPROVER_assert(sb == &g_so.so_rcv && sb->sb_tls_info == &g_new,
	    "the receive buffer checked, with its session");
	g_checked++;
}

void
cbmc_sb_mark_notready(struct sockbuf *sb)
{
	__CPROVER_assert(sb == &g_so.so_rcv && sb->sb_tls_info == &g_new,
	    "data already in marked for decryption");
	g_marked++;
}

/*
 * The I/O lock: interrupted, or had; while waiting for it, another
 * enable may win, or a splice.
 */
int
soiolock(struct socket *so, struct sx *sx, int flags)
{
	struct sockbuf *sb;

	__CPROVER_assert(!g_inpwl, "sleeps for the I/O lock unlocked");
	if (nondet_bool())
		return (EINTR);
	sb = g_dir == KTLS_TX ? &so->so_snd : &so->so_rcv;
	if (nondet_bool())
		sb->sb_tls_info = &g_other;
	if (nondet_bool())
		sb->sb_flags |= SB_SPLICED;
	g_ionlock++;
	g_gotlock = 1;
	return (0);
}

void
soiounlock(struct sx *sx)
{
	__CPROVER_assert(g_ionlock == 1, "the I/O lock released when had");
	g_ionlock--;
}

void
_rw_wlock_cookie(volatile uintptr_t *c, const char *file, int line)
{
	__CPROVER_assert(!g_inpwl, "the inpcb is not write-locked twice");
	g_inpwl = true;
}

void
_rw_wunlock_cookie(volatile uintptr_t *c, const char *file, int line)
{
	__CPROVER_assert(g_inpwl, "the inpcb is write-unlocked when held");
	g_inpwl = false;
}

static void
cbmc_hwtls_change(struct tcpcb *tp, int on)
{
	__CPROVER_assert(tp == &g_tp && on == 1 && g_inpwl,
	    "the stack told of NIC offload, the inpcb locked");
	g_hwtls++;
}

static struct sockbuf *
enable_setup(int dir, struct tls_enable *en)
{
	struct sockbuf *sb;
	int i;

	g_dir = dir;
	g_so.so_proto = &g_proto;
	g_proto.pr_protocol = nondet_bool() ? IPPROTO_TCP : IPPROTO_UDP;
	g_so.so_pcb = &g_tp.t_inpcb;
	g_tp.t_fb = &g_fb;
	g_tp.t_nic_ktls_xmit = 0;
	g_fb.tfb_hwtls_change = nondet_bool() ? cbmc_hwtls_change : NULL;
	ktls_offload_enable = nondet_bool();
	ktls_rx_offload_enable = nondet_bool();
	mb_use_ext_pgs = nondet_bool();
	ktls_offload_enable_calls = counter_u64_alloc(M_WAITOK);
	ktls_offload_total = counter_u64_alloc(M_WAITOK);
	ktls_sw_cbc = ktls_sw_gcm = ktls_sw_chacha20 =
	    counter_u64_alloc(M_WAITOK);
	g_ocf_err = nondet_bool() ? 0 : EPROTONOSUPPORT;
	sb = dir == KTLS_TX ? &g_so.so_snd : &g_so.so_rcv;
	sb->sb_tls_info = nondet_bool() ? &g_old : NULL;
	sb->sb_flags = nondet_bool() ? SB_SPLICED : 0;
	sb->sb_tls_seqno = 0;
	memset(en, 0, sizeof(*en));
	for (i = 0; i < 8; i++)
		en->rec_seq[i] = nondet_int();
	return (sb);
}

/*
 * What both directions promise: refused while offload is off (ENOTSUP),
 * on other than TCP (EINVAL), on a socket with a session (EALREADY), on
 * a spliced one (EINVAL), with the error of the session or the lock;
 * then the session freed and the socket left as it was; or the new
 * session installed, the buffer's sequence number the option's.
 */
static void
check_enable(int error, struct sockbuf *sb, struct ktls_session *was,
    int wasflags, bool off, struct tls_enable *en)
{
	__CPROVER_assert(g_ionlock == 0 && !g_inpwl,
	    "the I/O lock and the inpcb released");
	if (off)
		__CPROVER_assert(error == ENOTSUP && !g_created,
		    "refused while offload is off");
	else if (g_proto.pr_protocol != IPPROTO_TCP)
		__CPROVER_assert(error == EINVAL && !g_created,
		    "refused on other than TCP");
	else if (was != NULL)
		__CPROVER_assert(error == EALREADY && !g_created,
		    "refused on a socket with a session");
	if (error != 0) {
		__CPROVER_assert(!g_created || g_destroyed,
		    "on an error, the session is freed");
		__CPROVER_assert(sb->sb_tls_info != &g_new,
		    "nor installed");
		if (g_gotlock && sb->sb_tls_info == &g_other)
			__CPROVER_assert(error == EALREADY,
			    "refused if another enable won");
		else if (g_gotlock && (sb->sb_flags & SB_SPLICED) != 0)
			__CPROVER_assert(error == EINVAL,
			    "refused on a spliced socket (1000cc4a0d39)");
		return;
	}
	__CPROVER_assert(g_created && !g_destroyed &&
	    sb->sb_tls_info == &g_new && g_new.refcount == 1,
	    "the new session installed, the buffer's reference");
	__CPROVER_assert(sb->sb_tls_seqno == be64dec(en->rec_seq),
	    "at the option's sequence number");
	__CPROVER_assert(g_new.mode == TCP_TLS_MODE_SW ||
	    g_new.mode == TCP_TLS_MODE_IFNET, "in software or on the NIC");
	__CPROVER_assert((wasflags & SB_SPLICED) == 0,
	    "never on a spliced socket");
}

void
proof_enable_tx(void)
{
	struct tls_enable en;
	struct sockbuf *sb;
	struct ktls_session *was;
	int error, flags;
	bool off;

	sb = enable_setup(KTLS_TX, &en);
	was = sb->sb_tls_info;
	flags = sb->sb_flags;
	off = !ktls_offload_enable;

	error = ktls_enable_tx(&g_so, &en);

	if (!off && g_proto.pr_protocol == IPPROTO_TCP && was == NULL &&
	    !mb_use_ext_pgs)
		__CPROVER_assert(error == ENXIO && !g_created,
		    "refused without unmapped mbufs");
	check_enable(error, sb, was, flags, off, &en);
	if (error == 0)
		__CPROVER_assert(g_new.mode == TCP_TLS_MODE_SW ?
		    g_tp.t_nic_ktls_xmit == 0 && g_hwtls == 0 :
		    g_tp.t_nic_ktls_xmit == 1 &&
		    g_hwtls == (g_fb.tfb_hwtls_change != NULL),
		    "the stack told of NIC offload, only");
}

void
proof_enable_rx(void)
{
	struct tls_enable en;
	struct sockbuf *sb;
	struct ktls_session *was;
	int error, flags;
	bool off;

	sb = enable_setup(KTLS_RX, &en);
	was = sb->sb_tls_info;
	flags = sb->sb_flags;
	off = !ktls_offload_enable || !ktls_rx_offload_enable;

	error = ktls_enable_rx(&g_so, &en);

	check_enable(error, sb, was, flags, off, &en);
	if (error == 0)
		__CPROVER_assert((sb->sb_flags & SB_TLS_RX) != 0 &&
		    g_marked == 1 && g_checked == 1,
		    "the buffer receives TLS, its data marked and checked");
	else
		__CPROVER_assert(g_marked == 0 && g_checked == 0 &&
		    (sb->sb_flags & SB_TLS_RX) == 0,
		    "or left as it was");
}
