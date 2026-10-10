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
 * cbmc(1) harness for sendfile(2), sys/kern/kern_sendfile.c.
 *
 * Not a program: run.sh compiles it with SOURCE naming kern_sendfile.c or
 * a mutant of it, which is included whole, so the code proven is the
 * kernel's own, static functions included.  The reference is the manual
 * page, lib/libsys/sendfile.2.  Each proof is an entry point for
 * --function:
 *
 *   proof_xfsize	the per-page split of a run: the pages hold exactly
 *			the bytes of the run, each inside its page
 *   proof_fixspace	trimming a run at its first missing page keeps
 *			exactly the bytes of the pages before it
 *   proof_noloop	vn_sendfile() when it queues no page of the file,
 *			against the manual page
 *   proof_send		vn_sendfile() on a cached regular file and a
 *			blocking stream socket, against the manual page
 *   proof_read		the same with pages partly valid or not at all,
 *			which the pager reads
 *   proof_send_extpg	proof_send, proof_read and proof_nodiskio with
 *   proof_read_extpg	unmapped mbufs (mb_use_ext_pgs), what TCP uses
 *   proof_nodiskio_extpg on amd64
 *   proof_resize	proof_send with the file truncated or extended
 *			during the call
 *   proof_nodiskio	the same with SF_NODISKIO, pages partly valid but
 *			none needing a read, and grabs that can stop
 *			short: only bytes read from the file are sent
 *
 * The vn_sendfile() proofs watch the socket through the protocol's
 * pr_send() and through kern_filewrite(), which record the byte stream:
 * header bytes, then file bytes in file order from the offset, then
 * trailer bytes.  A file byte is identified by its page and its offset in
 * it, so a byte that is sent twice, skipped, or sent from a page that was
 * never read is caught where it is queued, and so is a chain longer than
 * the room the socket reported.
 *
 * The bounds are lengths: a file of at most MAXFILE bytes, a header and a
 * trailer of at most MAXHDR, a socket that reports between MINSPACE and
 * MAXSPACE bytes of room per wait, and MAXWAITS iterations of the send
 * loop, which run.sh picks so that they are enough.  The offset is free up
 * to past the end of the file and nbytes over all of size_t, which is
 * where the arithmetic goes wrong.
 */

#include SOURCE

static void *sfio_malloc(size_t, struct malloc_type *, int);
#define	CBMC_MALLOC_HOOK	sfio_malloc
static void resize(volatile uintptr_t *);
#define	CBMC_RW_RLOCK_HOOK	resize
#include "kern.h"

#ifndef MAXFILE
#define	MAXFILE		(2 * PAGE_SIZE + 1)
#endif
#ifndef MAXHDR
#define	MAXHDR		8
#endif
#ifndef MINSPACE
#define	MINSPACE	(PAGE_SIZE / 2)
#endif
#ifndef MAXSPACE
#define	MAXSPACE	(2 * PAGE_SIZE)
#endif

#ifndef MAXWAITS
#define	MAXWAITS	1	/* send loop iterations */
#endif

#define	NPAGES		(howmany(MAXFILE, PAGE_SIZE) + 1)

/* The file: its pages, in a page cache that may hold some of them. */
static struct vm_object	g_obj;
static struct vnode	g_vnode;
static struct vop_vector g_vop;
static struct file	g_fp;
/*
 * One object per page rather than an array of them: cbmc turns a pointer
 * into an array of structures into an index by dividing its offset by
 * the structure's size, 104 bytes, and those divisions were most of the
 * formula.
 */
static vm_page_t	g_pages[NPAGES];
static struct vm_page	g_bogus;
static char		g_data[NPAGES * PAGE_SIZE];	/* the pages' bytes */
vm_page_t bogus_page = &g_bogus;
static bool		g_nowait_fails;	/* SF_NODISKIO may grab short */
static bool		g_noloop;	/* the send loop is not entered */
static bool		g_cached;	/* every page is cached and valid */
static bool		g_noio;		/* no page needs reading */
static bool		g_resize;	/* the file size may change */
static bool		g_resized;	/* and it did */
static off_t		g_size_max;	/* the largest size it had */

/* The socket. */
static struct protosw	g_proto;
static struct socket	g_so;
static struct file	g_sock_fp;
#define	g_td		cbmc_thread

/* The byte stream the socket received, see above. */
static size_t		g_hdr_seen;
static off_t		g_file_next;
static off_t		g_file_seen;
static size_t		g_trl_seen;
static int		g_phase;	/* 0 header, 1 file, 2 trailer */
static int		g_room;		/* room the last wait reported */
static int		g_waits;	/* send loop iterations so far */
static struct uio	*g_hdr_uio;
static struct mbuf	*g_pending;	/* chain queued not ready */
static bool		g_short;	/* a write stopped short, returning 0 */


static vm_page_bits_t
page_bits(int base, int size)
{
	if (size == 0)
		return (0);
	return (((vm_page_bits_t)2 << ((base + size - 1) >> DEV_BSHIFT)) -
	    ((vm_page_bits_t)1 << (base >> DEV_BSHIFT)));
}

/*
 * An sf_io, typed: allocated as sizeof(struct sf_io) plus room for the
 * page pointers, which cbmc reads as the structure with its flexible
 * array sized.  A generic block would hold its fields as untyped words,
 * and cbmc could then tell neither sfio->so nor pa[i] from any pointer,
 * which sent an indirect call through sfio->so to every function of a
 * matching type.  The pointers start as INVARIANTS junk, see malloc().
 */
#define	SFIO_PAGES	(NPAGES + 1)

static void *
sfio_malloc(size_t size, struct malloc_type *type, int flags)
{
	struct sf_io *sfio;

	if (type != M_SENDFILE)
		return (NULL);
	__CPROVER_assert(size <= sizeof(struct sf_io) +
	    SFIO_PAGES * sizeof(vm_page_t), "model: sf_io fits");
	sfio = __CPROVER_allocate(sizeof(struct sf_io) +
	    SFIO_PAGES * sizeof(vm_page_t), 0);
	for (int i = 0; i < SFIO_PAGES; i++)
		sfio->pa[i] = (vm_page_t)0xdeadc0dedeadc0deUL;
	return (sfio);
}

/*
 * proof_resize: another thread truncating or extending the file, which
 * changes the pager's size, vnp_size, under the object lock.  Each time
 * vn_sendfile() takes that lock to read the size, the size may have
 * changed to any length the bounds allow.  The pages stay as they were:
 * truncation would free the ones past the end, but sendfile has them
 * wired.
 */
static void
resize(volatile uintptr_t *c)
{
	off_t size;

	if (!g_resize || c != &g_obj.lock.rw_lock || nondet_bool())
		return;
	size = nondet_off_t();
	__CPROVER_assume(size >= 0 && size <= MAXFILE);
	if (size != g_obj.un_pager.vnp.vnp_size)
		g_resized = true;
	g_obj.un_pager.vnp.vnp_size = size;
	if (size > g_size_max)
		g_size_max = size;
}

/* VM model. */

int
vm_page_grab_pages_unlocked(vm_object_t object, vm_pindex_t pindex,
    int allocflags, vm_page_t *ma, int count)
{
	int grabbed;

	__CPROVER_assert(object == &g_obj, "grabs from the file");
	__CPROVER_assert(count >= 0 && pindex + count <= NPAGES,
	    "grabs only pages of the file");
	grabbed = count;
	if ((allocflags & VM_ALLOC_NOWAIT) != 0 && g_nowait_fails) {
		grabbed = nondet_int();
		__CPROVER_assume(grabbed >= 0 && grabbed <= count);
	}
	for (int i = 0; i < grabbed; i++) {
		ma[i] = g_pages[pindex + i];
		if ((allocflags & VM_ALLOC_WIRED) != 0)
			ma[i]->ref_count++;
	}
	return (grabbed);
}

int
vm_page_is_valid(vm_page_t m, int base, int size)
{
	vm_page_bits_t bits;

	__CPROVER_assert(base >= 0 && size >= 0 && base + size <= PAGE_SIZE,
	    "vm_page_is_valid() range inside the page");
	/*
	 * Said outright rather than read from the page: cbmc cannot see
	 * through the pointer that every page holds the same bits, and the
	 * paging path it then explored was most of the formula.
	 */
	if (g_cached)
		return (1);
	bits = page_bits(base, size);
	return (m->valid != 0 && (m->valid & bits) == bits);
}

void
vm_page_valid(vm_page_t m)
{
	m->valid = VM_PAGE_BITS_ALL;
}

void pmap_zero_page(vm_page_t m) { }
void vm_page_xunbusy_hard(vm_page_t m) { }
void vm_page_xunbusy_hard_unchecked(vm_page_t m) { }
void
vm_page_unwire(vm_page_t m, uint8_t nqueue)
{
	__CPROVER_assert(m->ref_count > 0, "unwires a wired page");
	m->ref_count--;
}

void
vm_page_release(vm_page_t m, int flags)
{
	vm_page_unwire(m, PQ_INACTIVE);
}
void vm_object_pip_add(vm_object_t object, short i) { }
void vm_object_pip_wakeup(vm_object_t object) { }
void vm_object_reference_locked(vm_object_t object) { }
void vm_object_deallocate(vm_object_t object) { }

vm_page_t
vm_page_relookup(vm_object_t object, vm_pindex_t pindex)
{
	__CPROVER_assert(pindex < NPAGES, "relookup of a page of the file");
	return (g_pages[pindex]);
}

/*
 * vm_pager_has_page() is an inline reading pagertab[], which the headers
 * declare without a size; cbmc 6.11 aborts converting it once given one,
 * so run.sh replaces the calls to it with calls to this instead.
 */
boolean_t
cbmc_vm_pager_has_page(vm_object_t object, vm_pindex_t pindex, int *before,
    int *after)
{
	__CPROVER_assert(object == &g_obj, "asks the file's pager");
	/* proof_nodiskio: only the calls where no page needs reading. */
	__CPROVER_assume(!g_noio);
	if (after != NULL) {
		*after = nondet_int();
		__CPROVER_assume(*after >= 0 && *after < NPAGES);
	}
	return (nondet_bool());
}

/*
 * sf_buf_kva() makes a direct map pointer out of the page's physical
 * address, an integer, and cbmc encodes integer to pointer conversions
 * at a cost that dominated the formula.  run.sh replaces calls to it
 * with this, a pointer to the page's bytes in g_data.
 */
void *
cbmc_sf_buf_kva(struct sf_buf *sf)
{
	vm_page_t pg = sf_buf_page(sf);

	__CPROVER_assert(pg->pindex < NPAGES, "maps a page of the file");
	return (&g_data[pg->pindex * PAGE_SIZE]);
}

/* The pager reads the run, and the I/O completes at once. */
int
vm_pager_get_pages_async(vm_object_t object, vm_page_t *m, int count,
    int *rbehind, int *rahead, pgo_getpages_iodone_t iodone, void *arg)
{
	for (int i = 0; i < count; i++)
		if (m[i] != bogus_page)
			m[i]->valid = VM_PAGE_BITS_ALL;
	iodone(arg, m, count, 0);
	return (VM_PAGER_OK);
}

/* File and socket model. */

int
getsock(struct thread *td, int fd, const cap_rights_t *rightsp,
    struct file **fpp)
{
	*fpp = &g_sock_fp;
	g_sock_fp.f_count++;		/* the reference fdrop() drops */
	return (0);
}

int _fdrop(struct file *fp, struct thread *td) { return (0); }
int soiolock(struct socket *so, struct sx *sx, int flags) { return (0); }
void soiounlock(struct sx *sx) { }
void sorele_locked(struct socket *so) { }
int sbwait(struct socket *so, sb_which which) { return (0); }

/* A blocking socket: each wait returns room for some bytes, no error. */
static int
sendfile_wait(struct socket *so, off_t need, int *space)
{
	__CPROVER_assert(need > 0, "waits only for bytes to send");
	/* proof_noloop: only the calls that queue no file page. */
	__CPROVER_assume(!g_noloop);
	/*
	 * The bounds give the socket room for the whole transfer in
	 * MAXWAITS iterations.  One more is a property: were it reachable,
	 * the loop would be spinning.  Then it is cut here, at the top of
	 * the loop, because cbmc cannot rule it out on its own and unrolled
	 * it whole, which cost more than the iterations proven.
	 */
	/* A file growing under the loop legitimately takes more. */
	__CPROVER_assert(g_resize || g_waits < MAXWAITS,
	    "no more send loop iterations than the room needs");
	__CPROVER_assume(g_waits < MAXWAITS);
	g_waits++;
	*space = nondet_int();
	__CPROVER_assume(*space >= MINSPACE && *space <= MAXSPACE);
	g_room = *space;
	return (0);
}

u_int
m_length(struct mbuf *m0, struct mbuf **last)
{
	struct mbuf *m;
	u_int len;

	len = 0;
	for (m = m0; m != NULL; m = m->m_next) {
		len += m->m_len;
		if (m->m_next == NULL)
			break;
	}
	if (last != NULL)
		*last = m;
	return (len);
}

void
m_freem(struct mbuf *m)
{
	struct mbuf *n;

	while (m != NULL) {
		n = m->m_next;
		__CPROVER_deallocate(m);
		m = n;
	}
}

/* The header as an mbuf of the length copied, which it then leaves. */
struct mbuf *
m_uiotombuf(struct uio *uio, int how, int len, int lspace, int flags)
{
	struct mbuf *m;
	ssize_t n;

	n = uio->uio_resid;
	if (len > 0 && len < n)
		n = len;
	m = m_get(how, MT_DATA);
	m->m_len = n;
	uio->uio_resid -= n;
	return (m);
}

/* A file byte at OFF in page PG, LEN of them: in order, and read. */
static void
file_bytes(vm_page_t pg, size_t inpage, int len)
{
	__CPROVER_assert(len > 0, "no empty page in an mbuf");
	__CPROVER_assert(inpage + len <= PAGE_SIZE,
	    "mbuf data inside its page");
	__CPROVER_assert(IDX_TO_OFF(pg->pindex) + inpage == g_file_next,
	    "file bytes in file order, none skipped");
	__CPROVER_assert((pg->valid & page_bits(inpage, len)) ==
	    page_bits(inpage, len),
	    "only file bytes read from the file are sent");
	g_file_next += len;
	g_file_seen += len;
}

static int
pr_send(struct socket *so, int flags, struct mbuf *m0, struct sockaddr *a,
    struct mbuf *c, struct thread *td)
{
	struct mbuf *m;
	vm_page_t pg;
	vm_paddr_t pa;
	int len, sum;

	__CPROVER_assert(m_length(m0, NULL) <= (u_int)g_room,
	    "queues no more than the socket has room for");
	for (m = m0; m != NULL; m = m->m_next) {
		/*
		 * Header mbufs are the ones m_uiotombuf() makes, with no
		 * external storage; every page mbuf has some.  No flag marks
		 * them: M_PROTO1 was tried, and it is M_NOTREADY.
		 */
		if ((m->m_flags & M_EXT) == 0) {
			__CPROVER_assert(g_phase == 0,
			    "header bytes come before file bytes");
			g_hdr_seen += m->m_len;
			continue;
		}
		g_phase = 1;
		if ((m->m_flags & M_EXTPG) != 0) {
			/*
			 * Unmapped: pages by physical address, the first from
			 * m_epg_1st_off, the last m_epg_last_len long.
			 */
			__CPROVER_assert(m->m_epg_npgs > 0 &&
			    m->m_epg_npgs <= MBUF_PEXT_MAX_PGS,
			    "unmapped mbuf page count in range");
			sum = 0;
			for (int i = 0; i < m->m_epg_npgs; i++) {
				pa = m->m_epg_pa[i];
				__CPROVER_assert(pa % PAGE_SIZE == 0 &&
				    pa / PAGE_SIZE >= 1 &&
				    pa / PAGE_SIZE <= NPAGES,
				    "unmapped mbuf holds a page of the file");
				pg = g_pages[pa / PAGE_SIZE - 1];
				len = m_epg_pagelen(m, i,
				    i == 0 ? m->m_epg_1st_off : 0);
				file_bytes(pg, i == 0 ? m->m_epg_1st_off : 0,
				    len);
				sum += len;
			}
			__CPROVER_assert(sum == m->m_len,
			    "unmapped mbuf length is its pages'");
			continue;
		}
		__CPROVER_assert(m->m_ext.ext_type == EXT_SFBUF,
		    "file bytes come from a page");
		pg = sf_buf_page(m->m_ext.ext_arg1);
		__CPROVER_assert(m->m_ext.ext_buf ==
		    &g_data[pg->pindex * PAGE_SIZE],
		    "mbuf maps the page it holds");
		file_bytes(pg, m->m_data - m->m_ext.ext_buf, m->m_len);
	}
	/*
	 * A chain queued not ready stays until pr_ready() readies it.
	 * NO_READY_CHECK leaves that out: with a mapped mbuf per page it
	 * makes proof_read six times slower.
	 */
#ifndef NO_READY_CHECK
	if ((flags & PRUS_NOTREADY) != 0) {
		__CPROVER_assert(g_pending == NULL,
		    "one chain not ready at a time");
		g_pending = m0;
	} else
#endif
		m_freem(m0);
	return (0);
}

/*
 * What sbready() expects: from m on, count not-ready pages, one per
 * mapped mbuf and m_epg_nrdy per unmapped one, every mbuf among them not
 * ready.  sendfile readies all the pages of a chain at once, so none of
 * it may be left not ready.
 */
static int
pr_ready(struct socket *so, struct mbuf *m, int count)
{
#ifdef NO_READY_CHECK
	return (0);
#endif
	__CPROVER_assert(g_pending != NULL, "readies a chain queued not ready");
	__CPROVER_assert(count > 0, "readies at least one page");
	while (count > 0) {
		__CPROVER_assert(m != NULL, "readies no more pages than queued");
		__CPROVER_assert((m->m_flags & M_NOTREADY) != 0,
		    "readies only mbufs queued not ready");
		if ((m->m_flags & M_EXTPG) != 0 && m->m_epg_npgs != 0) {
			__CPROVER_assert(count >= m->m_epg_nrdy,
			    "readies every page of an unmapped mbuf");
			count -= m->m_epg_nrdy;
		} else
			count--;
		m = m->m_next;
	}
	for (; m != NULL; m = m->m_next)
		__CPROVER_assert((m->m_flags & M_NOTREADY) == 0,
		    "every page queued not ready is readied");
	m_freem(g_pending);
	g_pending = NULL;
	return (0);
}

/* Reached on an I/O error, which the pager model does not report. */
static void
pr_abort(struct socket *so)
{
	__CPROVER_assert(0, "model: pr_abort() on a read that cannot fail");
}

int
kern_filewrite(struct thread *td, int fd, struct file *fp, struct uio *auio,
    int flags, ssize_t *cntp)
{
	ssize_t n;
	int error;

	/*
	 * The socket takes it all, or stops short.  sousrsend() clears
	 * EAGAIN and EINTR on a stream socket that took some of it, so a
	 * short write returns 0, or a hard error such as EPIPE; for a
	 * socket, kern_filewrite() hands back the count with the error.
	 */
	__CPROVER_assert(fp == &g_sock_fp, "header or trailer to the socket");
	__CPROVER_assert(auio->uio_rw == UIO_WRITE && auio->uio_td == td,
	    "uio set up for a write");
	n = auio->uio_resid;
	error = 0;
	if (nondet_bool()) {
		n = nondet_size_t();
		__CPROVER_assume(n >= 0 && n < auio->uio_resid);
		error = nondet_bool() ? 0 : EPIPE;
		if (error == 0)
			g_short = true;
	}
	if (auio == g_hdr_uio) {
		__CPROVER_assert(g_phase == 0,
		    "header bytes come before file bytes");
		g_hdr_seen += n;
	} else {
		__CPROVER_assert(g_hdr_uio == NULL || g_hdr_uio->uio_resid == 0,
		    "no trailer after a partial header");
		__CPROVER_assert(g_phase != 2 || n == 0,
		    "trailer written once");
		g_phase = 2;
		g_trl_seen += n;
	}
	*cntp = n;
	auio->uio_resid -= n;
	return (error);
}

static int
vop_unlock(struct vop_unlock_args *ap)
{
	return (0);
}

/* Set up the file, the socket and a header and trailer of any length. */

static off_t
setup(struct uio *hdr, struct uio *trl, bool *has_hdr, bool *has_trl,
    bool cached)
{
	off_t size;

	g_cached = cached;
	size = nondet_off_t();
	__CPROVER_assume(size >= 0 && size <= MAXFILE);
	for (int i = 0; i < NPAGES; i++) {
		g_pages[i] = __CPROVER_allocate(sizeof(struct vm_page), 1);
		g_pages[i]->pindex = i;
		g_pages[i]->object = &g_obj;
		g_pages[i]->phys_addr = (vm_paddr_t)(i + 1) * PAGE_SIZE;
		g_pages[i]->valid = cached ? VM_PAGE_BITS_ALL :
		    nondet_vm_page_bits_t();
	}
	g_obj.type = OBJT_VNODE;
	g_obj.flags = 0;
	g_obj.un_pager.vnp.vnp_size = size;
	g_size_max = size;
	g_vnode.v_type = VREG;
	g_vnode.v_object = &g_obj;
	g_vop.vop_unlock = vop_unlock;
	g_vnode.v_op = &g_vop;
	g_fp.f_type = DTYPE_VNODE;
	g_fp.f_vnode = &g_vnode;

	g_proto.pr_type = SOCK_STREAM;
	g_proto.pr_protocol = IPPROTO_TCP;
	g_proto.pr_send = pr_send;
	g_proto.pr_ready = pr_ready;
	g_proto.pr_abort = pr_abort;
	g_proto.pr_sendfile_wait = sendfile_wait;
	g_so.so_type = SOCK_STREAM;
	g_so.so_proto = &g_proto;
	g_so.so_state = SS_ISCONNECTED;
	g_sock_fp.f_type = DTYPE_SOCKET;
	g_sock_fp.f_data = &g_so;

	*has_hdr = nondet_bool();
	*has_trl = nondet_bool();
	g_hdr_uio = *has_hdr ? hdr : NULL;
	trl->uio_rw = UIO_WRITE;	/* as kern_sendfile() sets it */
	trl->uio_td = &g_td;
	hdr->uio_resid = nondet_size_t();
	__CPROVER_assume(hdr->uio_resid >= 0 && hdr->uio_resid <= MAXHDR);
	trl->uio_resid = nondet_size_t();
	__CPROVER_assume(trl->uio_resid >= 0 && trl->uio_resid <= MAXHDR);
	return (size);
}

static void
check_stream(int error, off_t sent, off_t offset, size_t nbytes, off_t size,
    ssize_t hlen, ssize_t tlen)
{
	off_t want;

	__CPROVER_assert(sent == (off_t)(g_hdr_seen + g_file_seen +
	    g_trl_seen), "sbytes is what the socket received");
#ifdef SPEC_SHORT_WRITE
	/*
	 * sendfile.2: on a non-blocking socket "sendfile() may send fewer
	 * bytes than requested.  In this case ... the error EAGAIN is
	 * returned", and EINTR on a signal.  A header or trailer write cut
	 * short returns 0 instead, sousrsend() clearing the error; whether
	 * the manual or the code is right is an open question, so this is
	 * only checked on request.
	 */
	__CPROVER_assert(!g_short || error != 0,
	    "a short write makes sendfile(2) fail");
#endif
	if (error != 0 || g_short)
		return;
	__CPROVER_assert(g_pending == NULL, "every chain queued is readied");

	/*
	 * sendfile.2: "nbytes ... how many bytes of the file should be
	 * sent, with 0 having the special meaning of send until the end of
	 * file", and "Should offset fall beyond the end of file, the system
	 * will return success and report 0 bytes sent".
	 */
	__CPROVER_assert(g_hdr_seen == (size_t)hlen,
	    "the whole header is sent");
	if (g_resized) {
		/*
		 * With the size changing under it, sendfile.2 says nothing of
		 * how much of the file goes out; what is sent is file data,
		 * no more than asked for.  The header and trailer, as past
		 * the end of the file, go out in full.
		 */
		__CPROVER_assert(nbytes == 0 ||
		    (uintmax_t)g_file_seen <= (uintmax_t)nbytes,
		    "no more file bytes than asked for");
		__CPROVER_assert(offset + g_file_seen <= g_size_max ||
		    g_file_seen == 0, "only bytes the file had are sent");
	} else {
		want = offset >= size ? 0 : size - offset;
		if (nbytes != 0 && (uintmax_t)nbytes < (uintmax_t)want)
			want = nbytes;
		__CPROVER_assert(g_file_seen == want,
		    "the file bytes asked for are sent");
	}
	__CPROVER_assert(g_trl_seen == (size_t)tlen,
	    "the whole trailer is sent");
}

static void
send(int flags)
{
	struct uio hdr, trl;
	bool has_hdr, has_trl;
	off_t offset, sent, size;
	size_t nbytes;
	ssize_t hlen, tlen;
	int error;

	size = setup(&hdr, &trl, &has_hdr, &has_trl, true);
	hlen = has_hdr ? hdr.uio_resid : 0;
	tlen = has_trl ? trl.uio_resid : 0;
	/*
	 * kern_sendfile() refuses a negative offset.  Every offset past
	 * the end of the file takes the same path, rem <= 0, so the ones up
	 * to one past MAXFILE stand for all of them.
	 */
	offset = nondet_off_t();
	__CPROVER_assume(offset >= 0 && offset <= MAXFILE + 1);
	nbytes = nondet_size_t();
	g_file_next = offset;

	error = vn_sendfile(&g_fp, 0, has_hdr ? &hdr : NULL,
	    has_trl ? &trl : NULL, offset, nbytes, &sent, flags, &g_td);
	check_stream(error, sent, offset, nbytes, size, hlen, tlen);
}

/*
 * The send loop begins by waiting for room in the socket, so ruling the
 * wait out leaves every call that does not enter the loop: an offset at
 * or past the end of the file, an empty file, and anything else that
 * leaves nothing to read.  It has no loop and is cheap.
 */
void
proof_noloop(void)
{
	g_nowait_fails = false;
	g_noloop = true;
	send(0);
}

/*
 * The paging path: pages partly valid or not at all, read by the pager,
 * whose I/O completes at once.  The whole contract of proof_send holds.
 */
void
proof_read(void)
{
	struct uio hdr, trl;
	bool has_hdr, has_trl;
	off_t offset, sent, size;
	size_t nbytes;
	ssize_t hlen, tlen;
	int error;

	g_nowait_fails = false;
	size = setup(&hdr, &trl, &has_hdr, &has_trl, false);
	hlen = has_hdr ? hdr.uio_resid : 0;
	tlen = has_trl ? trl.uio_resid : 0;
	offset = nondet_off_t();
	__CPROVER_assume(offset >= 0 && offset <= MAXFILE + 1);
	nbytes = nondet_size_t();
	g_file_next = offset;

	error = vn_sendfile(&g_fp, 0, has_hdr ? &hdr : NULL,
	    has_trl ? &trl : NULL, offset, nbytes, &sent, 0, &g_td);
	check_stream(error, sent, offset, nbytes, size, hlen, tlen);
}

/* proof_send and proof_read with unmapped mbufs, as TCP uses on amd64. */
void
proof_send_extpg(void)
{
	mb_use_ext_pgs = true;
	g_nowait_fails = false;
	send(0);
}

void
proof_read_extpg(void)
{
	mb_use_ext_pgs = true;
	proof_read();
}

void
proof_nodiskio_extpg(void)
{
	mb_use_ext_pgs = true;
	proof_nodiskio();
}

/* proof_send with the file truncated or extended during the call. */
void
proof_resize(void)
{
	g_resize = true;
	g_nowait_fails = false;
	send(0);
}

void
proof_send(void)
{
	g_nowait_fails = false;
	send(0);
}

void
proof_nodiskio(void)
{
	struct uio hdr, trl;
	bool has_hdr, has_trl;
	off_t offset, sent;
	size_t nbytes;
	int error;

	/*
	 * Only the bytes queued are checked: SF_NODISKIO stops at the
	 * first page it cannot grab, with EBUSY.  The pages may be partly
	 * valid, but none so little that it needs reading: the pager is
	 * not asked, which keeps the paging path out of the formula.
	 */
	g_nowait_fails = true;
	g_noio = true;
	(void)setup(&hdr, &trl, &has_hdr, &has_trl, false);
	offset = nondet_off_t();
	__CPROVER_assume(offset >= 0 && offset <= MAXFILE + 1);
	nbytes = nondet_size_t();
	g_file_next = offset;

	error = vn_sendfile(&g_fp, 0, has_hdr ? &hdr : NULL,
	    has_trl ? &trl : NULL, offset, nbytes, &sent, SF_NODISKIO, &g_td);
	__CPROVER_assert(error == 0 || error == EBUSY,
	    "SF_NODISKIO fails only with EBUSY");
	__CPROVER_assert(sent == (off_t)(g_hdr_seen + g_file_seen +
	    g_trl_seen), "sbytes is what the socket received");
}

void
proof_xfsize(void)
{
	off_t off, space, sum;
	int npages;

	off = nondet_off_t();
	space = nondet_off_t();
	__CPROVER_assume(off >= 0 && space > 0 && space <= MAXSPACE &&
	    off <= OFF_MAX - space);
	npages = howmany(space + (off & PAGE_MASK), PAGE_SIZE);
	sum = 0;
	for (int i = 0; i < npages; i++) {
		off_t len = xfsize(i, npages, off, space);
		off_t base = vmoff(i, off) & PAGE_MASK;

		__CPROVER_assert(len > 0, "no page is empty");
		__CPROVER_assert(base + len <= PAGE_SIZE,
		    "a page's bytes are inside it");
		__CPROVER_assert(i == 0 || base == 0,
		    "only the first page starts inside");
		__CPROVER_assert(trunc_page(vmoff(i, off)) ==
		    trunc_page(off) + (off_t)i * PAGE_SIZE,
		    "page i is the i-th page of the run");
		sum += len;
	}
	__CPROVER_assert(sum == space, "the pages hold the whole run");
}

void
proof_fixspace(void)
{
	off_t off, space, keep;
	int npages, i;

	off = nondet_off_t();
	space = nondet_off_t();
	__CPROVER_assume(off >= 0 && space > 0 && space <= MAXSPACE &&
	    off <= OFF_MAX - space);
	npages = howmany(space + (off & PAGE_MASK), PAGE_SIZE);
	i = nondet_int();
	__CPROVER_assume(i >= 0 && i < npages);
	keep = 0;
	for (int j = 0; j < i; j++)
		keep += xfsize(j, npages, off, space);
	{
		int s = space;

		fixspace(npages, i, off, &s);
		__CPROVER_assert(s == keep,
		    "the run keeps the pages before the missing one");
	}
}
