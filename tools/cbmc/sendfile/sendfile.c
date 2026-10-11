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
 *   proof_send_tls	proof_send, proof_read and proof_ioerror on a
 *   proof_read_tls	KTLS socket, built with KERN_TLS: software, NIC
 *   proof_ioerror_tls	and TOE modes
 *   proof_ioerror	proof_read with reads that fail, at once or
 *			later, and complete after the call
 *   proof_nocache	proof_send with SF_NOCACHE: every page wired is
 *   proof_nocache_extpg released, freed unless the send stopped in it
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
static void unbusy(volatile u_int *);
#define	CBMC_CMPSET_HOOK	unbusy
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
static bool		g_busy[NPAGES];	/* busied by this call */
static bool		g_wired[NPAGES];	/* wired by this call, ever */
static bool		g_tryfree[NPAGES];	/* last released with VPR_TRYFREE */
static int		g_flags;		/* the call's flags */
/*
 * Page release through the mbufs' free routines, and the checks on it:
 * on for unmapped mbufs, KTLS and SF_NOCACHE, off for mapped mbufs, where
 * one release per page made each proof take over an hour.  A run-time
 * flag, constant in each proof, so that cbmc prunes the code it guards.
 */
static bool		g_release;
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
#ifdef KERN_TLS
static struct ktls_session g_tls;	/* the socket's TLS session */
#endif
static struct mbuf	*g_hdrm[MAXWAITS + 1];	/* header mbufs made */
static int		g_nhdrm;
static bool		g_ioerror;	/* reads may fail */
static bool		g_aborted;	/* pr_abort() was called */
static bool		g_syncerr;	/* a read failed at once */

/* Reads whose completion the pager model holds until after the call. */
#ifndef MAXIO
#define	MAXIO		2		/* reads held at once */
#endif
#ifndef IODEFER
#define	IODEFER		0		/* reads may complete after the call */
#endif
static struct {
	void		*arg;
	vm_page_t	*m;
	int		count;
	int		error;
} g_io[MAXIO];
static int		g_nio;
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

/*
 * The busy state of the pages, as ghost state: the grab busies each page
 * it returns, and vm_page_xunbusy() and vm_page_xunbusy_unchecked(), both
 * an atomic_cmpset_rel_int() on the page's busy_lock, unbusy one.  The
 * model of that compare-and-set calls this.
 */
static void
unbusy(volatile u_int *p)
{
	bool found;

	found = false;
	for (int k = 0; k < NPAGES; k++) {
		if (p == &g_pages[k]->busy_lock) {
			__CPROVER_assert(g_busy[k],
			    "unbusies only a page it holds busy");
			g_busy[k] = false;
			found = true;
		}
	}
	__CPROVER_assert(found, "unbusies a page of the file");
}

/*
 * When the call is done, no page it busied is still busy, and the
 * references it took on the socket and the TLS session are dropped.
 */
static void
all_unbusied(void)
{
	for (int k = 0; k < NPAGES; k++)
		__CPROVER_assert(!g_busy[k],
		    "leaves no page busy");
	__CPROVER_assert(g_pending != NULL || g_so.so_count == 1,
	    "socket references balanced");
#ifdef KERN_TLS
	__CPROVER_assert(g_pending != NULL || g_tls.refcount == 1,
	    "TLS session references balanced");
#endif
	if (g_pending != NULL || !g_release)
		return;
	for (int k = 0; k < NPAGES; k++) {
		__CPROVER_assert(g_pages[k]->ref_count == 0,
		    "every page wired is released");
		/*
		 * sendfile.2: with SF_NOCACHE "the data sent to socket will
		 * not be cached ... and will be freed directly to the pool of
		 * free pages".  vn_sendfile() keeps the page a send stopped
		 * in, when more of it is to follow, for the next one.
		 */
		__CPROVER_assert((g_flags & SF_NOCACHE) == 0 || !g_wired[k] ||
		    g_tryfree[k] || (g_file_next / PAGE_SIZE == k &&
		    g_file_next % PAGE_SIZE != 0 &&
		    g_file_next < g_obj.un_pager.vnp.vnp_size),
		    "SF_NOCACHE frees every page but one the send stopped in");
	}
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
		__CPROVER_assert(!g_busy[pindex + i],
		    "grabs no page it holds busy already");
		g_busy[pindex + i] = true;
		ma[i] = g_pages[pindex + i];
		if ((allocflags & VM_ALLOC_WIRED) != 0) {
			ma[i]->ref_count++;
			g_wired[pindex + i] = true;
		}
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

/*
 * A page sendfile_free_mext() or sendfile_free_mext_pg() releases when
 * its mbuf is freed; the flags of the last release are kept.
 */
void
vm_page_release(vm_page_t m, int flags)
{
	vm_page_unwire(m, PQ_INACTIVE);
	g_tryfree[m->pindex] = (flags & VPR_TRYFREE) != 0;
}

vm_page_t
PHYS_TO_VM_PAGE(vm_paddr_t pa)
{
	__CPROVER_assert(pa % PAGE_SIZE == 0 && pa / PAGE_SIZE >= 1 &&
	    pa / PAGE_SIZE <= NPAGES, "a physical address of the file's");
	return (g_pages[pa / PAGE_SIZE - 1]);
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

/*
 * The pager reads the run.  The read completes now, or is held until
 * after vn_sendfile() returns, as an asynchronous read does.  With
 * g_ioerror it may fail, either later, through the completion, or at
 * once; then, as vnode_pager_local_getpages_async() and ZFS do, the
 * completion runs with the error before the error is returned, which is
 * what restores the pages sendfile_swapin() replaced with bogus_page.
 */
static void
io_complete(void *arg, vm_page_t *m, int count, int error)
{
	if (error == 0)
		for (int i = 0; i < count; i++)
			if (m[i] != bogus_page)
				m[i]->valid = VM_PAGE_BITS_ALL;
	sendfile_iodone(arg, m, count, error);
}

static void
io_flush(void)
{
	for (int i = 0; i < g_nio; i++)
		io_complete(g_io[i].arg, g_io[i].m, g_io[i].count,
		    g_io[i].error);
	g_nio = 0;
}

int
vm_pager_get_pages_async(vm_object_t object, vm_page_t *m, int count,
    int *rbehind, int *rahead, pgo_getpages_iodone_t iodone, void *arg)
{
	int error;

	__CPROVER_assert(iodone == sendfile_iodone, "completes to sendfile");
	/*
	 * What vm_pager_assert_in() checks: consecutive pages, the first
	 * and the last real ones, each real one busied and not all valid.
	 */
	__CPROVER_assert(count > 0 && m[0] != bogus_page &&
	    m[count - 1] != bogus_page, "pager run ends on real pages");
	for (int i = 0; i < count; i++) {
		if (m[i] == bogus_page)
			continue;
		__CPROVER_assert(m[i]->pindex == m[0]->pindex + i,
		    "pager run of consecutive pages");
		__CPROVER_assert(g_busy[m[i]->pindex],
		    "pager reads only busied pages");
		__CPROVER_assert(m[i]->valid != VM_PAGE_BITS_ALL,
		    "pager reads no page already valid");
	}
	error = 0;
	if (g_ioerror && nondet_bool()) {
		error = EIO;
		if (!IODEFER && nondet_bool()) {
			/* Failing at once: what is pending completes first. */
			g_syncerr = true;
			io_flush();
			io_complete(arg, m, count, error);
			return (VM_PAGER_ERROR);
		}
	}
	/* IODEFER: every read completes after the call, the async case. */
	if (IODEFER && g_ioerror && g_nio < MAXIO) {
		g_io[g_nio].arg = arg;
		g_io[g_nio].m = m;
		g_io[g_nio].count = count;
		g_io[g_nio].error = error;
		g_nio++;
	} else
		io_complete(arg, m, count, error);
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
/* Called on the last reference, which frees the socket: the fd has one. */
void
sorele_locked(struct socket *so)
{
	__CPROVER_assert(0, "never drops the socket's last reference");
}
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

static bool is_hdr(struct mbuf *);

void
m_freem(struct mbuf *m)
{
	struct mbuf *n;

	while (m != NULL) {
		n = m->m_next;
#ifdef KERN_TLS
		if ((m->m_flags & M_EXTPG) != 0 && m->m_epg_tls != NULL)
			ktls_free(m->m_epg_tls);
#endif
		/*
		 * The pages of a page mbuf go back through the kernel's own
		 * free routine, named rather than called through ext_free,
		 * which would be one more indirect call to restrict.
		 */
		if (g_release && (m->m_flags & M_EXT) != 0 && !is_hdr(m)) {
			if (m->m_ext.ext_free == sendfile_free_mext)
				sendfile_free_mext(m);
			else {
				__CPROVER_assert(m->m_ext.ext_free ==
				    sendfile_free_mext_pg,
				    "a page mbuf frees through sendfile");
				sendfile_free_mext_pg(m);
			}
		}
		__CPROVER_deallocate(m);
		m = n;
	}
}

/*
 * The header as one mbuf of the length copied, which it then leaves:
 * unmapped with M_EXTPG, as a KTLS socket asks, holding no more than LSPACE
 * (max_frame_len) bytes, mapped otherwise.  The header mbufs are told from
 * the page mbufs by identity, kept in g_hdrm.
 */
struct mbuf *
m_uiotombuf(struct uio *uio, int how, int len, int lspace, int flags)
{
	struct mbuf *m;
	ssize_t n;

	n = uio->uio_resid;
	if (len > 0 && len < n)
		n = len;
	if ((flags & M_EXTPG) != 0) {
		__CPROVER_assert(lspace > 0 && n <= lspace,
		    "model: header fits one record");
		m = mb_alloc_ext_pgs(how, NULL, 0);
		m->m_epg_npgs = howmany(n, PAGE_SIZE);
		m->m_epg_last_len = n;
		m->m_ext.ext_size = PAGE_SIZE;
	} else
		m = m_get(how, MT_DATA);
	m->m_len = n;
	uio->uio_resid -= n;
	__CPROVER_assert(g_nhdrm <= MAXWAITS, "model: header mbufs bounded");
	g_hdrm[g_nhdrm++] = m;
	return (m);
}

static bool
is_hdr(struct mbuf *m)
{
	for (int i = 0; i < g_nhdrm; i++)
		if (g_hdrm[i] == m)
			return (true);
	return (false);
}

/* The payload of an mbuf, without the TLS header and trailer framing it. */
static int
payload(struct mbuf *m)
{
	if ((m->m_flags & M_EXTPG) != 0)
		return (m->m_len - m->m_epg_hdrlen - m->m_epg_trllen);
	return (m->m_len);
}

/*
 * LEN file bytes at INPAGE in page PG.  The socket buffer delivers in the
 * order data is queued, so their order is checked when they are queued
 * (QUEUED); that they were read from the file is checked when they can be
 * delivered (READY), at once or when pr_ready() readies them.
 */
#define	QUEUED		0x1
#define	READY		0x2

static void
file_bytes(vm_page_t pg, size_t inpage, int len, int how)
{
	if ((how & QUEUED) != 0) {
		__CPROVER_assert(len > 0, "no empty page in an mbuf");
		__CPROVER_assert(inpage + len <= PAGE_SIZE,
		    "mbuf data inside its page");
		__CPROVER_assert(IDX_TO_OFF(pg->pindex) + inpage ==
		    g_file_next, "file bytes in file order, none skipped");
		g_file_next += len;
		g_file_seen += len;
	}
	if ((how & READY) != 0) {
		__CPROVER_assert((pg->valid & page_bits(inpage, len)) ==
		    page_bits(inpage, len),
		    "only file bytes read from the file are sent");
		__CPROVER_assert(!g_busy[pg->pindex],
		    "delivers no page still busy");
	}
}

/* The bytes of a chain: header, then file bytes; HOW as file_bytes(). */
static void
deliver(struct mbuf *m0, int how)
{
	struct mbuf *m;
	vm_page_t pg;
	vm_paddr_t pa;
	int len, sum;

	for (m = m0; m != NULL; m = m->m_next) {
		/*
		 * Header mbufs are the ones m_uiotombuf() made.  No flag
		 * marks them: M_PROTO1 was tried, and it is M_NOTREADY.
		 */
		if (is_hdr(m)) {
			if ((how & QUEUED) != 0) {
				__CPROVER_assert(g_phase == 0,
				    "header bytes come before file bytes");
				g_hdr_seen += payload(m);
			}
			continue;
		}
		if ((how & QUEUED) != 0)
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
				    len, how);
				sum += len;
			}
			__CPROVER_assert((how & QUEUED) == 0 ||
			    sum == payload(m),
			    "unmapped mbuf length is its pages' and framing");
			continue;
		}
		__CPROVER_assert(m->m_ext.ext_type == EXT_SFBUF,
		    "file bytes come from a page");
		pg = sf_buf_page(m->m_ext.ext_arg1);
		__CPROVER_assert(m->m_ext.ext_buf ==
		    &g_data[pg->pindex * PAGE_SIZE],
		    "mbuf maps the page it holds");
		file_bytes(pg, m->m_data - m->m_ext.ext_buf, m->m_len, how);
	}
}

static int
chain_payload(struct mbuf *m0)
{
	int len;

	len = 0;
	for (struct mbuf *m = m0; m != NULL; m = m->m_next)
		len += payload(m);
	return (len);
}

static int
pr_send(struct socket *so, int flags, struct mbuf *m0, struct sockaddr *a,
    struct mbuf *c, struct thread *td)
{
	__CPROVER_assert(chain_payload(m0) <= g_room,
	    "queues no more than the socket has room for");
	/*
	 * A chain queued not ready takes its place in the stream now, and
	 * can be delivered once pr_ready() readies it; until then it stays.
	 * NO_READY_CHECK treats it as ready now: with a mapped mbuf per
	 * page, holding it makes proof_read six times slower.
	 */
#ifndef NO_READY_CHECK
	if ((flags & PRUS_NOTREADY) != 0) {
		__CPROVER_assert(g_pending == NULL,
		    "one chain not ready at a time");
		deliver(m0, QUEUED);
		g_pending = m0;
		return (0);
	}
#endif
	deliver(m0, QUEUED | READY);
	m_freem(m0);
	return (0);
}

/*
 * COUNT not-ready pages from M, one per mapped mbuf and m_epg_nrdy per
 * unmapped one, as sbready() and mb_free_notready() take them.
 */
static void
notready_pages(struct mbuf *m, int count)
{
	__CPROVER_assert(count > 0, "at least one page");
	while (count > 0) {
		__CPROVER_assert(m != NULL, "no more pages than queued");
		__CPROVER_assert((m->m_flags & M_NOTREADY) != 0,
		    "only mbufs queued not ready");
		if ((m->m_flags & M_EXTPG) != 0 && m->m_epg_npgs != 0) {
			__CPROVER_assert(count >= m->m_epg_nrdy,
			    "every page of an unmapped mbuf");
			count -= m->m_epg_nrdy;
		} else
			count--;
		m = m->m_next;
	}
}

/*
 * The COUNT pages are all the not-ready pages of the chain queued: none
 * is left not ready, before M (a TLS header record) or after.
 */
static void
all_ready(int count)
{
	int total;

	total = 0;
	for (struct mbuf *m = g_pending; m != NULL; m = m->m_next) {
		if ((m->m_flags & M_NOTREADY) == 0)
			continue;
		if ((m->m_flags & M_EXTPG) != 0 && m->m_epg_npgs != 0)
			total += m->m_epg_nrdy;
		else
			total++;
	}
	__CPROVER_assert(total == count,
	    "every page queued not ready is accounted for");
}

/*
 * What sbready() expects: from m on, count not-ready pages.  sendfile
 * readies all the pages of a chain at once.  The chain is then
 * delivered.
 */
#ifdef KERN_TLS
/*
 * KTLS.  The session the socket holds, with one reference, the socket's.
 * ktls_frame() is modelled by its preconditions, the KASSERT()s it makes
 * of every mbuf it frames, and by its effects: the record header and
 * trailer bytes, a session reference, and with software encryption the
 * pages to encrypt, queued not ready.  ktls_enqueue() encrypts at once:
 * it readies the pages, as sbready() does after encryption, and drops
 * the socket reference sendfile donated to it.
 */
void
ktls_frame(struct mbuf *top, struct ktls_session *tls, int *enq_cnt,
    uint8_t record_type)
{
	struct mbuf *m;
	int tls_len;

	__CPROVER_assert(tls == &g_tls, "frames with the socket's session");
	*enq_cnt = 0;
	for (m = top; m != NULL; m = m->m_next) {
		__CPROVER_assert(m->m_len > 0 &&
		    m->m_len <= tls->params.max_frame_len,
		    "a TLS record holds at most max_frame_len bytes");
		__CPROVER_assert((m->m_flags & M_EXTPG) != 0,
		    "a TLS record is an unmapped mbuf");
		tls_len = m->m_len;
		m->m_epg_tls = ktls_hold(tls);
		m->m_epg_hdrlen = tls->params.tls_hlen;
		m->m_epg_trllen = tls->params.tls_tlen;
		m->m_len += m->m_epg_hdrlen + m->m_epg_trllen;
		if (tls->mode == TCP_TLS_MODE_SW) {
			m->m_flags |= M_NOTREADY;
			m->m_epg_nrdy = tls_len == 0 ? 1 : m->m_epg_npgs;
			*enq_cnt += m->m_epg_nrdy;
		}
	}
}

void
ktls_enqueue(struct mbuf *m, struct socket *so, int page_count)
{
	__CPROVER_assert(g_tls.mode == TCP_TLS_MODE_SW,
	    "only software TLS is encrypted by the host");
	__CPROVER_assert(so == &g_so, "encrypts for the socket");
	__CPROVER_assert(g_pending != NULL, "encrypts a chain queued not ready");
	notready_pages(m, page_count);
	all_ready(page_count);
	deliver(g_pending, READY);
	m_freem(g_pending);
	g_pending = NULL;
	__CPROVER_assert(g_so.so_count > 1,
	    "the socket reference donated is not its last");
	g_so.so_count--;
}

void
ktls_destroy(struct ktls_session *tls)
{
	__CPROVER_assert(0, "the session is not freed while the socket has it");
}
#endif

static int
pr_ready(struct socket *so, struct mbuf *m, int count)
{
#ifdef NO_READY_CHECK
	return (0);
#endif
	__CPROVER_assert(g_pending != NULL, "readies a chain queued not ready");
	notready_pages(m, count);
	all_ready(count);
	deliver(g_pending, READY);
	m_freem(g_pending);
	g_pending = NULL;
	return (0);
}

/*
 * On a failed read, sendfile_iodone() aborts the socket, which frees
 * the ready mbufs, and frees the not-ready ones itself: none of the
 * chain is delivered.
 */
void
mb_free_notready(struct mbuf *m, int count)
{
	__CPROVER_assert(g_aborted, "frees not-ready mbufs on abort only");
	__CPROVER_assert(g_pending != NULL, "frees a chain queued not ready");
	/*
	 * It frees COUNT pages from M; pr_abort() frees the ready mbufs.
	 * A not-ready mbuf outside those COUNT pages would be lost.
	 */
	notready_pages(m, count);
	all_ready(count);
	m_freem(g_pending);
	g_pending = NULL;
}

static void
pr_abort(struct socket *so)
{
	__CPROVER_assert(g_ioerror, "pr_abort() only on a failed read");
	g_aborted = true;
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
	g_release = g_release || mb_use_ext_pgs;
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
	g_so.so_count = 1;
#ifdef KERN_TLS
	/*
	 * A TLS 1.2 or 1.3 session: max_frame_len is min(16384,
	 * kern.ipc.tls.maxlen), which the KTLS buffer code requires to be
	 * a multiple of the page size; the header and trailer are what an
	 * AEAD cipher adds.
	 */
	{
		int pages = nondet_int();

		__CPROVER_assume(pages >= 1 && pages <= 16384 / PAGE_SIZE);
		g_tls.params.max_frame_len = pages * PAGE_SIZE;
	}
	g_tls.params.tls_hlen = nondet_int();
	__CPROVER_assume(g_tls.params.tls_hlen >= 5 &&
	    g_tls.params.tls_hlen <= 13);
	g_tls.params.tls_tlen = nondet_int();
	__CPROVER_assume(g_tls.params.tls_tlen >= 16 &&
	    g_tls.params.tls_tlen <= 17);
#ifdef TLS_MODE
	g_tls.mode = TLS_MODE;		/* one mode, for the costlier proofs */
#else
	g_tls.mode = nondet_int();
	__CPROVER_assume(g_tls.mode == TCP_TLS_MODE_SW ||
	    g_tls.mode == TCP_TLS_MODE_IFNET || g_tls.mode == TCP_TLS_MODE_TOE);
#endif
	g_tls.refcount = 1;
	g_so.so_snd.sb_tls_info = &g_tls;
#endif
	g_so.so_state = SS_ISCONNECTED;
	g_sock_fp.f_type = DTYPE_SOCKET;
	g_sock_fp.f_data = &g_so;

	/* A signal may be pending on the thread, unmasked or not. */
	g_td.td_proc = &cbmc_proc;
	g_td.td_siglist.__bits[0] = nondet_u_int();
	g_td.td_sigmask.__bits[0] = nondet_u_int();

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

	all_unbusied();
	__CPROVER_assert(sent == (off_t)(g_hdr_seen + g_file_seen +
	    g_trl_seen), "sbytes is what the socket received");
	/*
	 * sendfile.2: on a non-blocking socket "sendfile() may send fewer
	 * bytes than requested.  In this case ... the error EAGAIN is
	 * returned", and EINTR when a signal interrupted it.
	 */
	__CPROVER_assert(!g_short || error == EINTR || error == EAGAIN,
	    "a short write makes sendfile(2) fail with EINTR or EAGAIN");
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

	g_flags = flags;
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

/*
 * proof_read with reads that fail, at once or through their completion,
 * which may come after vn_sendfile() has returned.  sendfile.2: "[EIO]
 * An error occurred while reading from fd"; when the read fails after
 * the data was queued not ready, the call has returned already, and the
 * socket is torn down with EIO instead (sendfile_iodone()).
 */
void
proof_ioerror(void)
{
	struct uio hdr, trl;
	bool has_hdr, has_trl;
	off_t offset, sent, size;
	size_t nbytes;
	ssize_t hlen, tlen;
	int error;

	g_nowait_fails = false;
	g_ioerror = true;
	size = setup(&hdr, &trl, &has_hdr, &has_trl, false);
	hlen = has_hdr ? hdr.uio_resid : 0;
	tlen = has_trl ? trl.uio_resid : 0;
	offset = nondet_off_t();
	__CPROVER_assume(offset >= 0 && offset <= MAXFILE + 1);
	nbytes = nondet_size_t();
	g_file_next = offset;

	error = vn_sendfile(&g_fp, 0, has_hdr ? &hdr : NULL,
	    has_trl ? &trl : NULL, offset, nbytes, &sent, 0, &g_td);
	io_flush();		/* the reads still in flight complete */
	all_unbusied();
	__CPROVER_assert(!g_syncerr || error == EIO,
	    "a read failing at once fails sendfile(2) with EIO");
	if (g_aborted) {
		__CPROVER_assert(g_so.so_error == EIO,
		    "a read failing later leaves EIO on the socket");
		__CPROVER_assert(g_pending == NULL,
		    "the data queued not ready is freed, not delivered");
		return;
	}
	check_stream(error, sent, offset, nbytes, size, hlen, tlen);
}

void
proof_ioerror_extpg(void)
{
	mb_use_ext_pgs = true;
	proof_ioerror();
}

#ifdef KERN_TLS
/* proof_send, proof_read and proof_ioerror on a KTLS socket. */
void
proof_send_tls(void)
{
	g_release = true;
	g_nowait_fails = false;
	send(0);
}

void
proof_read_tls(void)
{
	proof_read();
}

void
proof_ioerror_tls(void)
{
	proof_ioerror();
}
#endif

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

/* proof_send with SF_NOCACHE, on mapped and on unmapped mbufs. */
void
proof_nocache(void)
{
	g_release = true;
	g_nowait_fails = false;
	send(SF_NOCACHE);
}

void
proof_nocache_extpg(void)
{
	mb_use_ext_pgs = true;
	proof_nocache();
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
	all_unbusied();
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
