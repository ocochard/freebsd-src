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
 * Kernel model for cbmc(1) harnesses.
 *
 * A harness includes the kernel source file it proves, then this file,
 * which gives a body to the kernel functions that source calls and that
 * live elsewhere.  cbmc treats a function without a body as returning any
 * value and touching nothing, which is wrong for an allocator or for a
 * function filling an output argument, so each of those is modelled here.
 * Locks are no-ops: the proofs are sequential, and a concurrent writer is
 * modelled where it matters by the harness, not by the lock.
 *
 * A panic(), a failed KASSERT() included, is a property violation.
 */

#ifndef _CBMC_MODEL_KERN_H_
#define	_CBMC_MODEL_KERN_H_

bool	nondet_bool(void);
int	nondet_int(void);
u_int	nondet_u_int(void);
off_t	nondet_off_t(void);
size_t	nondet_size_t(void);
vm_page_bits_t nondet_vm_page_bits_t(void);

void
panic(const char *fmt, ...)
{
	__CPROVER_assert(0, "panic");
	__CPROVER_assume(0);
}

#ifndef kassert_panic
void
kassert_panic(const char *fmt, ...)
{
	__CPROVER_assert(0, "KASSERT");
	__CPROVER_assume(0);
}
#endif

int
printf(const char *fmt, ...)
{
	return (0);
}

/*
 * The one thread the proofs run in.  __curthread() reads %gs; run.sh
 * replaces calls to it with cbmc_curthread().
 */
struct thread cbmc_thread;
struct proc cbmc_proc;

struct thread *
cbmc_curthread(void)
{
	return (&cbmc_thread);
}

/* Memory. */

/*
 * malloc(9) hands out a block of a fixed size, CBMC_MALLOC_BUCKET bytes of
 * pointer-sized words, whatever the size asked for, as malloc(9) rounds a
 * request up to its bucket.  A block whose size depends on the input would
 * be an opaque array to cbmc, and every read from it unknown: with sfio,
 * sized by the page count, that left every branch on its pages open and
 * the formula out of reach.  Words rather than bytes, because cbmc reads
 * an untyped object byte by byte.  An overrun inside the bucket goes
 * unseen, as it does on a kernel without KASAN.
 */
#ifndef CBMC_MALLOC_BUCKET
#define	CBMC_MALLOC_BUCKET	256
#endif
/*
 * The word type: cbmc keeps reads and writes of a word as values only when
 * they are of its type, so a harness sets it to the type of the array the
 * code under proof allocates (vm_page_t for sendfile's sf_io).
 */
#ifndef CBMC_MALLOC_WORD
#define	CBMC_MALLOC_WORD	void *
#endif

void *
(malloc)(size_t size, struct malloc_type *type, int flags)
{
	CBMC_MALLOC_WORD (*p)[CBMC_MALLOC_BUCKET / sizeof(CBMC_MALLOC_WORD)];

#ifdef CBMC_MALLOC_HOOK
	/* A harness allocating a type of its own, typed, see sendfile.c. */
	void *q;

	if ((q = CBMC_MALLOC_HOOK(size, type, flags)) != NULL)
		return (q);
#endif
	__CPROVER_assert(size <= CBMC_MALLOC_BUCKET,
	    "model: allocation fits the modelled bucket");
	p = __CPROVER_allocate(sizeof(*p), (flags & M_ZERO) != 0);
	/*
	 * Without M_ZERO, the junk INVARIANTS fills a new item with
	 * (trash_ctor()): a word read before it is written is no page and
	 * no NULL, which lets cbmc settle those comparisons itself, and a
	 * pointer read from it is caught as invalid.
	 */
	if ((flags & M_ZERO) == 0)
		__CPROVER_array_set(*p,
		    (CBMC_MALLOC_WORD)0xdeadc0dedeadc0deUL);
	if ((flags & M_WAITOK) == 0 && nondet_bool())
		return (NULL);
	return (p);
}

void
(free)(void *addr, struct malloc_type *type)
{
	if (addr != NULL)
		__CPROVER_deallocate(addr);
}

void malloc_init(void *data) { }
void malloc_uninit(void *data) { }

uma_zone_t zone_mbuf;
bool mb_use_ext_pgs;
u_long maxphys = (1024 * 1024);	/* MAXPHYS of amd64 */

void *
uma_zalloc_arg(uma_zone_t zone, void *arg, int flags)
{
	struct mb_args *args = arg;
	struct mbuf *m;

	__CPROVER_assert(zone == zone_mbuf, "model: only mbufs from UMA");
	/* Typed, so that cbmc does not access each field byte by byte. */
	m = __CPROVER_allocate(sizeof(struct mbuf), 1);
	(void)m_init(m, flags, args->type, args->flags);
	return (m);
}

void
uma_zfree_arg(uma_zone_t zone, void *item, void *udata)
{
	__CPROVER_deallocate(item);
}

/*
 * An unmapped mbuf, as mb_alloc_ext_pgs() in kern_mbuf.c sets it up, with
 * no pages in it yet.
 */
struct mbuf *
mb_alloc_ext_pgs(int how, m_ext_free_t ext_free, int flags)
{
	struct mbuf *m;

	m = m_get(how, MT_DATA);
	m->m_epg_npgs = 0;
	m->m_epg_nrdy = 0;
	m->m_epg_1st_off = 0;
	m->m_epg_last_len = 0;
	m->m_epg_flags = 0;
	m->m_epg_hdrlen = 0;
	m->m_epg_trllen = 0;
	m->m_epg_tls = NULL;
	m->m_epg_so = NULL;
	m->m_data = NULL;
	m->m_flags |= M_EXT | M_EXTPG | flags;
	m->m_ext.ext_flags = EXT_FLAG_EMBREF;
	m->m_ext.ext_count = 1;
	m->m_ext.ext_size = 0;
	m->m_ext.ext_free = ext_free;
	return (m);
}

/* Counters: statistics only. */

counter_u64_t
counter_u64_alloc(int flags)
{
	return (__CPROVER_allocate(sizeof(uint64_t), 1));
}

/* counter_u64_add() adds through %gs; run.sh replaces calls with this. */
void cbmc_counter_u64_add(counter_u64_t c, int64_t inc) { }
void counter_u64_zero(counter_u64_t c) { }
uint64_t counter_u64_fetch(counter_u64_t c) { return (0); }

/*
 * Atomics.  The harness is built with SAN_NEEDS_INTERCEPTORS, as KCSAN
 * builds are, so that machine/atomic.h calls these out-of-line functions
 * rather than inline assembly cbmc cannot read; sequentially, each is the
 * plain operation.
 */

u_int
cbmc_atomic_load_int(const volatile u_int *p)
{
	return (*p);
}

u_short
cbmc_atomic_load_short(const volatile u_short *p)
{
	return (*p);
}

void
cbmc_atomic_store_int(volatile u_int *p, u_int v)
{
	*p = v;
}

u_int
cbmc_atomic_fetchadd_int(volatile u_int *p, u_int v)
{
	u_int old;

	old = *p;
	*p = old + v;
	return (old);
}

/*
 * The only caller is vm_page_xunbusy(), on the busy_lock of a page, which
 * nothing else in the model reads: the page is taken as busied by this
 * thread, and the lock is left alone, which keeps a pointer into the page
 * array out of the formula at every call.
 */
int
cbmc_atomic_cmpset_rel_int(volatile u_int *p, u_int cmp, u_int v)
{
	return (1);
}

int
cbmc_atomic_fcmpset_rel_int(volatile u_int *p, u_int *cmp, u_int v)
{
	if (*p != *cmp) {
		*cmp = *p;
		return (0);
	}
	*p = v;
	return (1);
}

/*
 * The reference counts of sys/refcount.h are retry loops over fcmpset;
 * cbmc unwinds each at every call site, which made up most of the formula.
 * run.sh replaces calls to them with these, which are what they do in one
 * thread, plus the KASSERT()s they make.
 */

u_int
cbmc_refcount_acquire(volatile u_int *count)
{
	return ((*count)++);
}

bool
cbmc_refcount_release(volatile u_int *count)
{
	__CPROVER_assert(*count > 0, "refcount released below zero");
	return (--(*count) == 0);
}

bool
cbmc_refcount_release_if_not_last(volatile u_int *count)
{
	if (*count <= 1)
		return (false);
	(*count)--;
	return (true);
}

void cbmc_atomic_thread_fence_acq(void) { }
void cbmc_atomic_thread_fence_rel(void) { }

void *
cbmc_memset(void *b, int c, size_t len)
{
	return (__builtin_memset(b, c, len));
}

/* Locks. */

void __mtx_lock_flags(volatile uintptr_t *c, int opts, const char *file,
    int line) { }
void __mtx_unlock_flags(volatile uintptr_t *c, int opts, const char *file,
    int line) { }
void __mtx_assert(const volatile uintptr_t *c, int what, const char *file,
    int line) { }
/*
 * A harness modelling another thread that changes what a lock protects
 * defines CBMC_RW_RLOCK_HOOK, called on each read lock taken: whatever it
 * changes, it changes while the lock was not held.
 */
void
__rw_rlock(volatile uintptr_t *c, const char *file, int line)
{
#ifdef CBMC_RW_RLOCK_HOOK
	CBMC_RW_RLOCK_HOOK(c);
#endif
}
void _rw_runlock_cookie(volatile uintptr_t *c, const char *file,
    int line) { }
void __rw_assert(const volatile uintptr_t *c, int what, const char *file,
    int line) { }
int _vn_lock(struct vnode *vp, int flags, const char *file, int line)
{
	return (0);
}
int VOP_UNLOCK_APV(const struct vop_vector *vop, struct vop_unlock_args *a)
{
	return (0);
}
int VOP_INOTIFY_APV(const struct vop_vector *vop, struct vop_inotify_args *a)
{
	return (0);
}
void assert_vop_locked(struct vnode *vp, const char *str) { }
int pause_sbt(const char *wmesg, sbintime_t sbt, sbintime_t pr, int flags)
{
	return (0);
}

#endif /* !_CBMC_MODEL_KERN_H_ */
