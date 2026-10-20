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
 * cbmc(1) harness for m_uiotombuf() with M_EXTPG, sys/kern/uipc_mbuf.c,
 * that is m_uiotombuf_nomap(): how sosend_generic() and sendfile(2) cut
 * a user's data into the records of a socket with a TLS send session.
 *
 * Not a program: run.sh compiles it with SOURCE naming uipc_mbuf.c or a
 * mutant of it, included whole.  The page allocator and
 * uiomove_fromphys() are modelled by what they are given.  The
 * reference is what its callers take it to do: a chain of unmapped
 * mbufs of new anonymous pages, holding the first len bytes of the uio
 * (all of it when len is 0), at most maxseg each, or one empty mbuf
 * when there is nothing to copy; NULL when the copy faults, with no
 * page kept.  The one entry point, for --function:
 *
 *   proof_nomap	m_uiotombuf() with M_EXTPG on a uio of any length up
 *			to two records and any record length up to 16K
 */

#include SOURCE

#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/ktls.h>
#include "kern.h"

#define	NR	3		/* mbufs in the chain */
#define	WPAGES	(NR * MBUF_PEXT_MAX_PGS)
#define	NEWPA(i)	((vm_paddr_t)(1UL << 40) + ptoa(i))

static struct vm_page *g_pg[WPAGES];
static bool g_pgfreed[WPAGES];
static int g_npg, g_fail, g_copied;
static struct uio g_uio;

/* A new page, wired, or none once: then vm_wait() and a retry. */
vm_page_t
vm_page_alloc_noobj(int req)
{
	vm_page_t pg;

	__CPROVER_assert((req & VM_ALLOC_WIRED) != 0, "a wired page");
	if (!g_fail && nondet_bool()) {
		g_fail = 1;
		return (NULL);
	}
	__CPROVER_assert(g_npg < WPAGES, "model: pages allocated");
	pg = __CPROVER_allocate(sizeof(struct vm_page), 1);
	pg->phys_addr = NEWPA(g_npg);
	pg->ref_count = 1;
	g_pg[g_npg++] = pg;
	return (pg);
}

void vm_wait(vm_object_t obj) { }

static int
pgidx(vm_paddr_t pa)
{
	__CPROVER_assert(pa >= NEWPA(0) && pa < NEWPA(g_npg) &&
	    (pa & PAGE_MASK) == 0, "a page m_uiotombuf() allocated");
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

	__CPROVER_assert(!g_pgfreed[i] && pg->ref_count == 0,
	    "a page freed once, unwired");
	g_pgfreed[i] = true;
}

/*
 * uiomove_fromphys(), uio_machdep.c: n bytes from the uio into the
 * pages from offset, or part of them and a fault.
 */
int
uiomove_fromphys(vm_page_t ma[], vm_offset_t offset, int n, struct uio *uio)
{
	int i, k;

	__CPROVER_assert(offset == 0 && n > 0 && n <= uio->uio_resid,
	    "copies bytes the uio has");
	for (i = 0; i < MBUF_PEXT_MAX_PGS; i++)
		if (ptoa(i) < n)
			__CPROVER_assert(ma[i] != NULL &&
			    ma[i]->phys_addr == NEWPA(pgidx(ma[i]->phys_addr)) &&
			    !g_pgfreed[pgidx(ma[i]->phys_addr)],
			    "into pages allocated for them");
	if (nondet_bool()) {
		k = nondet_int();
		__CPROVER_assume(k >= 0 && k < n);
		uio->uio_resid -= k;
		return (EFAULT);
	}
	uio->uio_resid -= n;
	g_copied += n;
	return (0);
}

/* m_freem(), kern_mbuf.c, for unmapped mbufs of anonymous pages. */
void
m_freem(struct mbuf *m)
{
	struct mbuf *n;
	int i;

	for (i = 0; i < NR + 1 && m != NULL; i++) {
		__CPROVER_assert(m->m_ext.ext_free == mb_free_mext_pgs,
		    "freed with its pages");
		n = m->m_next;
		mb_free_mext_pgs(m);
		m = n;
	}
	__CPROVER_assert(m == NULL, "model: mbufs freed");
}

void
proof_nomap(void)
{
	struct mbuf *m, *top;
	ssize_t resid, total;
	int i, len, maxseg, n, npg, seg;

	maxseg = nondet_int();
	__CPROVER_assume(maxseg >= 0 && maxseg <= TLS_MAX_MSG_SIZE_V10_2);
	seg = maxseg == 0 ? MBUF_PEXT_MAX_PGS * PAGE_SIZE : maxseg;
	len = nondet_int();
	__CPROVER_assume(len >= 0);
	g_uio.uio_resid = nondet_int();
	__CPROVER_assume(g_uio.uio_resid >= 0);
	resid = g_uio.uio_resid;
	total = len > 0 && len < resid ? len : resid;
	__CPROVER_assume(total <= (NR - 1) * seg);

	top = m_uiotombuf(&g_uio, M_WAITOK, len, maxseg, M_EXTPG);

	if (top == NULL) {
		__CPROVER_assert(total > 0, "nothing to copy gives an mbuf");
		for (i = 0; i < WPAGES; i++)
			if (i < g_npg)
				__CPROVER_assert(g_pgfreed[i],
				    "on a fault, every page is freed");
		return;
	}
	__CPROVER_assert(g_uio.uio_resid == resid - total,
	    "the uio gives exactly the bytes asked for");
	n = 0;
	npg = 0;
	m = top;
	for (i = 0; i < NR; i++) {
		if (m == NULL)
			break;
		__CPROVER_assert((m->m_flags & (M_EXT | M_EXTPG)) ==
		    (M_EXT | M_EXTPG) && (m->m_flags & M_PKTHDR) == 0 &&
		    m->m_epg_flags == EPG_FLAG_ANON,
		    "an unmapped mbuf of anonymous pages");
		__CPROVER_assert(m->m_len <= seg && (m->m_len > 0 ||
		    total == 0), "a record of at most maxseg bytes, not empty");
		__CPROVER_assert(m->m_next == NULL || m->m_len == seg,
		    "each record but the last is full");
		__CPROVER_assert(m->m_epg_1st_off == 0 &&
		    m->m_epg_npgs == howmany(m->m_len, PAGE_SIZE) &&
		    (m->m_len == 0 || m->m_epg_last_len ==
		    m->m_len - ptoa(m->m_epg_npgs - 1)) &&
		    m->m_ext.ext_size == ptoa(m->m_epg_npgs),
		    "its pages hold its bytes, the last one its tail");
		n += m->m_len;
		npg += m->m_epg_npgs;
		m = m->m_next;
	}
	__CPROVER_assert(m == NULL && n == total,
	    "the chain holds the bytes copied");
	__CPROVER_assert(npg == g_npg, "every page allocated is in the chain");
	for (i = 0; i < WPAGES; i++)
		if (i < g_npg)
			__CPROVER_assert(!g_pgfreed[i], "no page of it freed");
}
