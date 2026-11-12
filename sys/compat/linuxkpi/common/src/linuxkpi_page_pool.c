/*
 * Copyright (c) 2025-2026 The FreeBSD Foundation
 *
 * This software was developed by Björn Zeeb under sponsorship from
 * the FreeBSD Foundation.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <linux/types.h>
#include <linux/dma-mapping.h>
#include <net/page_pool/helpers.h>

#ifndef PAGE_IS_LKPI_PAGE
#include <sys/lock.h>
#include <sys/mutex.h>

/*
 * Without a LinuxKPI struct page there is nowhere to keep the pool and the
 * DMA address on the page, so track the pages we hand out in a hash table.
 */
struct lkpi_pp_page {
	struct lkpi_pp_page		*next;
	struct page			*page;
	struct device			*dev;
	dma_addr_t			dma;
	enum dma_data_direction		dir;
	bool				mapped;
};

#define	LKPI_PP_HASH_SIZE	1024
static struct lkpi_pp_page *lkpi_pp_hash[LKPI_PP_HASH_SIZE];
static struct mtx lkpi_pp_mtx;
MTX_SYSINIT(lkpi_pp_mtx, &lkpi_pp_mtx, "lkpi page pool", MTX_DEF);

static inline u_int
lkpi_pp_hash_idx(const struct page *p)
{

	return (((uintptr_t)p / sizeof(*p)) % LKPI_PP_HASH_SIZE);
}

/* Returns the link pointing at the entry for p, or at the chain's NULL end. */
static struct lkpi_pp_page **
lkpi_pp_lookup(const struct page *p)
{
	struct lkpi_pp_page **pppp;

	mtx_assert(&lkpi_pp_mtx, MA_OWNED);
	for (pppp = &lkpi_pp_hash[lkpi_pp_hash_idx(p)]; *pppp != NULL;
	    pppp = &(*pppp)->next)
		if ((*pppp)->page == p)
			break;
	return (pppp);
}
#endif

struct page_pool *
linuxkpi_page_pool_create(const struct page_pool_params *ppparams)
{
	struct page_pool *pp;
	int error;

	pp = kzalloc_node(sizeof(*pp), GFP_KERNEL, ppparams->nid);
	if (pp == NULL)
		return (ERR_PTR(-ENOMEM));

	pp->params = *ppparams;

	if ((pp->params.flags & PP_FLAG_DMA_MAP) != 0) {
		if (pp->params.dma_dir != DMA_FROM_DEVICE &&
		    pp->params.dma_dir != DMA_BIDIRECTIONAL) {
			pr_warn_once("%s: invalid dma_dir %#04x\n",
			    __func__, pp->params.dma_dir);
			error = -EINVAL;
			goto free_pp;
		}
	}

	if ((pp->params.flags & PP_FLAG_DMA_SYNC_DEV) != 0) {
		if ((pp->params.flags & PP_FLAG_DMA_MAP) == 0) {
			pr_warn_once("%s: DMA_SYNC_DEV but no DMA_MAP\n",
			    __func__);
			error = -EINVAL;
			goto free_pp;
		}

		if (pp->params.max_len == 0) {
			pr_warn_once("%s: max_len unset\n", __func__);
			error = -EINVAL;
			goto free_pp;
		}
	}

	return (pp);

free_pp:
	kfree(pp);
	return (ERR_PTR(error));
}

void
linuxkpi_page_pool_destroy(struct page_pool *pp)
{
	kfree(pp);
}

/* ---------------------------------------------------------------------------- */

struct page *
linuxkpi_page_pool_alloc_frag(struct page_pool *pp, uint32_t *offset,
    size_t size, gfp_t gfp)
{
#ifdef PAGE_IS_LKPI_PAGE
	struct page *p;
	dma_addr_t dma;

	if (size > PAGE_SIZE) {
		pr_warn_once("%s: size %zu > PAGE_SIZE\n", __func__, size);
		return (NULL);
	}

	/*
	 * We do not try to be smart on the first cut until 'struct page' work
	 * is sorted and settled.  Everyone gets a page for now.
	 * XXX in the future deal with page fragments, pool limits, etc.
	 */
	p = alloc_page(gfp);
	if (p == NULL)
		return (NULL);

	if (offset != NULL)
		*offset = 0;

	if ((pp->params.flags & PP_FLAG_DMA_MAP) != 0) {
		dma = dma_map_page_attrs(pp->params.dev, p, 0, PAGE_SIZE,
		    pp->params.dma_dir, DMA_ATTR_SKIP_CPU_SYNC);
		if (dma_mapping_error(pp->params.dev, dma)) {
			put_page(p);
			return (NULL);
		}

		/* We store the dma address in struct page as well. */
		p->dma_addr = dma;
	}

	if ((pp->params.flags & PP_FLAG_DMA_SYNC_DEV) != 0)
		dma_sync_single_for_device(pp->params.dev, dma, PAGE_SIZE,
		    pp->params.dma_dir);

	/*
	 * We may not yet need to track the page pool on the page in order
	 * to know where to return it but prepare at least for that.
	 */
	p->pp = pp;

	return (p);
#else
	struct lkpi_pp_page *ppp;
	struct page *p;

	if (size > PAGE_SIZE) {
		pr_warn_once("%s: size %zu > PAGE_SIZE\n", __func__, size);
		return (NULL);
	}

	ppp = kzalloc(sizeof(*ppp), gfp);
	if (ppp == NULL)
		return (NULL);
	p = alloc_page(gfp);
	if (p == NULL) {
		kfree(ppp);
		return (NULL);
	}
	ppp->page = p;
	ppp->dev = pp->params.dev;
	ppp->dir = pp->params.dma_dir;

	if ((pp->params.flags & PP_FLAG_DMA_MAP) != 0) {
		ppp->dma = dma_map_page_attrs(ppp->dev, p, 0, PAGE_SIZE,
		    ppp->dir, DMA_ATTR_SKIP_CPU_SYNC);
		if (dma_mapping_error(ppp->dev, ppp->dma)) {
			put_page(p);
			kfree(ppp);
			return (NULL);
		}
		ppp->mapped = true;
		if ((pp->params.flags & PP_FLAG_DMA_SYNC_DEV) != 0)
			dma_sync_single_for_device(ppp->dev, ppp->dma,
			    PAGE_SIZE, ppp->dir);
	}

	if (offset != NULL)
		*offset = 0;

	mtx_lock(&lkpi_pp_mtx);
	ppp->next = lkpi_pp_hash[lkpi_pp_hash_idx(p)];
	lkpi_pp_hash[lkpi_pp_hash_idx(p)] = ppp;
	mtx_unlock(&lkpi_pp_mtx);

	return (p);
#endif /* PAGE_IS_LKPI_PAGE */
}

struct page *
linuxkpi_page_pool_dev_alloc_frag(struct page_pool *pp, uint32_t *offset,
    size_t size)
{
	gfp_t gfp;

	gfp = (GFP_ATOMIC | __GFP_NOWARN);
	return (page_pool_alloc_frag(pp, offset, size, gfp));
}

void
linuxkpi_page_pool_put_full_page(struct page_pool *pp, struct page *page,
    bool allow_direct)
{
	/* We just free the full page we handed out for now. */
#ifdef PAGE_IS_LKPI_PAGE
	page->pp = NULL;
	page->dma_addr = 0;
#else
	struct lkpi_pp_page **pppp, *ppp;

	/* pp may be garbage here: callers derive it from the page. */
	mtx_lock(&lkpi_pp_mtx);
	pppp = lkpi_pp_lookup(page);
	ppp = *pppp;
	if (ppp != NULL)
		*pppp = ppp->next;
	mtx_unlock(&lkpi_pp_mtx);
	if (ppp != NULL) {
		if (ppp->mapped)
			dma_unmap_page_attrs(ppp->dev, ppp->dma, PAGE_SIZE,
			    ppp->dir, DMA_ATTR_SKIP_CPU_SYNC);
		kfree(ppp);
	}
#endif
	put_page(page);
}

dma_addr_t
linuxkpi_page_pool_get_dma_addr(const struct page *page)
{

	KASSERT(page != NULL, ("%s: page %p\n", __func__, page));

#ifdef PAGE_IS_LKPI_PAGE
	return (page->dma_addr);
#else
	struct lkpi_pp_page *ppp;
	dma_addr_t dma;

	mtx_lock(&lkpi_pp_mtx);
	ppp = *lkpi_pp_lookup(page);
	dma = (ppp != NULL) ? ppp->dma : 0;
	mtx_unlock(&lkpi_pp_mtx);
	return (dma);
#endif
}
