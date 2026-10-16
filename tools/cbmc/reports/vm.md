# VM bug reports

Bugs found by the CBMC proofs of `tools/cbmc/sendfile` that lie in the VM,
ready to file.  The fix is named by commit subject, which is stable, and by
hash on the `cbmc` branch, which changes when the branch is rebased: look the
hash up again before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | vnode_pager_generic_getpages() skips the async completion on its no-I/O and valid-last-page paths | [ad89fd83a152](https://github.com/ocochard/freebsd-src/commit/ad89fd83a152) | ready, developer confirmed the contract |

---

## 1. vnode_pager_generic_getpages() does not run the async completion on every page

**Status: the VM maintainer (kib@) confirmed the contract: "the completion
callback must be called for all pages."**

**Fix:** ad89fd83a152 "vm: Run the getpages completion on every requested page"
(`Fixes: 90effb23412f`)

**What happens:** `vnode_pager_generic_getpages()`
(`sys/vm/vnode_pager.c`), called asynchronously (`iodone != NULL`), must call
`iodone` once over every requested page.  The two wrappers,
`ffs_getpages_async()` and `vnode_pager_local_getpages_async()`, call `iodone`
themselves only when the generic routine returns an error, and trust it to call
`iodone` on every `VM_PAGER_OK` return.  Four paths return `VM_PAGER_OK` (or an
already-valid run) without doing so:

- the `VOP_BMAP()` `EOPNOTSUPP` fallback (`vnode_pager_input_old()`), on success;
- the small-block path, `pagesperblock == 0` (`vnode_pager_input_smlfs()`), on
  success;
- a sparse page, `bp->b_blkno == -1`;
- a run whose last page is already valid: `--count` drops it and the real-I/O
  completion then runs on `count - 1` pages, leaving the dropped page xbusy.

On any of these the asynchronous caller's completion is never run for those
pages.  A caller that keeps a per-request I/O count (as sendfile does, one
`refcount_acquire()` per `vm_pager_get_pages_async()` call) never reaches zero:
the request hangs, and the un-completed page stays exclusive-busy for good.

**Reachability:** no in-tree caller triggers it.  sendfile(2), the only
asynchronous `vm_pager_get_pages_async()` caller, calls `vm_pager_has_page()`
first, under the vnode lock it holds across the call, trims a run's valid
trailing pages itself, and runs only on UFS, which always has `VOP_BMAP()` with
a block of at least a page.  So every one of the four paths is unreachable from
it.  The bug is against the interface contract, for a future asynchronous
caller or a non-UFS file system.

**Fix detail:** run `iodone(arg, m, count, 0)` before the `VM_PAGER_OK` return
on each no-I/O success path (the error returns are left to the wrappers, which
already handle them, so there is no double call); and, for the valid last page,
suppress the trim when `iodone != NULL` so the single real-I/O completion covers
the whole run.

**Reproduce:** no test: no caller reaches these paths.  The CBMC
counterexamples (`run.sh` mutants `pager_nocomplete_bmap`,
`pager_nocomplete_smlfs`, `pager_nocomplete_sparse`, `pager_lastvalid_trim`,
each taking one line of the fix back): the completion is run zero times, or on
`count - 1` of `count` pages.

**Found by:** the property of `vnode_pager_generic_getpages()` "success, and the
completion runs once on the run it was given" (`proof_getpages`,
`sendfile/pager.c`), on the no-I/O and valid-last-page shapes (`run.sh` proofs
`pager_nobmap`, `pager_smlfs`, `pager_lastvalid`).
