# VM bug reports

Bugs found by the CBMC proofs under `tools/cbmc/sendfile`, in the VM
interface those proofs model, one report each.  Each names its fix by
commit subject, which is stable, and by hash on the `cbmc` branch, which
changes when the branch is rebased: look the hash up again before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | async `VOP_GETPAGES` skips the completion on its no-I/O exits | [987722b47487](https://github.com/ocochard/freebsd-src/commit/987722b47487) | confirmed by the developer (kib@) |

---

## 1. async VOP_GETPAGES skips the completion on its no-I/O exits

**Fix:** 987722b47487 "vm: Run the getpages completion on every requested
page"

**What happens:** `vnode_pager_generic_getpages()` run asynchronously
(`iodone != NULL`) must call the completion once, over every requested
page `m[0..count)`.  Four exits that read no disk break that:

- a run whose last page is already valid up to the end of the file:
  `--count` drops that page, I/O runs on the rest, and the completion
  covers only those; the dropped page is never unbusied or passed to the
  callback.
- a file system without `VOP_BMAP()` (`vnode_pager_input_old`) and a
  block smaller than a page (`vnode_pager_input_smlfs`): on success they
  return `VM_PAGER_OK` with no completion.
- a sparse-file hole (`bp->b_blkno == -1`): returns `VM_PAGER_OK` with no
  completion.

The only in-tree async caller is sendfile(2), which asks
`vm_pager_has_page()` first under the vnode lock, and runs on UFS, which
has `VOP_BMAP()`; so it reaches none of the four paths and nothing
crashes today.  But the interface is wrong against the confirmed
contract, and a future async caller would hang: sendfile does one
`refcount_acquire(&sfio->nios)` per `vm_pager_get_pages_async()` call and
`sendfile_iodone()` does one release per callback, so a skipped callback
leaves `nios` above zero and the request never completes (a doubled one
would underflow it).

**Why:** `count` is decremented only on the valid-last-page path; the
other three keep the full run but return without a callback.  The async
completion contract came in with the KPI change that added the `iodone`
argument; these no-I/O exits predate an async caller and were never
updated.

**The contract:** kib@, on the two open questions the proof left: "I
think that yes, the completion callback must be called for all pages."

**Fix:** for an async request, do not trim the valid last page (so the
full run flows to the one `done_async` completion), and call the callback
on the full run before returning from the three no-I/O exits.  The
failure returns of the two input loops still fall through to
`vnode_pager_local_getpages_async()`, which runs the callback on a
nonzero return, so they are left alone.

**Reproduce:** no in-tree caller reaches these paths, so there is no
userspace test; the CBMC proofs `pager_lastvalid`, `pager_nobmap` and
`pager_smlfs` hold with the fix, and the mutants `pager_lasttrim`,
`pager_oldnodone`, `pager_smlnodone` and `pager_holenodone`, which take
each part back, fail without it.

**Found by:** the property "on success the completion runs once, on the
whole run it was given", over a run of up to three pages, read-behind and
read-ahead asked for or not, with any block map, and over the no-I/O
exits (`tools/cbmc/sendfile/pager.c`).

**Fixes:** b0cd20172d85 ("A change to KPI of vm_pager_get_pages() and
underlying VOP_GETPAGES().")
