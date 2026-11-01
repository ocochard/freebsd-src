# CBMC findings: open questions for maintainers

Three memory-safety observations the CBMC proofs under `tools/cbmc` surfaced,
each a question rather than a filed bug: none is a demonstrated in-tree
exploit, and each turns on a precondition a caller currently establishes.
This is the one-page relay; the full analysis, with the `To:`/`Subject:` for
each, is in the linked report, and each harness reproduces the finding.

Branch `cbmc` (re-check the latest hash before filing; it moves on rebase).
"Found with CBMC."

---

## The three questions

1. **kern_mlock(): should a `round_page(addr+len)` wrap be rejected?**
   `mlock(0, (size_t)-1)` (page-aligned `addr`, `len` in the last page)
   returns success having wired nothing: `end = round_page(last)` wraps to 0,
   the `end < addr` guard misses it (0 < 0), `npages = atop(0 - 0) = 0`.  Not
   memory-safety -- a well-formed 0-length range reaches `vm_map_wire()` --
   but a contract violation: the caller believes the range is wired.
   `kern_mmap()` catches the equivalent wrap with `if (len > size) return
   (ENOMEM)`; `kern_mlock()` has no such check.  Reachable: `sys_mlock()`
   passes `uap->addr`/`uap->len` unclamped.
   **Question:** add the `kern_mmap`-style rounded-length check to
   `kern_mlock()`?
   Report: `reports/vm.md` #2.  Harness: `tools/cbmc/mmap/mlock_len.c`
   (`mlock_len`, mutant `mlock_wrap`).  To: markj@ / kib@.

2. **sbcreatecontrol(): should a `size` whose `CMSG_SPACE` wraps be refused?**
   For a `size` where `_ALIGN(size)` overflows `u_int` (e.g. `0xfffffff9`),
   `CMSG_SPACE(size)` collapses to 16, the plain-mbuf path is taken, and the
   payload `memcpy(CMSG_DATA(cp), p, size)` copies the full `size` bytes --
   far past the mbuf.  Not reachable in-tree: the variable-size callers bound
   `size` to a packet (`ip6_input`: `(u8+1)<<3 <= 2048`) or pass `p == NULL`
   so the copy is skipped (`uipc_usrreq`); the rest pass `sizeof(...)`.  So it
   is a latent gap that would bite a future or out-of-tree caller.
   **Question:** add a guard (e.g. `if (size > CMSG_SPACE(size)) return
   (NULL);`) so the wrap cannot undersize the mbuf?
   Report: `reports/socket.md` #1.  Harness:
   `tools/cbmc/sockbuf/sbcreatecontrol.c` (`sbctl_small`/`sbctl_fit`, open
   question `sbctl_wrap`).  To: the socket-layer maintainers.

3. **sl_uncompress_tcp_core(): should the VJ decoder bound the buffer before
   the DECODE walk?**
   On `TYPE_COMPRESSED_TCP` the decoder reads 1-3 bytes per changed field
   through the `DECODE` macros and checks the consumed length only afterward
   (`vjlen = cp - buf; if (buflen < 0) bad`).  A compressed packet shorter
   than its change mask demands is read past before that check.  The `ng_vjc`
   caller pulls up `min(MAX_VJHEADER = 19, pkthdr.len)`, which covers the
   19-byte worst case only when `pkthdr.len >= 19`; a shorter packet reads up
   to `19 - pkthdr.len` bytes past its valid data (within mbuf storage in the
   common case) and is tossed afterward.  Latent read-past, not a
   demonstrated exploit.
   **Question:** add a lower bound on `buflen` (or a per-`DECODE` bound)
   before the walk, turning the optimistic read into an early reject?
   Report: `reports/net.md` #1.  Harness: `tools/cbmc/slcompress/compress.c`
   (open question `slcmp_short`); the uncompressed path is proven
   (`slunc_small`/`slunc_big`).  To: the networking maintainers.

---

## Standing position

No kernel change has been made for any of these: the proofs and this relay are
to get a maintainer's read first.  If one confirms a direction, the fix goes
in as a separate, reviewed freebsd-src commit (kernel fix first, then the
tools/cbmc update), per the usual flow.  The one earlier finding that was
confirmed and fixed -- the async `VOP_GETPAGES` completion contract
(`reports/vm.md` #1, kib@) -- followed that path.
