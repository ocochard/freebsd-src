# Bounded model checking of system calls with CBMC

This directory proves parts of the kernel with
[CBMC](https://www.cprover.org/cbmc/), a bounded model checker for C.
For each system call, the reference is its manual page.  A harness
states what the manual promises as assertions, and CBMC checks them
against the kernel's own source for every input within the bounds,
not a sample of inputs as a test or a fuzzer would.

    pkg install cbmc
    tools/cbmc/run.sh            # every proof, about 100 minutes
    SLOW=1 tools/cbmc/run.sh     # and the ones over half an hour
    ONLY=nocache tools/cbmc/run.sh   # the jobs whose name matches
    tools/cbmc/run.sh sendfile   # one system call

## Method

- The harness `#include`s the kernel source file whole, so the code
  proven is the kernel's, static functions included, and never a copy.
- Kernel functions defined elsewhere are modelled in `model/kern.h`
  (shared) and in the harness (specific to the call).  Without a body,
  cbmc lets a function return anything and change nothing, which is
  wrong for an allocator or for a function that fills in an output
  argument.
- The build is a module build (`KLD_MODULE`) with `INVARIANTS`, so
  every `KASSERT()` is checked too.  It also defines
  `SAN_NEEDS_INTERCEPTORS`, as KCSAN builds do, so that atomics are
  calls to the model and not inline assembly cbmc cannot read.
- `run.sh` schedules the jobs longest first, as many at once as fit in
  70% of the memory, each counted at the peak it reached on the last
  run plus a margin, or at `CBMC_MEM` until measured (`costs`, which
  every run updates).  cbmc is
  single-threaded and most jobs need a few gigabytes, where a single
  limit for all had allowed 3 at once on a 64-core, 256 GB host.
- `run.sh` runs two passes.  First, every proof must hold on the
  source as it is.  Second, every mutant must fail: a mutant is the
  source with one fix taken back or one check removed.  Each mutant
  is reported with the property that caught it.  A mutation whose
  `sed` no longer applies fails the run, because otherwise it would
  silently prove the unmutated file again.
- A mutant never deletes an indirect call, it puts it under `if (0)`:
  the function pointer restrictions name call sites by their rank in
  the function, and deleting one shifts the others.
- An "open question" is a proof of the manual's wording where it and
  the code disagree and nobody has yet said which one is right.  It is
  expected to fail, and does not fail the run.  There is none at the
  moment.

Bug reports, one per fix, ready to file: `reports/sendfile.md`.

## Model choices forced by cbmc 6.11

Each of these was measured: without it, the proof did not finish or
cbmc crashed.

- Every indirect call is restricted to its real target with
  `goto-instrument --restrict-function-pointer` (the list is in
  `run.sh`).  Otherwise each call is resolved to every function of a
  compatible type.  `pr_abort()`, called through an `sf_io`, reached
  `malloc_init()` and `sendfile_free_mext()`, and that alone made a
  one-page proof time out where it now takes 21 seconds.
- `pagertab[]` is declared in `vm/vm_pager.h` without a size, and cbmc
  aborts ("number of literals in the literal map shall equal the
  bitvector width") once a definition gives it one.  Calls to
  `vm_pager_has_page()` are redirected to a model with
  `goto-instrument --replace-calls`, as are `sf_buf_kva()` (it builds a
  pointer from an integer, which cbmc encodes at great cost),
  `__curthread()` and `counter_u64_add()` (both read `%gs`), and the
  `refcount(9)` retry loops.
- Each page is an object of its own.  An array of `struct vm_page` cost
  59,000 signed divisions in the formula, one per pointer into it, to
  turn its offset into an index.
- An object whose size depends on the input is an opaque array to cbmc,
  and every read from it is unknown.  The `malloc(9)` model therefore
  hands out a fixed-size block, as `malloc(9)` rounds a request up to a
  bucket.  The sendfile harness allocates its `sf_io` typed, with the
  page array sized.  Fresh memory holds the junk `INVARIANTS` fills it
  with, so a word read before it is written is neither a page nor NULL.
  An overrun inside the block goes unseen, as on a kernel without KASAN.
- cbmc cannot tell that the send loop ends when the socket has room for
  everything, and unrolled a further iteration in full.  The socket
  model asserts that no more waits happen than the bounds need, then
  cuts the path there.

## sendfile(2)## sendfile(2)

Harness: `sendfile/sendfile.c`, for `sys/kern/kern_sendfile.c` against
`lib/libsys/sendfile.2`.

Proven:

- the per-page split of a run (`xfsize()`, `vmoff()`) and its trimming
  at a missing page (`fixspace()`);
- every call that queues no page of the file (`offset` at or past EOF,
  an empty file, `nbytes` out of range), with a file of up to two pages
  and a byte and socket writes that may stop short;
- the send loop on a cached file of up to two pages and a byte, in one
  iteration, so that a run has a first, a middle and a last page;
- the send loop in two iterations, on a file of up to a page and a byte,
  with the header split across the socket's room;
- the paging path: pages partly valid or not at all, read by the pager;
- `SF_NODISKIO` with page grabs that stop short, on runs of up to three
  pages: only bytes read from the file are sent;
- all of the above again with unmapped mbufs (`mb_use_ext_pgs`, the
  default for TCP on amd64), plus a six-page run that fills one unmapped
  mbuf (`MBUF_PEXT_MAX_PGS` is 5) and starts another;
- the file truncated or extended by another thread during the call,
  over one and two iterations, wherever `vn_sendfile()` holds no lock
  that keeps the truncation out: for a vnode, while it does not hold
  the vnode lock; for a shared memory object, while it holds neither
  the object lock nor the range lock.  The grab must only take pages
  within the object's size;
- truncation removing pages, as `vm_object_page_remove()` does: it
  waits for busy pages, invalidates wired ones, frees the others.  What
  is delivered is checked against what the pages hold, not their valid
  bits, which an invalidation clears without changing the contents.
  Over the cached resize proofs (a freed page is not grabbed again: a
  cached file has no invalid page) and the paging one, where freed pages
  are grabbed again afresh and the pages replaced with `bogus_page` are
  looked up again after a truncation;
- the partial last page of a truncation, zeroed past the new end in
  place (`vnode_pager_setsize()`, `shm_partial_page_invalidate()`): no
  byte a truncation zeroed is sent, while sendfile holds the file;
- vnodes whose object is not a vnode pager's (tmpfs): the size from
  `vn_getsize_locked()` and `VOP_GETATTR()`, which may fail, the size
  changing during the call, and the vnode unlocked on every error;
- shared memory objects (`DTYPE_SHM`): the cached send, the paging
  path, and resizing; and largepage ones, whose pages are unmanaged and
  wired by the object, and whose size only grows: their release only
  unwires them and never takes the object's own wiring, with unmapped
  mbufs;
- reads of the file that fail, at once (the pager returns the error,
  after running the completion with it, as the vnode pager and ZFS do)
  or later through the completion: a read failing at once fails the call
  with EIO; one failing later tears the socket down with EIO, and the
  pages queued not ready are freed, never delivered.  With unmapped
  mbufs, in 6 minutes; with reads completing after the call returns, in
  33 minutes (`SLOW=1`); with mapped mbufs, on one and two page runs, in
  25 and 39 minutes (36 and 50 GB);
- KTLS, built with `KERN_TLS`, in software, NIC and TOE modes, for any
  page-aligned `max_frame_len` up to 16384: every record handed to
  `ktls_frame()` meets what it asserts (unmapped, at most
  `max_frame_len` bytes), the header is one such record, the pages
  `ktls_enqueue()` encrypts are exactly those queued not ready, header
  record included, and the socket and session references taken are
  dropped once; the socket reference the read completion donates to
  `ktls_enqueue()` included.  On the paging and I/O error paths, in
  software mode on one-page runs, in 22 and 27 minutes; the I/O error
  one needs 60 GB and runs with `SLOW=1 CBMC_MEM=61440`;
- the wiring of the pages: every page the call wires is released
  exactly once, through the kernel's own `sendfile_free_mext()` and
  `sendfile_free_mext_pg()`, when its mbuf is freed.  Checked with
  unmapped mbufs, on the cached KTLS socket and with `SF_NOCACHE`; with
  mapped mbufs one release per page made each proof take over an hour,
  so they leave it out;
- `SF_NOCACHE`: every page sent is released to be freed
  (`VPR_TRYFREE`), but the one the send stopped in when more of it is to
  follow (`EXT_FLAG_CACHE_LAST` for unmapped mbufs), over one and two
  iterations.  With mapped mbufs, 36 minutes, `SLOW=1`;
- the busy state of the pages, on every path above, error paths
  included: every page the grab busies is unbusied exactly once, none
  is left busy when the call and its reads are done, no page is
  delivered while still busy, and what `vm_pager_assert_in()` requires
  of a read holds (consecutive pages, real ones at both ends, each real
  one busied and not all valid).  Busy state lives in
  `sendfile_swapin()` and `sendfile_iodone()`, whatever the mbufs; the
  paging proof with mapped mbufs, at 36 minutes, runs with `SLOW=1`;
- with the paging path, what `sbready()` expects of `pr_ready()`: the
  pages queued `M_NOTREADY`, counted one per mapped mbuf and
  `m_epg_nrdy` per unmapped one, are exactly those readied.  For mapped
  mbufs this takes 36 minutes and runs only with `SLOW=1`.

Against the manual page, every vn_sendfile() proof checks the
following.  The socket receives the whole header, then the file bytes
asked for in file order, then the whole trailer.  `*sbytes` is what it
received.  No chain is longer than the room the socket reported.  Every
`KASSERT()` holds, and there is no invalid memory access.  `offset` is
free, `nbytes` ranges over all of `size_t`, and the header and trailer
take up to 4 or 8 bytes.  The page-content arithmetic (`xfsize()`) is
proven for any run.  Each loop proof takes up to 6 minutes.

Found and fixed on this branch.  Each fix adds a regression test to
`lib/libc/tests/sys/sendfile_test.c`.  In a bhyve guest, the three
tests fail on a kernel built from the base of the branch and pass on
the branch's kernel, and the other 24 cases are unchanged:

| Commit | Bug |
|---|---|
| `sendfile: Send to EOF when nbytes does not fit an off_t` | `nbytes > OFF_MAX`, e.g. `SIZE_MAX`, sent nothing and returned 0 |
| `sendfile: Count a partial trailer in sbytes` | a trailer cut short by EPIPE was left out of `*sbytes` |
| `sendfile: Send the header when there is no file data` | with `offset` at or past EOF, or an empty file, the header was dropped but the trailer sent; regression from 2bab0c553588 |

Manual and code disagreed; settled with the developer:

- A header or trailer write cut short returned 0, `sousrsend()`
  clearing EAGAIN and EINTR once some bytes went out, where the manual
  says `sendfile()` fails: a code bug, fixed by `sendfile: Fail when a
  header or trailer write is cut short`.
- Readahead: the manual said the larger of the application's value and
  the internal one is used, the code adds the two: the manual's
  wording, fixed by `sendfile.2: Say that readahead adds ...`.
- ERRORS lacked a pending socket error, such as ECONNRESET, and EINVAL
  for header or trailer iovecs that `copyinuio()` refuses: missing
  documentation, fixed by `sendfile.2: Document two more errors`.

Open question for the developer (`run.sh` question
`sendfile_resize_window`): sendfile is zero-copy, so the socket later
transmits the pages themselves.  A truncation after `sendfile()` has
queued the data, before the peer reads it, zeroes the bytes past the new
end of the partial last page, while the pages past it, wired by the
mbufs, keep the old data: the peer receives neither the old file nor the
new one.  On 16.0-CURRENT, two pages of `x` truncated to 100 bytes after
`sendfile()` returned arrive as 100 `x`, 3996 zeros, 4096 `x`.
sendfile.2 says nothing of the file changing before transmission.

Found by the loop proofs, fixed on this branch, not yet reported:

- `sendfile: Validate the pages of a short grab over all they send`:
  with `SF_NODISKIO`, when `vm_page_grab_pages_unlocked()` stops short,
  `sendfile_swapin()` checks the validity of the last page grabbed only
  over the bytes a run ending there would use, while `vn_sendfile()`
  sends that page whole.  Bytes of a partly valid page that were never
  read from the file are then queued on the socket.  The counterexample
  is an 8193-byte file whose third page is busy and whose second page
  has its first `DEV_BSIZE` chunk valid but not its fourth.

Found by the resize proofs, fixed on this branch, waiting for the
developer to say whether this is the intended behaviour, since the
manual says nothing of a file that changes size during the call:

- `sendfile: Send the header and trailers when the file shrinks`: when
  the file shrinks below the offset during the call, `vn_sendfile()`
  takes `goto done`.  That drops a header copied in the same iteration
  and skips the trailers, and the call returns 0.  When the offset is
  past the end of the file from the start, the header and trailers are
  sent.  Reproduced on 16.0-CURRENT: a 1 MiB file truncated while a
  blocking `sendfile()` waits for room returns 0 without its trailer.
  The regression test is `trailer_after_truncation`.

Found by the shared memory proofs, fixed on this branch, not yet
reported:

- `sendfile: Keep a shared memory object from shrinking under the
  pages`: for a shared memory object `vn_sendfile()` read the size once
  and held nothing that keeps `shm_dotruncate_locked()` out.  An object
  truncated while sendfile waited for socket buffer space had its pages
  past the new end grabbed again, outside the object's size, and sent
  as zeros: a 1 MiB object truncated to 0 still sent 1 MiB, 960 KiB of
  it zeros, on 16.0-CURRENT.  The regression test is `shm_truncation`.

Not proven yet:

- `ktls_frame()` and `ktls_enqueue()` themselves are
  modelled, not proven; the encryption completes at once.  A
  `kern.ipc.tls.maxlen` that is not a multiple of the page size is not
  explored: the KTLS buffer code asserts it is one.
- Busy state is tracked for this call's own
  pages only; another thread holding a page busy is modelled only as a
  grab that stops short (`SF_NODISKIO`).
- Largepage objects with mapped mbufs, and with
  `SF_NOCACHE`, which cannot free their unmanaged pages.
