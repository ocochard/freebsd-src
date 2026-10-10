# Bounded model checking of system calls with CBMC

This directory proves parts of the kernel with
[CBMC](https://www.cprover.org/cbmc/), a bounded model checker for C.
For each system call, the reference is its manual page.  A harness
states what the manual promises as assertions, and CBMC checks them
against the kernel's own source for every input within the bounds,
not a sample of inputs as a test or a fuzzer would.

    pkg install cbmc
    tools/cbmc/run.sh            # every proof, about 2 seconds
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
- `run.sh` runs two passes.  First, every proof must hold on the
  source as it is.  Second, every mutant must fail: a mutant is the
  source with one fix taken back or one check removed.  Each mutant
  is reported with the property that caught it.  A mutation whose
  `sed` no longer applies fails the run, because otherwise it would
  silently prove the unmutated file again.
- An "open question" is a proof of the manual's wording where it and
  the code disagree and nobody has yet said which one is right.  It is
  expected to fail, and does not fail the run.

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
  pages: only bytes read from the file are sent.

Against the manual page, every vn_sendfile() proof checks the
following.  The socket receives the whole header, then the file bytes
asked for in file order, then the whole trailer.  `*sbytes` is what it
received.  No chain is longer than the room the socket reported.  Every
`KASSERT()` holds, and there is no invalid memory access.  `offset` is
free, `nbytes` ranges over all of `size_t`, and the header and trailer
take up to 4 or 8 bytes.  The page-content arithmetic (`xfsize()`) is
proven for any run.  Each loop proof takes 1 to 6 minutes.

Found and fixed on this branch.  Each fix adds a regression test to
`lib/libc/tests/sys/sendfile_test.c`.  In a bhyve guest, the three
tests fail on a kernel built from the base of the branch and pass on
the branch's kernel, and the other 24 cases are unchanged:

| Commit | Bug |
|---|---|
| `sendfile: Send to EOF when nbytes does not fit an off_t` | `nbytes > OFF_MAX`, e.g. `SIZE_MAX`, sent nothing and returned 0 |
| `sendfile: Count a partial trailer in sbytes` | a trailer cut short by EPIPE was left out of `*sbytes` |
| `sendfile: Send the header when there is no file data` | with `offset` at or past EOF, or an empty file, the header was dropped but the trailer sent; regression from 2bab0c553588 |

Manual and code disagree, waiting for a developer's answer:

- A header or trailer write cut short returns 0 (`sousrsend()` clears
  EAGAIN and EINTR once some bytes went out).  The manual says
  `sendfile()` returns EAGAIN (`run.sh` question
  `sendfile_short_write`).
- Readahead: the manual says the larger of the application's value and
  the internal one is used.  The code adds the two.
- Not in ERRORS: a pending socket error such as ECONNRESET, returned
  from `so_error`; and EINVAL for `hdr_cnt` or `trl_cnt` above
  `IOV_MAX`.

Found by the loop proofs, fixed on this branch, not yet reported:

- `sendfile: Validate the pages of a short grab over all they send`:
  with `SF_NODISKIO`, when `vm_page_grab_pages_unlocked()` stops short,
  `sendfile_swapin()` checks the validity of the last page grabbed only
  over the bytes a run ending there would use, while `vn_sendfile()`
  sends that page whole.  Bytes of a partly valid page that were never
  read from the file are then queued on the socket.  The counterexample
  is an 8193-byte file whose third page is busy and whose second page
  has its first `DEV_BSIZE` chunk valid but not its fourth.

Not proven yet:

- The unmapped mbuf path (`mb_use_ext_pgs`, the default for TCP on
  amd64) and KTLS: the model has `mb_use_ext_pgs` off.
- An I/O error from the pager, and a file that shrinks during the call
  (suspected: that `goto done` drops a header built in the same
  iteration and skips the trailer, returning 0).
- Shared memory objects (`DTYPE_SHM`) and `vn_getsize_locked()` objects.
