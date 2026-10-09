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

- `pagertab[]` is declared in `vm/vm_pager.h` without a size, and cbmc
  aborts ("number of literals in the literal map shall equal the
  bitvector width") once a definition gives it one.  Calls to
  `vm_pager_has_page()` are therefore redirected to a model with
  `goto-instrument --replace-calls`.
- `sf_buf_kva()` builds a direct map pointer from an integer, and
  cbmc's integer-to-pointer encoding dominated the formula.  It is
  redirected to a pointer into a modelled page data array.
- An array of `struct vm_page` cost 59,000 signed divisions in the
  formula: every pointer into it becomes an index, its offset divided
  by the 104-byte size.  Each page is therefore an object of its own.
- An object allocated untyped is read byte by byte, which gave 743,000
  array selects for `sfio->pa[i]` alone.  The `malloc(9)` model
  allocates pointer-sized words instead.
- The `refcount(9)` retry loops are unwound at every call site, so
  they are replaced by their one-thread meaning, keeping the
  underflow check.

## sendfile(2)

Harness: `sendfile/sendfile.c`, for `sys/kern/kern_sendfile.c` against
`lib/libsys/sendfile.2`.

Proven: the per-page split of a run (`xfsize()`, `vmoff()`), and its
trimming at a missing page (`fixspace()`).  Also every call to
`vn_sendfile()` that queues no page of the file, checked against the
manual: the socket receives the whole header, then the file bytes
asked for, then the whole trailer, and `*sbytes` is what it received.
Inputs: any `offset`, any `nbytes` over all of `size_t`, a file of up
to two pages and a byte, a header and a trailer of up to 8 bytes, and
socket writes that may stop short.

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

Not proven yet:

- The send loop itself, with file pages.  The harness has it,
  `proof_send` and `proof_nodiskio`, but its formula exceeds 32 GB
  even for one loop iteration over one page.  These two are not in
  `run.sh`.
- Suspected and unproven, for `proof_nodiskio`: with `SF_NODISKIO` and
  a short page grab, `sendfile_swapin()` checks the validity of the
  last grabbed page with `xfsize(i, grabbed, ...)`, while
  `vn_sendfile()` sends that page whole.
- Suspected and unproven: when the file shrinks below the offset
  during the call, `vn_sendfile()` takes `goto done`.  That drops a
  header built in the same iteration and skips the trailer, and the
  call returns 0.
