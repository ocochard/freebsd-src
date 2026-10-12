# Bounded model checking of system calls with CBMC

Proofs of kernel code with [CBMC](https://www.cprover.org/cbmc/), a
bounded model checker for C.  The reference is the system call's manual
page: a harness states what it promises as assertions, and CBMC checks
them against the kernel's own source for every input within the bounds.

    pkg install cbmc
    tools/cbmc/run.sh                # every proof, about 100 minutes
    SLOW=1 tools/cbmc/run.sh         # and the ones over half an hour
    ONLY=nocache tools/cbmc/run.sh   # the jobs whose name matches

## sendfile(2): fixes

Each fix comes with a regression test in
`lib/libc/tests/sys/sendfile_test.c` (but #4), which fails on the base
kernel and passes with the fix in a bhyve guest.  Bug reports, ready to
file: [reports/sendfile.md](reports/sendfile.md).

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | `nbytes` above `OFF_MAX` (e.g. `SIZE_MAX`) sends nothing and returns 0 | [b8708a7c4d8e](https://github.com/ocochard/freebsd-src/commit/b8708a7c4d8e) | ready |
| 2 | a trailer cut short by EPIPE is left out of `*sbytes` | [40f5b7d9c7a6](https://github.com/ocochard/freebsd-src/commit/40f5b7d9c7a6) | ready |
| 3 | with no file data (offset past EOF, empty file) the header is dropped | [42f012912f61](https://github.com/ocochard/freebsd-src/commit/42f012912f61) | ready |
| 4 | `SF_NODISKIO` with a short page grab sends bytes never read from the file | [5ffb5c5fb98c](https://github.com/ocochard/freebsd-src/commit/5ffb5c5fb98c) | sent privately to glebius@ |
| 5 | a file truncated during the call loses its header and trailer | [6ee7ec9c8778](https://github.com/ocochard/freebsd-src/commit/6ee7ec9c8778) | waiting for the developer |
| 6 | a short header or trailer write is reported as success | [67d6e7e09420](https://github.com/ocochard/freebsd-src/commit/67d6e7e09420) | confirmed by the developer |
| 7 | a shared memory object truncated during the call is sent as zeros | [20c3302e9d29](https://github.com/ocochard/freebsd-src/commit/20c3302e9d29) | ready |
| 8 | sendfile.2: readahead is added to the internal one, not the larger used | [a5bf794ee696](https://github.com/ocochard/freebsd-src/commit/a5bf794ee696) | confirmed by the developer |
| 9 | sendfile.2: document EINVAL for bad iovecs and pending socket errors | [c602ed263a2b](https://github.com/ocochard/freebsd-src/commit/c602ed263a2b) | confirmed by the developer |

Open question: sendfile is zero-copy, so a file truncated after
`sendfile()` returns, before the peer reads, arrives part old, part
zeroed (two pages of `x` truncated to 100 bytes: 100 `x`, 3996 zeros,
4096 `x`).  sendfile.2 says nothing of the file changing before
transmission (`run.sh` question `sendfile_resize_window`).

## sendfile(2): what is proven

Harness `sendfile/sendfile.c`, for `sys/kern/kern_sendfile.c`.  Every
proof checks the manual's contract (the whole header, then the file
bytes asked for in order, then the whole trailer; `*sbytes` is what the
socket received), memory safety, every `KASSERT()`, and that the call
leaves no lock, page busy state or reference behind.  `offset` and
`nbytes` are free; files span up to three pages (six for one case).

- calls that send no file data; the send loop over one and two
  iterations; the paging path; `SF_NODISKIO` short grabs
- mapped and unmapped (`mb_use_ext_pgs`) mbufs, KTLS (software, NIC,
  TOE), `SF_NOCACHE`
- vnodes, tmpfs-like vnodes (size from `VOP_GETATTR()`), shared memory
  and largepage shared memory objects
- I/O errors, at once and after the call; the file truncated or grown
  during the call, with page removal and partial-page zeroing
- page wiring released once, busy state, what `sbready()`,
  `ktls_frame()` and `vm_pager_assert_in()` require

Each property is shown to bite by a mutant, the source with one fix or
check taken back, which `run.sh` requires to fail.

Not covered: `ktls_frame()`/`ktls_enqueue()` themselves (modelled), a
page busied by another thread (only as a short grab), largepage objects
with mapped mbufs.

## How it works

- The harness `#include`s the kernel source whole: the code proven is
  the kernel's own.  Kernel functions defined elsewhere are modelled in
  `model/kern.h` and the harness.
- Built as a module with `INVARIANTS` (so `KASSERT()`s are checked) and
  `SAN_NEEDS_INTERCEPTORS` (so atomics are model calls, not assembly).
- `run.sh` proves every proof, requires every mutant to fail, and
  reports open questions without failing.  It runs the longest jobs
  first, as many as fit in 70% of the memory at their last measured
  peak (`costs`), and reruns alone a job that ran out of memory.

Model choices CBMC 6.11 forced, each measured:

- indirect calls restricted to their real target
  (`--restrict-function-pointer`): unrestricted, a one-page proof timed
  out, restricted it takes 21 seconds;
- `vm_pager_has_page()`, `sf_buf_kva()`, `__curthread()`,
  `counter_u64_add()` and `refcount(9)` replaced by models
  (`--replace-calls`): a sizeless `pagertab[]`, integer-to-pointer
  casts, `%gs` reads and retry loops made CBMC crash or blow up;
- one object per page, fixed-size typed `malloc(9)` blocks: arrays of
  structures and input-sized objects cost tens of thousands of
  divisions and array reads;
- the send loop cut past the iterations the bounds need, and page
  release left out with mapped mbufs, where it cost over an hour.

A mutant puts an indirect call under `if (0)` rather than deleting it,
which would shift the call sites the restrictions name.  Never edit
`run.sh` while a run uses it: `sh` reads it as it goes.
