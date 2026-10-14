# Bounded model checking of system calls with CBMC

Proofs of kernel code with [CBMC](https://www.cprover.org/cbmc/), a
bounded model checker for C.  The reference is the system call's manual
page: a harness states what it promises as assertions, and CBMC checks
them against the kernel's own source for every input within the bounds.

    pkg install cbmc
    tools/cbmc/run.sh                # every proof, about three hours
    SLOW=1 tools/cbmc/run.sh         # and the ones over half an hour
    ONLY=nocache tools/cbmc/run.sh   # the jobs whose name matches
    tools/cbmc/run.sh ktls           # one harness: sendfile or ktls

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
  and largepage shared memory objects, with mapped and unmapped mbufs
- I/O errors, at once and after the call; the file truncated or grown
  during the call, with page removal and partial-page zeroing
- page wiring released once, busy state, what `sbready()`,
  `ktls_frame()` and `vm_pager_assert_in()` require

Each property is shown to bite by a mutant, the source with one fix or
check taken back, which `run.sh` requires to fail.

Not covered: a page busied by another thread (only as a short grab).

## KTLS: what is proven

Harness `ktls/ktls.c`, for `sys/kern/uipc_ktls.c`, on sessions made by
the kernel's own `ktls_create_session()` from any parameters it accepts.
The reference is the TLS record layer: RFC 2246, 4346, 5246 and 8446,
with RFC 5288 (AES-GCM) and RFC 7905 (ChaCha20-Poly1305).  No bug found.

- `ktls_frame()`, on chains of up to three records, every cipher and
  version: the header and trailer each takes, CBC padding of 1 to 16
  bytes to whole blocks, the header's type, version and length, TLS 1.3
  records passed as TLS 1.2 application data with the real type in the
  trailer, a GCM nonce never used before, a random CBC IV from TLS 1.1
  on, a session reference per record, and with software encryption the
  pages left to encrypt.  This is what sendfile's model of it assumes.
- `ktls_enqueue()`, on the session state `ktls_create_session()` leaves
  (proven by the above): a batch of up to three records is queued to
  its session's queue and the queue's thread woken when idle; TLS 1.0
  records, whose CBC IVs chain them, are queued in sequence however
  their I/O completes, by induction over one call from any state the
  queue can be in.
- The worker, `ktls_encrypt()` and `ktls_encrypt_async()` with its
  completion, on a batch from either caller, then a record appended
  after it: each record is encrypted once, in place when its pages are
  anonymous, else into new pages or a contiguous buffer exactly over the
  payload, then the trailer; an encrypted record holds no session, is
  read-only and anonymous, its file pages let go once; the batch is
  readied whole, or the connection dropped with EIO and the batch freed;
  every page and buffer the worker took holds a record or is freed; the
  socket and session references are dropped once; the next record is
  left alone.  On a one record batch, and two synchronously (`SLOW=1`).
  Encryption itself (`ktls_ocf_encrypt()`) is modelled by what it is
  given; an asynchronous completion runs after the worker moves on.
- Receive: `tls13_find_record_type()` against RFC 8446 5.4 (the type is
  the last byte not zero before the tag, content with none refused);
  `ktls_detach_record()` takes exactly the record's bytes off the TLS
  chain, splitting an mbuf if need be, leaves the rest with its tail,
  and keeps the socket buffer's counts; `ktls_check_rx()` queues the
  socket once a whole record is in, once, with a reference, an error if
  only part of one is and no more can come.
- `ktls_decrypt()` (harness `ktls/ktls_rx.c`), on one record in one
  mbuf decrypted by the NIC, AES-GCM TLS 1.2: delivered as a
  TLS_GET_RECORD control message and its payload, no more.  Only on
  fixed shapes: over a byte stream the proof is past 80G.

Fix, waiting for the developer: a NIC-decrypted record shorter than its
tag (20 bytes, where header and tag are 29) passed `ktls_decrypt()`'s
header checks, which the software paths refuse with EMSGSIZE; its
payload came to -9 bytes and the trailer trim walked off the chain to a
NULL dereference.  The fix,
[a482e648447b](https://github.com/ocochard/freebsd-src/commit/a482e648447b),
refuses it with EMSGSIZE too (`run.sh` mutant `ktls_rx_decrypt_tagless`
takes it back).  Whether a NIC can mark such a record decrypted is the
hardware's: asked of the developer.  Report:
[reports/ktls.md](reports/ktls.md).

A TLS 1.0 sequence number past 2^64-1, which RFC 2246 forbids, would
leave a record waiting for good; only a session set up within a few
records of the end gets there, and the harness assumes none.

Model choices: the enqueue proofs pass `ktls_enqueue()` a token for its
socket, and one call each.  cbmc takes a pointer read from a union, as
the `m_epg_` fields of an mbuf are, to be any pointer written to it, so
every access through the session read back was also one to the socket
and the other records: two calls on two records took over 40G.  The
worker reads through both, so its proofs bear that cost: two records
asynchronously are past 100G.

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
