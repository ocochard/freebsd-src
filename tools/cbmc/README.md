# Bounded model checking of system calls with CBMC

Proofs of kernel code with [CBMC](https://www.cprover.org/cbmc/), a
bounded model checker for C.  The reference is the system call's manual
page: a harness states what it promises as assertions, and CBMC checks
them against the kernel's own source for every input within the bounds.

    pkg install cbmc
    tools/cbmc/run.sh                # every proof, about three hours
    SLOW=1 tools/cbmc/run.sh         # and the longest or largest
    ONLY=nocache tools/cbmc/run.sh   # the jobs whose name matches
    tools/cbmc/run.sh ktls           # one harness: sendfile, ktls, accept, kevent

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

The pager those proofs model, for a file on UFS (harness
`sendfile/pager.c`, for `vnode_pager_generic_getpages()`,
`sys/vm/vnode_pager.c`, as `ffs_getpages_async()` calls it): on a run
as `vm_pager_assert_in()` takes it, up to three pages of a four-page
file, read-behind and read-ahead asked for or not, any block map and
sector size, blocks of 4K and 8K, the read failing or not.  Success,
and the completion runs once, after the read, on the run given; the
run valid up to the end of the file; read-behind and read-ahead pages
freed on an error, queued otherwise, and reported; the pager buffer
freed; one asynchronous read of the file's bytes in whole sectors and
no more, from where the block map puts them.  The page cache is taken
as the pager states it, a page partly valid only past the end of the
file, and the run as `sendfile_swapin()` ends it, on a page not valid.
The block size is a constant per job: 64-bit division by a variable
block size took the formula past 46G in 40 minutes, a constant one 40
seconds.

Open questions, outside what sendfile and UFS give the pager (`run.sh`
questions): a run ending on the file's last page valid up to its end
completes on one page less, which stays busied
(`pager_lastvalid`); a hole, or a file system without `VOP_BMAP()`,
is read with no I/O and `VM_PAGER_OK` and the asynchronous completion
never runs, as `ffs_getpages_async()` and
`vnode_pager_local_getpages_async()` run it on an error only
(`pager_nobmap`).  sendfile asks `vm_pager_has_page()` first, under the
vnode lock, and trims a run's valid last pages.

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
- The ifnet send tag: `ktls_alloc_snd_tag()` allocates it on the
  route's interface, rate limited for a paced connection when the
  interface can, or fails with the error of what is missing (a
  connection, leave to offload unless forced, a route, unmapped mbufs,
  TLS offload for the address family), the interface reference let go;
  `ktls_output_eagain()` schedules a reset once, referenced;
  `ktls_reset_send_tag()` releases the old tag and installs a new one,
  or aborts the connection and leaves the reset pending, dropping its
  reference; `ktls_try_ifnet()` offloads the session with its tag, or
  leaves it as it was.  `ktls_set_tx_mode()` switches an open
  connection between software and NIC offload by a clone of its
  session, which replaces the old one, or is destroyed with the old one
  left in place when the mode cannot be set up, the send lock is not
  had, or another change won the race while the inpcb was unlocked;
  offload is refused twice, or once disabled; the inpcb is locked
  again on return.  `ktls_disable_ifnet()`, on too many retransmits,
  disables offload once per connection by a task holding the session
  and the socket, which switches an open connection to software and
  tells the stack, leaves a closed one alone, and lets go of both
  references and the inpcb.
- The receive tag: `ktls_alloc_rcv_tag()` allocates it on the route's
  interface or fails with the error of what is missing;
  `ktls_input_ifp_mismatch()` follows packets to another interface and
  schedules a reset once, referenced; `ktls_reset_receive_tag()` lets
  the old tag go and asks for a new one where the interface can receive
  TLS for the connection's family, leaving decryption to software
  where not.
- `sbappend_ktls_rx()` (harness `ktls/ktls_sb.c`, for
  `sys/kern/uipc_sockbuf.c`): TCP data lands in a TLS receive buffer as
  plain data, not ready, each mbuf decrypted as its packet was, then the
  buffer is checked for a whole record, and the session told when the
  last packet came in on another interface than its receive tag's.
  `sbcompress_ktls_rx()` (harness `ktls/ktls_sbc.c`), which appends the
  chain: the bytes follow those already there, in order, none moved
  between decrypted and encrypted data; empty mbufs are dropped and small
  ones copied into a tail that has the room, unless coalescing is off;
  a read-only tail is not written; the counts and the tail are kept.
  `sbcut_internal()`, which soreceive() and the flushes drop data with,
  on a TLS receive buffer: decrypted records, the one being decrypted,
  the TLS chain; each part counts out the bytes cut from it, the record
  being decrypted is let go so its worker frees it, the mbufs cut whole
  come back once each, and what is left stays in place.
  `sbappendcontrol_locked()`, as `ktls_decrypt()` appends a decrypted
  record: the control message then the payload, linked as the last
  record, counted and ready to read, its protocol flags cleared, the TLS
  data left alone.
- `sbready()` on TLS send records, as the KTLS worker readies encrypted
  records and sendfile(2) records whose pages were read: a record counts
  its unready pages, one for an empty TLS 1.0 record, and is ready when
  they all are; readying the first record not ready makes it and the
  ready ones behind it readable, readying one behind it nothing; and
  `sbready_compress()` moves a header to the end of the trailer before
  it, byte for byte, only out of a session, where it fits and coalescing
  is on.  Two records, on trailers of a fixed length; small unmapped
  mbufs are not turned plain (`mb_unmapped_compress()` declines).  With
  `SLOW=1`: about 36G each.
- `ktls_decrypt()` (harness `ktls/ktls_rx.c`), on one record in one
  mbuf decrypted by the NIC, AES-GCM TLS 1.2: delivered as a
  TLS_GET_RECORD control message and its payload, no more.  Only on
  fixed shapes: over a byte stream the proof is past 80G.
- Software decryption (harness `ktls/ktls_ocf.c`, for
  `sys/opencrypto/ktls_ocf.c`), on records of any bytes over two mbufs,
  the crypto framework modelled by what it is asked: every request
  reads and writes inside its buffer, mbuf or iovecs.
  `ktls_ocf_tls_cbc_decrypt()` (TLS 1.1 and 1.2, every MAC) against RFC
  5246 6.2.3.2: a record not whole blocks or too short for IV, MAC and
  padding is refused; a padding that does not fit or is not all its
  length is refused; any other, up to 255 bytes, goes on to the MAC,
  checked over the content, and the trailer is the MAC and padding.  On
  records of 40, 48, 64, 176 and 304 bytes (`SLOW=1`, 83 minutes, 8G),
  as the padding walk at an offset CBMC cannot settle took over 16
  minutes at any length up to 192.  `ktls_ocf_tls12_aead_decrypt()` and
  `ktls_ocf_tls13_aead_decrypt()` (AES-GCM, ChaCha20-Poly1305) against
  RFC 5288, RFC 7905 and RFC 8446 5.2, records of up to 64 bytes: too
  short for nonce, content type and tag is refused, else one request
  decrypts the content and checks the tag ending the record, the
  trailer is the tag.  The recrypt of a record the NIC decrypted in
  part (AES-GCM, TLS 1.2 and 1.3): the ciphertext goes back into the
  decrypted mbufs, over the content only, every other byte left.
  Timing is not a property CBMC checks.
- setsockopt(2) TCP_TXTLS_ENABLE and TCP_RXTLS_ENABLE (harness
  `ktls/ktls_enable.c`, for `sys/kern/uipc_ktls.c`):
  `ktls_copyin_tls_enable()` on an option of any size, the old one
  included, from a process or the kernel, any lengths and key pointers:
  a length past its bound or no cipher key refused, each key in a kernel
  buffer of exactly its length holding the process's bytes, the old
  option's fields kept from sequence number 0, or on an error nothing
  left for `tcp_setsockopt()` to free.  `ktls_enable_tx()` and
  `ktls_enable_rx()`, `ktls_create_session()` and the NIC modelled by
  their contracts, on a TCP socket or not, with a session or not,
  spliced or not, racing another enable while waiting for the I/O lock:
  refused with the error ktls(4) and 1000cc4a0d39 give, the session
  freed and the socket as it was; or the session installed at the
  option's sequence number, the stack told of NIC offload, receive data
  marked and checked.

Hardening: `ktls_decrypt()` takes a NIC-decrypted record to hold its
header and trailer, without the check the software paths make; one
shorter than its tag (20 bytes, where header and tag are 29) would come
to a payload of -9 bytes and a trailer trim walking off the chain to a
NULL dereference.  The developer answered that a driver passes up such
a record only with a length known to hold them, which cxgbe's TOE path
does by building it; for mlx5 it is the NIC's.
[a482e648447b](https://github.com/ocochard/freebsd-src/commit/a482e648447b)
refuses one with EMSGSIZE all the same (`run.sh` mutant
`ktls_rx_decrypt_tagless` takes it back).  Report:
[reports/ktls.md](reports/ktls.md).

Fix [a0d672151d9e](https://github.com/ocochard/freebsd-src/commit/a0d672151d9e):
`ktls_reset_receive_tag()` tested the receive TLS capabilities with
`IFCAP2_RXTLS4` and `IFCAP2_RXTLS6`, which are bit numbers (0 and 1),
not masks: an IPv4 connection never got a new receive tag after packets
moved to another interface, and an IPv6 one got one where the interface
had RXTLS4 but not RXTLS6.  `ktls_alloc_rcv_tag()` had the same mistake,
fixed in c721694a1ca8 (`run.sh` mutants `ktls_rx_tag_v4` and
`ktls_rx_tag_v6` take this fix back).

Fix [447cba6c6808](https://github.com/ocochard/freebsd-src/commit/447cba6c6808):
`sbappend_ktls_rx()` read each packet's receiving interface from the
chain's first mbuf, whose packet header it had demoted by then, so a
chain of two packets or more had no interface and a change of input
interface went unnoticed (`run.sh` mutant `ktls_rx_append_first` takes
the fix back).

Fix [1ae48c201579](https://github.com/ocochard/freebsd-src/commit/1ae48c201579):
`check_padding()` compared each CBC padding byte, read as a signed
`char`, with the padding length, a `uint8_t`, so on amd64 every record
with a padding length byte of 128 or more was refused, against RFC
5246, which allows up to 255 (`run.sh` mutant `ktls_ocf_cbc_sign` takes
the fix back; ATF cases `ktls_receive_*_padding_128_extra`).

Fix [a71bb0992737](https://github.com/ocochard/freebsd-src/commit/a71bb0992737):
`ktls_enable_rx()` refused a spliced socket with EALREADY, not the
EINVAL 1000cc4a0d39 set, which `ktls_enable_tx()` returns (`run.sh`
mutant `ktls_enable_rx_ret` takes the fix back; ATF case
`ktls_spliced_socket_rx`).

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

## accept(2) and accept4(2): what is proven

Harness `accept/accept.c`, for `sys_accept()`, `sys_accept4()`,
`accept1()` and `kern_accept4()`, `sys/kern/uipc_syscalls.c`, against
lib/libsys/accept.2.  The descriptor table, the listen queue, the
protocol's address and the socket's ioctls are modelled by what they
do.  On any descriptor (a listening socket, a socket not listening, a
file not a socket, none), a connection or an error from the queue
(EWOULDBLOCK for a non-blocking socket, EINTR, ECONNABORTED), a full
descriptor table, an address buffer of any length or none, faults on
either copy, and for accept4(2) any flags: refused with the manual's
errors (EINVAL for bad flags and for a socket not listening), no
descriptor, reference or capability left behind; or a new descriptor
for the connection, returned, with O_NONBLOCK, O_ASYNC and the signal
destination inherited (accept) or O_NONBLOCK from SOCK_NONBLOCK and
O_ASYNC and the signal destination cleared (accept4), close-on-exec and
close-on-fork from SOCK_CLOEXEC and SOCK_CLOFORK, the socket's
blocking and async state in step with its file, the peer's address
copied out to the room given and its own length returned.  No bug
found.  Not covered: MAC, capability rights, COMPAT_OLDSOCK.

## kevent(2): what is proven

Harness `kevent/kevent.c`, for `sys_kevent()`, `kern_kevent()`,
`kern_kevent_fp()` and `kqueue_kevent()`, `sys/kern/kern_event.c`,
against lib/libsys/kqueue.2: the layer between the process's change
and event lists and the kqueue, `kqueue_register()` and
`kqueue_scan()` modelled by what they are given and return.  On a
kqueue or another descriptor, up to 3 changes and 3 events (and 9
changes, two batches of `KQ_NEVENTS`), a timeout or none, any
registration results, faults on every copy: a negative list length
refused with EINVAL before any change, a timeout or change list that
cannot be read with EFAULT; every change applied in order, its system
flags cleared, before any event is read; an error or `EV_RECEIPT`
reported as an EV_ERROR event (its ident and filter, the error in
`data`) where there is room, the call failing with the error and the
changes after it left where not; the EV_ERROR events counted, or the
events read up to `nevents` with the timeout given; the descriptor and
kqueue references let go.

Fix [cd32be5ec761](https://github.com/ocochard/freebsd-src/commit/cd32be5ec761):
a negative `nevents` was refused only in `kqueue_scan()`, after the
changes, so a change that failed or had `EV_RECEIPT` was written as an
EV_ERROR event past the event list and counted, where e00bae5c181a and
kqueue.2 give EINVAL (`run.sh` mutant `kevent_negevents_late` takes the
fix back; ATF `tests/sys/kqueue/kqueue_lengths`).  Report:
[reports/kevent.md](reports/kevent.md).

Open questions (`run.sh` questions): an EV_ERROR event that cannot be
written is counted all the same, where kqueue.2 gives EFAULT
(`kevent_outfault`); a change with filter 0 is skipped, where kqueue.2
gives EINVAL for an invalid filter (`kevent_zerofilter`).

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
