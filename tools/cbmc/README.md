# Bounded model checking of system calls with CBMC

Proofs of kernel code with [CBMC](https://www.cprover.org/cbmc/), a
bounded model checker for C.  The reference is the system call's manual
page: a harness states what it promises as assertions, and CBMC checks
them against the kernel's own source for every input within the bounds.

    pkg install cbmc
    tools/cbmc/run.sh                # every proof, about three hours
    SLOW=1 tools/cbmc/run.sh         # and the longest or largest
    ONLY=nocache tools/cbmc/run.sh   # the jobs whose name matches
    tools/cbmc/run.sh ktls           # one harness: sendfile, ktls, accept, kevent, close, unp, tcp

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

The pager those proofs model has its own fix, in the VM interface, not in
sendfile(2): report [reports/vm.md](reports/vm.md).

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | async `VOP_GETPAGES` skips the completion on its no-I/O exits | [987722b47487](https://github.com/ocochard/freebsd-src/commit/987722b47487) | confirmed by the developer (kib@) |

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

The completion covers every requested page, exactly once, on the no-I/O
exits too.  kib@ confirmed the contract: the callback must be called for
all pages.  Four paths broke it (reports/vm.md): a run ending on the file's last
page valid up to its end trimmed that page and completed on one less
(`pager_lastvalid`); a hole, or a file system without `VOP_BMAP()`, read
with no I/O and `VM_PAGER_OK` and never ran the completion
(`pager_nobmap`, `pager_smlfs`).  sendfile does not take these paths (it
asks `vm_pager_has_page()` first, under the vnode lock, and UFS has
`VOP_BMAP()`), so no in-tree caller hit them and the mutants
(`pager_lasttrim`, `pager_oldnodone`, `pager_smlnodone`,
`pager_holenodone`) are the regression check.

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
- write(2) on a socket with a TLS send session (harness
  `ktls/ktls_send.c`, for the TLS branch of `sosend_generic_locked()`,
  `sys/kern/uipc_socket.c`), on sends of up to 3 bytes into a send
  buffer of up to 4, with or without a control message of exactly the
  bytes given, software or NIC sessions: a `TLS_SET_RECORD_TYPE`
  message's byte is the type of that send's records, read from within
  the message (ktls(4)), the message freed once and not passed to TCP;
  an empty write is refused unless TLS 1.0 CBC; every chain cut from the
  user's data is framed, sent not ready for software sessions, then
  queued to the worker with a socket reference, or freed on an error
  TCP leaves to the caller; the session is held for the call.
  `m_uiotombuf()` with `M_EXTPG` (harness `ktls/ktls_uio.c`, for
  `sys/kern/uipc_mbuf.c`), which cuts the data for it and sendfile(2):
  the bytes asked for, all of them for a length of 0, one empty mbuf for
  none, in records of the frame length, each but the last full, of new
  anonymous pages holding their bytes; on a fault, NULL and every page
  freed.  Up to two records, any frame length up to 16K.
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

Fix [dfa7f43dbdf6](https://github.com/ocochard/freebsd-src/commit/dfa7f43dbdf6): a `TLS_SET_RECORD_TYPE` control message was checked to
hold a `struct cmsghdr` only, not the byte after it: one of 12 to 16
bytes had its record type read past its end, from what the mbuf held
before, and sent to the peer (`run.sh` mutant `ktls_send_cmsglen` takes
the fix back; ATF case `ktls_transmit_short_record_type`).

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

Fix [459c6f697997](https://github.com/ocochard/freebsd-src/commit/459c6f697997):
an EV_ERROR event whose copyout faulted was counted and
kevent() returned success with nothing written, where kqueue.2 gives
EFAULT; markj@ confirmed the drop (from the 2000 original) was a bug
(`run.sh` mutant `kevent_outfault_drop`; ATF
`tests/sys/kqueue/kqueue_lengths` eventlist_fault).

Open question (`run.sh` question): a change with filter 0 is skipped,
where kqueue.2 gives EINVAL for an invalid filter (`kevent_zerofilter`).

## close(2) and close_range(2): what is proven

Harness `close/close.c`, for `kern_close()`, `closefp()`, `closef()`,
`kern_close_range()` and the descriptor table's own code,
`sys/kern/kern_descrip.c`, against lib/libsys/close.2 and closefrom.2,
on a table of 4 slots whose files may be shared between slots and held
elsewhere; a file's last close, its knotes and VOP_ADVLOCK() are
modelled.  close(2) of any descriptor: EBADF for one not active, the
table as it was; else the slot, its bit in the map and its capabilities
freed, the free-slot hint kept, the file's reference dropped once and
the file deactivated on its last one only, its knotes dropped and the
file told (`fo_fdclose()`), the process's POSIX locks on a vnode
released on any close, the last close's error returned with EINTR for
a restart (the descriptor freed all the same), every other slot as it
was, the table unlocked.  close_range(2) on any range, the ends past
the table and past `INT_MAX` included, and any flags: EINVAL for a bad
flag or `highfd` below `lowfd`, nothing done; else every open
descriptor in the range clamped to the table closed as above, or
flagged close-on-exec or close-on-fork, the others as they were, 0
returned whatever the closes return.  No bug found.  Not covered: a
table shared by process leaders (`p_fdtol`), capabilities' seqc, AUDIT.
goto-cc cannot evaluate the `_Static_assert()`s on constant arrays in
the file: they are compiled out.

## Unix socket SCM_RIGHTS: what is proven

Harness `unp/unp.c`, for `unp_internalize()` and `unp_externalize()`,
`sys/kern/uipc_usrreq.c`, against unix.4: the conversion of a sender's
file descriptors into file references and their installation in the
receiver's descriptor table, which `sendmsg(2)` and `recvmsg(2)` drive.
The descriptor table, the control mbufs and the file garbage collector
are modelled; the files passed are regular files, not sockets, so no
unpcb message count is touched.  On a SCM_RIGHTS message of 0, 1 or 2
descriptors, each slot open or not, passable or not, shared between
slots or held elsewhere:

- `unp_internalize()`: every descriptor is checked, and the first that
  is missing (EBADF) or not passable (EOPNOTSUPP) rejects the whole
  message; each file accepted is held once and internalized once; on any
  error every reference taken is rolled back and every allocation freed;
  the total of all files' reference counts is the baseline plus the
  references the message now holds, none lost or leaked.
- `unp_externalize()`: a descriptor is allocated and the file installed
  for each (its reference handed to the table), or, when the receiver
  does not want them or has cleared SO_PASSRIGHTS, or descriptor
  allocation fails (EMFILE), every file's message reference is released
  once; the message keeps no reference and its filedescent array is
  freed in every case.

No bug found.  Not covered: files that are themselves Unix sockets (the
`unp_msgcount` cycle the garbage collector walks), a message split over
several mbufs, SCM_CREDS content, and a descriptor array of more than
two (NFDS=3 internalize proves but at ~40G, through the real
`sbcreatecontrol()` and `filecaps_copy()`).  goto-cc cannot evaluate the
`_Static_assert()`s on constant arrays: they are compiled out.

## tcp_dooptions(): what is proven

Harness `tcp/tcp.c`, for `tcp_dooptions()`, `sys/netinet/tcp_input.c`,
against RFC 9293 3.1 (option format), RFC 7323 (window scale,
timestamps) and RFC 2018 (SACK): the parser of a TCP segment's options,
driven straight off the wire by any remote peer.  The callers pass
`cnt = (th_off << 2) - sizeof(struct tcphdr)`, so 0 to 40 bytes, and
`cp` at that many peer-controlled bytes.  On option buffers of 2, 4, 10
and 18 bytes (the 18-byte SIGNATURE and a two-block SACK included; cnt=20
proves too), SYN or not, every byte free: no read outside the buffer;
each option accepted only at its exact length and only where RFC allows
(MSS and window scale and SACK-permitted and TFO on a SYN, SACK off a
SYN); each parsed value the option's bytes (MSS in network order, window
scale `min(byte, 14)`, the SACK block count `(optlen - 2) / 8`, the TFO
cookie length `optlen - 2`); and every saved pointer (SACK blocks, the
MD5 signature, the TFO cookie) within the buffer with the length its
flag claims.  No bug found.

The option count is a constant per job: a symbolic 0..40 option stream
ran past 40 minutes, a fixed length seconds to a couple of minutes.  Not
covered: the one-byte over-read a dropped `cnt < 2` guard would cause is
not modelled (the harness array is a fixed size, so a read at `cp[cnt]`
stays in bounds, where the kernel buffer is the segment's); the
`nsacks` count mutant is equivalent (a valid SACK optlen is `2 + 8k`, so
`(optlen - 2) / 8` and `optlen / 8` are both `k`).

## tcp_sack_doack(): what is proven (partial)

Harness `tcp/sack.c`, for `tcp_sack_doack()`, `sys/netinet/tcp_sack.c`,
against RFC 2018: the peer's SACK blocks parsed from an option into the
retransmission scoreboard (a list of holes).  This function is large and
stateful, and the scoreboard sweep walks a doubly-linked hole list with
two crossing cursors; the symbolic version runs out of memory (over 50G).
So the proof is **partial**: the sequence space is a concrete constant per
job (GEO), and two geometries are proven, each with its accounting
checked (the returned status, `hole_bytes`, and `sacked_bytes`):

- GEO 0 - a pure cumulative ack with no SACK block: nothing sacked, the
  scoreboard untouched, `SACK_NOCHANGE`.
- GEO 2 - a peer block trimming a hole's front: the block accepted, the
  hole's start advanced, `hole_bytes` and `sacked_bytes` reduced by the
  acked amount, `SACK_CHANGE`.

Memory safety and every `KASSERT()` hold on both.  Mutants
(`sack_delivered`, `sack_holebytes`, `sack_movestart`) take the trim
accounting back.

Harness `tcp/sack_list.c`, for `tcp_update_sack_list()`, same file: the
receiver's SACK-block list maintenance, which merges a received range into
the ordered `sackblks[]` list, capped at `MAX_SACK_BLKS`.  A starting list
of 0..`MAX_SACK_BLKS` well-formed blocks (non-empty, ordered,
non-overlapping, above `rcv_nxt`) and a received range are
nondeterministic.  Proven, over the whole `SEQ_LEQ(rcv_start, rcv_end)`
range the function's `KASSERT` permits: after the call `rcv_numsacks` stays
within `MAX_SACK_BLKS` and no `sackblks[]` write runs past the array.  The
mutant `sack_list_cap`, dropping the cap, is caught by the count
overflowing.

This found a latent defect and its fix (this branch): the original cap sat
inside the `SEQ_LT(rcv_start, rcv_end)` branch, so on a *zero-length* range
(`rcv_start == rcv_end`) that keeps a DSACK block it was skipped while
`num_head` could still become 1 -- leaving `rcv_numsacks == MAX_SACK_BLKS +
1` and writing one block past `sackblks[]`.  No in-tree caller passes a
zero-length range (all pass `todrop`/`save_tlen > 0` or an existing block's
start..end), so it was not reachable; the fix moves the cap to after
`num_head` is set (`num_head + num_saved > MAX_SACK_BLKS`), so the bound
holds for every input, which this proof then confirms over the full range.

Harness `tcp/dsack_list.c`, for `tcp_update_dsack_list()`, same file: the
receiver's DSACK-block list maintenance, the companion to
`tcp_update_sack_list()`.  Same `sackblks[]`/`MAX_SACK_BLKS` bound.  Proven,
for any starting list and received range: `rcv_numsacks` stays within
`MAX_SACK_BLKS` and no `sackblks[]` write runs past the array.  Unlike its
sibling, this caps inside the saved-block loop's condition
(`n < MAX_SACK_BLKS`), so the bound holds for every input, including the
edge cases that break the other; the mutant `dsack_list_cap`, dropping that
condition, is caught by a `saved_blks[]` out-of-bounds write.  No bug found.

Harness `tcp/addoptions.c`, for `tcp_addoptions()`, `sys/netinet/tcp_output.c`:
the TCP option writer, the complement to `tcp_dooptions()`.  It assembles
the requested options (MSS, window scale, SACK-permitted, timestamp,
signature, SACK blocks, TFO cookie) into the fixed `TCP_MAXOLEN`-byte option
area, NOP-padding for alignment, and returns the length.  The option area is
a CBMC object of exactly `TCP_MAXOLEN` bytes, so a write past it is an
out-of-bounds write.  The requested option set and the attacker-influenced
counts (`to_nsacks <= TCP_MAX_SACK`, `to_tfo_len`) are nondeterministic.
Proven: every write stays within the option area and the returned length is
at most `TCP_MAXOLEN`, for any option combination.  The mutant
`addopt_sackclamp`, dropping the SACK-block count clamp to the remaining
room, is caught by an out-of-bounds write.  No bug found.

Not covered, for want of memory on this host: the whole-hole-removal,
back-trim, hole-split and new-hole-at-tail geometries (the sweep walks
more holes/blocks than fits), and the fully symbolic sequence space.  The
security-relevant property a remote peer can push on - that the SACK
block count cannot overflow `sack_blocks[TCP_MAX_SACK + 1]` - is bounded
separately by the `tcp_dooptions()` proof, which holds `to_nsacks <= 4`.
No bug found.

## read(2)/readv(2): what is proven

Harness `read/read.c`, for `copyinuio()`, `sys/kern/subr_uio.c`: the
iovec array copy-in shared by `readv(2)`, `writev(2)`, `preadv(2)` and
`pwritev(2)`.  A user `iovcnt` and up to `NIOV` iovecs of nondeterministic
length, against the readv(2) contract:

- `iovcnt` past `UIO_MAXIOV` is refused with `EINVAL` and no `uio`.
- a faulting copyin of the iovec array is propagated with no `uio`.
- each iovec length is checked so the running total never passes
  `IOSIZE_MAX`; on overflow the call fails with `EINVAL` and no `uio`.
- on success the `uio`'s `uio_resid` is the exact sum of the lengths and
  `uio_iovcnt` is the requested count.

The success path is where the arithmetic matters: a 64-bit running sum of
attacker-chosen lengths that must not wrap.  Mutants `copyinuio_overflow`,
`copyinuio_overflow2`, `copyinuio_resid` and `copyinuio_iovcnt` take the
overflow guard, the total and the iovcnt back.

Not covered: the `UIO_MAXIOV` cap itself (reaching it needs `iovcnt >
1024`, past the modelled iovec array of `NIOV`), and the single `M_IOV`
allocation's free on the fault path (not observable in the malloc model).
No bug found.

Harness `read/copyiniov.c`, for `copyiniov()`, same file: the lower-level
helper that copies a user iovec array into a freshly allocated kernel
array, behind `readv(2)`/`writev(2)` and the `sendmsg`/`recvmsg` iovec
handling.  The `M_IOV` buffer is a CBMC object of exactly `iovlen` bytes,
so the copyin is bounds-checked against it.  Proven: a count past
`UIO_MAXIOV` is refused with no array; an accepted count has `iovcnt *
sizeof(struct iovec)` not overflow (`iovlen` equals the size_t product) and
the copyin fills a buffer that holds it; a fault frees the array and yields
`NULL`.  The mutant `copyiniov_cap`, dropping the `UIO_MAXIOV` cap, is
caught by an out-of-bounds copy.  `iovcnt` is a constant per job sweeping
across the cap (`0`, `2`, `UIO_MAXIOV`, one past).  (This is the cap the
`copyinuio` proof above could not reach through its modelled array.)  No bug
found.

Harness `read/uiomove.c`, for `uiomove()` (through `uiomove_faultflag()`),
same file: the kernel's copy of `n` bytes between a kernel buffer and a user
iovec list, the workhorse behind `read(2)`, `write(2)` and most device and
socket I/O.  The loop copies `min(iov_len, remaining n)` bytes per iovec,
advancing the kernel pointer and shrinking `n`.  The kernel buffer is an
`N`-byte object and each iovec points at its own object; the user path
(`UIO_USERSPACE`) drives the modelled `copyin()`/`copyout()`.  Proven: every
copy stays within the `N`-byte kernel buffer and the addressed iovec, and
`uio_resid` is drawn down by exactly the bytes moved.  The mutant
`uiomove_clamp`, dropping the `cnt > n` clamp, is caught by an out-of-bounds
write past the kernel buffer (and the residual check); `uiomove_advance`,
dropping the `n` decrement, likewise.  Geometry is a constant per job: an
exact fit, a second iovec clamped by the count, a skipped empty iovec, and an
iovec larger than `N`.  No bug found.

## sockargs() and getsockaddr(): what is proven

Harness `sockargs/sockargs.c`, for `sockargs()`, `sys/kern/uipc_syscalls.c`:
the copy-in of a socket name or control buffer into an mbuf, shared by
`sendto(2)`, `sendmsg(2)`, `bind(2)`, `connect(2)` and their kin.  A
`buflen` and a `type` of `MT_SONAME` or `MT_DATA`, against the contract:

- `buflen` past `MCLBYTES` is refused with `EMSGSIZE` and no mbuf.
- a faulting copyin is reported, with the mbuf freed and none handed back.
- on success the mbuf's `m_len` is `buflen`, exactly `buflen` bytes are
  copied into a data area that holds them, and for a name `sa_len` is the
  low byte of `buflen`.

The data area is a CBMC object of the exact size class `m_get2()` would
give (`MLEN`, else a `MCLBYTES` cluster), so the copyin's write is
bounds-checked against the real capacity: the mutant `sockargs_cap`, which
drops the `MCLBYTES` refusal, is caught by an out-of-bounds write, which
is what makes the cap load-bearing.  Mutants `sockargs_mlen` and
`sockargs_salen` take the length and the stored `sa_len` back.

`buflen` is a constant per job (the copyin is a byte loop; a symbolic
length runs out of memory): the jobs sweep the boundaries, an `MLEN` mbuf
(`0`, `MLEN`), a cluster (`MLEN+1`, `MCLBYTES`) and a length past the cap
(`MCLBYTES+1`).  Not covered: a name longer than 255, whose `sa_len`
truncates to one byte; the only in-tree caller passes control data, not a
name, so that path is dead.  No bug found.

Harness `sockargs/getsockaddr.c`, for `getsockaddr()`, same file: the
copy-in of a socket address for `bind(2)`, `connect(2)`, `sendto(2)` and
`sendmsg(2)`.  A `len`, against the contract:

- `len` past `SOCK_MAXADDRLEN` (255) is refused with `ENAMETOOLONG` and no
  name.
- `len` below the fixed header (`offsetof(struct sockaddr, sa_data[0])`)
  is refused with `EINVAL`.
- a faulting copyin is reported, with the buffer freed and no name.
- on success the name's `sa_len` is `len` (capped at 255, so no byte
  truncation here), `len` bytes copied into a buffer that holds them.

The `M_SONAME` buffer is a CBMC object of exactly `len` bytes, so dropping
the cap (`getsockaddr_cap`) is caught by an out-of-bounds copy.  Mutants
`getsockaddr_hdr` and `getsockaddr_salen` take the header check and the
`sa_len` stamp back.  `len` is a constant per job, the jobs sweeping below
the header, the header, the cap and one past it.  No bug found.

## setsockopt(2) and getsockopt(2): what is proven

Harness `setsockopt/sooptcopyin.c`, for `sooptcopyin()`,
`sys/kern/uipc_socket.c`: the copy-in of a socket option value, used by
`setsockopt(2)` through `sosetopt()` and by every protocol
`pr_ctloutput()`.  The user controls `sopt_valsize`, against a caller
buffer of `len` bytes and a minimum `minlen`:

- a `valsize` below `minlen` is refused with `EINVAL`, `sopt_valsize`
  untouched, no copy.
- a `valsize` above `len` is clamped to `len`, and `sopt_valsize` reports
  the clamped length.
- the copy is only ever `min(valsize, len)` bytes, into the caller's
  buffer, never past it; on the user path it is a copyin that may fault.

The caller's buffer is a CBMC object of exactly `len` bytes, so the clamp
is load-bearing: the mutant `sooptcopyin_clamp`, which drops it, is caught
by an out-of-bounds write of the over-long value.  Mutants
`sooptcopyin_min` and `sooptcopyin_report` take the minimum check and the
reported length back.  `valsize` is a constant per job (the copy is a byte
loop), the jobs sweeping an empty value, one short of the buffer, the
buffer, and one past it, with `minlen` symbolic in `[0, len]`.  No bug
found.

Harness `setsockopt/sooptcopyout.c`, for `sooptcopyout()`, same file: the
copy-out of an option value for `getsockopt(2)` through `sogetopt()` and
every `pr_ctloutput()`.  The caller hands a kernel buffer of `len` bytes;
the user controls `sopt_valsize`:

- the copy is only ever `min(len, sopt_valsize)` bytes, read from the
  kernel buffer, never past it (which would leak adjacent kernel memory to
  user space).
- `sopt_valsize` is set to what was copied.

The kernel buffer is a CBMC object of exactly `len` bytes, so the clamp is
the information-leak guard: the mutant `sooptcopyout_clamp`, which drops
the `min()`, is caught by an out-of-bounds read of the kernel buffer.  The
mutant `sooptcopyout_report` takes the reported length back.  No bug found.

Harness `setsockopt/sooptmcopy.c`, for `soopt_mcopyin()` and
`soopt_mcopyout()`, same file: the copy of an option value between the user
buffer (`sopt_val`, `sopt_valsize` bytes) and an mbuf chain, on the IPv6
`pr_ctloutput()` path through `soopt_getm()`.  Each mbuf is copied in full
while the user buffer still has room (`sopt_valsize >= m_len`); the user
pointer advances by `m_len` and `sopt_valsize` shrinks by it.

- no copy, in either direction, runs past the user buffer or past any
  mbuf's storage.
- `soopt_mcopyout()` reports the copied total in `sopt_valsize`, and returns
  `EINVAL` (not a panic) when the user buffer is too short for an mbuf.

The user buffer is a CBMC object of exactly `VALSIZE` bytes and each mbuf a
separate object, so a copy past either end is an out-of-bounds access.  The
room check is the guard: the mutants `mcopyin_guard` and `mcopyout_guard`,
which force it true, are caught by an out-of-bounds dereference of the user
buffer once `sopt_valsize` is exhausted.  `mcopyout_advance`, which drops the
`sopt_val` advance, is caught by the reported-total check.  `GEO` sweeps a
single mbuf, a two-mbuf chain, a chain with an empty mbuf, and an `MLEN`-full
mbuf; `VALSIZE` is sized to cover the chain, as `soopt_getm()` allocates.  No
bug found.

## execve(2): what is proven

Harness `exec/exec_args.c`, for the argument-string accounting of
`execve(2)`, `sys/kern/kern_exec.c`: `exec_args_add_arg()` and
`exec_args_add_env()` (through `exec_args_add_str()`) each copy one user
string into the string buffer against a running budget (`stringspace`) and
advance the end pointer.  `NADD` successive appends, a prefix of them args
and the rest envs (the order the caller uses), each string of any length,
against the contract:

- the budget never underflows and never grows past its start.
- the end pointer stays inside the buffer and tracks the consumed budget
  (`endp - begin_argv == start - stringspace`).
- a string that does not fit the budget is refused with `E2BIG` (a fault
  with its own error).

The buffer is a CBMC object of exactly the budget, so the accounting is
load-bearing: the mutant `exec_args_charge`, which drops the budget
decrement, is caught by an out-of-bounds write (the next copy is handed
the whole budget again).  Mutants `exec_args_endp` and `exec_args_e2big`
take the pointer advance and the error mapping back.  The budget is a
small constant per job (the accounting is integer reasoning, the same at
any size; the real `ARG_MAX` of 256K would need a 256K symbolic buffer
that runs the solver out of memory).  `copyinstr()` is modelled to return
a length no greater than the room it was given, as `copyinstr(9)`
guarantees.  No bug found.

## recvmsg(2): what is proven

Harness `recvmsg/recvmsg.c`, for the control-message copy-out of
`recvmsg(2)`, `sys/kern/uipc_syscalls.c`: `kern_recvit()` takes a chain of
control mbufs from `soreceive()` and copies them out to the user's
`msg_control` buffer one mbuf at a time while they fit, accumulating
`msg_controllen` and flagging `MSG_CTRUNC` when the chain does not fit.  A
chain of up to `NMBUF` mbufs of any length against a user buffer of `CLEN`
bytes, with the work before the loop modelled away (`getsock()` returns a
file, `soreceive()` the chain and no address, an empty iovec list):

- each mbuf is copied out only while it still fits, right after the
  previous one, and the copy never runs past the user buffer.
- `msg_controllen` is the exact number of bytes copied out.
- `MSG_CTRUNC` is set iff the chain did not all fit.

The user buffer is a CBMC object of exactly `CLEN` bytes, so the loop's
`len >= m->m_len` guard is load-bearing: the mutant `recvit_len`, which
drops the remaining-room decrement, is caught by an out-of-bounds write
past the user buffer.  Mutants `recvit_ctlbuf`, `recvit_report` and
`recvit_ctrunc` take the destination advance, the reported length and the
truncation flag back.  No bug found.

## TCP SYN cookie: what is proven

Harness `syncache/syncookie.c`, for the SYN cookie of
`sys/netinet/tcp_syncache.c`: `syncookie_generate()` packs a connection's
MSS, window scale and SACK state plus a MAC into the 32-bit initial
sequence number of a SYN-ACK, and `syncookie_expand()` unpacks the ACK the
peer echoes, checks the MAC and restores those values.  The pair must
round-trip:

- a cookie this host generated decodes to the same MSS table entry, the
  same window-scale table entry, and the same SACK flag.

The 3-bit `mss_idx` and `wscale_idx` index the eight-entry `tcp_sc_msstab`
and `tcp_sc_wstab`, so the decode is in bounds by construction, which CBMC
also checks.  `syncookie_mac()` (SIPHASH, a byte loop) is replaced by a
deterministic, multiplier-free model: the round-trip then turns only on
the kernel's own bit packing, which is what is proven, and the SAT back
end stays fast.  Mutants `syncookie_mss`, `syncookie_wscale` and
`syncookie_sack` take the index packing and the SACK flag back.  The MSS
and window scale are constants per job (the encode walks the index
tables), the jobs sweeping the table boundaries.  Not proven here: that a
forged ACK is rejected, which rests on the MAC's collision resistance, not
on this code's packing.  No bug found.

## m_copydata(): what is proven

Harness `mbuf/m_copydata.c`, for `m_copydata()`, `sys/kern/uipc_mbuf.c`:
copy `len` bytes from offset `off` of an mbuf chain into a flat buffer,
called all over the stack to pull packet bytes out of a chain.  Under the
caller's contract (its `KASSERT`s: `off`, `len >= 0` and `off + len`
within the chain):

- the skip loop lands on the mbuf holding `off`, charging `off` against
  each mbuf it passes.
- each per-mbuf copy is `min(m_len - off, len)` bytes, read only within
  that mbuf's data, never past it.
- exactly `len` bytes are delivered to the destination.

Each mbuf's data is a CBMC object of exactly its `m_len`, so a read even
one byte past a mbuf is an out-of-bounds read: the mutant
`mcopydata_count`, which copies the whole remaining `len` from a shorter
mbuf, is caught that way, and `mcopydata_skip`, which stops charging `off`
against the skipped mbufs, is caught by the `off` underflow blowing up the
count (a `KASSERT`).  The chain geometry (per-mbuf lengths, `off`, `len`)
is a constant per job -- a symbolic chain's split combinatorics blow up --
the jobs sweeping a copy inside the first mbuf, one starting mid-mbuf, one
spanning three mbufs, an empty copy at a boundary, and an offset skipping
two mbufs.  The mapped path is proven; the `M_EXTPG` branch is not
reached.  No bug found.

Harness `mbuf/m_pulldown.c`, for `m_pulldown()`, `sys/kern/uipc_mbuf2.c`:
make `len` bytes starting at offset `off` contiguous in one mbuf, gathering
a head piece from the mbuf holding `off` and a tail piece from the next.
Used by every protocol that parses a header spanning mbufs.  Real `struct
mbuf`s, so the storage bounds and `M_TRAILINGSPACE`/`M_LEADINGSPACE` are the
kernel's; `m_dup1()` and `m_get()` go through the UMA model.  Proven: the
head and tail gather copies stay within each mbuf's storage, and on a
non-NULL return the result mbuf holds `len` contiguous bytes at the returned
offset (`offp + len <= m_len <= M_SIZE`).  The mutant `mpulldown_tlen`,
which takes one byte too few for the tail piece, is caught by the result
holding fewer than `len` contiguous bytes.  Geometry is a constant per job:
already contiguous, a chop at a non-zero offset, and a head+tail gather,
with `len <= MLEN` so the single-mbuf allocation path is taken (the cluster
path is the same logic at a larger size).  No bug found.

Harness `mbuf/m_copym.c`, for `m_copym()`, `sys/kern/uipc_mbuf.c`: copy
`len` bytes at offset `off` of a chain into a freshly allocated chain, used
all over the stack to duplicate a run of packet data.  This covers the plain
path (non-external, non-header): each new mbuf is filled with `min(len,
m_len - off)` bytes.  The source mbufs are real `struct mbuf`s, each a
separate object so an over-read is caught; the fresh mbufs come through the
UMA model.  Proven: each per-mbuf copy stays within the source and the fresh
mbuf, and on success the copied chain's lengths sum to `len`.  The mutant
`mcopym_minlen`, copying the whole remaining `len` from a shorter source
mbuf, is caught by an out-of-bounds read in a geometry placing the source at
the `MLEN` tail.  Geometry is a constant per job: a copy inside the first
mbuf, one starting mid-mbuf, a three-mbuf span, and the tail case.  The
`M_EXT` and `M_PKTHDR` branches are not covered.  No bug found.

Harness `mbuf/m_append.c`, for `m_append()`, same file: append `len` bytes
of `cp` to the end of a chain, used across the stack to grow a packet.  It
fills the last mbuf's trailing space first (up to `M_TRAILINGSPACE`), then
allocates fresh mbufs for the remainder, `min(MLEN, remainder)` bytes each.
The source is a `LEN`-byte object and each mbuf a separate object; fresh
mbufs come through the UMA model.  Proven: every copy stays within the source
buffer and the destination mbuf, the trailing fill never exceeds the last
mbuf's storage, and on success (return 1) the chain's lengths grew by exactly
`LEN`.  The mutant `mappend_space`, which drops the `space > remainder` cap on
the trailing fill, is caught by an out-of-bounds read of the source buffer
(the fill then copies the whole trailing space, far more than `LEN`).
Geometry is a constant per job: a fit in the trailing space, a spill to a
fresh mbuf, a full last mbuf, and a two-mbuf destination spilling off the end.
No bug found.

Harness `mbuf/m_copyback.c`, for `m_copyback()`, same file: the writing
counterpart, which puts `len` bytes at `off` into a chain, grows a mbuf
into its trailing room, and allocates fresh mbufs when `off` or `len`
runs past the end.  The first mbuf is a real `struct mbuf`, so its storage
bounds and `M_TRAILINGSPACE` are the kernel's, and `m_get()` allocates any
further mbufs through the UMA model (which may fail).  Proven:

- every write stays inside a mbuf's storage.
- a mbuf grows only within its trailing room, so no `m_len` ever exceeds
  `M_SIZE(m)` -- which a later reader trusting `m_len` would turn into an
  overread.
- a failed allocation stops the walk without a write past the end.

The mutant `mcopyback_grow`, which caps the growth by a huge value instead
of `M_TRAILINGSPACE`, is caught by the `m_len <= M_SIZE` invariant, and
`mcopyback_count`, which writes the whole remaining `len` into a shorter
mbuf, by an out-of-bounds write; both bite in a geometry placing the write
at the `MLEN` tail so the trailing-room cap binds.  Geometry is a constant
per job (a write inside the mbuf, one growing it into trailing room, two
allocating past the end, and the tail case).  No bug found.

Harness `mbuf/m_pullup.c`, for `m_pullup()`, same file: rearrange a chain
so its first `len` bytes are contiguous in the head, gathering them from
the following mbufs.  Every protocol parser calls it then reads `len`
bytes from the head, so the contract is load-bearing.  The chain is real
`struct mbuf`s (heap allocated, so `m_pullup()`'s `m_free()` of a consumed
mbuf is valid), `m_get()` goes through the UMA model (which may fail), and
`m_freem()` is modelled.  Proven:

- the gather stays within the head mbuf's storage and within each source
  mbuf, and no `m_len` ever exceeds `M_SIZE(m)`.
- on a non-NULL return the head holds at least `len` contiguous bytes.
- a request past `MHLEN` on the allocate path fails cleanly (`NULL`).

The mutant `mpullup_early`, which takes the "already contiguous" shortcut
unconditionally, is caught by the head then holding fewer than `len`
bytes.  Geometry is a constant per job: a pull already contiguous, a
two-mbuf pull in place, a three-mbuf gather, and a `> MHLEN` request.  The
free-space cap on the gather count is exercised by the proofs but not
mutation-checked: forcing the overshoot needs a head filled to the `MLEN`
tail, whose large-offset bounds check is too slow to run.  No bug found.

Harness `mbuf/m_split.c`, for `m_split()`, same file: split a chain in two
at byte offset `len0`, returning the tail.  This covers the plain path (no
`M_PKTHDR`, no external storage): the split mbuf's tail bytes are copied
into a fresh mbuf and the lengths divided.  Real `struct mbuf`s, so the
storage and the `M_ALIGN` placement are the kernel's.  Proven:

- the tail copy stays inside the split mbuf and the fresh mbuf.
- the split mbuf keeps exactly the bytes before the offset, the tail holds
  those after, and the two sum to the original (no byte lost or
  duplicated).
- no `m_len` exceeds its storage.

The mutants `msplit_remain` (tail one byte too long) and `msplit_mlen`
(split mbuf one byte too long) are caught by those exact-division
assertions.  Geometry is a constant per job: a split inside the first
mbuf, at a mbuf boundary (`remain == 0`), and inside a later mbuf.  The
`M_PKTHDR` and external-storage branches (`mb_dupcl`, the send-tag
reference, the recursive `remain > MHLEN` case) are a separate, heavier
proof and not covered here.  No bug found.

## IPv4 options: what is proven

Harness `ip/ip_options.c`, for `ip_dooptions()`, `sys/netinet/ip_options.c`:
the IPv4 options parser run on every received packet that carries options.
It walks the option area, trusting each option's length byte and advancing
by it, and for the record-route and timestamp options reads and writes at
an attacker-influenced pointer (`off`) into the option area.  The packet
is a `struct ip` followed by `OPTLEN` nondeterministic option bytes in one
object, so every `cp[...]` read and every `memcpy(cp + off, ...)` write is
bounds-checked against it:

- a length byte that would step the walk past the option area, and a
  record-route or timestamp pointer that would index past it, are refused
  by the loop's length and pointer checks.
- every option access stays within the option area, whatever opcodes,
  lengths and pointers the bytes encode.

The mutants `ip_optlen` (dropping the `optlen > cnt` check) and `ip_rroff`
(dropping the record-route pointer bound) are each caught by an
out-of-bounds write.  The interface, route and ICMP helpers the opcodes
reach are modelled; the route lookup returns a `struct in_ifaddr` as the
real nhop guarantees (a modelling gap there first showed a spurious
overread, since fixed).  `OPTLEN` is a constant per job (a symbolic length
ran the parser past the time budget); the jobs sweep the minimum and sizes
reaching the record-route and timestamp opcodes, up to 12 bytes -- the
full 40-byte area is too slow and adds no opcode.  No bug found.

Harness `ip/ip_fragment.c`, for `ip_fragment()`, `sys/netinet/ip_output.c`:
split an IPv4 packet too large for the outgoing MTU into fragments.  The
fragments it builds are collected off the original's `m_nextpkt` chain and
their `(ip_off, ip_len)` checked.  Proven: the fragments tile `[hlen,
ip_len)` exactly -- contiguous 8-byte-aligned offsets, each payload at most
the MTU payload, the More-Fragments bit set on every fragment but the last,
and together covering the whole payload.  The per-fragment mbuf helpers
(`m_gethdr` via the UMA model, `m_dup_pkthdr`, `m_copym`, `in_cksum`,
`ip_optcopy`) are modelled; the packet carries no options (`hlen = 20`) and
no delayed checksum.  The mutant `ip_fragment_last`, dropping the trim of
the final fragment to the remainder, is caught by the coverage check (an
over-long last fragment, with a spurious MF bit, breaks the tiling).
`ip_len` and `mtu` are constants per job (a symbolic length makes the
fragment loop unbounded); the jobs sweep an exact multiple of the fragment
payload, a remainder, and a two-fragment split.  No bug found.

Harness `ip/ip_optcopy.c`, for `ip_optcopy()`, same file: copy the "copied"
IP options from one header to another when building fragments (the real
copier the `ip_fragment` proof modelled away).  It walks the source options
and `bcopy()`s each `IPOPT_COPIED` one into the destination option area, then
pads to a 4-byte boundary.  Each header owns exactly `MAX_IPOPTLEN` option
bytes as a CBMC object, so a read or write past the area is an out-of-bounds
access.  Proven, for a well-formed source layout (as `ip_dooptions` leaves
it): every source read and destination write stays within the option area,
and the returned length is at most `MAX_IPOPTLEN`.  The mutant
`ip_optcopy_len`, copying one byte more than the option length, is caught by
an out-of-bounds write.  The source option length is a constant per job (4,
8, 40); the option data stays nondeterministic.  No bug found.

Harness `ip6/ip6_fragment.c`, for `ip6_fragment()`, `sys/netinet6/ip6_output.c`:
the IPv6 counterpart, splitting a packet into fragments of a given `fraglen`.
The fragments hang off the original's `m_nextpkt`; each fragment's
`ip6_frag` header (placed by the real, static `ip6_insertfraghdr()` in the
fragment mbuf's trailing space) and its `ip6_plen` are read back.  Proven:
the fragments tile `[hlen, tlen)` -- contiguous 8-byte-aligned offsets, each
payload at most `fraglen`, the More-Fragments bit set on every fragment but
the last and clear on the last, together covering the whole payload.  The
offset and MF bit are decoded exactly as `frag6_input()` does (mask the raw
offlg, then `ntohs`).  The per-fragment helpers (`m_gethdr` via the UMA
model, `m_dup_pkthdr`, `m_copym`, `m_cat`) are modelled.  The mutant
`ip6_fragment_last`, dropping the trim of the final fragment, is caught by
that fragment wrongly carrying the MF bit.  `tlen` and `fraglen` are
constants per job, the jobs sweeping an exact multiple and a remainder.  No
bug found.

## TCP reassembly accounting: what is proven

Harness `tcp/reass.c`, for the reassembly helpers of
`sys/netinet/tcp_reass.c`: `tcp_reass_prepend()`, which splices a new
segment in front of a queued out-of-order segment and trims the overlap,
and `tcp_reass_append()`, which tacks one onto the end.  Each maintains a
queued segment's `(tqe_start, tqe_len)` over the TCP sequence space; a
wrong trim double-counts or loses bytes.  The sequence numbers and lengths
are symbolic, bounded so the trim arithmetic cannot wrap:

- after a prepend the segment starts at the new sequence and still ends
  where the two together reach -- the overlap is trimmed exactly once, so
  no byte of the sequence space is double-counted or lost.
- after an append the segment's length grew by exactly the appended length
  and its start is unchanged.

The mutants `reass_trimlen` (dropping the length trim) and `reass_overlap`
(trimming one byte too few) are caught by the end no longer being
preserved, and `reass_appendlen` by the length not growing fully.  `m_adj()`
is modelled (it only trims the mbuf, which the accounting does not read);
the per-CPU stat macros are compiled out.  This is the reassembly-overlap
accounting the whole-function `frag6_input()` could not supply tractably
(it is too large for the solver even with concrete input).  No bug found.

Harness `tcp/reass_fwd.c`, for `tcp_reass_merge_forward()`, same file: once
a segment `ent` is in the queue, this walks the segments after it and
coalesces every one `ent` overlaps forward -- freeing a segment `ent` fully
covers, trimming a partially overlapping one and merging it in.  This is
the multi-segment overlap resolution (the fragment-overlap bug class).  A
queue of `ent` plus a few successors of a concrete per-job geometry is
built (a symbolic queue's overlap combinatorics blow up):

- afterwards `ent` spans exactly up to the furthest merged end, the overlap
  trimmed exactly, so no sequence-space byte is double-counted or lost.
- no following segment still overlaps `ent`, and the queue stays sorted.

The mutant `reass_fwdtrim` (trimming one byte too few) and `reass_fwdconsume`
(not consuming a fully covered segment) are caught by `ent`'s span no longer
matching the expected merged end.  The geometries sweep a gap (no overlap),
a partial trim, a full consume, and two successors.  No bug found.

## sbcompress(): what is proven

Harness `sockbuf/sbcompress.c`, for `sbcompress()`,
`sys/kern/uipc_sockbuf.c`: appends an mbuf chain to a socket buffer's tail,
coalescing a small mbuf into the previous one's trailing space when it
fits, else linking it in.  Hit by every protocol's receive path.  The tail
and appended mbufs are real `struct mbuf`s, so the storage bounds and
`M_TRAILINGSPACE` are the kernel's; `sballoc()` runs for real.

- the coalesce copy stays within the tail mbuf's storage.
- `sb_ccc` grows by exactly the bytes appended, and the buffer's total
  walked matches `sb_ccc`: no byte lost or double-counted.

The mutant `sbcompress_room`, which drops the `m->m_len <=
M_TRAILINGSPACE(n)` guard, is caught by an out-of-bounds write (in a
geometry with the tail near `MLEN` so the trailing room is small), and
`sbcompress_ccc`, which skips the byte-count update, by `sb_ccc` not
matching.  Geometry is a constant per job: a coalescing appendee, a too-big
one (linked), and two appendees.  No bug found.

Harness `sockbuf/sbappendaddr.c`, for `sbappendaddr_locked()`, same file:
the datagram receive append used by UDP and Unix-domain datagram sockets.
It assembles a record of (sockaddr, optional data) and puts it on the
receive buffer if there is room.  The sockaddr-carrying mbuf is real, so
the address bcopy is bounds-checked against its storage; `sballoc()` and
the space check run for real.

- a record whose length exceeds the buffer's space is refused, leaving the
  byte count unchanged.
- an accepted record grows `sb_ccc` by exactly the address plus data
  length.
- the address copy stays within its mbuf.

The mutant `sbaddr_space`, which drops the `space > sbspace()` check, is
caught by an over-sized record being accepted past the high-water.  The
address and data lengths are a constant per job, bracketing the space bound:
a record that fits, one that just overflows, and one with no data.  No bug
found.

Harness `sockbuf/sbreserve.c`, for `sbreserve_locked_limit()`, same file:
the socket-buffer sizing behind `setsockopt(SO_RCVBUF/SO_SNDBUF)`.  A
requested byte count `cc` is capped against `BUF_MAX_ADJ(buf_max)` so that
`cc * sb_efficiency` cannot overflow, then the mbuf ceiling is set to
`min(cc * sb_efficiency, buf_max)`.  `cc` is a nondeterministic `u_long`
(the attacker-chosen value); `buf_max` is bounded by `SB_MAX`, the sysctl's
real ceiling, below where `BUF_MAX_ADJ`'s own `buf_max * MCLBYTES` would
overflow.  Proven: an accepted request has `cc` within the cap (so with
`--unsigned-overflow-check` the `cc * sb_efficiency` multiply does not
overflow), `sb_mbmax <= buf_max`, `sb_hiwat == cc`, and `sb_lowat <=
sb_hiwat`.  The mutant `sbreserve_cap`, which drops the cap, is caught by
`cc` no longer being within it.  `chgsbsize()` is modelled; `lim_cur()` is
reached only with a non-NULL thread, which the proof does not pass.  No bug
found.

Harness `sockbuf/sbcreatecontrol.c`, for `sbcreatecontrol()`, same file:
build a control-message (cmsg) mbuf of `size` payload bytes, used by the
socket layer to hand ancillary data (SCM_RIGHTS, SCM_CREDS, IPv6 options) to
`recvmsg(2)`.  It sizes the mbuf by `CMSG_SPACE(size)`, zeroes it, copies
`size` payload bytes in, and writes the cmsg header.  This covers the plain
path (`CMSG_SPACE(size) <= MLEN`), where the mbuf data area is a real MLEN
object.  Proven: the `CMSG_SPACE` zero and the `size`-byte payload copy stay
within the mbuf for a small payload (`sbctl_small`) and the largest that fits
MLEN (`sbctl_fit`).  The open question `sbctl_wrap` records a latent gap: for
a `size` where `_ALIGN(size)` overflows `u_int`, `CMSG_SPACE(size)` collapses
below MLEN and the mbuf is sized small, yet the payload `memcpy` still uses
the full `size`, writing past the mbuf.  No in-tree caller passes such a
`size` (the variable-size callers bound it to a packet, or pass `p == NULL`
so the copy is skipped), so it is not reachable today; `reports/socket.md` has
the analysis.

## mmap(2): what is proven

Harness `mmap/mmap_len.c`, for the length/offset validation of
`kern_mmap()`, `sys/vm/vm_mmap.c`: `mmap(2)` adds the page offset to the
requested length and rounds up to a page (`size = round_page(len +
pageoff)`), then guards the sum wrapping to zero (`if (len > size) return
ENOMEM`).  A wrapped `size` would map fewer pages than asked -- an overflow
bug class.  `len` and `pos` are nondeterministic, and the anonymous path is
driven; `vm_mmap_object()` is intercepted to observe the size handed to the
mapping.  Proven: if the request reaches the mapping, the size passed is at
least `len` and page-aligned, so a wrapped size never takes effect.  The
mutant `mmap_wrap`, dropping the `len > size` guard, is caught by the size
reaching the mapping being smaller than `len`.  No bug found.

Harness `mmap/mlock_len.c`, for the address/length validation of
`kern_mlock()`, same file: `mlock(2)` rounds `[addr, addr+len)` to pages and
guards the sum wrapping (`last < addr || end < addr`).  `addr` and `len` are
nondeterministic; `vm_map_wire()` is intercepted to observe the range.
Proven: the range reaching `vm_map_wire()` is always ordered (`end >=
start`) and page-aligned.  The mutant `mlock_wrap`, dropping the guard, is
caught by the range no longer being ordered.

This found a coverage gap: for `addr == 0` and a `len` in the last page of
the address space (e.g. `mlock(0, (size_t)-1)`), `round_page(addr + len)`
wraps to 0; the guard `end < addr` (0 < 0) misses it, `npages` becomes
`atop(0 - 0) == 0`, and `kern_mlock()` returns success having wired nothing
-- a silent no-op instead of locking or failing.  `kern_mmap()` catches the
equivalent wrap with an explicit `len > size` check; `kern_mlock()` has
none.  Not a memory-safety issue (the 0-length range is well-formed), a
contract violation; sent to the maintainers as a question.

## sysctl(2): what is proven

Harness `sysctl/old_user.c`, for `sysctl_old_user()`,
`sys/kern/kern_sysctl.c`: the copy-out helper every `sysctl(2)` read goes
through.  It copies a chunk of the result to the user buffer at the running
offset, clamped to the validated length, and accounts the total requested
in `oldidx`.  The user buffer is a CBMC object of exactly `validlen` bytes,
so a copy-out past it is an out-of-bounds write.  The chunk length, offset
and `validlen` are nondeterministic within a small bound.  Proven: the
copy-out stays within the validated buffer (`offset + len <= validlen`),
`oldidx` advances by the whole requested chunk length, and a non-empty
chunk that did not fully fit returns `ENOMEM`.  The mutant
`sysctl_old_clamp`, dropping the remaining-room clamp, is caught by an
out-of-bounds write past the user buffer.  No bug found.

Harness `sysctl/new_user.c`, for `sysctl_new_user()`, same file: the
copy-in helper every `sysctl(2)` write goes through, the companion to
`sysctl_old_user()`.  It reads a chunk of the user's `new` buffer at the
running offset into a kernel buffer, refusing `EINVAL` if the chunk does
not fit the remaining `new` length, and accounts it in `newidx`.  The user
buffer is a CBMC object of exactly `newlen` bytes.  Proven: a chunk past
the remaining length is refused with no read and `newidx` unchanged; an
accepted chunk's copy-in stays within the buffer (`offset + len <=
newlen`), and `newidx` advances by the chunk length, staying within
`newlen`.  The mutant `sysctl_new_fit`, dropping the remaining-length
check, is caught by an out-of-bounds read past the user buffer.  No bug
found.

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
