# KTLS bug reports

Bugs found by the CBMC proofs of `tools/cbmc/ktls`, ready to file.  The
fix is named by commit subject, which is stable, and by hash on the
`cbmc` branch, which changes when the branch is rebased: look the hash up
again before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | a NIC-decrypted record's length is not checked against its trailer (hardening) | [a482e648447b](https://github.com/ocochard/freebsd-src/commit/a482e648447b) | hardening, developer answered |
| 2 | a receive tag reset tests the wrong capability bits | [a0d672151d9e](https://github.com/ocochard/freebsd-src/commit/a0d672151d9e) | ready |
| 3 | a chain of packets loses its receiving interface | [447cba6c6808](https://github.com/ocochard/freebsd-src/commit/447cba6c6808) | ready |
| 4 | a CBC record with more than 128 bytes of padding is refused | [1ae48c201579](https://github.com/ocochard/freebsd-src/commit/1ae48c201579) | ready |
| 5 | TLS receive on a spliced socket is refused with EALREADY, not EINVAL | [a71bb0992737](https://github.com/ocochard/freebsd-src/commit/a71bb0992737) | ready |
| 6 | a record type message without its byte sends a byte of stale kernel memory | [dfa7f43dbdf6](https://github.com/ocochard/freebsd-src/commit/dfa7f43dbdf6) | ready |

---

## 1. ktls_decrypt() trusts a NIC-decrypted record's length

**Status: hardening.  The developer answered that a driver is expected
to pass up an M_DECRYPTED record only with a length it knows to hold
the header and trailer, as cxgbe does; the check makes ktls_decrypt()
not depend on that.**

**Fix:** a482e648447b "ktls: Refuse a NIC-decrypted record shorter than its trailer"
(`Fixes: fe8c78f0d202`)

**What happens:** `ktls_decrypt()` checks a record's length against its
header length only (`tls_len < tls_hlen`).  For a record the NIC marked
decrypted (`KTLS_MBUF_CRYPTO_ST_DECRYPTED`), it then takes the trailer to
be `tls_tlen` long whatever the record's length.  Were a record shorter
than its header and trailer marked decrypted, its payload length would
be negative, stored as a large one in `tgr.tls_length`, and the trailer
trim, `for (m = data; remain > m->m_len; m = m->m_next)`, would walk past
the end of the chain and dereference NULL.  The software paths
(`ktls_ocf_tls12_aead_decrypt()`, `ktls_ocf_tls13_aead_decrypt()`,
`ktls_ocf_tls_cbc_decrypt()`) refuse such records with EMSGSIZE.

**Reachability, by the drivers:** `sbappend_ktls_rx()` marks all mbufs
of a packet decrypted when the driver set `CSUM_TLS_DECRYPTED`.
- cxgbe TOE (`t4_tls.c`, `do_rx_tls_cmp()`) cannot get there: it reports
  a decryption error as EBADMSG and passes no record up, and it builds
  the decrypted record it passes up itself, the header, the data and
  `tls_tlen` bytes of trailer, rewriting the header's length to match.
- mlx5 (`mlx5_en_rx.c`) marks a packet decrypted from its completion
  entry, one with an error not, and passes the record as on the wire,
  its trailer the peer's.  It gets there only if the NIC reports as
  decrypted a record too short to carry its tag, which it cannot have
  authenticated; whether firmware ever does is not visible in the source.
- TLS 1.3 records are refused anyway (EBADMSG, the content type falls in
  the header).

**Fix detail:** in the decrypted case, fail with EMSGSIZE when
`tls_len < tls_hlen + tls_tlen`, as the software paths do; the error
path drops the record and sets `so_error`.  A comparison per record
decrypted by the NIC.

**Reproduce:** no test: it needs a NIC that breaks the contract above.
The CBMC counterexample (`run.sh` mutant `ktls_rx_decrypt_tagless`):
AES-GCM TLS 1.2 (header 13, tag 16), a 20-byte record in one mbuf, marked
decrypted: payload -9, `remain` 65527, NULL dereference reading
`m->m_len`.

**Found by:** memory safety of `ktls_decrypt()` (`proof_rx_decrypt`,
`ktls/ktls_rx.c`), with the NIC's marks free.

---

## 2. ktls_reset_receive_tag() tests the wrong receive TLS capability bits

**Fix:** a0d672151d9e "ktls: Fix capability checks in ktls_reset_receive_tag()"
(`Fixes: fe8c78f0d202`)

**What happens:** when packets of a connection with NIC receive TLS
offload arrive on another interface, `ktls_input_ifp_mismatch()` has
`ktls_reset_receive_tag()` swap the receive tag for one on that
interface.  It releases the old tag, then checks the interface can
receive TLS with `if_getcapenable2(ifp) & IFCAP2_RXTLS4` (IPv4) or
`& IFCAP2_RXTLS6` (IPv6).  `IFCAP2_RXTLS4` and `IFCAP2_RXTLS6` are bit
numbers, 0 and 1, not masks (`IFCAP2_BIT()` makes the mask).  So for
IPv4 the test is `& 0`, always false: no new tag is ever asked for, and
the connection stays in software decryption for good after any change of
input interface.  For IPv6 it tests the RXTLS4 bit: a tag is asked for
on an interface that has RXTLS4 but not RXTLS6, and not on one with only
RXTLS6.

**Why:** the same checks in `ktls_alloc_rcv_tag()` had the same mistake,
fixed in c721694a1ca8 ("ktls_alloc_rcv_tag: Fix capability checks for
RXTLS4/6"); this copy was left.

**Fix detail:** use `IFCAP2_BIT(IFCAP2_RXTLS4)` and
`IFCAP2_BIT(IFCAP2_RXTLS6)`, as `ktls_alloc_rcv_tag()` does.

**Reproduce:** no test: it needs a NIC with TLS receive offload and an
input path change.  The CBMC counterexamples (`run.sh` mutants
`ktls_rx_tag_v4`, `ktls_rx_tag_v6`), with `if_capenable2` = 1 (RXTLS4):
an IPv4 connection asks for no tag; an IPv6 one asks for a tag the
interface cannot give.

**Found by:** the properties of `ktls_reset_receive_tag()`, "a new tag is
asked for where it can" and "no tag where the interface cannot receive
TLS" (`proof_rx_tag_reset`).

---

## 3. sbappend_ktls_rx() loses the interface of a chain of packets

**Fix:** 447cba6c6808 "ktls: Take the receiving interface of each packet in sbappend_ktls_rx()"
(`Fixes: fe8c78f0d202`)

**What happens:** `sbappend_ktls_rx()` turns the mbuf chain TCP appends
to a TLS receive buffer into plain data, one packet header at a time,
and remembers the interface the packets came in on to see whether it is
still the one the session's receive tag is on.  It reads that interface
as `m->m_pkthdr.leaf_rcvif`, from the chain's first mbuf, inside the
loop over the packet headers `n`.  The first pass demotes `m`'s packet
header, and `m_demote_pkthdr()` zeroes it: when the chain holds a second
packet header, the interface read is NULL, and the check that calls
`ktls_input_ifp_mismatch()` is skipped.  A change of input interface is
then not noticed on that append, and the receive tag stays on the old
interface until a later append of a single packet.  TCP reassembly
appends such chains (`tcp_reass.c`).  The same loop reads the decrypted
mark from `n`, as intended.

**Fix detail:** read `n->m_pkthdr.leaf_rcvif`, the interface of the
packet whose header is being demoted, so the last packet's is kept.

**Reproduce:** no test: it needs a NIC with TLS receive offload and a
change of input interface during reassembly.  The CBMC counterexample
(`run.sh` mutant `ktls_rx_append_first`): a chain of two packets, the
last in on another interface than the session's; `ktls_input_ifp_mismatch()`
is not called.

**Found by:** the property of `sbappend_ktls_rx()` "the session is told
the last packet came in elsewhere" (`proof_rx_append`, `ktls/ktls_sb.c`).

---

## 4. ktls_ocf_tls_cbc_decrypt() refuses valid padding of more than 128 bytes

**Fix:** 1ae48c201579 "ktls: Compare CBC padding bytes as unsigned"
(`Fixes: 9a673b715897`)

**What happens:** software decryption of an AES-CBC TLS 1.1 or 1.2
record checks its padding with `check_padding()`, called through
`m_apply()` on each padding byte.  It reads the bytes through a
`const char *` and compares them with the padding length, a `uint8_t`:
`if (*cp != pad)`.  `char` is signed on amd64 and i386, so a byte of
128 or more reads as negative and never equals `pad`.  Every record
whose padding length byte is 128 to 255 is refused with EBADMSG, though
RFC 5246 6.2.3.2 allows padding of up to 255 bytes, to hide a message's
length, and requires the receiver to accept it.  `ktls_decrypt()` then
sets `so_error` and the connection fails.

**Reachability:** any peer sending a CBC record with more than 128
bytes of padding to a socket with software KTLS receive (CBC receive is
TLS 1.1 and 1.2 only).  It breaks the connection, no more: a padding
check that refuses too much reads nothing out of bounds.  Architectures
where `char` is unsigned (arm64, powerpc, riscv) are not affected.

**Fix detail:** read the padding through `const uint8_t *`.

**Reproduce:** `tests/sys/kern/ktls_test.c` gains
`ktls_receive_*_cbc_*_padding_128_extra`, a record with 144 or more
bytes of padding.  In a bhyve guest, on the base kernel all eight
cases fail (`recvmsg()` returns an error); with the fix all pass, as do
the `padding_32_extra` cases on both.  The CBMC counterexample
(`run.sh` mutant `ktls_ocf_cbc_sign`): a 176-byte TLS record, padding
byte 135 and all 136 padding bytes 135, refused with EBADMSG.

**Found by:** the property of `ktls_ocf_tls_cbc_decrypt()` "any padding
RFC 5246 allows goes on to the MAC" (`proof_cbc_decrypt`,
`ktls/ktls_ocf.c`), on a record of 304 bytes.

---

## 5. ktls_enable_rx() refuses a spliced socket with EALREADY

**Fix:** a71bb0992737 "ktls: Return EINVAL for TLS receive on a spliced socket"
(`Fixes: 1000cc4a0d39`)

**What happens:** 1000cc4a0d39 ("so_splice: Disallow splicing with
KTLS-enabled sockets") made `ktls_enable_tx()` and `ktls_enable_rx()`
refuse a socket whose buffer is spliced, with EINVAL, and EALREADY
still for one that already has a session.  `ktls_enable_tx()` returns
the error it set.  `ktls_enable_rx()` sets it, then returns EALREADY
whatever it is, so setsockopt(2) TCP_RXTLS_ENABLE on the source of a
splice fails with EALREADY ("Operation already in progress"), as if TLS
receive were already on.

**Reachability:** any process that splices a socket (SO_SPLICE) and then
enables TLS receive on it.  The session is refused either way; only the
error is wrong.

**Fix detail:** return the error, as `ktls_enable_tx()` does.

**Reproduce:** `tests/sys/kern/ktls_test.c` gains `ktls_spliced_socket_rx`.
In a bhyve guest it fails on the base kernel ("Expected errno 22, got
37") and passes with the fix.  The CBMC counterexample (`run.sh` mutant
`ktls_enable_rx_ret`): a receive buffer spliced, no session, the error
EINVAL set, EALREADY returned.

**Found by:** the property of `ktls_enable_rx()` "refused on a spliced
socket (1000cc4a0d39)" (`proof_enable_rx`, `ktls/ktls_enable.c`).

---

## 6. sosend_generic() reads a TLS record type past its control message


**Fix:** dfa7f43dbdf6 "ktls: Check the record type message holds its byte"
(`Fixes: b2e60773c6b0`)

**What happens:** on a socket with a TLS send session,
`sosend_generic_locked()` takes a control message of type
`TLS_SET_RECORD_TYPE` as the type of the records it sends, its payload
"a single byte holding the desired TLS record type" (ktls(4)).  It
checks only that the message holds a `struct cmsghdr`, `clen >=
sizeof(*cm)`, 12 bytes on amd64, then reads `*CMSG_DATA(cm)`, at offset
16.  A control message of 12 to 16 bytes has no byte there: the read
is past the data `sockargs()` copied in, inside the mbuf it was copied
into, which `m_get2()` does not clear.  The byte read is what that
mbuf held before, and `ktls_frame()` writes it into the records' header
(TLS 1.2 and earlier) or inner content type (TLS 1.3).  `sendit()`
accepts any `msg_controllen` of at least `sizeof(struct cmsghdr)`, and
no one checks `cmsg_len`.

**Reachability:** any process with a KTLS send socket, a single
sendmsg(2) with `msg_controllen` of 12 to 16: one byte of a freed mbuf
per call sent to the peer.  A process connected to itself over loopback
reads it back.  All modes (software, NIC, TOE).

**Fix detail:** require `clen >= CMSG_LEN(sizeof(tls_rtype))`.  A
shorter message is no longer taken as a record type and goes to TCP,
which refuses control data with EINVAL.  The message's level is not
checked either, so any cmsg of type 1 (e.g. SCM_RIGHTS) is taken as a
record type; ktls(4) names no level, so the fix leaves that alone.

**Reproduce:** `tests/sys/kern/ktls_test.c` gains
`ktls_transmit_short_record_type`, a sendmsg(2) with a 16-byte control
message.  In a bhyve guest it fails on the base kernel (the send
succeeds) and passes with the fix (EINVAL); the
`ktls_transmit_*_control` cases pass on both.  The CBMC counterexample
(`run.sh` mutant `ktls_send_cmsglen`): a 16-byte control message of type
`TLS_SET_RECORD_TYPE`, read at offset 16, outside the object; the
record went out with type 199.

**Found by:** memory safety of `sosend_generic_locked()`
(`proof_send`, `ktls/ktls_send.c`), on control messages of exactly the
bytes the user gave.
