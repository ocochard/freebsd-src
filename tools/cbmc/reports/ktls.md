# KTLS bug reports

Bugs found by the CBMC proofs of `tools/cbmc/ktls`, ready to file.  The
fix is named by commit subject, which is stable, and by hash on the
`cbmc` branch, which changes when the branch is rebased: look the hash up
again before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | a NIC-decrypted record shorter than its tag is a NULL dereference | [a482e648447b](https://github.com/ocochard/freebsd-src/commit/a482e648447b) | waiting for the developer |
| 2 | a receive tag reset tests the wrong capability bits | [a0d672151d9e](https://github.com/ocochard/freebsd-src/commit/a0d672151d9e) | ready |
| 3 | a chain of packets loses its receiving interface | [447cba6c6808](https://github.com/ocochard/freebsd-src/commit/447cba6c6808) | ready |

---

## 1. ktls_decrypt() walks off the chain on a short NIC-decrypted record

**Status: candidate fix; asked the developer whether the hardware can
deliver such a record.**

**Fix:** a482e648447b "ktls: Refuse a NIC-decrypted record shorter than its trailer"
(`Fixes: fe8c78f0d202`)

**What happens:** `ktls_decrypt()` checks a record's length against its
header length only (`tls_len < tls_hlen`).  For a record the NIC marked
decrypted (`KTLS_MBUF_CRYPTO_ST_DECRYPTED`), it then takes the trailer to
be `tls_tlen` long whatever the record's length.  A record shorter than
its header and trailer gives a negative payload length, stored as a
large one in `tgr.tls_length`, and the trailer trim,
`for (m = data; remain > m->m_len; m = m->m_next)`, walks past the end of
the chain and dereferences NULL.  The software paths
(`ktls_ocf_tls12_aead_decrypt()`, `ktls_ocf_tls13_aead_decrypt()`,
`ktls_ocf_tls_cbc_decrypt()`) refuse such records with EMSGSIZE.

**Reachability:** `sbappend_ktls_rx()` marks all mbufs of a packet
decrypted when the driver set `CSUM_TLS_DECRYPTED` (mlx5:
`mlx5_en_rx.c`, per completion; cxgbe TOE: `t4_tls.c`).  The record
header is the peer's; whether the NIC reports such a record decrypted is
the hardware's, not visible in the source.  TLS 1.3 records were already
refused (EBADMSG, the content type falls in the header).

**Fix detail:** in the decrypted case, fail with EMSGSIZE when
`tls_len < tls_hlen + tls_tlen`, as the software paths do; the error
path drops the record and sets `so_error`.

**Reproduce:** no test: it needs a NIC with TLS receive offload.  The
CBMC counterexample (`run.sh` mutant `ktls_rx_decrypt_tagless`): AES-GCM
TLS 1.2 (header 13, tag 16), a 20-byte record in one mbuf, decrypted by
the NIC: payload -9, `remain` 65527, NULL dereference reading `m->m_len`.

**Found by:** memory safety of `ktls_decrypt()` (`proof_rx_decrypt`,
`ktls/ktls_rx.c`).

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
