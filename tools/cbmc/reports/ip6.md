# IPv6 input bug reports

Bugs found by the CBMC proofs of `tools/cbmc/ip6`, one report each.  Each
names its fix by commit subject, which is stable, and by hash on the `cbmc`
branch, which changes when the branch is rebased: look the hash up again
before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | icmp6_notify_error() reads the routing header after an m_pullup() that freed it | [a07f0cadcfc4](https://github.com/ocochard/freebsd-src/commit/a07f0cadcfc4) | sent to glebius@ |
| 2 | ip6_process_hopopts() forms an ICMPv6 pointer past the option area | [4f2c4d73ff70](https://github.com/ocochard/freebsd-src/commit/4f2c4d73ff70) | ready (cleanup) |
| 3 | ip6_process_hopopts() accepts an option running past its header, dest6_input() drops it | none | question |

---

## 1. icmp6_notify_error() use-after-free reading rth->ip6r_nxt

**Status:** sent to glebius@ (remotely triggerable; ask whether it goes
through secteam@ before filing publicly)
**Fix:** a07f0cadcfc4 "icmp6: fix use-after-free in icmp6_notify_error()"
(`Fixes: a61b5cfbbfd5`)

**What happens:** in the `IPPROTO_ROUTING` case of the quoted-packet header
walk, `rth` points into the mbuf.  The second `m_pullup(m, eoff + rthlen)`
can take the allocate-and-copy path and free the old head; `nxt =
rth->ip6r_nxt` afterwards reads freed memory (`sys/netinet6/icmp6.c`, the
line after `eoff += rthlen;`).

**Why:** the use-after-free dates from a61b5cfbbfd5 (bz@, 2019, "Remove
PULLDOWN_TESTs"), which made `m_pullup()` relocate where `IP6_EXTHDR_CHECK`
only failed.  abb8b02550c3 (glebius@) later reshaped the function but kept
the read in place.

**Reachability:** a reassembled packet (frag6.c joins fragments with
`m_cat`) keeps an mbuf boundary at each fragment edge, and `icmp6_input()`
pulls up only the outer ICMPv6 header.  A peer lands the boundary inside the
quoted routing header by sending the ICMPv6 error in two IPv6 fragments.
The RFC 7112 full-header-chain check is still `XXX TODO` in frag6.c (thj's
D16851), so the split-header fragment is not rejected.  One-byte read of a
freed mbuf; it selects `ip6_ctlprotox[nxt]` (`nxt` is uint8_t, so the index
cannot overflow).  A remote panic on KASAN/INVARIANTS kernels; a wrong
ctlinput dispatch otherwise.  Not an info leak, no out-of-bounds index, no
write.

**Fix detail:** read `nxt` from the routing header before the second
`m_pullup()`, while `rth` is still valid.

**Reproduce:** the ATF test `tests/sys/netinet6/icmp6_rthdr_uaf` (and its
`icmp6_rthdr_uaf.py`): a two-fragment ICMPv6 Packet Too Big error quoting a
type 0 routing header, split inside that header; the target stops answering
on a KASAN kernel.  CBMC mutant `icmp6_notify_uaf` restores the read after
the pullup and is caught by "deallocated dynamic object in rth->ip6r_nxt" at
`icmp6.c` `nxt = rth->ip6r_nxt`.

**Found by:** the property that no read of the quoted headers touches a freed
mbuf, in the `ip6/icmp6_notify_error.c` proof.

---

## 2. ip6_process_hopopts() pointer arithmetic past the option area

**Status:** ready (cleanup, no behaviour change)
**Fix:** 4f2c4d73ff70 "ip6: Avoid out-of-object pointer arithmetic in ip6_process_hopopts()"
(`Fixes: 33841545909f`)

**What happens:** the offset of an ICMPv6 Parameter Problem is computed as
`erroff + opt + 1 - opthead` (Router Alert of a wrong length) and
`erroff + opt - opthead` (unknown option), `sys/netinet6/ip6_input.c`.  C
evaluates `erroff + opt` first: a pointer `erroff` (42) bytes past the
option, past the end of the option area whenever the option is within 42
bytes of its end.  Pointer arithmetic outside an object is undefined (C17
6.5.6p8).

**Why:** KAME code (33841545909f, 2001); 069a67374ed9 moved it unchanged.

**Reachability:** any peer sending a Hop-by-Hop header with an unknown
option of type bits 10 or 11, or a Router Alert of a wrong length.  As
compiled (flat address space, `-fwrapv`) the value is right: no observable
bug today.

**Fix detail:** `erroff + (opt + 1 - opthead)` and `erroff + (opt -
opthead)`: the pointer difference first, then the integer offset.

**Reproduce:** no ATF test, behaviour is unchanged.  CBMC: run.sh mutant
`hop_ptr_ub`, `pointer relation: pointer outside object bounds in
erroff + opt` (HBHLEN 6).

**Found by:** CBMC's pointer checks, proof `hopopts_6`.

---

## 3. Hop-by-Hop accepts an option running past its header

**Status:** question, not sent
**Fix:** none until answered

**What happens:** `dest6_input()` drops an option whose data runs past the
end of the header (`*(opt + 1) + 2 > dstoptlen`, `sys/netinet6/dest6.c`).
`ip6_process_hopopts()` has no such check: a PadN or a skippable unknown
option claiming more bytes than the header has left ends the walk and the
packet is accepted.  Counterexample (proof `hopopts_strict`, 6 option
bytes): `01 02 46 85 01 46`, a PadN of 2 then a PadN of 70 at the last 2
bytes.  Nothing is read past the header; the two walks just disagree.
RFC 8200 4.2 gives the option length without saying what to do when it
overruns; Linux (`ip6_parse_tlv()`) drops it in both headers.

**Draft message (to the user to send):**

    Subject: ip6_process_hopopts(): accept an option overrunning the header?

    I'm trying out CBMC on parts of the kernel and it found this:
    dest6_input() drops an option whose length runs past the end of the
    Destination Options header ("*(opt + 1) + 2 > dstoptlen"), but
    ip6_process_hopopts() has no such check: a Hop-by-Hop header with
    options 01 02 46 85 01 46 (PadN 2, then PadN 70 in the last 2 bytes)
    is accepted.  Nothing is read out of bounds.  Should Hop-by-Hop drop
    it as dest6 (and Linux) does, or is the difference intended?

