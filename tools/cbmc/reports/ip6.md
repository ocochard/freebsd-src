# IPv6 input bug reports

Bugs found by the CBMC proofs of `tools/cbmc/ip6`, one report each.  Each
names its fix by commit subject, which is stable, and by hash on the `cbmc`
branch, which changes when the branch is rebased: look the hash up again
before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | icmp6_notify_error() reads the routing header after an m_pullup() that freed it | [a07f0cadcfc4](https://github.com/ocochard/freebsd-src/commit/a07f0cadcfc4) | sent to glebius@ |

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
