# Socket layer bug reports

Latent defects found by the CBMC proofs under `tools/cbmc/sockbuf` and
`tools/cbmc/setsockopt`, in the socket code those proofs model, one report
each.  Each names any fix by commit subject, which is stable, and by hash on
the `cbmc` branch, which changes when the branch is rebased: look the hash up
again before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | `sbcreatecontrol()` `CMSG_SPACE(size)` wraps `u_int`, undersizing the mbuf while the payload copy uses the full `size` | (none) | latent, not reachable in-tree; question sent to the maintainers |

---

## 1. sbcreatecontrol(): CMSG_SPACE(size) u_int wrap undersizes the control mbuf

**To:** the socket-layer maintainers (sys/kern/uipc_sockbuf.c)
**Subject:** sbcreatecontrol(): CMSG_SPACE(size) u_int wrap undersizes the control mbuf

**What happens:** `sbcreatecontrol(p, size, ...)` (`sys/kern/uipc_sockbuf.c`)
sizes its control-message mbuf by `CMSG_SPACE(size)` but copies the payload
with the original `size`.  For a `size` large enough that `_ALIGN(size)`
overflows `u_int`, `CMSG_SPACE(size)` collapses to a small value while the
`memcpy(CMSG_DATA(cp), p, size)` still moves `size` bytes, writing far past
the mbuf.

**Why:** `size` is a `u_int`.  `CMSG_SPACE(l)` is
`_ALIGN(sizeof(struct cmsghdr)) + _ALIGN(l)`, and `_ALIGN(l)` rounds `l` up to
the pointer alignment, `(l + 7) & ~7`, in the type of `l`.  For
`size == 0xfffffff9` (and any `size > 0xfffffff8`), `size + 7` carries past
`0xffffffff` and `_ALIGN(size)` wraps to 0.  So:

- `CMSG_SPACE(size) == _ALIGN(sizeof(struct cmsghdr)) + 0 == 16`.
- `16 > MCLBYTES` is false, so the `M_NOWAIT` guard does not reject it.
- `16 > MLEN` is false, so a plain `m_get()` mbuf (MLEN) is taken, not a
  cluster.
- `KASSERT(CMSG_SPACE(size) <= M_TRAILINGSPACE(m))` holds (16 <= MLEN).
- `bzero(cp, 16)` is fine, but `if (p != NULL) memcpy(CMSG_DATA(cp), p, size)`
  copies `0xfffffff9` bytes into the 16-byte-intended, MLEN-storage mbuf: a
  massive out-of-bounds write.

**Reachable:** not by any in-tree caller.  The callers with a variable `size`
bound it to a received packet (`ip6_input.c`: `hbhlen`/`elen` are
`(u8 + 1) << 3 <= 2048`) or pass `p == NULL` so the payload `memcpy` is
skipped (`uipc_usrreq.c`: SCM_RIGHTS/SCM_CREDS).  The fixed-`size` callers
pass `sizeof(...)`.  So the wrap is a latent gap, not a live bug: it would
bite a future or out-of-tree caller that passes an attacker-controlled
near-`UINT_MAX` `size` with a non-NULL `p`.

**Fix:** none proposed yet.  A guard rejecting a `size` whose `CMSG_SPACE`
would wrap (for example `if (size > CMSG_SPACE(size))`, or an explicit cap)
would turn the silent overrun into a `NULL` return.  A question to the
maintainers on whether to add it.

**Found by:** the property "the CMSG_SPACE zero and the size-byte payload copy
stay within the mbuf", which holds for small and MLEN-fitting sizes
(`sbctl_small`, `sbctl_fit`) and fails for the wrap size (the open question
`sbctl_wrap`) (`tools/cbmc/sockbuf/sbcreatecontrol.c`).
