# Network-layer reports

Observations from the CBMC proofs under `tools/cbmc/slcompress` and the other
`sys/net` harnesses, in the code those proofs model, one entry each.  Each
names any fix by commit subject, which is stable, and by hash on the `cbmc`
branch, which changes when the branch is rebased: look the hash up again
before filing.

| # | Observation | Fix | Status |
|---|---|---|---|
| 1 | `sl_uncompress_tcp_core()` reads the VJ compressed header past a short wire buffer before validating the consumed length | (none) | latent, bounded by the caller's pullup; question to the maintainers |

---

## 1. sl_uncompress_tcp_core(): compressed-header DECODE reads past a short buffer

**To:** the networking maintainers (sys/net/slcompress.c)
**Subject:** VJ decompressor reads a compressed header past a short wire buffer before the length check

**What happens:** on the `TYPE_COMPRESSED_TCP` path, `sl_uncompress_tcp_core()`
walks the compressed header with `cp`, reading 1 to 3 bytes per changed field
through the `DECODE{L,S,U}` macros, and checks how much it consumed only
afterward:

	vjlen = cp - buf;
	buflen -= vjlen;
	if (buflen < 0)
		goto bad;

So for a compressed packet whose `changes` mask asks for more fields than the
wire buffer holds, the `DECODE` reads run past the end of `buf` before that
check rejects the packet.  CBMC flags the `cp[1]`/`cp[2]` reads (e.g. at the
`NEW_I` / `NEW_A` / `NEW_S` decodes) as out of bounds for a buffer shorter
than the mask's worst-case 19-byte walk.

**Why:** the decoder is optimistic by design -- it decodes first and validates
the length last.  The worst-case consumption is 19 bytes: `changes` (1) +
explicit state index (1) + `th_sum` (2) + up to four `NEW_*` fields and
`NEW_I`, each a `DECODE` of up to 3 bytes.

**Reachable:** the in-tree caller `ng_vjc` (`sys/netgraph/ng_vjc.c`) does
`m_pullup(m, need2pullup)` with `need2pullup = min(MAX_VJHEADER, pkthdr.len)`
and `MAX_VJHEADER == 19`.  So when `pkthdr.len >= 19` the buffer holds the
full 19-byte worst case and no read runs past it.  When `pkthdr.len < 19`,
`need2pullup` is clamped to `pkthdr.len`, the buffer is that short, and a
compressed packet with an aggressive `changes` mask reads up to `19 -
pkthdr.len` bytes past its valid data.  Those bytes are within the mbuf's
storage in the common case (not a wild out-of-bounds), the decoded header is
discarded because the subsequent `buflen < 0` check tosses the packet, and
the read is of adjacent mbuf bytes, so this is a latent robustness/read-past
issue rather than a demonstrated exploit.

**Fix:** none proposed.  A lower bound on `buflen` before the decode walk (or
a per-`DECODE` bound) would turn the optimistic read into an early reject.  A
question to the maintainers on whether to add one.

**Found by:** the property "every `cp` read over the DECODE walk stays within
the wire buffer", which fails for a buffer shorter than the change mask's walk
(the open question `slcmp_short`, `tools/cbmc/slcompress/compress.c`).  The
`TYPE_UNCOMPRESSED_TCP` path, with explicit `hlen > buflen` guards, is proven
safe (`slunc_small`, `slunc_big`).
