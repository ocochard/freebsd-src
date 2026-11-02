# Network-layer reports

Observations from the CBMC proofs under `tools/cbmc/slcompress` and the other
`sys/net` harnesses, in the code those proofs model, one entry each.  Each
names any fix by commit subject, which is stable, and by hash on the `cbmc`
branch, which changes when the branch is rebased: look the hash up again
before filing.

| # | Observation | Fix | Status |
|---|---|---|---|
| 1 | `sl_uncompress_tcp_core()` reads the VJ compressed header past a short wire buffer before validating the consumed length | (none) | latent, bounded by the caller's pullup; question to the maintainers |
| 2 | `icmp_input()` logs a redirect (`log_redirect`) reading the quoted `ip_dst` past a message shorter than 28 bytes | [2679c48d4cbd](https://github.com/ocochard/freebsd-src/commit/2679c48d4cbd) | ready |

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

---

## 2. icmp_input() reads past a short ICMP redirect to log it

**Fix:** 2679c48d4cbd "icmp: Do not log a redirect too short to quote a header"
(`Fixes: 18d3153eadbd`)

**What happens:** with `net.inet.icmp.log_redirect=1`, the `ICMP_REDIRECT`
case prints the redirect's quoted destination, `icp->icmp_ip.ip_dst` (ICMP
offset 24 to 27), before the length check that follows it
(`sys/netinet/ip_icmp.c`, `dst = ntohl(icp->icmp_ip.ip_dst.s_addr)`).
`icmp_input()` has only checked `icmplen >= ICMP_MINLEN` (8) and pulled up
`min(icmplen, ICMP_ADVLENMIN)`: for a redirect of 8 to 27 bytes the read
is past the end of the message, in whatever the mbuf holds beyond its data.

**Why:** the logging came with the sysctl (18d3153eadbd, 1999) and was put
before the drop and length checks so that ignored redirects are logged too.

**Reachability:** any host on the path can send a short redirect; the
logging is off by default.  Up to 4 bytes beyond the packet go to the
console as the "redirect from ... => ..." destination: stale mbuf contents,
a small information leak to whoever reads the console log.  No write, no
crash outside KASAN.

**Fix detail:** log only when `icmplen >= ICMP_ADVLENMIN`, the length the
redirect path itself requires; redirects that are then ignored (routers,
`drop_redirect`) are still logged.

**Reproduce:** no ATF test: the bytes read are stale mbuf contents, not a
stable output.  CBMC: run.sh mutant `icmp_log` (the fix taken back), at
`ICMPLEN=8`: type 5 code 0, `log_redirect` 1, `pointer outside object
bounds in icp->icmp_dun` at the `ip_dst` read.

**Found by:** CBMC's bounds checks, proof `icmp_input_8` (the datagram an
object of exactly `ip_len` bytes).

