# sendfile(2) bug reports

Bugs found by the CBMC proofs of `tools/cbmc/sendfile`, one report each,
ready to file.  Each names its fix by commit subject, which is stable,
and by hash on the `cbmc` branch, which changes when the branch is
rebased: look the hash up again before filing.  Every fix adds a test
to `lib/libc/tests/sys/sendfile_test.c` (but the `SF_NODISKIO` one, see
there), which fails on a kernel built from `aa4086951b4a` and passes
with the fix in a bhyve guest, the other cases unchanged.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | `nbytes` past `OFF_MAX` sends nothing | [b8708a7c4d8e](https://github.com/ocochard/freebsd-src/commit/b8708a7c4d8e) | ready |
| 2 | partial trailer left out of `*sbytes` | [40f5b7d9c7a6](https://github.com/ocochard/freebsd-src/commit/40f5b7d9c7a6) | ready |
| 3 | header dropped when there is no file data | [42f012912f61](https://github.com/ocochard/freebsd-src/commit/42f012912f61) | ready |
| 4 | `SF_NODISKIO` sends bytes never read | [5ffb5c5fb98c](https://github.com/ocochard/freebsd-src/commit/5ffb5c5fb98c) | private, sent to glebius@ |
| 5 | header/trailer dropped when the file shrinks | [6ee7ec9c8778](https://github.com/ocochard/freebsd-src/commit/6ee7ec9c8778) | waiting for the developer |
| 6 | short header/trailer write reported as success | [67d6e7e09420](https://github.com/ocochard/freebsd-src/commit/67d6e7e09420) | confirmed by the developer |
| 7 | truncated shared memory object sent as zeros | [20c3302e9d29](https://github.com/ocochard/freebsd-src/commit/20c3302e9d29) | ready |

Open question, no fix yet: data truncated after `sendfile()` queued it
and before the socket transmitted it arrives part zeroed, part old (see
`../README.md`, `sendfile_resize_window`); sendfile.2 says nothing of
the file changing before transmission.

The two manual page commits, `a5bf794ee696` (readahead wording) and
`c602ed263a2b` (two more errors), were confirmed by the developer and
need no report.

---

## 1. sendfile(2) sends nothing when nbytes exceeds OFF_MAX

**Fix:** b8708a7c4d8e "sendfile: Send to EOF when nbytes does not fit an off_t"

**What happens:** `sendfile(fd, s, 0, SIZE_MAX, NULL, &sbytes, 0)` on a
10-byte file returns 0 with `sbytes == 0` and sends nothing.  So does
any `nbytes` above `OFF_MAX`.  sendfile.2 says `nbytes` is how many
bytes to send, so `SIZE_MAX` should send to the end of the file.

**Why:** `vn_sendfile()` passes the `size_t` `nbytes` to `omin()`, which
takes `off_t`, so a value above `OFF_MAX` turns negative and `rem` is
negative.  The same conversion overflows `nbytes + offset` when the
file size changes during the call.  The bug predates the 2016 rewrite
(`omin(rem, nbytes)` before it).

**Reproduce:** test `nbytes_past_off_max`.

**Found by:** the property "the file bytes asked for are sent", with
`nbytes` free over all of `size_t`.

---

## 2. sendfile(2) leaves a partial trailer out of *sbytes

**Fix:** 40f5b7d9c7a6 "sendfile: Count a partial trailer in sbytes"

**What happens:** when the trailer write stops short with an error such
as EPIPE (the peer goes away mid-trailer), the bytes of the trailer
that did go out are not counted in `*sbytes`.  sendfile.2 says `*sbytes`
holds the number of bytes sent on the socket.

**Why:** `kern_filewrite()` returns the count written together with the
error, and `vn_sendfile()` added it to `sbytes` only when there was no
error.

**Reproduce:** test `sbytes_partial_trailer`: the peer reads the file
and part of a 1 MiB trailer, then exits; `sbytes` is 10, the file only.

**Found by:** the property "sbytes is what the socket received".

---

## 3. sendfile(2) drops the header when there is no file data

**Fix:** 42f012912f61 "sendfile: Send the header when there is no file data"
(`Fixes: 2bab0c553588`)

**What happens:** with `offset` at or past the end of the file, or an
empty file, the header given in `hdtr` is silently dropped while the
trailer is sent: a header "HEAD" and trailer "TAIL" give "TAIL",
`sbytes == 4`.  The comment in `kern_sendfile()` says that past EOF
only the header and trailer are sent, and before `2bab0c553588` the
header was.

**Why:** the header goes out with the first file pages, in the loop
that runs while there is file data left; with none, the loop does not
run.

**Reproduce:** test `hdtr_without_file_data`.

**Found by:** the property "the whole header is sent".

---

## 4. sendfile(2) with SF_NODISKIO may send bytes never read from the file

**Status: security sensitive, sent privately to glebius@ on 2026-10-10.
Do not file publicly until he answers.**

**Fix:** 5ffb5c5fb98c "sendfile: Validate the pages of a short grab over all they send"

**What happens:** with `SF_NODISKIO`, when `vm_page_grab_pages_unlocked()`
stops short of the run at a busy page, `sendfile_swapin()` checks the
validity of the last page grabbed with `xfsize()` over the shorter
count, that is only over the bytes a run ending there would use.
`vn_sendfile()` then trims the run with `fixspace()` and sends that page
whole.  When the page is only partly valid, the bytes past that point,
which were never read from the file and may hold stale memory, go out
on the socket.

**Reproduce:** no deterministic test: it needs a concurrent busy page
and a partly valid one.  The CBMC counterexample: an 8193-byte file,
offset 0, whose third page is busy and whose second page has its first
`DEV_BSIZE` chunk valid but not its fourth; the second page is checked
over 1 byte and sent over 4096.

**Found by:** the property "only file bytes read from the file are sent"
(`proof_nodiskio`).

---

## 5. sendfile(2) drops the header and trailer when the file shrinks

**Status: candidate fix, waiting for the developer to say whether this
is the intended behaviour; the manual says nothing of a file that
changes size during the call.**

**Fix:** 6ee7ec9c8778 "sendfile: Send the header and trailers when the file shrinks"

**What happens:** when the file is truncated below the current offset
during the call, `vn_sendfile()` takes `goto done`: a header copied in
that iteration is freed, the trailers are skipped, and the call returns
0.  When the offset is past the end of the file from the start, the
header and trailers are sent.

**Reproduce:** test `trailer_after_truncation`: a 1 MiB file truncated
while a blocking `sendfile()` waits for socket buffer space returns 0,
and the peer never sees the trailer.

**Found by:** the properties "the whole header is sent" and "the whole
trailer is sent", with the file size changing during the call.

---

## 6. sendfile(2) reports a short header or trailer write as success

**Fix:** 67d6e7e09420 "sendfile: Fail when a header or trailer write is cut short"

**What happens:** the header (when there is no file data) and the
trailers are written with `kern_filewrite()`.  On a stream socket,
`sousrsend()` clears EAGAIN, EINTR and ERESTART once some data went
out, so a write cut short by a full non-blocking socket, a send timeout
or a signal returned 0, and so did `sendfile()`.  sendfile.2 says it
fails with EAGAIN (or EINTR for a signal) and reports the bytes sent in
`*sbytes`.  The developer confirmed this is a code bug.

**Fix detail:** after a short write with no error, fail with EINTR when
a signal is pending, EAGAIN otherwise.

**Reproduce:** test `hdtr_short_nonblocking`: a 1 MiB trailer, or
header with an empty file, on a non-blocking socket nobody reads.

**Found by:** the property "a short write makes sendfile(2) fail with
EINTR or EAGAIN".

---

## 7. sendfile(2) sends a truncated shared memory object as zeros

**Fix:** 20c3302e9d29 "sendfile: Keep a shared memory object from shrinking under the pages"

**What happens:** for a vnode, `vn_sendfile()` checks the size again on
every pass under the vnode lock, which a truncation takes exclusive.
For a shared memory object it read the size once and held nothing that
keeps `shm_dotruncate_locked()` out.  An object truncated while
`sendfile()` waits for socket buffer space has the pages past its new
end grabbed again, outside the object's size and after their swap
reservation was released, and sent as zeros: a 1 MiB object truncated
to 0 still sends 1 MiB, 960 KiB of it zeros, and `sendfile()` returns
0 with `sbytes == 1048576`.

**Fix detail:** hold the object's range lock, as `shm_read()` does,
from a size check on every pass until the pages are wired.

**Reproduce:** test `shm_truncation`.

**Found by:** the property "grabs only pages within the object's size",
with the object truncated where `vn_sendfile()` holds no lock that
keeps the truncation out.
