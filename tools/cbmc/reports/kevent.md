# kevent bug reports

Bugs found by the CBMC proofs of `tools/cbmc/kevent`, ready to file.
The fix is named by commit subject, which is stable, and by hash on the
`cbmc` branch, which changes when the branch is rebased: look the hash
up again before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | a negative event list length is refused only after the changes, which can write EV_ERROR events past it | [cd32be5ec761](https://github.com/ocochard/freebsd-src/commit/cd32be5ec761) | ready |

---

## 1. kevent() writes EV_ERROR events with a negative event list length

**Fix:** cd32be5ec761 "kevent: Refuse a negative event list length before the changes"
(`Fixes: e00bae5c181a`)

**What happens:** e00bae5c181a ("kevent: Prohibit negative change and
event list lengths") made kevent(2) return EINVAL for a negative
`nevents`, because a negative length "would result in bogus copyouts",
and kqueue.2 says so ("The specified length of the event or change
lists is negative").  The check went into `kqueue_scan()`, which runs
after the change list.  In `kqueue_kevent()`, a change that fails, or
has `EV_RECEIPT`, is reported as an EV_ERROR event when `nevents != 0`,
and a negative `nevents` is not 0: the event is copied out to the
event list, `nevents` goes further below 0, and the call returns the
number of such events instead of EINVAL.  Every later failing change
is written after it, as many as the change list holds, past the length
the caller gave.

**Reachability:** any process, with a kqueue and a change that fails
or has `EV_RECEIPT`.  The writes go to the caller's own memory, at the
address it passed, so this is an API contract bug, not a kernel memory
one; a caller with a buffer smaller than its change list gets it
overrun.

**Fix detail:** refuse a negative `nevents` with the negative
`nchanges`, at the top of `kqueue_kevent()`, before any change is
applied.

**Reproduce:** `tests/sys/kqueue/kqueue_lengths.c`, `negative_nevents`:
an `EV_ADD | EV_RECEIPT` change with `nevents` -1.  In a bhyve guest it
fails on the base kernel (the call succeeds) and passes with the fix
(EINVAL, the change not applied).  The CBMC counterexample (`run.sh`
mutant `kevent_negevents_late`): `nevents` -1, one change with
`EV_RECEIPT`, one EV_ERROR event written to the event list, the call
returning 1.

**Found by:** the property of kevent(2) "writes within the event list's
nevents entries" (`proof_kevent -DNEGEVENTS`, `kevent/kevent.c`).
