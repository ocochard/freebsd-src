# kevent bug reports

Bugs found by the CBMC proofs of `tools/cbmc/kevent`, ready to file.
The fix is named by commit subject, which is stable, and by hash on the
`cbmc` branch, which changes when the branch is rebased: look the hash
up again before filing.

| # | Bug | Fix | Status |
|---|---|---|---|
| 1 | a negative event list length is refused only after the changes, which can write EV_ERROR events past it | [cd32be5ec761](https://github.com/ocochard/freebsd-src/commit/cd32be5ec761) | ready |
| 2 | a faulting EV_ERROR copyout is ignored and the event counted, so kevent() returns success having written nothing | [459c6f697997](https://github.com/ocochard/freebsd-src/commit/459c6f697997) | ready, developer confirmed |

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

---

## 2. kevent() ignores a fault while writing an EV_ERROR event

**Status: the developer (markj@) confirmed this is a bug: "this seems
like a (very minor) bug.  kevent() has behaved like this since the
initial commit ... I don't object to fixing this."**

**Fix:** 459c6f697997 "kevent: Return EFAULT when an EV_ERROR event cannot be copied out"
(`Fixes: 3ee12e4fe3c8`)

**What happens:** in `kqueue_kevent()`, a change that fails or carries
`EV_RECEIPT` is reported to the caller by copying an EV_ERROR event into
the event list.  The copyout result is discarded:
`(void)k_ops->k_copyout(k_ops->arg, kevp, 1)`.  If that copyout faults
(the caller's `eventlist` is unwritable), the fault is ignored: the event
is counted in `nerrors` all the same, and kevent(2) returns the count as
a success with nothing written.  The caller is told N changes produced
EV_ERROR events but its buffer is untouched, and kqueue.2 lists EFAULT
for "an error reading or writing the kevent structure".  The changelist
copyin on the same loop does return its fault; only this copyout drops
it.

**Reachability:** any process passing a `changelist` change that fails
or has `EV_RECEIPT` together with an `eventlist` that cannot be written.
Not a memory-safety bug (the write simply does not happen); a wrong
return value.

**Fix detail:** return the copyout error, as the copyin path does.  The
changes applied up to that point stay applied, which is the same contract
kqueue.2 already states for the EINTR return.

**Reproduce:** `tests/sys/kqueue/kqueue_lengths.c`, `eventlist_fault`:
an `EV_ADD | EV_RECEIPT` timer change with the `eventlist` pointing at a
`PROT_NONE` page.  In a bhyve guest it fails on the base kernel (the call
succeeds) and passes with the fix (EFAULT).  The CBMC counterexample
(`run.sh` mutant `kevent_outfault_drop`): the EV_ERROR copyout faults,
the event is counted, kevent() returns 1 with nothing written.

**Found by:** the property "a copyout fault makes kevent() return EFAULT"
(`proof_kevent -DOUTFAULT`, `kevent/kevent.c`).
