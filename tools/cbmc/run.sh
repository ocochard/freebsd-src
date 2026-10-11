#!/bin/sh
#
# Copyright (c) 2026 Olivier Cochard <olivier@FreeBSD.org>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# run.sh - prove kernel code with cbmc(1), and prove the proofs bite
#
# Two passes, and both have to hold: a checker that says nothing has
# either found nothing or checked nothing, and only a control tells the
# two apart.
#
#   1. Each proof against the source as it is in sys/: cbmc has to answer
#      VERIFICATION SUCCESSFUL.
#   2. Each proof against mutants of that source, each with one fix taken
#      back or one check removed: cbmc has to answer VERIFICATION FAILED.
#      A mutation that no longer applies, because the line it edits has
#      changed, fails the run too, since proving the unmutated file a
#      second time is the failure this pass exists for.
#
# A harness includes the kernel source file whole, so what is proven is
# the kernel's code; the functions it calls in the rest of the kernel are
# modelled in model/kern.h and in the harness.  The build is a kernel
# module build (KLD_MODULE) with INVARIANTS, so that every KASSERT() is a
# property, and with SAN_NEEDS_INTERCEPTORS, as KCSAN builds are, so that
# atomics are calls to the model rather than inline assembly.
#
# Usage: run.sh [syscall ...]	(default: every one listed below)
# ONLY=regex runs only the jobs whose name matches; SLOW=1 adds the ones
# over half an hour.
# Needs cbmc and goto-cc (pkg install cbmc).  JOBS sets the parallelism.

set -eu

top=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
here="$top/tools/cbmc"
# Each job runs under a CBMC_MEM megabyte limit, so that a proof that
# blows up fails as one proof rather than taking the host with it; the
# send loop proofs need most of it.  By default JOBS is the core count,
# bounded so that every job at its limit still fits in half the memory.
CBMC_MEM=${CBMC_MEM:-40960}
[ -n "${JOBS:-}" ] && JOBS_SET=1
if [ -z "${JOBS:-}" ]; then
	JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
	mem=$(($(sysctl -n hw.physmem 2>/dev/null || echo 0) / 1048576))
	if [ $((mem / 2 / CBMC_MEM)) -lt "$JOBS" ]; then
		JOBS=$((mem / 2 / CBMC_MEM))
	fi
	[ "$JOBS" -ge 1 ] || JOBS=1
fi

for t in cbmc goto-cc goto-instrument; do
	if ! command -v $t >/dev/null 2>&1; then
		echo "run.sh: $t not found, pkg install cbmc" >&2
		exit 77
	fi
done

# Calls goto-instrument redirects to a model, each for a reason given
# where the model is defined.
replace="vm_pager_has_page:cbmc_vm_pager_has_page
	sf_buf_kva:cbmc_sf_buf_kva
	counter_u64_add:cbmc_counter_u64_add
	__curthread:cbmc_curthread
	refcount_acquire:cbmc_refcount_acquire
	refcount_release:cbmc_refcount_release
	refcount_release_if_not_last:cbmc_refcount_release_if_not_last"

# The targets of each indirect call, which goto-instrument would otherwise
# resolve to every function of a compatible type: pr_abort() through an
# sf_io went to malloc_init() and sendfile_free_mext(), and that alone
# made a one page proof time out where it now takes seconds.
restrict="vn_sendfile.function_pointer_call.1/sendfile_wait
	vn_sendfile.function_pointer_call.2/pr_send
	vn_sendfile.function_pointer_call.3/pr_send
	sendfile_iodone.function_pointer_call.1/pr_abort
	sendfile_iodone.function_pointer_call.2/pr_ready
	fo_sendfile.function_pointer_call.1/vn_sendfile"

# A worker, which is this script run by xargs below: build and check job N
# of the queue in WORK, leaving cbmc's status beside its log -- 0 proved,
# 10 a property failed, anything else broken.
if [ "${1:-}" = "--job" ]; then
	work=$2
	{
		read -r name
		read -r harness
		read -r source
		read -r function
		read -r defs
		read -r unwind
	} <"$work/job.$3"
	ulimit -v $((CBMC_MEM * 1024))
	rflags=
	for r in $replace; do
		rflags="$rflags --replace-calls $r"
	done
	for r in $restrict; do
		rflags="$rflags --restrict-function-pointer $r"
	done
	# shellcheck disable=SC2086
	{
		goto-cc -nostdinc -D_KERNEL -DKLD_MODULE -DINVARIANTS \
		    -DINVARIANT_SUPPORT -DSAN_NEEDS_INTERCEPTORS \
		    -DSAN_INTERCEPTOR_PREFIX=cbmc \
		    '-D__builtin_align_down(x,a)=((__typeof__(x))((__uintptr_t)(x)&(~((a)-1))))' \
		    '-D__builtin_align_up(x,a)=((__typeof__(x))(((__uintptr_t)(x)+((a)-1))&(~((a)-1))))' \
		    '-D__builtin_is_aligned(x,a)=(((__uintptr_t)(x)&((a)-1))==0)' \
		    -I"$work/inc" -I"$top/sys" -I"$top/sys/contrib/ck/include" \
		    -I"$here/model" -DSOURCE="\"$source\"" $defs \
		    -c "$harness" -o "$work/$name.goto" &&
		goto-instrument $rflags "$work/$name.goto" \
		    "$work/$name.i.goto" &&
		cbmc "$work/$name.i.goto" --function "$function" \
		    --unwind 2 --unwindset "$unwind"
	} >"$work/$name.log" 2>&1 && rc=0 || rc=$?
	echo "$rc" >"$work/$name.rc"
	exit 0
fi

# A job under time(1): job N in WORK, its wall seconds and peak resident
# megabytes left in N.cost for the scheduler.
if [ "${1:-}" = "--timed" ]; then
	work=$2
	name=$(head -1 "$work/job.$3")
	/usr/bin/time -l -o "$work/$name.time" sh "$0" --job "$work" "$3"
	awk -v n="$name" '/ real /{t=$1} /maximum resident set size/{m=int($1/1024)}
	    END{print n, int(t), m}' "$work/$name.time" >"$work/$name.cost"
	exit 0
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/kern-cbmc.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

# The generated headers a kernel build has: vnode_if*.h, and an empty
# opt_*.h for each option header the sources include, so every option is
# off.  The machine/ and x86/ links are what the kernel build makes.
mkdir -p "$work/inc"
(
	cd "$work/inc"
	for f in -h -p -q; do
		awk -f "$top/sys/tools/vnode_if.awk" \
		    "$top/sys/kern/vnode_if.src" $f
	done
	ln -s "$top/sys/amd64/include" machine
	ln -s "$top/sys/x86/include" x86
) >/dev/null
for f in $(sed -n 's/^#include "\(opt_[a-z0-9_]*\.h\)"/\1/p' \
    "$top/sys/kern/kern_sendfile.c"); do
	: >"$work/inc/$f"
done

fail=0
njobs=0
: >"$work/order"

# queue KIND NAME HARNESS SOURCE PROOF DEFS UNWINDSET
queue()
{
	# ONLY: a regular expression the job's name must match.
	if [ -n "${ONLY:-}" ] && ! echo "$2" | grep -qE "$ONLY"; then
		return
	fi
	njobs=$((njobs + 1))
	printf '%s\n' "$2" "$3" "$4" "$5" "$6" "$7" >"$work/job.$njobs"
	echo "$1 $2" >>"$work/order"
}

# proof NAME HARNESS SOURCE PROOF DEFS UNWINDSET: has to be proven.
proof()
{
	queue proof "$@"
}

# mutant NAME HARNESS SOURCE PROOF DEFS UNWINDSET SED: SOURCE with SED
# applied has to have changed, and the proof has to fail on it.
mutant()
{
	if [ -n "${ONLY:-}" ] && ! echo "$1" | grep -qE "$ONLY"; then
		return
	fi
	dst="$work/$1.c"
	sed -e "$7" "$3" >"$dst"
	if cmp -s "$3" "$dst"; then
		printf '%s\n' "$7" >"$work/$1.sed"
		echo "unapplied $1" >>"$work/order"
		return
	fi
	queue mutant "$1" "$2" "$dst" "$4" "$5" "$6"
}

# slow KIND NAME ...: a proof or mutant that takes over half an hour,
# queued only with SLOW=1.
slow()
{
	[ "${SLOW:-0}" = 1 ] || return 0
	"$@"
}

# question NAME HARNESS SOURCE PROOF DEFS UNWINDSET: the manual and the
# code disagree and it is not settled which is right; the proof fails
# until it is, and is reported without failing the run.
question()
{
	queue question "$@"
}

# want SYSCALL: true when SYSCALL was asked for, or nothing was.
want()
{
	[ -z "$selected" ] && return 0
	for p in $selected; do
		[ "$p" = "$1" ] && return 0
	done
	return 1
}
selected="$*"

#
# sendfile(2): sys/kern/kern_sendfile.c against lib/libsys/sendfile.2.
#
h="$here/sendfile/sendfile.c"
s="$top/sys/kern/kern_sendfile.c"
# The file spans three pages and a byte, so a run can start inside one
# page and end inside another; header and trailer up to 8 bytes.
d="-DMAXFILE=(2*PAGE_SIZE+1) -DMAXHDR=8"
u="setup.0:5,deliver.0:4,deliver.1:6,m_freem.0:4,m_length.0:4"
u="$u,sigsetmasked.0:5,__sigisempty.0:5,all_unbusied.0:6,all_unbusied.1:6"
# The page arithmetic, for runs up to two pages.
ua="proof_xfsize.0:4,proof_fixspace.0:4,fixspace.0:4,fixspace.1:4"

if want sendfile; then
	proof sendfile_xfsize "$h" "$s" proof_xfsize "" "$ua"
	proof sendfile_fixspace "$h" "$s" proof_fixspace "" "$ua"
	proof sendfile_noloop "$h" "$s" proof_noloop "$d" "$u"

	# A short trailer write makes sendfile(2) fail.
	mutant sendfile_short_trailer "$h" "$s" proof_noloop "$d" "$u" \
	    '/len = trl_uio->uio_resid;/,/goto out;/s/error = sendfile_short_write(td);/;/'
	# So does a short header write.
	mutant sendfile_short_header "$h" "$s" proof_noloop "$d" "$u" \
	    '/Do not send trailers after a partial header/,/goto out;/s/if (error != 0)$/if (error != 0 || cnt != len)/;/hdr_uio, 0,$/,/Do not send/s/error = sendfile_short_write(td);/;/'

	# The three fixes of 2026, taken back one at a time.
	mutant sendfile_nbytes_offmax "$h" "$s" proof_noloop \
	    "$d" "$u" \
	    's/nbytes > (size_t)(OFF_MAX - offset)/0/'
	mutant sendfile_trailer_count "$h" "$s" proof_noloop \
	    "$d" "$u" \
	    '/A socket write counts what it sent/{n;s/sbytes += cnt;/if (error == 0) sbytes += cnt;/;}'
	mutant sendfile_header_eof "$h" "$s" proof_noloop \
	    "$d" "$u" \
	    's/if ((hdr_uio != NULL \&\& hdr_uio->uio_resid > 0) || trl_uio != NULL) {/if (trl_uio != NULL) {/'
	# A partial header must not be followed by the trailer.
	mutant sendfile_header_partial "$h" "$s" proof_noloop "$d" "$u" \
	    '/hdr_uio, 0,$/,/Do not send/s/error = sendfile_short_write(td);/;/'
	# The page split: the last page of a run, and the first.
	mutant sendfile_xfsize_last "$h" "$s" proof_xfsize "" "$ua" \
	    's/if (i == n - 1 \&\& ((off + len) \& PAGE_MASK) > 0)/if (i == n - 1)/'
	mutant sendfile_fixspace_first "$h" "$s" proof_fixspace "" "$ua" \
	    's/\*space -= xfsize(0, old, off, \*space);/*space -= PAGE_SIZE;/'
fi

#
# sendfile(2), the send loop.  Every loop a proof runs is bounded below,
# in iterations plus one, for runs of up to three pages.
#
ul="vn_sendfile.11:4,sendfile_swapin.12:4,sendfile_swapin.0:4"
ul="$ul,sendfile_swapin.5:4,sendfile_swapin.8:4,setup.0:5,sfio_malloc.0:6"
ul="$ul,vm_page_grab_pages_unlocked.0:4"
ul="$ul,deliver.0:6,deliver.1:6,notready_pages.0:6,all_ready.0:6"
ul="$ul,ktls_frame.0:6,chain_payload.0:6,is_hdr.0:4"
ul="$ul,io_complete.0:4,io_flush.0:3,sendfile_swapin.9:4,sendfile_swapin.10:4"
ul="$ul,sendfile_swapin.11:4,unbusy.0:6,all_unbusied.0:6,all_unbusied.1:6"
ul="$ul,sendfile_free_mext_pg.0:6,sendfile_free_mext_pg.1:6,setup.1:5"
ul="$ul,vm_pager_get_pages_async.0:4"
ul="$ul,m_freem.0:6,m_length.0:6,fixspace.0:4,fixspace.1:4"
ul="$ul,sigsetmasked.0:5,__sigisempty.0:5"
for l in 0 1 2 3 4 5 6 7 9; do
	ul="$ul,sendfile_iodone.$l:4"
done
# One iteration over a cached file of three pages and a byte, so a run
# has a first, a middle and a last page: the socket has room for the
# header and all of it, and a byte more, or the loop trims the run to a
# page boundary and goes round again.
dsend="-DMAXFILE=(2*PAGE_SIZE+1) -DMAXHDR=4 -DMINSPACE=(2*PAGE_SIZE+6)"
dsend="$dsend -DMAXSPACE=(3*PAGE_SIZE)"
# Two iterations: room for at least half of a two page file each time,
# and never more than a page, so the run is never trimmed.
dtwo="-DMAXFILE=(PAGE_SIZE+1) -DMAXHDR=4 -DMINSPACE=(PAGE_SIZE/2+5)"
dtwo="$dtwo -DMAXSPACE=PAGE_SIZE -DMAXWAITS=2"
# The pager reading pages of a two page file, partly valid or not.
dread="-DMAXFILE=(PAGE_SIZE+1) -DMAXHDR=4 -DMINSPACE=(PAGE_SIZE+6)"
dread="$dread -DMAXSPACE=(2*PAGE_SIZE)"
# SF_NODISKIO stopping short in a three page run, with no header.
dndio="-DMAXFILE=(2*PAGE_SIZE+1) -DMAXHDR=0 -DMINSPACE=(2*PAGE_SIZE+2)"
dndio="$dndio -DMAXSPACE=(3*PAGE_SIZE)"

if want sendfile; then
	proof sendfile_send "$h" "$s" proof_send "$dsend" "vn_sendfile.14:2,$ul"
	proof sendfile_twice "$h" "$s" proof_send "$dtwo" "vn_sendfile.14:3,$ul"
	# Mapped mbufs on the paging path, with the busy state, take 36
	# minutes; the unmapped proof below covers the same paging code.
	slow proof sendfile_read "$h" "$s" proof_read "$dread -DNO_READY_CHECK" \
	    "vn_sendfile.14:2,$ul"
	slow proof sendfile_read_ready "$h" "$s" proof_read "$dread" \
	    "vn_sendfile.14:2,$ul"
	proof sendfile_nodiskio "$h" "$s" proof_nodiskio "$dndio" \
	    "vn_sendfile.14:2,$ul"

	# Each mbuf maps its bytes at their offset in the page.
	mutant sendfile_send_mdata "$h" "$s" proof_send "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    '/m0->m_data = (char \*)sf_buf_kva(sf) +/{n;s/(vmoff(i, off) \& PAGE_MASK)/0/;}'
	# A run starting inside a page spans one more page.
	mutant sendfile_send_npages "$h" "$s" proof_send "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    's/npages = howmany(space + (off \& PAGE_MASK), PAGE_SIZE);/npages = howmany(space, PAGE_SIZE);/'
	# No more than what is left is sent.
	mutant sendfile_send_clamp "$h" "$s" proof_send "$dsend" \
	    "vn_sendfile.14:2,$ul" 's/if (space > rem)$/if (0)/'
	# The header takes its room out of the socket's.
	mutant sendfile_twice_hdrspace "$h" "$s" proof_send "$dtwo" \
	    "vn_sendfile.14:3,$ul" 's/space -= hdrlen;/;/'
	# An invalid page is read before it is sent.
	mutant sendfile_read_valid "$h" "$s" proof_read_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    's/if (vm_page_is_valid(pa\[i\], vmoff(i, off) \& PAGE_MASK,$/if (1 || vm_page_is_valid(pa[i], vmoff(i, off) \& PAGE_MASK,/'
	# A mapped page queued while it is being read is marked not ready.
	slow mutant sendfile_read_notready "$h" "$s" proof_read "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    's/^\([[:space:]]*\)m0->m_flags |= M_NOTREADY;$/\1;/'
	# SF_NOCACHE: every page wired is released, and freed unless the
	# send stopped in it with more of it to come.
	# Releasing a mapped mbuf per page is costly: the one pass proof
	# runs on runs of up to two pages, the two pass one with SLOW=1
	# CBMC_MEM=61440.
	slow proof sendfile_nocache "$h" "$s" proof_nocache "$dread" \
	    "vn_sendfile.14:2,$ul"
	slow proof sendfile_nocache_twice "$h" "$s" proof_nocache "$dtwo" \
	    "vn_sendfile.14:3,$ul"
	# A page sent is freed ...
	mutant sendfile_nocache_noflag "$h" "$s" proof_nocache_extpg "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    '/if (flags \& SF_NOCACHE) {/{n;n;s/EXT_FLAG_NOCACHE;/0;/;}'
	# ... unless the send stopped in it with more to come ...
	mutant sendfile_nocache_cachelast "$h" "$s" proof_nocache_extpg \
	    "$dsend" "vn_sendfile.14:2,$ul" \
	    's/if ((npages - i <= max_pgs) \&\&/if (1 || (npages - i <= max_pgs) \&\&/'
	# ... and every page wired is released.
	mutant sendfile_nocache_leak "$h" "$s" proof_nocache_extpg "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    's/for (i = 0; i < m->m_epg_npgs; i++) {/for (i = 0; i < m->m_epg_npgs - 1; i++) {/'
	# The same with mapped mbufs.
	slow mutant sendfile_nocache_mapped "$h" "$s" proof_nocache "$dread" \
	    "vn_sendfile.14:2,$ul" 's/if ((flags \& SF_NOCACHE) \&\&/if (0 \&\&/'
	proof sendfile_nocache_extpg "$h" "$s" proof_nocache_extpg "$dsend" \
	    "vn_sendfile.14:2,$ul"
	proof sendfile_nocache_twice_extpg "$h" "$s" proof_nocache_extpg \
	    "$dtwo" "vn_sendfile.14:3,$ul"
	# A shared memory object (DTYPE_SHM), and one resized under the call.
	proof sendfile_shm "$h" "$s" proof_shm "$dsend" "vn_sendfile.14:2,$ul"
	proof sendfile_shm_read "$h" "$s" proof_shm_read \
	    "$dread -DNO_READY_CHECK" "vn_sendfile.14:2,$ul"
	proof sendfile_shm_resize "$h" "$s" proof_shm_resize "$dsend" \
	    "vn_sendfile.14:2,$ul"
	# The range lock keeps a truncation off the pages being grabbed ...
	mutant sendfile_shm_rangelock "$h" "$s" proof_shm_resize "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    's/rl_cookie = rangelock_rlock(\&shmfd->shm_rl, off, OFF_MAX);/;/'
	# ... and the size is read again under it.
	mutant sendfile_shm_size "$h" "$s" proof_shm_resize "$dsend" \
	    "vn_sendfile.14:2,$ul" 's/nobj_size = shmfd->shm_size;/nobj_size = obj_size;/'

	# A largepage shared memory object: unmanaged pages the object keeps
	# wired, and a size that only grows.
	proof sendfile_shm_lp "$h" "$s" proof_shm_lp "$dsend" \
	    "vn_sendfile.14:2,$ul"
	proof sendfile_shm_lp_resize "$h" "$s" proof_shm_lp_resize "$dsend" \
	    "vn_sendfile.14:2,$ul"
	# A page is released once: twice would free one the object holds.
	mutant sendfile_shm_lp_release "$h" "$s" proof_shm_lp "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    '/^sendfile_free_mext_pg/,/^}/s/vm_page_release(pg, flags);/vm_page_release(pg, flags); vm_page_release(pg, flags);/'
	# A vnode whose object is not a vnode pager's (tmpfs): its size from
	# VOP_GETATTR(), which may fail.
	proof sendfile_novnp "$h" "$s" proof_novnp "$dsend" "vn_sendfile.14:2,$ul"
	proof sendfile_novnp_resize "$h" "$s" proof_novnp_resize "$dsend" \
	    "vn_sendfile.14:2,$ul"
	proof sendfile_novnp_attrerr "$h" "$s" proof_novnp_attrerr "$dsend" \
	    "vn_sendfile.14:2,$ul"
	# A failing VOP_GETATTR() leaves the vnode unlocked ...
	mutant sendfile_novnp_unlock "$h" "$s" proof_novnp_attrerr "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    '/error = VOP_GETATTR(vp, \&va, td->td_ucred);/,/goto done;/s/VOP_UNLOCK(vp);/;/'
	# ... and the size it reports is the one used.  Ignoring a failing
	# vn_getsize_locked() in sendfile_getobj() is no mutant: the loop
	# reads the size again before it grabs a page, or fails.
	mutant sendfile_novnp_size "$h" "$s" proof_novnp_resize "$dsend" \
	    "vn_sendfile.14:2,$ul" 's/nobj_size = va.va_size;/nobj_size = obj_size;/'
	# The file truncated or extended under the call.
	proof sendfile_resize "$h" "$s" proof_resize "$dsend" \
	    "vn_sendfile.14:2,$ul"
	proof sendfile_resize_twice "$h" "$s" proof_resize "$dtwo" \
	    "vn_sendfile.14:3,$ul"
	# Past the new end of file, the trailers still go out ...
	mutant sendfile_resize_trailer "$h" "$s" proof_resize "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    '/if (mh == NULL)$/{n;s/break;/goto done;/;}'
	# ... and so does a header copied in the same iteration.
	mutant sendfile_resize_header "$h" "$s" proof_resize "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    '/^[[:space:]]*rem = 0;$/,/goto prepend_header;/s/goto prepend_header;/goto done;/'
	# The fix of 2026 to sendfile_swapin(), taken back.
	mutant sendfile_nodiskio_short "$h" "$s" proof_nodiskio "$dndio" \
	    "vn_sendfile.14:2,$ul" \
	    's/xfsize(i, sfio->npages, off, len)/xfsize(i, npages, off, len)/'
fi

#
# sendfile(2) when reading the file fails: at once, the pager returning
# the error, or later, through the read's completion, which may come
# after vn_sendfile() has returned.  With mapped mbufs the not-ready
# accounting makes these proofs too slow; they run with unmapped ones,
# and the mapped one, which did not finish within an hour, with SLOW=1.
#
dlater="-DMAXFILE=PAGE_SIZE -DMAXHDR=4 -DMINSPACE=(PAGE_SIZE+6)"
dlater="$dlater -DMAXSPACE=(2*PAGE_SIZE) -DIODEFER=1 -DMAXIO=1"

if want sendfile; then
	proof sendfile_ioerror_extpg "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul"
	slow proof sendfile_ioerror_later_extpg "$h" "$s" proof_ioerror_extpg \
	    "$dlater" "vn_sendfile.14:2,$ul"
	slow proof sendfile_ioerror "$h" "$s" proof_ioerror "$dread" \
	    "vn_sendfile.14:2,$ul"

	# A read failing at once fails the call with EIO ...
	mutant sendfile_ioerror_sync "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    '/sendfile_iowait(sfio, "sferrio");/,/return (EIO);/s/return (EIO);/return (0);/'
	# ... one failing later leaves EIO on the socket ...
	mutant sendfile_ioerror_soerror "$h" "$s" proof_ioerror_extpg \
	    "$dread" "vn_sendfile.14:2,$ul" 's/so->so_error = EIO;/;/'
	# ... after aborting it ...
	mutant sendfile_ioerror_abort "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    's/so->so_proto->pr_abort(so);/if (0) so->so_proto->pr_abort(so);/'
	# The pages of a failed run, unbusied by the completion, are not
	# unbusied again ...
	mutant sendfile_busy_double "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" 's/if (j >= i + count1)/if (j >= i + count)/'
	# ... and every page busied is unbusied: by the completion, ...
	mutant sendfile_busy_iodone "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    's/^\([[:space:]]*\)vm_page_xunbusy_unchecked(pa\[i\]);/\1;/'
	# ... when skipped as valid, ...
	mutant sendfile_busy_skip "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    '/Skip valid pages/,/continue;/s/vm_page_xunbusy(pa\[i\]);/;/'
	# ... or trimmed off the end of a run.
	mutant sendfile_busy_trim "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    '/for (j = i + count - 1; j > i; j--) {/,/count--;/s/vm_page_xunbusy(pa\[j\]);/;/'
	# ... and freeing exactly the pages queued not ready.
	mutant sendfile_ioerror_free "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    's/mb_free_notready(sfio->m, sfio->npages);/mb_free_notready(sfio->m, sfio->npages + 1);/'
fi

#
# sendfile(2) on a KTLS socket, built with KERN_TLS: software encryption,
# NIC offload and TOE.  The paging and I/O error proofs, in software mode
# on one page runs, take over 20 minutes each, their mutants too.
#
dtls="$dsend -DKERN_TLS"
dtlsp="-DKERN_TLS -DTLS_MODE=TCP_TLS_MODE_SW -DMAXFILE=PAGE_SIZE -DMAXHDR=4"
dtlsp="$dtlsp -DMINSPACE=(PAGE_SIZE+6) -DMAXSPACE=(2*PAGE_SIZE)"
# A one page run's chain holds a header and a page mbuf: the model's walks
# of it are bounded so, as each is inlined at every call site.
utlsp=$(echo "$ul" | sed -E 's/(deliver\.[01]|notready_pages\.0|all_ready\.0|chain_payload\.0|ktls_frame\.0|m_freem\.0|m_length\.0|is_hdr\.0):[0-9]+/\1:3/g; s/sfio_malloc\.0:6/sfio_malloc.0:4/; s/setup\.0:5/setup.0:3/')

if want sendfile; then
	proof sendfile_send_tls "$h" "$s" proof_send_tls "$dtls" \
	    "vn_sendfile.14:2,$ul"
	proof sendfile_read_tls "$h" "$s" proof_read_tls "$dtlsp" \
	    "vn_sendfile.14:2,$utlsp"
	# Over 40G: SLOW=1 CBMC_MEM=61440 (proven so, in 27 minutes).
	slow proof sendfile_ioerror_tls "$h" "$s" proof_ioerror_tls "$dtlsp" \
	    "vn_sendfile.14:2,$utlsp"

	# A record holds at most max_frame_len bytes ...
	mutant sendfile_tls_maxpgs "$h" "$s" proof_send_tls "$dtls" \
	    "vn_sendfile.14:2,$ul" \
	    's/max_pgs = num_pages(tls->params.max_frame_len);/max_pgs = MBUF_PEXT_MAX_PGS;/'
	# ... and the header is one, unmapped.
	mutant sendfile_tls_header "$h" "$s" proof_send_tls "$dtls" \
	    "vn_sendfile.14:2,$ul" \
	    's/tls->params.max_frame_len, M_EXTPG);/0, 0);/'
	# The socket reference ktls_enqueue() is given is taken first ...
	mutant sendfile_tls_soref "$h" "$s" proof_send_tls "$dtls" \
	    "vn_sendfile.14:2,$ul" \
	    '/ktls_enqueue(m, so, tls_enq_cnt);/!{/soref(so);$/{N;/ktls_enqueue/s/soref(so);/;/;};}'
	# ... and the session reference sendfile holds is dropped.
	mutant sendfile_tls_free "$h" "$s" proof_send_tls "$dtls" \
	    "vn_sendfile.14:2,$ul" \
	    '/if (tls != NULL)$/{N;s/ktls_free(tls);/;/;}'
	# The completion donates its socket reference to ktls_enqueue() ...
	slow mutant sendfile_tls_ref "$h" "$s" proof_read_tls "$dtlsp" \
	    "vn_sendfile.14:2,$utlsp" 's/goto out_with_ref;/;/'
	# ... and encrypts the header record with the pages ...
	slow mutant sendfile_tls_hdrm "$h" "$s" proof_read_tls "$dtlsp" \
	    "vn_sendfile.14:2,$utlsp" \
	    's/if (hdrlen != 0 \&\& tls != NULL \&\&/if (0 \&\& tls != NULL \&\&/'
	# ... or, on a failed read, frees it with them.
	slow mutant sendfile_tls_abortfree "$h" "$s" proof_ioerror_tls \
	    "$dtlsp" "vn_sendfile.14:2,$utlsp" \
	    '/so->so_error = EIO;/,/mb_free_notready/s/if (sfio->tls_m != NULL)/if (0)/'
fi

#
# sendfile(2) with unmapped mbufs (mb_use_ext_pgs), what TCP uses on
# amd64.  One such mbuf holds MBUF_PEXT_MAX_PGS pages, five here, so the
# six page run fills one and starts another.
#
dsix="-DMAXFILE=(5*PAGE_SIZE+1) -DMAXHDR=0 -DMINSPACE=(5*PAGE_SIZE+2)"
dsix="$dsix -DMAXSPACE=(6*PAGE_SIZE)"
usix=$(echo "$ul" | sed 's/:4/:8/g; s/:5/:9/g; s/:6/:10/g')

if want sendfile; then
	proof sendfile_send_extpg "$h" "$s" proof_send_extpg "$dsend" \
	    "vn_sendfile.14:2,$ul"
	proof sendfile_six_extpg "$h" "$s" proof_send_extpg "$dsix" \
	    "vn_sendfile.14:2,$usix"
	proof sendfile_twice_extpg "$h" "$s" proof_send_extpg "$dtwo" \
	    "vn_sendfile.14:3,$ul"
	proof sendfile_read_extpg "$h" "$s" proof_read_extpg "$dread" \
	    "vn_sendfile.14:2,$ul"
	proof sendfile_nodiskio_extpg "$h" "$s" proof_nodiskio_extpg \
	    "$dndio" "vn_sendfile.14:2,$ul"

	# The first page starts at the run's offset in it.
	mutant sendfile_extpg_1st_off "$h" "$s" proof_send_extpg "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    's/^\([[:space:]]*\)vmoff(i, off) \& PAGE_MASK;$/\10;/'
	# The last page is as long as the run uses of it.
	mutant sendfile_extpg_last_len "$h" "$s" proof_send_extpg "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    's/m0->m_epg_last_len = xfs;/m0->m_epg_last_len = PAGE_SIZE;/'
	# The mbuf is as long as its pages' bytes.
	mutant sendfile_extpg_len "$h" "$s" proof_send_extpg "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    's/mtail->m_len += xfs;/mtail->m_len += PAGE_SIZE;/'
	# A full mbuf is followed by a fresh one from its first slot.
	mutant sendfile_extpg_wrap "$h" "$s" proof_send_extpg "$dsix" \
	    "vn_sendfile.14:2,$usix" \
	    's/^\([[:space:]]*\)ext_pgs_idx = 0;$/\1ext_pgs_idx = 1;/'
	# Each page being read counts in m_epg_nrdy for sbready().
	mutant sendfile_extpg_nrdy "$h" "$s" proof_read_extpg "$dread" \
	    "vn_sendfile.14:2,$ul" \
	    's/^\([[:space:]]*\)m0->m_epg_nrdy++;$/\1;/'
fi

[ "$njobs" -gt 0 ] || { echo "run.sh: nothing selected" >&2; exit 2; }

# Longest first, as many at once as fit in the memory budget, each job
# counted at its measured peak and a margin, from the costs of the last
# run (costs, beside this script), or at CBMC_MEM when it has none, so
# that a job never measured cannot overcommit the host; JOBS still
# bounds how many run at once.  cbmc is single-threaded and most proofs
# need a few gigabytes, so this runs far more of them at once than one
# limit for all would.
costs="$here/costs"
budget=$(( $(sysctl -n hw.physmem) / 1048576 * 7 / 10 ))
[ -n "${JOBS_SET:-}" ] || JOBS=$(sysctl -n hw.ncpu)
for i in $(seq 1 "$njobs"); do
	n=$(head -1 "$work/job.$i")
	awk -v n="$n" -v i="$i" -v def="$CBMC_MEM" '
	    $1 == n { t = $2; m = int($3 * 13 / 10) + 512 }
	    END { if (t == "") { t = 100000; m = def }
		  if (m > def) m = def; print t, m, i }' "$costs" 2>/dev/null ||
	    echo "100000 $CBMC_MEM $i"
done | sort -rn >"$work/queue"
used=0
running=""
while [ -s "$work/queue" ] || [ -n "$running" ]; do
	# Reap the jobs done.
	still=""
	for r in $running; do
		i=${r%%:*}
		if [ -f "$work/$(head -1 "$work/job.$i").cost" ]; then
			used=$((used - ${r#*:}))
		else
			still="$still $r"
		fi
	done
	running=$still
	# Start the longest job that fits, or any when nothing runs.
	started=0
	nrun=$(echo $running | wc -w)
	while read -r t m i; do
		if [ "$nrun" -lt "$JOBS" ] &&
		    { [ $((used + m)) -le "$budget" ] || [ -z "$running" ]; }; then
			sh "$0" --timed "$work" "$i" &
			running="$running $i:$m"
			used=$((used + m))
			grep -v " $i\$" "$work/queue" >"$work/queue.new" || true
			mv "$work/queue.new" "$work/queue"
			started=1
			break
		fi
	done <"$work/queue"
	[ "$started" = 1 ] || sleep 2
done
wait

# Keep the costs measured for the next run's schedule.
cat "$work"/*.cost 2>/dev/null >"$work/costs.new" || true
if [ -s "$work/costs.new" ]; then
	{ cat "$work/costs.new"; [ -f "$costs" ] && cat "$costs"; } |
	    awk '!seen[$1]++' | sort >"$work/costs.all"
	cp "$work/costs.all" "$costs"
fi

while read -r kind name; do
	case $kind in
	unapplied)
		echo "FAIL mutant $name: did not apply: $(cat "$work/$name.sed")"
		fail=1
		continue
		;;
	esac
	rc=$(cat "$work/$name.rc")
	case $kind:$rc in
	proof:0)
		echo "ok   proof  $name"
		;;
	mutant:10)
		# The property that caught it, rather than a loop bound
		# the mutant ran past, when there is one.
		why=$( (grep ': FAILURE$' "$work/$name.log" |
		    grep -v 'unwinding assertion'; grep -m1 ': FAILURE$' \
		    "$work/$name.log") | head -1 |
		    sed 's/^\[[^]]*\] //; s/: FAILURE$//')
		echo "ok   mutant $name: caught by $why"
		;;
	proof:10)
		echo "FAIL proof  $name:"
		grep ': FAILURE$' "$work/$name.log" | sed 's/^/	/'
		fail=1
		;;
	question:10)
		why=$(grep -m1 ': FAILURE$' "$work/$name.log" |
		    sed 's/^\[[^]]*\] //; s/: FAILURE$//')
		echo "open question $name: $why"
		;;
	question:0)
		echo "FAIL question $name: proven, update the question"
		fail=1
		;;
	mutant:0)
		echo "FAIL mutant $name: proven, the proof does not see it"
		fail=1
		;;
	*)
		echo "FAIL $kind $name: cbmc exit $rc"
		grep -iE 'error|out of memory' "$work/$name.log" | head -5 |
		    sed 's/^/	/'
		fail=1
		;;
	esac
done <"$work/order"

exit $fail
