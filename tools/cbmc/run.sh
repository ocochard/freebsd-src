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
# over half an hour or so large that few fit at once.
# Needs cbmc and goto-cc (pkg install cbmc).  JOBS sets the parallelism.

set -eu

top=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
here="$top/tools/cbmc"
# Each job runs under a CBMC_MEM megabyte limit, so that a proof that
# blows up fails as one proof rather than taking the host with it; the
# send loop proofs need most of it.  By default JOBS is the core count,
# bounded so that every job at its limit still fits in half the memory.
CBMC_MEM=${CBMC_MEM:-61440}
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
# where the model is defined: in model/kern.h for every harness, and in
# the harness for those named replace_HARNESS.
replace="counter_u64_add:cbmc_counter_u64_add
	__curthread:cbmc_curthread
	refcount_acquire:cbmc_refcount_acquire
	refcount_release:cbmc_refcount_release
	refcount_release_if_not_last:cbmc_refcount_release_if_not_last"
replace_sendfile="vm_pager_has_page:cbmc_vm_pager_has_page
	sf_buf_kva:cbmc_sf_buf_kva"
replace_ktls="ktls_buffer_alloc:cbmc_ktls_buffer_alloc
	ktls_drop:cbmc_ktls_drop
	ktls_destroy:cbmc_ktls_destroy"
replace_ktls_sb="sbcompress_ktls_rx:cbmc_sbcompress_ktls_rx"
replace_ktls_ocf="ktls_ocf_dispatch:cbmc_ktls_ocf_dispatch"
replace_ktls_enable="ktls_create_session:cbmc_ktls_create_session
	ktls_try_ifnet:cbmc_ktls_try_ifnet
	ktls_destroy:cbmc_ktls_destroy
	ktls_check_rx:cbmc_ktls_check_rx
	sb_mark_notready:cbmc_sb_mark_notready"
replace_ktls_rx="$replace_ktls
	ktls_resync_ifnet:cbmc_ktls_resync_ifnet
	m_free:cbmc_m_free"

# The targets of each indirect call, which goto-instrument would otherwise
# resolve to every function of a compatible type: pr_abort() through an
# sf_io went to malloc_init() and sendfile_free_mext(), and that alone
# made a one page proof time out where it now takes seconds.  Named
# restrict_HARNESS, as each names functions of one source.
restrict_sendfile="vn_sendfile.function_pointer_call.1/sendfile_wait
	vn_sendfile.function_pointer_call.2/pr_send
	vn_sendfile.function_pointer_call.3/pr_send
	sendfile_iodone.function_pointer_call.1/pr_abort
	sendfile_iodone.function_pointer_call.2/pr_ready
	fo_sendfile.function_pointer_call.1/vn_sendfile"
restrict_ktls="ktls_encrypt.function_pointer_call.1/cbmc_pr_ready
	ktls_encrypt_cb.function_pointer_call.1/cbmc_pr_ready
	ktls_finish_nonanon.function_pointer_call.1/cbmc_file_free
	ktls_set_tx_mode.function_pointer_call.1/cbmc_hwtls_change
	ktls_disable_ifnet_help.function_pointer_call.1/cbmc_hwtls_change"
# cbmc flags of a harness: the KTLS worker turns physical addresses into
# pointers, each an object, past cbmc's 256; and the kernel is built with
# -fwrapv, so a signed overflow wraps (IFCAP_BIT(31) is 1 << 31).
cbmc_ktls="--object-bits 10 --no-signed-overflow-check"
restrict_ktls_rx=$restrict_ktls
cbmc_ktls_sb="--no-signed-overflow-check"
restrict_ktls_ocf="m_apply.function_pointer_call.1/check_padding"
cbmc_ktls_ocf="--no-signed-overflow-check"
cbmc_ktls_enable="--no-signed-overflow-check"
cbmc_ktls_sbc="--no-signed-overflow-check --object-bits 10"
# ktls_decrypt() walking off its chain goes on with what it reads there,
# and fails further on: stop at the first property a trace violates.
cbmc_ktls_rx="$cbmc_ktls --stop-on-fail"

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
	h=$(basename "$harness" .c)
	eval "hreplace=\${replace_$h:-} hrestrict=\${restrict_$h:-}"
	eval "hcbmc=\${cbmc_$h:-}"
	rflags=
	for r in $replace $hreplace; do
		rflags="$rflags --replace-calls $r"
	done
	for r in $hrestrict; do
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
		    --unwind 2 --unwindset "$unwind" $hcbmc
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
    "$top/sys/kern/kern_sendfile.c" "$top/sys/kern/uipc_ktls.c" \
    "$top/sys/kern/uipc_sockbuf.c" "$top/sys/opencrypto/ktls_ocf.c"); do
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
	# A job's files are named after it: two of one name share them.
	if grep -q " $2\$" "$work/order"; then
		echo "run.sh: two jobs named $2" >&2
		exit 2
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

# slow KIND NAME ...: a proof or mutant that takes over half an hour, or
# so much memory that few run at once, queued only with SLOW=1.
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
ul="$ul,resize_point.0:6,resize_point.1:6,resize_point.2:6"
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
# One and two page runs with mapped mbufs, the model's walks of the chain
# bounded to what they hold: a header and one, or two, page mbufs.
dioe1="-DMAXFILE=PAGE_SIZE -DMAXHDR=4 -DMINSPACE=(PAGE_SIZE+6)"
dioe1="$dioe1 -DMAXSPACE=(2*PAGE_SIZE)"
uioe1=$(echo "$ul" | sed -E 's/(deliver\.[01]|notready_pages\.0|all_ready\.0|m_freem\.0|m_length\.0|is_hdr\.0|chain_payload\.0):[0-9]+/\1:3/g; s/sfio_malloc\.0:6/sfio_malloc.0:4/; s/setup\.0:5/setup.0:3/')
uioe2=$(echo "$ul" | sed -E 's/(deliver\.[01]|notready_pages\.0|all_ready\.0|m_freem\.0|m_length\.0|is_hdr\.0|chain_payload\.0):[0-9]+/\1:4/g; s/sfio_malloc\.0:6/sfio_malloc.0:5/; s/setup\.0:5/setup.0:4/')

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
	# With mapped mbufs, a release per page: one and two page runs, the
	# model's walks bounded to what they hold.
	proof sendfile_shm_lp_mapped1 "$h" "$s" proof_shm_lp_mapped "$dioe1" \
	    "vn_sendfile.14:2,$uioe1"
	# Over 60G of address space: SLOW=1 CBMC_MEM=102400 (58 minutes).
	slow proof sendfile_shm_lp_mapped2 "$h" "$s" proof_shm_lp_mapped \
	    "$dread" "vn_sendfile.14:2,$uioe2"
	proof sendfile_shm_lp_mapped_resize "$h" "$s" proof_shm_lp_mapped_resize \
	    "$dioe1" "vn_sendfile.14:2,$uioe1"
	mutant sendfile_shm_lp_mapped_release "$h" "$s" proof_shm_lp_mapped \
	    "$dioe1" "vn_sendfile.14:2,$uioe1" \
	    '/^sendfile_free_mext(/,/^}/s/vm_page_release(pg, flags);/vm_page_release(pg, flags); vm_page_release(pg, flags);/'
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
	# Truncation removing pages while they are read: freed ones grabbed
	# again, bogus_page ones looked up again.
	proof sendfile_read_resize "$h" "$s" proof_read_resize "$dread" \
	    "vn_sendfile.14:2,$ul"
	# The pages sendfile holds are wired, so that a truncation only
	# invalidates them rather than freeing them under the mbufs.
	mutant sendfile_resize_wired "$h" "$s" proof_resize "$dsend" \
	    "vn_sendfile.14:2,$ul" \
	    's/VM_ALLOC_NORMAL | VM_ALLOC_WIRED | flags, pa, npages);/VM_ALLOC_NORMAL | flags, pa, npages);/'
	# sendfile is zero-copy: a truncation after the data is queued, before
	# the socket transmits it, zeroes bytes the peer then receives.
	# sendfile.2 says nothing of it.
	question sendfile_resize_window "$h" "$s" proof_resize_window \
	    "$dsend" "vn_sendfile.14:2,$ul"
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
# after vn_sendfile() has returned.  With mapped mbufs, one per page,
# the not-ready accounting is costly: those proofs bound the model's
# walks of the chain to what one and two page runs hold.
#
dlater="-DMAXFILE=PAGE_SIZE -DMAXHDR=4 -DMINSPACE=(PAGE_SIZE+6)"
dlater="$dlater -DMAXSPACE=(2*PAGE_SIZE) -DIODEFER=1 -DMAXIO=1"

if want sendfile; then
	proof sendfile_ioerror_extpg "$h" "$s" proof_ioerror_extpg "$dread" \
	    "vn_sendfile.14:2,$ul"
	slow proof sendfile_ioerror_later_extpg "$h" "$s" proof_ioerror_extpg \
	    "$dlater" "vn_sendfile.14:2,$ul"
	# Mapped mbufs, on one page runs, the model's walks bounded to a
	# header and a page mbuf, and on two page runs.
	proof sendfile_ioerror_mapped1 "$h" "$s" proof_ioerror "$dioe1" \
	    "vn_sendfile.14:2,$uioe1"
	proof sendfile_ioerror_mapped2 "$h" "$s" proof_ioerror "$dread" \
	    "vn_sendfile.14:2,$uioe2"
	# The abort frees exactly the mapped page mbufs queued not ready ...
	mutant sendfile_ioerror_mapped_free "$h" "$s" proof_ioerror "$dioe1" \
	    "vn_sendfile.14:2,$uioe1" \
	    's/mb_free_notready(sfio->m, sfio->npages);/mb_free_notready(sfio->m, sfio->npages + 1);/'
	# ... which are the ones queued while their pages are read.
	mutant sendfile_ioerror_mapped_notready "$h" "$s" proof_ioerror \
	    "$dioe1" "vn_sendfile.14:2,$uioe1" \
	    's/^\([[:space:]]*\)m0->m_flags |= M_NOTREADY;$/\1;/'

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
	# Near 60G: SLOW=1 (proven so, in 27 minutes).
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

#
# ktls_frame() and ktls_enqueue(): sys/kern/uipc_ktls.c against the TLS
# record layer of the RFCs, on sessions ktls_create_session() makes.
#
h="$here/ktls/ktls.c"
s="$top/sys/kern/uipc_ktls.c"
# Chains of up to three records (MAXREC), so walks of four iterations;
# keys of up to 64 bytes.
dk="-DKERN_TLS"
uk="ktls_frame.2:4,proof_frame.0:4,records.0:4,framed.0:4,randomized.0:5"
uk="$uk,session.0:9,ktls_enqueue.3:4,ktls_enqueue.12:4,ktls_enqueue.13:4"
uk="$uk,ktls_enqueue.18:4,ktls_batched_records.0:4,proof_enqueue.0:4"
uk="$uk,proof_enqueue_turn.3:4,proof_enqueue_turn.4:4"
uk="$uk,proof_enqueue_turn.5:4,proof_enqueue_turn.8:4,cbmc_memmove.0:65"
# The worker on one record (WREC) of up to five pages.
dw="-DKERN_TLS -DWREC=1"
uw="ktls_encrypt.4:2,ktls_encrypt_async.5:2,ktls_encrypt_record.4:6"
uw="$uw,ktls_encrypt_record.6:6,ktls_finish_nonanon.1:6"
uw="$uw,ktls_finish_nonanon.2:6,mb_free_notready.0:7,mb_free_extpg.0:6"
uw="$uw,widx.0:2,cbmc_pr_ready.0:2,ktls_ocf_encrypt.0:6,batch.0:3"
uw="$uw,check_batch.0:2,check_batch.1:2,check_batch.2:6"
uw="$uw,proof_encrypt_async.0:2,session.0:9,cbmc_memmove.0:65"
dw2="-DKERN_TLS -DWREC=2"
# Receive: records of up to 40 bytes (RLEN) over three mbufs.
ur="proof_rx_type.0:41,proof_rx_type.1:41,rx_chain.0:4"
ur="$ur,tls13_find_record_type.0:41,tls13_find_record_type.1:4"
ur="$ur,proof_rx_check.0:41,m_copydata.0:22,chain_byte.0:5,cbmc_memmove.0:41"
dr12="-DKERN_TLS -DRLEN=12"
ur12="proof_rx_detach.0:13,proof_rx_detach.1:13,m_length.0:5,chain_byte.0:5"
ur12="$ur12,check_tls_chain.0:13,mbcnt.0:5,rx_chain.0:4"
ur12="$ur12,ktls_detach_record.1:5,ktls_detach_record.3:5,cbmc_memmove.0:13"
hr="$here/ktls/ktls_rx.c"
# The send tag proofs have no loop of their own.
ut="cbmc_memmove.0:65"
drn="-DKERN_TLS -DRMBUF=1 -DRX_RECORD -DRX_NIC -DRX_CIPHER=CRYPTO_AES_NIST_GCM_16"
drn="$drn -DRX_VMINOR=TLS_MINOR_VER_TWO"
urn="proof_rx_decrypt.1:2,proof_rx_decrypt.3:3,ktls_decrypt.8:3"
urn="$urn,ktls_decrypt.6:3,ktls_decrypt.7:3,m_freem.0:5,ktls_detach_record.1:4"
urn="$urn,ktls_detach_record.3:4,tls13_find_record_type.1:3,m_copydata.0:22"
urn="$urn,m_length.0:3,chain_byte.0:3,rx_chain.0:2,ktls_mbuf_crypto_state.0:2"
urn32="$urn,proof_rx_decrypt.0:33,proof_rx_decrypt.2:33"
urn32="$urn32,tls13_find_record_type.0:33,cbmc_memmove.0:33"
urn20="$urn,proof_rx_decrypt.0:21,proof_rx_decrypt.2:21"
urn20="$urn20,tls13_find_record_type.0:21,cbmc_memmove.0:21"
uw2=$(echo "$uw" | sed -E 's/(ktls_encrypt\.4|widx\.0|cbmc_pr_ready\.0|check_batch\.[01]):2/\1:3/g; s/mb_free_notready\.0:7/mb_free_notready.0:12/; s/batch\.0:3/batch.0:4/; s/check_batch\.2:6/check_batch.2:11/')

if want ktls; then
	proof ktls_frame "$h" "$s" proof_frame "$dk" "$uk"
	proof ktls_enqueue "$h" "$s" proof_enqueue "$dk" "$uk"
	proof ktls_enqueue_turn "$h" "$s" proof_enqueue_turn "$dk" "$uk"

	# CBC pads to whole blocks ...
	mutant ktls_frame_cbcpad "$h" "$s" proof_frame "$dk" "$uk" \
	    's/m->m_epg_trllen -= delta;/;/'
	# ... after a random explicit IV from TLS 1.1 on.
	mutant ktls_frame_iv "$h" "$s" proof_frame "$dk" "$uk" \
	    's/arc4rand(tlshdr + 1, AES_BLOCK_LEN, 0);/;/'
	# Each GCM record has a nonce of its own.
	mutant ktls_frame_nonce "$h" "$s" proof_frame "$dk" "$uk" \
	    's/(\*noncep)++;/;/'
	# The header gives the length of what follows it.
	mutant ktls_frame_length "$h" "$s" proof_frame "$dk" "$uk" \
	    's/htons(m->m_len - sizeof(\*tlshdr));/htons(m->m_len);/'
	# TLS 1.3 records pass as TLS 1.2 application data ...
	mutant ktls_frame_tls13ver "$h" "$s" proof_frame "$dk" "$uk" \
	    's/tlshdr->tls_vminor = TLS_MINOR_VER_TWO;/tlshdr->tls_vminor = tls->params.tls_vminor;/'
	# ... their real type in the trailer, which has room for it.
	mutant ktls_frame_tls13type "$h" "$s" proof_frame "$dk" "$uk" \
	    's/m->m_epg_trail\[0\] = record_type;/;/'
	mutant ktls_frame_tls13tlen "$h" "$s" proof_frame "$dk" "$uk" \
	    's/tls->params.tls_tlen += sizeof(uint8_t);/;/'
	# A record holds a session reference.
	mutant ktls_frame_hold "$h" "$s" proof_frame "$dk" "$uk" \
	    's/m->m_epg_tls = ktls_hold(tls);/m->m_epg_tls = tls;/'
	# An empty TLS 1.0 record has one page to encrypt.
	mutant ktls_frame_empty "$h" "$s" proof_frame "$dk" "$uk" \
	    's/m->m_epg_nrdy = 1;/m->m_epg_nrdy = m->m_epg_npgs;/'
	# Only TLS 1.0 CBC records are encrypted in turn.
	mutant ktls_create_sequential "$h" "$s" proof_frame "$dk" "$uk" \
	    's/tls->sequential_records = true;/;/'

	# An idle queue's thread is woken.
	mutant ktls_enqueue_wakeup "$h" "$s" proof_enqueue "$dk" "$uk" \
	    '/^ktls_enqueue(/,/^}/s/if (!running)$/if (0)/'
	# A TLS 1.0 batch out of turn waits ...
	mutant ktls_enqueue_outofturn "$h" "$s" proof_enqueue "$dk" "$uk" \
	    's/if (m->m_epg_seqno != tls->next_seqno) {/if (0) {/'
	# ... the next in turn being past every record of the batch ...
	mutant ktls_enqueue_batched "$h" "$s" proof_enqueue "$dk" "$uk" \
	    's/tls->next_seqno += ktls_batched_records(m);/tls->next_seqno++;/'
	# ... in sequence with the others waiting ...
	mutant ktls_enqueue_sorted "$h" "$s" proof_enqueue_turn "$dk" "$uk" \
	    '/^ktls_enqueue(/,/^}/s/if (n == NULL)$/if (1)/'
	# ... until those before it are queued, and is then counted so.
	mutant ktls_enqueue_drain "$h" "$s" proof_enqueue_turn "$dk" "$uk" \
	    's/while (!STAILQ_EMPTY(\&tls->pending_records)) {/while (0) {/'
	mutant ktls_enqueue_pending "$h" "$s" proof_enqueue_turn "$dk" "$uk" \
	    's/counter_u64_add(ktls_cnt_tx_pending, -(queued - 1));/;/'

	# The worker, on a batch of one record and the record after it.
	proof ktls_encrypt "$h" "$s" proof_encrypt "$dw" "$uw"
	proof ktls_encrypt_async "$h" "$s" proof_encrypt_async "$dw" "$uw"
	# Two records, 54G (proven so, in 25 minutes); asynchronously, past
	# 100G, out of reach.
	slow proof ktls_encrypt2 "$h" "$s" proof_encrypt "$dw2" "$uw2"

	# A record's pages count as many as it has unready ...
	mutant ktls_encrypt_nrdy "$h" "$s" proof_encrypt "$dw" "$uw" \
	    '/^ktls_encrypt(/,/^}/s/npages += m->m_epg_nrdy;/npages += m->m_epg_npgs;/'
	# ... and once encrypted it holds no session, is read-only ...
	mutant ktls_encrypt_session "$h" "$s" proof_encrypt "$dw" "$uw" \
	    '/^ktls_encrypt(/,/^}/s/^		ktls_free(tls);/		;/'
	mutant ktls_encrypt_rdonly "$h" "$s" proof_encrypt "$dw" "$uw" \
	    '/^ktls_encrypt(/,/^}/s/m->m_flags |= M_RDONLY;/;/'
	# ... and anonymous, its file pages let go for the new ones, freed
	# by a routine of theirs.
	mutant ktls_finish_anon "$h" "$s" proof_encrypt "$dw" "$uw" \
	    's/m->m_epg_flags |= EPG_FLAG_ANON;/;/'
	mutant ktls_finish_srcfree "$h" "$s" proof_encrypt "$dw" "$uw" \
	    '/^ktls_finish_nonanon(/,/^}/s/^	m->m_ext.ext_free(m);/	if (0) m->m_ext.ext_free(m);/'
	mutant ktls_finish_contig "$h" "$s" proof_encrypt "$dw" "$uw" \
	    's/m->m_ext.ext_free = ktls_free_mext_contig;/m->m_ext.ext_free = mb_free_mext_pgs;/'
	# The output covers the payload, page by page from its offset.
	mutant ktls_record_iovlen "$h" "$s" proof_encrypt "$dw" "$uw" \
	    's/state->dst_iov\[0\].iov_len = len;/state->dst_iov[0].iov_len = len - 1;/'
	mutant ktls_record_offset "$h" "$s" proof_encrypt "$dw" "$uw" \
	    's/for (i = 0; i < m->m_epg_npgs; i++, off = 0) {/for (i = 0; i < m->m_epg_npgs; i++) {/'
	# A failed encryption frees the pages it took and the batch.
	mutant ktls_record_pgfree "$h" "$s" proof_encrypt "$dw" "$uw" \
	    '/^ktls_encrypt_record(/,/^}/s/vm_page_free(pg);/;/'
	mutant ktls_encrypt_errfree "$h" "$s" proof_encrypt "$dw" "$uw" \
	    '/^ktls_encrypt(/,/^}/s/mb_free_notready(top, total_pages);/;/'
	# Asynchronously, each request holds a socket reference, and its
	# completion drops the session's and frees what failed.
	mutant ktls_async_soref "$h" "$s" proof_encrypt_async "$dw" "$uw" \
	    '/^ktls_encrypt_async(/,/^}/s/^		soref(so);/		;/'
	mutant ktls_async_errfree "$h" "$s" proof_encrypt_async "$dw" \
	    "$uw" 's/mb_free_notready(m, total_pages - npages);/;/'
	mutant ktls_cb_session "$h" "$s" proof_encrypt_async "$dw" "$uw" \
	    '/^ktls_encrypt_cb(/,/^}/s/^	ktls_free(tls);/	;/'
	mutant ktls_cb_errfree "$h" "$s" proof_encrypt_async "$dw" "$uw" \
	    '/^ktls_encrypt_cb(/,/^}/s/mb_free_notready(m, npages);/;/'

	# Receive: the TLS 1.3 record type, a record detached from the TLS
	# chain (on chains of 12 bytes, which is enough for its splits),
	# and a socket queued for decryption.
	proof ktls_rx_type "$h" "$s" proof_rx_type "$dk" "$ur"
	proof ktls_rx_detach "$h" "$s" proof_rx_detach "$dr12" "$ur12"
	proof ktls_rx_check "$h" "$s" proof_rx_check "$dk" "$ur"

	# Content with no type is refused ...
	mutant ktls_rx_notype "$h" "$s" proof_rx_type "$dk" "$ur" \
	    's/if (last_offset < tls->params.tls_hlen)/if (0)/'
	# ... and the trailer starts at the type.
	mutant ktls_rx_trailer "$h" "$s" proof_rx_type "$dk" "$ur" \
	    's/\*trailer_len = tls_len - last_offset;/*trailer_len = tls_len - last_offset - 1;/'
	# What is left after a split record starts after it, is counted,
	# and its tail kept.
	mutant ktls_rx_split "$h" "$s" proof_rx_detach "$dr12" "$ur12" \
	    's/n->m_data = m->m_data + remain;/n->m_data = m->m_data;/'
	mutant ktls_rx_tlscc "$h" "$s" proof_rx_detach "$dr12" "$ur12" \
	    '/^ktls_detach_record(/,/^}/s/sb->sb_tlscc -= n->m_len;/;/'
	mutant ktls_rx_tail "$h" "$s" proof_rx_detach "$dr12" "$ur12" \
	    '/^ktls_detach_record(/,/^}/s/sb->sb_mtlstail = n;/;/'
	# A socket is queued for a whole record only, once, referenced.
	mutant ktls_rx_whole "$h" "$s" proof_rx_check "$dk" "$ur" \
	    's/if (sb->sb_tlscc < sizeof(hdr) + ntohs(hdr.tls_length)) {/if (sb->sb_tlscc < sizeof(hdr)) {/'
	mutant ktls_rx_once "$h" "$s" proof_rx_check "$dk" "$ur" \
	    '/^ktls_check_rx(/,/^}/s/if (sb->sb_flags \& SB_TLS_RX_RUNNING)$/if (0)/'
	mutant ktls_rx_soref "$h" "$s" proof_rx_check "$dk" "$ur" \
	    '/^ktls_check_rx(/,/^}/s/^	soref(so);/	;/'

	# ktls_decrypt(), on one record in one mbuf, decrypted by the NIC,
	# AES-GCM TLS 1.2 (header 13, tag 16): one of 32 bytes is delivered,
	# one of 20, shorter than its tag, refused.
	proof ktls_rx_decrypt_nic "$hr" "$s" proof_rx_decrypt \
	    "$drn -DRX_LEN=32 -DRLEN=32" "$urn32"
	proof ktls_rx_decrypt_short "$hr" "$s" proof_rx_decrypt \
	    "$drn -DRX_LEN=20 -DRLEN=20" "$urn20"
	# The fix taken back: the payload comes to -9 bytes and the trailer
	# trim walks off the chain to a NULL dereference.
	mutant ktls_rx_decrypt_tagless "$hr" "$s" proof_rx_decrypt \
	    "$drn -DRX_LEN=20 -DRLEN=20" "$urn20" \
	    's/if (tls_len < tls->params.tls_hlen +$/if (0 \&\& tls_len < tls->params.tls_hlen +/'

	# The ifnet send tag: allocated on the route's interface, or the
	# error of what is missing; a reset scheduled once on a route
	# change, which installs a new tag or aborts the connection.
	proof ktls_tag_alloc "$h" "$s" proof_tag_alloc "$dk" "$ut"
	proof ktls_tag_eagain "$h" "$s" proof_tag_eagain "$dk" "$ut"
	proof ktls_tag_reset "$h" "$s" proof_tag_reset "$dk" "$ut"
	proof ktls_tag_try "$h" "$s" proof_tag_try "$dk" "$ut"

	# Forced requests pass the administrative switch ...
	mutant ktls_tag_force "$h" "$s" proof_tag_alloc "$dk" "$ut" \
	    's/if (!force \&\& ktls_ifnet_permitted == 0) {/if (ktls_ifnet_permitted == 0) {/'
	# ... the interface is let go, can offload the address family, and
	# rate limits a paced connection.
	mutant ktls_tag_ifrele "$h" "$s" proof_tag_alloc "$dk" "$ut" \
	    '/^ktls_alloc_snd_tag(/,/^}/s/^	if_rele(ifp);/	;/'
	mutant ktls_tag_inet6 "$h" "$s" proof_tag_alloc "$dk" "$ut" \
	    '/^ktls_alloc_snd_tag(/,/^}/s/IFCAP_TXTLS6) == 0) {/IFCAP_TXTLS4) == 0) {/'
	mutant ktls_tag_rtlmt "$h" "$s" proof_tag_alloc "$dk" "$ut" \
	    '/^ktls_alloc_snd_tag(/,/^}/s/if (tp->t_pacing_rate != -1 \&\&/if (tp->t_pacing_rate == -1 \&\&/'
	# A reset is scheduled once, with a reference ...
	mutant ktls_tag_once "$h" "$s" proof_tag_eagain "$dk" "$ut" \
	    '/^ktls_output_eagain(/,/^}/s/if (!tls->reset_pending) {/if (1) {/'
	mutant ktls_tag_hold "$h" "$s" proof_tag_eagain "$dk" "$ut" \
	    '/^ktls_output_eagain(/,/^}/s/(void) ktls_hold(tls);/;/'
	# ... and lets the old tag go, is done once it has a new one, and
	# drops its reference.
	mutant ktls_tag_oldrele "$h" "$s" proof_tag_reset "$dk" "$ut" \
	    '/^ktls_reset_send_tag(/,/^}/s/^		m_snd_tag_rele(old);/		;/'
	mutant ktls_tag_done "$h" "$s" proof_tag_reset "$dk" "$ut" \
	    '/^ktls_reset_send_tag(/,/^}/s/tls->reset_pending = false;/;/'
	mutant ktls_tag_taskref "$h" "$s" proof_tag_reset "$dk" "$ut" \
	    '/^ktls_reset_send_tag(/,/^}/s/^	ktls_free(tls);/	;/'
	# An offloaded session holds its tag.
	mutant ktls_tag_install "$h" "$s" proof_tag_try "$dk" "$ut" \
	    '/^ktls_try_ifnet(/,/^}/s/tls->snd_tag = mst;/;/'

	# Switching an open connection between software and NIC offload.
	proof ktls_set_tx_mode "$h" "$s" proof_set_tx_mode "$dk" "$ut"
	# Offload is enabled once ...
	mutant ktls_mode_again "$h" "$s" proof_set_tx_mode "$dk" "$ut" \
	    '/^ktls_set_tx_mode(/,/^}/s/if (tp->t_nic_ktls_xmit)$/if (0)/'
	# ... a switch that lost the race to another fails and frees its
	# clone ...
	mutant ktls_mode_race "$h" "$s" proof_set_tx_mode "$dk" "$ut" \
	    '/^ktls_set_tx_mode(/,/^}/s/if (tls != so->so_snd.sb_tls_info) {/if (0) {/'
	mutant ktls_mode_busyfree "$h" "$s" proof_set_tx_mode "$dk" "$ut" \
	    '/^ktls_set_tx_mode(/,/^}/{/SOCK_IO_SEND_UNLOCK(so);$/{n;s/ktls_free(tls_new);/;/;};}'
	# ... one that won lets the old session go and marks the
	# connection ...
	mutant ktls_mode_oldref "$h" "$s" proof_set_tx_mode "$dk" "$ut" \
	    '/KASSERT(tls->refcount >= 2/{n;s/ktls_free(tls);/;/;}'
	mutant ktls_mode_mark "$h" "$s" proof_set_tx_mode "$dk" "$ut" \
	    '/^ktls_set_tx_mode(/,/^}/s/tp->t_nic_ktls_xmit = 1;/;/'
	# ... and it sleeps for the send lock with the inpcb unlocked.
	mutant ktls_mode_unlock "$h" "$s" proof_set_tx_mode "$dk" "$ut" \
	    '/^ktls_set_tx_mode(/,/^}/s/^	INP_WUNLOCK(inp);$/	;/'

	# Offload disabled on too many retransmits, by a task.
	proof ktls_disable_ifnet "$h" "$s" proof_disable_ifnet "$dk" "$ut"
	# Once per connection ...
	mutant ktls_disable_once "$h" "$s" proof_disable_ifnet "$dk" "$ut" \
	    '/^ktls_disable_ifnet(void/,/^}/s/if (tp->t_nic_ktls_xmit_dis == 1) {/if (0) {/'
	# ... the task holding the session and the socket, and letting
	# both go ...
	mutant ktls_disable_hold "$h" "$s" proof_disable_ifnet "$dk" "$ut" \
	    '/^ktls_disable_ifnet(void/,/^}/s/(void)ktls_hold(tls);/;/'
	mutant ktls_disable_soref "$h" "$s" proof_disable_ifnet "$dk" "$ut" \
	    '/^ktls_disable_ifnet(void/,/^}/s/^	soref(so);/	;/'
	mutant ktls_disable_sorele "$h" "$s" proof_disable_ifnet "$dk" "$ut" \
	    '/^ktls_disable_ifnet_help(/,/^}/s/^	sorele(so);/	;/'
	mutant ktls_disable_free "$h" "$s" proof_disable_ifnet "$dk" "$ut" \
	    '/^ktls_disable_ifnet_help(/,/^}/s/^	ktls_free(tls);/	;/'
	# ... and the inpcb; a closed connection left alone, an open one
	# switched to software and the stack told offload is off.
	mutant ktls_disable_unlock "$h" "$s" proof_disable_ifnet "$dk" "$ut" \
	    '/^ktls_disable_ifnet_help(/,/^}/s/^	INP_WUNLOCK(inp);/	;/'
	mutant ktls_disable_closed "$h" "$s" proof_disable_ifnet "$dk" "$ut" \
	    '/^ktls_disable_ifnet_help(/,/^}/s/if (tp->t_flags \& TF_DISCONNECTED) {/if (0) {/'
	mutant ktls_disable_off "$h" "$s" proof_disable_ifnet "$dk" "$ut" \
	    '/^ktls_disable_ifnet_help(/,/^}/s/(\*tp->t_fb->tfb_hwtls_change)(tp, 0);/(*tp->t_fb->tfb_hwtls_change)(tp, 1);/'

	# The receive tag: allocated on the route's interface, or the error
	# of what is missing; reset once when packets come in on another,
	# a new tag where that interface can receive TLS for the family.
	proof ktls_rx_tag_alloc "$h" "$s" proof_rx_tag_alloc "$dk" "$ut"
	proof ktls_rx_tag_mismatch "$h" "$s" proof_rx_tag_mismatch "$dk" "$ut"
	proof ktls_rx_tag_reset "$h" "$s" proof_rx_tag_reset "$dk" "$ut"

	# The fix taken back, for each family: IFCAP2_RXTLS4/6 are bit
	# numbers, not masks.
	mutant ktls_rx_tag_v4 "$h" "$s" proof_rx_tag_reset "$dk" "$ut" \
	    '/^ktls_reset_receive_tag(/,/^}/s/IFCAP2_BIT(IFCAP2_RXTLS4))/IFCAP2_RXTLS4)/'
	mutant ktls_rx_tag_v6 "$h" "$s" proof_rx_tag_reset "$dk" "$ut" \
	    '/^ktls_reset_receive_tag(/,/^}/s/IFCAP2_BIT(IFCAP2_RXTLS6))/IFCAP2_RXTLS6)/'
	# The reset is done, and lets go of the socket and interface.
	mutant ktls_rx_tag_done "$h" "$s" proof_rx_tag_reset "$dk" "$ut" \
	    '/^ktls_reset_receive_tag(/,/^}/s/tls->reset_pending = false;/;/'
	mutant ktls_rx_tag_sorele "$h" "$s" proof_rx_tag_reset "$dk" "$ut" \
	    '/^ktls_reset_receive_tag(/,/^}/s/^	sorele(so);/	;/'
	mutant ktls_rx_tag_ifrele "$h" "$s" proof_rx_tag_reset "$dk" "$ut" \
	    '/^ktls_reset_receive_tag(/,/^}/s/^		if_rele(ifp);/		;/'
	# It is scheduled once, with a socket reference.
	mutant ktls_rx_tag_once "$h" "$s" proof_rx_tag_mismatch "$dk" "$ut" \
	    '/^ktls_input_ifp_mismatch(/,/^}/s/if (!tls->reset_pending) {/if (1) {/'
	mutant ktls_rx_tag_soref "$h" "$s" proof_rx_tag_mismatch "$dk" "$ut" \
	    '/^ktls_input_ifp_mismatch(/,/^}/s/^		soref(so);/		;/'
	# No tag the NIC cannot hand back, or for the wrong family.
	mutant ktls_rx_tag_recrypt "$h" "$s" proof_rx_tag_alloc "$dk" "$ut" \
	    's/if (!ktls_ocf_recrypt_supported(tls))/if (0)/'
	mutant ktls_rx_tag_alloc6 "$h" "$s" proof_rx_tag_alloc "$dk" "$ut" \
	    '/^ktls_alloc_rcv_tag(/,/^}/s/IFCAP2_BIT(IFCAP2_RXTLS6)/IFCAP2_BIT(IFCAP2_RXTLS4)/'

	# The software decryption of sys/opencrypto/ktls_ocf.c, on records
	# of any bytes over two mbufs.  CBC, TLS 1.1 and 1.2, every MAC, on
	# records of a fixed length: not whole blocks (40), too short for
	# SHA-256 and SHA-384 (48), short (64), padding byte past 127 (176,
	# 17 minutes) and up to 255 (304, 83 minutes and 8G: SLOW=1).
	ho="$here/ktls/ktls_ocf.c"
	so="$top/sys/opencrypto/ktls_ocf.c"
	uo="record.0:3,cbyte.0:3,cbmc_ktls_ocf_dispatch.0:4,cbmc_memmove.0:17"
	uc="$uo,ktls_ocf_tls_cbc_decrypt.0:3,ktls_ocf_tls_cbc_decrypt.1:3"
	uc="$uc,check_padding.0:257,m_apply.0:3,m_apply.1:3,m_copydata.0:9"
	uc="$uc,proof_cbc_decrypt.0:257"
	for l in 40 48 64 176; do
		proof ktls_ocf_cbc_$l "$ho" "$so" proof_cbc_decrypt \
		    "$dk -DRLEN=$l" "$uc"
	done
	slow proof ktls_ocf_cbc_304 "$ho" "$so" proof_cbc_decrypt \
	    "$dk -DRLEN=304" "$uc"
	dc="$dk -DRLEN=64"
	# The fix taken back: padding bytes compared as signed chars, so a
	# valid record with a padding byte past 127 is refused.
	mutant ktls_ocf_cbc_sign "$ho" "$so" proof_cbc_decrypt \
	    "$dk -DRLEN=176" "$uc" \
	    '/^check_padding(/,/^}/s/const uint8_t \*cp = data;/const char *cp = data;/'
	# A record too short or not whole blocks is refused ...
	mutant ktls_ocf_cbc_short "$ho" "$so" proof_cbc_decrypt "$dc" "$uc" \
	    's/tls_len < AES_BLOCK_LEN + roundup2(os->mac_len + 1, AES_BLOCK_LEN))/tls_len < AES_BLOCK_LEN)/'
	# ... decrypted after its IV ...
	mutant ktls_ocf_cbc_iv "$ho" "$so" proof_cbc_decrypt "$dc" "$uc" \
	    's/crp.crp_iv_start = sizeof(\*hdr);/crp.crp_iv_start = 0;/'
	# ... its padding refused when it does not fit after the IV and MAC,
	# or is not all its length (walking it one byte short is no mutant:
	# the byte left out is the padding length itself) ...
	mutant ktls_ocf_cbc_fit "$ho" "$so" proof_cbc_decrypt "$dc" "$uc" \
	    's/if (AES_BLOCK_LEN + \*trailer_len > tls_len)/if (*trailer_len > tls_len)/'
	mutant ktls_ocf_cbc_pad "$ho" "$so" proof_cbc_decrypt "$dc" "$uc" \
	    '/^check_padding(/,/^}/s/if (\*cp != pad)/if (0 \&\& *cp != pad)/'
	mutant ktls_ocf_cbc_walk "$ho" "$so" proof_cbc_decrypt "$dc" "$uc" \
	    's/(pad + 1), pad + 1,/pad, pad + 1,/'
	# ... the MAC checked over the content, after the IV, and the
	# trailer the MAC and padding.
	mutant ktls_ocf_cbc_skip "$ho" "$so" proof_cbc_decrypt "$dc" "$uc" \
	    's/skip = sizeof(\*hdr) + AES_BLOCK_LEN;/skip = sizeof(*hdr);/'
	mutant ktls_ocf_cbc_mac "$ho" "$so" proof_cbc_decrypt "$dc" "$uc" \
	    's/tls_comp_len = tls_len - (AES_BLOCK_LEN + \*trailer_len);/tls_comp_len = tls_len - *trailer_len;/'
	mutant ktls_ocf_cbc_trailer "$ho" "$so" proof_cbc_decrypt "$dc" "$uc" \
	    's/= os->mac_len + pad + 1;/= os->mac_len + pad;/'

	# AES-GCM and ChaCha20-Poly1305, TLS 1.2 and 1.3, on records of up
	# to 64 bytes: refused when too short for nonce, content type and
	# tag, else decrypted and the tag checked in one request.
	proof ktls_ocf_aead12 "$ho" "$so" proof_aead12_decrypt "$dc" "$uo"
	proof ktls_ocf_aead13 "$ho" "$so" proof_aead13_decrypt "$dc" "$uo"
	mutant ktls_ocf_aead12_short "$ho" "$so" proof_aead12_decrypt "$dc" \
	    "$uo" '/^ktls_ocf_tls12_aead_decrypt(/,/^}/s/tls->params.tls_hlen +$/tls->params.tls_hlen + 0 */'
	mutant ktls_ocf_aead12_len "$ho" "$so" proof_aead12_decrypt "$dc" \
	    "$uo" '/^ktls_ocf_tls12_aead_decrypt(/,/^}/s/(AES_GMAC_HASH_LEN + sizeof(uint64_t));/AES_GMAC_HASH_LEN;/'
	mutant ktls_ocf_aead13_short "$ho" "$so" proof_aead13_decrypt "$dc" \
	    "$uo" 's/if (tls_len < tag_len + 1)/if (tls_len < tag_len)/'
	mutant ktls_ocf_aead13_len "$ho" "$so" proof_aead13_decrypt "$dc" \
	    "$uo" '/^ktls_ocf_tls13_aead_decrypt(/,/^}/s/crp.crp_payload_length = tls_len - tag_len;/crp.crp_payload_length = tls_len - tag_len - 1;/'

	# The recrypt of a record the NIC decrypted in part, AES-GCM TLS 1.2
	# and 1.3, records of a fixed length (each byte is checked), too
	# short or not: the ciphertext back in the decrypted mbufs only, over
	# the content only.
	ur="record.0:3,cbyte.0:3,cbmc_ktls_ocf_dispatch.0:4,cbmc_memmove.0:54"
	ur="$ur,cbmc_ktls_ocf_dispatch.1:49"
	ur="$ur,proof_recrypt.0:3,proof_recrypt.1:3,proof_recrypt.2:54"
	ur="$ur,ktls_ocf_recrypt_fixup.0:3,ktls_ocf_recrypt_fixup.1:3"
	for v in TWO:20 TWO:32 THREE:16 THREE:32; do
		proof ktls_ocf_recrypt_${v%:*}_${v#*:} "$ho" "$so" proof_recrypt \
		    "$dk -DVMINOR=TLS_MINOR_VER_${v%:*} -DRLEN=${v#*:}" "$ur"
	done
	d2="$dk -DVMINOR=TLS_MINOR_VER_TWO -DRLEN=32"
	d3="$dk -DVMINOR=TLS_MINOR_VER_THREE -DRLEN=32"
	mutant ktls_ocf_recrypt_dec "$ho" "$so" proof_recrypt "$d2" "$ur" \
	    '/^ktls_ocf_recrypt_fixup(/,/^}/s/if (m->m_flags \& M_DECRYPTED)/if (1)/'
	mutant ktls_ocf_recrypt_skip "$ho" "$so" proof_recrypt "$d3" "$ur" \
	    '/^ktls_ocf_tls13_aead_recrypt(/,/^}/s/ktls_ocf_recrypt_fixup(m, tls->params.tls_hlen,/ktls_ocf_recrypt_fixup(m, 0,/'
	mutant ktls_ocf_recrypt_error "$ho" "$so" proof_recrypt "$d3" "$ur" \
	    '/^ktls_ocf_tls13_aead_recrypt(/,/^}/s/if (error == 0)/if (1)/'
	mutant ktls_ocf_recrypt_len12 "$ho" "$so" proof_recrypt "$d2" "$ur" \
	    '/^ktls_ocf_tls12_aead_recrypt(/,/^}/s/payload_len = tls_len - (AES_GMAC_HASH_LEN + sizeof(uint64_t));/payload_len = tls_len - AES_GMAC_HASH_LEN;/'
	mutant ktls_ocf_recrypt_short12 "$ho" "$so" proof_recrypt \
	    "$dk -DVMINOR=TLS_MINOR_VER_TWO -DRLEN=20" "$ur" \
	    's/if (tls_len < sizeof(uint64_t) + AES_GMAC_HASH_LEN)/if (tls_len < AES_GMAC_HASH_LEN)/'
	mutant ktls_ocf_recrypt_short13 "$ho" "$so" proof_recrypt \
	    "$dk -DVMINOR=TLS_MINOR_VER_THREE -DRLEN=16" "$ur" \
	    's/if (tls_len < AES_GMAC_HASH_LEN + 1)/if (tls_len < AES_GMAC_HASH_LEN)/'

	# setsockopt(2) TCP_TXTLS_ENABLE and TCP_RXTLS_ENABLE, uipc_ktls.c:
	# the option and keys copied in, then the session given the socket.
	he="$here/ktls/ktls_enable.c"
	se="$top/sys/kern/uipc_ktls.c"
	ue="cbmc_memmove.0:73,same.0:9,proof_copyin.0:9,enable_setup.0:9"
	proof ktls_copyin "$he" "$se" proof_copyin "$dk" "$ue"
	proof ktls_enable_tx "$he" "$se" proof_enable_tx "$dk" "$ue"
	proof ktls_enable_rx "$he" "$se" proof_enable_rx "$dk" "$ue"
	# A length past its bound, or no cipher key, refused ...
	mutant ktls_copyin_keylen "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/if (tls->cipher_key_len < 0 || tls->cipher_key_len > TLS_MAX_PARAM_SIZE)/if (tls->cipher_key_len < 0)/'
	mutant ktls_copyin_ivlen "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/if (tls->iv_len < 0 || tls->iv_len > sizeof/if (tls->iv_len < 0 \&\& tls->iv_len > sizeof/'
	mutant ktls_copyin_authlen "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/if (tls->auth_key_len < 0 || tls->auth_key_len > TLS_MAX_PARAM_SIZE)/if (tls->auth_key_len < 0)/'
	mutant ktls_copyin_nokey "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/if (tls->cipher_key_len == 0)/if (0)/'
	# ... nothing left allocated on an error ...
	mutant ktls_copyin_leak "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/zfree(iv, M_KTLS);/;/'
	# ... each key in a kernel buffer of its length holding the process's
	# bytes ...
	mutant ktls_copyin_ptr "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/tls->iv = iv;/;/'
	mutant ktls_copyin_copy "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/error = copyin(tls->auth_key, auth_key, tls->auth_key_len);/error = 0;/'
	# ... the old option's fields kept, from sequence number 0.
	mutant ktls_copyin_v0zero "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/memset(tls, 0, sizeof(\*tls));/;/'
	mutant ktls_copyin_v0flags "$he" "$se" proof_copyin "$dk" "$ue" \
	    '/^ktls_copyin_tls_enable(/,/^}/s/tls->flags = tls_v0.flags;/;/'
	# Refused while offload is off, on other than TCP, with unmapped mbufs
	# off, on a socket with a session, or one another enable won ...
	mutant ktls_enable_rx_off "$he" "$se" proof_enable_rx "$dk" "$ue" \
	    '/^ktls_enable_rx(/,/^}/s/if (!ktls_offload_enable || !ktls_rx_offload_enable)/if (!ktls_offload_enable)/'
	mutant ktls_enable_tx_tcp "$he" "$se" proof_enable_tx "$dk" "$ue" \
	    '/^ktls_enable_tx(/,/^}/s/if (so->so_proto->pr_protocol != IPPROTO_TCP)/if (0)/'
	mutant ktls_enable_tx_extpgs "$he" "$se" proof_enable_tx "$dk" "$ue" \
	    '/^ktls_enable_tx(/,/^}/s/if (mb_use_ext_pgs == 0)/if (0)/'
	mutant ktls_enable_tx_already "$he" "$se" proof_enable_tx "$dk" "$ue" \
	    '/^ktls_enable_tx(/,/^}/s/if (so->so_snd.sb_tls_info != NULL)$/if (0)/'
	mutant ktls_enable_tx_race "$he" "$se" proof_enable_tx "$dk" "$ue" \
	    '/^ktls_enable_tx(/,/^}/s/if (__predict_false(so->so_snd.sb_tls_info != NULL))/if (0)/'
	# ... on a spliced socket, with EINVAL; the fix taken back (rx_ret):
	# EALREADY ...
	mutant ktls_enable_tx_splice "$he" "$se" proof_enable_tx "$dk" "$ue" \
	    '/^ktls_enable_tx(/,/^}/s/else if ((so->so_snd.sb_flags \& SB_SPLICED) != 0)/else if (0)/'
	mutant ktls_enable_rx_splice "$he" "$se" proof_enable_rx "$dk" "$ue" \
	    '/^ktls_enable_rx(/,/^}/s/else if ((so->so_rcv.sb_flags \& SB_SPLICED) != 0)/else if (0)/'
	mutant ktls_enable_rx_ret "$he" "$se" proof_enable_rx "$dk" "$ue" \
	    '/else if ((so->so_rcv.sb_flags \& SB_SPLICED) != 0)/,/so->so_rcv.sb_tls_seqno/s/return (error);/return (EALREADY);/'
	# ... the session freed ...
	mutant ktls_enable_rx_free "$he" "$se" proof_enable_rx "$dk" "$ue" \
	    '/error = ktls_ocf_try(tls, KTLS_RX);/,/return (error);/s/ktls_free(tls);/;/'
	# ... or installed at the option's sequence number, the stack told of
	# NIC offload, receive data marked and checked, in software or on the
	# NIC.
	mutant ktls_enable_tx_seq "$he" "$se" proof_enable_tx "$dk" "$ue" \
	    '/^ktls_enable_tx(/,/^}/s/so->so_snd.sb_tls_seqno = be64dec(en->rec_seq);/;/'
	mutant ktls_enable_tx_nic "$he" "$se" proof_enable_tx "$dk" "$ue" \
	    '/^ktls_enable_tx(/,/^}/s/tp->t_nic_ktls_xmit = 1;/;/'
	mutant ktls_enable_tx_hw "$he" "$se" proof_enable_tx "$dk" "$ue" \
	    '/^ktls_enable_tx(/,/^}/s/if (tp->t_fb->tfb_hwtls_change != NULL)/if (0)/'
	mutant ktls_enable_rx_notready "$he" "$se" proof_enable_rx "$dk" "$ue" \
	    '/^ktls_enable_rx(/,/^}/s/sb_mark_notready(\&so->so_rcv);/;/'
	mutant ktls_enable_rx_check "$he" "$se" proof_enable_rx "$dk" "$ue" \
	    '/^ktls_enable_rx(/,/^}/s/ktls_check_rx(\&so->so_rcv);/;/'
	mutant ktls_enable_rx_sw "$he" "$se" proof_enable_rx "$dk" "$ue" \
	    '/^ktls_enable_rx(/,/^}/s/ktls_use_sw(tls);/;/'

	# sbappend_ktls_rx(), uipc_sockbuf.c: TCP data into a TLS receive
	# buffer, and the check for packets in on another interface.
	hs="$here/ktls/ktls_sb.c"
	ss="$top/sys/kern/uipc_sockbuf.c"
	us="sbappend_ktls_rx.3:4,proof_rx_append.0:4,proof_rx_append.1:4"
	proof ktls_rx_append "$hs" "$ss" proof_rx_append "$dk" "$us"
	# The fix taken back: the interface read from the first mbuf, whose
	# packet header is demoted by then, so NULL past one packet.
	mutant ktls_rx_append_first "$hs" "$ss" proof_rx_append "$dk" "$us" \
	    's/ifp = n->m_pkthdr.leaf_rcvif;/ifp = m->m_pkthdr.leaf_rcvif;/'
	# Each mbuf decrypted as its packet, demoted to plain data ...
	mutant ktls_rx_append_decrypted "$hs" "$ss" proof_rx_append "$dk" \
	    "$us" '/^sbappend_ktls_rx(/,/^}/s/flags = M_NOTREADY | M_DECRYPTED;/flags = M_NOTREADY;/'
	mutant ktls_rx_append_demote "$hs" "$ss" proof_rx_append "$dk" "$us" \
	    '/^sbappend_ktls_rx(/,/^}/s/n->m_flags \&= M_DEMOTEFLAGS;/;/'
	# ... the buffer checked for a whole record, and the session told
	# of another interface only.
	mutant ktls_rx_append_check "$hs" "$ss" proof_rx_append "$dk" "$us" \
	    '/^sbappend_ktls_rx(/,/^}/s/^	ktls_check_rx(sb);/	;/'
	mutant ktls_rx_append_mismatch "$hs" "$ss" proof_rx_append "$dk" \
	    "$us" '/^sbappend_ktls_rx(/,/^}/s/sb->sb_tls_info->rx_ifp != ifp)/sb->sb_tls_info->rx_ifp == ifp)/'

	# sbcompress_ktls_rx(), which sbappend_ktls_rx() appends with: the
	# bytes kept in order, coalesced only into a tail with room, of the
	# same decrypted state, and not when coalescing is off.  (Its
	# M_WRITABLE() test is implied by M_TRAILINGSPACE(), which is 0 on a
	# tail not writable: taking it back is no mutant.)
	hc="$here/ktls/ktls_sbc.c"
	uc="proof_rx_compress.0:7,proof_rx_compress.1:4,proof_rx_compress.2:19"
	uc="$uc,proof_rx_compress.3:5,cbyte.0:5,sbcompress_ktls_rx.4:4"
	uc="$uc,cbmc_memmove.0:7"
	proof ktls_rx_compress "$hc" "$ss" proof_rx_compress "$dk" "$uc"
	mutant ktls_rx_compress_mixed "$hc" "$ss" proof_rx_compress "$dk" "$uc" \
	    '/^sbcompress_ktls_rx(/,/^}/s/!((m->m_flags ^ n->m_flags) \& M_DECRYPTED) \&\&/1 \&\&/'
	mutant ktls_rx_compress_room "$hc" "$ss" proof_rx_compress "$dk" "$uc" \
	    '/^sbcompress_ktls_rx(/,/^}/s/m->m_len <= M_TRAILINGSPACE(n)) {/1) {/'
	mutant ktls_rx_compress_nocoal "$hc" "$ss" proof_rx_compress "$dk" \
	    "$uc" '/^sbcompress_ktls_rx(/,/^}/s/((sb->sb_flags \& SB_NOCOALESCE) == 0) \&\&/1 \&\&/'
	mutant ktls_rx_compress_empty "$hc" "$ss" proof_rx_compress "$dk" "$uc" \
	    '/^sbcompress_ktls_rx(/,/^}/s/if (m->m_len == 0) {/if (0) {/'
	mutant ktls_rx_compress_tlscc "$hc" "$ss" proof_rx_compress "$dk" "$uc" \
	    '/^sbcompress_ktls_rx(/,/^}/s/sb->sb_tlscc += m->m_len;/;/'
	mutant ktls_rx_compress_tail "$hc" "$ss" proof_rx_compress "$dk" "$uc" \
	    '/^sbcompress_ktls_rx(/,/^}/s/sb->sb_mtlstail = m;/;/'

	# sbcut_internal() on a TLS receive buffer: the decrypted records,
	# the record being decrypted, then the TLS chain.
	ux="sbcut_internal.5:6,proof_rx_cut.0:5,proof_rx_cut.1:3"
	ux="$ux,proof_rx_cut.2:3,proof_rx_cut.3:5,proof_rx_cut.4:6"
	ux="$ux,proof_rx_cut.5:6,proof_rx_cut.6:5"
	proof ktls_rx_cut "$hc" "$ss" proof_rx_cut "$dk" "$ux"
	# The record being decrypted is let go, counted out ...
	mutant ktls_rx_cut_dccclear "$hc" "$ss" proof_rx_cut "$dk" "$ux" \
	    '/^sbcut_internal(/,/^}/s/sb->sb_tlsdcc = 0;/;/'
	mutant ktls_rx_cut_dcclen "$hc" "$ss" proof_rx_cut "$dk" "$ux" \
	    '/^sbcut_internal(/,/^}/s/len -= sb->sb_tlsdcc;/;/'
	# ... the TLS chain freed as TLS data, all of it handed back ...
	mutant ktls_rx_cut_tlsfree "$hc" "$ss" proof_rx_cut "$dk" "$ux" \
	    '/^sbcut_internal(/,/^}/s/sbfree_ktls_rx(sb, m);/sbfree(sb, m);/'
	mutant ktls_rx_cut_tlslist "$hc" "$ss" proof_rx_cut "$dk" "$ux" \
	    '/^sbcut_internal(/,/^}/s/if (m->m_flags \& M_NOTREADY \&\& !is_tls)/if (m->m_flags \& M_NOTREADY)/'
	# ... and what is left of it, and of the records, kept in place.
	mutant ktls_rx_cut_mtls "$hc" "$ss" proof_rx_cut "$dk" "$ux" \
	    '/^sbcut_internal(/,/^}/s/sb->sb_mtls = m;/;/'
	mutant ktls_rx_cut_mtlstail "$hc" "$ss" proof_rx_cut "$dk" "$ux" \
	    '/^sbcut_internal(/,/^}/s/sb->sb_mtlstail = NULL;/;/'
	mutant ktls_rx_cut_sbmb "$hc" "$ss" proof_rx_cut "$dk" "$ux" \
	    '/^sbcut_internal(/,/^}/s/^		sb->sb_mb = NULL;/		;/'

	# sbappendcontrol_locked(), as ktls_decrypt() appends a record: its
	# control message, then its payload ...
	ur="proof_rx_record.0:3,proof_rx_record.1:3,sbappendcontrol_locked.1:4"
	ur="$ur,m_last.0:4,sbm_clrprotoflags.0:4"
	proof ktls_rx_record "$hc" "$ss" proof_rx_record "$dk" "$ur"
	mutant ktls_rx_record_link "$hc" "$ss" proof_rx_record "$dk" "$ur" \
	    '/^sbappendcontrol_locked(/,/^}/s/m_last(control)->m_next = m0;/;/'
	mutant ktls_rx_record_tail "$hc" "$ss" proof_rx_record "$dk" "$ur" \
	    '/^sbappendcontrol_locked(/,/^}/s/sb->sb_mbtail = mlast;/;/'
	# ... the last record (SBLINKRECORD(), which it alone uses here) ...
	mutant ktls_rx_record_last "$hc" "$ss" proof_rx_record "$dk" "$ur" \
	    's/^\t(sb)->sb_lastrecord = (m0);/\t;/'
	# ... every mbuf counted, the payload's protocol flags cleared.
	mutant ktls_rx_record_count "$hc" "$ss" proof_rx_record "$dk" "$ur" \
	    '/^sbappendcontrol_locked(/,/^}/s/^		sballoc(sb, m);/		;/'
	mutant ktls_rx_record_countlast "$hc" "$ss" proof_rx_record "$dk" \
	    "$ur" '/^sbappendcontrol_locked(/,/^}/s/^	sballoc(sb, m);/	;/'
	mutant ktls_rx_record_proto "$hc" "$ss" proof_rx_record "$dk" "$ur" \
	    '/^sbappendcontrol_locked(/,/^}/s/sbm_clrprotoflags(m0, flags);/;/'

	# sbready() on TLS send records, as the KTLS worker and sendfile(2)
	# ready them, and the headers sbready_compress() then moves into the
	# trailer before: on trailers of no byte, room for a header, and too
	# little room (TLEN).  About 36G and 20 minutes each, these fourteen
	# held the run past an hour: SLOW=1.
	ub="sbready.3:3,sbready.5:4,sbready_compress.3:4,sbready_compress.2:3"
	ub="$ub,proof_tx_ready.0:5,proof_tx_ready.1:4,proof_tx_ready.2:3"
	ub="$ub,proof_tx_ready.3:3,proof_tx_ready.4:3,proof_tx_ready.5:3"
	ub="$ub,proof_tx_ready.6:5,proof_tx_ready.7:5,proof_tx_ready.8:2"
	ub="$ub,cbmc_memmove.0:5"
	for t in 0 16 62; do
		slow proof ktls_tx_ready_$t "$hc" "$ss" proof_tx_ready \
		    "$dk -DTLEN=$t" "$ub"
	done
	db="$dk -DTLEN=16"
	# A record counts its unready pages, one if it has none ...
	slow mutant ktls_tx_ready_pages "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready(/,/^}/s/count -= m->m_epg_nrdy;/count--;/'
	slow mutant ktls_tx_ready_part "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready(/,/^}/s/m->m_epg_nrdy -= count;/m->m_epg_nrdy = 0;/'
	slow mutant ktls_tx_ready_empty "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready(/,/^}/s/if ((m->m_flags \& M_EXTPG) != 0 \&\& m->m_epg_npgs != 0) {/if ((m->m_flags \& M_EXTPG) != 0) {/'
	# ... readying the first record not ready makes it and the ready
	# ones after it readable ...
	slow mutant ktls_tx_ready_accrec "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready(/,/^}/s/^			sb->sb_acc += m->m_len;/			;/'
	slow mutant ktls_tx_ready_accnext "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready(/,/^}/s/^		sb->sb_acc += m->m_len;/		;/'
	slow mutant ktls_tx_ready_fnrdy "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready(/,/^}/s/sb->sb_fnrdy = m;/;/'
	# ... and a header moves to the end of the trailer before it, out
	# of a session, where it fits and coalescing is on.
	slow mutant ktls_tx_ready_sess "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/Try to coalesce adjacent ktls/,/int hdr_len, trail_len;/s/!mbuf_has_tls_session(m) \&\&/1 \&\&/'
	slow mutant ktls_tx_ready_room "$hc" "$ss" proof_tx_ready "$dk -DTLEN=62" \
	    "$ub" '/^sbready_compress(/,/^}/s/trail_len + hdr_len <= MBUF_PEXT_TRAIL_LEN) {/1) {/'
	slow mutant ktls_tx_ready_nocoal "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready_compress(/,/^}/s/if ((sb->sb_flags \& SB_NOCOALESCE) != 0)/if (0)/'
	slow mutant ktls_tx_ready_offset "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready_compress(/,/^}/s/memcpy(\&m->m_epg_trail\[trail_len\],/memcpy(\&m->m_epg_trail[0],/'
	slow mutant ktls_tx_ready_hdrzero "$hc" "$ss" proof_tx_ready "$db" "$ub" \
	    '/^sbready_compress(/,/^}/s/n->m_epg_hdrlen = 0;/;/'
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
	# A run killed from outside loses its work directory: stop.
	[ -d "$work" ] || exit 1
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

# A job that ran out of memory beside others, its cost underestimated
# after a change to the model, runs again alone.
for f in "$work"/*.rc; do
	[ -f "$f" ] || continue
	n=$(basename "$f" .rc)
	if [ "$(cat "$f")" != 0 ] && [ "$(cat "$f")" != 10 ] &&
	    grep -qi 'out of memory' "$work/$n.log"; then
		for j in "$work"/job.*; do
			[ "$(head -1 "$j")" = "$n" ] && i=${j##*.}
		done
		echo "run.sh: $n ran out of memory, running it alone" >&2
		rm -f "$work/$n.cost" "$f"
		sh "$0" --timed "$work" "$i"
	fi
done

# Keep the costs measured for the next run's schedule.
cat "$work"/*.cost 2>/dev/null >"$work/costs.new" || true
if [ -s "$work/costs.new" ]; then
	{ cat "$work/costs.new"; [ -f "$costs" ] && cat "$costs"; } |
	    awk '!seen[$1]++' | sort >"$work/costs.all"
	cp "$work/costs.all" "$costs"
fi

# violated LOG: the property a trace violates, which is all cbmc says of
# a failure under --stop-on-fail.
violated()
{
	awk '/^Violated property:/{getline; sub(/.* line /, ""); l=$1;
	    getline; sub(/^ */, ""); print "line " l " " $0; exit}' "$1"
}

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
		why=$( (violated "$work/$name.log"
		    (grep ': FAILURE$' "$work/$name.log" |
		    grep -v 'unwinding assertion'; grep -m1 ': FAILURE$' \
		    "$work/$name.log") | sed 's/^\[[^]]*\] //; s/: FAILURE$//') |
		    head -1)
		echo "ok   mutant $name: caught by $why"
		;;
	proof:10)
		echo "FAIL proof  $name:"
		grep ': FAILURE$' "$work/$name.log" | sed 's/^/	/'
		fail=1
		;;
	question:10)
		why=$( (violated "$work/$name.log"; grep -m1 ': FAILURE$' \
		    "$work/$name.log" | sed 's/^\[[^]]*\] //; s/: FAILURE$//') |
		    head -1)
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
