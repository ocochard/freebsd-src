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
replace_pager="vnode_pager_input_old:cbmc_vnode_pager_input
	vnode_pager_input_smlfs:cbmc_vnode_pager_input"
replace_kevent="kqueue_register:cbmc_kqueue_register
	kqueue_scan:cbmc_kqueue_scan"
replace_close="_fdrop:cbmc_fdrop
	filecaps_free:cbmc_filecaps_free"
replace_unp="unp_internalize_fp:cbmc_unp_internalize_fp
	unp_externalize_fp:cbmc_unp_externalize_fp
	unp_discard:cbmc_unp_discard"
replace_recvmsg="getsock:cbmc_getsock
	m_dispose_extcontrolm:cbmc_dispose"
replace_mmap_len="vm_mmap_object:cbmc_vm_mmap_object
	kern_mmap_maxprot:cbmc_kern_mmap_maxprot"
replace_mlock_len="vm_map_wire:cbmc_vm_map_wire
	priv_check_cred:cbmc_priv_check_cred
	pmap_wired_count:cbmc_pmap_wired_count"
replace_ip_fragment="m_copym:cbmc_m_copym
	m_dup_pkthdr:cbmc_m_dup_pkthdr
	in_cksum:cbmc_in_cksum"
replace_ip6_fragment="m_copym:cbmc_m_copym
	m_dup_pkthdr:cbmc_m_dup_pkthdr
	m_cat:cbmc_m_cat"
replace_syncookie="syncookie_mac:cbmc_syncookie_mac"
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
# m_apply() runs a caller function over the chain by pointer; pin it to the
# harness callback so cbmc does not branch over every matching function.
restrict_m_apply="m_apply_one.function_pointer_call.1/cbmc_apply_f"
restrict_ktls_send="sosend_generic_locked.function_pointer_call.1/cbmc_pr_send"
cbmc_ktls_send="--no-signed-overflow-check"
cbmc_ktls_enable="--no-signed-overflow-check"
cbmc_tcp="--no-signed-overflow-check"
cbmc_read="--no-signed-overflow-check"
cbmc_sbreserve="--unsigned-overflow-check"
# sbcreatecontrol's bzero/memcpy are byte loops in the kern.h model; a size
# near UINT_MAX would blow up their unwinding, so swap in touch models.
replace_sbcreatecontrol="cbmc_memset:cbmc_sb_memset
	cbmc_memcpy:cbmc_sb_memcpy"
cbmc_mmap_len="--no-signed-overflow-check"
cbmc_mlock_len="--no-signed-overflow-check"
replace_sack="tcp_record_dsack:cbmc_tcp_record_dsack"
cbmc_sack="--no-signed-overflow-check"
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
    "$top/sys/kern/uipc_sockbuf.c" "$top/sys/opencrypto/ktls_ocf.c" \
    "$top/sys/kern/uipc_socket.c" "$top/sys/kern/uipc_mbuf.c" \
    "$top/sys/vm/vnode_pager.c" "$top/sys/kern/uipc_syscalls.c" \
    "$top/sys/kern/kern_event.c" "$top/sys/kern/kern_descrip.c" \
    "$top/sys/kern/uipc_usrreq.c" "$top/sys/netinet/tcp_input.c" \
    "$top/sys/kern/kern_exec.c" "$top/sys/netinet/tcp_syncache.c" \
    "$top/sys/netinet/ip_options.c" "$top/sys/vm/vm_mmap.c" \
    "$top/sys/kern/kern_sysctl.c" "$top/sys/netinet/ip_output.c" \
    "$top/sys/netinet6/ip6_output.c"); do
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
if want sendfile; then
	# vnode_pager_generic_getpages(), sys/vm/vnode_pager.c, as
	# ffs_getpages_async() calls it for sendfile(2) on UFS: the pager the
	# sendfile proofs model.  Blocks of 4K and 8K, a run of up to 3 pages.
	h="$here/sendfile/pager.c"
	s="$top/sys/vm/vnode_pager.c"
	up="vm_object_prepare_buf_pages.0:3,vm_object_prepare_buf_pages.1:4"
	up="$up,vm_object_prepare_buf_pages.2:3,cbmc_iodone.0:4"
	up="$up,proof_getpages.0:5,proof_getpages.1:4,proof_getpages.2:4"
	up="$up,proof_getpages.3:5,proof_getpages.4:4"
	up="$up,vnode_pager_generic_getpages.4:4,vnode_pager_generic_getpages.5:4"
	up="$up,vnode_pager_generic_getpages.10:4,vnode_pager_generic_getpages.13:8"
	up="$up,vnode_pager_generic_getpages.18:8"
	up="$up,vnode_pager_generic_getpages_done.1:3"
	up="$up,vnode_pager_generic_getpages_done.2:3"
	up="$up,vnode_pager_generic_getpages_done.6:8"
	up="$up,vnode_pager_generic_getpages_done_async.0:8"
	for b in 4096 8192; do
		proof pager_ufs_$b "$h" "$s" proof_getpages \
		    "-DUFS -DBSIZE=$b" "$up"
	done
	# The asynchronous completion covers every requested page, exactly
	# once, on the no-I/O exits too (kib@: it must be called for all
	# pages).  A run ending on the file's last page valid up to its end
	# no longer trims that page for an async request, so the whole run
	# flows to one completion; and a hole or a file system without
	# VOP_BMAP() completes on the full run instead of skipping the
	# callback.  sendfile does not take these paths (it asks
	# vm_pager_has_page() first and UFS has VOP_BMAP()), so the mutants
	# are the regression check.
	proof pager_lastvalid "$h" "$s" proof_getpages \
	    "-DUFS -DBSIZE=4096 -DLASTVALID" "$up"
	proof pager_nobmap "$h" "$s" proof_getpages "-DBSIZE=4096" "$up"
	# A block smaller than a page takes the small-filesystem path.
	proof pager_smlfs "$h" "$s" proof_getpages "-DBSIZE=2048" "$up"
	# The trim that dropped the valid last page for async is gone ...
	mutant pager_lasttrim "$h" "$s" proof_getpages \
	    "-DUFS -DBSIZE=4096 -DLASTVALID" "$up" \
	    '/^vnode_pager_generic_getpages(/,/^}/s/if (!vm_page_none_valid(m\[count - 1\]) \&\& iodone == NULL \&\&/if (!vm_page_none_valid(m[count - 1]) \&\&/'
	# ... the no-VOP_BMAP input loop completes the run ...
	mutant pager_oldnodone "$h" "$s" proof_getpages "-DBSIZE=4096" "$up" \
	    '/if (error == EOPNOTSUPP) {/,/} else if (error != 0) {/s/if (error == 0 \&\& iodone != NULL)/if (0)/'
	# ... the small-filesystem loop completes the run ...
	mutant pager_smlnodone "$h" "$s" proof_getpages "-DBSIZE=2048" "$up" \
	    '/if (pagesperblock == 0) {/,/^	}/s/if (error == 0 \&\& iodone != NULL)/if (0)/'
	# ... the sparse-file hole completes the run.
	mutant pager_holenodone "$h" "$s" proof_getpages "-DBSIZE=4096" "$up" \
	    '/if (bp->b_blkno == -1) {/,/^	}/s/if (iodone != NULL)/if (0)/'
	d="-DUFS -DBSIZE=8192"
	# The completion runs once, on the run given ...
	mutant pager_pages "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages_done_async(/,/^}/s/bp->b_pgiodone(bp->b_caller1, bp->b_pages + bp->b_pgbefore,/bp->b_pgiodone(bp->b_caller1, bp->b_pages,/'
	mutant pager_count "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages_done_async(/,/^}/s/bp->b_npages - bp->b_pgbefore - bp->b_pgafter, error);/bp->b_npages - bp->b_pgbefore, error);/'
	# ... the pager buffer freed ...
	mutant pager_pbuf "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages_done_async(/,/^}/s/uma_zfree(vnode_pbuf_zone, bp);/;/'
	mutant pager_bmapfree "$h" "$s" proof_getpages "$d" "$up" \
	    '/} else if (error != 0) {/,/return (VM_PAGER_ERROR);/s/uma_zfree(vnode_pbuf_zone, bp);/;/'
	# ... read-behind and read-ahead pages freed on an error, queued
	# otherwise ...
	mutant pager_behind "$h" "$s" proof_getpages "$d" "$up" \
	    '/for (i = 0; i < bp->b_pgbefore; i++)/,/vm_page_free_invalid/s/vm_page_free_invalid(bp->b_pages\[i\]);/;/'
	mutant pager_finish "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages_done(/,/^}/s/vm_page_readahead_finish(mt);/;/'
	# ... the run valid up to the end of the file ...
	mutant pager_valid "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages_done(/,/^}/s/^			vm_page_valid(mt);/			;/'
	mutant pager_eof "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages_done(/,/^}/s/vm_page_set_valid_range(mt, 0,/if (0) vm_page_set_valid_range(mt, 0,/'
	# ... what was read around the run reported; the read asynchronous,
	# the file's bytes in whole sectors, from where the block map puts
	# them (the INVARIANTS offset checks catch offset and behindoff).
	mutant pager_report "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages(/,/^}/s/\*a_rahead = bp->b_pgafter;/*a_rahead = rahead + 1;/'
	mutant pager_async "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages(/,/^}/s/bp->b_flags |= B_ASYNC;/;/'
	mutant pager_sector "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages(/,/^}/s/bytecount = (bytecount + secmask) \& ~secmask;/;/'
	mutant pager_eofcut "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages(/,/^}/s/bytecount = object->un_pager.vnp.vnp_size - foff;/;/'
	mutant pager_offset "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages(/,/^}/s/bp->b_blkno += (foff % bsize) \/ DEV_BSIZE;/;/'
	mutant pager_behindoff "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages(/,/^}/s/bp->b_blkno -= IDX_TO_OFF(rbehind) \/ DEV_BSIZE;/;/'
	mutant pager_trim "$h" "$s" proof_getpages "$d" "$up" \
	    '/^vnode_pager_generic_getpages(/,/^}/s/rahead = min(rahead, after);/;/'
fi

if want accept; then
	# accept(2) and accept4(2), uipc_syscalls.c, against accept.2.
	h="$here/accept/accept.c"
	s="$top/sys/kern/uipc_syscalls.c"
	ua="soaccept.0:129,cbmc_memmove.0:137,check.0:129"
	proof accept "$h" "$s" proof_accept "" "$ua"
	proof accept4 "$h" "$s" proof_accept4 "" "$ua"
	# accept4: invalid flags refused, before the descriptor is looked up.
	mutant accept_flags "$h" "$s" proof_accept4 "" "$ua" \
	    's/if ((uap->flags \& ~(SOCK_CLOEXEC | SOCK_CLOFORK | SOCK_NONBLOCK)) != 0)/if ((uap->flags \& ~(SOCK_CLOEXEC | SOCK_CLOFORK | SOCK_NONBLOCK | SOCK_STREAM)) != 0)/'
	# EINVAL on a socket not listening, before a descriptor is allocated.
	mutant accept_listen "$h" "$s" proof_accept4 "" "$ua" \
	    '/fflag = atomic_load_int(\&headfp->f_flag);/,/error = EINVAL;/s/if (!SOLISTENING(head)) {/if (0) {/'
	# Close-on-exec and close-on-fork from the flags ...
	mutant accept_cloexec "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/((flags \& SOCK_CLOEXEC) != 0 ? O_CLOEXEC : 0) |/0 |/'
	mutant accept_clofork "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/((flags \& SOCK_CLOFORK) != 0 ? O_CLOFORK : 0), \&fcaps);/0, \&fcaps);/'
	# ... the new descriptor returned ...
	mutant accept_retval "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/td->td_retval\[0\] = fd;/;/'
	# ... accept: the signal destination inherited; accept4: cleared,
	# O_ASYNC cleared, O_NONBLOCK from the flags ...
	mutant accept_inherit "$h" "$s" proof_accept "" "$ua" \
	    '/^kern_accept4(/,/^}/s/fsetown(pgid, \&so->so_sigio);/;/'
	mutant accept_setown "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/if (flags \& ACCEPT4_INHERIT) {/if (1) {/'
	mutant accept_clear "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/fflag \&= ~(FNONBLOCK | FASYNC);/fflag \&= ~FNONBLOCK;/'
	mutant accept_nonblock "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/fflag |= FNONBLOCK;/;/'
	# ... the socket's state in step with its file ...
	mutant accept_nbio "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/tmp = fflag \& FNONBLOCK;/tmp = 0;/'
	mutant accept_async "$h" "$s" proof_accept "" "$ua" \
	    '/^kern_accept4(/,/^}/s/tmp = fflag \& FASYNC;/tmp = 0;/'
	# ... on an error, the new descriptor closed, and every reference and
	# capability let go ...
	mutant accept_close "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/fdclose(td, nfp, fd);/;/'
	mutant accept_caps "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/filecaps_free(\&fcaps);/;/'
	mutant accept_drop "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/fdrop(headfp, td);/;/'
	mutant accept_nfpdrop "$h" "$s" proof_accept4 "" "$ua" \
	    '/^kern_accept4(/,/^}/s/fdrop(nfp, td);/;/'
	# ... the address copied out to the room given, its own length
	# returned, the descriptor closed when that faults.
	mutant accept_addrlen "$h" "$s" proof_accept4 "" "$ua" \
	    '/^accept1(/,/^}/s/addrlen = min(ss.ss_len, addrlen);/addrlen = ss.ss_len;/'
	mutant accept_retlen "$h" "$s" proof_accept4 "" "$ua" \
	    '/^accept1(/,/^}/s/addrlen = ss.ss_len;/;/'
	mutant accept_efault "$h" "$s" proof_accept4 "" "$ua" \
	    '/^accept1(/,/^}/s/fdclose(td, fp, td->td_retval\[0\]);/;/'
fi

if want kevent; then
	# kevent(2), kern_event.c: the change and event lists, against
	# kqueue.2.  Up to 3 changes and 3 events, and 9 changes, two
	# batches of KQ_NEVENTS (about 5 minutes).
	h="$here/kevent/kevent.c"
	s="$top/sys/kern/kern_event.c"
	uk="proof_kevent.0:4,proof_kevent.1:4,kqueue_kevent.0:4"
	uk="$uk,kqueue_kevent.1:2,cbmc_memmove.0:193"
	uk9="proof_kevent.0:10,proof_kevent.1:10,kqueue_kevent.0:9"
	uk9="$uk9,kqueue_kevent.1:3,cbmc_memmove.0:513"
	proof kevent "$h" "$s" proof_kevent "" "$uk"
	proof kevent_9 "$h" "$s" proof_kevent "-DNC=9" "$uk9"
	# A negative nevents refused with EINVAL before any change.  The fix
	# taken back: a change that fails or has EV_RECEIPT is written as an
	# EV_ERROR event past the event list and counted.
	proof kevent_negevents "$h" "$s" proof_kevent "-DNEGEVENTS" "$uk"
	mutant kevent_negevents_late "$h" "$s" proof_kevent "-DNEGEVENTS" \
	    "$uk" '/^kqueue_kevent(/,/^}/s/if (nchanges < 0 || nevents < 0)/if (nchanges < 0)/'
	# A copyout of an EV_ERROR event that faults makes kevent() return
	# EFAULT (markj@ confirmed the drop was a bug; 459c6f697997).  The fix taken
	# back: the fault is ignored and the event counted.
	proof kevent_outfault "$h" "$s" proof_kevent "-DOUTFAULT" "$uk"
	mutant kevent_outfault_drop "$h" "$s" proof_kevent "-DOUTFAULT" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/error = k_ops->k_copyout(k_ops->arg, kevp, 1);/(void)k_ops->k_copyout(k_ops->arg, kevp, 1); error = 0;/'
	# Open question, kqueue.2 against the code: a change with filter 0 is
	# skipped, no EINVAL.
	question kevent_zerofilter "$h" "$s" proof_kevent "-DZEROFILTER" "$uk"
	# EINVAL for a negative change list; the system's flags cleared ...
	mutant kevent_negchanges "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/if (nchanges < 0 || nevents < 0)/if (nevents < 0)/'
	mutant kevent_sysflags "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/kevp->flags \&= ~EV_SYSFLAGS;/;/'
	# ... an error or EV_RECEIPT an EV_ERROR event where there is room, the
	# call failing with the error where not ...
	mutant kevent_noroom "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/if (nevents == 0)/if (0)/'
	mutant kevent_receipt "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/if (error || (kevp->flags \& EV_RECEIPT)) {/if (error) {/'
	mutant kevent_flags "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/kevp->flags = EV_ERROR;/kevp->flags |= EV_ERROR;/'
	mutant kevent_data "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/kevp->data = error;/;/'
	mutant kevent_dec "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/nevents--;/;/'
	# ... the EV_ERROR events counted, or the events read up to nevents
	# with the timeout given ...
	mutant kevent_nerrors "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/nerrors++;/;/'
	mutant kevent_retval "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/td->td_retval\[0\] = nerrors;/;/'
	mutant kevent_scanmax "$h" "$s" proof_kevent "" "$uk" \
	    '/^kqueue_kevent(/,/^}/s/return (kqueue_scan(kq, nevents, k_ops, timeout, keva, td));/return (kqueue_scan(kq, nevents + 1, k_ops, timeout, keva, td));/'
	# ... the change list read in batches of KQ_NEVENTS, in order ...
	mutant kevent_batch "$h" "$s" proof_kevent "-DNC=9" "$uk9" \
	    '/^kqueue_kevent(/,/^}/s/n = nchanges > KQ_NEVENTS ? KQ_NEVENTS : nchanges;/n = nchanges;/'
	mutant kevent_advance "$h" "$s" proof_kevent "-DNC=9" "$uk9" \
	    '/^kevent_copyin(/,/^}/s/uap->changelist += count;/;/'
	mutant kevent_outadvance "$h" "$s" proof_kevent "" "$uk" \
	    '/^kevent_copyout(/,/^}/s/uap->eventlist += count;/;/'
	# ... the kqueue and descriptor let go, the timeout read or EFAULT.
	mutant kevent_release "$h" "$s" proof_kevent "" "$uk" \
	    '/^kern_kevent_fp(/,/^}/s/kqueue_release(kq, 0);/;/'
	mutant kevent_fdrop "$h" "$s" proof_kevent "" "$uk" \
	    '/^kern_kevent(/,/^}/s/fdrop(fp, td);/;/'
	mutant kevent_timeout "$h" "$s" proof_kevent "" "$uk" \
	    '/^kern_kevent_generic(/,/^}/s/tsp = \&ts;/tsp = NULL;/'
	mutant kevent_tsfault "$h" "$s" proof_kevent "" "$uk" \
	    '/^kern_kevent_generic(/,/^}/s/if (error)$/if (0)/'
fi

if want close; then
	# close(2) and close_range(2), kern_descrip.c, against close.2 and
	# closefrom.2, on a table of 4 slots.  goto-cc cannot evaluate the
	# _Static_assert()s on constant arrays: they are compiled out.
	h="$here/close/close.c"
	s="$top/sys/kern/kern_descrip.c"
	dc='-D_Static_assert(a,b)='
	uc="close_range_impl.0:6,close_range_flags.0:6,flags_trans.0:3"
	uc="$uc,setup.4:5,setup.5:5,setup.6:5,setup.7:5,cbmc_filecaps_free.0:5"
	uc="$uc,proof_close.0:5,proof_close_range.0:5,proof_close_range.1:5"
	uc="$uc,proof_close_range.2:5,proof_close_range.3:5"
	uc="$uc,check_closed.0:5,check_closed.1:5,check_closed.2:5"
	proof close "$h" "$s" proof_close "$dc" "$uc"
	proof close_range "$h" "$s" proof_close_range "$dc" "$uc"
	# close: EBADF for no active descriptor; the slot, its map bit, its
	# capabilities freed, the free-slot hint kept ...
	mutant close_ebadf "$h" "$s" proof_close "$dc" "$uc" \
	    '/^kern_close(/,/^}/s/if ((fp = fget_noref(fdp, fd)) == NULL) {/if ((fp = fget_noref(fdp, fd)) == NULL \&\& fd < 0) {/'
	mutant close_free "$h" "$s" proof_close "$dc" "$uc" \
	    '/^kern_close(/,/^}/s/fdfree(fdp, fd);/;/'
	mutant close_slot "$h" "$s" proof_close "$dc" "$uc" \
	    '/^fdfree(/,/^}/s/fde->fde_file = NULL;/;/'
	mutant close_caps "$h" "$s" proof_close "$dc" "$uc" \
	    '/^fdefree_last(/,/^}/s/filecaps_free(\&fde->fde_caps);/;/'
	mutant close_map "$h" "$s" proof_close "$dc" "$uc" \
	    '/^fdunused(/,/^}/s/fdp->fd_map\[NDSLOT(fd)\] \&= ~NDBIT(fd);/;/'
	mutant close_freefile "$h" "$s" proof_close "$dc" "$uc" \
	    '/^fdunused(/,/^}/s/fdp->fd_freefile = fd;/;/'
	# ... its knotes and fo_fdclose(), the POSIX locks released, EINTR
	# for a restart, the table unlocked.
	mutant close_knote "$h" "$s" proof_close "$dc" "$uc" \
	    '/^closefp_impl(/,/^}/s/knote_fdclose(td, fd);/;/'
	mutant close_fdclose "$h" "$s" proof_close "$dc" "$uc" \
	    '/^closefp_impl(/,/^}/s/fp->f_ops->fo_fdclose(fp, fd, td);/;/'
	mutant close_restart "$h" "$s" proof_close "$dc" "$uc" \
	    '/^closefp_impl(/,/^}/s/error = EINTR;/;/'
	mutant close_advlock "$h" "$s" proof_close "$dc" "$uc" \
	    '/^closef(/,/^}/s/if ((td->td_proc->p_leader->p_flag \& P_ADVLOCK) != 0) {/if (0) {/'
	mutant close_unlock "$h" "$s" proof_close "$dc" "$uc" \
	    '/^closefp_impl(/,/^}/s/FILEDESC_XUNLOCK(fdp);/;/'
	# close_range: EINVAL for highfd below lowfd or a bad flag; every open
	# descriptor in the range, clamped to the table, closed ...
	mutant close_order "$h" "$s" proof_close_range "$dc" "$uc" \
	    '/^kern_close_range(/,/^}/s/if (highfd < lowfd) {/if (highfd < lowfd \&\& lowfd != highfd + 1) {/'
	mutant close_rflags "$h" "$s" proof_close_range "$dc" "$uc" \
	    '/^sys_close_range(/,/^}/s/if ((uap->flags \& ~(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_CLOFORK)) != 0)/if (0)/'
	mutant close_clamp "$h" "$s" proof_close_range "$dc" "$uc" \
	    '/^close_range_impl(/,/^}/s/highfd = MIN(highfd, fdt->fdt_nfiles - 1);/highfd = MIN(highfd, fdt->fdt_nfiles);/'
	mutant close_skip "$h" "$s" proof_close_range "$dc" "$uc" \
	    '/^close_range_impl(/,/^}/s/fdfree(fdp, fd);/;/'
	# ... or flagged close-on-exec or close-on-fork, the open ones in the
	# range only.
	mutant close_setflags "$h" "$s" proof_close_range "$dc" "$uc" \
	    '/^close_range_flags(/,/^}/s/fde->fde_flags |= fde_flags;/fde->fde_flags = fde_flags;/'
	mutant close_setopen "$h" "$s" proof_close_range "$dc" "$uc" \
	    '/^close_range_flags(/,/^}/s/if (fde->fde_file != NULL)/if (1)/'
	mutant close_setclamp "$h" "$s" proof_close_range "$dc" "$uc" \
	    '/^close_range_flags(/,/^}/s/for (; fd <= highfd; fd++) {/for (; fd < highfd; fd++) {/'
fi

if want unp; then
	# The SCM_RIGHTS control messages of Unix sockets, uipc_usrreq.c,
	# against unix.4: unp_internalize() and unp_externalize(), the file
	# references modelled.  Messages of 0, 1 and 2 descriptors; the
	# round-trip reference count is sound.  (NFDS=3 internalize proves at
	# ~40G: the sbcreatecontrol/filecaps round-trip; left to the 0..2
	# cases, which bite every mutant.)  goto-cc cannot evaluate the
	# _Static_assert()s on constant arrays: they are compiled out.
	h="$here/unp/unp.c"
	s="$top/sys/kern/uipc_usrreq.c"
	di='-D_Static_assert(a,b)='
	ui="unp_internalize.0:4,unp_internalize.1:4,unp_internalize.2:4"
	ui="$ui,unp_internalize.3:4,unp_internalize.4:4,unp_internalize.5:4"
	ui="$ui,unp_internalize.6:2,unp_internalize_cleanup_rights.0:4"
	ui="$ui,build_control.0:4,proof_internalize.0:4,proof_internalize.1:4"
	ui="$ui,proof_internalize.2:4,fdallocn.0:4,check_balance.0:4"
	ui="$ui,check_balance.1:4,check_balance.2:4,setup.0:4,setup.1:4"
	ui="$ui,setup.2:4,cbmc_memmove.0:33,unp_freerights.0:4,unp_freerights.1:4"
	ux="unp_externalize.0:4,unp_externalize.1:4,unp_externalize.2:2"
	ux="$ux,fdallocn.0:4,setup.0:4,setup.1:4,setup.2:4,proof_externalize.0:4"
	ux="$ux,proof_externalize.1:4,proof_externalize.2:4,proof_externalize.3:4"
	ux="$ux,check_balance.0:4,check_balance.1:4,check_balance.2:4"
	ux="$ux,cbmc_memmove.0:33,unp_freerights.0:4,unp_freerights.1:4"
	for n in 0 1 2; do
		proof unp_internalize_$n "$h" "$s" proof_internalize \
		    "$di -DNFDS=$n" "$ui"
	done
	for n in 0 1 2 3; do
		proof unp_externalize_$n "$h" "$s" proof_externalize \
		    "$di -DNFDS=$n" "$ux"
	done
	# A non-passable or missing descriptor is rejected, every reference
	# held rolled back; each file held is internalized once.
	mutant unp_int_passable "$h" "$s" proof_internalize "$di -DNFDS=2" "$ui" \
	    '/^unp_internalize(/,/^}/s/if (!(fp->f_ops->fo_flags \& DFLAG_PASSABLE)) {/if (0) {/'
	mutant unp_int_hold "$h" "$s" proof_internalize "$di -DNFDS=2" "$ui" \
	    '/^unp_internalize(/,/^}/s/if (!fhold(fdesc->fd_ofiles\[\*fdp\].fde_file)) {/if (0) {/'
	mutant unp_int_intfp "$h" "$s" proof_internalize "$di -DNFDS=2" "$ui" \
	    '/^unp_internalize(/,/^}/s/unp_internalize_fp(fdep\[i\]->fde_file);/;/'
	mutant unp_int_cleanup "$h" "$s" proof_internalize "$di -DNFDS=2" "$ui" \
	    's/unp_internalize_cleanup_rights(mc_first(mc));/;/'
	# Each file installed (its reference handed to the table) or discarded
	# once; the message keeps none; the fdep array is freed.
	mutant unp_ext_pass "$h" "$s" proof_externalize "$di -DNFDS=2" "$ux" \
	    '/^unp_externalize(/,/^}/s/SO_PASSRIGHTS) == 0) {/SO_PASSRIGHTS) == 1) {/'
	mutant unp_ext_finstall "$h" "$s" proof_externalize "$di -DNFDS=2" "$ux" \
	    '/^unp_externalize(/,/^}/s/_finstall(fdesc, fp, \*fdp,/if (0) _finstall(fdesc, fp, *fdp,/'
	mutant unp_ext_extfp "$h" "$s" proof_externalize "$di -DNFDS=2" "$ux" \
	    '/^unp_externalize(/,/^}/s/unp_externalize_fp(fp);/;/'
	mutant unp_ext_freearray "$h" "$s" proof_externalize "$di -DNFDS=2" "$ux" \
	    '/^unp_externalize(/,/^}/s/free(fdep\[0\], M_FILECAPS);/;/'
fi

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

if want tcp; then
	# tcp_dooptions(), sys/netinet/tcp_input.c, against RFC 9293 3.1,
	# RFC 7323 and RFC 2018: the parser of a segment's options, driven
	# off the wire by any peer.  cnt (the option bytes) is a constant per
	# job, as a symbolic 0..40 stream ran past 40 minutes; 2, 4, 10 and
	# 18 bytes exercise every option, the 18-byte SIGNATURE and a
	# two-block SACK included (cnt=20 proves too, at ~5 minutes).
	# TCP_RFC7413 enables the TFO path.
	h="$here/tcp/tcp.c"
	s="$top/sys/netinet/tcp_input.c"
	dt="-DINET -DINET6 -DTCP_RFC7413"
	ut="tcp_dooptions.0:4,tcp_dooptions.1:21,proof_dooptions.0:41"
	ut="$ut,cbmc_memmove.0:11"
	for c in 2 4 10 18; do
		proof tcp_dooptions_$c "$h" "$s" proof_dooptions \
		    "$dt -DCNT=$c" "$ut"
	done
	# EOL ends the options; the option-length bounds hold ...
	mutant tcp_eol "$h" "$s" proof_dooptions "$dt -DCNT=18" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/if (opt == TCPOPT_EOL)/if (0 \&\& opt == TCPOPT_EOL)/'
	mutant tcp_optmin "$h" "$s" proof_dooptions "$dt -DCNT=10" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/if (optlen < 2 || optlen > cnt)/if (optlen > cnt)/'
	mutant tcp_optmax "$h" "$s" proof_dooptions "$dt -DCNT=18" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/if (optlen < 2 || optlen > cnt)/if (optlen < 2)/'
	# ... each option accepted only at its exact length, and its value is
	# the option bytes (MSS network order, window scale min 14, SACK count,
	# TFO cookie length) ...
	mutant tcp_msslen "$h" "$s" proof_dooptions "$dt -DCNT=18" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/if (optlen != TCPOLEN_MAXSEG)/if (0)/'
	mutant tcp_wscale "$h" "$s" proof_dooptions "$dt -DCNT=18" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/to->to_wscale = min(cp\[2\], TCP_MAX_WINSHIFT);/to->to_wscale = cp[2];/'
	mutant tcp_siglen "$h" "$s" proof_dooptions "$dt -DCNT=18" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/if (optlen != TCPOLEN_SIGNATURE)/if (0)/'
	mutant tcp_sackmod "$h" "$s" proof_dooptions "$dt -DCNT=18" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/if (optlen <= 2 || (optlen - 2) % TCPOLEN_SACK != 0)/if (optlen <= 2)/'
	mutant tcp_sackle2 "$h" "$s" proof_dooptions "$dt -DCNT=18" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/if (optlen <= 2 || (optlen - 2) % TCPOLEN_SACK != 0)/if ((optlen - 2) % TCPOLEN_SACK != 0)/'
	mutant tcp_tfolen "$h" "$s" proof_dooptions "$dt -DCNT=18" "$ut" \
	    '/^tcp_dooptions(/,/^}/s/to->to_tfo_len = optlen - 2;/to->to_tfo_len = optlen;/'
	# nsacks ((optlen-2)/8 vs optlen/8) is an equivalent mutant: a valid
	# SACK option has optlen = 2 + 8k, so both are k.  cnt2 (dropping the
	# "cnt < 2" guard, a one-byte over-read at the buffer's end) the
	# harness cannot catch: its option array is a fixed OPTMAX, so a read
	# at cp[cnt] stays in bounds; the kernel buffer is the segment's.
	# tcp_sack_doack(), sys/netinet/tcp_sack.c, against RFC 2018: the peer
	# SACK blocks parsed into the retransmission scoreboard.  The sequence
	# space is concrete per job (GEO), as the symbolic scoreboard sweep
	# ran out of memory (>50G); GEO 0 is a pure cumulative ack, GEO 2 a
	# peer block trimming a hole's front, each with its delivered /
	# hole_bytes / sacked_bytes accounting checked.  The other geometries
	# (whole-hole removal, back trim, split, tail insert) make the sweep
	# walk more holes than this host can hold and are left out; the SACK
	# block-count overflow (CVE-2019-11477 class) is bounded separately by
	# the tcp_dooptions proof (to_nsacks <= 4).
	hk="$here/tcp/sack.c"
	sk="$top/sys/netinet/tcp_sack.c"
	us="build_scoreboard.0:2,build_scoreboard.1:2,build_scoreboard.2:2"
	us="$us,build_scoreboard.3:2,tcp_sack_doack.0:3,tcp_sack_doack.1:3"
	us="$us,tcp_sack_doack.2:3,tcp_sack_doack.3:3,tcp_sack_doack.4:4"
	us="$us,tcp_sack_doack.5:4,tcp_sack_doack.6:4,tcp_sack_doack.7:4"
	us="$us,tcp_sack_doack.8:4,tcp_sack_doack.9:4,tcp_sack_doack.10:4"
	us="$us,tcp_sack_doack.11:4,cbmc_memmove.0:9"
	proof sack_doack_0 "$hk" "$sk" proof_sack_doack "-DINET -DINET6 -DGEO=0" "$us"
	proof sack_doack_2 "$hk" "$sk" proof_sack_doack "-DINET -DINET6 -DGEO=2" "$us"
	# The front-trim accounting: delivered data and hole_bytes, and the
	# hole's new start.  (The end>start acceptance check is equivalent for
	# a well-formed block, so it is no mutant.)
	mutant sack_delivered "$hk" "$sk" proof_sack_doack "-DINET -DINET6 -DGEO=2" \
	    "$us" '/^tcp_sack_doack(/,/^}/s/delivered_data += (sblkp->end - cur->start);/delivered_data += (sblkp->end - cur->start) + 1;/'
	mutant sack_holebytes "$hk" "$sk" proof_sack_doack "-DINET -DINET6 -DGEO=2" \
	    "$us" '/^tcp_sack_doack(/,/^}/s/tp->sackhint.hole_bytes -= sblkp->end - cur->start;/;/'
	mutant sack_movestart "$hk" "$sk" proof_sack_doack "-DINET -DINET6 -DGEO=2" \
	    "$us" '/^tcp_sack_doack(/,/^}/s/cur->start = sblkp->end;/cur->start = sblkp->start;/'

	# tcp_update_sack_list(), same file: the receiver's SACK-block list
	# maintenance.  A received range is merged into the ordered sackblks[]
	# list, capped at MAX_SACK_BLKS.  The array bound is the security
	# property (the receiver-side SACK-overflow class): rcv_numsacks never
	# exceeds MAX_SACK_BLKS and no sackblks[] write runs past the array.
	# The starting list and the received range are nondeterministic.
	hl="$here/tcp/sack_list.c"
	ul="tcp_update_sack_list.0:7,tcp_update_sack_list.1:7,proof_sack_list.0:7"
	ul="$ul,cbmc_memmove.0:49"
	proof sack_list "$hl" "$sk" proof_sack_list "-DINET -DINET6" "$ul"
	# The MAX_SACK_BLKS cap on the saved blocks is load-bearing: dropping it
	# lets the copy-back write past sackblks[] (and, before the fix, a
	# zero-length range did exactly that -- see reports/tcp.md).
	mutant sack_list_cap "$hl" "$sk" proof_sack_list "-DINET -DINET6" "$ul" \
	    '/^tcp_update_sack_list(/,/^}/s/if (num_head + num_saved > MAX_SACK_BLKS)/if (0)/'

	# tcp_update_dsack_list(), same file: the receiver's DSACK-block list
	# maintenance, companion to tcp_update_sack_list().  Same sackblks[]
	# array bound (the receiver-side SACK-overflow class): rcv_numsacks never
	# exceeds MAX_SACK_BLKS and no sackblks[] write runs past the array.  The
	# starting list and DSACK range are nondeterministic.  (Unlike its
	# sibling this caps inside the loop condition, so it holds for all
	# inputs.)
	hd="$here/tcp/dsack_list.c"
	ud="tcp_update_dsack_list.0:7,tcp_update_dsack_list.1:7"
	ud="$ud,tcp_update_dsack_list.2:7,tcp_update_dsack_list.3:7"
	ud="$ud,proof_dsack_list.0:7,cbmc_memmove.0:49"
	proof dsack_list "$hd" "$sk" proof_dsack_list "-DINET -DINET6" "$ud"
	# The loop-condition cap n < MAX_SACK_BLKS is load-bearing: dropping it
	# lets the saved-block append write past saved_blks[].
	mutant dsack_list_cap "$hd" "$sk" proof_dsack_list "-DINET -DINET6" "$ud" \
	    '/^tcp_update_dsack_list(/,/^}/s/(j < tp->rcv_numsacks) \&\& (n < MAX_SACK_BLKS)/(j < tp->rcv_numsacks)/'

	# tcp_addoptions(), sys/netinet/tcp_output.c: the TCP option writer, the
	# complement to tcp_dooptions().  It assembles the requested options into
	# the fixed TCP_MAXOLEN-byte option area, NOP-padding for alignment.
	# Every write stays within the area; the per-option room checks and the
	# SACK-block clamp are the guard.  The area is a CBMC object of exactly
	# TCP_MAXOLEN bytes, so a write past it is an out-of-bounds write.  The
	# option set and the attacker-influenced counts are nondeterministic.
	ho="$here/tcp/addoptions.c"
	so="$top/sys/netinet/tcp_output.c"
	do="-DINET -DINET6 -DTCPSTAT_ADD(n,v)= -DTCPSTAT_INC(n)= "
	oo="tcp_addoptions.0:20,tcp_addoptions.1:20,tcp_addoptions.2:20"
	oo="$oo,tcp_addoptions.3:20,tcp_addoptions.4:20,tcp_addoptions.5:20"
	oo="$oo,tcp_addoptions.6:20,tcp_addoptions.7:20,tcp_addoptions.8:20"
	oo="$oo,tcp_addoptions.9:20,tcp_addoptions.10:20,tcp_addoptions.11:20"
	oo="$oo,tcp_addoptions.12:20,tcp_addoptions.13:20,cbmc_memmove.0:17"
	proof tcp_addoptions "$ho" "$so" proof_addoptions "$do" "$oo"
	# The SACK-block count clamp to the remaining room is load-bearing:
	# without it, to_nsacks blocks are written past the option area.  Rewrite
	# min(to_nsacks, room) to take to_nsacks unclamped (0 * the room term).
	mutant addopt_sackclamp "$ho" "$so" proof_addoptions "$do" "$oo" \
	    '/case TOF_SACK:/,/case TOF_FASTOPEN:/s/sackblks = min(to->to_nsacks,/sackblks = (to->to_nsacks) + 0 * (/'
fi

if want read; then
	# copyinuio(), sys/kern/subr_uio.c: the iovec copy-in of readv(2),
	# writev(2), preadv(2), pwritev(2) against readv(2).  Up to NIOV
	# iovecs of any length: iovcnt past UIO_MAXIOV refused, each length
	# checked so the running total never passes IOSIZE_MAX, a fault
	# propagated with no uio; else a uio whose resid is the exact sum.
	h="$here/read/read.c"
	s="$top/sys/kern/subr_uio.c"
	ur="copyinuio.0:5,proof_copyinuio.0:5,proof_copyinuio.1:5,cbmc_memmove.0:65"
	proof copyinuio "$h" "$s" proof_copyinuio "" "$ur"
	# Each length checked against the running total so it cannot overflow
	# IOSIZE_MAX; the total is the exact sum; the iovcnt is recorded.
	# (The UIO_MAXIOV cap and the fault-path free are not covered: iovcnt
	# > 1024 exceeds the modelled iovec array, and the single M_IOV
	# allocation's free is not observable in the malloc model.)
	mutant copyinuio_overflow "$h" "$s" proof_copyinuio "" "$ur" \
	    '/^copyinuio(/,/^}/s/if (iov->iov_len > IOSIZE_MAX - uio->uio_resid) {/if (0) {/'
	mutant copyinuio_overflow2 "$h" "$s" proof_copyinuio "" "$ur" \
	    '/^copyinuio(/,/^}/s/if (iov->iov_len > IOSIZE_MAX - uio->uio_resid) {/if (iov->iov_len > IOSIZE_MAX) {/'
	mutant copyinuio_resid "$h" "$s" proof_copyinuio "" "$ur" \
	    '/^copyinuio(/,/^}/s/uio->uio_resid += iov->iov_len;/uio->uio_resid += iov->iov_len + 1;/'
	mutant copyinuio_iovcnt "$h" "$s" proof_copyinuio "" "$ur" \
	    '/^copyinuio(/,/^}/s/uio->uio_iovcnt = iovcnt;/uio->uio_iovcnt = iovcnt + 1;/'

	# copyiniov(), same file: copy a user iovec array into a fresh kernel
	# array, behind readv(2)/writev(2) and sendmsg/recvmsg.  iovcnt is capped
	# at UIO_MAXIOV so iovcnt * sizeof(struct iovec) cannot overflow; the
	# copyin then fills a buffer of exactly that size, freed on a fault.
	# iovcnt is a constant per job (the copyin is a byte loop): the jobs
	# sweep an empty array, a small one, the cap, and one past it.
	hv="$here/read/copyiniov.c"
	for n in 0 2 1024 1025; do
		proof copyiniov_$n "$hv" "$s" proof_copyiniov "-DIOVCNT=$n" \
		    "copyiniov.0:2"
	done
	# The UIO_MAXIOV cap is load-bearing: dropping it lets iovcnt * sizeof
	# overflow, undersizing the array the copyin then overruns.
	mutant copyiniov_cap "$hv" "$s" proof_copyiniov "-DIOVCNT=1025" \
	    "copyiniov.0:2" \
	    '/^copyiniov(/,/^}/s/if (iovcnt > UIO_MAXIOV)/if (0)/'

	# uiomove() (through uiomove_faultflag()), same file: the kernel's copy
	# of n bytes between a kernel buffer and a user iovec list, behind
	# read(2), write(2) and most device and socket I/O.  Each step copies
	# min(iov_len, remaining n) bytes, advancing the kernel pointer and
	# shrinking n; every copy stays within the n-byte kernel buffer and the
	# iovec.  The kernel buffer is an N-byte object, each iovec its own
	# object; the user path drives the modelled copyin/copyout.  GEO: an
	# exact fit, a second iovec clamped by the count, a skipped empty iovec,
	# and an iovec larger than N (the count clamp).
	hu="$here/read/uiomove.c"
	uu="uiomove_faultflag.5:5,proof_uiomove.0:4,proof_uiomove.1:4"
	for g in 0 1 2 3; do
		proof uiomove_geo$g "$hu" "$s" proof_uiomove "-DGEO=$g" "$uu"
	done
	# The per-step count is clamped to the remaining n (the kernel buffer):
	# dropping the clamp copies the whole iovec, overrunning the N-byte
	# kernel buffer.  GEO 3's iovec (20) is larger than N (8), so the
	# uncapped copy runs past the kernel buffer.
	mutant uiomove_clamp "$hu" "$s" proof_uiomove "-DGEO=3" "$uu" \
	    '/^uiomove_faultflag(/,/^}/s/if (cnt > n)/if (0)/'
	# The kernel pointer and n advance by the bytes moved: dropping the n
	# decrement loops without draining the count, re-copying from cp past
	# the kernel buffer.
	mutant uiomove_advance "$hu" "$s" proof_uiomove "-DGEO=1" "$uu" \
	    '/cp = (char \*)cp + cnt;/{n;s/^\t\tn -= cnt;/;/;}'
fi

if want sockargs; then
	# sockargs(), sys/kern/uipc_syscalls.c: the copy-in of a socket name
	# or control buffer into an mbuf, for sendto(2), sendmsg(2), bind(2),
	# connect(2) and kin.  A buflen past MCLBYTES refused with EMSGSIZE
	# and no mbuf; a faulting copyin reported with the mbuf freed; else
	# an mbuf of m_len == buflen, buflen bytes copied into a data area
	# that holds them, and for a name an sa_len of buflen.
	# buflen is a constant per job: the copyin is a byte loop, and a
	# symbolic length runs out of memory.  The boundaries are swept as CPP
	# expressions (MLEN is a struct offset, not a plain number): an MLEN
	# mbuf (0, MLEN), an MCLBYTES cluster (MLEN+1, MCLBYTES), and a length
	# past the cap (MCLBYTES+1).  The copyin loop unwinds to MCLBYTES+1.
	h="$here/sockargs/sockargs.c"
	s="$top/sys/kern/uipc_syscalls.c"
	u="sockargs.0:2050,cbmc_memmove.0:2050"
	proof sockargs_empty "$h" "$s" proof_sockargs \
	    "-DINET -DINET6 -DLEN=0" "$u"
	proof sockargs_mbuf "$h" "$s" proof_sockargs \
	    "-DINET -DINET6 -DLEN=MLEN" "$u"
	proof sockargs_clmin "$h" "$s" proof_sockargs \
	    "-DINET -DINET6 -DLEN=(MLEN+1)" "$u"
	proof sockargs_clmax "$h" "$s" proof_sockargs \
	    "-DINET -DINET6 -DLEN=MCLBYTES" "$u"
	proof sockargs_over "$h" "$s" proof_sockargs \
	    "-DINET -DINET6 -DLEN=(MCLBYTES+1)" "$u"
	d="-DINET -DINET6 -DLEN=MCLBYTES"
	# The data area holds exactly what is copied in (m_len == buflen) ...
	mutant sockargs_mlen "$h" "$s" proof_sockargs "$d" "$u" \
	    '/^sockargs(/,/^}/s/m->m_len = buflen;/m->m_len = buflen + 1;/'
	# ... a length past the cap is refused ...
	mutant sockargs_cap "$h" "$s" proof_sockargs \
	    "-DINET -DINET6 -DLEN=(MCLBYTES+1)" "$u" \
	    '/^sockargs(/,/^}/s/if (buflen > MCLBYTES)/if (0)/'
	# ... a name's sa_len is the length copied in.
	mutant sockargs_salen "$h" "$s" proof_sockargs "$d" "$u" \
	    '/^sockargs(/,/^}/s/sa->sa_len = buflen;/sa->sa_len = buflen + 1;/'

	# getsockaddr(), same file: the copy-in of a socket address for
	# bind(2), connect(2), sendto(2), sendmsg(2).  A len past
	# SOCK_MAXADDRLEN refused with ENAMETOOLONG, below the header with
	# EINVAL, a faulting copyin with the buffer freed; else a name of
	# sa_len == len.  len is a constant per job; the jobs sweep below the
	# header (1), the header (2), the cap (SOCK_MAXADDRLEN) and one past.
	h="$here/sockargs/getsockaddr.c"
	g="getsockaddr.0:256,cbmc_memmove.0:256"
	proof getsockaddr_small "$h" "$s" proof_getsockaddr \
	    "-DINET -DINET6 -DLEN=1" "$g"
	proof getsockaddr_header "$h" "$s" proof_getsockaddr \
	    "-DINET -DINET6 -DLEN=2" "$g"
	proof getsockaddr_max "$h" "$s" proof_getsockaddr \
	    "-DINET -DINET6 -DLEN=SOCK_MAXADDRLEN" "$g"
	proof getsockaddr_over "$h" "$s" proof_getsockaddr \
	    "-DINET -DINET6 -DLEN=(SOCK_MAXADDRLEN+1)" "$g"
	dg="-DINET -DINET6 -DLEN=SOCK_MAXADDRLEN"
	# A length past the cap is refused ...
	mutant getsockaddr_cap "$h" "$s" proof_getsockaddr \
	    "-DINET -DINET6 -DLEN=(SOCK_MAXADDRLEN+1)" "$g" \
	    '/^getsockaddr(/,/^}/s/if (len > SOCK_MAXADDRLEN)/if (0)/'
	# ... a length below the header is refused ...
	mutant getsockaddr_hdr "$h" "$s" proof_getsockaddr \
	    "-DINET -DINET6 -DLEN=1" "$g" \
	    '/^getsockaddr(/,/^}/s/if (len < offsetof(struct sockaddr, sa_data\[0\]))/if (0)/'
	# ... the name's sa_len is the length copied in.
	mutant getsockaddr_salen "$h" "$s" proof_getsockaddr "$dg" "$g" \
	    '/^getsockaddr(/,/^}/s/sa->sa_len = len;/sa->sa_len = len + 1;/'
fi

if want setsockopt; then
	# sooptcopyin(), sys/kern/uipc_socket.c: the copy-in of a socket
	# option value, for setsockopt(2) through sosetopt() and every
	# protocol pr_ctloutput().  The user controls sopt_valsize: below the
	# caller's minlen it is refused with EINVAL, above the caller's buffer
	# it is clamped, and the copy is only ever min(valsize, len) bytes
	# into a len-byte buffer, never past it.  valsize is a constant per
	# job (the copy is a byte loop); the jobs sweep an empty value, one
	# short of the buffer, the buffer, and one past it, against a caller
	# buffer of LEN=8 and a symbolic minlen in [0, LEN].
	h="$here/setsockopt/sooptcopyin.c"
	s="$top/sys/kern/uipc_socket.c"
	ds="-DINET -DINET6 -DLEN=8"
	so="sooptcopyin.0:9,_sooptcopyin.0:9,cbmc_memmove.0:9"
	proof sooptcopyin_empty "$h" "$s" proof_sooptcopyin "$ds -DVALSIZE=0" "$so"
	proof sooptcopyin_short "$h" "$s" proof_sooptcopyin "$ds -DVALSIZE=4" "$so"
	proof sooptcopyin_full "$h" "$s" proof_sooptcopyin "$ds -DVALSIZE=8" "$so"
	proof sooptcopyin_over "$h" "$s" proof_sooptcopyin "$ds -DVALSIZE=12" "$so"
	# A value below the minimum is refused ...
	mutant sooptcopyin_min "$h" "$s" proof_sooptcopyin "$ds -DVALSIZE=4" "$so" \
	    '/^_sooptcopyin(/,/^}/s/if ((valsize = sopt->sopt_valsize) < minlen)/if ((valsize = sopt->sopt_valsize), 0)/'
	# ... an over-long value is clamped to the buffer (no copy past it) ...
	mutant sooptcopyin_clamp "$h" "$s" proof_sooptcopyin "$ds -DVALSIZE=12" "$so" \
	    '/^_sooptcopyin(/,/^}/s/sopt->sopt_valsize = valsize = len;/sopt->sopt_valsize = valsize;/'
	# ... the retrieved length is reported in sopt_valsize.
	mutant sooptcopyin_report "$h" "$s" proof_sooptcopyin "$ds -DVALSIZE=12" "$so" \
	    '/^_sooptcopyin(/,/^}/s/sopt->sopt_valsize = valsize = len;/valsize = len;/'

	# sooptcopyout(), same file: the copy-out of a socket option value for
	# getsockopt(2) through sogetopt() and every protocol pr_ctloutput().
	# The copy is only ever min(len, sopt_valsize) bytes, read from the
	# kernel buffer of len bytes, never past it (which would leak adjacent
	# kernel memory); sopt_valsize is set to what was copied.  The kernel
	# buffer is sized to len, so an over-read is caught.  sopt_valsize is a
	# constant per job; the jobs sweep an empty user buffer, one short, the
	# buffer, and larger (the clamp).  LEN is the kernel buffer, 8 bytes.
	h="$here/setsockopt/sooptcopyout.c"
	do="-DINET -DINET6 -DLEN=8"
	oo="sooptcopyout.0:9,cbmc_memmove.0:9"
	proof sooptcopyout_empty "$h" "$s" proof_sooptcopyout "$do -DVALSIZE=0" "$oo"
	proof sooptcopyout_short "$h" "$s" proof_sooptcopyout "$do -DVALSIZE=4" "$oo"
	proof sooptcopyout_full "$h" "$s" proof_sooptcopyout "$do -DVALSIZE=8" "$oo"
	proof sooptcopyout_over "$h" "$s" proof_sooptcopyout "$do -DVALSIZE=12" "$oo"
	# The copy is clamped to the kernel buffer (no read past it) ...
	mutant sooptcopyout_clamp "$h" "$s" proof_sooptcopyout "$do -DVALSIZE=12" "$oo" \
	    '/^sooptcopyout(/,/^}/s/valsize = min(len, sopt->sopt_valsize);/valsize = sopt->sopt_valsize;/'
	# ... and the copied length reported in sopt_valsize.
	mutant sooptcopyout_report "$h" "$s" proof_sooptcopyout "$do -DVALSIZE=12" "$oo" \
	    '/^sooptcopyout(/,/^}/s/sopt->sopt_valsize = valsize;/;/'

	# soopt_mcopyin()/soopt_mcopyout(), same file: the copy of a socket
	# option value between the user buffer (sopt_val, sopt_valsize bytes)
	# and an mbuf chain, on the IPv6 pr_ctloutput path.  Each mbuf is copied
	# in full while sopt_valsize >= m_len; sopt_val advances by m_len and
	# sopt_valsize shrinks by it, so no copy runs past the user buffer or any
	# mbuf.  The user buffer is a VALSIZE-byte CBMC object and each mbuf a
	# separate object; the chain is a concrete geometry per job, VALSIZE sized
	# to cover it (as ip6's soopt_getm() allocates).  GEO sweeps one mbuf, a
	# two-mbuf chain, a chain with an empty mbuf, and an MLEN-full mbuf.
	h="$here/setsockopt/sooptmcopy.c"
	mi="soopt_mcopyin.0:5,build_chain.0:4,build_chain.1:4"
	mo="soopt_mcopyout.0:5,build_chain.0:4,build_chain.1:4"
	proof mcopyin_one   "$h" "$s" proof_mcopyin  "$do -DGEO=0 -DVALSIZE=8"       "$mi"
	proof mcopyin_two   "$h" "$s" proof_mcopyin  "$do -DGEO=1 -DVALSIZE=14"      "$mi"
	proof mcopyin_empty "$h" "$s" proof_mcopyin  "$do -DGEO=2 -DVALSIZE=14"      "$mi"
	proof mcopyin_full  "$h" "$s" proof_mcopyin  "$do -DGEO=3 -DVALSIZE=(MLEN+4)" "$mi"
	proof mcopyout_one   "$h" "$s" proof_mcopyout "$do -DGEO=0 -DVALSIZE=8"       "$mo"
	proof mcopyout_two   "$h" "$s" proof_mcopyout "$do -DGEO=1 -DVALSIZE=14"      "$mo"
	proof mcopyout_short "$h" "$s" proof_mcopyout "$do -DGEO=1 -DVALSIZE=10"      "$mo"
	proof mcopyout_full  "$h" "$s" proof_mcopyout "$do -DGEO=3 -DVALSIZE=(MLEN+4)" "$mo"
	# Drop the room check: a copy then runs past the user buffer (caught by
	# touch_user / the VALSIZE object) once sopt_valsize is exhausted.
	mutant mcopyin_guard "$h" "$s" proof_mcopyin "$do -DGEO=1 -DVALSIZE=10" "$mi" \
	    '/^soopt_mcopyin(/,/^}/s/sopt->sopt_valsize >= m->m_len/1/'
	mutant mcopyout_guard "$h" "$s" proof_mcopyout "$do -DGEO=1 -DVALSIZE=10" "$mo" \
	    '/^soopt_mcopyout(/,/^}/s/sopt->sopt_valsize >= m->m_len/1/'
	# Drop the advance: the user pointer stays put, so the reported total is
	# wrong (mcopyout) and a later copy rereads the same bytes.
	mutant mcopyout_advance "$h" "$s" proof_mcopyout "$do -DGEO=1 -DVALSIZE=14" "$mo" \
	    '/^soopt_mcopyout(/,/^}/s/valsize += m->m_len;/;/'
fi

if want exec; then
	# The argument-string accounting of execve(2), sys/kern/kern_exec.c:
	# exec_args_add_fname() lays the filename, then each add_arg()/_env()
	# copies one user string against the running stringspace budget and
	# advances endp.  The budget never underflows and endp never runs past
	# the buffer; a string that does not fit is E2BIG.  NADD successive
	# appends are proven; the string buffer is sized to the real
	# PATH_MAX + ARG_MAX, so an overrun is an out-of-bounds write.
	h="$here/exec/exec_args.c"
	s="$top/sys/kern/kern_exec.c"
	db="-DBUDGET=6"
	ue="proof_exec_args.0:5"
	for n in 1 2 3; do
		proof exec_args_$n "$h" "$s" proof_exec_args "$db -DNADD=$n" "$ue"
	done
	# The budget is charged for each string copied ...
	mutant exec_args_charge "$h" "$s" proof_exec_args "$db -DNADD=2" "$ue" \
	    '/^exec_args_add_str(/,/^}/s/args->stringspace -= length;/;/'
	# ... and the end pointer advanced, so endp tracks the budget ...
	mutant exec_args_endp "$h" "$s" proof_exec_args "$db -DNADD=2" "$ue" \
	    '/^exec_args_add_str(/,/^}/s/args->endp += length;/;/'
	# ... a copy too long for the budget is E2BIG, not a different error.
	mutant exec_args_e2big "$h" "$s" proof_exec_args "$db -DNADD=2" "$ue" \
	    '/^exec_args_add_str(/,/^}/s/return (error == ENAMETOOLONG ? E2BIG : error);/return (error);/'
fi

if want recvmsg; then
	# The control-message copy-out of recvmsg(2), sys/kern/uipc_syscalls.c:
	# kern_recvit() copies the control mbuf chain out to the user's
	# msg_control buffer one mbuf at a time while they fit, accumulating
	# msg_controllen and flagging MSG_CTRUNC on overflow.  The copy never
	# runs past the user buffer, the reported length is the bytes copied,
	# and truncation is flagged iff the chain does not all fit.  The user
	# buffer is sized to CLEN, so an overrun is an out-of-bounds write.
	# The chain is up to NMBUF mbufs of any length; getsock(), soreceive()
	# and the leftover-chain dispose are modelled.
	h="$here/recvmsg/recvmsg.c"
	s="$top/sys/kern/uipc_syscalls.c"
	ur="kern_recvit.0:1,kern_recvit.1:4,soreceive.0:4,m_freem.0:4"
	ur="$ur,cbmc_memmove.0:65"
	dr="-DINET -DINET6 -DNMBUF=3"
	for c in 0 32 64 128; do
		proof recvit_$c "$h" "$s" proof_recvit "$dr -DCLEN=$c" "$ur"
	done
	dc="$dr -DCLEN=64"
	# Each mbuf copied out advances the user pointer ...
	mutant recvit_ctlbuf "$h" "$s" proof_recvit "$dc" "$ur" \
	    '/if (mp->msg_control \&\& controlp == NULL) {/,/^	}/s/ctlbuf += m->m_len;/;/'
	# ... and shrinks the remaining room, so a later mbuf cannot overrun ...
	mutant recvit_len "$h" "$s" proof_recvit "$dc" "$ur" \
	    '/if (mp->msg_control \&\& controlp == NULL) {/,/^	}/s/len -= m->m_len;/;/'
	# ... the reported length is the bytes copied ...
	mutant recvit_report "$h" "$s" proof_recvit "$dc" "$ur" \
	    '/if (mp->msg_control \&\& controlp == NULL) {/,/^	}/s/mp->msg_controllen += m->m_len;/;/'
	# ... and a chain that does not fit is flagged truncated.
	mutant recvit_ctrunc "$h" "$s" proof_recvit "$dc" "$ur" \
	    '/if (m != NULL) {/,/m_dispose_extcontrolm(m);/s/mp->msg_flags |= MSG_CTRUNC;/;/'
fi

if want syncache; then
	# The TCP SYN cookie, sys/netinet/tcp_syncache.c: syncookie_generate()
	# packs a connection's MSS, window scale and SACK state plus a MAC into
	# the SYN-ACK ISS, and syncookie_expand() unpacks the ACK the peer
	# echoes and restores them.  The pair round-trips: a cookie this host
	# generated decodes to the same MSS, window scale and SACK.  The MAC
	# (SIPHASH) is replaced by a deterministic model, so what is proven is
	# the bit packing; the 3-bit indices stay within the 8-entry tables.
	# Rejection of a forged ACK is the MAC's property, not proven here.
	h="$here/syncache/syncookie.c"
	s="$top/sys/netinet/tcp_syncache.c"
	us="syncookie_generate.0:9,syncookie_generate.1:9,syncookie_expand.0:16"
	us="$us,proof_roundtrip.0:9,proof_roundtrip.1:9,proof_roundtrip.2:9"
	us="$us,cbmc_memmove.0:65"
	# PMSS and WSCALE are constants per job (the encode walks the index
	# tables): sweep a small MSS (index 0), an exact table entry, and a
	# large one (top index); with no window scale, and with a scale that
	# hits a middle and the top table entry.
	proof syncookie_rt_small "$h" "$s" proof_roundtrip \
	    "-DINET -DINET6 -DPMSS=100 -DWSCALE=-1" "$us"
	proof syncookie_rt_exact "$h" "$s" proof_roundtrip \
	    "-DINET -DINET6 -DPMSS=1460 -DWSCALE=-1" "$us"
	proof syncookie_rt_wscale "$h" "$s" proof_roundtrip \
	    "-DINET -DINET6 -DPMSS=1200 -DWSCALE=4" "$us"
	proof syncookie_rt_big "$h" "$s" proof_roundtrip \
	    "-DINET -DINET6 -DPMSS=65535 -DWSCALE=8" "$us"
	dd="-DINET -DINET6 -DPMSS=1200 -DWSCALE=4"
	# The MSS index packs into the cookie and unpacks to the same entry ...
	mutant syncookie_mss "$h" "$s" proof_roundtrip "$dd" "$us" \
	    '/^syncookie_generate(/,/^}/s/cookie.flags.mss_idx = i;/cookie.flags.mss_idx = i + 1;/'
	# ... the SACK flag round-trips ...
	mutant syncookie_sack "$h" "$s" proof_roundtrip "$dd" "$us" \
	    '/^syncookie_expand(/,/^}/s/if (cookie.flags.sack_ok)/if (0)/'
	# ... the window scale round-trips.
	mutant syncookie_wscale "$h" "$s" proof_roundtrip "$dd" "$us" \
	    '/^syncookie_generate(/,/^}/s/cookie.flags.wscale_idx = i;/cookie.flags.wscale_idx = i + 1;/'
fi

if want mbuf; then
	# m_copydata(), sys/kern/uipc_mbuf.c: copy len bytes from offset off
	# of an mbuf chain into a flat buffer, used all over the stack to pull
	# packet bytes out of a chain.  Under the caller's contract (off, len
	# >= 0 and off + len within the chain) every per-mbuf read stays
	# inside that mbuf's data and exactly len bytes are delivered.  Each
	# mbuf's data is sized to its m_len, so a read past a mbuf is an
	# out-of-bounds read.  off and len are constants per job, the chain
	# lengths symbolic within them; the jobs sweep a zero offset, an
	# offset mid-mbuf, and one spanning several mbufs.
	h="$here/mbuf/m_copydata.c"
	s="$top/sys/kern/uipc_mbuf.c"
	um="m_copydata.0:5,m_copydata.1:5,m_copydata.2:5,m_copydata.3:5"
	um="$um,m_copydata.4:5,m_copydata.5:5"
	um="$um,proof_copydata.0:5,proof_copydata.1:11,cbmc_memmove.0:9"
	# GEO is a concrete chain geometry per job (a symbolic chain's split
	# combinatorics blow up): 0 a copy inside the first mbuf, 1 a copy
	# starting mid-mbuf, 2 a copy spanning three mbufs, 3 an empty copy at
	# a boundary.
	for g in 0 1 2 3 4; do
		proof mcopydata_geo$g "$h" "$s" proof_copydata "-DGEO=$g" "$um"
	done
	# The per-mbuf copy count stays within the mbuf (m_len - off): copying
	# the whole remaining len from a shorter mbuf reads past it ...
	mutant mcopydata_count "$h" "$s" proof_copydata "-DGEO=2" "$um" \
	    '/^m_copydata(/,/^}/s/count = min(m->m_len - off, len);/count = len;/'
	# ... and the skip loop that charges off against each mbuf keeps off
	# bounded (GEO 4 skips two mbufs), so m_len - off cannot go negative
	# and blow up the count.
	mutant mcopydata_skip "$h" "$s" proof_copydata "-DGEO=4" "$um" \
	    '/^m_copydata(/,/^}/s/off -= m->m_len;/;/'

	# m_pulldown(), sys/kern/uipc_mbuf2.c: make len bytes at offset off
	# contiguous in one mbuf, gathering a head piece from the mbuf holding
	# off and a tail piece from the next.  Used by every protocol parsing a
	# header that spans mbufs.  The gather copies stay within each mbuf's
	# storage, and on a non-NULL return the result mbuf holds len contiguous
	# bytes at the returned offset.  Real struct mbufs; m_dup1()/m_get() go
	# through the UMA model.  GEO is a concrete geometry: already contiguous,
	# a chop at non-zero off, and a head+tail gather (len <= MLEN).
	hd="$here/mbuf/m_pulldown.c"
	s2="$top/sys/kern/uipc_mbuf2.c"
	ud="m_pulldown.0:6,m_pulldown.1:6,m_pulldown.2:6,m_pulldown.3:6"
	ud="$ud,m_pulldown.4:6,m_dup1.0:6,m_copydata.0:6"
	ud="$ud,proof_pulldown.0:6,proof_pulldown.1:6,cbmc_memmove.0:41"
	for g in 0 1 2; do
		proof mpulldown_geo$g "$hd" "$s2" proof_pulldown "-DGEO=$g" "$ud"
	done
	# The tail length is len minus the head piece (len - hlen): a short tail
	# leaves the result holding fewer than len contiguous bytes.
	mutant mpulldown_tlen "$hd" "$s2" proof_pulldown "-DGEO=2" "$ud" \
	    '/^m_pulldown(/,/^}/s/tlen = len - hlen;/tlen = len - hlen - 1;/'

	# m_copym(), sys/kern/uipc_mbuf.c: copy len bytes at off of a chain into a
	# freshly allocated chain, used all over the stack.  Plain path (non-EXT,
	# non-header): each new mbuf is filled with min(len, m_len - off) bytes.
	# Each copy stays within the source and the fresh mbuf, and the copied
	# chain's lengths sum to len.  Real source mbufs; fresh mbufs via the UMA
	# model.  GEO: a copy inside the first mbuf, one starting mid-mbuf, and a
	# three-mbuf span.
	hm="$here/mbuf/m_copym.c"
	uc="m_copym.0:6,m_copym.1:6,m_copym.2:6,m_copym.3:6,m_copym.4:6"
	uc="$uc,m_copym.5:6,m_copym.6:6,proof_copym.0:9,proof_copym.1:9"
	uc="$uc,proof_copym.2:9,cbmc_memmove.0:33"
	for g in 0 1 2 3; do
		proof mcopym_geo$g "$hm" "$s" proof_copym "-DGEO=$g" "$uc"
	done
	# The per-mbuf copy length is min(len, m_len - off): copying the whole
	# remaining len from a shorter source mbuf reads past it.  GEO 3 places
	# the source near MLEN so the over-long read runs off the mbuf.
	mutant mcopym_minlen "$hm" "$s" proof_copym "-DGEO=3" "$uc" \
	    '/^m_copym(/,/^}/s/n->m_len = min(len, m->m_len - off);/n->m_len = len;/'

	# m_append(), same file: append len bytes of cp to the end of a chain.
	# It fills the last mbuf's trailing space (up to M_TRAILINGSPACE), then
	# allocates fresh mbufs for the remainder.  Every copy stays within the
	# source buffer and the destination mbuf; the trailing fill never exceeds
	# the last mbuf's storage.  The source is a LEN-byte CBMC object and each
	# mbuf a separate object; fresh mbufs come from the UMA model.  GEO: a fit
	# in the trailing space, a spill to a fresh mbuf, a full last mbuf, and a
	# two-mbuf destination spilling off the end.
	ha="$here/mbuf/m_append.c"
	ua="m_append.0:3,m_append.1:3,proof_append.0:4,proof_append.1:4"
	ua="$ua,proof_append.2:5,proof_append.3:4,cbmc_memmove.0:12"
	for g in 0 1 2 3; do
		proof mappend_geo$g "$ha" "$s" proof_append "-DGEO=$g" "$ua"
	done
	# The trailing fill is capped by M_TRAILINGSPACE (space > remainder):
	# dropping the cap copies min(space, len) from the source but writes
	# space bytes, and a space larger than the remaining source over-reads
	# the LEN-byte source buffer.  GEO 0 has trailing space (MLEN - 4) far
	# larger than LEN, so the uncapped fill reads past the source.
	mutant mappend_space "$ha" "$s" proof_append "-DGEO=0" "$ua" \
	    '/^m_append(/,/^}/s/if (space > remainder)/if (0)/'

	# m_apply(), same file: run a caller function f over len bytes of a chain
	# starting off bytes in, used by the checksum and crypto paths.  It skips
	# to the mbuf holding byte off, then hands f each sub-run [m_data + off,
	# +min(m_len - off, len)); that run must stay within the mbuf data.  The
	# chain is real mbufs, each a separate object; f is pinned to the harness
	# callback, which checks the run lies within the mbuf.  GEO: a run inside
	# the first mbuf, one starting mid-mbuf, a three-mbuf span, and a run
	# reaching the last byte.
	hp="$here/mbuf/m_apply.c"
	up="m_apply.3:4,m_apply.5:4,proof_apply.0:4,proof_apply.1:4"
	for g in 0 1 2 3; do
		proof mapply_geo$g "$hp" "$s" proof_apply "-DGEO=$g" "$up"
	done
	# The per-mbuf run is min(m_len - off, len): handing f the whole len from
	# a shorter mbuf reads past it.  GEO 4 places the first mbuf near MLEN
	# with off near its end, so the over-long run runs off the mbuf storage.
	mutant mapply_min "$hp" "$s" proof_apply "-DGEO=4" "$up" \
	    '/^m_apply(/,/^}/s/count = min(m->m_len - off, len);/count = len;/'

	# m_copyback(), same file: write len bytes at off into an mbuf chain,
	# growing a mbuf into its trailing room and allocating new mbufs when
	# off or len runs past the end.  Every write stays inside a mbuf's
	# storage, a mbuf grows only within its trailing room, and a failed
	# allocation stops without a write past the end.  The chain is real
	# struct mbufs, so the storage bounds and M_TRAILINGSPACE are the
	# kernel's; a write past m_dat is an out-of-bounds write.  GEO is a
	# concrete geometry per job: a write inside the mbuf, one growing it
	# into trailing room, one allocating past the end, one skipping past
	# the end.
	h="$here/mbuf/m_copyback.c"
	ub="m_copyback.0:5,m_copyback.1:5,proof_copyback.0:13,proof_copyback.1:13"
	ub="$ub,cbmc_memmove.0:65"
	for g in 0 1 2 3 4; do
		proof mcopyback_geo$g "$h" "$s" proof_copyback "-DGEO=$g" "$ub"
	done
	# The mbuf grows only within its trailing room: capping by a huge
	# value instead of M_TRAILINGSPACE lets m_len grow past the storage.
	# GEO 4 puts the mbuf one short of MLEN with a larger write, so the
	# shortfall exceeds the trailing room and the cap binds; the mutant
	# then leaves m_len > M_SIZE(m), caught by the post-walk invariant and
	# by the write that follows.
	mutant mcopyback_grow "$h" "$s" proof_copyback "-DGEO=4" "$ub" \
	    '/^m_copyback(/,/^}/s/M_TRAILINGSPACE(m));/65535);/'
	# ... the per-mbuf write count stays within the mbuf (m_len - off).
	mutant mcopyback_count "$h" "$s" proof_copyback "-DGEO=4" "$ub" \
	    '/^m_copyback(/,/^}/s/mlen = min (m->m_len - off, len);/mlen = len;/'

	# m_pullup(), same file: rearrange a chain so its first len bytes are
	# contiguous in the head, gathering them from the following mbufs.
	# Every protocol parser calls it then reads len bytes from the head,
	# so on a non-NULL return the head holds at least len contiguous
	# bytes, and the gather never writes past the head's storage nor reads
	# past a source mbuf.  The chain is real struct mbufs, so the storage
	# bounds are the kernel's; a gather past the head is an out-of-bounds
	# write.  GEO is a concrete geometry: a pull already contiguous, a
	# two-mbuf pull in place, a three-mbuf gather, and a > MHLEN request
	# that must fail cleanly.
	h="$here/mbuf/m_pullup.c"
	uu="m_pullup.0:5,m_pullup.1:5,m_pullup.2:5,proof_pullup.0:9"
	uu="$uu,proof_pullup.1:9,proof_pullup.2:9,m_freem.0:9,cbmc_memmove.0:65"
	for g in 0 1 2 3; do
		proof mpullup_geo$g "$h" "$s" proof_pullup "-DGEO=$g" "$uu"
	done
	# A pull shorter than len is not reported contiguous: the early-return
	# shortcut fires only when the head already holds len.  (The free-space
	# cap on the gather count is exercised by the proofs; a mutant forcing
	# the overshoot needs a geometry filling the head to the MLEN tail,
	# whose large-offset bounds check is too slow to run here.)
	mutant mpullup_early "$h" "$s" proof_pullup "-DGEO=1" "$uu" \
	    '/^m_pullup(/,/^}/s/if (n->m_len >= len)/if (1)/'

	# m_split(), same file: split a chain in two at byte offset len0,
	# returning the tail.  The plain path (no M_PKTHDR, no external
	# storage) copies the split mbuf's tail bytes into a fresh mbuf and
	# divides the lengths exactly.  The copy stays inside both mbufs and
	# len + remain equals the original length.  Real struct mbufs, so the
	# storage and M_ALIGN placement are the kernel's; a copy past a mbuf is
	# an out-of-bounds access.  GEO: split inside the first mbuf, at a mbuf
	# boundary (remain == 0), and inside a later mbuf.
	h="$here/mbuf/m_split.c"
	ut="m_split.0:5,m_split.1:5,proof_split.0:5,proof_split.1:5"
	ut="$ut,proof_split.2:5,proof_split.3:9,cbmc_memmove.0:65"
	for g in 0 1 2; do
		proof msplit_geo$g "$h" "$s" proof_split "-DGEO=$g" "$ut"
	done
	# The tail length is the bytes after the offset (m_len - len) ...
	mutant msplit_remain "$h" "$s" proof_split "-DGEO=0" "$ut" \
	    '/^m_split(/,/^}/s/remain = m->m_len - len;/remain = m->m_len - len + 1;/'
	# ... and the split mbuf keeps exactly the bytes before the offset.
	mutant msplit_mlen "$h" "$s" proof_split "-DGEO=0" "$ut" \
	    '/^m_split(/,/^}/s/m->m_len = len;/m->m_len = len + 1;/'
fi

if want ip; then
	# ip_dooptions(), sys/netinet/ip_options.c: the IPv4 options parser run
	# on every received packet carrying options.  It walks the option area
	# trusting each option's length byte, and for record-route and
	# timestamp options reads and writes at an attacker-influenced pointer
	# into the option area.  Every access stays within the option area; the
	# length and pointer checks in the loop are the guard.  The packet is a
	# struct ip plus OPTLEN nondeterministic option bytes in one object, so
	# a read or write past it is an out-of-bounds access.  OPTLEN is a
	# constant per job (a symbolic length ran past the time budget); the
	# jobs sweep a few option-area sizes covering the record-route and
	# timestamp layouts.
	h="$here/ip/ip_options.c"
	s="$top/sys/netinet/ip_options.c"
	ui="ip_dooptions.0:41,ip_dooptions.1:41,ip_dooptions.2:41,ip_dooptions.3:41"
	ui="$ui,save_rte.0:41,cbmc_memmove.0:41,proof_dooptions.0:41"
	# OPTLEN sweeps the option-area size: 4 the minimum, 8 and 12 reaching
	# the record-route and timestamp opcodes.  (The full 40-byte area is
	# not swept: a 40-byte symbolic option stream runs the parser past the
	# time budget, and 12 already exercises every opcode and guard.)
	for n in 4 8 12; do
		proof ip_dooptions_$n "$h" "$s" proof_dooptions \
		    "-DINET -DOPTLEN=$n" "$ui"
	done
	# The option length is checked not to run past the remaining bytes:
	# dropping the optlen > cnt check lets the walk step past the area ...
	mutant ip_optlen "$h" "$s" proof_dooptions "-DINET -DOPTLEN=12" "$ui" \
	    '/^ip_dooptions(/,/^}/s/if (optlen < IPOPT_OLEN + sizeof(\*cp) || optlen > cnt) {/if (optlen < IPOPT_OLEN + sizeof(*cp)) {/'
	# ... the record-route pointer is checked against the option length.
	mutant ip_rroff "$h" "$s" proof_dooptions "-DINET -DOPTLEN=12" "$ui" \
	    '/case IPOPT_RR:/,/case IPOPT_TS:/s/if (off > optlen - (int)sizeof(struct in_addr))/if (0)/'

	# ip_fragment(), sys/netinet/ip_output.c: split an IPv4 packet too large
	# for the MTU into fragments.  The fragments must tile [hlen, ip_len)
	# exactly: contiguous 8-aligned offsets, each payload <= the MTU payload,
	# the More-Fragments bit on all but the last.  The per-fragment mbuf
	# helpers are modelled; ip_len and mtu are constants per job (a symbolic
	# length makes the loop unbounded).  The jobs sweep an exact multiple of
	# the fragment payload, a remainder, and a single fragment.
	hf="$here/ip/ip_fragment.c"
	sf="$top/sys/netinet/ip_output.c"
	uf="ip_fragment.0:12,ip_fragment.1:12,ip_fragment.2:12,ip_fragment.3:12"
	uf="$uf,ip_fragment.4:12,proof_fragment.0:16,cbmc_memmove.0:9"
	df="-DINET -DIPSTAT_ADD(n,v)= -DIPSTAT_INC(n)= "
	# MTU 48 -> payload (48-20)&~7 = 24.  ip_fragment is called only when the
	# packet exceeds the MTU, so IPLEN > MTU.  IPLEN-20 payload: 92-20=72=3*24
	# exact tiling, 100-20=80 a remainder, 68-20=48=2*24 two fragments.
	proof ip_fragment_exact "$hf" "$sf" proof_fragment "$df -DMTU=48 -DIPLEN=92" "$uf"
	proof ip_fragment_rem "$hf" "$sf" proof_fragment "$df -DMTU=48 -DIPLEN=100" "$uf"
	proof ip_fragment_two "$hf" "$sf" proof_fragment "$df -DMTU=48 -DIPLEN=68" "$uf"
	# The last fragment's length is trimmed to the remainder: dropping the
	# trim leaves it over-long and sets MF, breaking the tiling.
	mutant ip_fragment_last "$hf" "$sf" proof_fragment "$df -DMTU=48 -DIPLEN=100" "$uf" \
	    '/^ip_fragment(/,/^}/s/if (off + len >= ip_len)/if (0)/'

	# ip_optcopy(), sys/netinet/ip_options.c: copy the "copied" IP options
	# from one header to another when building fragments.  It walks the
	# source options and bcopy()s each copied one into the destination option
	# area, then pads to 4 bytes.  Both source reads and destination writes
	# stay within the 40-byte option areas.  Each header owns exactly
	# MAX_IPOPTLEN option bytes as a CBMC object, so a read or write past it
	# is an out-of-bounds access.  A well-formed source layout per job.
	hc="$here/ip/ip_optcopy.c"
	uc="ip_optcopy.0:12,proof_optcopy.0:41,cbmc_memmove.0:41"
	for n in 4 8 40; do
		proof ip_optcopy_$n "$hc" "$s" proof_optcopy "-DINET -DOPTLEN=$n" "$uc"
	done
	# The copy length is exactly the option length: copying one byte more
	# writes past the source option and the destination area.
	mutant ip_optcopy_len "$hc" "$s" proof_optcopy "-DINET -DOPTLEN=40" "$uc" \
	    '/^ip_optcopy(/,/^}/s/bcopy(cp, dp, optlen);/bcopy(cp, dp, optlen + 1);/'
fi

if want ip6; then
	# ip6_fragment(), sys/netinet6/ip6_output.c: split an IPv6 packet into
	# fragments of a given fraglen, the IPv6 counterpart of ip_fragment().
	# The fragments tile [hlen, tlen) exactly: contiguous 8-aligned offsets,
	# each payload fraglen, the More-Fragments bit on all but the last.  The
	# per-fragment helpers are modelled and the fragment header placed in a
	# harness buffer so the offlg writes are bounds-checked.  tlen and fraglen
	# are constants per job; the jobs sweep an exact multiple and a remainder.
	h6="$here/ip6/ip6_fragment.c"
	s6="$top/sys/netinet6/ip6_output.c"
	u6="ip6_fragment.0:12,ip6_fragment.1:12,ip6_fragment.2:12,ip6_fragment.3:12"
	u6="$u6,ip6_fragment.4:12,ip6_fragment.5:12,ip6_fragment.6:12"
	u6="$u6,ip6_fragment.7:12,proof_ip6_fragment.0:16,cbmc_memmove.0:9"
	d6="-DINET6 -DIP6STAT_ADD(n,v)= -DIP6STAT_INC(n)= "
	# hlen 40, fraglen 24.  tlen-40 payload: 112=? use 136-40=96=4*24 exact,
	# 160-40=120=5*24 exact; 150-40=110 remainder.
	proof ip6_fragment_exact "$h6" "$s6" proof_ip6_fragment "$d6 -DTLEN=136 -DFRAGLEN=24" "$u6"
	proof ip6_fragment_rem "$h6" "$s6" proof_ip6_fragment "$d6 -DTLEN=150 -DFRAGLEN=24" "$u6"
	# The last fragment's length trim is load-bearing: dropping it over-sizes
	# the last fragment and sets MF, breaking the tiling.
	mutant ip6_fragment_last "$h6" "$s6" proof_ip6_fragment "$d6 -DTLEN=150 -DFRAGLEN=24" "$u6" \
	    '/^ip6_fragment(/,/^}/s/if (off + fraglen >= tlen)/if (0)/'
fi

if want reass; then
	# The TCP reassembly accounting helpers, sys/netinet/tcp_reass.c:
	# tcp_reass_prepend() splices a new segment in front of a queued
	# out-of-order segment and trims the overlap, and tcp_reass_append()
	# tacks one onto the end.  They maintain each segment's (start, len)
	# over the sequence space; a wrong trim double-counts or loses bytes.
	# Prepend starts the segment at the new sequence and preserves its end
	# (overlap trimmed once); append grows the length by exactly the
	# appended length.  m_adj() is modelled; the stat macros are compiled
	# out.  Sequence numbers and lengths are symbolic, bounded so the trim
	# cannot wrap.
	h="$here/tcp/reass.c"
	s="$top/sys/netinet/tcp_reass.c"
	dr="-DINET -DINET6 -DTCPSTAT_ADD(n,v)= -DTCPSTAT_INC(n)= "
	proof reass_prepend "$h" "$s" proof_prepend "$dr" ""
	proof reass_append "$h" "$s" proof_append "$dr" ""
	# The overlap length trim is load-bearing: dropping it overcounts the
	# combined length so the segment's end moves past where the data reaches
	# ...
	mutant reass_trimlen "$h" "$s" proof_prepend "$dr" "" \
	    '/^tcp_reass_prepend(/,/^}/s/first->tqe_len -= i;/;/'
	# ... and the overlap amount must be the full excess (th_seq + tlen -
	# start), not less, or the trim leaves bytes double-counted.
	mutant reass_overlap "$h" "$s" proof_prepend "$dr" "" \
	    '/^tcp_reass_prepend(/,/^}/s/i = (th->th_seq + tlen) - first->tqe_start;/i = (th->th_seq + tlen) - first->tqe_start - 1;/'
	# append must add the whole appended length.
	mutant reass_appendlen "$h" "$s" proof_append "$dr" "" \
	    '/^tcp_reass_append(/,/^}/s/last->tqe_len += tlen;/last->tqe_len += tlen - 1;/'

	# tcp_reass_merge_forward(), same file: coalesce every segment after ent
	# that ent overlaps forward, freeing a fully-covered one and trimming a
	# partially overlapping one before merging it.  Afterwards no following
	# segment overlaps ent and the queue stays sorted.  GEO is a concrete
	# queue geometry per job (a symbolic queue's overlap combinatorics blow
	# up): a gap, a partial-overlap trim, a full consume, and two segments.
	hf="$here/tcp/reass_fwd.c"
	uw="tcp_reass_merge_forward.0:9,tcp_reass_merge_forward.1:9"
	uw="$uw,tcp_reass_merge_forward.2:9,tcp_reass_merge_forward.3:9"
	uw="$uw,tcp_reass_merge_forward.4:9,tcp_reass_merge_forward.5:9"
	uw="$uw,proof_merge_fwd.0:9,proof_merge_fwd.1:9,proof_merge_fwd.2:9"
	uw="$uw,proof_merge_fwd.3:9,proof_merge_fwd.4:9,proof_merge_fwd.5:9"
	uw="$uw,proof_merge_fwd.6:9,proof_merge_fwd.7:9,proof_merge_fwd.8:9"
	uw="$uw,proof_merge_fwd.9:9,proof_merge_fwd.10:9,proof_merge_fwd.11:9"
	uw="$uw,cbmc_memmove.0:41"
	for g in 0 1 2 3; do
		proof reass_fwd_geo$g "$hf" "$s" proof_merge_fwd "$dr -DGEO=$g" "$uw"
	done
	# The forward trim amount is the overlap (max - q->tqe_start): a short
	# trim leaves q still overlapping ent after the merge.
	mutant reass_fwdtrim "$hf" "$s" proof_merge_fwd "$dr -DGEO=1" "$uw" \
	    '/^tcp_reass_merge_forward(/,/^}/s/i = max - q->tqe_start;/i = max - q->tqe_start - 1;/'
	# A segment ent fully covers is consumed, not left in the queue.
	mutant reass_fwdconsume "$hf" "$s" proof_merge_fwd "$dr -DGEO=2" "$uw" \
	    '/^tcp_reass_merge_forward(/,/^}/s/if (SEQ_GEQ(max, (q->tqe_start + q->tqe_len))) {/if (0) {/'
fi

if want sockbuf; then
	# sbcompress(), sys/kern/uipc_sockbuf.c: append an mbuf chain to a socket
	# buffer's tail, coalescing a small mbuf into the previous one's trailing
	# space when it fits, else linking it in.  Hit by every protocol receive.
	# The coalesce copy stays within the tail mbuf's storage and sb_ccc ends
	# equal to the bytes in the buffer.  Real struct mbufs, so the storage
	# bounds and M_TRAILINGSPACE are the kernel's; sballoc() runs for real.
	# GEO is a concrete geometry per job: a coalescing appendee, a too-big
	# one (linked), and two appendees.
	h="$here/sockbuf/sbcompress.c"
	s="$top/sys/kern/uipc_sockbuf.c"
	usb="sbcompress.0:9,proof_sbcompress.0:9,proof_sbcompress.1:9,cbmc_memmove.0:260"
	for g in 0 1 2; do
		proof sbcompress_geo$g "$h" "$s" proof_sbcompress "-DGEO=$g" "$usb"
	done
	# The coalesce copies only when the mbuf fits the tail's trailing space:
	# dropping that check copies past the tail ...
	mutant sbcompress_room "$h" "$s" proof_sbcompress "-DGEO=1" "$usb" \
	    '/^sbcompress(/,/^}/s/m->m_len <= M_TRAILINGSPACE(n) &&/1 \&\&/'
	# ... and every coalesced mbuf's bytes are added to sb_ccc.
	mutant sbcompress_ccc "$h" "$s" proof_sbcompress "-DGEO=0" "$usb" \
	    '/^sbcompress(/,/^}/s/sb->sb_ccc += m->m_len;/;/'

	# sbappendaddr_locked(), same file: the datagram receive append (UDP,
	# Unix-domain datagram).  It assembles a (sockaddr, data) record and
	# puts it on the receive buffer if there is room.  A record over the
	# buffer's space is refused; an accepted one grows sb_ccc by exactly the
	# record length; the sockaddr copy stays within its mbuf.  The address
	# and data lengths are a constant per job, bracketing the space bound
	# (HIWAT=64): a record that fits, one that just overflows, and one with
	# no data.
	a="$here/sockbuf/sbappendaddr.c"
	ua="sbappendaddr_locked_internal.0:4,m_length.0:4,proof_addr.0:4"
	ua="$ua,cbmc_memmove.0:40"
	proof sbaddr_fit "$a" "$s" proof_addr "-DSALEN=16 -DDLEN=20 -DHIWAT=64" "$ua"
	proof sbaddr_over "$a" "$s" proof_addr "-DSALEN=16 -DDLEN=60 -DHIWAT=64" "$ua"
	proof sbaddr_nodata "$a" "$s" proof_addr "-DSALEN=16 -DDLEN=0 -DHIWAT=64" "$ua"
	# The space check is load-bearing: dropping it accepts a record that
	# does not fit (sb_ccc then exceeds the high-water) ...
	mutant sbaddr_space "$a" "$s" proof_addr "-DSALEN=16 -DDLEN=60 -DHIWAT=64" "$ua" \
	    '/^sbappendaddr_locked(/,/^}/s/if (space > sbspace(sb))/if (0)/'

	# sbreserve_locked_limit(), same file: socket-buffer sizing for
	# setsockopt(SO_RCVBUF/SO_SNDBUF).  A requested count cc is capped
	# against BUF_MAX_ADJ(buf_max) so cc * sb_efficiency cannot overflow,
	# then sb_mbmax = min(cc * sb_efficiency, buf_max).  The cap is the
	# overflow guard.  cc and buf_max are nondeterministic u_long.
	# chgsbsize() and lim_cur() are modelled.
	r="$here/sockbuf/sbreserve.c"
	proof sbreserve "$r" "$s" proof_sbreserve "" ""
	# The cap is load-bearing: dropping it lets cc * sb_efficiency overflow.
	mutant sbreserve_cap "$r" "$s" proof_sbreserve "" "" \
	    '/^sbreserve_locked_limit(/,/^}/s/if (cc > BUF_MAX_ADJ(buf_max))/if (0)/'

	# sbcreatecontrol(), same file: build a control-message (cmsg) mbuf of
	# size payload bytes, used by the socket layer to hand ancillary data to
	# recvmsg(2).  It sizes the mbuf by CMSG_SPACE(size), zeroes it, copies
	# size payload bytes in, and writes the cmsg header.  The zero and the
	# copy must stay within the mbuf storage.  This covers the plain-mbuf
	# path (CMSG_SPACE(size) <= MLEN); the mbuf data area is a real MLEN
	# object.  SIZE is a constant per job: small payloads, the largest that
	# still fits MLEN, and the value where _ALIGN(size) wraps u_int.
	c="$here/sockbuf/sbcreatecontrol.c"
	cc="sbcreatecontrol.0:2"
	proof sbctl_small "$c" "$s" proof_sbcreatecontrol "-DSIZE=8" "$cc"
	proof sbctl_fit "$c" "$s" proof_sbcreatecontrol "-DSIZE=(MLEN-16)" "$cc"
	# A latent gap, left open as a question: for a size where _ALIGN(size)
	# overflows u_int, CMSG_SPACE(size) collapses below MLEN so the mbuf is
	# sized small (plain path), yet the payload memcpy still uses the full
	# size, writing past the mbuf.  No in-tree caller passes such a size
	# (the variable-size callers bound it to a packet, or pass p == NULL so
	# the memcpy is skipped), so this is not reachable today; see README and
	# reports/socket.md.
	question sbctl_wrap "$c" "$s" proof_sbcreatecontrol "-DSIZE=0xfffffff9U" "$cc"
fi

if want mmap; then
	# The length/offset validation of kern_mmap(), sys/vm/vm_mmap.c: mmap(2)
	# adds the page offset to the length and rounds up, then guards the sum
	# wrapping to zero.  A wrapped size would map fewer pages than asked (an
	# overflow bug class).  len and pos are nondeterministic; the anonymous
	# path is driven, and vm_mmap_object() is intercepted to check the size
	# handed to the mapping is at least len and page-aligned.
	h="$here/mmap/mmap_len.c"
	s="$top/sys/vm/vm_mmap.c"
	um="kern_mmap.0:4,proof_mmap_len.0:4"
	proof mmap_len "$h" "$s" proof_mmap_len "-DINET -DINET6" "$um"
	# The wrap guard is load-bearing: dropping it lets a wrapped (tiny) size
	# through to the mapping.
	mutant mmap_wrap "$h" "$s" proof_mmap_len "-DINET -DINET6" "$um" \
	    '/^kern_mmap(/,/^}/s/if (len > size)/if (0)/'

	# The address/length wrap guard of kern_mlock(), sys/vm/vm_mmap.c:
	# mlock(2) rounds [addr, addr+len) to pages and guards the sum wrapping
	# (last < addr || end < addr).  A wrapped range would wire a bogus
	# region.  addr and len are nondeterministic; vm_map_wire() is
	# intercepted to check the range reaching it is ordered, page-aligned and
	# covers the request.
	hl="$here/mmap/mlock_len.c"
	ul="kern_mlock.0:4,proof_mlock_len.0:4"
	proof mlock_len "$hl" "$s" proof_mlock_len "-DINET -DINET6" "$ul"
	# The wrap guard is load-bearing: dropping it lets a wrapped range reach
	# vm_map_wire with end < start.
	mutant mlock_wrap "$hl" "$s" proof_mlock_len "-DINET -DINET6" "$ul" \
	    '/^kern_mlock(/,/^}/s/if (last < addr || end < addr)/if (0)/'
fi

if want bpf; then
	# bpf_validate(), sys/net/bpf_filter.c: the check of a classic-BPF
	# program before BIOCSETF installs it and bpf_filter() runs it on every
	# captured packet.  A program it accepts must be safe to interpret: its
	# jumps stay within the instruction array (so bpf_filter's pc never runs
	# off the end), its scratch indices are < BPF_MEMWORDS, and it ends in a
	# return.  The program is a LEN-instruction CBMC object of nondet fields,
	# so bpf_validate's own reads are bounds-checked; LEN is a constant per
	# job (1 to 4 instructions).
	h="$here/bpf/bpf_validate.c"
	s="$top/sys/net/bpf_filter.c"
	bv="bpf_validate.0:5,proof_bpf_validate.0:5,proof_bpf_validate.1:5"
	for n in 1 2 3 4; do
		proof bpfval_len$n "$h" "$s" proof_bpf_validate "-DLEN=$n" "$bv"
	done
	# The jump-bound check is load-bearing: weakening it (the target may
	# equal len - i - 1, one past the last reachable instruction) lets an
	# accepted program jump off the array.
	mutant bpfval_jump "$h" "$s" proof_bpf_validate "-DLEN=3" "$bv" \
	    '/^bpf_validate(/,/^}/s/if (offset >= (u_int)(len - i) - 1)/if (offset > (u_int)(len - i) - 1)/'
	# The memory-index check is load-bearing: dropping it lets an accepted
	# program use a scratch index past BPF_MEMWORDS.
	mutant bpfval_mem "$h" "$s" proof_bpf_validate "-DLEN=2" "$bv" \
	    '/^bpf_validate(/,/^}/s/if (p->k >= BPF_MEMWORDS)/if (0)/'
	# The trailing-return check is load-bearing: dropping it accepts a
	# program that does not end in BPF_RET.
	mutant bpfval_ret "$h" "$s" proof_bpf_validate "-DLEN=2" "$bv" \
	    '/^bpf_validate(/,/^}/s/return (BPF_CLASS(f\[len - 1\].code) == BPF_RET);/return (1);/'

	# bpf_filter(), same file: the interpreter.  Its packet loads (BPF_LD of
	# a word/half/byte, absolute or X-indexed) guard the read against buflen
	# before touching p[k]; a wrong guard reads past the packet and leaks
	# adjacent memory into the accumulator.  The packet is a BUFLEN-byte CBMC
	# object; a short program drives one load with a nondet X and k, and CBMC
	# bounds-checks the read.  buflen is non-zero, so the mbuf fallback is not
	# the subject.  LOAD selects the load per job.
	hf="$here/bpf/bpf_filter.c"
	bf="bpf_filter.3:4"
	for l in 0 1 2 3 4 5; do
		proof bpffilt_ld$l "$hf" "$s" proof_bpf_filter "-DLOAD=$l -DBUFLEN=8" "$bf"
	done
	# The absolute-word load guards k > buflen || sizeof > buflen - k;
	# dropping the first clause lets a large k with the unsigned buflen - k
	# wrapping slip a read past the packet.
	mutant bpffilt_absw "$hf" "$s" proof_bpf_filter "-DLOAD=0 -DBUFLEN=8" "$bf" \
	    '/case BPF_LD|BPF_W|BPF_ABS:/,/continue;/s/if (k > buflen || sizeof(int32_t) > buflen - k)/if (sizeof(int32_t) > buflen - k)/'
	# The X-indexed byte load guards pc->k >= buflen || X >= buflen - pc->k;
	# dropping the second clause lets X push the read past the packet.
	mutant bpffilt_indb "$hf" "$s" proof_bpf_filter "-DLOAD=5 -DBUFLEN=8" "$bf" \
	    '/case BPF_LD|BPF_B|BPF_IND:/,/continue;/s/if (pc->k >= buflen || X >= buflen - pc->k)/if (pc->k >= buflen)/'
fi

if want sysctl; then
	# sysctl_old_user(), sys/kern/kern_sysctl.c: the copy-out helper every
	# sysctl(2) read goes through.  It copies a chunk to the user buffer at
	# the running offset, clamped to the validated length, accounting the
	# total in oldidx.  The copy stays within the buffer, oldidx advances by
	# the chunk length, and a truncated read returns ENOMEM.  The user buffer
	# is a CBMC object of exactly validlen bytes, so a copy past it is an
	# out-of-bounds write.  The chunk length, offset and validlen are
	# nondeterministic within a small bound.
	h="$here/sysctl/old_user.c"
	s="$top/sys/kern/kern_sysctl.c"
	uo="proof_old_user.0:4"
	proof sysctl_old_user "$h" "$s" proof_old_user "" "$uo"
	# The remaining-room clamp is load-bearing: copying the whole chunk
	# ignoring validlen writes past the user buffer.
	mutant sysctl_old_clamp "$h" "$s" proof_old_user "" "$uo" \
	    '/^sysctl_old_user(/,/^}/s/if (i > len - origidx)/if (0)/'

	# sysctl_new_user(), same file: the copy-in helper every sysctl(2) write
	# goes through, companion to sysctl_old_user().  It reads a chunk of the
	# user new buffer at the running offset, refusing EINVAL if it does not
	# fit the remaining new length, accounting it in newidx.  The copy-in
	# stays within the buffer and newidx advances by the chunk length.  The
	# buffer is sized to newlen, so a read past it is caught.
	hn="$here/sysctl/new_user.c"
	un="proof_new_user.0:4"
	proof sysctl_new_user "$hn" "$s" proof_new_user "" "$un"
	# The remaining-length check is load-bearing: dropping it lets a chunk
	# past the buffer be read.
	mutant sysctl_new_fit "$hn" "$s" proof_new_user "" "$un" \
	    '/^sysctl_new_user(/,/^}/s/if (req->newlen - req->newidx < l)/if (0)/'
fi

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

	# write(2) on a socket with a TLS send session, the TLS branch of
	# sosend_generic_locked(), uipc_socket.c: sends of up to 3 bytes, with
	# or without a control message, software or NIC sessions.
	hn="$here/ktls/ktls_send.c"
	sn="$top/sys/kern/uipc_socket.c"
	un="sosend_generic_locked.0:3,sosend_generic_locked.1:6"
	un="$un,sosend_generic_locked.2:6,proof_send.0:6,proof_send.1:6"
	un="$un,chain.0:6"
	proof ktls_send "$hn" "$sn" proof_send "$dk" "$un"
	# The fix taken back: a control message of only its header has its
	# type byte read past its end.  (Setting the record type back to
	# application data after the first chain is no mutant: a send with
	# a type is atomic, one chain.)
	mutant ktls_send_cmsglen "$hn" "$sn" proof_send "$dk" "$un" \
	    's/if (clen >= CMSG_LEN(sizeof(tls_rtype)) \&\&/if (clen >= sizeof(*cm) \&\&/'
	# The control message freed once, not passed on ...
	mutant ktls_send_ctlfree "$hn" "$sn" proof_send "$dk" "$un" \
	    '/tls_rtype = \*((uint8_t \*)CMSG_DATA(cm));/,/atomic = 1;/s/m_freem(control);/;/'
	mutant ktls_send_ctlnull "$hn" "$sn" proof_send "$dk" "$un" \
	    '/tls_rtype = \*((uint8_t \*)CMSG_DATA(cm));/,/atomic = 1;/s/control = NULL;/;/'
	# ... an empty write refused unless TLS 1.0 CBC ...
	mutant ktls_send_empty "$hn" "$sn" proof_send "$dk" "$un" \
	    's/if (resid == 0 \&\& !ktls_permit_empty_frames(tls)) {/if (0) {/'
	# ... every chain framed, sent not ready for software sessions, then
	# queued to the worker with a socket reference, or freed on an error
	# TCP leaves to the caller; the session held throughout.
	mutant ktls_send_frame "$hn" "$sn" proof_send "$dk" "$un" \
	    '/top = m_uiotombuf(uio, M_WAITOK, space,$/,/tls_rtype = TLS_RLTYPE_APP;/s/if (top != NULL) {/if (0) {/'
	mutant ktls_send_notready "$hn" "$sn" proof_send "$dk" "$un" \
	    's/tls_send_flag = PRUS_NOTREADY;/tls_send_flag = 0;/'
	mutant ktls_send_errfree "$hn" "$sn" proof_send "$dk" "$un" \
	    '/if (tls != NULL \&\& tls->mode == TCP_TLS_MODE_SW) {/,/^#endif/s/m_freem(top);/;/'
	mutant ktls_send_soref "$hn" "$sn" proof_send "$dk" "$un" \
	    '/if (tls != NULL \&\& tls->mode == TCP_TLS_MODE_SW) {/,/^#endif/s/soref(so);/;/'
	mutant ktls_send_enqueue "$hn" "$sn" proof_send "$dk" "$un" \
	    '/if (tls != NULL \&\& tls->mode == TCP_TLS_MODE_SW) {/,/^#endif/s/ktls_enqueue(top, so, tls_enq_cnt);/;/'
	mutant ktls_send_swonly "$hn" "$sn" proof_send "$dk" "$un" \
	    's/if (tls != NULL \&\& tls->mode == TCP_TLS_MODE_SW) {/if (tls != NULL) {/'
	mutant ktls_send_hold "$hn" "$sn" proof_send "$dk" "$un" \
	    '/^out:/,/^}/s/ktls_free(tls);/;/'

	# m_uiotombuf() with M_EXTPG, uipc_mbuf.c, which cuts the user's data
	# into records for the above and sendfile(2): up to two records, any
	# record length up to 16K.
	hu="$here/ktls/ktls_uio.c"
	su="$top/sys/kern/uipc_mbuf.c"
	uu="m_uiotombuf_nomap.2:3,m_uiotombuf_nomap.3:6"
	uu="$uu,m_uiotombuf_nomap.14:3,mb_free_mext_pgs.1:6,uiomove_fromphys.0:6"
	uu="$uu,proof_nomap.0:16,proof_nomap.1:4,proof_nomap.2:16,m_freem.0:4"
	proof ktls_uio "$hu" "$su" proof_nomap "$dk" "$uu"
	f='/^m_uiotombuf_nomap(/,/^}/'
	# The bytes asked for, all of them when len is 0, one empty mbuf for
	# none ...
	mutant ktls_uio_len "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/total = MIN(uio->uio_resid, len);/total = uio->uio_resid;/"
	mutant ktls_uio_empty "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/if (__predict_false(total == 0)) {/if (0) {/"
	# ... in records of maxseg bytes, the last shorter, linked ...
	mutant ktls_uio_seg "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/needed = length = MIN(maxseg, total);/needed = length = total;/"
	mutant ktls_uio_maxseg "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/maxseg = MBUF_PEXT_MAX_PGS \\* PAGE_SIZE;/maxseg = PAGE_SIZE;/"
	mutant ktls_uio_mlen "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/mb->m_len = length;/mb->m_len = needed;/"
	mutant ktls_uio_link "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/prev->m_next = mb;/;/"
	# ... each of anonymous pages holding its bytes ...
	mutant ktls_uio_anon "$hu" "$su" proof_nomap "$dk" "$uu" \
	    '/Allocate the pages/,/return (m);/s/mb->m_epg_flags = EPG_FLAG_ANON;/;/'
	mutant ktls_uio_lastlen "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/mb->m_epg_last_len = length - PAGE_SIZE \\* (mb->m_epg_npgs - 1);/mb->m_epg_last_len = PAGE_SIZE;/"
	mutant ktls_uio_extsize "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/mb->m_ext.ext_size += PAGE_SIZE \\* mb->m_epg_npgs;/;/"
	# ... and on a fault, NULL and every page freed.
	mutant ktls_uio_fault "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/if (error != 0)\$/if (0)/"
	mutant ktls_uio_failfree "$hu" "$su" proof_nomap "$dk" "$uu" \
	    "${f}s/^	m_freem(m);/	;/"

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
