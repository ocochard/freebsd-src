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
# Usage: run.sh [proof ...]	(default: every proof listed below)
# Needs cbmc and goto-cc (pkg install cbmc).  JOBS sets the parallelism.

set -eu

top=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
here="$top/tools/cbmc"
JOBS=${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 1)}
CBMC_MEM=${CBMC_MEM:-8192}

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
	refcount_acquire:cbmc_refcount_acquire
	refcount_release:cbmc_refcount_release
	refcount_release_if_not_last:cbmc_refcount_release_if_not_last"

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
	dst="$work/$1.c"
	sed -e "$7" "$3" >"$dst"
	if cmp -s "$3" "$dst"; then
		printf '%s\n' "$7" >"$work/$1.sed"
		echo "unapplied $1" >>"$work/order"
		return
	fi
	queue mutant "$1" "$2" "$dst" "$4" "$5" "$6"
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
u="setup.0:5,pr_send.0:4,m_freem.0:4,m_length.0:4"
# The page arithmetic, for runs up to two pages.
ua="proof_xfsize.0:4,proof_fixspace.0:4,fixspace.0:4,fixspace.1:4"

if want sendfile; then
	proof sendfile_xfsize "$h" "$s" proof_xfsize "" "$ua"
	proof sendfile_fixspace "$h" "$s" proof_fixspace "" "$ua"
	proof sendfile_noloop "$h" "$s" proof_noloop "$d" "$u"

	question sendfile_short_write "$h" "$s" proof_noloop \
	    "$d -DSPEC_SHORT_WRITE" "$u"

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
	    's/if (error != 0 || cnt != len)/if (error != 0)/'
	# The page split: the last page of a run, and the first.
	mutant sendfile_xfsize_last "$h" "$s" proof_xfsize "" "$ua" \
	    's/if (i == n - 1 \&\& ((off + len) \& PAGE_MASK) > 0)/if (i == n - 1)/'
	mutant sendfile_fixspace_first "$h" "$s" proof_fixspace "" "$ua" \
	    's/\*space -= xfsize(0, old, off, \*space);/*space -= PAGE_SIZE;/'
fi

[ "$njobs" -gt 0 ] || { echo "run.sh: nothing selected" >&2; exit 2; }

# shellcheck disable=SC2016
seq 1 "$njobs" | xargs -P "$JOBS" -I % sh "$0" --job "$work" %

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
		why=$(grep -m1 ': FAILURE$' "$work/$name.log" |
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
