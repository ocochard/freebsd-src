#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Olivier Cochard-Labbe <olivier@FreeBSD.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

#
# Delegations: the server recalls the one a client holds when another
# client opens the file for writing.  vfs.nfsd.issue_delegations is global,
# so the test sets it on the host and restores it.
#

. $(atf_get_srcdir)/nfs.subr

# Print server statistic $2 of jail $1, as named by nfsstat(1) --libxo.
srvstat()
{
	jexec $1 nfsstat -e -s --libxo xml |
	    sed -n "s|.*<$2>\([0-9]*\)</$2>.*|\1|p"
}

# Check that c2 opening a file for writing recalls the delegation that c1
# holds, with extra mount options $1.
recall_check()
{
	local i m1 m2 ret t0

	nfs_init
	nfs_require_clients 2
	sysctl -n vfs.nfsd.issue_delegations > issue_delegations
	atf_check -o ignore sysctl vfs.nfsd.issue_delegations=1
	nfs_server_start srv
	# Only a client running nfscbd(8) gets delegations.
	nfs_client_start c1 allow.nfsd
	atf_check jexec c1 nfscbd
	nfs_client_start c2
	nfs_mount c1 $(nfs_addr srv) $1
	nfs_mount c2 $(nfs_addr srv) $1
	m1=$(nfs_mnt c1)
	m2=$(nfs_mnt c2)

	echo one > srv/export/file
	# The server checks the callback path first: retry until c1 opens
	# the file with a delegation.
	for i in $(seq 10); do
		atf_check -o inline:"one\n" cat ${m1}/file
		[ "$(srvstat srv delegs)" -gt 0 ] && break
		sleep 1
	done
	[ "$(srvstat srv delegs)" -gt 0 ] || atf_fail "no delegation issued"
	ret=$(srvstat srv delreg)

	t0=$(date +%s)
	echo two >> ${m2}/file
	[ $(($(date +%s) - t0)) -le ${NFS_MAX_STALL} ] ||
	    atf_fail "write waited $(($(date +%s) - t0))s for the recall"
	[ "$(srvstat srv delreg)" -gt ${ret} ] ||
	    atf_fail "c1 did not return its delegation"
	atf_check -o inline:"one\ntwo\n" cat ${m1}/file
}

atf_test_case "recall" "cleanup"
recall_head()
{
	atf_set descr 'NFSv4.1: a conflicting open recalls a delegation'
	atf_set require.user root
	atf_set timeout 120
}

recall_body()
{
	recall_check
}

recall_cleanup()
{
	nfs_cleanup
	[ -f issue_delegations ] &&
	    sysctl vfs.nfsd.issue_delegations=$(cat issue_delegations) > /dev/null
	true
}

atf_init_test_cases()
{
	atf_add_test_case "recall"
}
