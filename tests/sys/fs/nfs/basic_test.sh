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

. $(atf_get_srcdir)/nfs.subr

atf_test_case "basic" "cleanup"
basic_head()
{
	atf_set descr 'NFSv4.1 file operations against a vnet jail server'
	atf_set require.user root
}

basic_body()
{
	basic_io
}

basic_cleanup()
{
	nfs_cleanup
}

atf_test_case "v40_basic" "cleanup"
v40_basic_head()
{
	atf_set descr 'NFSv4.0 file operations against a vnet jail server'
	atf_set require.user root
}

v40_basic_body()
{
	basic_io minorversion=0
}

v40_basic_cleanup()
{
	nfs_cleanup
}

# Mount a server with extra mount options $1 and check file operations.
basic_io()
{
	local cl m

	nfs_init
	nfs_server_start srv
	nfs_client_start c1
	cl=$(nfs_client c1)
	nfs_mount ${cl} $(nfs_addr srv) $1
	basic_files $(nfs_mnt ${cl})
}

# Check file operations in mount point $1 of server srv.
basic_files()
{
	local m=$1

	echo hello > $m/file
	atf_check -o inline:"hello\n" cat $m/file
	atf_check -o inline:"hello\n" cat srv/export/file
	atf_check mkdir $m/dir
	atf_check mv $m/file $m/dir/renamed
	atf_check -o inline:"renamed\n" ls $m/dir
	atf_check dd if=/dev/random of=$m/big bs=1m count=8 status=none
	atf_check -o save:big.sum sha256 -q $m/big
	atf_check -o file:big.sum sha256 -q srv/export/big
	atf_check rm -r $m/dir $m/big
	atf_check -o empty ls srv/export
}

atf_test_case "v3_basic" "cleanup"
v3_basic_head()
{
	atf_set descr 'NFSv3 file operations against a vnet jail server, no NLM'
	atf_set require.user root
	atf_set require.progs rpcbind
}

v3_basic_body()
{
	local cl m

	nfs_init
	nfs_server_start_v3 srv
	nfs_client_start c1
	cl=$(nfs_client c1)
	# NLM cannot run in a jail: lock locally.
	nfs_mount ${cl} $(nfs_addr srv) nfsv3,tcp,nolockd
	m=$(nfs_mnt ${cl})
	# The line after "<server> on <mount point>" lists its options.
	atf_check -o match:nfsv3 -x \
	    "nfsstat -m | awk -v m=$m '\$NF == m { getline; print }'"
	echo locked > $m/lockfile
	atf_check lockf -k -w -t 0 $m/lockfile true
	atf_check rm $m/lockfile
	basic_files $m
}

v3_basic_cleanup()
{
	nfs_cleanup
}

atf_test_case "v40_server_freed" "cleanup"
v40_server_freed_head()
{
	atf_set descr 'A server jail goes away after its NFSv4.0 client unmounts'
	atf_set require.user root
}

v40_server_freed_body()
{
	local cl m

	nfs_init
	nfs_server_start srv
	nfs_client_start c1
	cl=$(nfs_client c1)
	nfs_mount ${cl} $(nfs_addr srv) minorversion=0
	m=$(nfs_mnt ${cl})
	echo hello > $m/file
	atf_check -o inline:"hello\n" cat $m/file
	# NFSv4.0 has no DESTROY_CLIENTID: the server keeps the client.
	nfs_umount ${cl}
	nfs_jail_remove srv 10
}

v40_server_freed_cleanup()
{
	nfs_cleanup
}

atf_test_case "two_clients" "cleanup"
two_clients_head()
{
	atf_set descr 'Two NFSv4.1 clients share data and see each other locks'
	atf_set require.user root
}

two_clients_body()
{
	local i m1 m2

	nfs_init
	nfs_require_clients 2
	nfs_server_start srv
	nfs_client_start c1
	nfs_client_start c2
	nfs_mount c1 $(nfs_addr srv)
	nfs_mount c2 $(nfs_addr srv)
	m1=$(nfs_mnt c1)
	m2=$(nfs_mnt c2)

	echo from-c1 > $m1/file
	atf_check -o inline:"from-c1\n" cat $m2/file
	# A lock held through c1 conflicts with one asked through c2.
	lockf -w -k $m1/file sleep 10 &
	for i in $(seq 10); do
		lockf -k -w -t 0 $m2/file true 2>/dev/null || break
		sleep 0.5
	done
	atf_check -s exit:75 -e ignore lockf -k -w -t 0 $m2/file true
	wait
	atf_check lockf -w -t 0 $m2/file true
}

two_clients_cleanup()
{
	nfs_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "basic"
	atf_add_test_case "v40_basic"
	atf_add_test_case "v3_basic"
	atf_add_test_case "v40_server_freed"
	atf_add_test_case "two_clients"
}
