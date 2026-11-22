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
# NFSv4.1 with Kerberos (RFC 7530 Section 3.2, RFC 2203): KDC, nfsd and
# gssd in the server jail, gssd with a host-based keytab entry in the
# client jail.
#

. $(atf_get_srcdir)/nfs.subr

# Export /export with Kerberos only, and prepare client c1 to mount it.
krb5_setup()
{
	nfs_init
	nfs_krb5_require
	if ! nfs_jailed_clients; then
		atf_skip "Kerberos tests need allow.mount.nfs"
	fi
	nfs_server_jail srv -sec=krb5:krb5i:krb5p
	nfs_client_start c1 allow.nfsd
	nfs_kdc_start srv
	nfs_krb5_keytab srv nfs
	nfs_krb5_keytab c1 host
	nfs_gssd_start srv
	nfs_server_run srv
	nfs_gssd_start c1 -h
}

# Capture the NFS traffic on the bridge to wire.pcap.  Without immediate
# mode, packets wait in BPF up to its 1s timeout and are lost at the kill.
krb5_capture_start()
{
	local i

	tcpdump -i $(cat nfs_bridge) --immediate-mode -U -w wire.pcap \
	    tcp port 2049 2> tcpdump.log &
	echo $! > tcpdump.pid
	for i in $(seq 10); do
		grep -q "listening on" tcpdump.log && return 0
		sleep 1
	done
	atf_fail "tcpdump did not start: $(cat tcpdump.log)"
}

# Stop the capture; fail unless it holds NFS packets.
krb5_capture_stop()
{
	sleep 1
	kill $(cat tcpdump.pid)
	wait
	[ $(tcpdump -r wire.pcap 2>/dev/null | wc -l) -gt 0 ] ||
	    atf_fail "no NFS packet captured"
}

# Mount with flavor $1, then write, read back and check on the server.
krb5_check()
{
	local m

	nfs_mount c1 $(nfs_name srv) sec=$1,gssname=host,allgssname
	atf_check -o match:"sec=$1," jexec c1 nfsstat -m
	m=$(nfs_mnt c1)
	echo $2 > $m/file
	atf_check -o inline:"$2\n" cat $m/file
	atf_check -o inline:"$2\n" cat srv/export/file
}

atf_test_case "krb5" "cleanup"
krb5_head()
{
	atf_set descr 'NFSv4.1 with sec=krb5; sec=sys is refused'
	atf_set require.user root
}

krb5_body()
{
	krb5_setup
	atf_check -s not-exit:0 -e ignore jexec c1 mount -t nfs \
	    -o nfsv4,minorversion=1,retrycnt=1,sec=sys $(nfs_name srv):/ /mnt
	krb5_check krb5 hello-krb5
}

krb5_cleanup()
{
	nfs_cleanup
}

atf_test_case "krb5i" "cleanup"
krb5i_head()
{
	atf_set descr 'NFSv4.1 with sec=krb5i: integrity, data in clear'
	atf_set require.user root
	atf_set require.progs tcpdump
}

krb5i_body()
{
	krb5_setup
	krb5_capture_start
	krb5_check krb5i nfstest-marker-krb5i
	krb5_capture_stop
	atf_check -o not-empty grep -a nfstest-marker-krb5i wire.pcap
}

krb5i_cleanup()
{
	nfs_cleanup
}

atf_test_case "krb5p" "cleanup"
krb5p_head()
{
	atf_set descr 'NFSv4.1 with sec=krb5p: data encrypted on the wire'
	atf_set require.user root
	atf_set require.progs tcpdump
}

krb5p_body()
{
	krb5_setup
	krb5_capture_start
	krb5_check krb5p nfstest-marker-krb5p
	krb5_capture_stop
	atf_check -s exit:1 grep -a -q nfstest-marker-krb5p wire.pcap
}

krb5p_cleanup()
{
	nfs_cleanup
}

atf_test_case "server_freed" "cleanup"
server_freed_head()
{
	atf_set descr 'A Kerberos server jail goes away after its client unmounts'
	atf_set require.user root
}

server_freed_body()
{
	krb5_setup
	krb5_check krb5 nfstest-marker-freed
	nfs_umount c1
	nfs_jail_remove srv 10
}

server_freed_cleanup()
{
	nfs_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "krb5"
	atf_add_test_case "krb5i"
	atf_add_test_case "krb5p"
	atf_add_test_case "server_freed"
}
