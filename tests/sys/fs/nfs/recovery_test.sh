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
# Client recovery when the server loses its state (RFC 8881 Section 8.4.2),
# driven by nfs_reset_proxy.py.
#

. $(atf_get_srcdir)/nfs.subr

# Mount through the proxy and start probing.
recovery_setup()
{
	local cl

	nfs_init
	nfs_server_start srv
	nfs_client_start c1
	cl=$(nfs_client c1)
	nfs_proxy_start srv
	nfs_mount ${cl} $(nfs_addr proxy)
	nfs_probe_start $(nfs_mnt ${cl})
	sleep 3
}

atf_test_case "server_reset" "cleanup"
server_reset_head()
{
	atf_set descr 'Recover once the server loses the session and client ID'
	atf_set require.user root
	atf_set require.progs python3
	atf_set timeout 180
}

server_reset_body()
{
	local t0

	recovery_setup
	t0=$(date +%s)
	nfs_reset
	sleep 20

	atf_check -o not-empty grep "inject 10052" proxy.log
	atf_check -o not-empty grep "inject 10022" proxy.log
	nfs_probe_check ${t0}
}

server_reset_cleanup()
{
	nfs_cleanup
}

atf_test_case "server_reset_twice" "cleanup"
server_reset_twice_head()
{
	atf_set descr 'Recover from two server resets within one renewal period'
	atf_set require.user root
	atf_set require.progs python3
	atf_set timeout 300
}

server_reset_twice_body()
{
	local t0

	recovery_setup
	# The client allows one full recovery per nfsc_renew (half the lease,
	# 60s with nfsd): reset again well inside it, then wait for it to end.
	t0=$(date +%s)
	nfs_reset
	sleep 15
	nfs_reset
	sleep 60

	atf_check -o not-empty grep "inject 10022" proxy.log
	nfs_probe_check ${t0}
}

server_reset_twice_cleanup()
{
	nfs_cleanup
}

atf_test_case "session_leak" "cleanup"
session_leak_head()
{
	atf_set descr 'Free the sessions that recovery replaced'
	atf_set require.user root
	atf_set require.progs python3
	atf_set timeout 300
}

session_leak_body()
{
	local i n0 n

	n0=$(nfs_sessions)
	recovery_setup
	for i in 1 2 3; do
		nfs_reset
		sleep 20
	done
	# A replaced session is freed 2 x nfsc_renew (120s with nfsd) after
	# the recovery that replaced it.
	sleep 120

	# The mount and each recovery create a session.
	[ $(grep -c 'learn session' proxy.log) -ge 4 ] ||
	    atf_fail "not every reset caused a recovery"
	n=$(nfs_sessions)
	atf_expect_fail "Sessions replaced by recovery are freed only at unmount"
	[ ${n} -le $((n0 + 1)) ] ||
	    atf_fail "$((n - n0)) sessions in use for one mount"
}

session_leak_cleanup()
{
	nfs_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "server_reset"
	atf_add_test_case "server_reset_twice"
	atf_add_test_case "session_leak"
}
