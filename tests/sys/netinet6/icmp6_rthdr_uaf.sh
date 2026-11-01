#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Olivier Cochard <olivier@FreeBSD.org>
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

. $(atf_get_srcdir)/../common/vnet.subr

atf_test_case "icmp6_rthdr_uaf" "cleanup"
icmp6_rthdr_uaf_head()
{
	atf_set descr 'ICMPv6 error quoting a fragmented routing header: use-after-free in icmp6_notify_error()'
	atf_set require.user root
	atf_set require.progs python3 scapy
}

icmp6_rthdr_uaf_body()
{
	id=`printf "%x" $$`

	vnet_init

	ip6a="2001:db8:6666::1:${id}"
	ip6b="2001:db8:6666::2:${id}"

	epair=$(vnet_mkepair)
	ifconfig ${epair}a up
	ifconfig ${epair}a inet6 ${ip6a}/64 no_dad

	jname="v6uaf-${id}"
	vnet_mkjail ${jname} ${epair}b
	jexec ${jname} sysctl net.inet6.ip6.dad_count=0
	jexec ${jname} ifconfig ${epair}b up
	jexec ${jname} ifconfig ${epair}b inet6 ${ip6b}/64 no_dad

	# Let neighbour discovery settle so the target answers our echo.
	while [ `ifconfig ${epair}a inet6 | grep -c tentative` != "0" ]; do
		sleep 0.1
	done

	# The script sends the crafted two-fragment ICMPv6 error and then an
	# echo request; it exits non-zero if the target stops answering, which
	# is what a panic (or KASAN report plus wedge) looks like from outside.
	atf_check -s exit:0 $(atf_get_srcdir)/icmp6_rthdr_uaf.py \
		--sendif ${epair}a --recvif ${epair}a \
		--src ${ip6a} --to ${ip6b}
}

icmp6_rthdr_uaf_cleanup()
{
	vnet_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "icmp6_rthdr_uaf"
}
