/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Olivier Cochard <olivier@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * cbmc(1) harness for ip_dooptions(), sys/netinet/ip_options.c: the IPv4
 * options parser run on every received packet that carries options.  It
 * walks the option area, trusting each option's length byte and advancing
 * by it, and for record-route and timestamp options reads and writes at
 * an attacker-influenced pointer (off) into the option area.  Every such
 * access must stay within the option area; the length and pointer checks
 * in the loop are what keep it there.
 *
 * Not a program: run.sh compiles it with SOURCE naming ip_options.c or a
 * mutant of it, included whole.  The packet is a struct ip followed by
 * OPTLEN option bytes, one CBMC object, with the option bytes
 * nondeterministic so the parser faces every option layout.  ip_hl is set
 * so the option area is exactly OPTLEN bytes; a read or write past the
 * object is an out-of-bounds access CBMC catches.  The interface, route
 * and ICMP helpers the opcodes reach are modelled.  OPTLEN is a constant
 * per job (a symbolic length ran the parser past the time budget).
 *
 * The entry point, for --function:
 *
 *   proof_dooptions	ip_dooptions() on a header with OPTLEN option bytes
 *			of any value: every option access stays within the
 *			option area, whatever the lengths and pointers the
 *			bytes encode.
 */

#include SOURCE

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

#ifndef OPTLEN
#define	OPTLEN	12		/* option bytes after the fixed IP header */
#endif

/*
 * The interface address the option opcodes copy from.  It must be a
 * struct in_ifaddr, because IA_SIN() casts the ifaddr to that and reads
 * its embedded ia_addr (a struct sockaddr_in); a plain struct ifaddr
 * would be too small.  nh_ifa points at it, as the real nhop guarantees.
 */
static struct in_ifaddr g_ia;
static struct nhop_object g_nh;

int
ifa_ifwithaddr_check(const struct sockaddr *sa)
{
	return (nondet_bool());
}

struct ifaddr *
ifa_ifwithaddr(const struct sockaddr *sa)
{
	return (nondet_bool() ? &g_ia.ia_ifa : NULL);
}

struct ifaddr *
ifaof_ifpforaddr(const struct sockaddr *sa, if_t ifp)
{
	return (nondet_bool() ? &g_ia.ia_ifa : NULL);
}

struct nhop_object *
fib4_lookup(uint32_t fibnum, struct in_addr dst, uint32_t scopeid,
    uint32_t flags, uint32_t flowid)
{
	g_nh.nh_ifa = &g_ia.ia_ifa;		/* always non-NULL, per the KPI */
	return (nondet_bool() ? &g_nh : NULL);
}

void icmp_error(struct mbuf *m, int type, int code, uint32_t dest, int mtu) { }
void ip_forward(struct mbuf *m, int srcrt) { }
void m_freem(struct mbuf *m) { }	/* the bad path frees the packet */
uint32_t iptime(void) { return (nondet_uint()); }

/*
 * m_tag_alloc() returns NULL, so save_rte() (the only tag user reached)
 * takes its early return without touching tag storage.  The option read it
 * would do is already bounded by the caller's optlen <= cnt check.
 */
struct m_tag *
m_tag_alloc(uint32_t cookie, uint16_t type, int len, int wait)
{
	return (NULL);
}

/* VNET sysctls that live outside this file; VNET() is identity here. */
int ipforwarding;
int ipstealth;

/* NET_EPOCH_ASSERT(): in the net epoch; and the log helpers on a bad path. */
int in_epoch(epoch_t epoch) { return (1); }
void log(int level, const char *fmt, ...) { }
char *
inet_ntoa_r(struct in_addr ina, char *buf)
{
	buf[0] = 0;
	return (buf);
}

/*
 * The packet: a struct ip then OPTLEN option bytes, one object.  g_ifa's
 * address field is what the record-route/timestamp copies read from.
 */
union {
	struct ip ip;
	u_char b[sizeof(struct ip) + OPTLEN];
} g_pkt;
static struct mbuf g_m;

void
proof_dooptions(void)
{
	int i;

	/* A received IPv4 packet whose header claims OPTLEN option bytes. */
	g_pkt.ip.ip_hl = (sizeof(struct ip) + OPTLEN) >> 2;
	g_pkt.ip.ip_v = IPVERSION;
	for (i = 0; i < OPTLEN; i++)
		g_pkt.b[sizeof(struct ip) + i] = nondet_char();

	bzero(&g_m, sizeof(g_m));
	g_m.m_data = (caddr_t)&g_pkt;
	g_m.m_len = sizeof(struct ip) + OPTLEN;
	g_m.m_flags = M_PKTHDR;
	g_m.m_pkthdr.len = g_m.m_len;
	g_m.m_pkthdr.rcvif = NULL;

	/*
	 * No explicit assertion: every cp[...] read and memcpy(cp + off, ...)
	 * write in the parser is bounds-checked against the packet object, so
	 * a length byte or pointer that would walk past the option area fails
	 * here.  V_ip_doopts must be 1 (process options) to enter the walk.
	 */
	V_ip_doopts = 1;
	(void)ip_dooptions(&g_m, nondet_int());
}
