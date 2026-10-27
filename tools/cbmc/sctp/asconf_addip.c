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
 * cbmc(1) harness for sctp_process_asconf_add_ip(), sys/netinet/sctp_asconf.c:
 * validate and act on one inbound ASCONF "add IP address" parameter.  The
 * parameter has been copied into a buffer of aparam_length bytes; this
 * function casts the inner address parameter to a fixed sctp_ipv4addr_param /
 * sctp_ipv6addr_param and reads the address out of it.  The size checks
 * (aparam_length lower bound, param_length + asconf-hdr == aparam_length, and
 * param_length == the address-param size) must ensure that read stays within
 * the aparam_length-byte buffer.
 *
 * Not a program: run.sh compiles it with SOURCE naming sctp_asconf.c or a
 * mutant of it, included whole.  The parameter is a CBMC object of exactly
 * APLEN bytes, so a cast read past it is an out-of-bounds read.  The
 * address-add tail (sctp_add_remote_addr and the notify/timer/hb calls) is
 * stubbed via --replace-calls so the proof is the parse/validate/read core.
 * The buffer bytes are nondeterministic except the two length fields and the
 * param type, which are set so a chosen param reaches the address read; APLEN
 * is a constant per job.
 *
 * The entry point, for --function:
 *
 *   proof_asconf_addip	sctp_process_asconf_add_ip() on an APLEN-byte add-IP
 *			parameter: the address read stays within the buffer.
 */

#include SOURCE

#include <sys/mbuf.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <sys/counter.h>
#include "kern.h"

/* Stubs for the address-add tail (pcb/timer/notify), replaced by run.sh. */
int
cbmc_add_remote_addr(struct sctp_tcb *stcb, struct sockaddr *newaddr,
    struct sctp_nets **netp, uint16_t port, int set_scope, int so)
{
	return (0);
}
void cbmc_ulp_notify(uint32_t n, struct sctp_tcb *s, uint32_t e, void *d,
    int l) { }
void cbmc_timer_start(int t, struct sctp_inpcb *i, struct sctp_tcb *s,
    struct sctp_nets *n) { }
void cbmc_send_hb(struct sctp_tcb *s, struct sctp_nets *n, int l) { }

static struct sctp_tcb g_stcb;
static union sctp_sockstore g_src;

void
proof_asconf_addip(void)
{
	struct sctp_asconf_paramhdr *aph;
	struct sctp_paramhdr *ph;
	uint8_t *buf;
	int i;

	/*
	 * The ASCONF parameter the caller copied in, a buffer of exactly APLEN
	 * bytes.  Its bytes are nondeterministic; the harness sets only the two
	 * length fields and the inner param type so a given address parameter is
	 * reached, exactly as a wire packet would carry them.
	 */
	buf = __CPROVER_allocate(APLEN == 0 ? 1 : APLEN, 0);
	for (i = 0; i < APLEN; i++)
		buf[i] = nondet_char();

	aph = (struct sctp_asconf_paramhdr *)buf;
	aph->ph.param_length = htons(APLEN);
	ph = (struct sctp_paramhdr *)(aph + 1);
	ph->param_length = htons(APLEN - sizeof(struct sctp_asconf_paramhdr));
	ph->param_type = htons(PTYPE);
	/*
	 * Pin the address to a plain unicast value so the flow reaches the
	 * (stubbed) address-add rather than the bad/zero-address error-response
	 * path, which builds an error mbuf -- out of scope for this read proof.
	 * The address field follows the inner paramhdr.  The read of it, the
	 * memory-safety property, is unaffected by its value.
	 */
#if PTYPE == SCTP_IPV4_ADDRESS
	if (APLEN >= (int)sizeof(struct sctp_ipv4addr_param) +
	    (int)sizeof(struct sctp_asconf_paramhdr)) {
		struct sctp_ipv4addr_param *v4 = (struct sctp_ipv4addr_param *)ph;
		v4->addr = htonl(0x01010101);
	}
#elif PTYPE == SCTP_IPV6_ADDRESS
	{
		struct sctp_ipv6addr_param *v6 = (struct sctp_ipv6addr_param *)ph;
		for (i = 0; i < (int)sizeof(v6->addr); i++)
			v6->addr[i] = (i == 0) ? 0x20 : 0x01;
	}
#endif

	g_src.sa.sa_family = AF_INET;
	g_src.sa.sa_len = sizeof(struct sockaddr_in);

	(void)sctp_process_asconf_add_ip(&g_src.sa, aph, &g_stcb, 0, 0);
	/*
	 * The address read (v4addr->addr / v6addr->addr) was bounds-checked
	 * against the APLEN buffer during the call; the size checks keep it
	 * within the parameter.
	 */
}
