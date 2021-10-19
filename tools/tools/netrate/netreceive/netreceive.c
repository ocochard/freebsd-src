/*-
 * Copyright (c) 2004 Robert N. M. Watson
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/sysctl.h>     /* sysctl */

#include <netinet/in.h>
#include <netdb.h>          /* getaddrinfo */

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         /* close */

#define MAXSOCK 20

#include <pthread.h>
#include <pthread_np.h>
#include <fcntl.h>
#include <time.h>	/* clock_getres() */

/* sysctl wrapper to return the number of active CPUs
   function from netmap/pkt-gen.c */
static int
system_ncpus(void)
{
    int ncpus;
    int mib[2] = { CTL_HW, HW_NCPU };
    size_t len = sizeof(mib);
    sysctl(mib, 2, &ncpus, &len, NULL, 0);
    return (ncpus);
}

/* set the thread affinity
   function from netmap/pkt-gen.c */
static int
setaffinity(pthread_t me, int i)
{
    cpuset_t cpumask;

    if (i == -1)
        return 0;

    /* Set thread affinity affinity.*/
    CPU_ZERO(&cpumask);
    CPU_SET(i, &cpumask);
    if (pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0) {
        perror("Unable to set affinity");
        return 1;
    }
    return 0;
}

static int round_to(int n, int l)
{
	return ((n + l - 1)/l)*l;
}

/*
 * Each socket uses multiple threads so the receiver is
 * more efficient. A collector thread runs the stats.
 */
struct td_desc {
	pthread_t td_id;
	uint64_t count;	/* rx counter */
	uint64_t byte_count;	/* rx byte counter */
	char *buf;
	char *argv;
	int buflen;
};

static void
usage(void)
{

	fprintf(stderr, "netreceive port [nthreads]\n");
	exit(-1);
}

static __inline void
timespec_add(struct timespec *tsa, struct timespec *tsb)
{

        tsa->tv_sec += tsb->tv_sec;
        tsa->tv_nsec += tsb->tv_nsec;
        if (tsa->tv_nsec >= 1000000000) {
                tsa->tv_sec++;
                tsa->tv_nsec -= 1000000000;
        }
}

static __inline void
timespec_sub(struct timespec *tsa, struct timespec *tsb)
{

        tsa->tv_sec -= tsb->tv_sec;
        tsa->tv_nsec -= tsb->tv_nsec;
        if (tsa->tv_nsec < 0) {
                tsa->tv_sec--;
                tsa->tv_nsec += 1000000000;
        }
}

static void *
rx_body(void *data)
{
	struct td_desc *t = data;
	struct addrinfo hints = {0}, *res = NULL , *res0 = NULL;
	struct pollfd fds;
	int error, y;
	const char *cause = NULL;

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

    int v = 1; /* dummy value for setsockopt */
	error = getaddrinfo(NULL, t->argv, &hints, &res0);
	if (error) {
		perror(gai_strerror(error));
		return NULL;
		/*NOTREACHED*/
	}

	int s = -1; /* socket */
	for (res = res0; res ; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s < 0) {
			cause = "socket";
			continue;
		}

#if __FreeBSD_version <= 1200069
		if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &v, sizeof v) < 0) {
			cause = "SO_REUSEPORT";
#else
		if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT_LB, &v, sizeof v) < 0) {
            cause = "SO_REUSEPORT_LB";
#endif
			close(s);
			continue;
		}

		v = 128 * 1024;
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)) < 0) {
			cause = "SO_RCVBUF";
			close(s);
			continue;
		}
		if (bind(s, res->ai_addr, res->ai_addrlen) < 0) {
			cause = "bind";
			close(s);
			continue;
		}
		(void) listen(s, 5);
	}
	if (s < 0) {
		perror(cause);
		return NULL;
		/*NOTREACHED*/
	}

	fds.fd = s;
	fds.events = POLLIN;

	for (;;) {
		if (poll(&fds, 1, -1) < 0)
			perror("poll on thread");
		if (!(fds.revents & POLLIN))
			continue;
		for (;;) {
			y = recv(s, t->buf, t->buflen, MSG_DONTWAIT);
			if (y < 0)
				break;
			t->count++;
			t->byte_count += y;
		}
	}
	return NULL;
}

static struct td_desc **
make_threads(char *argv, int nthreads)
{
	int lb = round_to(nthreads * sizeof (struct td_desc *), 64);
	int td_len = round_to(sizeof(struct td_desc), 64); // cache align
	char *m = calloc(1, lb + td_len * nthreads);
	struct td_desc **tp;

	printf("td len %d -> %d\n", (int)sizeof(struct td_desc) , td_len);
	/* pointers plus the structs */
	if (m == NULL) {
		perror("no room for pointers!");
		exit(1);
	}
	tp = (struct td_desc **)m;
	m += lb;	/* skip the pointers */
	int ncpu = system_ncpus();
	for (int i = 0; i < nthreads; i++, m += td_len) {
		tp[i] = (struct td_desc *)m;
		tp[i]->argv = argv;
		tp[i]->buflen = 65536;
		tp[i]->buf = calloc(1, tp[i]->buflen);
		if (pthread_create(&tp[i]->td_id, NULL, rx_body, tp[i])) {
			perror("unable to create thread");
			exit(1);
		}
		if (setaffinity(tp[i]->td_id, i % ncpu)) {
            perror("unable to set thread affinity");
        }

	}
	return tp;
}

static void
main_thread(struct td_desc **tp, int nthreads)
{
	uint64_t c0, c1, bc0, bc1;
	struct timespec now, then, delta;
	/* now the parent collects and prints results */
	c0 = c1 = bc0 = bc1 = 0;
	uint64_t old[128] = {0};
	clock_gettime(CLOCK_REALTIME, &then);
	fprintf(stderr, "start at %jd.%09ld\n", (__intmax_t)then.tv_sec, then.tv_nsec);
	while (1) {
		int64_t dn;
		uint64_t pps, bps;

		if (poll(NULL, 0, 500) < 0)
			perror("poll");
		c0 = bc0 = 0;
		for (int i = 0; i < nthreads; i++) {
			c0 += tp[i]->count;
			bc0 += tp[i]->byte_count;
			/* printf("thread %d: recv %lu ", i, tp[i]->count - old[i]); */
			old[i] = tp[i]->count;
		}
		/* printf("\n"); */
		dn = c0 - c1;
		clock_gettime(CLOCK_REALTIME, &now);
		delta = now;
		timespec_sub(&delta, &then);
		then = now;
		pps = dn;
		pps = (pps * 1000000000) / (delta.tv_sec*1000000000 + delta.tv_nsec + 1);
		bps = ((bc0 - bc1) * 8000000000) / (delta.tv_sec*1000000000 + delta.tv_nsec + 1);
		fprintf(stderr, " %9ld pps %8.3f Mbps", (long)pps, .000001*bps);
		fprintf(stderr, " - %d pkts in %jd.%09ld ns\n",
			(int)dn, (__intmax_t)delta.tv_sec, delta.tv_nsec);
		c1 = c0;
		bc1 = bc0;
	}
}

int
main(int argc, char *argv[])
{
	char *dummy, *packet;
	int port;
	int nthreads = 1;
	struct td_desc **tp;

	if (argc < 2)
		usage();

	port = strtoul(argv[1], &dummy, 10);
	if (port < 1 || port > 65535 || *dummy != '\0')
		usage();
	if (argc > 2)
		nthreads = strtoul(argv[2], &dummy, 10);
	if (nthreads < 1)
		usage();
	int ncpu = system_ncpus();
    if (nthreads > ncpu) {
        printf("WARNING: %d threads but only %d core(s) available\n", nthreads, ncpu);
    }

	packet = malloc(65536);
	if (packet == NULL) {
		perror("malloc");
		return (-1);
	}
	bzero(packet, 65536);

	printf("netreceive using %d threads listening on UDP port %d\n",
		nthreads, (u_short)port);

	tp = make_threads(argv[1], nthreads);
	main_thread(tp, nthreads);
}
