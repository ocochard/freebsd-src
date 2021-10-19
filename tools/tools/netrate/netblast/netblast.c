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

#include <sys/endian.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/sysctl.h> 	/* sysctl */

#include <netinet/in.h>
#include <netdb.h>			/* getaddrinfo */

#include <signal.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>			/* close */
#include <sys/cpuset.h>
#include <pthread.h>
#include <pthread_np.h>
#include <fcntl.h>
#include <time.h>   /* clock_getres() */

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

static void
usage(void)
{

	fprintf(stderr, "netblast [ip] [port] [payloadsize] [duration] [nthreads]\n");
	exit(-1);
}

static bool	global_stop_flag=true;

static void
signal_handler(int signum __unused)
{

	global_stop_flag = false;
}

/*
 * Each socket uses multiple threads so the generator is
 * more efficient. A collector thread runs the stats.
 */
struct td_desc {
	pthread_t td_id;
	uint64_t counter; /* tx counter */
	uint64_t send_errors; /* tx send errors */
	uint64_t send_calls;    /* tx send calls */
	char *address, *port;
	int family;
	u_char *packet;
	u_int packet_len;
};

static void *
blast(void *data)
{
    struct td_desc *t = data;
	t->counter=0;
	t->send_errors=0;
	t->send_calls=0;

	struct addrinfo hints = {0}, *res = NULL , *res0 = NULL;

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	int error = getaddrinfo(t->address,t->port, &hints, &res0);
	if (error) {
		perror(gai_strerror(error));
		return NULL;
		/*NOTREACHED*/
	}

	int s = -1; /* socket */
	int n = 1; /* dummy value for setsockopt */
	const char *cause = NULL;

	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, 0);
		if (s < 0) {
			cause = "socket";
			continue;
		}

		if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &n, sizeof n) < 0) {
            cause = "SO_REUSEPORT";
            close(s);
			s = -1;
            continue;
        }

		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
			cause = "connect";
			close(s);
			s = -1;
			continue;
		}

		break;  /* okay we got one */
	}
	if (s < 0) {
		perror(cause);
		return NULL;
		/*NOTREACHED*/
	}

	/* Store address family for Ethernet bandwitdh estimation */
	t->family=res->ai_family;

	while (global_stop_flag) {
		/*
		 * We maintain and, if there's room, send a counter.  Note
		 * that even if the error is purely local, we still increment
		 * the counter, so missing sequence numbers on the receive
		 * side should not be assumed to be packets lost in transit.
		 * For example, if the UDP socket gets back an ICMP from a
		 * previous send, the error will turn up the current send
		 * operation, causing the current sequence number also to be
		 * skipped.
		 */
		if (t->packet_len >= 4) {
			be32enc(t->packet, t->counter);
			t->counter++;
		}
		if (send(s, t->packet, t->packet_len, 0) < 0)
			t->send_errors++;
		t->send_calls++;
	}
    return NULL;
}

static struct td_desc **
make_threads(char *address, char *port, u_char *packet, u_int packet_len, int nthreads)
{
    int i;
    int lb = round_to(nthreads * sizeof (struct td_desc *), 64);
    int td_len = round_to(sizeof(struct td_desc), 64); // cache align
    char *m = calloc(1, lb + td_len * nthreads);
    struct td_desc **tp;

    /* pointers plus the structs */
    if (m == NULL) {
        perror("no room for pointers!");
        exit(1);
    }
    tp = (struct td_desc **)m;
    m += lb;    /* skip the pointers */
	int ncpu = system_ncpus();
    for (i = 0; i < nthreads; i++, m += td_len) {
        tp[i] = (struct td_desc *)m;
        tp[i]->address = address;
		tp[i]->port = port;
        tp[i]->packet = packet;
        tp[i]->packet_len = packet_len;
        if (pthread_create(&tp[i]->td_id, NULL, blast, tp[i])) {
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
main_thread(struct td_desc **tp, long duration, struct timespec starttime, struct timespec tmptime, long payloadsize, int nthreads)
{
	uint64_t send_errors=0, send_calls=0;
	if (clock_gettime(CLOCK_REALTIME, &tmptime) == -1) {
		perror("clock_gettime");
	}

	for (int i = 0; i < nthreads; i++) {
		/* Wait for thread end */
		pthread_join( tp[i]->td_id, NULL);
		send_calls+=tp[i]->send_calls;
		send_errors+=tp[i]->send_errors;
    }

	printf("\n");
	printf("start:                      %zd.%09lu\n", starttime.tv_sec,
	    starttime.tv_nsec);
	printf("finish:                     %zd.%09lu\n", tmptime.tv_sec,
	    tmptime.tv_nsec);
	printf("send calls:                 %" PRIu64 "\n", send_calls);
	printf("send errors:                %" PRIu64 "\n", send_errors);
	printf("send success:               %" PRIu64 "\n", send_calls - send_errors);
	printf("approx send rate:           %" PRIu64 "\n", (send_calls - send_errors) /
	    duration);
	printf("approx error rate:          %" PRIu64 "\n", (send_errors / send_calls));
	printf("approx Ethernet throughput: ");
	if (tp[0]->family == AF_INET)
		printf("%" PRIu64 " Mib/s\n", ((send_calls - send_errors) / duration ) *
		(payloadsize + 8 + 20 + 14 ) * 8 / 1000 / 1000);
	else if (tp[0]->family == AF_INET6)
		printf("%" PRIu64 " Mib/s\n", ((send_calls - send_errors) / duration ) *
		(payloadsize + 8 + 40 + 14 ) * 8 / 1000 / 1000);
	else printf("CAN 'T DETERMINE family type %i\n",tp[0]->family);
	printf("approx payload throughput:  %" PRIu64 " Mib/s\n", ((send_calls - send_errors) /
		duration ) * payloadsize * 8 / 1000 / 1000);
}

int
main(int argc, char *argv[])
{
	long payloadsize, duration;
	char *dummy;
	u_char *packet;
	int port, nthreads = 1;
	struct td_desc **tp;
	struct timespec starttime, tmptime;
	struct itimerval it;



	if (argc < 5)
		usage();

	port = strtoul(argv[2], &dummy, 10);
	if (port < 1 || port > 65535 || *dummy != '\0') {
		fprintf(stderr, "Invalid port number: %s\n", argv[2]);
		usage();
		/*NOTREACHED*/
	}

	payloadsize = strtoul(argv[3], &dummy, 10);
	if (payloadsize < 0 || *dummy != '\0')
		usage();
	if (payloadsize > 32768) {
		fprintf(stderr, "payloadsize > 32768\n");
		return (-1);
		/*NOTREACHED*/
	}

	duration = strtoul(argv[4], &dummy, 10);
	if (duration < 0 || *dummy != '\0') {
		fprintf(stderr, "Invalid duration time: %s\n", argv[4]);
		usage();
		/*NOTREACHED*/
	}

	if (argc > 5)
		nthreads = strtoul(argv[5], &dummy, 10);
	if (nthreads < 1)
		usage();
	int ncpu = system_ncpus();
	if (nthreads > ncpu) {
		printf("WARNING: %d threads but only %d core(s) available\n", nthreads, ncpu);
	}

	packet = malloc(payloadsize);
	if (packet == NULL) {
		perror("malloc");
		return (-1);
		/*NOTREACHED*/
	}

	bzero(packet, payloadsize);

	printf("netblast %d threads sending on UDP port %d during %lu seconds\n",
    nthreads, (u_short)port, duration);

	/*
	 * Begin by recording time information stats.
	 * Set the interval timer for when we want to wake up.
	 * SIGALRM will set a flag indicating it's time to stop.  Note that there's
	 * some overhead to the signal and timer setup, so the smaller the duration,
	 * the higher the relative overhead.
	 */

	if (signal(SIGALRM, signal_handler) == SIG_ERR) {
		perror("signal");
		return (-1);
	}

	if (clock_getres(CLOCK_REALTIME, &tmptime) == -1) {
		perror("clock_getres");
		return (-1);
	}

	if (clock_gettime(CLOCK_REALTIME, &starttime) == -1) {
		perror("clock_gettime");
		return (-1);
	}

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_usec = 0;
	it.it_value.tv_sec = duration;
	it.it_value.tv_usec = 0;

	if (setitimer(ITIMER_REAL, &it, NULL) < 0) {
		perror("setitimer");
		return (-1);
	}

    tp = make_threads(argv[1],argv[2], packet, payloadsize, nthreads);
    main_thread(tp, duration, starttime,  tmptime, payloadsize, nthreads);

}
