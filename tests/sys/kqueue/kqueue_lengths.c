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

#include <sys/event.h>

#include <atf-c.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

/*
 * A negative event list length is refused with EINVAL, even when a change
 * would report an EV_ERROR event, and the change is not applied.
 */
ATF_TC_WITHOUT_HEAD(negative_nevents);
ATF_TC_BODY(negative_nevents, tc)
{
	struct kevent kev, out[2];
	int kq, p[2];

	ATF_REQUIRE(pipe(p) == 0);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);

	EV_SET(&kev, p[0], EVFILT_READ, EV_ADD | EV_RECEIPT, 0, 0, 0);
	memset(out, 0, sizeof(out));
	ATF_REQUIRE_ERRNO(EINVAL, kevent(kq, &kev, 1, out, -1, NULL) == -1);
	ATF_REQUIRE_EQ(0, out[0].flags);

	/* Not registered: deleting it fails. */
	EV_SET(&kev, p[0], EVFILT_READ, EV_DELETE, 0, 0, 0);
	ATF_REQUIRE_ERRNO(ENOENT, kevent(kq, &kev, 1, NULL, 0, NULL) == -1);

	ATF_REQUIRE(close(kq) == 0);
	ATF_REQUIRE(close(p[0]) == 0);
	ATF_REQUIRE(close(p[1]) == 0);
}

/* A negative change list length is refused with EINVAL. */
ATF_TC_WITHOUT_HEAD(negative_nchanges);
ATF_TC_BODY(negative_nchanges, tc)
{
	struct kevent out;
	int kq;

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_ERRNO(EINVAL, kevent(kq, NULL, -1, &out, 1, NULL) == -1);
	ATF_REQUIRE(close(kq) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, negative_nevents);
	ATF_TP_ADD_TC(tp, negative_nchanges);

	return (atf_no_error());
}
