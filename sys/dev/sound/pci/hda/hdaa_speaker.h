/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Olivier Cochard-Labbe <olivier@FreeBSD.org>
 */

#ifndef _HDAA_SPEAKER_H_
#define	_HDAA_SPEAKER_H_

#include <sys/eventhandler.h>

/*
 * Fired by hdaa(4) when a playback stream to a fixed internal speaker pin
 * starts or stops, outside of any hdaa lock.  Drivers of external speaker
 * amplifiers (side codecs) match the codec subsystem id and must not sleep
 * in the handler.
 */
typedef void (*hdaa_speaker_fn)(void *arg, device_t hdaa, uint32_t subsystem,
    bool active);
EVENTHANDLER_DECLARE(hdaa_speaker, hdaa_speaker_fn);

#endif /* _HDAA_SPEAKER_H_ */
