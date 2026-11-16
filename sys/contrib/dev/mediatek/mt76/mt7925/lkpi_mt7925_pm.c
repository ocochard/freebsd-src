/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Olivier Cochard <olivier@FreeBSD.org>
 */

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>

/* Suspend and resume net80211 around the PCI suspend and resume. */
extern driver_t lkpi_80211_pm_driver;
DRIVER_MODULE(lkpi80211_pm, mt7925, lkpi_80211_pm_driver, 0, 0);
