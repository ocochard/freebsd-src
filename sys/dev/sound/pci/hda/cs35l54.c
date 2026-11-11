/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Olivier Cochard-Labbe <olivier@FreeBSD.org>
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
 * Cirrus Logic CS35L54 smart speaker amplifiers behind an HDA codec, as
 * found in the HP ZBook Ultra G1a: one ACPI device (CSC3554) describes
 * several amplifiers on one I2C bus.  The amplifiers boot a ROM firmware
 * that does not render audio; the driver downloads the DSP program (wmfw)
 * and one tuning file (bin) per amplifier from /boot/firmware/cirrus/, then
 * starts and stops playback on request.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/ctype.h>
#include <sys/efi.h>
#include <sys/firmware.h>
#include <sys/gpio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#include <dev/gpio/gpiobusvar.h>
#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>
#include <dev/sound/pci/hda/hdaa_speaker.h>

#define	CS_MAX_AMPS		4

/* Registers: 32-bit address, 32-bit big-endian value. */
#define	CS_REVID		0x0000004
#define	CS_ASP1_ENABLES1	0x0004800
#define	CS_IRQ1_STATUS		0x000E004
#define	CS_MBOX			0x0011020
#define	CS_FW_VER		0x2800010
#define	CS_HALO_STATE		0x28021E0
#define	CS_PM_CUR_STATE		0x2804308
#define	CS_USER_MUTE		0x3400024
#define	CS_USER_VOLUME		0x340002C
#define	CS_POSTURE		0x3400094
#define	CS_PROT_STS		0x34000D8
#define	CS_ACTUAL_PS		0x3400150

#define	CS_REVID_B0		0xB0
#define	CS_HALO_BOOT_DONE	2
#define	CS_HALO_SHUTDOWN	1
#define	CS_FIRMWARE_MISSING	0x1

#define	CS_MBOX_PLAY		0x0B000001
#define	CS_MBOX_PAUSE		0x0B000002
#define	CS_MBOX_REINIT		0x0B000003
#define	CS_MBOX_PREVENT_HIB	0x02000003
#define	CS_MBOX_ALLOW_HIB	0x02000004
#define	CS_MBOX_SHUTDOWN	0x02000005
#define	CS_MBOX_SYSTEM_RESET	0x02000007

/* DSP memory, and the wmfw/bin region types that address it. */
#define	CS_XM_PACKED		0x2000000
#define	CS_XM_UNPACKED24	0x2800000
#define	CS_YM_PACKED		0x2C00000
#define	CS_YM_UNPACKED24	0x3400000
#define	CS_PM_PACKED		0x3800000

#define	CS_RT_XM		0x05
#define	CS_RT_YM		0x06
#define	CS_RT_PM_PACKED		0x10
#define	CS_RT_XM_PACKED		0x11
#define	CS_RT_YM_PACKED		0x12
#define	CS_RT_ABSOLUTE		0xF0

#define	CS_ALG_LIST_END		0x00BEDEAD
#define	CS_MAX_ALGS		64
#define	CS_RAW_CHUNK		4096

struct cs_reg_val {
	uint32_t	reg;
	uint32_t	val;
};

/* Defaults to restore after each boot of the amplifier firmware. */
static const struct cs_reg_val cs_patch[] = {
	{ 0x0004C70, 0x00000018 },	/* SWIRE_DP3_CH1_INPUT */
	{ 0x0004C74, 0x00000019 },	/* SWIRE_DP3_CH2_INPUT */
	{ 0x0004C78, 0x00000029 },	/* SWIRE_DP3_CH3_INPUT */
	{ 0x0004C7C, 0x00000028 },	/* SWIRE_DP3_CH4_INPUT */
	{ 0x000E0D4, 0x1F7DF0FF },	/* IRQ1_MASK_18 */
	{ CS_USER_MUTE, 0x00000000 },
	{ CS_POSTURE, 0x00000000 },
};

/* Audio serial port 1 setup for the link from the HDA codec. */
static const struct cs_reg_val cs_asp_config[] = {
	{ 0x0004804, 0x00000021 },	/* ASP1_CONTROL1 */
	{ 0x0004808, 0x20200200 },	/* ASP1_CONTROL2 */
	{ 0x000480C, 0x00000003 },	/* ASP1_CONTROL3 */
	{ 0x0004810, 0x03020100 },	/* ASP1_FRAME_CONTROL1 */
	{ 0x0004820, 0x00020100 },	/* ASP1_FRAME_CONTROL5 */
	{ 0x0004840, 0x00000018 },	/* ASP1_DATA_CONTROL5 */
	{ 0x0004830, 0x00000018 },	/* ASP1_DATA_CONTROL1 */
	{ CS_ASP1_ENABLES1, 0x00000000 },
	{ 0x0004C20, 0x00000018 },	/* ASP1TX1_INPUT */
	{ 0x0004C24, 0x00000019 },	/* ASP1TX2_INPUT */
	{ 0x0004C28, 0x00000020 },	/* ASP1TX3_INPUT */
	{ 0x0004C2C, 0x00000028 },	/* ASP1TX4_INPUT */
};

struct cs_alg {
	uint32_t	id;
	uint32_t	xm_base;
	uint32_t	ym_base;
};

struct cs35l54_softc {
	device_t	dev;
	struct sx	lock;
	struct task	fw_task;
	struct task	play_task;
	eventhandler_tag speaker_tag;
	gpio_pin_t	reset;
	char		sub[16];	/* ACPI _SUB, lower case */
	uint32_t	subsystem;	/* _SUB, as HDA reports it */
	uint16_t	addr[CS_MAX_AMPS];
	int		namps;
	int		volume;		/* dB */
	bool		loaded;
	bool		playing;
	bool		stream;		/* HDA speaker stream on */
	bool		detaching;
};

static int	cs_set_playing(struct cs35l54_softc *sc, bool on);

static int
cs_sleep(int us)
{
	if (cold)
		DELAY(us);
	else
		pause_sbt("cs35l54", ustosbt(us), 0, C_PREL(1));
	return (0);
}

static uint32_t
cs_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
}

static uint32_t
cs_le32(const uint8_t *p)
{
	return (p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24);
}

static void
cs_put_be32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

/*
 * Through ig4(4), the first 32-bit word of every read from these
 * amplifiers is stale: it holds the word after the end of the previous
 * read.  Read one extra word starting 4 bytes early and drop it; this also
 * gives the right result on a controller without the problem.
 */
static int
cs_read(struct cs35l54_softc *sc, uint16_t addr, uint32_t reg, uint32_t *out,
    size_t n)
{
	struct iic_msg msgs[2];
	uint8_t w[4], *r;
	int error;

	if (reg < 4)
		return (EINVAL);
	r = malloc(4 * (n + 1), M_TEMP, M_WAITOK);
	cs_put_be32(w, reg - 4);
	msgs[0] = (struct iic_msg){ addr << 1, IIC_M_WR, sizeof(w), w };
	msgs[1] = (struct iic_msg){ addr << 1, IIC_M_RD, 4 * (n + 1), r };
	error = iicbus_transfer_excl(sc->dev, msgs, nitems(msgs), IIC_WAIT);
	if (error == 0)
		for (size_t i = 0; i < n; i++)
			out[i] = cs_be32(r + 4 * (i + 1));
	free(r, M_TEMP);
	return (error);
}

static int
cs_rd32(struct cs35l54_softc *sc, uint16_t addr, uint32_t reg, uint32_t *val)
{
	return (cs_read(sc, addr, reg, val, 1));
}

/* Raw write: data is copied as is, already big-endian. */
static int
cs_write_raw(struct cs35l54_softc *sc, uint16_t addr, uint32_t reg,
    const uint8_t *data, size_t len)
{
	struct iic_msg msg;
	uint8_t *buf;
	size_t n;
	int error = 0;

	if (len % 4 != 0)
		return (EINVAL);
	buf = malloc(4 + MIN(len, CS_RAW_CHUNK), M_TEMP, M_WAITOK);
	while (len > 0 && error == 0) {
		n = MIN(len, CS_RAW_CHUNK);
		cs_put_be32(buf, reg);
		memcpy(buf + 4, data, n);
		msg = (struct iic_msg){ addr << 1, IIC_M_WR, 4 + n, buf };
		error = iicbus_transfer_excl(sc->dev, &msg, 1, IIC_WAIT);
		reg += n;
		data += n;
		len -= n;
	}
	free(buf, M_TEMP);
	return (error);
}

static int
cs_wr32(struct cs35l54_softc *sc, uint16_t addr, uint32_t reg, uint32_t val)
{
	uint8_t v[4];

	cs_put_be32(v, val);
	return (cs_write_raw(sc, addr, reg, v, sizeof(v)));
}

static int
cs_wr_seq(struct cs35l54_softc *sc, uint16_t addr,
    const struct cs_reg_val *seq, size_t n)
{
	int error;

	for (size_t i = 0; i < n; i++)
		if ((error = cs_wr32(sc, addr, seq[i].reg, seq[i].val)) != 0)
			return (error);
	return (0);
}

/* Poll reg until it reads want; step and timeout in microseconds. */
static int
cs_poll(struct cs35l54_softc *sc, uint16_t addr, uint32_t reg, uint32_t want,
    int step, int timeout, uint32_t *last)
{
	uint32_t val = ~want;

	for (int t = 0; t <= timeout; t += step) {
		if (cs_rd32(sc, addr, reg, &val) == 0 && val == want)
			break;
		cs_sleep(step);
	}
	if (last != NULL)
		*last = val;
	return (val == want ? 0 : ETIMEDOUT);
}

/* The firmware clears the mailbox when it takes the command. */
static int
cs_mbox(struct cs35l54_softc *sc, uint16_t addr, uint32_t cmd)
{
	uint32_t val;
	int error;

	if ((error = cs_wr32(sc, addr, CS_MBOX, cmd)) != 0)
		return (error);
	error = cs_poll(sc, addr, CS_MBOX, 0, 250, 5000, &val);
	if (error != 0)
		device_printf(sc->dev, "0x%02x: mailbox 0x%08x not taken "
		    "(0x%08x)\n", addr, cmd, val);
	return (error);
}

/* Two accesses 1 ms apart wake a hibernating amplifier. */
static void
cs_wake(struct cs35l54_softc *sc, uint16_t addr)
{
	uint32_t val;

	(void)cs_rd32(sc, addr, CS_IRQ1_STATUS, &val);
	cs_sleep(1000);
	(void)cs_rd32(sc, addr, CS_IRQ1_STATUS, &val);
	cs_sleep(2200);
}

static int
cs_wait_boot(struct cs35l54_softc *sc, uint16_t addr)
{
	uint32_t val;
	int error;

	error = cs_poll(sc, addr, CS_HALO_STATE, CS_HALO_BOOT_DONE, 1000,
	    250000, &val);
	if (error != 0)
		device_printf(sc->dev, "0x%02x: firmware boot timeout, "
		    "HALO_STATE 0x%x\n", addr, val);
	return (error);
}

static int
cs_system_reset(struct cs35l54_softc *sc, uint16_t addr)
{
	int error;

	if ((error = cs_wr32(sc, addr, CS_HALO_STATE, 0)) != 0 ||
	    (error = cs_wr32(sc, addr, CS_MBOX, CS_MBOX_SYSTEM_RESET)) != 0)
		return (error);
	cs_sleep(2200);
	return (cs_wait_boot(sc, addr));
}

static int
cs_setup(struct cs35l54_softc *sc, uint16_t addr)
{
	int error;

	if ((error = cs_mbox(sc, addr, CS_MBOX_PREVENT_HIB)) != 0 ||
	    (error = cs_wr_seq(sc, addr, cs_patch, nitems(cs_patch))) != 0)
		return (error);
	return (cs_wr_seq(sc, addr, cs_asp_config, nitems(cs_asp_config)));
}

static uint32_t
cs_region_to_reg(int type, uint32_t off)
{
	switch (type) {
	case CS_RT_XM:
		return (CS_XM_UNPACKED24 + off * 4);
	case CS_RT_YM:
		return (CS_YM_UNPACKED24 + off * 4);
	case CS_RT_XM_PACKED:
		return ((CS_XM_PACKED + off * 3) & ~3u);
	case CS_RT_YM_PACKED:
		return ((CS_YM_PACKED + off * 3) & ~3u);
	case CS_RT_PM_PACKED:
		return (CS_PM_PACKED + off * 5);
	}
	return (0);
}

/*
 * wmfw file: 12-byte header ("WMFW", length, core type, version), 16 bytes
 * of memory sizes, 12-byte footer, then regions.  A region is a 24-bit
 * little-endian offset with the type in the 4th byte, a 32-bit length, and
 * the data.
 */
static int
cs_write_wmfw(struct cs35l54_softc *sc, uint16_t addr, const uint8_t *fw,
    size_t len)
{
	uint32_t off, rlen, reg;
	size_t pos;
	int error, type;

	if (len < 40 || memcmp(fw, "WMFW", 4) != 0 || fw[10] != 4 ||
	    cs_le32(fw + 4) != 40) {
		device_printf(sc->dev, "wmfw: bad header\n");
		return (EFTYPE);
	}
	for (pos = 40; pos + 8 <= len; pos += 8 + rlen) {
		off = cs_le32(fw + pos) & 0xFFFFFF;
		type = fw[pos + 3];
		rlen = cs_le32(fw + pos + 4);
		if (rlen > len - pos - 8)
			return (EFTYPE);
		if (type == CS_RT_ABSOLUTE)
			reg = off;
		else
			reg = cs_region_to_reg(type, off);
		if (reg == 0)
			continue;
		error = cs_write_raw(sc, addr, reg, fw + pos + 8, rlen);
		if (error != 0)
			return (error);
	}
	return (0);
}

/*
 * The firmware describes itself in XM: a 10-word header (core id, block
 * revision, vendor, firmware id, version, XM base and size, YM base and
 * size, algorithm count), then 6 words per algorithm (id, version, XM base
 * and size, YM base and size), then 0xBEDEAD.  The firmware id owns XM and
 * YM regions like an algorithm.
 */
static int
cs_read_algs(struct cs35l54_softc *sc, uint16_t addr, struct cs_alg *algs,
    int *nalgs)
{
	uint32_t hdr[10], end, *list;
	int error, n;

	if ((error = cs_read(sc, addr, CS_XM_UNPACKED24, hdr, 10)) != 0)
		return (error);
	n = hdr[9];
	if (n <= 0 || n > CS_MAX_ALGS)
		return (EFTYPE);
	error = cs_rd32(sc, addr, CS_XM_UNPACKED24 + 40 + n * 24, &end);
	if (error != 0 || end != CS_ALG_LIST_END)
		return (error != 0 ? error : EFTYPE);
	list = malloc(n * 24, M_TEMP, M_WAITOK);
	error = cs_read(sc, addr, CS_XM_UNPACKED24 + 40, list, n * 6);
	if (error == 0) {
		algs[0] = (struct cs_alg){ hdr[3], hdr[5], hdr[7] };
		for (int i = 0; i < n; i++)
			algs[i + 1] = (struct cs_alg){ list[6 * i],
			    list[6 * i + 2], list[6 * i + 4] };
		*nalgs = n + 1;
	}
	free(list, M_TEMP);
	return (error);
}

/*
 * bin file: "WMDR", header length, then blocks of 20 bytes (16-bit offset,
 * 16-bit type, algorithm id, version, 32-bit offset, length) and data,
 * padded to 4 bytes.  Memory blocks are relative to their algorithm base.
 */
static int
cs_write_bin(struct cs35l54_softc *sc, uint16_t addr, const uint8_t *fw,
    size_t len, const struct cs_alg *algs, int nalgs)
{
	uint32_t off, id, blen, reg;
	size_t pos;
	int error, i, type;

	if (len < 16 || memcmp(fw, "WMDR", 4) != 0)
		return (EFTYPE);
	for (pos = cs_le32(fw + 4); pos + 20 <= len;
	    pos += (blen + 20 + 3) & ~3u) {
		off = fw[pos] | fw[pos + 1] << 8;
		type = fw[pos + 2] | fw[pos + 3] << 8;
		id = cs_le32(fw + pos + 4);
		blen = cs_le32(fw + pos + 16);
		if (blen > len - pos - 20)
			return (EFTYPE);
		if ((type & 0xFF00) == 0xF400) {	/* 32-bit offset */
			off = cs_le32(fw + pos + 12);
			type &= 0xFF;
		}
		reg = 0;
		switch (type) {
		case CS_RT_ABSOLUTE << 8:
			reg = off;
			break;
		case CS_RT_XM:
		case CS_RT_XM_PACKED:
		case CS_RT_YM:
		case CS_RT_YM_PACKED:
			for (i = 0; i < nalgs && algs[i].id != id; i++)
				;
			if (i == nalgs) {
				device_printf(sc->dev, "0x%02x: bin: no "
				    "algorithm 0x%x\n", addr, id);
				return (EFTYPE);
			}
			reg = cs_region_to_reg(type,
			    type == CS_RT_XM || type == CS_RT_XM_PACKED ?
			    algs[i].xm_base : algs[i].ym_base) + off;
			break;
		}
		if (reg == 0)
			continue;
		error = cs_write_raw(sc, addr, reg, fw + pos + 20, blen);
		if (error != 0)
			return (error);
	}
	return (0);
}

/*
 * Speaker calibration measured at the factory, in the UEFI variable
 * CirrusSmartAmpCalibrationData: one entry per amplifier, matched by the
 * amplifier silicon id, or by index when the entry has no id.
 */
#define	CS_OTP_UID		0x00300D4
#define	CS_CAL_ALG		0x9F210
#define	CS_CAL_MAX		4096

struct cs_cal_entry {
	uint32_t	target[2];	/* silicon id, low word first */
	uint32_t	time[2];
	int8_t		ambient;	/* degrees C */
	uint8_t		status;
	uint16_t	calr;
} __packed;

struct cs_cal_data {
	uint32_t	size;
	uint32_t	count;
	struct cs_cal_entry entry[];
} __packed;

static struct cs_cal_data *
cs_read_cal(struct cs35l54_softc *sc)
{
	static const char vname[] = "CirrusSmartAmpCalibrationData";
	efi_guid_t guid = { 0x02f9af02, 0x7734, 0x4233,
	    { 0xb4, 0x3d, 0x93, 0xfe, 0x5a, 0xa3, 0x5d, 0xb3 } };
	uint16_t name[nitems(vname)];
	struct cs_cal_data *cal;
	size_t len = CS_CAL_MAX;
	int error;

	for (size_t i = 0; i < nitems(vname); i++)
		name[i] = vname[i];
	cal = malloc(CS_CAL_MAX, M_TEMP, M_WAITOK);
	error = efi_var_get(name, &guid, NULL, &len, cal);
	if (error != 0 || len < sizeof(*cal) ||
	    cal->count > (len - sizeof(*cal)) / sizeof(cal->entry[0])) {
		device_printf(sc->dev, "no speaker calibration in UEFI (%d)\n",
		    error);
		free(cal, M_TEMP);
		return (NULL);
	}
	return (cal);
}

/*
 * Find the word offset of a named control in the wmfw algorithm metadata
 * regions.  Each region: algorithm id, name (8-bit length), description
 * (16-bit length), coefficient count, then per coefficient an 8-byte header
 * (offset, memory type, block size) followed by its name; strings are
 * padded to 4 bytes.
 */
static int
cs_find_ctl(const uint8_t *fw, size_t len, uint32_t alg, int mtype,
    const char *ctl, uint32_t *offp)
{
	const uint8_t *p, *end, *blk;
	uint32_t rlen, n;
	size_t pos;

	for (pos = 40; pos + 8 <= len; pos += 8 + rlen) {
		rlen = cs_le32(fw + pos + 4);
		if (rlen > len - pos - 8)
			return (EFTYPE);
		if (fw[pos + 3] != 0xF2 || rlen < 12 ||
		    cs_le32(fw + pos + 8) != alg)
			continue;
		p = fw + pos + 12;
		end = fw + pos + 8 + rlen;
		p += (p[0] + 1 + 3) & ~3u;
		if (p + 2 > end)
			return (EFTYPE);
		p += (p[0] + (p[1] << 8) + 2 + 3) & ~3u;
		if (p + 4 > end)
			return (EFTYPE);
		n = cs_le32(p);
		p += 4;
		for (; n > 0 && p + 9 <= end; n--, p = blk) {
			blk = p + 8 + cs_le32(p + 4);
			if (blk > end)
				return (EFTYPE);
			if ((p[2] | p[3] << 8) == mtype &&
			    p[8] == strlen(ctl) && p + 9 + p[8] <= end &&
			    memcmp(p + 9, ctl, p[8]) == 0) {
				*offp = p[0] | p[1] << 8;
				return (0);
			}
		}
	}
	return (ENOENT);
}

static int
cs_apply_cal(struct cs35l54_softc *sc, int index, const uint8_t *fw,
    size_t len, const struct cs_alg *algs, int nalgs,
    const struct cs_cal_data *cal)
{
	static const char *const ctls[] = { "CAL_AMBIENT", "CAL_R",
	    "CAL_STATUS", "CAL_CHECKSUM" };
	const struct cs_cal_entry *e = NULL;
	uint16_t addr = sc->addr[index];
	uint32_t w[3], vals[4], regs[4], off, base;
	uint64_t uid, target;
	uint8_t b[12];
	int error, i;

	/* Silicon id from OTP, assembled as Linux cs35l56 does. */
	if ((error = cs_read(sc, addr, CS_OTP_UID, w, 3)) != 0)
		return (error);
	for (i = 0; i < 3; i++)
		cs_put_be32(b + 4 * i, w[i]);
	uid = (uint64_t)(b[6] | b[5] << 8 | b[4] << 16) << 32 |
	    (b[0] | b[7] << 8 | b[1] << 16 | (uint32_t)b[11] << 24);
	for (i = 0; i < (int)cal->count; i++) {
		target = (uint64_t)cal->entry[i].target[1] << 32 |
		    cal->entry[i].target[0];
		if ((cal->entry[i].time[0] || cal->entry[i].time[1]) &&
		    target == uid) {
			e = &cal->entry[i];
			break;
		}
	}
	if (e == NULL && index < (int)cal->count &&
	    cal->entry[index].target[0] == 0 &&
	    cal->entry[index].target[1] == 0)
		e = &cal->entry[index];
	if (e == NULL) {
		device_printf(sc->dev, "0x%02x: no calibration for silicon id "
		    "0x%jx\n", addr, (uintmax_t)uid);
		return (ENOENT);
	}
	for (i = 0; i < nalgs && algs[i].id != CS_CAL_ALG; i++)
		;
	if (i == nalgs)
		return (ENOENT);
	base = algs[i].ym_base;
	vals[0] = (uint32_t)(int32_t)e->ambient;
	vals[1] = e->calr;
	vals[2] = e->status;
	vals[3] = e->calr + 1;
	for (i = 0; i < (int)nitems(ctls); i++) {
		if ((error = cs_find_ctl(fw, len, CS_CAL_ALG, CS_RT_YM, ctls[i],
		    &off)) != 0) {
			device_printf(sc->dev, "control %s not found\n",
			    ctls[i]);
			return (error);
		}
		regs[i] = cs_region_to_reg(CS_RT_YM, base + off);
		if ((error = cs_wr32(sc, addr, regs[i], vals[i])) != 0)
			return (error);
	}
	device_printf(sc->dev, "0x%02x: calibration R %u, ambient %d C\n",
	    addr, e->calr, e->ambient);
	if (bootverbose)
		device_printf(sc->dev, "0x%02x: CAL_AMBIENT 0x%x CAL_R 0x%x "
		    "CAL_STATUS 0x%x CAL_CHECKSUM 0x%x\n", addr, regs[0],
		    regs[1], regs[2], regs[3]);
	return (0);
}

static int
cs_load_amp(struct cs35l54_softc *sc, int index, const struct firmware *wmfw,
    const struct cs_cal_data *cal)
{
	const struct firmware *bin;
	struct cs_alg *algs;
	char name[64];
	uint16_t addr = sc->addr[index];
	uint32_t val;
	int error, nalgs;

	snprintf(name, sizeof(name), "cirrus/cs35l54-b0-dsp1-misc-%s-amp%d.bin",
	    sc->sub, index + 1);
	if ((bin = firmware_get(name)) == NULL)
		return (ENOENT);
	algs = malloc(sizeof(*algs) * (CS_MAX_ALGS + 1), M_TEMP, M_WAITOK);
	cs_wake(sc, addr);
	if ((error = cs_wait_boot(sc, addr)) != 0)
		goto out;
	if ((error = cs_rd32(sc, addr, CS_REVID, &val)) != 0)
		goto out;
	if ((val & 0xFF) != CS_REVID_B0) {
		device_printf(sc->dev, "0x%02x: REVID 0x%x not supported\n",
		    addr, val);
		error = ENXIO;
		goto out;
	}
	if ((error = cs_mbox(sc, addr, CS_MBOX_PREVENT_HIB)) != 0 ||
	    (error = cs_system_reset(sc, addr)) != 0 ||
	    (error = cs_setup(sc, addr)) != 0 ||
	    (error = cs_rd32(sc, addr, CS_PROT_STS, &val)) != 0)
		goto out;
	if (val & CS_FIRMWARE_MISSING) {
		if ((error = cs_mbox(sc, addr, CS_MBOX_SHUTDOWN)) != 0 ||
		    (error = cs_poll(sc, addr, CS_PM_CUR_STATE,
		    CS_HALO_SHUTDOWN, 1000, 250000, NULL)) != 0)
			goto out;
	}
	if ((error = cs_write_wmfw(sc, addr, wmfw->data,
	    wmfw->datasize)) != 0 ||
	    (error = cs_read_algs(sc, addr, algs, &nalgs)) != 0 ||
	    (error = cs_write_bin(sc, addr, bin->data, bin->datasize, algs,
	    nalgs)) != 0 ||
	    (error = cs_system_reset(sc, addr)) != 0 ||
	    (error = cs_setup(sc, addr)) != 0)
		goto out;
	/* Like Linux, play uncalibrated if calibration cannot be applied. */
	if (cal != NULL && cs_apply_cal(sc, index, wmfw->data, wmfw->datasize,
	    algs, nalgs, cal) != 0)
		device_printf(sc->dev, "0x%02x: calibration not applied\n",
		    addr);
	if ((error = cs_mbox(sc, addr, CS_MBOX_REINIT)) != 0)
		goto out;
	if ((error = cs_rd32(sc, addr, CS_PROT_STS, &val)) == 0 &&
	    (val & CS_FIRMWARE_MISSING) != 0)
		error = EIO;
out:
	free(algs, M_TEMP);
	firmware_put(bin, FIRMWARE_UNLOAD);
	if (error != 0)
		device_printf(sc->dev, "0x%02x: firmware download failed: %d\n",
		    addr, error);
	return (error);
}

/* Pulse the shared reset line: low for at least 1.1 ms, then high. */
static void
cs_hard_reset(struct cs35l54_softc *sc)
{
	if (sc->reset == NULL)
		return;
	gpio_pin_setflags(sc->reset, GPIO_PIN_OUTPUT);
	gpio_pin_set_active(sc->reset, false);
	cs_sleep(2200);
	gpio_pin_set_active(sc->reset, true);
	cs_sleep(4400);
}

static void
cs_fw_task(void *arg, int pending)
{
	struct cs35l54_softc *sc = arg;
	const struct firmware *wmfw;
	struct cs_cal_data *cal;
	uint32_t ver;
	char name[64];
	int error = 0;

	snprintf(name, sizeof(name), "cirrus/cs35l54-b0-dsp1-misc-%s.wmfw",
	    sc->sub);
	if ((wmfw = firmware_get(name)) == NULL) {
		device_printf(sc->dev, "%s not found in /boot/firmware\n",
		    name);
		return;
	}
	cal = cs_read_cal(sc);
	sx_xlock(&sc->lock);
	cs_hard_reset(sc);
	for (int i = 0; i < sc->namps && error == 0 && !sc->detaching; i++)
		error = cs_load_amp(sc, i, wmfw, cal);
	if (error == 0 && !sc->detaching) {
		sc->loaded = true;
		if (sc->stream)
			(void)cs_set_playing(sc, true);
		if (cs_rd32(sc, sc->addr[0], CS_FW_VER, &ver) == 0)
			device_printf(sc->dev, "%d amplifiers, firmware "
			    "%u.%u.%u\n", sc->namps, (ver >> 16) & 0xFF,
			    (ver >> 8) & 0xFF, ver & 0xFF);
	}
	sx_xunlock(&sc->lock);
	free(cal, M_TEMP);
	firmware_put(wmfw, FIRMWARE_UNLOAD);
}

static uint32_t
cs_volume_raw(int db)
{
	int q = MAX(-400, MIN(48, db * 4));	/* 0.25 dB steps */

	return (((uint32_t)q & 0x3FF) << 6);
}

static int
cs_play(struct cs35l54_softc *sc)
{
	uint16_t addr;
	int error;

	sx_assert(&sc->lock, SA_XLOCKED);
	for (int i = 0; i < sc->namps; i++) {
		addr = sc->addr[i];
		cs_wake(sc, addr);
		if ((error = cs_wait_boot(sc, addr)) != 0 ||
		    (error = cs_setup(sc, addr)) != 0 ||
		    (error = cs_wr32(sc, addr, CS_USER_VOLUME,
		    cs_volume_raw(sc->volume))) != 0 ||
		    (error = cs_mbox(sc, addr, CS_MBOX_PLAY)) != 0)
			return (error);
		if (cs_poll(sc, addr, CS_ACTUAL_PS, 0, 500, 50000, NULL) != 0)
			device_printf(sc->dev, "0x%02x: PS0 not reached\n",
			    addr);
		/* ASP1 RX1 and RX2 in, one TX slot per amplifier. */
		error = cs_wr32(sc, addr, CS_ASP1_ENABLES1,
		    0x00030000 | 1u << i);
		if (error != 0)
			return (error);
	}
	return (0);
}

static int
cs_stop(struct cs35l54_softc *sc)
{
	uint16_t addr;
	int error, ret = 0;

	sx_assert(&sc->lock, SA_XLOCKED);
	for (int i = 0; i < sc->namps; i++) {
		addr = sc->addr[i];
		cs_wake(sc, addr);
		if ((error = cs_mbox(sc, addr, CS_MBOX_PAUSE)) != 0 ||
		    (error = cs_wr32(sc, addr, CS_ASP1_ENABLES1, 0)) != 0 ||
		    (error = cs_mbox(sc, addr, CS_MBOX_ALLOW_HIB)) != 0)
			ret = error;
	}
	return (ret);
}

static int
cs_set_playing(struct cs35l54_softc *sc, bool on)
{
	int error = 0;

	sx_assert(&sc->lock, SA_XLOCKED);
	if (!sc->loaded)
		return (ENXIO);
	if (on && !sc->playing) {
		if ((error = cs_play(sc)) == 0)
			sc->playing = true;
	} else if (!on && sc->playing) {
		error = cs_stop(sc);
		sc->playing = false;
	}
	return (error);
}

static int
cs_sysctl_play(SYSCTL_HANDLER_ARGS)
{
	struct cs35l54_softc *sc = arg1;
	int error, val;

	val = sc->playing;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	sx_xlock(&sc->lock);
	error = cs_set_playing(sc, val != 0);
	sx_xunlock(&sc->lock);
	return (error);
}

/* Follow the HDA speaker stream; runs in taskqueue_thread. */
static void
cs_play_task(void *arg, int pending)
{
	struct cs35l54_softc *sc = arg;

	sx_xlock(&sc->lock);
	if (!sc->detaching)
		(void)cs_set_playing(sc, sc->stream);
	sx_xunlock(&sc->lock);
}

/* hdaa_speaker event: called without hdaa locks, must not sleep. */
static void
cs_speaker_event(void *arg, device_t hdaa, uint32_t subsystem, bool active)
{
	struct cs35l54_softc *sc = arg;

	if (subsystem != sc->subsystem)
		return;
	sc->stream = active;
	taskqueue_enqueue(taskqueue_thread, &sc->play_task);
}

static int
cs_sysctl_volume(SYSCTL_HANDLER_ARGS)
{
	struct cs35l54_softc *sc = arg1;
	int error, val;

	val = sc->volume;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (val < -100 || val > 12)
		return (EINVAL);
	sx_xlock(&sc->lock);
	sc->volume = val;
	for (int i = 0; sc->playing && i < sc->namps && error == 0; i++)
		error = cs_wr32(sc, sc->addr[i], CS_USER_VOLUME,
		    cs_volume_raw(val));
	sx_xunlock(&sc->lock);
	return (error);
}

/*
 * "cirrus,dev-index" in _DSD lists the I2C address of each amplifier, in
 * order.  device_get_property() cannot be used: on an acpi_iicbus child it
 * reaches acpi(4), which takes the child ivars for its own.  _DSD is a list
 * of (UUID, properties) pairs; properties are (name, value) packages.
 */
static int
cs_get_amps(struct cs35l54_softc *sc)
{
	ACPI_BUFFER buf = { ACPI_ALLOCATE_BUFFER, NULL };
	ACPI_OBJECT *dsd, *props, *prop, *key, *val, *e;
	int error = ENXIO;

	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(acpi_get_handle(sc->dev),
	    "_DSD", NULL, &buf, ACPI_TYPE_PACKAGE)))
		return (ENXIO);
	dsd = buf.Pointer;
	for (u_int i = 1; i < dsd->Package.Count && error != 0; i += 2) {
		props = &dsd->Package.Elements[i];
		if (props->Type != ACPI_TYPE_PACKAGE)
			continue;
		for (u_int j = 0; j < props->Package.Count; j++) {
			prop = &props->Package.Elements[j];
			if (prop->Type != ACPI_TYPE_PACKAGE ||
			    prop->Package.Count != 2)
				continue;
			key = &prop->Package.Elements[0];
			val = &prop->Package.Elements[1];
			if (key->Type != ACPI_TYPE_STRING || strcmp(
			    key->String.Pointer, "cirrus,dev-index") != 0)
				continue;
			if (val->Type != ACPI_TYPE_PACKAGE)
				break;
			sc->namps = MIN(val->Package.Count, CS_MAX_AMPS);
			error = 0;
			for (int k = 0; k < sc->namps; k++) {
				e = &val->Package.Elements[k];
				if (e->Type != ACPI_TYPE_INTEGER) {
					error = ENXIO;
					break;
				}
				sc->addr[k] = e->Integer.Value;
			}
			break;
		}
	}
	AcpiOsFree(buf.Pointer);
	return (error == 0 && sc->namps > 0 ? 0 : ENXIO);
}

/* The firmware files are named after the ACPI subsystem id. */
static int
cs_get_sub(struct cs35l54_softc *sc)
{
	ACPI_BUFFER buf = { ACPI_ALLOCATE_BUFFER, NULL };
	ACPI_OBJECT *obj;
	ACPI_STATUS status;

	status = AcpiEvaluateObjectTyped(acpi_get_handle(sc->dev), "_SUB",
	    NULL, &buf, ACPI_TYPE_STRING);
	if (ACPI_FAILURE(status))
		return (ENXIO);
	obj = buf.Pointer;
	strlcpy(sc->sub, obj->String.Pointer, sizeof(sc->sub));
	for (char *p = sc->sub; *p != '\0'; p++)
		*p = tolower(*p);
	AcpiOsFree(buf.Pointer);
	return (0);
}

struct cs_gpio_res {
	ACPI_HANDLE	ctrl;
	uint32_t	pin;
};

static ACPI_STATUS
cs_find_gpio_cb(ACPI_RESOURCE *res, void *arg)
{
	struct cs_gpio_res *gr = arg;
	ACPI_RESOURCE_GPIO *g = &res->Data.Gpio;

	if (res->Type != ACPI_RESOURCE_TYPE_GPIO ||
	    g->ConnectionType != ACPI_RESOURCE_GPIO_TYPE_IO ||
	    g->PinTableLength == 0)
		return (AE_OK);
	if (ACPI_FAILURE(AcpiGetHandle(NULL, g->ResourceSource.StringPtr,
	    &gr->ctrl)))
		return (AE_OK);
	gr->pin = g->PinTable[0];
	return (AE_CTRL_TERMINATE);
}

/* The reset line is the first GpioIo resource; it is optional. */
static void
cs_get_reset(struct cs35l54_softc *sc)
{
	struct cs_gpio_res gr = { NULL, 0 };
	device_t ctrl, bus;

	AcpiWalkResources(acpi_get_handle(sc->dev), "_CRS", cs_find_gpio_cb,
	    &gr);
	if (gr.ctrl == NULL || (ctrl = acpi_get_device(gr.ctrl)) == NULL ||
	    (bus = device_find_child(ctrl, "gpiobus",
	    DEVICE_UNIT_ANY)) == NULL ||
	    gpio_pin_get_by_bus_pinnum(bus, gr.pin, &sc->reset) != 0) {
		device_printf(sc->dev, "no reset GPIO, wake only\n");
		sc->reset = NULL;
	}
}

static int
cs35l54_probe(device_t dev)
{
	ACPI_HANDLE handle;

	if ((handle = acpi_get_handle(dev)) == NULL ||
	    acpi_MatchHid(handle, "CSC3554") == ACPI_MATCHHID_NOMATCH)
		return (ENXIO);
	device_set_desc(dev, "Cirrus Logic CS35L54 speaker amplifiers");
	return (BUS_PROBE_DEFAULT);
}

static int
cs35l54_attach(device_t dev)
{
	struct cs35l54_softc *sc = device_get_softc(dev);
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid_list *tree;

	sc->dev = dev;
	sc->volume = -30;
	if (cs_get_amps(sc) != 0 || cs_get_sub(sc) != 0) {
		device_printf(dev, "incomplete ACPI description\n");
		return (ENXIO);
	}
	sc->subsystem = strtoul(sc->sub, NULL, 16);
	cs_get_reset(sc);
	sx_init(&sc->lock, "cs35l54");
	TASK_INIT(&sc->fw_task, 0, cs_fw_task, sc);
	TASK_INIT(&sc->play_task, 0, cs_play_task, sc);
	sc->speaker_tag = EVENTHANDLER_REGISTER(hdaa_speaker, cs_speaker_event,
	    sc, EVENTHANDLER_PRI_ANY);

	tree = SYSCTL_CHILDREN(device_get_sysctl_tree(dev));
	SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, "play",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0, cs_sysctl_play,
	    "I", "Amplifiers playing (1) or paused (0)");
	SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, "volume",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, sc, 0, cs_sysctl_volume,
	    "I", "Amplifier volume in dB (-100 to 12)");
	SYSCTL_ADD_BOOL(ctx, tree, OID_AUTO, "loaded", CTLFLAG_RD,
	    &sc->loaded, 0, "DSP firmware downloaded");

	/* The download takes seconds and needs the root file system. */
	taskqueue_enqueue(taskqueue_thread, &sc->fw_task);
	return (0);
}

static int
cs35l54_detach(device_t dev)
{
	struct cs35l54_softc *sc = device_get_softc(dev);

	EVENTHANDLER_DEREGISTER(hdaa_speaker, sc->speaker_tag);
	sc->detaching = true;
	taskqueue_drain(taskqueue_thread, &sc->fw_task);
	taskqueue_drain(taskqueue_thread, &sc->play_task);
	sx_xlock(&sc->lock);
	if (sc->playing)
		cs_stop(sc);
	sx_xunlock(&sc->lock);
	if (sc->reset != NULL)
		gpio_pin_release(sc->reset);
	sx_destroy(&sc->lock);
	return (0);
}

static device_method_t cs35l54_methods[] = {
	DEVMETHOD(device_probe,		cs35l54_probe),
	DEVMETHOD(device_attach,	cs35l54_attach),
	DEVMETHOD(device_detach,	cs35l54_detach),
	DEVMETHOD_END
};

static driver_t cs35l54_driver = {
	"cs35l54",
	cs35l54_methods,
	sizeof(struct cs35l54_softc),
};

DRIVER_MODULE(cs35l54, iicbus, cs35l54_driver, NULL, NULL);
MODULE_DEPEND(cs35l54, iicbus, IICBUS_MINVER, IICBUS_PREFVER, IICBUS_MAXVER);
MODULE_DEPEND(cs35l54, gpiobus, 1, 1, 1);
MODULE_DEPEND(cs35l54, firmware, 1, 1, 1);
MODULE_VERSION(cs35l54, 1);
