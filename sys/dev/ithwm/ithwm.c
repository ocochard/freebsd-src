/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Olivier Cochard
 */

/*
 * Driver for the hardware monitor logical device of the ITE IT8613E SuperIO.
 * Exposes temperatures (deg C), fan speeds (RPM), and voltages (mV)
 * via sysctl under dev.ithwm.<unit>.
 *
 * Register access uses the 8-byte I/O window reported by the SuperIO bus for
 * LDN 4 via an index/data port pair (iobase+5 addr, iobase+6 data).  This
 * window is separate from the SuperIO config ports and requires no SuperIO
 * locking; a per-device mutex serialises concurrent sysctl reads.
 *
 * References:
 *   - Linux drivers/hwmon/it87.c and the out-of-tree frankcrawford/it87
 *     driver (IT8613E feature set: 16-bit fans, five fans, 11 mV ADC)
 *   - sys/dev/itwd/itwd.c   (ITE SuperIO child driver template)
 *   - sys/dev/ncthwm/ncthwm.c (HWM-via-SuperIO pattern)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <sys/sysctl.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/superio/superio.h>

/* ------------------------------------------------------------------ */
/* IT87xx HWM I/O window layout                                        */
/*                                                                     */
/* The HWM exposes an 8-byte index/data window.  Registers are not    */
/* memory-mapped at fixed offsets; they are accessed by writing the   */
/* register number to the address port and reading/writing the data   */
/* port.                                                              */
/*                                                                     */
/*   iobase+5  ADDR port - write target register number here          */
/*   iobase+6  DATA port - read/write register value here             */
/* ------------------------------------------------------------------ */

#define ITHWM_PORT_ADDR		5	/* offset of address port in window */
#define ITHWM_PORT_DATA		6	/* offset of data port in window    */
#define ITHWM_IOSIZE		8	/* window size in bytes             */

/* Logical register numbers (written to ADDR port) */

/*
 * Fan tachometers.  The IT8613E always runs its tachometers in 16-bit mode
 * with a fixed divisor of 2: count = (high << 8) | low.
 */
#define ITHWM_REG_FAN1_L	0x0d
#define ITHWM_REG_FAN2_L	0x0e
#define ITHWM_REG_FAN3_L	0x0f
#define ITHWM_REG_FAN4_L	0x80
#define ITHWM_REG_FAN5_L	0x82

#define ITHWM_REG_FAN1_H	0x18
#define ITHWM_REG_FAN2_H	0x19
#define ITHWM_REG_FAN3_H	0x1a
#define ITHWM_REG_FAN4_H	0x81
#define ITHWM_REG_FAN5_H	0x83

/* Voltage ADC readings (raw, 1 LSB = 11 mV on the IT8613E) */
#define ITHWM_REG_VIN0		0x20
#define ITHWM_REG_VIN1		0x21
#define ITHWM_REG_VIN2		0x22
#define ITHWM_REG_VIN3		0x23
#define ITHWM_REG_VIN4		0x24
#define ITHWM_REG_VIN5		0x25
#define ITHWM_REG_VIN6		0x26
#define ITHWM_REG_VIN7		0x27
#define ITHWM_REG_VBAT		0x28

/* Temperature readings (signed 8-bit, deg C) */
#define ITHWM_REG_TEMP1		0x29
#define ITHWM_REG_TEMP2		0x2a
#define ITHWM_REG_TEMP3		0x2b

/* Temperature register value reported when no sensor is connected */
#define ITHWM_TEMP_NONE		(-128)

/* RPM base clock for the IT87xx family */
#define ITHWM_FAN_CLOCK		1350000
#define ITHWM_FAN16_DIV		2

/*
 * ADC LSB in mV.  VIN7 (VSB) and VBAT are internal inputs halved by an
 * on-chip divider, so their LSB is doubled.
 */
#define ITHWM_ADC_LSB_MV	11
#define ITHWM_VIN_SCALED	((1 << 7) | (1 << ITHWM_NVINS))

/* Inputs not bonded out on the IT8613E: FAN1, VIN3 and VIN6 */
#define ITHWM_FAN_ABSENT	(1 << 0)
#define ITHWM_VIN_ABSENT	((1 << 3) | (1 << 6))

#define ITHWM_DEVID_IT8613	0x8613

/* 0 deg C in decikelvin - matches amdtemp(4) "IK" sysctl convention */
#define ITHWM_ZERO_C_TO_K	2731

#define ITHWM_NFANS		5
#define ITHWM_NVINS		8	/* VIN0..VIN7; VBAT separate */
#define ITHWM_NTEMPS		3

/* ------------------------------------------------------------------ */
/* Softc                                                               */
/* ------------------------------------------------------------------ */

struct ithwm_softc {
	struct resource	*io_res;
	int		io_rid;
	struct mtx	lock;
};

/* ------------------------------------------------------------------ */
/* Low-level register accessors (index/data port pair)                 */
/* ------------------------------------------------------------------ */

static uint8_t
ithwm_readb(struct ithwm_softc *sc, uint8_t reg)
{
	mtx_assert(&sc->lock, MA_OWNED);
	bus_write_1(sc->io_res, ITHWM_PORT_ADDR, reg);
	return (bus_read_1(sc->io_res, ITHWM_PORT_DATA));
}

/* ------------------------------------------------------------------ */
/* Sysctl handlers                                                     */
/* ------------------------------------------------------------------ */

/*
 * Temperature handler - returns decikelvin (int), matching the "IK"
 * sysctl convention used by amdtemp(4) and lm75(4).
 * 0 deg C = 2731 (273.1 K * 10).  Each register LSB is 1 deg C.
 * arg2 = 0..2 selects TEMP1..TEMP3.
 */
static int
ithwm_sysctl_temp(SYSCTL_HANDLER_ARGS)
{
	struct ithwm_softc *sc = arg1;
	int		idx = arg2;
	int8_t		raw;
	int		val;
	const uint8_t regs[ITHWM_NTEMPS] = {
		ITHWM_REG_TEMP1, ITHWM_REG_TEMP2, ITHWM_REG_TEMP3
	};

	KASSERT(idx >= 0 && idx < ITHWM_NTEMPS,
	    ("%s: idx %d out of range", __func__, idx));

	mtx_lock(&sc->lock);
	raw = (int8_t)ithwm_readb(sc, regs[idx]);
	mtx_unlock(&sc->lock);

	/* Convert deg C register value to decikelvin for "IK" sysctl format */
	val = (int)raw * 10 + ITHWM_ZERO_C_TO_K;
	return (sysctl_handle_int(oidp, &val, 0, req));
}

/*
 * Fan speed handler - returns RPM (unsigned int).
 * arg2 = 0..4 selects FAN1..FAN5.
 *
 * RPM = clock / (count * 2); count 0 or 0xffff => stalled / absent => 0 RPM.
 */
static int
ithwm_sysctl_fan(SYSCTL_HANDLER_ARGS)
{
	struct ithwm_softc *sc = arg1;
	int		idx = arg2;
	uint16_t	count;
	unsigned int	rpm;
	const uint8_t lregs[ITHWM_NFANS] = {
		ITHWM_REG_FAN1_L, ITHWM_REG_FAN2_L, ITHWM_REG_FAN3_L,
		ITHWM_REG_FAN4_L, ITHWM_REG_FAN5_L
	};
	const uint8_t hregs[ITHWM_NFANS] = {
		ITHWM_REG_FAN1_H, ITHWM_REG_FAN2_H, ITHWM_REG_FAN3_H,
		ITHWM_REG_FAN4_H, ITHWM_REG_FAN5_H
	};

	KASSERT(idx >= 0 && idx < ITHWM_NFANS,
	    ("%s: idx %d out of range", __func__, idx));

	mtx_lock(&sc->lock);
	count = ithwm_readb(sc, lregs[idx]);
	count |= (uint16_t)ithwm_readb(sc, hregs[idx]) << 8;
	mtx_unlock(&sc->lock);

	if (count == 0 || count == 0xffff)
		rpm = 0;
	else
		rpm = ITHWM_FAN_CLOCK /
		    ((unsigned int)count * ITHWM_FAN16_DIV);

	return (sysctl_handle_int(oidp, &rpm, 0, req));
}

/*
 * Voltage handler - returns millivolts (unsigned int).
 * arg2 = 0..ITHWM_NVINS selects VIN0..VIN7 then VBAT.
 *
 * Each ADC LSB is 11 mV (22 mV for the internally scaled VIN7 and VBAT).
 * On-board voltage dividers for higher rails (e.g. +12 V) are
 * board-specific and not applied.
 */
static int
ithwm_sysctl_vin(SYSCTL_HANDLER_ARGS)
{
	struct ithwm_softc *sc = arg1;
	int		idx = arg2;
	unsigned int	mv;
	uint8_t		raw;
	const uint8_t regs[ITHWM_NVINS + 1] = {
		ITHWM_REG_VIN0, ITHWM_REG_VIN1, ITHWM_REG_VIN2,
		ITHWM_REG_VIN3, ITHWM_REG_VIN4, ITHWM_REG_VIN5,
		ITHWM_REG_VIN6, ITHWM_REG_VIN7, ITHWM_REG_VBAT
	};

	KASSERT(idx >= 0 && idx <= ITHWM_NVINS,
	    ("%s: idx %d out of range", __func__, idx));

	mtx_lock(&sc->lock);
	raw = ithwm_readb(sc, regs[idx]);
	mtx_unlock(&sc->lock);

	mv = (unsigned int)raw * ITHWM_ADC_LSB_MV;
	if (ITHWM_VIN_SCALED & (1 << idx))
		mv *= 2;
	return (sysctl_handle_int(oidp, &mv, 0, req));
}

/* ------------------------------------------------------------------ */
/* Probe / Attach / Detach                                            */
/* ------------------------------------------------------------------ */

static int
ithwm_probe(device_t dev)
{
	if (superio_vendor(dev) != SUPERIO_VENDOR_ITE)
		return (ENXIO);
	if (superio_get_type(dev) != SUPERIO_DEV_HWM)
		return (ENXIO);
	if (superio_devid(dev) != ITHWM_DEVID_IT8613)
		return (ENXIO);
	device_set_desc(dev, "ITE IT8613E Hardware Monitor");
	return (BUS_PROBE_DEFAULT);
}

static int
ithwm_attach(device_t dev)
{
	struct ithwm_softc *sc;
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid_list *tree;
	uint16_t	iobase;
	int8_t		temp;
	int		i;
	char		name[8];
	char		desc[64];

	sc = device_get_softc(dev);

	iobase = superio_get_iobase(dev);
	if (iobase == 0 || iobase == 0xffff) {
		device_printf(dev, "invalid I/O base address 0x%x\n", iobase);
		return (ENXIO);
	}

	/*
	 * The IT87xx HWM window is 8 bytes wide.  Sensor registers are
	 * accessed via the index/data port pair at iobase+5 / iobase+6.
	 */
	sc->io_rid = 0;
	if (bus_set_resource(dev, SYS_RES_IOPORT, sc->io_rid,
	    iobase, ITHWM_IOSIZE) != 0) {
		device_printf(dev, "failed to set I/O resource at 0x%x\n",
		    iobase);
		return (ENXIO);
	}
	sc->io_res = bus_alloc_resource_any(dev, SYS_RES_IOPORT,
	    &sc->io_rid, RF_ACTIVE);
	if (sc->io_res == NULL) {
		device_printf(dev, "can't map I/O space at 0x%x\n", iobase);
		bus_delete_resource(dev, SYS_RES_IOPORT, sc->io_rid);
		return (ENXIO);
	}

	mtx_init(&sc->lock, "ithwm", NULL, MTX_DEF);

	if (bootverbose)
		device_printf(dev, "iobase 0x%x\n", iobase);

	ctx = device_get_sysctl_ctx(dev);
	tree = SYSCTL_CHILDREN(device_get_sysctl_tree(dev));

	/* Temperatures: temp0, temp1, temp2; skip unconnected sensors */
	for (i = 0; i < ITHWM_NTEMPS; i++) {
		mtx_lock(&sc->lock);
		temp = (int8_t)ithwm_readb(sc, ITHWM_REG_TEMP1 + i);
		mtx_unlock(&sc->lock);
		if (temp == ITHWM_TEMP_NONE)
			continue;
		snprintf(name, sizeof(name), "temp%d", i);
		SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, name,
		    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, i, ithwm_sysctl_temp, "IK",
		    "Temperature sensor");
	}

	/* Fan speeds: fan1..fan4 */
	for (i = 0; i < ITHWM_NFANS; i++) {
		if (ITHWM_FAN_ABSENT & (1 << i))
			continue;
		snprintf(name, sizeof(name), "fan%d", i);
		SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, name,
		    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, i, ithwm_sysctl_fan, "IU", "Fan speed in RPM");
	}

	/* Voltages: vin0..vin7 except absent inputs, vbat */
	for (i = 0; i < ITHWM_NVINS; i++) {
		if (ITHWM_VIN_ABSENT & (1 << i))
			continue;
		snprintf(name, sizeof(name), "vin%d", i);
		if (ITHWM_VIN_SCALED & (1 << i))
			snprintf(desc, sizeof(desc),
			    "3VSB voltage in millivolts");
		else
			snprintf(desc, sizeof(desc), "Voltage at VIN%d pin in "
			    "millivolts (rail is board-specific)", i);
		SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, name,
		    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, i, ithwm_sysctl_vin, "IU", desc);
	}
	SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, "vbat",
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, ITHWM_NVINS, ithwm_sysctl_vin, "IU",
	    "Battery voltage in millivolts");

	return (0);
}

static int
ithwm_detach(device_t dev)
{
	struct ithwm_softc *sc = device_get_softc(dev);

	/*
	 * Remove all sysctl OIDs and drain any handler that is currently
	 * running before tearing down the hardware.  After this returns,
	 * no sysctl handler can execute or will ever run again for this
	 * device, so it is safe to destroy the mutex and release resources.
	 */
	sysctl_ctx_free(device_get_sysctl_ctx(dev));

	mtx_destroy(&sc->lock);
	bus_release_resource(dev, SYS_RES_IOPORT, sc->io_rid, sc->io_res);
	return (0);
}

/* ------------------------------------------------------------------ */
/* Driver registration                                                 */
/* ------------------------------------------------------------------ */

static device_method_t ithwm_methods[] = {
	DEVMETHOD(device_probe,		ithwm_probe),
	DEVMETHOD(device_attach,	ithwm_attach),
	DEVMETHOD(device_detach,	ithwm_detach),
	DEVMETHOD_END
};

static driver_t ithwm_driver = {
	"ithwm",
	ithwm_methods,
	sizeof(struct ithwm_softc)
};

DRIVER_MODULE(ithwm, superio, ithwm_driver, NULL, NULL);
MODULE_DEPEND(ithwm, superio, 1, 1, 1);
MODULE_VERSION(ithwm, 1);

/*
 * PNP info table for devmatch(8) / devd(8) auto-loading.
 * The superio bus publishes pnpinfo "type=HWM" for hardware monitor LDNs.
 * devmatch strips trailing digits from the parent name to get bus="superio".
 */
static const struct {
	const char *type;
} ithwm_pnp_table[] = {
	{ "HWM" },
	{ NULL }
};
MODULE_PNP_INFO("Z:type", superio, ithwm, ithwm_pnp_table,
    nitems(ithwm_pnp_table) - 1);
