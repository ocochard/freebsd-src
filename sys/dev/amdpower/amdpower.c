/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Olivier Cochard
 */

/*
 * Driver for AMD CPU power sensors using RAPL (Running Average Power Limit)
 * energy counters.
 *
 * Exposes average power in milliwatts via sysctl under dev.amdpower.<unit>:
 *
 *   pkg_power      Package (socket) average power
 *   core<N>_power  Per-physical-core average power (one per physical core)
 *   interval_ms    Measurement interval, tunable (default: 250 ms)
 *
 * Power is computed from snapshots of the AMD RAPL energy counters that are
 * documented in the AMD Processor Programming Reference (PPR):
 *
 *   MSR_AMD_RAPL_PWR_UNIT  0xC0010299  Energy / power / time unit exponents
 *   MSR_AMD_CORE_ENERGY    0xC001029A  Per-core energy counter (32-bit)
 *   MSR_AMD_PKG_ENERGY     0xC001029B  Package energy counter (32-bit)
 *
 * MSR_AMD_CORE_ENERGY is per-physical-core: reading it on logical CPU N
 * returns the accumulated energy of the physical core that CPU N belongs to.
 * When SMT is enabled, both logical threads of a core read the same counter.
 * The driver reads only the first logical thread of each physical core to
 * avoid double-counting.  The first thread is the one whose APIC ID has the
 * SMT bits clear; the number of threads per core comes from CPUID leaf
 * 0x8000001E, whose EBX[15:8] field reports ThreadsPerComputeUnit - 1.
 *
 * A periodic callout snapshots all counters in a single SMP rendezvous and
 * divides the energy deltas by the measured elapsed time.  The 32-bit
 * counters wrap; unsigned 32-bit subtraction handles a single wrap between
 * snapshots, which interval_ms is bounded to guarantee.
 *
 * Only one instance attaches.  On multi-socket systems pkg_power reports the
 * package of the first core.
 *
 * References:
 *   - AMD PPR for Family 17h / 19h / 1Ah (AMD public documentation)
 *   - sys/dev/amdtemp/amdtemp.c  (PCI device ID table, attach pattern)
 *   - sys/dev/ithwm/ithwm.c      (sysctl style)
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/cpuset.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>

#include <dev/pci/pcivar.h>

/* AMD RAPL MSR addresses (AMD PPR, publicly documented). */
#define	MSR_AMD_RAPL_PWR_UNIT	0xC0010299U
#define	MSR_AMD_CORE_ENERGY	0xC001029AU
#define	MSR_AMD_PKG_ENERGY	0xC001029BU

/*
 * RAPL_PWR_UNIT fields (MSR 0xC0010299):
 *   bits [3:0]   PwrUnits    power  unit = 1/2^PU  watts
 *   bits [12:8]  EnergyUnits energy unit = 1/2^ESU joules
 *   bits [19:16] TimeUnits   time   unit = 1/2^TU  seconds
 */
#define	RAPL_ENERGY_UNIT_SHIFT	8
#define	RAPL_ENERGY_UNIT_MASK	0x1fu

/*
 * Measurement interval.  The upper bound keeps the 32-bit counters from
 * wrapping more than once between snapshots (about 218 s at 300 W with an
 * energy unit of 1/2^16 J).
 */
#define	AMDPWR_INTERVAL_MS_DEFAULT	250
#define	AMDPWR_INTERVAL_MS_MIN		10
#define	AMDPWR_INTERVAL_MS_MAX		60000

/* Maximum physical cores we will expose (covers all current Zen CPUs). */
#define	AMDPWR_MAX_CORES	128

/* PCI vendor/device IDs for AMD host bridges hosting Zen-class CPUs. */
#define	VENDORID_AMD				0x1022u
#define	DEVICEID_AMD_HOSTB17H_ROOT		0x1450u
#define	DEVICEID_AMD_HOSTB17H_M10H_ROOT		0x15d0u
#define	DEVICEID_AMD_HOSTB17H_M30H_ROOT		0x1480u
#define	DEVICEID_AMD_HOSTB17H_M60H_ROOT		0x1630u
#define	DEVICEID_AMD_HOSTB19H_M10H_ROOT		0x14a4u
#define	DEVICEID_AMD_HOSTB19H_M40H_ROOT		0x14b5u
#define	DEVICEID_AMD_HOSTB19H_M60H_ROOT		0x14d8u
#define	DEVICEID_AMD_HOSTB19H_M70H_ROOT		0x14e8u
#define	DEVICEID_AMD_HOSTB1AH_M00H_ROOT		0x153au
#define	DEVICEID_AMD_HOSTB1AH_M20H_ROOT		0x1507u
#define	DEVICEID_AMD_HOSTB1AH_M60H_ROOT		0x1122u

static const struct amdpwr_product {
	uint16_t	vendorid;
	uint16_t	deviceid;
} amdpwr_products[] = {
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB17H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB17H_M10H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB17H_M30H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB17H_M60H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB19H_M10H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB19H_M40H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB19H_M60H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB19H_M70H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB1AH_M00H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB1AH_M20H_ROOT },
	{ VENDORID_AMD, DEVICEID_AMD_HOSTB1AH_M60H_ROOT },
};

MALLOC_DEFINE(M_AMDPWR, "amdpower", "amdpower per-core state");

/* Per-physical-core state. */
struct amdpwr_core {
	int		cpu;		/* logical CPU number to read MSR on */
	uint32_t	prev;		/* previous raw counter value */
	uint32_t	mw;		/* last computed power (milliwatts) */
};

struct amdpwr_softc {
	device_t		sc_dev;
	struct mtx		sc_lock;
	struct callout		sc_callout;

	uint32_t		sc_energy_shift; /* RAPL_PWR_UNIT [12:8] */
	int			sc_interval_ms;
	sbintime_t		sc_prev_sbt;	 /* previous snapshot */

	/* CPUs sampled by the rendezvous and their raw counters by CPU id. */
	cpuset_t		sc_cpus;
	uint32_t		*sc_raw;

	/* Package counter, read on sc_pkg_cpu during the rendezvous. */
	int			sc_pkg_cpu;
	uint32_t		sc_pkg_raw;
	uint32_t		sc_pkg_prev;
	uint32_t		sc_pkg_mw;

	/* Per-physical-core array, allocated at attach. */
	struct amdpwr_core	*sc_cores;
	int			sc_ncores;
};

/*
 * Rendezvous action: runs on every CPU in sc_cpus with interrupts disabled.
 * The MSRs were verified readable on these CPUs at attach time.
 */
static void
amdpwr_read_action(void *arg)
{
	struct amdpwr_softc *sc = arg;
	u_int cpu = curcpu;

	sc->sc_raw[cpu] = (uint32_t)rdmsr(MSR_AMD_CORE_ENERGY);
	if (cpu == (u_int)sc->sc_pkg_cpu)
		sc->sc_pkg_raw = (uint32_t)rdmsr(MSR_AMD_PKG_ENERGY);
}

/* Snapshot all counters and return the time of the snapshot. */
static sbintime_t
amdpwr_snapshot(struct amdpwr_softc *sc)
{
	smp_rendezvous_cpus(sc->sc_cpus, smp_no_rendezvous_barrier,
	    amdpwr_read_action, smp_no_rendezvous_barrier, sc);
	return (sbinuptime());
}

/*
 * Power (mW) = delta * 10^9 / (2^energy_shift * dt_us)
 *
 * A 32-bit delta * 10^9 is below 2^62, so the product fits in uint64_t.
 */
static uint32_t
amdpwr_mw(uint32_t delta, uint64_t dt_us, uint32_t shift)
{
	return ((uint32_t)(((uint64_t)delta * 1000000000ULL / dt_us) >> shift));
}

/* Callout: snapshot all energy counters, compute average power, reschedule. */
static void
amdpwr_poll(void *arg)
{
	struct amdpwr_softc *sc = arg;
	struct amdpwr_core *core;
	sbintime_t now;
	uint64_t dt_us;
	uint32_t raw;
	int i;

	mtx_assert(&sc->sc_lock, MA_OWNED);

	now = amdpwr_snapshot(sc);
	dt_us = (uint64_t)(now - sc->sc_prev_sbt) / SBT_1US;
	sc->sc_prev_sbt = now;

	if (dt_us > 0) {
		sc->sc_pkg_mw = amdpwr_mw(sc->sc_pkg_raw - sc->sc_pkg_prev,
		    dt_us, sc->sc_energy_shift);
		for (i = 0; i < sc->sc_ncores; i++) {
			core = &sc->sc_cores[i];
			raw = sc->sc_raw[core->cpu];
			core->mw = amdpwr_mw(raw - core->prev, dt_us,
			    sc->sc_energy_shift);
		}
	}
	sc->sc_pkg_prev = sc->sc_pkg_raw;
	for (i = 0; i < sc->sc_ncores; i++)
		sc->sc_cores[i].prev = sc->sc_raw[sc->sc_cores[i].cpu];

	callout_reset(&sc->sc_callout,
	    MSEC_2_TICKS(sc->sc_interval_ms), amdpwr_poll, sc);
}

/* ------------------------------------------------------------------ */
/* Sysctl handlers                                                     */
/* ------------------------------------------------------------------ */

static int
amdpwr_sysctl_pkg(SYSCTL_HANDLER_ARGS)
{
	struct amdpwr_softc *sc = arg1;
	uint32_t val;

	mtx_lock(&sc->sc_lock);
	val = sc->sc_pkg_mw;
	mtx_unlock(&sc->sc_lock);
	return (sysctl_handle_int(oidp, &val, 0, req));
}

static int
amdpwr_sysctl_core(SYSCTL_HANDLER_ARGS)
{
	struct amdpwr_softc *sc = arg1;
	int idx = arg2;
	uint32_t val;

	mtx_lock(&sc->sc_lock);
	val = sc->sc_cores[idx].mw;
	mtx_unlock(&sc->sc_lock);
	return (sysctl_handle_int(oidp, &val, 0, req));
}

static int
amdpwr_sysctl_interval(SYSCTL_HANDLER_ARGS)
{
	struct amdpwr_softc *sc = arg1;
	int val, error;

	mtx_lock(&sc->sc_lock);
	val = sc->sc_interval_ms;
	mtx_unlock(&sc->sc_lock);

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (val < AMDPWR_INTERVAL_MS_MIN || val > AMDPWR_INTERVAL_MS_MAX)
		return (EINVAL);

	mtx_lock(&sc->sc_lock);
	sc->sc_interval_ms = val;
	mtx_unlock(&sc->sc_lock);
	return (0);
}

/* ------------------------------------------------------------------ */
/* Identify / Probe / Attach / Detach                                  */
/* ------------------------------------------------------------------ */

static bool
amdpwr_match(device_t dev)
{
	uint16_t vendor, devid;
	int i;

	vendor = pci_get_vendor(dev);
	devid  = pci_get_device(dev);
	for (i = 0; i < nitems(amdpwr_products); i++) {
		if (vendor == amdpwr_products[i].vendorid &&
		    devid  == amdpwr_products[i].deviceid)
			return (true);
	}
	return (false);
}

static void
amdpwr_identify(driver_t *driver, device_t parent)
{
	devclass_t dc;
	device_t child;

	/*
	 * Multi-node parts expose one matching root complex per node, but
	 * the energy counters are per core and per package, not per node:
	 * attach a single instance system-wide.
	 */
	dc = devclass_find("amdpower");
	if (dc != NULL && devclass_get_device(dc, 0) != NULL)
		return;
	if (amdpwr_match(parent)) {
		child = device_add_child(parent, "amdpower", DEVICE_UNIT_ANY);
		if (child == NULL)
			device_printf(parent, "add amdpower child failed\n");
	}
}

static int
amdpwr_probe(device_t dev)
{
	uint32_t family;

	if (resource_disabled("amdpower", device_get_unit(dev)))
		return (ENXIO);
	if (!amdpwr_match(device_get_parent(dev)))
		return (ENXIO);

	family = CPUID_TO_FAMILY(cpu_id);
	switch (family) {
	case 0x17:
	case 0x19:
	case 0x1a:
		break;
	default:
		return (ENXIO);
	}

	device_set_descf(dev, "AMD Family %02Xh CPU Power Sensors", family);
	return (BUS_PROBE_GENERIC);
}

/*
 * Select the first logical CPU of each physical core and verify that the
 * core energy MSR is readable there.
 *
 * CPUID leaf 0x8000001E (Zen and later) reports:
 *   EBX bits [15:8]: ThreadsPerComputeUnit - 1
 *
 * The value is uniform across the system, so it is read once on whichever
 * CPU attach runs on.  The SMT threads of a core share all APIC ID bits
 * except the low log2(threads) ones, so the first thread of each core is
 * the one whose APIC ID is a multiple of the thread count.
 */
static int
amdpwr_find_cores(struct amdpwr_softc *sc)
{
	u_int regs[4];
	int threads_per_core, cpu, ncores;
	uint64_t raw;

	do_cpuid(0x80000000, regs);
	if (regs[0] < 0x8000001e) {
		/* No extended topology leaf: every logical CPU is a core. */
		threads_per_core = 1;
	} else {
		do_cpuid(0x8000001e, regs);
		threads_per_core = ((regs[1] >> 8) & 0xff) + 1;
	}

	CPU_ZERO(&sc->sc_cpus);
	ncores = 0;
	CPU_FOREACH(cpu) {
		if ((pcpu_find(cpu)->pc_apic_id % threads_per_core) != 0)
			continue;
		if (ncores >= AMDPWR_MAX_CORES)
			break;

		if (x86_msr_op(MSR_AMD_CORE_ENERGY, MSR_OP_READ | MSR_OP_SAFE |
		    MSR_OP_SCHED_ONE | MSR_OP_CPUID(cpu), 0, &raw) != 0)
			continue;

		sc->sc_cores[ncores].cpu = cpu;
		CPU_SET(cpu, &sc->sc_cpus);
		ncores++;
	}

	return (ncores);
}

static void
amdpwr_free(struct amdpwr_softc *sc)
{
	free(sc->sc_cores, M_AMDPWR);
	free(sc->sc_raw, M_AMDPWR);
}

static int
amdpwr_attach(device_t dev)
{
	struct amdpwr_softc *sc;
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid_list *tree;
	uint64_t pwr_unit, raw;
	char name[16];
	char desc[48];
	int i;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	sc->sc_interval_ms = AMDPWR_INTERVAL_MS_DEFAULT;

	/* Read unit exponent from RAPL_PWR_UNIT. */
	if (rdmsr_safe(MSR_AMD_RAPL_PWR_UNIT, &pwr_unit) != 0) {
		device_printf(dev, "RAPL_PWR_UNIT MSR not readable\n");
		return (ENXIO);
	}
	sc->sc_energy_shift = (uint32_t)(
	    (pwr_unit >> RAPL_ENERGY_UNIT_SHIFT) & RAPL_ENERGY_UNIT_MASK);
	if (sc->sc_energy_shift == 0) {
		device_printf(dev,
		    "RAPL energy unit is 0; MSR not supported\n");
		return (ENXIO);
	}

	if (bootverbose)
		device_printf(dev,
		    "RAPL_PWR_UNIT=0x%016llx energy_shift=%u "
		    "(1 LSB = 1/%u J)\n",
		    (unsigned long long)pwr_unit,
		    sc->sc_energy_shift,
		    1u << sc->sc_energy_shift);

	sc->sc_cores = mallocarray(AMDPWR_MAX_CORES,
	    sizeof(*sc->sc_cores), M_AMDPWR, M_WAITOK | M_ZERO);
	sc->sc_raw = mallocarray(mp_maxid + 1, sizeof(*sc->sc_raw),
	    M_AMDPWR, M_WAITOK | M_ZERO);

	sc->sc_ncores = amdpwr_find_cores(sc);
	if (sc->sc_ncores == 0) {
		device_printf(dev, "no readable core energy MSRs found\n");
		amdpwr_free(sc);
		return (ENXIO);
	}

	sc->sc_pkg_cpu = sc->sc_cores[0].cpu;
	if (x86_msr_op(MSR_AMD_PKG_ENERGY, MSR_OP_READ | MSR_OP_SAFE |
	    MSR_OP_SCHED_ONE | MSR_OP_CPUID(sc->sc_pkg_cpu), 0, &raw) != 0) {
		device_printf(dev, "package energy MSR not readable\n");
		amdpwr_free(sc);
		return (ENXIO);
	}

	if (bootverbose)
		device_printf(dev, "%d physical core(s) found\n",
		    sc->sc_ncores);

	/* Prime all counters. */
	sc->sc_prev_sbt = amdpwr_snapshot(sc);
	sc->sc_pkg_prev = sc->sc_pkg_raw;
	for (i = 0; i < sc->sc_ncores; i++)
		sc->sc_cores[i].prev = sc->sc_raw[sc->sc_cores[i].cpu];

	mtx_init(&sc->sc_lock, "amdpower", NULL, MTX_DEF);
	callout_init_mtx(&sc->sc_callout, &sc->sc_lock, 0);
	mtx_lock(&sc->sc_lock);
	callout_reset(&sc->sc_callout,
	    MSEC_2_TICKS(sc->sc_interval_ms), amdpwr_poll, sc);
	mtx_unlock(&sc->sc_lock);

	ctx  = device_get_sysctl_ctx(dev);
	tree = SYSCTL_CHILDREN(device_get_sysctl_tree(dev));

	SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, "pkg_power",
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE,
	    sc, 0, amdpwr_sysctl_pkg, "IU",
	    "Average package power in milliwatts");

	for (i = 0; i < sc->sc_ncores; i++) {
		snprintf(name, sizeof(name), "core%d_power", i);
		snprintf(desc, sizeof(desc),
		    "Average core %d power in milliwatts (cpu%d)",
		    i, sc->sc_cores[i].cpu);
		SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, name,
		    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_MPSAFE,
		    sc, i, amdpwr_sysctl_core, "IU", desc);
	}

	SYSCTL_ADD_PROC(ctx, tree, OID_AUTO, "interval_ms",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
	    sc, 0, amdpwr_sysctl_interval, "I",
	    "Measurement interval in milliseconds");

	return (0);
}

static int
amdpwr_detach(device_t dev)
{
	struct amdpwr_softc *sc = device_get_softc(dev);

	callout_drain(&sc->sc_callout);
	sysctl_ctx_free(device_get_sysctl_ctx(dev));
	mtx_destroy(&sc->sc_lock);
	amdpwr_free(sc);
	return (0);
}

/* ------------------------------------------------------------------ */
/* Driver registration                                                 */
/* ------------------------------------------------------------------ */

static device_method_t amdpwr_methods[] = {
	DEVMETHOD(device_identify,	amdpwr_identify),
	DEVMETHOD(device_probe,		amdpwr_probe),
	DEVMETHOD(device_attach,	amdpwr_attach),
	DEVMETHOD(device_detach,	amdpwr_detach),

	DEVMETHOD_END
};

static driver_t amdpwr_driver = {
	"amdpower",
	amdpwr_methods,
	sizeof(struct amdpwr_softc)
};

DRIVER_MODULE(amdpower, hostb, amdpwr_driver, NULL, NULL);
MODULE_VERSION(amdpower, 1);
MODULE_PNP_INFO("U16:vendor;U16:device", pci, amdpower, amdpwr_products,
    nitems(amdpwr_products));
