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
 *   MSR_AMD_PKG_ENERGY     0xC001029B  Package energy counter (32-bit on
 *                                      Family 17h and 19h, 64-bit on
 *                                      Family 1Ah)
 *
 * MSR_AMD_CORE_ENERGY is per-physical-core: reading it on logical CPU N
 * returns the accumulated energy of the physical core that CPU N belongs to.
 * When SMT is enabled, both logical threads of a core read the same counter.
 * The driver reads only the first logical thread of each physical core to
 * avoid double-counting.  Physical-core membership is determined at attach
 * time via CPUID leaf 0x8000001E, whose EBX[15:8] field reports
 * ThreadsPerComputeUnit - 1.
 *
 * The 32-bit counters wrap; the driver handles this transparently via
 * unsigned subtraction in a wide enough type.
 *
 * References:
 *   - AMD PPR for Family 17h / 19h / 1Ah (AMD public documentation)
 *   - sys/dev/amdtemp/amdtemp.c  (PCI device ID table, attach pattern)
 *   - sys/dev/ithwm/ithwm.c      (sysctl and callout style)
 *   - sys/dev/cpuctl/cpuctl.c    (sched_bind / rdmsr_safe pattern)
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
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

/* Default measurement interval. */
#define	AMDPWR_INTERVAL_MS_DEFAULT	250

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

	uint32_t		sc_energy_shift;  /* from RAPL_PWR_UNIT [12:8] */
	int			sc_interval_ms;

	/*
	 * Package-level counters.  The package energy MSR returns the same
	 * value from any CPU in the package, so the poll callout reads it on
	 * whichever CPU it happens to run on (no binding needed).
	 * The package counter is 64-bit on Family 1Ah (Strix Halo and later);
	 * using uint64_t here is correct for all supported families.
	 */
	uint64_t		sc_pkg_prev;
	uint32_t		sc_pkg_mw;

	/* Per-physical-core array, allocated at attach. */
	struct amdpwr_core	*sc_cores;
	int			sc_ncores;
};

/*
 * Read an MSR on a specific logical CPU.
 *
 * Saves the current CPU binding, migrates to the target CPU, reads the MSR,
 * then restores the original binding.  Must be called from a non-preemptible
 * context with no locks held (sched_bind acquires the thread lock internally).
 */
static int
amdpwr_rdmsr_on_cpu(int cpu, uint32_t msr, uint64_t *val)
{
	struct thread *td;
	int oldcpu, is_bound, error;

	td = curthread;
	thread_lock(td);
	is_bound = sched_is_bound(td);
	oldcpu = td->td_oncpu;
	sched_bind(td, cpu);
	thread_unlock(td);

	error = rdmsr_safe(msr, val);

	thread_lock(td);
	if (is_bound)
		sched_bind(td, oldcpu);
	else
		sched_unbind(td);
	thread_unlock(td);

	return (error);
}

/*
 * Callout: read all energy counters, compute average power, reschedule.
 *
 * Power (mW) = delta_count * 1000000 / (2^energy_shift * interval_ms)
 *
 * We multiply delta by 1000000 before dividing to avoid integer truncation
 * to zero (at shift=16 and interval_ms=250 the divisor is 16,384,000).
 * A 32-bit delta * 1,000,000 fits in 52 bits, safe in uint64_t.
 */
static void
amdpwr_poll(void *arg)
{
	struct amdpwr_softc *sc = arg;
	uint64_t raw64, pkg_delta;
	uint32_t core_raw, core_delta;
	uint64_t divisor;
	int i;

	mtx_assert(&sc->sc_lock, MA_OWNED);

	divisor = (uint64_t)(1u << sc->sc_energy_shift) *
	    (uint32_t)sc->sc_interval_ms;

	/*
	 * Package energy: read on the current CPU (all CPUs in the package
	 * return the same value for this MSR, so no binding is needed).
	 * The counter is 32-bit on Family 17h/19h and 64-bit on Family 1Ah;
	 * sc_pkg_prev is uint64_t so unsigned subtraction handles both cases.
	 */
	if (rdmsr_safe(MSR_AMD_PKG_ENERGY, &raw64) == 0) {
		pkg_delta = raw64 - sc->sc_pkg_prev;
		sc->sc_pkg_prev = raw64;
		sc->sc_pkg_mw = (uint32_t)(
		    (pkg_delta * 1000000) / divisor);
	}

	/* Per-core energy: must read on each core's assigned logical CPU. */
	for (i = 0; i < sc->sc_ncores; i++) {
		/*
		 * Drop the mutex while migrating between CPUs to avoid
		 * holding it across sched_bind which acquires the thread
		 * lock.  The callout re-acquires it after each MSR read.
		 * The per-core prev/mw fields are only written here so
		 * there is no concurrent write hazard during the gap.
		 */
		mtx_unlock(&sc->sc_lock);
		if (amdpwr_rdmsr_on_cpu(sc->sc_cores[i].cpu,
		    MSR_AMD_CORE_ENERGY, &raw64) == 0) {
			core_raw = (uint32_t)raw64;
			mtx_lock(&sc->sc_lock);
			core_delta = core_raw - sc->sc_cores[i].prev;
			sc->sc_cores[i].prev = core_raw;
			sc->sc_cores[i].mw  = (uint32_t)(
			    ((uint64_t)core_delta * 1000000) / divisor);
		} else {
			mtx_lock(&sc->sc_lock);
		}
	}

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
	if (val <= 0)
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
	device_t child;

	if (device_find_child(parent, "amdpower", DEVICE_UNIT_ANY) != NULL)
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

	if (resource_disabled("amdpower", 0))
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
 * Determine which logical CPUs are the first thread of each physical core.
 *
 * CPUID leaf 0x8000001E (Zen and later) reports:
 *   EBX bits [15:8]: ThreadsPerComputeUnit - 1
 *
 * If ThreadsPerComputeUnit > 1, SMT is active.  This value is uniform across
 * the package, so we read it once on whichever CPU this function happens to
 * run on (attach context) and use it as the stride.
 *
 * FreeBSD numbers logical CPUs such that the SMT siblings of a physical core
 * are contiguous (cpu0+cpu1 -> core0, cpu2+cpu3 -> core1, ...), so selecting
 * every Nth logical CPU (where N = threads_per_core) yields exactly one
 * logical CPU per physical core.
 */
static int
amdpwr_find_cores(struct amdpwr_softc *sc)
{
	u_int regs[4];
	int threads_per_core, cpu, ncores;
	uint64_t raw;

	/* Verify CPUID leaf 0x8000001E is available. */
	do_cpuid(0x80000000, regs);
	if (regs[0] < 0x8000001e) {
		/* No extended topology leaf: treat every logical CPU as a core. */
		threads_per_core = 1;
	} else {
		do_cpuid(0x8000001e, regs);
		threads_per_core = ((regs[1] >> 8) & 0xff) + 1;
	}

	ncores = 0;
	CPU_FOREACH(cpu) {
		/*
		 * Only take every Nth logical CPU where N = threads_per_core.
		 * This selects the first thread of each physical core.
		 */
		if ((cpu % threads_per_core) != 0)
			continue;
		if (ncores >= AMDPWR_MAX_CORES)
			break;

		/* Verify the MSR is readable on this CPU. */
		if (amdpwr_rdmsr_on_cpu(cpu, MSR_AMD_CORE_ENERGY, &raw) != 0)
			continue;

		sc->sc_cores[ncores].cpu  = cpu;
		sc->sc_cores[ncores].prev = (uint32_t)raw;
		sc->sc_cores[ncores].mw   = 0;
		ncores++;
	}

	return (ncores);
}

static int
amdpwr_attach(device_t dev)
{
	struct amdpwr_softc *sc;
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid_list *tree;
	uint64_t pwr_unit, pkg_raw;
	char name[16];
	char desc[48];
	int i;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	sc->sc_interval_ms = AMDPWR_INTERVAL_MS_DEFAULT;

	/* Read unit exponent from RAPL_PWR_UNIT. */
	pwr_unit = rdmsr(MSR_AMD_RAPL_PWR_UNIT);
	sc->sc_energy_shift = (uint32_t)(
	    (pwr_unit >> RAPL_ENERGY_UNIT_SHIFT) & RAPL_ENERGY_UNIT_MASK);
	if (sc->sc_energy_shift == 0) {
		device_printf(dev, "RAPL energy unit is 0; MSR not supported\n");
		return (ENXIO);
	}

	if (bootverbose)
		device_printf(dev,
		    "RAPL_PWR_UNIT=0x%016llx energy_shift=%u "
		    "(1 LSB = 1/%u J)\n",
		    (unsigned long long)pwr_unit,
		    sc->sc_energy_shift,
		    1u << sc->sc_energy_shift);

	/* Allocate per-core array. */
	sc->sc_cores = mallocarray(AMDPWR_MAX_CORES,
	    sizeof(*sc->sc_cores), M_AMDPWR, M_WAITOK | M_ZERO);

	/* Discover physical cores and prime their counters. */
	sc->sc_ncores = amdpwr_find_cores(sc);
	if (sc->sc_ncores == 0) {
		device_printf(dev, "no readable core energy MSRs found\n");
		free(sc->sc_cores, M_AMDPWR);
		return (ENXIO);
	}

	/* Prime package counter. */
	if (rdmsr_safe(MSR_AMD_PKG_ENERGY, &pkg_raw) != 0) {
		device_printf(dev, "package energy MSR not readable\n");
		free(sc->sc_cores, M_AMDPWR);
		return (ENXIO);
	}
	sc->sc_pkg_prev = pkg_raw;
	sc->sc_pkg_mw   = 0;

	if (bootverbose)
		device_printf(dev, "%d physical core(s) found\n",
		    sc->sc_ncores);

	mtx_init(&sc->sc_lock, "amdpower", NULL, MTX_DEF);
	callout_init_mtx(&sc->sc_callout, &sc->sc_lock, 0);
	callout_reset(&sc->sc_callout,
	    MSEC_2_TICKS(sc->sc_interval_ms), amdpwr_poll, sc);

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
	free(sc->sc_cores, M_AMDPWR);
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
