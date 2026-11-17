/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Olivier Cochard-Labbe <olivier@FreeBSD.org>
 */

/*
 * Interrupt sources for GPIO pins.
 *
 * x86 does not use INTRNG, so a GPIO controller cannot act as the interrupt
 * controller of the devices wired to its pins.  This pseudo-PIC fills the
 * gap.  Like MSI, it reserves a block of IRQ numbers at boot and creates an
 * interrupt source on demand for each mapped pin.  A GPIO controller driver
 * registers mask, unmask and trigger configuration methods, then calls
 * gpio_intr_dispatch() from its own interrupt filter for each pin with a
 * pending event.  The pin handlers therefore run nested in the interrupt
 * context of the controller's parent interrupt.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/gpio.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#include <machine/atomic.h>
#include <machine/intr_machdep.h>

struct gpio_intsrc {
	struct intsrc		gi_intsrc;
	struct gpio_intr_ctlr	*gi_ctlr;	/* NULL when the source is free */
	u_int			gi_pin;
	u_int			gi_irq;
	uint32_t		gi_mode;	/* GPIO_INTR_* */
};

struct gpio_intr_ctlr {
	device_t		gc_dev;
	const struct gpio_intr_ops *gc_ops;
	u_int			gc_npins;
	struct gpio_intsrc	**gc_src;	/* mapped source, by pin */
	TAILQ_ENTRY(gpio_intr_ctlr) gc_link;
};

static MALLOC_DEFINE(M_GPIOINTR, "gpiointr", "GPIO interrupt sources");

static u_int num_gpio_irqs = 32;
SYSCTL_UINT(_machdep, OID_AUTO, num_gpio_irqs, CTLFLAG_RDTUN, &num_gpio_irqs,
    0, "Number of IRQs reserved for GPIO pin interrupts");

static u_int first_gpio_irq;
static u_int gpio_nsrcs;		/* sources created so far */
static struct gpio_intsrc **gpio_srcs;	/* created sources, by IRQ offset */
static TAILQ_HEAD(, gpio_intr_ctlr) gpio_ctlrs =
    TAILQ_HEAD_INITIALIZER(gpio_ctlrs);
static struct sx gpio_intr_lock;
static bool gpio_intr_enabled;

static void
gpio_intr_enable_source(struct intsrc *isrc)
{
	struct gpio_intsrc *gi = (struct gpio_intsrc *)isrc;
	struct gpio_intr_ctlr *ctlr = gi->gi_ctlr;

	if (ctlr != NULL)
		ctlr->gc_ops->gio_unmask(ctlr->gc_dev, gi->gi_pin);
}

static void
gpio_intr_disable_source(struct intsrc *isrc, int eoi __unused)
{
	struct gpio_intsrc *gi = (struct gpio_intsrc *)isrc;
	struct gpio_intr_ctlr *ctlr = gi->gi_ctlr;

	if (ctlr != NULL)
		ctlr->gc_ops->gio_mask(ctlr->gc_dev, gi->gi_pin);
}

static void
gpio_intr_eoi_source(struct intsrc *isrc __unused)
{
	/* The controller acknowledges the event before dispatching it. */
}

static void
gpio_intr_enable_intr(struct intsrc *isrc __unused)
{
}

static void
gpio_intr_disable_intr(struct intsrc *isrc __unused)
{
}

static int
gpio_intr_vector(struct intsrc *isrc)
{
	struct gpio_intsrc *gi = (struct gpio_intsrc *)isrc;

	return (gi->gi_irq);
}

static int
gpio_intr_source_pending(struct intsrc *isrc __unused)
{
	return (0);
}

static int
gpio_intr_config_intr(struct intsrc *isrc, enum intr_trigger trig,
    enum intr_polarity pol)
{
	struct gpio_intsrc *gi = (struct gpio_intsrc *)isrc;
	struct gpio_intr_ctlr *ctlr = gi->gi_ctlr;
	uint32_t mode;
	bool high, level;
	int error;

	if (ctlr == NULL)
		return (ENXIO);
	if (trig == INTR_TRIGGER_CONFORM && pol == INTR_POLARITY_CONFORM)
		return (0);

	if (trig == INTR_TRIGGER_CONFORM)
		level = (gi->gi_mode &
		    (GPIO_INTR_LEVEL_LOW | GPIO_INTR_LEVEL_HIGH)) != 0;
	else
		level = trig == INTR_TRIGGER_LEVEL;
	if (pol == INTR_POLARITY_CONFORM)
		high = (gi->gi_mode &
		    (GPIO_INTR_LEVEL_HIGH | GPIO_INTR_EDGE_RISING)) != 0;
	else
		high = pol == INTR_POLARITY_HIGH;

	if (level)
		mode = high ? GPIO_INTR_LEVEL_HIGH : GPIO_INTR_LEVEL_LOW;
	else
		mode = high ? GPIO_INTR_EDGE_RISING : GPIO_INTR_EDGE_FALLING;

	error = ctlr->gc_ops->gio_config(ctlr->gc_dev, gi->gi_pin, mode);
	if (error == 0)
		gi->gi_mode = mode;
	return (error);
}

static int
gpio_intr_assign_cpu(struct intsrc *isrc __unused, u_int apic_id __unused)
{
	/* Pin handlers run on the CPU that takes the parent interrupt. */
	return (EOPNOTSUPP);
}

static struct pic gpio_pic = {
	.pic_enable_source = gpio_intr_enable_source,
	.pic_disable_source = gpio_intr_disable_source,
	.pic_eoi_source = gpio_intr_eoi_source,
	.pic_enable_intr = gpio_intr_enable_intr,
	.pic_disable_intr = gpio_intr_disable_intr,
	.pic_vector = gpio_intr_vector,
	.pic_source_pending = gpio_intr_source_pending,
	.pic_config_intr = gpio_intr_config_intr,
	.pic_assign_cpu = gpio_intr_assign_cpu,
};

/*
 * Reserve the GPIO IRQ block.  Must run before intr_init_sources() sizes
 * the interrupt source table.
 */
void
gpio_intr_init(void)
{
	if (num_gpio_irqs == 0)
		return;
	if (num_gpio_irqs > UINT_MAX - num_io_irqs)
		panic("num_gpio_irqs too high");

	first_gpio_irq = num_io_irqs;
	num_io_irqs += num_gpio_irqs;
	gpio_srcs = mallocarray(num_gpio_irqs, sizeof(*gpio_srcs), M_GPIOINTR,
	    M_WAITOK | M_ZERO);
	sx_init(&gpio_intr_lock, "gpiointr");
	intr_register_pic(&gpio_pic);
	gpio_intr_enabled = true;
}

struct gpio_intr_ctlr *
gpio_intr_register(device_t dev, u_int npins,
    const struct gpio_intr_ops *ops)
{
	struct gpio_intr_ctlr *ctlr;

	if (!gpio_intr_enabled)
		return (NULL);

	ctlr = malloc(sizeof(*ctlr), M_GPIOINTR, M_WAITOK | M_ZERO);
	ctlr->gc_dev = dev;
	ctlr->gc_ops = ops;
	ctlr->gc_npins = npins;
	ctlr->gc_src = mallocarray(npins, sizeof(*ctlr->gc_src), M_GPIOINTR,
	    M_WAITOK | M_ZERO);

	sx_xlock(&gpio_intr_lock);
	TAILQ_INSERT_TAIL(&gpio_ctlrs, ctlr, gc_link);
	sx_xunlock(&gpio_intr_lock);
	return (ctlr);
}

/*
 * The controller must have torn down its own interrupt handler first, so
 * gpio_intr_dispatch() cannot run concurrently.
 */
int
gpio_intr_deregister(struct gpio_intr_ctlr *ctlr)
{
	struct gpio_intsrc *gi;
	u_int pin;

	sx_xlock(&gpio_intr_lock);
	for (pin = 0; pin < ctlr->gc_npins; pin++) {
		gi = ctlr->gc_src[pin];
		if (gi != NULL && gi->gi_intsrc.is_handlers != 0) {
			sx_xunlock(&gpio_intr_lock);
			return (EBUSY);
		}
	}
	for (pin = 0; pin < ctlr->gc_npins; pin++) {
		gi = ctlr->gc_src[pin];
		if (gi == NULL)
			continue;
		ctlr->gc_ops->gio_mask(ctlr->gc_dev, pin);
		ctlr->gc_src[pin] = NULL;
		gi->gi_ctlr = NULL;
	}
	TAILQ_REMOVE(&gpio_ctlrs, ctlr, gc_link);
	sx_xunlock(&gpio_intr_lock);

	free(ctlr->gc_src, M_GPIOINTR);
	free(ctlr, M_GPIOINTR);
	return (0);
}

/*
 * Return a free source, creating one if the reserved block allows it.
 * Sources are never destroyed: x86 cannot unregister an interrupt source,
 * so a source freed by gpio_intr_deregister() is reused here.
 */
static int
gpio_intr_get_source(struct gpio_intsrc **gip)
{
	struct gpio_intsrc *gi;
	u_int i;
	int error;

	sx_assert(&gpio_intr_lock, SA_XLOCKED);

	for (i = 0; i < gpio_nsrcs; i++) {
		if (gpio_srcs[i]->gi_ctlr == NULL) {
			*gip = gpio_srcs[i];
			return (0);
		}
	}
	if (gpio_nsrcs == num_gpio_irqs)
		return (ENOSPC);

	gi = malloc(sizeof(*gi), M_GPIOINTR, M_WAITOK | M_ZERO);
	gi->gi_intsrc.is_pic = &gpio_pic;
	gi->gi_irq = first_gpio_irq + gpio_nsrcs;
	error = intr_register_source(&gi->gi_intsrc);
	if (error != 0) {
		free(gi, M_GPIOINTR);
		return (error);
	}
	nexus_add_irq(gi->gi_irq);
	gpio_srcs[gpio_nsrcs++] = gi;
	*gip = gi;
	return (0);
}

/*
 * Map pin 'pin' of GPIO controller 'dev' to an IRQ number, and program the
 * pin for trigger mode 'mode' (one of GPIO_INTR_*).
 */
int
gpio_intr_map(device_t dev, u_int pin, uint32_t mode, u_int *irqp)
{
	struct gpio_intr_ctlr *ctlr;
	struct gpio_intsrc *gi;
	int error;

	if (!gpio_intr_enabled)
		return (ENXIO);

	sx_xlock(&gpio_intr_lock);
	TAILQ_FOREACH(ctlr, &gpio_ctlrs, gc_link) {
		if (ctlr->gc_dev == dev)
			break;
	}
	if (ctlr == NULL) {
		error = ENXIO;
		goto out;
	}
	if (pin >= ctlr->gc_npins) {
		error = EINVAL;
		goto out;
	}

	gi = ctlr->gc_src[pin];
	if (gi != NULL) {
		if (gi->gi_mode == mode) {
			*irqp = gi->gi_irq;
			error = 0;
			goto out;
		}
		if (gi->gi_intsrc.is_handlers != 0) {
			error = EBUSY;
			goto out;
		}
	} else {
		error = gpio_intr_get_source(&gi);
		if (error != 0)
			goto out;
	}

	error = ctlr->gc_ops->gio_config(dev, pin, mode);
	if (error != 0)
		goto out;
	gi->gi_pin = pin;
	gi->gi_mode = mode;
	gi->gi_ctlr = ctlr;
	atomic_store_rel_ptr((volatile uintptr_t *)&ctlr->gc_src[pin],
	    (uintptr_t)gi);
	*irqp = gi->gi_irq;
out:
	sx_xunlock(&gpio_intr_lock);
	return (error);
}

/*
 * Run the handlers of pin 'pin'.  Called by the controller driver from its
 * interrupt filter, after it acknowledged the event.  Returns ENOENT if the
 * pin is not mapped; the controller should then mask the pin.
 */
int
gpio_intr_dispatch(struct gpio_intr_ctlr *ctlr, u_int pin)
{
	struct gpio_intsrc *gi;

	if (pin >= ctlr->gc_npins)
		return (EINVAL);
	gi = (struct gpio_intsrc *)atomic_load_acq_ptr(
	    (volatile uintptr_t *)&ctlr->gc_src[pin]);
	if (gi == NULL)
		return (ENOENT);
	intr_execute_handlers(&gi->gi_intsrc, curthread->td_intr_frame);
	return (0);
}
