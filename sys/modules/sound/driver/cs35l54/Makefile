.PATH: ${SRCTOP}/sys/dev/sound/pci/hda

KMOD=	snd_cs35l54
SRCS=	cs35l54.c
SRCS+=	acpi_if.h bus_if.h device_if.h gpio_if.h gpiobus_if.h iicbus_if.h
SRCS+=	opt_acpi.h opt_platform.h

.include <bsd.kmod.mk>
