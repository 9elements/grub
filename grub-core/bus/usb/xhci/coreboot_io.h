/* IO functions used by Coreboot, adapted to GRUB */

#ifndef COREBOOT_IO_H
#define COREBOOT_IO_H

#include <stddef.h>

#define IS_ENABLED(option) (COREBOOT_OPTION_##option)

/* Inline confiuration */
#define COREBOOT_OPTION_CONFIG_LP_USB_HID 0
#define COREBOOT_OPTION_CONFIG_LP_USB_MSC 0
#define COREBOOT_OPTION_CONFIG_LP_USB_HUB 1
#define COREBOOT_OPTION_CONFIG_LP_USB_XHCI_MTK_QUIRK 0
#define COREBOOT_OPTION_CONFIG_LP_USB_PCI 1
#define COREBOOT_OPTION_CONFIG_LP_ARCH_X86 1

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

/* GRUB lacks full stdint.h header */
#define PRIx8 "x"
#define PRIx32 "lx"

void *xzalloc(size_t size);
void mdelay(int delay_ms);
void udelay(int delay_us);
void *dma_memalign(size_t align, size_t size);
void *memalign(size_t align, size_t size);
int dma_initialized(void);
void fatal(const char *fmt, ...);
int dma_coherent(void *p);

#endif /* COREBOOT_IO_H */
