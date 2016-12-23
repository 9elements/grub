/* IO functions used by Coreboot, adapted to GRUB */

#include "coreboot_io.h"
#include <grub/time.h>
#include <grub/types.h> /* grub_uint32_t, grub_cpu_to_le32 */
#include <grub/pci.h> /* grub_memalign_dma32, grub_dma_get_phys */
#include <grub/mm.h> /* grub_zalloc */
#include <grub/misc.h> /* grub_abort */
#include <grub/term.h> /* grub_getkey */
#include <stdlib.h>

void *xzalloc(size_t size)
{
  return grub_zalloc(size);
}

void mdelay(int delay_ms)
{
  grub_millisleep((grub_uint32_t)delay_ms);
}

void udelay(int delay_us)
{
  int delay_ms = delay_us / 1000;

  if (delay_ms <= 0)
    delay_ms = 1;

  /* GRUB doesn't have microsecond sleep */
  grub_millisleep(delay_ms);
}

void *dma_memalign(size_t align, size_t size)
{
  return grub_memalign_dma32 (align, size);
}

void *memalign(size_t align, size_t size)
{
  return grub_memalign_dma32 (align, size);
}

int dma_initialized(void)
{
  /* REVISIT */
  return 1;
}

void fatal(const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  grub_vprintf (_(fmt), ap);
  va_end (ap);

  grub_printf ("\nAborted.");
  grub_printf (" Press any key to exit.");
  grub_getkey ();
  grub_exit ();
}

int dma_coherent(void *p)
{
  /* REVISIT */
  return 1;
}
