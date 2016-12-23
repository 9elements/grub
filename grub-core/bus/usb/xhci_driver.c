/* Glue code to connect xHCI driver to GRUB */

#include <grub/types.h> /* grub_uint32_t */
#include <grub/pci.h> /* grub_pci_device_t */
#include <grub/usb.h> /* grub_usb_controller_dev */
#include <grub/mm.h> /* grub_zalloc */
#include <grub/time.h> /* grub_millisleep */
#include <grub/dl.h> /* GRUB_MOD_INIT */
#include <grub/disk.h> /* grub_stop_disk_firmware */
#include <grub/loader.h> /* grub_loader_register_preboot_hook */
#include <grub/env.h> /* grub_env_get */
#include <grub/command.h> /* struct grub_command_t */
#include <grub/extcmd.h> /* grub_register_extcmd */
#include <grub/lib/arg.h> /* struct grub_arg_option */

#include "xhci/usb/xhci.h"
#include "xhci/usb/generic_hub.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define XHCI_PCI_SBRN_REG  0x60

static grub_extcmd_t cmd_xhci_status;
struct grub_preboot *preboot_hook;

/* Controller super-structure */
typedef struct xhci
{
  /* The coreboot xhci driver */
  hci_t *hci;

  /* PCI id for status printout */
  int pci_vendor_id;
  int pci_device_id;

  /* xHC's set device addresses. But GRUB also want to do that!
   * This adds an address mapping between GRUB and xHCI driver to keep everyone
   * happy. The index is the device address from GRUB, the value is the address
   * assigned by xHC.
   */
#define MAX_USB_DEVICES 128
  int usbdev_xhc_addr[MAX_USB_DEVICES];

  /* Store pointer to usbdev_t for each port of this controller. Needed to
   * remember which device to talk to when grub calls control/bulk_transfer.
   */
#define MAX_PORTS_PER_CONTROLLER 256
  usbdev_t *usbdev[MAX_PORTS_PER_CONTROLLER];
} xhci_t;

/* List of found xHCI controllers */
static xhci_t *xhci_list[16];
static size_t xhci_list_num_elems;

static xhci_t *xhci_list_first (int *iter)
{
  if (xhci_list_num_elems == 0)
    {
      return NULL;
    }

  *iter = 0;
  return xhci_list[0];
}

static int xhci_list_add (xhci_t *xhci)
{
  if (xhci_list_num_elems >= (sizeof (xhci_list) / sizeof (xhci_list[0]) ) )
    {
      return -1;
    }

  xhci_list[xhci_list_num_elems] = xhci;
  xhci_list_num_elems++;
  return 0;
}

static xhci_t *xhci_list_next (int *iter)
{
  *iter += 1;
  if (*iter >= (int) xhci_list_num_elems)
    return NULL;

  return xhci_list[*iter];
}

static void dbg (const char *fmt, ...)
{
  va_list ap;
  const char *debug = grub_env_get ("debug");

  va_start (ap, fmt);
  va_end (ap);

  if (debug && (grub_strword (debug, "all") || grub_strword (debug, "xhci") ) )
    {
      grub_vprintf (fmt, ap);
      va_end (ap);
    }
}

static const struct grub_arg_option cmd_options[] =
{
  {"verbose", 'v', 0, N_ ("Be verbose."), 0, ARG_TYPE_NONE},
  {"id", 'i', 0, N_ ("Operate on this instance [0..n]"), 0, ARG_TYPE_INT},
  {0, 0, 0, 0, 0, 0}
};

static int get_int_arg (const struct grub_arg_list *state)
{
  int default_value = -1; /* if arg not set */
  return (state->set ? (int) grub_strtoul (state->arg, 0, 0) : default_value);
}

static void
print_xhci_status (xhci_t *xhci, int id)
{
  usbdev_t *roothub = xhci->hci->devices[0];
  generic_hub_t *hub = GEN_HUB (roothub);
  const char *class_str;
  unsigned int addr = 0;

  grub_printf ("xhci-%d [%04x:%04x]: num_ports=%d devices:\n",
               id, xhci->pci_vendor_id, xhci->pci_device_id,
               hub->num_ports);

  for (addr = 1; addr < sizeof (xhci->hci->devices) / sizeof (xhci->hci->devices[0]); addr++)
    {
      usbdev_t *dev = xhci->hci->devices[addr];
      if (dev)
        {
          /*
           * Based on code from Coreboot usb.c. Some checks are left out because
           * coreboot has already run them (and aborted device attach if they
           * trigged). We only check the first interface.
           */
          configuration_descriptor_t *cd = dev->configuration;
          interface_descriptor_t *intf = (interface_descriptor_t *) ( ( (char *) cd) + sizeof (*cd) );
          int class = dev->descriptor->bDeviceClass;
          if (class == 0)
            class = intf->bInterfaceClass;

          enum
          {
            audio_device      = 0x01,
            comm_device       = 0x02,
            hid_device        = 0x03,
            physical_device   = 0x05,
            imaging_device    = 0x06,
            printer_device    = 0x07,
            msc_device        = 0x08,
            hub_device        = 0x09,
            cdc_device        = 0x0a,
            ccid_device       = 0x0b,
            security_device   = 0x0d,
            video_device      = 0x0e,
            healthcare_device = 0x0f,
            diagnostic_device = 0xdc,
            wireless_device   = 0xe0,
            misc_device       = 0xef,
          };
          switch (class)
            {
            case audio_device:
              class_str = "audio";
              break;
            case comm_device:
              class_str = "communication";
              break;
            case hid_device:
              class_str = "HID";
              break;
            case physical_device:
              class_str = "physical";
              break;
            case imaging_device:
              class_str = "camera";
              break;
            case printer_device:
              class_str = "printer";
              break;
            case msc_device:
              class_str = "MSC";
              break;
            case hub_device:
              class_str = "hub";
              break;
            case cdc_device:
              class_str = "CDC";
              break;
            case ccid_device:
              class_str = "smartcard";
              break;
            case security_device:
              class_str = "content security";
              break;
            case video_device:
              class_str = "video";
              break;
            case healthcare_device:
              class_str = "healthcare";
              break;
            case diagnostic_device:
              class_str = "diagnostic";
              break;
            case wireless_device:
              class_str = "wireless";
              break;
            case misc_device:
              class_str = "misc";
              break;
            default:
              class_str = "UNKNOWN";
              break;
            }
          grub_printf ("  device(vid:pid)=0x%04x:0x%04x USB %x.%02x addr=%02d class/if0=0x%02x (%s)\n",
                       dev->descriptor->idVendor, dev->descriptor->idProduct,
                       dev->descriptor->bcdUSB >> 8, dev->descriptor->bcdUSB & 0xff,
                       dev->address, class, class_str);
        }
    }

}

static grub_err_t
do_cmd_xhci_status (grub_extcmd_context_t ctxt, int argc, char *argv[])
{
  int iter;
  xhci_t *xhci;
  enum op { CMD_NOP, STATUS } op;
  struct grub_arg_list *state = ctxt->state;
  int i = 0;
  int verbose     = state[i++].set;
  int id          = get_int_arg (&state[i++]);
  (void) verbose;
  (void) op;

  /* Get the operation */
  op = STATUS;
  for (i = 0; i < argc; i++)
    {
      if (grub_strcmp (argv[i], "cmd-nop") == 0)
        {
          op = CMD_NOP;
        }
    }

  for (i = 0, xhci = xhci_list_first (&iter); xhci; xhci = xhci_list_next (&iter), i++)
    {
      if (id >= 0)
        {
          /* get specific device */
          if (i == id)
            {
              print_xhci_status (xhci, i);
              break;
            }
        }
      else
        {
          /* get all devices */
          print_xhci_status (xhci, i);
        }

    }

  if (id >= 0 && !xhci)
    {
      grub_printf ("no such device (bad --id value: %d)\n", id);
      return GRUB_ERR_UNKNOWN_DEVICE;
    }

  return 0;
}

/* PCI iteration function, to be passed to grub_pci_iterate.
 *
 * grub_pci_iterate will invoke this function for each PCI device that exists
 * in the system. This function checks if the device is an xHC and initializes
 * it. Return 0 to continue iterating over devices, != 0 to abort.
 */
static int pci_iter (grub_pci_device_t dev, grub_pci_id_t pciid, void *data)
{
  (void) data;
  hci_t *hci;
  grub_uint32_t class_code;
  grub_uint32_t base;
  grub_uint32_t release;
  volatile grub_uint32_t *mmio_base_addr;
  grub_uint32_t base_h;
  grub_pci_address_t addr;
  int pci_vendor_id;
  int pci_device_id;

  /* Exit if not USB3.0 xHCI controller */
  addr = grub_pci_make_address (dev, GRUB_PCI_REG_CLASS);
  class_code = grub_pci_read (addr) >> 8;
  if (class_code != 0x0c0330)
    return 0;

  /* Check Serial Bus Release Number */
  addr = grub_pci_make_address (dev, XHCI_PCI_SBRN_REG);
  release = grub_pci_read_byte (addr);
  if (release != 0x30)
    {
      grub_dprintf ("xhci", "Wrong SBRN: 0x%0x (expected 0x%0x)\n",
                    release, 0x30);
      return 0;
    }

  pci_vendor_id = grub_le_to_cpu32 (pciid) & 0xffff;
  pci_device_id = (grub_le_to_cpu32 (pciid) >> 16) & 0xffff;
  dbg ("xhci: controller at %d:%02x.%d, vendor:device %04x:%04x\n",
       dev.bus, dev.device, dev.function,
       pci_vendor_id, pci_device_id);

  /* Determine xHCI MMIO registers base address */
  addr = grub_pci_make_address (dev, GRUB_PCI_REG_ADDRESS_REG0);
  base = grub_pci_read (addr);
  addr = grub_pci_make_address (dev, GRUB_PCI_REG_ADDRESS_REG1);
  base_h = grub_pci_read (addr);
  /* Stop if registers are mapped above 4G - GRUB does not currently
   * work with registers mapped above 4G */
  if ( ( (base & GRUB_PCI_ADDR_MEM_TYPE_MASK) != GRUB_PCI_ADDR_MEM_TYPE_32)
       && (base_h != 0) )
    {
      dbg ("xhci: registers above 4G are not supported\n");
      return 0;
    }
  base &= GRUB_PCI_ADDR_MEM_MASK;
  if (!base)
    {
      dbg ("xhci: BARs not programmed (broken PC firmware)\n");
      return 0;
    }

  /* Set bus master - needed for coreboot, VMware, broken BIOSes etc. or else
   * MMIO access doesn't work (no effect).
   */
  addr = grub_pci_make_address (dev, GRUB_PCI_REG_COMMAND);
  grub_pci_write_word (addr,
                       GRUB_PCI_COMMAND_MEM_ENABLED
                       | GRUB_PCI_COMMAND_BUS_MASTER
                       | grub_pci_read_word (addr) );

  /* PCI config space is 256 bytes */
  mmio_base_addr = grub_pci_device_map_range (dev, base, 0x100);
  (void) mmio_base_addr;

  grub_uint32_t pciaddr = grub_pci_make_address (dev, 0);
  hci = xhci_pci_init (pciaddr);
  if (!hci)
    {
      grub_printf ("xhci: out of memory\n");
      return GRUB_USB_ERR_INTERNAL;
    }

  /* Build list of xHCI controllers */
  xhci_t *xhci = grub_malloc (sizeof (xhci_t) );
  if (!xhci)
    {
      grub_printf ("xhci: out of memory\n");
      return GRUB_USB_ERR_INTERNAL;
    }
  grub_memset (xhci, 0, sizeof (*xhci) );
  xhci->hci = hci;
  xhci->pci_vendor_id = pci_vendor_id;
  xhci->pci_device_id = pci_device_id;
  xhci_list_add (xhci);

  /* For debug/test, run the full coreboot stack right here */
  while (0)
    {
      usb_poll();
      grub_millisleep (50);
    }

  return 0;
}

static grub_err_t
xhci_fini_hw (int noreturn __attribute__ ( (unused) ) )
{
  xhci_t *xhci;
  int iter;

  /* We should disable all xHCI HW to prevent any DMA access etc. */
  for (xhci = xhci_list_first (&iter); xhci; xhci = xhci_list_next (&iter) )
    {
      /* FIXME: this segfault + reboots machine */
      //grub_dprintf ("xhci", "shutting down controller %p\n", hci);
      //hci->shutdown(hci);
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
xhci_restore_hw (void)
{
  dbg ("grub_xhci_restore_hw enter\n");
  /* We should re-enable all xHCI HW similarly as on inithw */
//  for (xhci = xhci_list; xhci; xhci = xhci->next)
//    {
//      /* Check if xHCI is halted and halt it if not */
//      if (xhci_halt (xhci) != GRUB_USB_ERR_NONE)
//	grub_error (GRUB_ERR_TIMEOUT, "restore_hw: xHCI halt timeout");
//
//      /* Reset xHCI */
//      if (xhci_reset (xhci) != GRUB_USB_ERR_NONE)
//	grub_error (GRUB_ERR_TIMEOUT, "restore_hw: xHCI reset timeout");
//
//      /* Setup some xHCI registers and enable xHCI */
////      grub_xhci_oper_write32 (xhci, GRUB_XHCI_OPER_USBCMD,
////			      XHCI_USBCMD_RUNSTOP |
////			      grub_xhci_oper_read32 (xhci, GRUB_XHCI_OPER_USBCMD));
//
//      /* Now should be possible to power-up and enumerate ports etc. */
//	  /* Power on all ports */
//    }

  return GRUB_ERR_NONE;
}

static int
xhci_iterate (grub_usb_controller_iterate_hook_t hook, void *hook_data)
{
  xhci_t *xhci;
  struct grub_usb_controller dev;
  (void) dev;
  int iter;

  dbg ("xhci_iterate enter\n");
  for (xhci = xhci_list_first (&iter); xhci; xhci = xhci_list_next (&iter) )
    {
      dev.data = xhci;
      if (hook (&dev, hook_data) )
        return 1;
    }

  return 0;
}

static grub_usb_err_t
setup_transfer (grub_usb_controller_t dev,
                grub_usb_transfer_t transfer)
{
  (void) dev;
  (void) transfer;
  /* we replaced setup/check/cancel_transfer with control/bulk_transfer */
  grub_printf ("%s: should NOT be called (this may happen when a HUB is attached to the USB3.0 controller)\n", __func__);
  grub_millisleep (1000);
  return GRUB_USB_ERR_INTERNAL;
}

static grub_usb_err_t
check_transfer (grub_usb_controller_t dev,
                grub_usb_transfer_t transfer, grub_size_t *actual)
{
  (void) dev;
  (void) transfer;
  (void) actual;

  /* we replaced setup/check/cancel_transfer with control/bulk_transfer */
  grub_printf ("%s: should NOT be called (this may happen when a HUB is attached to the USB3.0 controller)\n", __func__);
  grub_millisleep (1000);
  return GRUB_USB_ERR_INTERNAL;
}

static grub_usb_err_t
cancel_transfer (grub_usb_controller_t dev,
                 grub_usb_transfer_t transfer)
{
  (void) dev;
  (void) transfer;

  /* we replaced setup/check/cancel_transfer with control/bulk_transfer */
  grub_printf ("%s: should NOT be called (this may happen when a HUB is attached to the USB3.0 controller)\n", __func__);
  grub_millisleep (1000);
  return GRUB_USB_ERR_INTERNAL;
}

static grub_usb_err_t
control_transfer (grub_usb_device_t dev,
                  grub_uint8_t reqtype,
                  grub_uint8_t request,
                  grub_uint16_t value,
                  grub_uint16_t index,
                  grub_size_t size0, char *data_in)
{
  xhci_t *xhci = (xhci_t *) dev->controller.data;
  hci_t *hci = xhci->hci;
  int ret = 0;
  int slot_id; /* the xHC slot used for addressing the device (assigned by xHC) */
  int portno = dev->portno;
  dev_req_t dr;
  direction_t dir = (reqtype & 128) ? IN : OUT;

  dr.bmRequestType = reqtype;
  dr.bRequest = request;
  dr.wValue = value;
  dr.wIndex = index;
  dr.wLength = size0;

  /* xHCI controllers are made so that *they* set the device address. This
   * conflicts with the GRUB USB driver which assumes it can set the device
   * address by doing a control message.
   * We work around that by (1) storing the last connected device for a given
   * port until GRUB tells us the address for the newly connected device. Then
   * we store the GRUB -> xHC address mapping for later.
   */
  if (dev->initialized)
    {
      slot_id = xhci->usbdev_xhc_addr[dev->addr];
    }
  else
    {
      slot_id = xhci->usbdev[portno]->address;
    }

  if (request == GRUB_USB_REQ_SET_ADDRESS)
    {
      /* Setting the address has already been handled by xHC */
      grub_dprintf ("xhci", "creating address map from GRUB to xHC: %d -> %d\n",
                    value, slot_id);
      xhci->usbdev_xhc_addr[value] = slot_id;
    }
  else
    {
      ret = hci->control (hci->devices[slot_id], dir, sizeof (dr), &dr, size0,
                          (unsigned char *) data_in);
    }
  return ret >= 0 ? GRUB_USB_ERR_NONE : GRUB_USB_ERR_INTERNAL;
}

static grub_usb_err_t
bulk_transfer (grub_usb_device_t dev,
               struct grub_usb_desc_endp *endpoint,
               grub_size_t size, char *data_in,
               grub_transfer_type_t type, int timeout,
               grub_size_t *actual)
{
  xhci_t *xhci = (xhci_t *) dev->controller.data;
  hci_t *hci = xhci->hci;
  int ret = -1;
  int slot_id = -1;
  (void) timeout;

  /* add the printout from GRUB USB stack that we "shorted out" by implementing
   * bulk_transfer callback
   */
  grub_dprintf ("usb", "bulk: size=0x%02lx type=%d\n", (unsigned long) size,
                type);

  if (!dev->initialized)
    {
      grub_printf ("err: bulk_transfer: device structure not initialized\n");
      grub_millisleep (60000);
      return GRUB_USB_ERR_INTERNAL;
    }

  /* convert from GRUB addr to xHC addr */
  slot_id = xhci->usbdev_xhc_addr[dev->addr];

  usbdev_t *udevf = hci->devices[slot_id];
  endpoint_t *ep = &udevf->endpoints[endpoint->endp_addr & 0x7f];

  ret = hci->bulk (ep, size, (unsigned char *) data_in, 0);
  *actual = ret >= 0 ? ret : 0;
  grub_dprintf ("xhci", "%s: ret=%d\n", __func__, ret);
  return ret >= 0 ? GRUB_USB_ERR_NONE : GRUB_USB_ERR_INTERNAL;
}

static int hubports (grub_usb_controller_t dev)
{
  xhci_t *xhci = (xhci_t *) dev->data;
  hci_t *hci = xhci->hci;
  usbdev_t *roothub = hci->devices[0];
  generic_hub_t *hub = GEN_HUB (roothub);

  grub_dprintf ("xhci", "%s: num_ports=%d\n", __func__, hub->num_ports);
  return hub->num_ports;
}

static grub_usb_err_t
portstatus (grub_usb_controller_t dev,
            unsigned int port, unsigned int enable)
{
  (void) dev;
  (void) port;
  (void) enable;
  grub_dprintf ("xhci", "%s: port=%d enable=%d\n", __func__, port, enable);
  /* Enabling/disabled is handled in detect_dev (easier to match with Coreboot
   * xHCI driver) */
  return GRUB_USB_ERR_NONE;
}

static grub_usb_speed_t
detect_dev (grub_usb_controller_t dev, int port, int *changed)
{
  int ret = -1;
  int status_changed;
  int connected;
  usb_speed speed;
  grub_usb_speed_t grub_speed = GRUB_USB_SPEED_NONE;
  xhci_t *xhci = (xhci_t *) dev->data;
  hci_t *hci = xhci->hci;
  usbdev_t *roothub = hci->devices[0];
  generic_hub_t *hub = GEN_HUB (roothub);

  status_changed = hub->ops->port_status_changed (roothub, port);
  connected = hub->ops->port_connected (roothub, port);
  if (status_changed)
    {
      *changed = 1;

      if (connected)
        {
          /* GRUB (usually) handles debouncing (stable power), but here we let the
           * xHCI driver do that itself. Also, let it set the device address,
           * something GRUB typically does (e.g. for EHCI). XHCI controllers are
           * written that way; *they* set the device address and the host software
           * reads the address back from the controller HW.
           *
           * Because of how the Coreboot xHCI driver is written, and that we want
           * to change it as little as possible (maintainability), it seems
           * simpler this way. We have to pay attention to filter out control
           * messages of SET_ADDRESS type from GRUB.
           */
          if (generic_hub_debounce (roothub, port) < 0)
            return GRUB_USB_SPEED_NONE;

          hub->ops->reset_port (roothub, port);
          speed = hub->ops->port_speed (roothub, port);
          /* usb_attach_device() bypasses GRUB (it sends SET_ADDRESS,
           * GET_DESCRIPTOR and SET_CONFIGURATION control messages). Those extra
           * messages should do no harm. After this call the device will have an
           * address and all endpoints (in driver) have been initialized.
           */
          ret = usb_attach_device (hci, roothub->address, port, speed);
          if (ret < 0)
            {
              grub_dprintf ("xhci", "Failed to attach device\n");
            }
          hub->ports[port] = ret;
          /* remember the newly attached device */
          usbdev_t *udev = ret >= 0 ? hci->devices[ret] : NULL;
          xhci->usbdev[port] = udev;
          //grub_dprintf("xhci", "ep[0].maxpacketsize: %d\n", udev->endpoints[0].maxpacketsize);
        }
      else
        {
          /* free resources */
          usb_detach_device (hci, hub->ports[port]);
          hub->ports[port] = NO_DEV;
          xhci->usbdev[port] = NULL;
        }
    }

  if (connected)
    {
      speed = hub->ops->port_speed (roothub, port);
      switch (speed)
        {
        case LOW_SPEED:
          grub_speed = GRUB_USB_SPEED_LOW;
          break;

        case FULL_SPEED:
          grub_speed = GRUB_USB_SPEED_FULL;
          break;

        case HIGH_SPEED:
          grub_speed = GRUB_USB_SPEED_HIGH;
          break;

        case SUPER_SPEED:
          /* unsupported, so disable it */
          if (status_changed)
            {
              grub_printf ("warning: USB 3.0 devices are unsupported, forcing speed=NONE\n");
            }
          grub_speed = GRUB_USB_SPEED_NONE;
          break;
        }
    }

  if (status_changed)
    {
      grub_dprintf ("xhci", "%s: port=%d *changed=%d connected=%d speed=%d\n",
                    __func__, port, *changed, connected, grub_speed);
    }

  return grub_speed;
}

static struct grub_usb_controller_dev usb_controller_dev =
{
  .name = "xhci",
  .iterate = xhci_iterate,
  .setup_transfer = setup_transfer, /* give data to HW, let it go */

  .check_transfer = check_transfer, /* check if HW has completed transfer,
                                          * polled by USB framework (see
                                          * usbtrans.c)
                                          */

  .cancel_transfer = cancel_transfer, /* called if/when check_transfer has
                                            * failed over a period of time
                                            */
  .control_transfer = control_transfer,
  .bulk_transfer = bulk_transfer,
  .hubports = hubports,
  .portstatus = portstatus,
  .detect_dev = detect_dev,
};

GRUB_MOD_INIT (xhci)
{
  //dbg ("[loading]\n");

  xhci_list_num_elems = 0;
  grub_stop_disk_firmware ();
  grub_boot_time ("Initing xHCI hardware");
  grub_pci_iterate (pci_iter, NULL);
  grub_boot_time ("Registering xHCI driver");
  grub_usb_controller_dev_register (&usb_controller_dev);
  grub_boot_time ("xHCI driver registered");
  //dbg ("xHCI driver is registered, register preboot hook\n");
  preboot_hook = grub_loader_register_preboot_hook (xhci_fini_hw, xhci_restore_hw,
                 GRUB_LOADER_PREBOOT_HOOK_PRIO_DISK);

  cmd_xhci_status =
    grub_register_extcmd ("xhci", do_cmd_xhci_status, 0,
                          N_ ("[-v|--verbose] [-i|--id N] [cmd-nop]"),
                          N_ ("Print xHCI driver status."),
                          cmd_options);
  //dbg ("GRUB_MOD_INIT completed\n");
}

GRUB_MOD_FINI (xhci)
{
  //dbg ("[unloading]\n");
  grub_unregister_extcmd (cmd_xhci_status);
  grub_usb_controller_dev_unregister (&usb_controller_dev);
  grub_loader_unregister_preboot_hook (preboot_hook);
  xhci_fini_hw (0);
}
