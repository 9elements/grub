/* xhci.c - XHCI Support.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2020 9elements Cyber Security
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/dl.h>
#include <grub/mm.h>
#include <grub/usb.h>
#include <grub/usbtrans.h>
#include <grub/misc.h>
#include <grub/time.h>
#include <grub/loader.h>
#include <grub/disk.h>
#include <grub/dma.h>
#include <grub/cache.h>
#include <grub/i386/cpuid.h>

GRUB_MOD_LICENSE ("GPLv3+");

// This simple GRUB implementation of XHCI driver

/* Seabios stuff */
#define PAGE_SIZE 4096
#define xhci_get_field(data, field)             \
    (((data) >> field##_SHIFT) & field##_MASK)
#define XHCI_PORTSC_PLS_MASK     0xf
#define XHCI_PORTSC_PLS_SHIFT    5
#define XHCI_PORTSC_SPEED_MASK   0xf
#define XHCI_PORTSC_SPEED_SHIFT  10

enum
{
  XHCI_USB_FULLSPEED = 1,
  XHCI_USB_LOWSPEED,
  XHCI_USB_HIGHSPEED,
  XHCI_USB_SUPERSPEED
};

/* Capability registers offsets */
//enum
//{
//  GRUB_XHCI_CAPLENGTH = 0x00,	/* byte */
//  GRUB_XHCI_HCIVERSION = 0x02,	/* word */
//  GRUB_XHCI_HCSPARAMS1 = 0x04,	/* dword */
//  GRUB_XHCI_HCSPARAMS2 = 0x08,	/* dword */
//  GRUB_XHCI_HCSPARAMS3 = 0x0c,	/* dword */
//  GRUB_XHCI_HCCPARAMS = 0x10,	/* dword */
//  GRUB_XHCI_DBOFF = 0x14,	/* dword */
//  GRUB_XHCI_RTSOFF = 0x18,	/* dword */
//};

struct grub_xhci_caps {
    grub_uint8_t  caplength;
    grub_uint8_t  reserved_01;
    grub_uint16_t hciversion;
    grub_uint32_t hcsparams1;
    grub_uint32_t hcsparams2;
    grub_uint32_t hcsparams3;
    grub_uint32_t hccparams;
    grub_uint32_t dboff;
    grub_uint32_t rtsoff;
} GRUB_PACKED;

// extended capabilities
struct grub_xhci_xcap {
    grub_uint32_t cap;
    grub_uint32_t data[];
} GRUB_PACKED;

struct xhci_portmap {
    grub_uint8_t start;
    grub_uint8_t count;
};


/* Operational registers offsets */
//enum
//{
//  GRUB_XHCI_USBCMD = 0x00,	/* USB Command */
//  GRUB_XHCI_USBSTS = 0x04,	/* USB Status */
//  GRUB_XHCI_PAGESIZE = 0x08,	/* Page Size */
//  GRUB_XHCI_DNCTRL = 0x14,	/* Device Notification Control */
//  GRUB_XHCI_CRCR_LOW = 0x18,	/* Command Ring Control */
//  GRUB_XHCI_CRCR_HIGH = 0x1c,
//  GRUB_XHCI_DCBAAP_LOW = 0x30,	/* Device Context Base Address Array Pointer */
//  GRUB_XHCI_DCBAAP_HIGH = 0x34,
//  GRUB_XHCI_CONFIG = 0x38,	/* Configure */
//};

struct grub_xhci_op {
    grub_uint32_t usbcmd;
    grub_uint32_t usbsts;
    grub_uint32_t pagesize;
    grub_uint32_t reserved_01[2];
    grub_uint32_t dnctl;
    grub_uint32_t crcr_low;
    grub_uint32_t crcr_high;
    grub_uint32_t reserved_02[4];
    grub_uint32_t dcbaap_low;
    grub_uint32_t dcbaap_high;
    grub_uint32_t config;
} GRUB_PACKED;

enum
{
  GRUB_XHCI_CMD_RS = (1<<0),
  GRUB_XHCI_CMD_HCRST = (1<<1),
  GRUB_XHCI_CMD_INTE = (1<<2),
  GRUB_XHCI_CMD_HSEE = (1<<3),
  GRUB_XHCI_CMD_LHCRST = (1<<7),
  GRUB_XHCI_CMD_CSS = (1<<8),
  GRUB_XHCI_CMD_CRS = (1<<9),
  GRUB_XHCI_CMD_EWE = (1<<10),
  GRUB_XHCI_CMD_EU3S = (1<<11)
};

enum
{
  GRUB_XHCI_STS_HCH = (1<<0),
  GRUB_XHCI_STS_HSE = (1<<2),
  GRUB_XHCI_STS_EINT = (1<<3),
  GRUB_XHCI_STS_PCD = (1<<4),
  GRUB_XHCI_STS_SSS = (1<<8),
  GRUB_XHCI_STS_RSS = (1<<9),
  GRUB_XHCI_STS_SRE = (1<<10),
  GRUB_XHCI_STS_CNR = (1<<11),
  GRUB_XHCI_STS_HCE = (1<<12)
};


/* Port Registers Offset */
#define GRUB_XHCI_PR_OFFSET 0x400
/* Interrupter Registers Offset */
#define GRUB_XHCI_IR_OFFSET 0x20


/* Port Status and Control registers offsets */

//enum
//{
//  GRUB_XHCI_PORTSC = 0x00,	/* Port Status and Control */
//  GRUB_XHCI_PORTPMSC = 0x04,	/* Port Power Management Status and Control */
//  GRUB_XHCI_PORTLI = 0x08,	/* Port Link Info */
//};

enum
{
  GRUB_XHCI_PORTSC_CCS = (1<<0),
  GRUB_XHCI_PORTSC_PED = (1<<1),
  GRUB_XHCI_PORTSC_OCA = (1<<3),
  GRUB_XHCI_PORTSC_PR = (1<<4),
  GRUB_XHCI_PORTSC_PP = (1<<9),
  GRUB_XHCI_PORTSC_SPEED_FULL = (1<<10),
  GRUB_XHCI_PORTSC_SPEED_LOW = (2<<10),
  GRUB_XHCI_PORTSC_SPEED_HIGH = (3<<10),
  GRUB_XHCI_PORTSC_SPEED_SUPER = (4<<10),
  GRUB_XHCI_PORTSC_LWS = (1<<16),
  GRUB_XHCI_PORTSC_CSC = (1<<17),
  GRUB_XHCI_PORTSC_PEC = (1<<18),
  GRUB_XHCI_PORTSC_WRC = (1<<19),
  GRUB_XHCI_PORTSC_OCC = (1<<20),
  GRUB_XHCI_PORTSC_PRC = (1<<21),
  GRUB_XHCI_PORTSC_PLC = (1<<22),
  GRUB_XHCI_PORTSC_CEC = (1<<23),
  GRUB_XHCI_PORTSC_CAS = (1<<24),
  GRUB_XHCI_PORTSC_WCE = (1<<25),
  GRUB_XHCI_PORTSC_WDE = (1<<26),
  GRUB_XHCI_PORTSC_WOE = (1<<27),
  GRUB_XHCI_PORTSC_DR = (1<<30),
  GRUB_XHCI_PORTSC_WPR = (1<<31)
};

/* XHCI memory data structs */

#define GRUB_XHCI_RING_ITEMS 64
#define GRUB_XHCI_RING_SIZE (GRUB_XHCI_RING_ITEMS*sizeof(struct grub_xhci_trb))
/*
 *  xhci_ring structs are allocated with XHCI_RING_SIZE alignment,
 *  then we can get it from a trb pointer (provided by evt ring).
 */
#define XHCI_RING(_trb)          \
    ((struct grub_xhci_ring*)((grub_uint32_t)(_trb) & ~(GRUB_XHCI_RING_SIZE-1)))

// slot context
struct grub_xhci_slotctx {
  grub_uint32_t ctx[4];
  grub_uint32_t reserved_01[4];
} GRUB_PACKED;

// endpoint context
struct grub_xhci_epctx {
  grub_uint32_t ctx[2];
  grub_uint32_t deq_low;
  grub_uint32_t deq_high;
  grub_uint32_t length;
  grub_uint32_t reserved_01[3];
} GRUB_PACKED;

// device context array element
struct grub_xhci_devlist {
  grub_uint32_t ptr_low;
  grub_uint32_t ptr_high;
} GRUB_PACKED;

// input context
struct grub_xhci_inctx {
  grub_uint32_t del;
  grub_uint32_t add;
  grub_uint32_t reserved_01[6];
} GRUB_PACKED;

// transfer block (ring element)
struct grub_xhci_trb {
  grub_uint32_t ptr_low;
  grub_uint32_t ptr_high;
  grub_uint32_t status;
  grub_uint32_t control;
} GRUB_PACKED;

#define TRB_C               (1<<0)
#define TRB_TYPE_SHIFT          10
#define TRB_TYPE_MASK       0x3f
#define TRB_TYPE(t)         (((t) >> TRB_TYPE_SHIFT) & TRB_TYPE_MASK)

#define TRB_EV_ED           (1<<2)

#define TRB_TR_ENT          (1<<1)
#define TRB_TR_ISP          (1<<2)
#define TRB_TR_NS           (1<<3)
#define TRB_TR_CH           (1<<4)
#define TRB_TR_IOC          (1<<5)
#define TRB_TR_IDT          (1<<6)
#define TRB_TR_TBC_SHIFT        7
#define TRB_TR_TBC_MASK     0x3
#define TRB_TR_BEI          (1<<9)
#define TRB_TR_TLBPC_SHIFT      16
#define TRB_TR_TLBPC_MASK   0xf
#define TRB_TR_FRAMEID_SHIFT    20
#define TRB_TR_FRAMEID_MASK 0x7ff
#define TRB_TR_SIA          (1<<31)

#define TRB_TR_DIR          (1<<16)

#define TRB_CR_SLOTID_SHIFT     24
#define TRB_CR_SLOTID_MASK  0xff
#define TRB_CR_EPID_SHIFT       16
#define TRB_CR_EPID_MASK    0x1f

#define TRB_CR_BSR          (1<<9)
#define TRB_CR_DC           (1<<9)

#define TRB_LK_TC           (1<<1)

#define TRB_INTR_SHIFT          22
#define TRB_INTR_MASK       0x3ff
#define TRB_INTR(t)         (((t).status >> TRB_INTR_SHIFT) & TRB_INTR_MASK)

typedef enum TRBType {
    TRB_RESERVED = 0,
    TR_NORMAL,
    TR_SETUP,
    TR_DATA,
    TR_STATUS,
    TR_ISOCH,
    TR_LINK,
    TR_EVDATA,
    TR_NOOP,
    CR_ENABLE_SLOT,
    CR_DISABLE_SLOT,
    CR_ADDRESS_DEVICE,
    CR_CONFIGURE_ENDPOINT,
    CR_EVALUATE_CONTEXT,
    CR_RESET_ENDPOINT,
    CR_STOP_ENDPOINT,
    CR_SET_TR_DEQUEUE,
    CR_RESET_DEVICE,
    CR_FORCE_EVENT,
    CR_NEGOTIATE_BW,
    CR_SET_LATENCY_TOLERANCE,
    CR_GET_PORT_BANDWIDTH,
    CR_FORCE_HEADER,
    CR_NOOP,
    ER_TRANSFER = 32,
    ER_COMMAND_COMPLETE,
    ER_PORT_STATUS_CHANGE,
    ER_BANDWIDTH_REQUEST,
    ER_DOORBELL,
    ER_HOST_CONTROLLER,
    ER_DEVICE_NOTIFICATION,
    ER_MFINDEX_WRAP,
} TRBType;

typedef enum TRBCCode {
    CC_INVALID = 0,
    CC_SUCCESS,
    CC_DATA_BUFFER_ERROR,
    CC_BABBLE_DETECTED,
    CC_USB_TRANSACTION_ERROR,
    CC_TRB_ERROR,
    CC_STALL_ERROR,
    CC_RESOURCE_ERROR,
    CC_BANDWIDTH_ERROR,
    CC_NO_SLOTS_ERROR,
    CC_INVALID_STREAM_TYPE_ERROR,
    CC_SLOT_NOT_ENABLED_ERROR,
    CC_EP_NOT_ENABLED_ERROR,
    CC_SHORT_PACKET,
    CC_RING_UNDERRUN,
    CC_RING_OVERRUN,
    CC_VF_ER_FULL,
    CC_PARAMETER_ERROR,
    CC_BANDWIDTH_OVERRUN,
    CC_CONTEXT_STATE_ERROR,
    CC_NO_PING_RESPONSE_ERROR,
    CC_EVENT_RING_FULL_ERROR,
    CC_INCOMPATIBLE_DEVICE_ERROR,
    CC_MISSED_SERVICE_ERROR,
    CC_COMMAND_RING_STOPPED,
    CC_COMMAND_ABORTED,
    CC_STOPPED,
    CC_STOPPED_LENGTH_INVALID,
    CC_MAX_EXIT_LATENCY_TOO_LARGE_ERROR = 29,
    CC_ISOCH_BUFFER_OVERRUN = 31,
    CC_EVENT_LOST_ERROR,
    CC_UNDEFINED_ERROR,
    CC_INVALID_STREAM_ID_ERROR,
    CC_SECONDARY_BANDWIDTH_ERROR,
    CC_SPLIT_TRANSACTION_ERROR
} TRBCCode;

enum {
    PLS_U0              =  0,
    PLS_U1              =  1,
    PLS_U2              =  2,
    PLS_U3              =  3,
    PLS_DISABLED        =  4,
    PLS_RX_DETECT       =  5,
    PLS_INACTIVE        =  6,
    PLS_POLLING         =  7,
    PLS_RECOVERY        =  8,
    PLS_HOT_RESET       =  9,
    PLS_COMPILANCE_MODE = 10,
    PLS_TEST_MODE       = 11,
    PLS_RESUME          = 15,
};


// event ring segment
struct grub_xhci_er_seg {
  grub_uint32_t ptr_low;
  grub_uint32_t ptr_high;
  grub_uint32_t size;
  grub_uint32_t reserved_01;
} GRUB_PACKED;


struct grub_xhci_ring {
    struct grub_xhci_trb      ring[GRUB_XHCI_RING_ITEMS];
    struct grub_xhci_trb      evt;
    grub_uint32_t             eidx;
    grub_uint32_t             nidx;
    grub_uint32_t             cs;
};

// port registers
struct grub_xhci_pr {
    grub_uint32_t portsc;
    grub_uint32_t portpmsc;
    grub_uint32_t portli;
    grub_uint32_t reserved_01;
} GRUB_PACKED;

// doorbell registers
struct grub_xhci_db {
    grub_uint32_t doorbell;
} GRUB_PACKED;

// runtime registers
struct grub_xhci_rts {
    grub_uint32_t mfindex;
} GRUB_PACKED;


// interrupter registers
struct grub_xhci_ir {
    grub_uint32_t iman;
    grub_uint32_t imod;
    grub_uint32_t erstsz;
    grub_uint32_t reserved_01;
    grub_uint32_t erstba_low;
    grub_uint32_t erstba_high;
    grub_uint32_t erdp_low;
    grub_uint32_t erdp_high;
} GRUB_PACKED;


//enum
//{
//	GRUB_XHCI_ESEG_PTR_LOW = 0x00,
//	GRUB_XHCI_ESEG_PTR_HIGH = 0x04,
//	GRUB_XHCI_ESEG_SIZE = 0x08,
//	GRUB_XHCI_ESEG_REV = 0x0c,
//};

#define GRUB_XHCI_N_TD  640

struct grub_xhci_slots {
  grub_uint8_t              slotid;
  grub_uint32_t             max_packet; // maximum packet size
  grub_uint32_t             dev_addr; // as assigned by xHCI
  grub_usb_device_t         *dev;
  struct grub_xhci_trb      *enpoint_trbs[32];
};

struct grub_xhci
{
  /* xhci registers */
  volatile struct grub_xhci_caps *caps;	/* Capability registers */
  volatile struct grub_xhci_op *op;	/* Operational registers */
  volatile struct grub_xhci_pr *pr;	/* Port Registers */
  volatile struct grub_xhci_db *db;	/* doorbell */
  volatile struct grub_xhci_ir *ir;	/* Interrupt Registers */
  /* devinfo */
  grub_uint32_t xcap;
  grub_uint32_t ports;
  grub_uint32_t slots;
  grub_uint8_t flag64;
  struct xhci_portmap usb2;
  struct xhci_portmap usb3;
  /* xhci data structures */
  struct grub_xhci_devlist  *devs;
  volatile struct grub_xhci_ring     *cmds;
  volatile struct grub_xhci_ring     *evts;
  struct grub_xhci_er_seg   *eseg;

  grub_uint32_t reset;		/* bits 1-15 are flags if port was reset from connected time or not */
  struct grub_xhci *next;

  struct grub_xhci_slots *slots_meta;
};

struct grub_xhci_port {
    grub_uint32_t portsc;
    grub_uint32_t portpmsc;
    grub_uint32_t portli;
    grub_uint32_t reserved_01;
};


struct grub_xhci_transfer_controller_data {
    struct grub_xhci_ring     *reqs;
    grub_uint32_t             slotid;
    grub_uint32_t             epid;
    grub_uint32_t             transfer_size;
    void                 *buf;
    int                  bufused;
};

static struct grub_xhci *xhci;

/* general access functions */

static inline void
grub_xhci_write32(volatile void *addr, grub_uint32_t val) {
    *(volatile grub_uint32_t *)addr = val;
}
static inline void
grub_xhci_write16(volatile void *addr, grub_uint16_t val) {
    *(volatile grub_uint16_t *)addr = val;
}
static inline void
grub_xhci_write8(void *addr, grub_uint8_t val) {
    *(volatile grub_uint8_t *)addr = val;
}

static inline grub_uint32_t
grub_xhci_read32(volatile void *addr) {
  return grub_le_to_cpu32 (*((volatile grub_uint32_t *)addr));
}

static inline grub_uint16_t
grub_xhci_read16(volatile void *addr) {
  return grub_le_to_cpu16 (*((volatile grub_uint32_t *)addr));
}
static inline grub_uint8_t
grub_xhci_read8(volatile void *addr) {
  return (*((volatile grub_uint32_t *)addr));
}

static inline grub_uint32_t
grub_xhci_port_read (struct grub_xhci *x, grub_uint32_t port)
{
  return grub_xhci_read32(&x->pr[port].portsc);
}

static inline void
grub_xhci_port_resbits (struct grub_xhci *x, grub_uint32_t port,
			grub_uint32_t bits)
{
  grub_xhci_write32(&x->pr[port].portsc,
		grub_xhci_read32(&x->pr[port].portsc) &
		~(bits));
}

static inline void
grub_xhci_port_setbits (struct grub_xhci *x, grub_uint32_t port,
			grub_uint32_t bits)
{
  grub_xhci_write32(&x->pr[port].portsc,
		grub_xhci_read32(&x->pr[port].portsc) |
		  (bits));
}

// Just for debugging
static void xhci_check_status(struct grub_xhci *x)
{
  grub_uint32_t reg;

  reg = grub_xhci_read32(&x->op->usbsts);
  if (reg & 1)
    grub_dprintf("xhci", "%s: xHCI halted\n", __func__);
  if (reg & 2)
    grub_dprintf("xhci", "%s: Host system error detected\n", __func__);
  if (reg & (1 << 12))
    grub_dprintf("xhci", "%s: Internal error detected\n", __func__);
  reg = grub_xhci_read32(&x->op->crcr_low);
  if (reg & (1 << 3))
    grub_dprintf("xhci", "%s: Command ring running\n", __func__);
}

/****************************************************************
 * End point communication
 ****************************************************************/

// Signal the hardware to process events on a TRB ring
static void xhci_doorbell(struct grub_xhci *x, grub_uint32_t slotid, grub_uint32_t value)
{
  xhci_check_status(x);
    grub_dprintf("xhci", "%s: slotid %d, epid %d\n", __func__, slotid, value);
    grub_xhci_write32(&x->db[slotid].doorbell, value);
}

// Dequeue events on the XHCI command ring generated by the hardware
static void xhci_process_events(struct grub_xhci *x)
{
    volatile struct grub_xhci_ring *evts = x->evts;

    for (;;) {
        /* check for event */
        grub_uint32_t nidx = grub_xhci_read32(&evts->nidx);
        grub_uint32_t cs = grub_xhci_read32(&evts->cs);
        volatile struct grub_xhci_trb *etrb = evts->ring + nidx;
        grub_uint32_t control = grub_xhci_read32(&etrb->control);
        if ((control & TRB_C) != (cs ? 1 : 0))
            return;

        /* process event */
        grub_uint32_t evt_type = TRB_TYPE(control);
        grub_uint32_t evt_cc = (grub_xhci_read32(&etrb->status) >> 24) & 0xff;

        switch (evt_type) {
        case ER_TRANSFER:
        case ER_COMMAND_COMPLETE:
        {
            struct grub_xhci_trb  *rtrb = (void*)grub_xhci_read32(&etrb->ptr_low);
            struct grub_xhci_ring *ring = XHCI_RING(rtrb);
            volatile struct grub_xhci_trb  *evt = &ring->evt;
            grub_uint32_t eidx = rtrb - ring->ring + 1;
            grub_dprintf("xhci", "%s: ring %p [trb %p, evt %p, type %d, eidx %d, cc %d]\n",
                    __func__, ring, rtrb, evt, evt_type, eidx, evt_cc);
            grub_memcpy(evt, etrb, sizeof(*etrb));
            grub_xhci_write32(&ring->eidx, eidx);
            break;
        }
        case ER_PORT_STATUS_CHANGE:
        {
            grub_uint32_t port = ((etrb->ptr_low >> 24) & 0xff) - 1;
            // Read status, and clear port status change bits
            grub_uint32_t portsc = grub_xhci_read32(&x->pr[port].portsc);
            grub_uint32_t pclear = (((portsc & ~(GRUB_XHCI_PORTSC_PED|GRUB_XHCI_PORTSC_PR))
                           & ~(XHCI_PORTSC_PLS_MASK<<XHCI_PORTSC_PLS_SHIFT))
                          | (1<<XHCI_PORTSC_PLS_SHIFT));
            grub_xhci_write32(&x->pr[port].portsc, pclear);

            //xhci_print_port_state(3, __func__, port, portsc);
            break;
        }
        default:
            grub_dprintf("xhci", "%s: unknown event, type %d, cc %d\n",
                    __func__, evt_type, evt_cc);
            break;
        }

        /* move ring index, notify xhci */
        nidx++;
        if (nidx == GRUB_XHCI_RING_ITEMS) {
            nidx = 0;
            cs = cs ? 0 : 1;
            grub_xhci_write32(&evts->cs, cs);
        }
        grub_xhci_write32(&evts->nidx, nidx);
        volatile struct grub_xhci_ir *ir = x->ir;
        grub_uint32_t erdp = (grub_uint32_t)(evts->ring + nidx);
        grub_xhci_write32(&ir->erdp_low, erdp);
        grub_xhci_write32(&ir->erdp_high, 0);
    }
}

// Check if a ring has any pending TRBs
static int xhci_ring_busy(volatile struct grub_xhci_ring *ring)
{
    grub_uint32_t eidx = grub_xhci_read32(&ring->eidx);
    grub_uint32_t nidx = grub_xhci_read32(&ring->nidx);

    return (eidx != nidx);
}

// Returns free space in ring
static int xhci_ring_free_space(volatile struct grub_xhci_ring *ring)
{
  grub_uint32_t eidx = grub_xhci_read32(&ring->eidx);
  grub_uint32_t nidx = grub_xhci_read32(&ring->nidx);

  // nidx is never 0, so reduce ring buffer size by one
  return (eidx > nidx) ? eidx-nidx
                : (ARRAY_SIZE(ring->ring) - 1) - nidx + eidx;
}

// Check if a ring is full
static int xhci_ring_full(volatile struct grub_xhci_ring *ring)
{
  // Might need to insert one link TRB
  return xhci_ring_free_space(ring) <= 1;
}

// Check if a ring is almost full
static int xhci_ring_almost_full(volatile struct grub_xhci_ring *ring)
{
  // Might need to insert one link TRB
  return xhci_ring_free_space(ring) <= 2;
}

// Wait for a ring to empty (all TRBs processed by hardware)
static int xhci_event_wait(struct grub_xhci *x,
                           volatile struct grub_xhci_ring *ring,
                           grub_uint32_t timeout)
{
    grub_uint32_t end = grub_get_time_ms () + timeout;

    for (;;) {
        xhci_check_status(x);
        xhci_process_events(x);
        if (!xhci_ring_busy(ring)) {
            grub_uint32_t status = ring->evt.status;
            return (status >> 24) & 0xff;
        }
        if (grub_get_time_ms () > end) {
            xhci_check_status(x);
            grub_dprintf("xhci", "%s: Timeout waiting for event\n", __func__);
            return -1;
        }
    }
}

// Add a TRB to the given ring
static void xhci_trb_fill(volatile struct grub_xhci_ring *ring
                          , void *data, grub_uint32_t xferlen, grub_uint32_t flags)
{
    struct grub_xhci_trb *dst = &ring->ring[ring->nidx];
    if (flags & TRB_TR_IDT) {
        grub_memcpy(&dst->ptr_low, data, xferlen & 0x1ffff);
    } else {
        dst->ptr_low = (grub_uint32_t)data;
        dst->ptr_high = 0;
    }
    dst->status = xferlen;
    dst->control = flags | (ring->cs ? TRB_C : 0);
}

// Queue a TRB onto a ring, wrapping ring as needed
static void xhci_trb_queue(volatile struct grub_xhci_ring *ring,
                           void *data, grub_uint32_t xferlen, grub_uint32_t flags)
{
  grub_dprintf("xhci", "%s: ring %p data %p len %d flags 0x%x remain 0x%x\n", __func__,
  ring, data, xferlen & 0x1ffff, flags, xferlen >> 17);

  if (xhci_ring_full(ring)) {
    grub_dprintf("xhci", "%s: ERROR: ring %p is full, discarding TRB\n",
      __func__, ring);
    return;
  }
  if (ring->nidx >= ARRAY_SIZE(ring->ring) - 1) {
    xhci_trb_fill(ring, ring->ring, 0, (TR_LINK << 10) | TRB_LK_TC);
    ring->nidx = 0;
    ring->cs ^= 1;
    grub_dprintf("xhci", "%s: ring %p [linked]\n", __func__, ring);
  }

  xhci_trb_fill(ring, data, xferlen, flags);
  ring->nidx++;
  grub_dprintf("xhci", "%s: ring %p [nidx %d, len %d]\n",
          __func__, ring, ring->nidx, xferlen);
}

// Submit a command to the xhci controller ring and flush if full
static int xhci_trb_queue_and_flush(struct grub_xhci *x,
                                    grub_uint32_t slotid,
                                    grub_uint32_t epid,
                                    volatile struct grub_xhci_ring *ring,
                                    void *data, grub_uint32_t xferlen, grub_uint32_t flags)
{
  if (xhci_ring_almost_full(ring)) {
    grub_dprintf("xhci", "%s: almost full e %d n %d\n", __func__, ring->eidx, ring->nidx);
    flags |= TRB_TR_IOC;
  }
  xhci_trb_queue(ring, data, xferlen, flags);
  if (xhci_ring_full(ring)) {
    xhci_doorbell(x, slotid, epid);
    int rc = xhci_event_wait(x, x->cmds, 1000);
    grub_dprintf("xhci", "%s: xhci_event_wait = %d\n", __func__, rc);
    return rc;
  }
  return 0;
}

// Submit a command to the xhci controller ring
static int xhci_cmd_submit(struct grub_xhci *x, struct grub_xhci_inctx *inctx
                           , grub_uint32_t flags)
{
    if (inctx) {
        struct grub_xhci_slotctx *slot = (void*)&inctx[1 << x->flag64];
        grub_uint32_t port = ((slot->ctx[1] >> 16) & 0xff) - 1;
        grub_uint32_t portsc = grub_xhci_read32(&x->pr[port].portsc);
        if (!(portsc & GRUB_XHCI_PORTSC_CCS)) {
          grub_dprintf("xhci", "%s: root port %d no longer connected\n",
            __func__, port);
            return -1;
        }
    }

    xhci_trb_queue(x->cmds, inctx, 0, flags);
    xhci_doorbell(x, 0, 0);
    int rc = xhci_event_wait(x, x->cmds, 1000);
    grub_dprintf("xhci", "%s: xhci_event_wait = %d\n", __func__, rc);

    return rc;
}

static int xhci_cmd_enable_slot(struct grub_xhci *x)
{
    grub_dprintf("xhci", "%s:\n", __func__);
    int cc = xhci_cmd_submit(x, NULL, CR_ENABLE_SLOT << 10);
    if (cc != CC_SUCCESS)
        return -1;
    grub_dprintf("xhci", "%s: %p\n", __func__, &x->cmds->evt.control);
    grub_dprintf("xhci", "%s: %x\n", __func__, grub_xhci_read32(&x->cmds->evt.control));

    return (grub_xhci_read32(&x->cmds->evt.control) >> 24) & 0xff;
}

static int xhci_cmd_disable_slot(struct grub_xhci *x, grub_uint32_t slotid)
{
    grub_dprintf("xhci", "%s: slotid %d\n", __func__, slotid);
    return xhci_cmd_submit(x, NULL, (CR_DISABLE_SLOT << 10) | (slotid << 24));
}

static int xhci_cmd_stop_endpoint(struct grub_xhci *x, grub_uint32_t slotid
                                       , grub_uint32_t epid
                                       , grub_uint32_t suspend)
{
    return xhci_cmd_submit(x, NULL
                           , (CR_STOP_ENDPOINT << 10) | (epid << 16) | (suspend << 23) | (slotid << 24));
}

static int xhci_cmd_reset_endpoint(struct grub_xhci *x, grub_uint32_t slotid
                                       , grub_uint32_t epid
                                       , grub_uint32_t preserve)
{
    return xhci_cmd_submit(x, NULL
                           , (preserve << 9) | (CR_RESET_ENDPOINT << 10) | (epid << 16) | (slotid << 24));
}

static int xhci_cmd_address_device(struct grub_xhci *x, grub_uint32_t slotid
                                   , struct grub_xhci_inctx *inctx)
{
    grub_dprintf("xhci", "%s: slotid %d\n", __func__, slotid);
    return xhci_cmd_submit(x, inctx
                           , (CR_ADDRESS_DEVICE << 10) | (slotid << 24));
}

static int xhci_cmd_configure_endpoint(struct grub_xhci *x, grub_uint32_t slotid
                                       , struct grub_xhci_inctx *inctx)
{
    grub_dprintf("xhci", "%s: slotid %d, add 0x%x, del 0x%x\n", __func__,
            slotid, inctx->add, inctx->del);
    return xhci_cmd_submit(x, inctx
                           , (CR_CONFIGURE_ENDPOINT << 10) | (slotid << 24));
}

static int xhci_cmd_evaluate_context(struct grub_xhci *x, grub_uint32_t slotid
                                     , struct grub_xhci_inctx *inctx)
{
    grub_dprintf("xhci", "%s: slotid %d, add 0x%x, del 0x%x\n", __func__,
            slotid, inctx->add, inctx->del);
    return xhci_cmd_submit(x, inctx
                           , (CR_EVALUATE_CONTEXT << 10) | (slotid << 24));
}


static struct grub_xhci_inctx *
grub_xhci_alloc_inctx(struct grub_xhci *x, int maxepid,
                      struct grub_usb_device *dev)
{
  int size = (sizeof(struct grub_xhci_inctx) * 33) << x->flag64;
  struct grub_xhci_inctx *in = grub_memalign_dma32(2048 << x->flag64, size);
  if (!in) {
      return NULL;
  }
  grub_memset(in, 0, size);

  struct grub_xhci_slotctx *slot = (void*)&in[1 << x->flag64];
  slot->ctx[0]    |= maxepid << 27; // context entries
   grub_dprintf("xhci", "%s: %d\n", __func__, dev->speed);
  switch (dev->speed) {
    case GRUB_USB_SPEED_FULL:
      slot->ctx[0]    |= XHCI_USB_FULLSPEED << 20;
      break;
    case GRUB_USB_SPEED_HIGH:
     slot->ctx[0]     |= XHCI_USB_HIGHSPEED << 20;
      break;
    case GRUB_USB_SPEED_LOW:
      slot->ctx[0]    |= XHCI_USB_LOWSPEED << 20;
      break;
    case GRUB_USB_SPEED_SUPER:
      slot->ctx[0]    |= XHCI_USB_SUPERSPEED << 20;
      break;
    case GRUB_USB_SPEED_NONE:
      slot->ctx[0]    |= 0 << 20;
      break;
  }

  // Route is greater zero on devices that are connected to a non root hub
  if (dev->route) {
    // XXX
#if 0
      if (dev->speed == GRUB_USB_SPEED_LOW || dev->speed == GRUB_USB_SPEED_FULL) {
          struct xhci_pipe *hpipe = container_of(
              hubdev->defpipe, struct xhci_pipe, pipe);
          if (hubdev->speed  == XHCI_USB_HIGHSPEED) {
              slot->ctx[2] |= hpipe->slotid;
              slot->ctx[2] |= (usbdev->port+1) << 8;
          } else {
              struct xhci_slotctx *hslot = (void*)xhci->devs[hpipe->slotid].ptr_low;
              slot->ctx[2] = hslot->ctx[2];
          }
      }

#endif
  }
  slot->ctx[0]    |= dev->route;
  slot->ctx[1]    |= (dev->root_port+1) << 16;

  return in;
}

void
grub_xhci_reset (struct grub_xhci *x)
{
  grub_uint32_t hcs1, hcc, reg;
  grub_uint32_t end;
  int i;

  reg = grub_xhci_read32(&x->op->usbcmd);
  if (reg & GRUB_XHCI_CMD_RS) {
    reg &= ~GRUB_XHCI_CMD_RS;
    grub_xhci_write32(&x->op->usbcmd, reg);

    end = grub_get_time_ms () + 32;
    while (grub_xhci_read32(&x->op->usbcmd) & GRUB_XHCI_STS_HCH) {
      if (grub_get_time_ms () > end) {
          return GRUB_USB_ERR_TIMEOUT;
      }
      grub_millisleep(1);
    }
  }

  grub_dprintf("xhci", "grub_xhci_reset: resetting HC\n");
  grub_xhci_write32(&x->op->usbcmd, GRUB_XHCI_CMD_HCRST);

  // Wait for device to complete reset and be enabled
  end = grub_get_time_ms () + 100;
  while (grub_xhci_read32(&x->op->usbcmd) & GRUB_XHCI_CMD_HCRST) {
      if (grub_get_time_ms () > end) {
          return GRUB_USB_ERR_TIMEOUT;
      }
      grub_millisleep(1);
  }

  // Wait for device to complete reset and be enabled
  end = grub_get_time_ms () + 100;
  while (grub_xhci_read32(&x->op->usbsts) & GRUB_XHCI_STS_CNR) {
      if (grub_get_time_ms () > end) {
          return GRUB_USB_ERR_TIMEOUT;
      }
      grub_millisleep(1);
  }

  grub_xhci_write32(&x->op->config, x->slots);
  grub_xhci_write32(&x->op->dcbaap_low, (grub_uint32_t)x->devs);
  grub_xhci_write32(&x->op->dcbaap_high, 0);
  grub_xhci_write32(&x->op->crcr_low, (grub_uint32_t)x->cmds | 1);
  grub_xhci_write32(&x->op->crcr_high, 0);
  x->cmds->cs = 1;

  x->eseg->ptr_low = (grub_uint32_t)x->evts;
  x->eseg->ptr_high = 0;
  x->eseg->size = GRUB_XHCI_RING_ITEMS;

  grub_xhci_write32(&x->ir->erstsz, 1);
  grub_xhci_write32(&x->ir->erdp_low, (grub_uint32_t)x->evts);
  grub_xhci_write32(&x->ir->erdp_high, 0);
  grub_xhci_write32(&x->ir->erstba_low, (grub_uint32_t)x->eseg);
  grub_xhci_write32(&x->ir->erstba_high, 0);
  x->evts->cs = 1;

  reg = grub_xhci_read32(&x->caps->hcsparams2);
  grub_uint32_t spb = (reg >> 21 & 0x1f) << 5 | reg >> 27;
  if (spb) {
      grub_dprintf("xhci", "%s: setup %d scratch pad buffers\n", __func__, spb);
      grub_uint64_t *spba = (grub_uint64_t *) grub_memalign_dma32(64, sizeof(*spba) * spb);
      void *pad = grub_memalign_dma32(PAGE_SIZE, PAGE_SIZE * spb);
      if (!spba || !pad) {
          grub_free(spba);
          grub_free(pad);
          return GRUB_USB_ERR_INTERNAL;
      }
      for (i = 0; i < spb; i++)
          spba[i] = (grub_uint32_t)pad + (i * PAGE_SIZE);
      x->devs[0].ptr_low = (grub_uint32_t)spba;
      x->devs[0].ptr_high = 0;
  }
  xhci_check_status(x);

  grub_dprintf ("xhci", "XHCI OP COMMAND: %08x\n",
		grub_xhci_read32 (&x->op->usbcmd));
  grub_dprintf ("xhci", "XHCI OP STATUS: %08x\n",
		grub_xhci_read32 (&x->op->usbsts));
  grub_dprintf ("xhci", "XHCI OP PAGESIZE: %08x\n",
		grub_xhci_read32 (&x->op->pagesize));
  grub_dprintf ("xhci", "XHCI OP DNCTRL: %08x\n",
		grub_xhci_read32 (&x->op->dnctl));
  grub_dprintf ("xhci", "XHCI OP CRCR_LOW: %08x\n",
		grub_xhci_read32 (&x->op->crcr_low));
  grub_dprintf ("xhci", "XHCI OP CRCR_HIGH: %08x\n",
		grub_xhci_read32 (&x->op->crcr_high));
  grub_dprintf ("xhci", "XHCI OP DCBAAP_LOW: %08x\n",
		grub_xhci_read32 (&x->op->dcbaap_low));
  grub_dprintf ("xhci", "XHCI OP DCBAAP_HIGH: %08x\n",
		grub_xhci_read32 (&x->op->dcbaap_high));
  grub_dprintf ("xhci", "XHCI OP CONFIG: %08x\n",
		grub_xhci_read32 (&x->op->config));
  grub_dprintf ("xhci", "XHCI IR ERSTSZ: %08x\n",
		grub_xhci_read32 (&x->ir->erstsz));
  grub_dprintf ("xhci", "XHCI IR ERDP: %08x\n",
		grub_xhci_read32 (&x->ir->erdp_low));
  grub_dprintf ("xhci", "XHCI IR ERSTBA: %08x\n",
		grub_xhci_read32 (&x->ir->erstba_low));

  xhci_check_status(x);
}

/* PCI iteration function... */
void
grub_xhci_init_device (volatile void *regs)
{
  struct grub_xhci *x;
  grub_uint32_t hcs1, hcc, reg;

  /* Allocate memory for the controller and fill basic values. */
  x = grub_zalloc (sizeof (*x));
  if (!x) {
    grub_dprintf("xhci", "XHCI grub_ehci_pci_iter memory allocation failed\n");
    return;
  }
  x->caps = (struct grub_xhci_caps *) regs;
  x->op = (struct grub_xhci_op *) (((grub_uint8_t *)regs) + grub_xhci_read8(&x->caps->caplength));
  x->pr = (struct grub_xhci_pr *) (((grub_uint8_t *)x->op) + GRUB_XHCI_PR_OFFSET);
  x->db = (struct grub_xhci_db *) (((grub_uint8_t *)regs) + grub_xhci_read32(&x->caps->dboff));
  x->ir = (struct grub_xhci_ir *) (((grub_uint8_t *)regs) +
		  grub_xhci_read32(&x->caps->rtsoff) + GRUB_XHCI_IR_OFFSET);

  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: CAPLENGTH: %02x\n",
		grub_xhci_read8 (&x->caps->caplength));
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: HCIVERSION: %04x\n",
		grub_xhci_read16 (&x->caps->hciversion));
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: HCSPARAMS1: %08x\n",
		grub_xhci_read32 (&x->caps->hcsparams1));
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: HCSPARAMS2: %08x\n",
		grub_xhci_read32 (&x->caps->hcsparams2));
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: HCSPARAMS3: %08x\n",
		grub_xhci_read32 (&x->caps->hcsparams3));
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: HCCPARAMS: %08x\n",
		grub_xhci_read32 (&x->caps->hcsparams3));
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: DBOFF: %08x\n",
		grub_xhci_read32 (&x->caps->dboff));
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: RTOFF: %08x\n",
		grub_xhci_read32 (&x->caps->rtsoff));

  hcs1 = grub_xhci_read32(&x->caps->hcsparams1);
  hcc = grub_xhci_read32(&x->caps->hccparams);
  x->ports = (grub_uint32_t) ((hcs1 >> 24) & 0xff);
  x->slots = (grub_uint32_t) (hcs1         & 0xff);
  x->xcap  = (grub_uint32_t) (((hcc >> 16) & 0xffff) << 2);
  x->flag64 = (grub_uint8_t) ((hcc & 0x04) ? 1 : 0);
  grub_dprintf("xhci", "XHCI init: %d ports, %d slots"
          ", %d byte contexts\n"
          , x->ports, x->slots
          , x->flag64 ? 64 : 32);
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: flag64=%d\n", x->flag64);

  if (x->xcap) {
    grub_uint32_t off;
    volatile void *addr = (grub_uint8_t *) x->caps + x->xcap;
    do {
      volatile struct grub_xhci_xcap *xcap = addr;
      grub_uint32_t ports, name, cap = grub_xhci_read32(&xcap->cap);
      switch (cap & 0xff) {
      case 0x02:
        name  = grub_xhci_read32(&xcap->data[0]);
        ports = grub_xhci_read32(&xcap->data[1]);
        grub_uint8_t major = (cap >> 24) & 0xff;
        grub_uint8_t minor = (cap >> 16) & 0xff;
        grub_uint8_t count = (ports >> 8) & 0xff;
        grub_uint8_t start = (ports >> 0) & 0xff;
        grub_dprintf("xhci", "XHCI    protocol %c%c%c%c %x.%02x"
            ", %d ports (offset %d), def %x\n"
            , (name >>  0) & 0xff
            , (name >>  8) & 0xff
            , (name >> 16) & 0xff
            , (name >> 24) & 0xff
            , major, minor
            , count, start
            , ports >> 16);
        if (name == 0x20425355 /* "USB " */) {
          if (major == 2) {
              x->usb2.count = count;
          }
          if (major == 3) {
              x->usb3.start = start;
              x->usb3.count = count;
          }
        }
        break;
      default:
          grub_dprintf("xhci", "XHCI    extcap 0x%x @ %p\n", cap & 0xff, addr);
          break;
      }
      off = (cap >> 8) & 0xff;
      addr += off << 2;
    } while (off > 0);
  }

  grub_uint32_t pagesize = grub_xhci_read32(&x->op->pagesize);
  if (PAGE_SIZE != (pagesize<<12)) {
      grub_dprintf("xhci", "XHCI driver does not support page size code %d\n"
              , pagesize<<12);
    goto fail;
  }
  x->slots_meta = grub_zalloc(sizeof(x->slots_meta[0]) * (x->slots + 1));
  x->devs = grub_memalign_dma32(64, sizeof(*x->devs) * (x->slots + 1));
  x->eseg = grub_memalign_dma32(64, sizeof(*x->eseg));
  x->cmds = grub_memalign_dma32(GRUB_XHCI_RING_SIZE, sizeof(*x->cmds));
  x->evts = grub_memalign_dma32(GRUB_XHCI_RING_SIZE, sizeof(*x->evts));
  grub_dprintf ("xhci", "XHCI devs %p\n", x->devs);
  grub_dprintf ("xhci", "XHCI eseg %p\n", x->eseg);
  grub_dprintf ("xhci", "XHCI cmds %p\n", x->cmds);
  grub_dprintf ("xhci", "XHCI evts %p\n", x->evts);

  if (!x->slots_meta || !x->devs || !x->cmds || !x->evts || !x->eseg) {
      goto fail;
  }
  grub_memset(x->devs, 0, sizeof(*x->devs) * (x->slots + 1));
  grub_memset(x->cmds, 0, sizeof(*x->cmds));
  grub_memset(x->evts, 0, sizeof(*x->evts));
  grub_memset(x->eseg, 0, sizeof(*x->eseg));

  grub_xhci_reset(x);

  /* Set the running bit */
  reg = grub_xhci_read32 (&x->op->usbcmd);
  reg |= GRUB_XHCI_CMD_RS;
  grub_xhci_write32 (&x->op->usbcmd, reg);

  /* Link to xhci now that initialisation is successful.  */
  x->next = xhci;
  xhci = x;

  return;

fail:
  grub_dprintf ("xhci", "XHCI grub_xhci_pci_iter: FAILED!\n");
  if (x)
    {
      if (x->devs)
        grub_dma_free ((void *) x->devs);
      if (x->eseg)
        grub_dma_free ((void *) x->eseg);
      if (x->cmds)
        grub_dma_free ((void *) x->cmds);
      if (x->evts)
        grub_dma_free ((void *) x->evts);
      if (x->slots_meta)
        grub_free (x->slots_meta);
    }
  grub_free (x);

  return;
}

static int
grub_xhci_iterate (grub_usb_controller_iterate_hook_t hook, void *hook_data)
{
  struct grub_xhci *x;
  struct grub_usb_controller dev;

  for (x = xhci; x; x = x->next)
    {
      dev.data = x;
      if (hook (&dev, hook_data))
	return 1;
    }

  return 0;
}

static grub_usb_err_t
grub_xhci_update_hub_portcount (struct grub_xhci *x,
			  grub_usb_transfer_t transfer,
        grub_uint32_t slotid)
{
  grub_uint32_t epid = 0;
  grub_usb_err_t err;

  if (!transfer || !transfer->dev || !transfer->dev->nports)
    return GRUB_USB_ERR_NONE;

  struct grub_xhci_slotctx *hdslot = (void*)x->devs[slotid].ptr_low;
  if ((hdslot->ctx[3] >> 27) == 3)
    // Already configured
    return 0;

  grub_dprintf("xhci", "%s: updating hub config to %d ports\n", __func__,
     transfer->dev->nports);

  xhci_check_status(x);

  // Allocate input context and initialize endpoint info.
  struct grub_xhci_inctx *in = grub_xhci_alloc_inctx(x, epid, transfer->dev);
  if (!in)
    return GRUB_USB_ERR_INTERNAL;
  in->add = (1 << epid);

  struct grub_xhci_epctx *ep = (void*)&in[(epid+1) << x->flag64];
  ep->ctx[0]   |= 1 << 26;
  ep->ctx[1]   |= transfer->dev->nports << 24;

  int cc = xhci_cmd_configure_endpoint(x, slotid, in);
  grub_dma_free(in);

  if (cc != CC_SUCCESS) {
      grub_dprintf("xhci", "%s: reconf ctl endpoint: failed (cc %d)\n",
              __func__, cc);
    return GRUB_USB_ERR_BADDEVICE;
  }

  return GRUB_USB_ERR_NONE;
}

static grub_usb_err_t
grub_xhci_update_max_paket_size (struct grub_xhci *x,
			  grub_usb_transfer_t transfer,
        grub_uint32_t slotid)
{
  grub_uint32_t epid = 1;
  grub_usb_err_t err;

  if (!transfer || !transfer->dev || !transfer->dev->descdev.maxsize0)
    return GRUB_USB_ERR_NONE;

  grub_dprintf("xhci", "%s: updating max packet size to 0x%x\n", __func__,
    transfer->dev->descdev.maxsize0);

  xhci_check_status(x);

  // Allocate input context and initialize endpoint info.
  struct grub_xhci_inctx *in = grub_xhci_alloc_inctx(x, epid, transfer->dev);
  if (!in)
    return GRUB_USB_ERR_INTERNAL;
  in->add = (1 << epid);

  struct grub_xhci_epctx *ep = (void*)&in[(epid+1) << x->flag64];
  ep->ctx[1]   |= transfer->dev->descdev.maxsize0 << 16;

  int cc = xhci_cmd_evaluate_context(x, slotid, in);
  grub_dma_free(in);

  if (cc != CC_SUCCESS) {
      grub_dprintf("xhci", "%s: reconf ctl endpoint: failed (cc %d)\n",
              __func__, cc);
    return GRUB_USB_ERR_BADDEVICE;
  }

  return GRUB_USB_ERR_NONE;
}

static grub_usb_err_t
grub_xhci_prepare_endpoint (grub_usb_controller_t dev,
			  grub_usb_transfer_t transfer,
        struct grub_xhci_slots **out)
{
  struct grub_xhci *x = (struct grub_xhci *) dev->data;
  grub_uint32_t epid;
  struct grub_xhci_slots *slots = NULL;
  volatile struct grub_xhci_ring     *reqs;
  grub_usb_err_t err;

  xhci_check_status(x);

  if (transfer->endpoint == 0) {
    epid = 1;
  } else {
    epid = (transfer->endpoint & 0x0f) * 2;
    epid += (transfer->dir == GRUB_USB_TRANSFER_TYPE_IN) ? 1 : 0;
  }
  grub_dprintf("xhci", "%s: epid %d, dev %d\n", __func__,
            epid, transfer->dev->addr);

  // Lookup metadata set on first device contact
  for (int i = 0; i < x->slots; i++) {
    if (x->slots_meta[i].slotid > 0 && x->slots_meta[i].dev == transfer->dev) {
      slots = &x->slots_meta[i];
      break;
    }
  }
  if (slots && slots->enpoint_trbs[epid]) {
    *out = slots;
    grub_dprintf("xhci", "%s: setup already done\n", __func__);
    return GRUB_USB_ERR_NONE;
  }

  reqs = grub_memalign_dma32(GRUB_XHCI_RING_SIZE, sizeof(*reqs));
  if (!reqs)
    return GRUB_USB_ERR_INTERNAL;
  grub_memset(reqs, 0, sizeof(*reqs));
  reqs->cs = 1;

  // Allocate input context and initialize endpoint info.
  struct grub_xhci_inctx *in = grub_xhci_alloc_inctx(x, epid, transfer->dev);
  if (!in)
    return GRUB_USB_ERR_INTERNAL;
  in->add = 0x01 | (1 << epid);

  struct grub_xhci_epctx *ep = (void*)&in[(epid+1) << x->flag64];
  switch (transfer->type) {
    case GRUB_USB_TRANSACTION_TYPE_CONTROL:
      ep->ctx[1]   |= 0 << 3;
      break;
    case GRUB_USB_TRANSACTION_TYPE_BULK:
      ep->ctx[1]   |= 2 << 3;
      break;
  }
  if (transfer->dir == GRUB_USB_TRANSFER_TYPE_IN
      || transfer->type == GRUB_USB_TRANSACTION_TYPE_CONTROL)
      ep->ctx[1] |= 1 << 5;
  ep->ctx[1]   |= transfer->max << 16;
  ep->deq_low  = (grub_uint32_t)&reqs->ring[0];
  ep->deq_low  |= 1;         // dcs
  ep->length   = transfer->max;

  grub_dprintf("xhci", "%s: dev ports %d hub_endpoint %p class %x\n", __func__,
            transfer->dev->nports,
            transfer->dev->hub_endpoint,
            transfer->dev->descdev.class
            );
  grub_dprintf("xhci", "%s: ring %p, epid %d, max %d\n", __func__,
            reqs, epid, transfer->max);
  if (epid == 1 || slots == NULL) {

    #if 0
    if (usbdev->hub->usbdev) {
        // Make sure parent hub is configured.
        int ret = xhci_config_hub(usbdev->hub);
        if (ret)
          return GRUB_USB_ERR_BADDEVICE;
    }
    #endif
    // Enable slot.
    int slotid = xhci_cmd_enable_slot(x);
    if (slotid < 0) {
        grub_dprintf("xhci", "%s: enable slot: failed\n", __func__);
        grub_dma_free(in);
        return GRUB_USB_ERR_BADDEVICE;
    }
    grub_dprintf("xhci", "%s: get slot %d assigned\n", __func__, slotid);

    grub_uint32_t size = (sizeof(struct grub_xhci_slotctx) * 32) << x->flag64;
    struct grub_xhci_slotctx *slotctx = grub_memalign_dma32(1024 << x->flag64, size);
    if (!slotctx) {
      grub_dprintf("xhci", "%s: grub_memalign_dma32 failed\n", __func__);

      grub_dma_free(in);
      return GRUB_USB_ERR_INTERNAL;
    }
    grub_dprintf("xhci", "%s: enable slot: got slotid %d\n", __func__, slotid);
    grub_memset(slotctx, 0, size);
    x->devs[slotid].ptr_low = (grub_uint32_t)slotctx;
    x->devs[slotid].ptr_high = 0;

    // Send set_address command.
    int cc = xhci_cmd_address_device(x, slotid, in);
    if (cc != CC_SUCCESS) {
        grub_dprintf("xhci","%s: address device: failed (cc %d)\n", __func__, cc);
        cc = xhci_cmd_disable_slot(x, slotid);
        if (cc != CC_SUCCESS) {
            grub_dma_free(slotctx);
            grub_dma_free(in);
            grub_dprintf("xhci", "%s: disable failed (cc %d)\n", __func__, cc);
            return GRUB_USB_ERR_BADDEVICE;
        }
        x->devs[slotid].ptr_low = 0;
        grub_dma_free(slotctx);
        grub_dma_free(in);
        return GRUB_USB_ERR_BADDEVICE;
    }
    x->slots_meta[slotid].enpoint_trbs[epid] = reqs;
    x->slots_meta[slotid].slotid = slotid;
    x->slots_meta[slotid].dev = transfer->dev;
    x->slots_meta[slotid].dev_addr = 0;     //new->dev_addr = 0; FIXME
    x->slots_meta[slotid].max_packet = 8;
    slots = &x->slots_meta[slotid];

    *out = &x->slots_meta[slotid];
  }
  if (epid != 1) {
      // Send configure command.
      int cc = xhci_cmd_configure_endpoint(x, slots->slotid, in);
      if (cc != CC_SUCCESS) {
          grub_dprintf("xhci", "%s: configure endpoint: failed (cc %d)\n", __func__, cc);
          grub_dma_free(in);

          return GRUB_USB_ERR_BADDEVICE;
      }
    x->slots_meta[slots->slotid].enpoint_trbs[epid] = reqs;
    *out = &x->slots_meta[slots->slotid];
  }

  grub_dprintf("xhci", "%s:done\n", __func__);
  grub_dma_free(in);

  return GRUB_USB_ERR_NONE;
}

static grub_usb_err_t
grub_xhci_usb_to_grub_err (unsigned char status)
{
  if (status != CC_SUCCESS) {
    grub_dprintf("xhci", "%s: xfer failed (cc %d)\n", __func__, status);
  } else {
    grub_dprintf("xhci", "%s: xfer done   (cc %d)\n", __func__, status);
  }

  if (status == CC_BABBLE_DETECTED) {
    return GRUB_USB_ERR_BABBLE;
  } else if (status == CC_DATA_BUFFER_ERROR) {
    return GRUB_USB_ERR_DATA;
  } else if (status == CC_STALL_ERROR) {
    return GRUB_USB_ERR_STALL;
  } else if (status != CC_SUCCESS) {
    return GRUB_USB_ERR_NAK;
  }

  return GRUB_USB_ERR_NONE;
}

static int
grub_xhci_transfer_is_zlp(grub_usb_transfer_t transfer,
                          int idx)
{
  if (idx >= transfer->transcnt)
    return 0;

  grub_usb_transaction_t tr = &transfer->transactions[idx];

  return (tr->size == 0) &&
    ((tr->pid == GRUB_USB_TRANSFER_TYPE_OUT) ||
    (tr->pid == GRUB_USB_TRANSFER_TYPE_IN));
}

static int
grub_xhci_transfer_is_last(grub_usb_transfer_t transfer,
                           int idx)
{
    return (idx + 1) == transfer->transcnt;
}

static int
grub_xhci_transfer_is_data(grub_usb_transfer_t transfer,
                           int idx)
{
  grub_usb_transaction_t tr;

  if (idx >= transfer->transcnt)
    return 0;

  tr = &transfer->transactions[idx];
  if (tr->size == 0 ||
      (tr->pid == GRUB_USB_TRANSFER_TYPE_SETUP))
    return 0;

  // If there's are no DATA pakets before it's a DATA paket
  for (int i = idx - 1; i >= 0; i--) {
    tr = &transfer->transactions[i];
    if (tr->size > 0 &&
        ((tr->pid == GRUB_USB_TRANSFER_TYPE_OUT) ||
        (tr->pid == GRUB_USB_TRANSFER_TYPE_IN))) {
          return 0;
    }
  }
  return 1;
}

static int
grub_xhci_transfer_next_is_data(grub_usb_transfer_t transfer,
                                int idx)
{
  return grub_xhci_transfer_is_data(transfer, idx + 1);
}

static int
grub_xhci_transfer_is_normal(grub_usb_transfer_t transfer,
                            int idx)
{
  grub_usb_transaction_t tr;
  int first = 1;

  if (idx >= transfer->transcnt)
    return 0;

  tr = &transfer->transactions[idx];
  if (tr->size == 0 ||
      (tr->pid == GRUB_USB_TRANSFER_TYPE_SETUP))
    return 0;

  // If there's at least one DATA paket before it's a normal
  for (int i = idx - 1; i >= 0; i--) {
    tr = &transfer->transactions[i];
    if (tr->size > 0 &&
        ((tr->pid == GRUB_USB_TRANSFER_TYPE_OUT) ||
        (tr->pid == GRUB_USB_TRANSFER_TYPE_IN))) {
          return 1;
    }
  }
  return 0;
}

static int
grub_xhci_transfer_next_is_normal(grub_usb_transfer_t transfer,
                                  int idx)
{
  return grub_xhci_transfer_is_normal(transfer, idx + 1);
}

static grub_usb_err_t
grub_xhci_setup_transfer (grub_usb_controller_t dev,
			  grub_usb_transfer_t transfer)
{
  struct grub_xhci_transfer_controller_data *cdata;
  struct grub_xhci *x = (struct grub_xhci *) dev->data;
  grub_uint32_t epid;
  grub_usb_err_t err;
  int rc;
  struct grub_xhci_slots *slots = NULL;

   xhci_check_status(x);

  if (transfer->endpoint == 0) {
      epid = 1;
  } else {
      epid = (transfer->endpoint & 0x0f) * 2;
      epid += (transfer->dir == GRUB_USB_TRANSFER_TYPE_IN) ? 1 : 0;
  }

  err = grub_xhci_prepare_endpoint(dev, transfer, &slots);
  if (err != GRUB_USB_ERR_NONE)
    return err;

  if (!slots || !slots->enpoint_trbs[epid])
    return GRUB_USB_ERR_INTERNAL;

  // Update the max packet size once descdev.maxsize0 is valid
  if (epid == 1 &&
    (slots->max_packet < transfer->dev->descdev.maxsize0)) {
    slots->max_packet = transfer->dev->descdev.maxsize0) {
    err = grub_xhci_update_max_paket_size(x, transfer, slots->slotid);
    if (err != GRUB_USB_ERR_NONE) {
      grub_dprintf("xhci", "%s: Updating max paket size failed\n", __func__);
      return err;
    }
  }
  if (epid == 1 &&
      transfer->dev->descdev.class == 9 &&
      transfer->dev->nports > 0) {
    err = grub_xhci_update_hub_portcount(x, transfer, slots->slotid);
    if (err != GRUB_USB_ERR_NONE) {
      grub_dprintf("xhci", "%s: Updating max paket size failed\n", __func__);
      return err;
    }
  }

  cdata = grub_zalloc(sizeof(*cdata));
  if (!cdata)
    return GRUB_USB_ERR_INTERNAL;

  cdata->epid = epid;
  cdata->reqs = slots->enpoint_trbs[epid];
  cdata->slotid = slots->slotid;

  transfer->controller_data = cdata;

  // Now queue the transfers
  if (transfer->type == GRUB_USB_TRANSACTION_TYPE_CONTROL) {
    volatile struct grub_usb_packet_setup *setupdata;
    grub_uint32_t data_count = 0;
    setupdata = (void *)transfer->transactions[0].data;
    grub_dprintf("xhci", "%s: CONTROLL TRANS req %d\n", __func__, setupdata->request);
    grub_dprintf("xhci", "%s: CONTROLL TRANS length %d\n", __func__, setupdata->length);

    if (setupdata && setupdata->request == GRUB_USB_REQ_SET_ADDRESS)
      return GRUB_USB_ERR_NONE;

    for (int i = 0; i < transfer->transcnt; i++)
    {
      grub_uint32_t flags = 0;
      grub_uint32_t remaining_td;
      grub_usb_transaction_t tr = &transfer->transactions[i];

      switch (tr->pid) {
        case GRUB_USB_TRANSFER_TYPE_SETUP:
            grub_dprintf("xhci", "%s: SETUP PKG\n", __func__);
            grub_dprintf("xhci", "%s: transfer->size %d\n", __func__, transfer->size);
            grub_dprintf("xhci", "%s: tr->size %d SETUP PKG\n", __func__, tr->size);

          flags |= (TR_SETUP << 10);
          flags |= TRB_TR_IDT;

          if (transfer->size > 0) {
            if (transfer->dir == GRUB_USB_TRANSFER_TYPE_IN) {
              flags |= (3 << 16); // TRT IN
            } else {
              flags |= (2 << 16); // TRT OUT
            }
          }
          break;
        case GRUB_USB_TRANSFER_TYPE_OUT:
          grub_dprintf("xhci", "%s: OUT PKG\n", __func__);
          cdata->transfer_size += tr->size;
          break;
        case GRUB_USB_TRANSFER_TYPE_IN:
          grub_dprintf("xhci", "%s: IN PKG\n", __func__);
          cdata->transfer_size += tr->size;
          flags |= TRB_TR_DIR; // DIR IN
          break;
      }

      if (grub_xhci_transfer_is_normal(transfer, i)) {
        flags |= (TR_NORMAL << 10);
      } else if (grub_xhci_transfer_is_data(transfer, i)) {
        flags |= (TR_DATA << 10);
      } else if (grub_xhci_transfer_is_zlp(transfer, i)) {
        flags |= (TR_STATUS << 10);
      }
      if (grub_xhci_transfer_next_is_normal(transfer, i)) {
        flags |= TRB_TR_CH;
      }
      if (grub_xhci_transfer_is_last(transfer, i)) {
        flags |= TRB_TR_IOC;
      }

      // Seems not required. Seabios doesn't have it ....
      remaining_td = ((transfer->transcnt - 1) -i);
      if (remaining_td > 31)
        remaining_td = 31;

      // Assume the ring has enough free space for all TRBs
      xhci_trb_queue(cdata->reqs, (void *)tr->data,
                     (remaining_td << 17) | tr->size, flags);

    }
  } else if (transfer->type == GRUB_USB_TRANSACTION_TYPE_BULK) {

    for (int i = 0; i < transfer->transcnt; i++)
    {
      grub_uint32_t flags = (TR_NORMAL << 10);
      grub_usb_transaction_t tr = &transfer->transactions[i];
      switch (tr->pid) {
        case GRUB_USB_TRANSFER_TYPE_OUT:
           grub_dprintf("xhci", "%s: OUT PKG\n", __func__);
           cdata->transfer_size += tr->size;
          break;
        case GRUB_USB_TRANSFER_TYPE_IN:
           grub_dprintf("xhci", "%s: IN PKG\n", __func__);
           cdata->transfer_size += tr->size;
          flags |= TRB_TR_DIR; // DIR IN
          break;
      }
      if (grub_xhci_transfer_is_last(transfer, i)) {
        flags |= TRB_TR_IOC;
      }
      // The ring might be to small, submit while adding new entries
      rc = xhci_trb_queue_and_flush(x, cdata->slotid, cdata->epid,
                               cdata->reqs, (void *)tr->data, tr->size, flags);
      if (rc < 0) {
        return GRUB_USB_ERR_TIMEOUT;
      } else if (rc > 1) {
        return grub_xhci_usb_to_grub_err(rc);
      }
    }
  }
  xhci_doorbell(x, cdata->slotid, cdata->epid);

  return GRUB_USB_ERR_NONE;
}

static grub_usb_err_t
grub_xhci_check_transfer (grub_usb_controller_t dev,
			  grub_usb_transfer_t transfer, grub_size_t * actual)
{
  grub_uint32_t status;
  grub_uint32_t remaining;
  int rc;

  struct grub_xhci *x = (struct grub_xhci *) dev->data;
  volatile struct grub_xhci_transfer_controller_data *cdata =
    transfer->controller_data;

  xhci_check_status(x);
  xhci_process_events(x);

  // Get current status from event ring buffer
  status = (cdata->reqs->evt.status>> 24) & 0xff;
  remaining = cdata->reqs->evt.status & 0xffffff;

  if (status != CC_STOPPED_LENGTH_INVALID) {
    *actual = cdata->transfer_size - remaining;
  } else {
    *actual = 0;
  }

  if (xhci_ring_busy(cdata->reqs)) {
      return GRUB_USB_ERR_WAIT;
  }

  // DONE
  grub_free(cdata);

  if (status != CC_SUCCESS) {
    grub_dprintf("xhci", "%s: xfer failed (cc %d)\n", __func__, status);
  }
  if (status == CC_BABBLE_DETECTED) {
    return GRUB_USB_ERR_BABBLE;
  } else if (status == CC_DATA_BUFFER_ERROR) {
    return GRUB_USB_ERR_DATA;
  } else if (status == CC_STALL_ERROR) {
    // Clear the stall by resetting the endpoint
    rc = xhci_cmd_reset_endpoint(x, cdata->slotid, cdata->epid, 1);
    if (rc < 0) {
      return GRUB_USB_ERR_TIMEOUT;
    }
    return GRUB_USB_ERR_STALL;
  } else if (remaining > 0) {
    return GRUB_USB_ERR_DATA;
  }  else if (status != CC_SUCCESS) {
    return GRUB_USB_ERR_NAK;
  }
  grub_dprintf("xhci", "%s: xfer done\n", __func__);

  return GRUB_USB_ERR_NONE;
}

static grub_usb_err_t
grub_xhci_cancel_transfer (grub_usb_controller_t dev,
			grub_usb_transfer_t transfer)
{
  grub_uint32_t reg;
  int rc;

  struct grub_xhci *x = (struct grub_xhci *) dev->data;
  struct grub_xhci_transfer_controller_data *cdata =
    transfer->controller_data;

  rc = xhci_cmd_stop_endpoint(x, cdata->slotid, cdata->epid, 0);
  if (rc < 0) {
    return GRUB_USB_ERR_TIMEOUT;
  }

  xhci_doorbell(x, cdata->slotid, cdata->epid);

  grub_free (cdata);

  return GRUB_USB_ERR_NONE;
}

static int
grub_xhci_hubports (grub_usb_controller_t dev)
{
  struct grub_xhci *x = (struct grub_xhci *) dev->data;
  grub_uint32_t portinfo;

  portinfo = x->ports;
  grub_dprintf ("xhci", "root hub ports=%d\n", portinfo);
  return portinfo;
}

static grub_usb_err_t
grub_xhci_portstatus (grub_usb_controller_t dev,
			  unsigned int port, unsigned int enable)
{
  struct grub_xhci *x = (struct grub_xhci *) dev->data;
  grub_uint32_t portsc, pls;
  grub_uint32_t end;

  portsc = grub_xhci_read32(&x->pr[port].portsc);
  pls = xhci_get_field(portsc, XHCI_PORTSC_PLS);

 grub_dprintf("xhci", "grub_xhci_portstatus port #%d: 0x%08x,%s%s pls %d enable %d\n",
          port, portsc,
          (portsc & GRUB_XHCI_PORTSC_PP)  ? " powered," : "",
          (portsc & GRUB_XHCI_PORTSC_PED) ? " enabled," : "",
          pls, enable);
  xhci_check_status(x);

  if ((enable && (portsc & GRUB_XHCI_PORTSC_PED)) ||
      (!enable && !(portsc & GRUB_XHCI_PORTSC_PED)))
    return GRUB_USB_ERR_NONE;

  if (!enable) {
    // Disable port
    grub_xhci_write32(&x->pr[port].portsc, portsc | GRUB_XHCI_PORTSC_PED);
    return GRUB_USB_ERR_NONE;
  }

  grub_dprintf ("xhci", "portstatus: XHCI STATUS: %08x\n",
		grub_xhci_read32(&x->op->usbsts));
  grub_dprintf ("xhci",
		"portstatus: begin, iobase=%p, port=%d, status=0x%08x\n",
		x->caps, port, portsc);

  switch (pls) {
  case PLS_U0:
      // A USB3 port - controller automatically performs reset
      break;
  case PLS_POLLING:
      // A USB2 port - perform device reset
      grub_xhci_write32(&x->pr[port].portsc, portsc | GRUB_XHCI_PORTSC_PR);
      break;
  default:
      return GRUB_USB_ERR_NONE;
  }

  // Wait for device to complete reset and be enabled
  end = grub_get_time_ms () + 100;
  for (;;) {
      portsc = grub_xhci_read32(&x->pr[port].portsc);
      if (!(portsc & GRUB_XHCI_PORTSC_CCS)) {
          // Device disconnected during reset
          grub_dprintf ("xhci","ERROR: %s device disconnected\n", __func__);
          return GRUB_USB_ERR_BADDEVICE;
      }
      if (portsc & GRUB_XHCI_PORTSC_PED)
          // Reset complete
          break;
      if (grub_get_time_ms () > end) {
          grub_dprintf ("xhci","ERROR: %s TIMEOUT\n", __func__);
          return GRUB_USB_ERR_TIMEOUT;
      }
  }
  xhci_check_status(x);

  return GRUB_USB_ERR_NONE;
}

static grub_usb_speed_t
grub_xhci_detect_dev (grub_usb_controller_t dev, int port, int *changed)
{
  struct grub_xhci *x = (struct grub_xhci *) dev->data;
  grub_uint32_t portsc, pls, speed;

  portsc = grub_xhci_read32(&x->pr[port].portsc);
  pls = xhci_get_field(portsc, XHCI_PORTSC_PLS);
  speed = xhci_get_field(portsc, XHCI_PORTSC_SPEED);

  /* Connect Status Change bit - it detects change of connection */
  if (portsc & GRUB_XHCI_PORTSC_CSC)
    {
      *changed = 1;
      /* Reset bit Connect Status Change */
      //grub_xhci_port_setbits (x, port, GRUB_XHCI_PORTSC_CSC);
    }
  else
    *changed = 0;
#if 0
  grub_dprintf("xhci", "port #%d: 0x%08x,%s%s%s pls %d, speed %d\n",
          port, portsc,
          (portsc & GRUB_XHCI_PORTSC_PP)  ? " powered," : "",
          (portsc & GRUB_XHCI_PORTSC_PED) ? " enabled," : "",
          *changed ? "changed, " : "",
          pls, speed);
#endif
  if (!(portsc & GRUB_XHCI_PORTSC_CCS))
    {				/* We should reset related "reset" flag in not connected state */
      x->reset &= ~(1 << port);
      return GRUB_USB_SPEED_NONE;
    }

  switch (speed) {
	  case XHCI_USB_HIGHSPEED:
		  return GRUB_USB_SPEED_HIGH;
	  case XHCI_USB_FULLSPEED:
		  return GRUB_USB_SPEED_FULL;
	  case XHCI_USB_LOWSPEED:
		  return GRUB_USB_SPEED_LOW;
	  case XHCI_USB_SUPERSPEED:
		  return GRUB_USB_SPEED_SUPER;
  }

  return GRUB_USB_SPEED_NONE;
}

static void
grub_xhci_halt(struct grub_xhci *x)
{
  grub_uint32_t reg;
  int i, j;

  for (i = 0; i < x->slots; i++) {
    for (j = 0; j < 32; j++) {
      if (x->slots_meta[i].enpoint_trbs[j] != NULL) {
        xhci_cmd_stop_endpoint(x, x->slots_meta[i].slotid, j, 1);
        grub_dma_free(x->slots_meta[i].enpoint_trbs[j]);
        x->slots_meta[i].enpoint_trbs[j] = NULL;
      }
    }
  }

  // Halt the command ring
  reg = grub_xhci_read32(&x->op->crcr_low);
  grub_xhci_write32(&x->op->crcr_low, reg | 4);

  int rc = xhci_event_wait(x, x->cmds, 100);
  grub_dprintf("xhci", "%s: xhci_event_wait = %d\n", __func__, rc);
  if (rc < 0) {
    return;
  }

  // Stop the controller
  reg = grub_xhci_read32(&x->op->usbcmd);
  if (reg & GRUB_XHCI_CMD_RS) {
    reg &= ~GRUB_XHCI_CMD_RS;
    grub_xhci_write32(&x->op->usbcmd, reg);
  }

  return;
}

static grub_err_t
grub_xhci_fini_hw (int noreturn __attribute__ ((unused)))
{
  struct grub_xhci *x;

  /* We should disable all XHCI HW to prevent any DMA access etc. */
  for (x = xhci; x; x = x->next)
    {
      /* Check if xHCI is halted and halt it if not */
      grub_xhci_halt (x);

      /* Reset xHCI */
      grub_xhci_reset (x);
    }

  return GRUB_ERR_NONE;
}

static struct grub_usb_controller_dev usb_controller = {
  .name = "xhci",
  .iterate = grub_xhci_iterate,
  .setup_transfer = grub_xhci_setup_transfer,
  .check_transfer = grub_xhci_check_transfer,
  .cancel_transfer = grub_xhci_cancel_transfer,
  .hubports = grub_xhci_hubports,
  .portstatus = grub_xhci_portstatus,
  .detect_dev = grub_xhci_detect_dev,
  /* estimated max. count of TDs for one bulk transfer */
  .max_bulk_tds = GRUB_XHCI_N_TD * 3 / 4
};

GRUB_MOD_INIT (xhci)
{
  grub_stop_disk_firmware ();

  grub_boot_time ("Initing XHCI hardware");
  grub_xhci_pci_scan ();
  grub_boot_time ("Registering XHCI driver");
  grub_usb_controller_dev_register (&usb_controller);
  grub_boot_time ("XHCI driver registered");
//  grub_loader_register_preboot_hook (grub_xhci_fini_hw, grub_xhci_restore_hw,
//				     GRUB_LOADER_PREBOOT_HOOK_PRIO_DISK);
}

GRUB_MOD_FINI (xhci)
{
  grub_xhci_fini_hw (0);
  grub_usb_controller_dev_unregister (&usb_controller);
}
