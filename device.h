// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef DEVICE_H_
#define DEVICE_H_

#include <pthread.h>

#include "usb_io.h"
#include "utils.h"

struct device;
struct notifier;

// Configuration commands often can affect either port A, B, or both. It's a bit
// mask, and not affecting any port is allowed too.
// Warning: raw values are part of the user interface.
#define DEV_PORT_A      0x1
#define DEV_PORT_B      0x2
#define DEV_PORT_ALL    (DEV_PORT_A | DEV_PORT_B)
#define DEV_PORT_NONE   0x0

// If this value is passed, force MDIO commands to always set the page 0. This
// is needed because we pretend there's a single address space, which doesn't
// actually exist.
// This makes reg==1 and reg==MDIO_PAGE_REG(0, 1) different. The former
// addresses register 1 on the current page, the latter sets the page register
// to 0 before accessing register 1.
#define REG_FORCE_PAGE (1 << 16)

// Address register on a specific page. This is translated to 2 MDIO commands.
#define MDIO_PAGE_REG(page, reg) (REG_FORCE_PAGE | ((page) << 6) | ((reg) & 0x3f))

// Size of inject command payload buffer in words (APP_ADDR_BITS).
#define DEV_INJECT_PKT_BUF_SIZE (1 << 5)

// Size of inject command packet buffer in bytes (ETH_ADDR_BITS).
#define DEV_INJECT_ETH_BUF_SIZE (1 << 14)

// Send a raw configuration packet, and wait for a reply. By definition, every
// command will result in an immediate reply (or it's a firmware/gateware bug).
// The definitions of all commands and their replies are located in
// cfg_interface.v.
// *out_data and *out_num are set. *out_data must be free()'d to avoid memory
// leaks. Returns status (>=0 ok, <0 error); on error, *out_data==*out_num=0.
// out_data/out_num can be NULL to discard the reply data.
int device_config_raw(struct device *dev, uint32_t *in_data, size_t in_num,
                      uint32_t **out_data, size_t *out_num);

// Read a MDIO register.
//  dev: target device
//  ports: DEV_PORT_* bit mask
//  reg: MDIO register (can be a MDIO_PAGE_REG value)
//  returns: >=0: register contents, <0: error code
// This command returns the register contents of the first selected port (i.e.
// if DEV_PORT_ALL was passed, only the value for DEV_PORT_A is returned). Use
// device_mdio_read_both() to read from two ports at once (nearly-atomically).
int device_mdio_read(struct device *dev, unsigned ports, int reg);

// Read a MDIO register from both ports. The reads are driven at the same MDIO
// clock cycle, so the access happens mostly at the same time. Returns the
// status only (similar to device_mdio_write()), out_val[x] are set to the
// result values (or 0 on error).
//  dev: target device
//  reg: MDIO register (can be a MDIO_PAGE_REG value)
//  out_val: out_val[0] is set to port A, out_val[1] to port B
//  returns: ==0: success, <0: error code
int device_mdio_read_both(struct device *dev, int reg, int out_val[2]);

// Write a MDIO register.
//  dev: target device
//  ports: DEV_PORT_* bit mask
//  reg: MDIO register (can be a MDIO_PAGE_REG value)
//  val: 16 bit value to write
//  returns: ==0: success, <0: error code
int device_mdio_write(struct device *dev, unsigned ports, int reg, int val);

// Send packet injector command. See cfg_interface.v.
bool device_inject_pkt(struct logfn logfn, struct device *dev, unsigned ports,
                       int repeat, int gap, const void *data, size_t size);

// Get exclusive access to running configuration commands within the current
// thread. This roughly works like a recursive pthread_mutex_lock().
// Every such call must be matched with device_cfg_unlock().
void device_cfg_lock(struct device *dev);

// Undo previous device_cfg_unlock() call. Must be done on the same thread.
void device_cfg_unlock(struct device *dev);

struct phy_status {
    bool link;
    int speed; // 10/100/1000, 0 if not established
};

// This returns the last known PHY status. It does not actually communicate with
// the device, instead it is updated in the background using interrupts (using
// device.phy_update to signal potential changes).
// All of *st is written to (all-0 if port isn't DEV_PORT_A or DEV_PORT_B).
void device_get_phy_status(struct device *dev, int port, struct phy_status *st);

struct device {
    struct global *global;
    struct libusb_device_handle *dev;

    // Triggered on certain PHY related interrupts.
    struct notifier *phy_update;

    // Triggered on physical disconnection (or similar fatal errors).
    struct notifier *on_disconnect;

    // Non-NULL if this is currently dumping packets.
    // Access from main thread only.
    struct grabber *grabber;

    // --- Internal to device.c.
    struct usb_ep cfg_in, cfg_out, debug_in;
    pthread_mutex_t lock;
    pthread_cond_t cfg_wait, irq_wait;
    int fw_version;
    // --- Protected by mutex.
    bool cfg_expect_pkt;            // something sent a packet; waiting for reply
    bool cfg_send_err;              // sending the packet actually errored
    uint32_t *cfg_pkt;              // received config EP packet
    size_t cfg_pkt_num;             // received 32 bit words
    int cfg_locked;                 // a thread has exclusive access
    pthread_t cfg_locked_by;
    struct phy_status phys[2];
    pthread_t irq_thread;
    bool irq_thread_valid;
    bool irq_pending;               // IRQ packets were received
    bool shutdown;
};

// Find and open the given device. If devname==NULL or devname=="", find the
// first device that could be claimed. Returns NULL on failure.
// Free the device with device_close().
struct device *device_open(struct global *global, const char *devname);

// Wrap the given raw device handle. This must have been referenced with
// usb_thread_device_ref, and this function takes ownership of it (even on
// failure). Returns NULL on failure.
struct device *device_open_with_handle(struct global *global,
                                       struct libusb_device_handle *dev);

// dev becomes invalid. No-OP if dev==NULL.
// Must be called on main thread; everything must have been stopped.
void device_close(struct device *dev);

#endif
