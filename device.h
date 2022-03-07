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

// DEV_PORT_* value from port index. The index must be 0 or 1.
#define DEV_PORT_FROM_INDEX(index) (1u << (index))

// Port names by DEV_PORT_* values.
extern const char *const port_names[4];

// If this value is passed, force MDIO commands to always set the page 0. This
// is needed because we pretend there's a single address space, which doesn't
// actually exist.
// This makes reg==1 and reg==MDIO_PAGE_REG(0, 1) different. The former
// addresses register 1 on the current page, the latter sets the page register
// to 0 before accessing register 1.
#define REG_FORCE_PAGE (1 << 16)

// Address register on a specific page. This is translated to 2 MDIO commands.
#define MDIO_PAGE_REG(page, reg) (REG_FORCE_PAGE | ((page) << 6) | ((reg) & 0x3f))

// Size of inject command packet buffer in bytes (PKT_ADDR_BITS).
#define DEV_INJECT_ETH_BUF_SIZE (1 << 14)

// Maximum size of packets that can be inject (non-raw, without preamble/FCS).
#define DEV_INJECT_MAX_PKT_SIZE (DEV_INJECT_ETH_BUF_SIZE - 8 - 4)

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

// All fields have mostly reasonable defaults at 0 init.
struct device_inject_params {
    uint32_t num_packets;   // number of packets to inject (UINT32_MAX for
                            // infinite; 0 for disable sending)
    bool raw;               // if true, don't add preamble
    bool enable_corrupt;    // if true, use corrupt_at
    const void *data;       // pointer to packet data to send
    size_t data_size;       // number of bytes valid in *data
    uint32_t append_random; // number of pseudo-random bytes to append after data
    uint32_t append_zero;   // number of 0 bytes to append after random bytes
    uint32_t gap;           // 0 uses default
    uint32_t corrupt_at;    // make PHY emit invalid ethernet symbol here
                            // ignored if enable_corrupt==false
};

// Send packet injector command.
//  logfn: for error messages
//  dev: target device
//  ports: DEV_PORT_* bit mask
//  params: ...
//  returns: ==0: success, <0: error code
int device_inject_pkt(struct logfn logfn, struct device *dev, unsigned ports,
                      const struct device_inject_params *params);

enum device_disrupt_mode {
    DEVICE_DISRUPT_BIT_FLIP,    // invert a pseudo-random bit
    DEVICE_DISRUPT_BIT_ERR,     // make PHY emit invalid ethernet symbol
    DEVICE_DISRUPT_DROP,        // drop the entire packet
};

// All fields have mostly reasonable defaults at 0 init.
struct device_disrupt_params {
    uint32_t num_packets;   // number of packets to affect
                            // (UINT32_MAX for infinite; 0 for disable all)
    enum device_disrupt_mode mode; // how to do it
    uint32_t skip;          // number of packets to skip each time
                            // (1 = corrupt every 2nd packet)
    uint32_t offset;        // byte offset to corrupt (0 = 1st byte of preamble)
};

// Send packet disrupt command.
//  logfn: for error messages
//  dev: target device
//  ports: DEV_PORT_* bit mask
//  params: ...
//  returns: ==0: success, <0: error code
int device_disrupt_pkt(struct logfn logfn, struct device *dev, unsigned ports,
                       const struct device_disrupt_params *params);

// Various per-port state, whatever I happened to need.
struct device_port_state {
    uint32_t inject_active;     // # packets still to inject (UINT32_MAX = inf)
    uint32_t inject_count;      // # packets injected (mod 2^32)
    uint32_t inject_dropped;    // # packets dropped because injection was active
    uint32_t disrupt_active;    // # packets still to disrupt (UINT32_MAX = inf)
    uint32_t disrupt_affected;  // # packets that got disrupted (mod 2^32)
};

// Read some packet disruptor state.
//  logfn: for error messages
//  dev: target device
//  port: DEV_PORT_A or DEV_PORT_B (not a bit mask)
//  state: overwritten with results on success
//  returns: ==0: success, <0: error code
int device_get_port_state(struct logfn logfn, struct device *dev, unsigned port,
                          struct device_port_state *state);

enum {
    // Speed mode (see code)
    DEVICE_SETTING_SPEED_MODE       = 1,
    // Autospeed PHY wait time in ms
    DEVICE_SETTING_SPEED_PHY_WAIT   = 2,
};

// Read a setting that is persistently stored on the device.
//  logfn: for error messages
//  dev: target device
//  id: settings ID, one of DEVICE_SETTING_*
//  out_val: overwritten with setting value (or 0 on failure)
//  returns: ==0: success, <0: error code
int device_setting_read(struct logfn logfn, struct device *dev, uint32_t id,
                        uint32_t *out_val);

// Write a setting that is persistently stored on the device. If applicable, the
// device immediately uses the new value.
//  logfn: for error messages
//  dev: target device
//  id: settings ID, one of DEVICE_SETTING_*
//  val: new value
//  returns: ==0: success, <0: error code
int device_setting_write(struct logfn logfn, struct device *dev, uint32_t id,
                        uint32_t val);

// Get exclusive access to running configuration commands within the current
// thread. This roughly works like a recursive pthread_mutex_lock().
// Every such call must be matched with device_cfg_unlock().
void device_cfg_lock(struct device *dev);

// Undo previous device_cfg_unlock() call. Must be done on the same thread.
void device_cfg_unlock(struct device *dev);

struct phy_status {
    bool link;
    int speed; // 10/100/1000, 0 if not established
    int master;
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

void print_fw_update_instructions(struct logfn logfn, struct device *dev);

#endif
