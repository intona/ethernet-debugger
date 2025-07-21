// SPDX-License-Identifier: GPL-3.0-or-later
#include "crc32.h"
#include "device.h"
#include "global.h"
#include "usb_control.h"
#include "utils.h"

const char *const port_names[4] = {"none", "A", "B", "AB"};

// Send/receive maximum size in 32 bit units.
#define CFG_BUF_WORDS 128

// Note: internals still need to acquire dev->lock outside of this for fields
//       which are used by other threads (e.g. libusb).
void device_cfg_lock(struct device *dev)
{
    pthread_mutex_lock(&dev->lock);
    while (dev->cfg_locked && !pthread_equal(pthread_self(), dev->cfg_locked_by))
        pthread_cond_wait(&dev->cfg_wait, &dev->lock);
    dev->cfg_locked += 1;
    dev->cfg_locked_by = pthread_self();
    pthread_mutex_unlock(&dev->lock);
}

void device_cfg_unlock(struct device *dev)
{
    pthread_mutex_lock(&dev->lock);
    assert(dev->cfg_locked > 0);
    assert(pthread_equal(pthread_self(), dev->cfg_locked_by));
    dev->cfg_locked -= 1;
    pthread_cond_broadcast(&dev->cfg_wait);
    pthread_mutex_unlock(&dev->lock);
}

int device_config_raw(struct device *dev, uint32_t *in_data, size_t in_num,
                      uint32_t **out_data, size_t *out_num)
{
    int res = -1;

    if (out_data)
        *out_data = NULL;
    if (out_num)
        *out_num = 0;

    device_cfg_lock(dev);

    pthread_mutex_lock(&dev->lock);
    assert(!dev->cfg_pkt && !dev->cfg_pkt_num && !dev->cfg_expect_pkt);
    dev->cfg_expect_pkt = true;
    pthread_mutex_unlock(&dev->lock);

    // NB: emulating pseudo-synchronous access is probably still less trouble
    //     than mixing libusb synchronous and asynchronous APIs. Maybe.
    int r = usb_ep_out_submit(&dev->cfg_out, in_data, in_num * 4, 1000);

    pthread_mutex_lock(&dev->lock);
    if (!r)
        goto done;

    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += 1;

    while (!dev->cfg_pkt && !dev->cfg_send_err) {
        if (pthread_cond_timedwait(&dev->cfg_wait, &dev->lock, &t))
            goto done; // timed out
    }

    if (dev->cfg_send_err)
        goto done;

    res = 0;
    if (out_data) {
        *out_data = dev->cfg_pkt;
    } else {
        free(dev->cfg_pkt);
    }
    if (out_num)
        *out_num = dev->cfg_pkt_num;
    dev->cfg_pkt = NULL;
    dev->cfg_pkt_num = 0;

done:
    dev->cfg_expect_pkt = false;
    dev->cfg_send_err = false;
    pthread_mutex_unlock(&dev->lock);
    device_cfg_unlock(dev);
    return res;
}

// non-paged
static int mdio_write(struct device *dev, unsigned ports, int reg, int val)
{
    if (reg < 0 || reg > 0x3F || val < 0 || val > 0xFFFF || ports > 3)
        return -1;

    uint32_t cmd = (ports << (24 + 6)) |        // PHY select
                   (0 << (24 + 5)) |            // R bit
                   (1 << 24) |                  // command: mdio r/w
                   (reg << 16) |                // address
                   val;                         // value
    uint32_t *rep;
    size_t rep_num;
    int r = device_config_raw(dev, &cmd, 1, &rep, &rep_num);
    if (r < 0)
        return r;

    free(rep);
    return 0;
}

static int mdio_read(struct device *dev, unsigned ports, int reg, int val[2])
{
    int r = -1;
    bool page_set = false;
    uint32_t *rep = NULL;
    size_t rep_num = 0;
    device_cfg_lock(dev);

    val[0] = val[1] = 0;

    if (reg & REG_FORCE_PAGE) {
        reg &= ~(unsigned int)REG_FORCE_PAGE;
        r = mdio_write(dev, ports, 22, reg >> 6);
        if (r < 0)
            goto done;
        page_set = true;
        reg &= 0x3Fu;
    }

    if (reg >= 0x40u || ports > 3)
        goto done;

    uint32_t cmd = (ports << (24 + 6)) |        // PHY select
                   (1 << (24 + 5)) |            // R bit
                   (1 << 24) |                  // command: mdio r/w
                   ((reg & 0x3F) << 16);        // address

    r = device_config_raw(dev, &cmd, 1, &rep, &rep_num);
    if (r < 0)
        goto done;

    if (rep_num != 2)
        goto done;

    r = 0;
    val[0] = rep[1] & 0xFFFF;
    val[1] = rep[1] >> 16;

done:
    if (page_set)
        mdio_write(dev, ports, 22, 0);
    free(rep);
    device_cfg_unlock(dev);
    return r;
}

int device_mdio_read(struct device *dev, unsigned ports, int reg)
{
    int val[2];
    int r = mdio_read(dev, ports, reg, val);
    if (r < 0)
        return r;
    if (ports & DEV_PORT_A)
        return val[0];
    if (ports & DEV_PORT_B)
        return val[1];
    return 0;
}

int device_mdio_read_both(struct device *dev, int reg, int out_val[2])
{
    return mdio_read(dev, DEV_PORT_ALL, reg, out_val);
}

int device_mdio_write(struct device *dev, unsigned ports, int reg, int val)
{
    int r = -1;
    bool page_set = false;
    device_cfg_lock(dev);

    if (reg & REG_FORCE_PAGE) {
        reg &= ~(unsigned int)REG_FORCE_PAGE;
        r = mdio_write(dev, ports, 22, reg >> 6);
        if (r < 0)
            goto done;
        page_set = true;
        reg &= 0x3Fu;
    }

    if (reg >= 0x40u)
        goto done;

    r = mdio_write(dev, ports, reg & 0x3F, val);

done:
    if (page_set)
        mdio_write(dev, ports, 22, 0);
    device_cfg_unlock(dev);
    return r;
}

int device_time_sync(struct device *dev)
{
    if (dev->fw_version < 0x111)
        return -1;

    // Repeat the test a number of times to fight jitter.
    int num_runs = 10;
    int64_t min_delay = INT64_MAX;
    uint64_t res_host_time = 0;
    uint64_t res_device_time = 0;
    bool ok = true;

    // Prevent that other slow cfg commands are executed (such as MDIO updates).
    device_cfg_lock(dev);

    for (int run = 0; run < num_runs; run++) {
        uint64_t host_start = get_time_us() * 1000;
        uint32_t cmd = 10 << 24;
        uint32_t *recv;
        size_t recv_sz;
        int r = device_config_raw(dev, &cmd, 1, &recv, &recv_sz);
        if (r < 0 || recv_sz < 2) {
            LOG(dev->global, "Time sync HW failure.\n");
            ok = false;
            break;
        }
        uint64_t host_end = get_time_us() * 1000;
        uint64_t delay = host_end - host_start;
        uint64_t device_time = (((uint64_t)recv[0]) << 32) | recv[1];
        // Assume that both directions take around the same time (like NTP
        // does). Try to determine the host time when the device sampled its
        // own time.
        // This may or may not be a good idea.
        uint64_t delay_2 = delay / 2;
        uint64_t host_time = host_start + delay_2;
        int64_t diff = host_time - device_time;

        HINT(dev->global,
             "HW time: 0x%"PRIx64" ns, delay=%"PRId64" ns, diff=%"PRId64" ns\n",
             device_time, delay_2, diff);

        if (delay_2 <= min_delay) {
            min_delay = delay_2;
            res_host_time = host_time;
            res_device_time = device_time;
        }
    }

    pthread_mutex_lock(&dev->lock);
    if (ok) {
        HINT(dev->global, "Minimum delay: %"PRIu64" ns\n", min_delay);
        dev->clock_info = (struct device_clock_info){
            .valid = true,
            .host_time = res_host_time,
            .device_time = res_device_time,
            .delay = min_delay,
        };
    } else {
        dev->clock_info.valid = false;
    }
    pthread_mutex_unlock(&dev->lock);

    device_cfg_unlock(dev);

    return ok ? 0 : -1;
}

void device_get_clock_info(struct device *dev, struct device_clock_info *info)
{
    pthread_mutex_lock(&dev->lock);
    *info = dev->clock_info;
    pthread_mutex_unlock(&dev->lock);
}

// Responding to IRQs is done on a separate thread to avoid blocking, and to
// avoid terrible libusb callback reentrancy issues.
static void *irq_thread(void *p)
{
    struct device *dev = p;

    while (1) {
        while (1) {
            pthread_mutex_lock(&dev->lock);
            if (dev->shutdown) {
                pthread_mutex_unlock(&dev->lock);
                goto done;
            }
            if (dev->irq_pending) {
                dev->irq_pending = false;
                pthread_mutex_unlock(&dev->lock);
                break;
            }
            pthread_cond_wait(&dev->irq_wait, &dev->lock);
            pthread_mutex_unlock(&dev->lock);
        }

        int regs[2];

        if (dev->fw_version < 0x106) {
            // Read register 19 (interrupt status register), which resets it.
            // Important, since IRQs are level triggered.
            device_mdio_read_both(dev, MDIO_PAGE_REG(0, 19), regs);

            // ACK interrupt (interrupt logic outside of PHY).
            uint32_t ack_cmd = 4 << 24;
            device_config_raw(dev, &ack_cmd, 1, NULL, NULL);
        }

        // Read register 17 (copper status) and update known PHY status.
        if (device_mdio_read_both(dev, MDIO_PAGE_REG(0, 17), regs) >= 0) {
            int reg10[2];
            if (device_mdio_read_both(dev, MDIO_PAGE_REG(0, 10), reg10) < 0)
                reg10[0] = reg10[1] = -1;

            pthread_mutex_lock(&dev->lock);

            for (size_t phy = 0; phy < 2; phy++) {
                struct phy_status *st = &dev->phys[phy];
                st->link = regs[phy] & (1 << 3);        // global link status
                st->speed = 0;
                if (regs[phy] & (1 << 11)) {            // speed/duplex resolved
                    switch (regs[phy] >> 14) {          // speed
                    case 0: st->speed = 10;   break;
                    case 1: st->speed = 100;  break;
                    case 2: st->speed = 1000; break;
                    }
                }
                st->duplex = regs[phy] & (1 << 13);
                st->master = -1;
                if (st->speed == 1000 && reg10[phy] >= 0)
                    st->master = reg10[phy] & (1 << 14);
            }

            pthread_mutex_unlock(&dev->lock);

            notifier_trigger(dev->phy_update);
        }
    }

done:
    return NULL;
}

static void cfg_on_receive(struct usb_ep *ep, void *data, size_t size)
{
    struct device *dev = ep->user_data;

    pthread_mutex_lock(&dev->lock);

    if (size % 4) {
        size = size & ~(size_t)3;
        LOG(dev->global, "error: uneven config packet size: %zd\n", size);
    }

    if (size >= 4) {
        uint32_t header;
        memcpy(&header, data, 4);
        if ((header & 0x1F000000) == 0x1F000000 && size == 4) {
            dev->irq_pending = true;
            pthread_cond_broadcast(&dev->irq_wait);
        } else if (dev->cfg_expect_pkt && !dev->cfg_send_err) {
            free(dev->cfg_pkt);
            dev->cfg_pkt = xmemdup(data, size);
            dev->cfg_pkt_num = size / 4;
            pthread_cond_broadcast(&dev->cfg_wait);
        } else {
            LOG(dev->global, "error: stray config packet:\n");
            log_hexdump(dev->global->log, data, size);
        }
    }

    pthread_mutex_unlock(&dev->lock);
}

static void cfg_on_sent(struct usb_ep *ep, bool success)
{
    struct device *dev = ep->user_data;
    pthread_mutex_lock(&dev->lock);
    if (!success && dev->cfg_expect_pkt) {
        dev->cfg_send_err = true;
        pthread_cond_broadcast(&dev->cfg_wait);
    }
    pthread_mutex_unlock(&dev->lock);
}

void device_get_phy_status(struct device *dev, int port, struct phy_status *st)
{
    pthread_mutex_lock(&dev->lock);
    if (port == DEV_PORT_A) {
        *st = dev->phys[0];
    } else if (port == DEV_PORT_B) {
        *st = dev->phys[1];
    } else {
        *st = (struct phy_status){0};
    }
    pthread_mutex_unlock(&dev->lock);
}

static void debug_on_receive(struct usb_ep *ep, void *data, size_t size)
{
    struct device *dev = ep->user_data;

    char *s = data;

    if (size && s[size - 1] == '\n')
        size -= 1;

    HINT(dev->global, "Device debug output: %.*s\n", (int)size, s);
}

static void cfg_error(struct usb_ep *ep, enum libusb_error error)
{
    struct device *dev = ep->user_data;

    if (error == LIBUSB_ERROR_NO_DEVICE)
        notifier_trigger(dev->on_disconnect);
}

void device_close(struct device *dev)
{
    if (dev) {
        pthread_mutex_lock(&dev->lock);
        dev->shutdown = true;
        pthread_cond_broadcast(&dev->cfg_wait);
        pthread_cond_broadcast(&dev->irq_wait);
        pthread_mutex_unlock(&dev->lock);

        if (dev->irq_thread_valid)
            pthread_join(dev->irq_thread, NULL);

        assert(!dev->cfg_locked); // must have been stopped
        assert(!dev->cfg_pkt);

        usb_ep_remove(&dev->cfg_in);
        usb_ep_remove(&dev->cfg_out);
        usb_ep_remove(&dev->debug_in);
        usb_thread_device_unref(dev->global->usb_thr, dev->dev);
        notifier_free(dev->phy_update);
        notifier_free(dev->on_disconnect);
        pthread_cond_destroy(&dev->cfg_wait);
        pthread_cond_destroy(&dev->irq_wait);
        pthread_mutex_destroy(&dev->lock);
        free(dev);
    }
}

#define IN_USE_MSG \
    "This error can happen if another process has the device still opened.\n"

struct device *device_open_with_handle(struct global *global,
                                       struct libusb_device_handle *udev)
{
    int r;

    if (!udev)
        return NULL;

    struct device *dev = XALLOC_PTRTYPE(dev);
    dev->global = global;
    dev->dev = udev;
    dev->phy_update = notifier_xalloc();
    dev->on_disconnect = notifier_xalloc();

    pthread_mutex_init(&dev->lock, NULL);
    pthread_cond_init(&dev->cfg_wait, NULL);
    pthread_cond_init(&dev->irq_wait, NULL);

    if (libusb_claim_interface(udev, 0)) {
        LOG(global, "Could not claim USB interface.\n");
        LOG(global, IN_USE_MSG);
        goto fail;
    }

    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(libusb_get_device(udev), &desc))
        goto fail;

    dev->fw_version = desc.bcdDevice;

    char name[USB_DEVICE_NAME_LEN];
    usb_get_device_name(libusb_get_device(udev), name, sizeof(name));
    char serial[USB_DEVICE_SERIAL_LEN];
    usb_get_device_serial(libusb_get_device(udev), serial, sizeof(serial));
    LOG(global, "Device %s / %s (firmware %d.%02d) opened.\n", serial, name,
        dev->fw_version >> 8, dev->fw_version & 0xFF);

    uint8_t major_dev_ver = desc.bcdDevice >> 8;
    if (major_dev_ver > 1) {
        LOG(global, "Unsupported device: device version is %d, but this software "
                    "supports only version 1. Outdated software?\n", major_dev_ver);
        goto fail;
    }

    dev->cfg_in = (struct usb_ep){
        .dev = udev,
        .ep = 0x85,
        .on_receive = cfg_on_receive,
        // Somewhat arbitrary: use this endpoint to track device disconnection.
        .on_error = cfg_error,
        .user_data = dev,
    };
    if (!usb_ep_in_add(global->usb_thr, &dev->cfg_in, 2, 16 * 1024))
        goto fail;

    dev->cfg_out = (struct usb_ep){
        .dev = udev,
        .ep = 0x04,
        .on_sent = cfg_on_sent,
        .user_data = dev,
    };
    if (!usb_ep_out_add(global->usb_thr, &dev->cfg_out))
        goto fail;

    dev->debug_in = (struct usb_ep){
        .dev = udev,
        .ep = 0x83,
        .on_receive = debug_on_receive,
        .user_data = dev,
    };
    if (!usb_ep_in_add(global->usb_thr, &dev->debug_in, 6, 16 * 1024))
        goto fail;

    device_time_sync(dev);

    if (dev->fw_version < 0x106) {
        bool mdio_init_ok = true;

        // Configure the interrupt pin
        r = device_mdio_write(dev, DEV_PORT_ALL, MDIO_PAGE_REG(3, 18),
                            (2 << 12) |   // pulse stretch
                            (1 << 8) |    // blink rate
                            (1 << 7) |    // int enable
                            (1 << 2) |    // pulse
                            (1 << 0));    // pulse
        mdio_init_ok &= r >= 0;

        // Interrupt enable
        r = device_mdio_write(dev, DEV_PORT_ALL, 18,
                            (1 << 10) |   // link status changed interrupt
                            (1 << 11) |   // auto-negotiation completed interrupt
                            (1 << 14) |   // speed changed interrupt
                            (1 << 15));   // auto-negotiation error interrupt
        mdio_init_ok &= r >= 0;

        // Can happen if you try to reopen the device after aborted FW update.
        if (!mdio_init_ok)
            LOG(global, "Warning: could not set mdio registers.\n");
    }

    dev->irq_pending = true;
    dev->irq_thread_valid = true;
    if (pthread_create(&dev->irq_thread, NULL, irq_thread, dev)) {
        dev->irq_thread_valid = false;
        goto fail;
    }

    return dev;

fail:
    device_close(dev);
    return NULL;
}

struct device *device_open(struct global *global, const char *devname)
{
    libusb_context *usb_ctx = usb_thread_libusb_context(global->usb_thr);
    libusb_device_handle *handle = NULL;

    if (devname && devname[0]) {
        libusb_device *usb_dev_ref = usb_find_device(usb_ctx, devname);
        if (!usb_dev_ref) {
            LOG(global, "Device not found: '%s'\n", devname);
            return NULL;
        }

        int err = libusb_open(usb_dev_ref, &handle);
        if (err != 0) {
            libusb_unref_device(usb_dev_ref);
            LOG(global, "Could not not find or access device '%s' (libusb error: %s)\n",
                devname, libusb_error_name(err));
            if (err == LIBUSB_ERROR_ACCESS)
                LOG(global, IN_USE_MSG);
            return NULL;
        }

        assert(handle);
    } else {
        // Find the first device with our VID/PID and which we can "claim".
        libusb_device **list = NULL;
        libusb_context *usb_ctx = usb_thread_libusb_context(global->usb_thr);
        libusb_get_device_list(usb_ctx, &list);

        for (size_t n = 0; list && list[n]; n++) {
            libusb_device *dev = list[n];

            // A silly way to reuse the code that checks for PID/VID.
            if (!usb_get_device_name(dev, &(char){0}, 1))
                continue;

            if (libusb_open(dev, &handle))
                continue;
            assert(handle);

            if (!libusb_claim_interface(handle, 0))
                break;

            libusb_close(handle);
            handle = NULL;
        }

        libusb_free_device_list(list, 1);

        if (!handle) {
            LOG(global, "No devices found.\n");
            return NULL;
        }
    }

    usb_thread_device_ref(global->usb_thr, handle);

    return device_open_with_handle(global, handle);
}

// read count registers at reg0...reg0+count-1 into vals[0]...vals[count-1]
static bool regs_read(struct logfn logfn, struct device *dev, uint32_t reg0,
                      uint32_t *vals, uint32_t count)
{
    while (count) {
        size_t num = MIN(count, CFG_BUF_WORDS - 2);
        uint32_t cmd[2] = {(8 << 24) | (reg0 & 0xFFFFFF), num};

        uint32_t *rep;
        size_t rep_num;
        int r = device_config_raw(dev, cmd, 2, &rep, &rep_num);
        if (r < 0) {
            logline(logfn, "error: failed to send request to device\n");
            return false;
        }
        if (rep_num < 2 || rep_num - 2 != num || rep[1]) {
            logline(logfn, "error: processing reg read command on device\n");
            free(rep);
            return false;
        }

        for (size_t n = 0; n < num; n++)
            vals[n] = rep[2 + n];

        vals += num;
        count -= num;
        reg0 += num;

        free(rep);
    }
    return true;
}

// write count registers at reg0...reg0+count-1 from vals[0]...vals[count-1]
static bool regs_write(struct logfn logfn, struct device *dev, uint32_t reg0,
                       uint32_t *vals, uint32_t count)
{
    while (count) {
        size_t num = MIN(count, CFG_BUF_WORDS - 1);
        uint32_t cmd[CFG_BUF_WORDS];
        cmd[0] = ((0x40 | 8) << 24) | (reg0 & 0xFFFFFF);
        for (size_t n = 0; n < num; n++)
            cmd[n + 1] = vals[n];

        uint32_t *rep;
        size_t rep_num;
        int r = device_config_raw(dev, cmd, 1 + num, &rep, &rep_num);
        if (r < 0) {
            logline(logfn, "error: failed to send request to device\n");
            return false;
        }
        if (rep_num != 2 || rep[1]) {
            logline(logfn, "error: processing reg write command on device\n");
            free(rep);
            return false;
        }

        vals += num;
        count -= num;
        reg0 += num;

        free(rep);
    }
    return true;
}

// pre 1.06 firmware
#define DEV_INJECT_PKT_BUF_SIZE (1 << 5)
static bool device_inject_pkt_old(struct logfn logfn, struct device *dev, unsigned ports,
                                  int repeat, int gap, const void *data, size_t size)
{
    device_cfg_lock(dev);

    repeat = CLAMP(repeat, 0, 15);
    gap = CLAMP(gap, 0, 0xFFFF);

    bool success = true;
    bool resume = false;

    do {
        uint32_t cmd[1 + DEV_INJECT_PKT_BUF_SIZE];

        size_t payload = size < DEV_INJECT_PKT_BUF_SIZE * 4 ?
                         size : DEV_INJECT_PKT_BUF_SIZE * 4;
        size_t payload_words = (payload + 3) / 4;

        // In theory not kosher, I think (at least with non-mod 4 sizes). Who cares.
        if (payload)
            memcpy(cmd + 1, data, payload);
        size -= payload;
        data = (char *)data + payload;

        int discard = payload_words * 4 - payload;
        bool last = !size;

        cmd[0] = ((ports & 3u) << (24 + 6)) | (3 << 24) | (last << (16 + 7)) |
                 (resume << (16 + 6)) | (repeat << (16 + 2)) | (discard << 16) |
                 gap;

        resume = true;

        int r = device_config_raw(dev, cmd, 1 + payload_words, NULL, NULL);
        if (r < 0) {
            logline(logfn, "error: failed to send command\n");
            success = false;
            break;
        }
    } while (size);

    device_cfg_unlock(dev);
    return success;
}

static void compute_sizes(const struct device_inject_params *params,
                          size_t *out_size, size_t *out_extra_zeros)
{
    size_t extra_zeros = 0;
    size_t size = params->data_size;

    size += params->append_random;
    size += params->append_zero;

    if (!params->raw) {
        size += 4; // FCS
        if (size < 64 && !params->nopad) {
            extra_zeros = 64 - size;
            size += extra_zeros;
        }
        size += 8; // preamble, SFD
    }

    *out_size = size;
    *out_extra_zeros = extra_zeros;
}

size_t device_inject_get_raw_length(const struct device_inject_params *params)
{
    size_t size, extra_zeros;
    compute_sizes(params, &size, &extra_zeros);
    return size;
}

// Send packet injector command.
int device_inject_pkt(struct logfn logfn, struct device *dev, unsigned ports,
                      const struct device_inject_params *params)
{
    uint32_t gap = params->gap;
    if (!gap)
        gap = ETHERNET_MIN_GAP;

    static_assert(DEV_INJECT_ETH_BUF_SIZE < (1 << 30) / 4, "possibly overflows");
    if (params->data_size > DEV_INJECT_ETH_BUF_SIZE ||
        params->append_random > DEV_INJECT_ETH_BUF_SIZE ||
        params->append_zero > DEV_INJECT_ETH_BUF_SIZE)
    {
        // Probably a (well defined) integer overflow?
        logline(logfn, "error: packet too large\n");
        return -1;
    }

    if (dev->fw_version < 0x107 && params->loop_count) {
        logline(logfn, "error: firmware version too old\n");
        return -1;
    }

    size_t size, extra_zeros;
    compute_sizes(params, &size, &extra_zeros);

    if (size > DEV_INJECT_ETH_BUF_SIZE) {
        logline(logfn, "error: packet too large\n");
        return -1;
    }

    // Aligned to 32 bit, so we can pass it to regs_write().
    size_t full_size = (size + 3) & ~3u;
    uint8_t *data = calloc(1, full_size);
    size_t offset = 0;
    if (!data) {
        logline(logfn, "error: out of memory\n");
        return -1;
    }

    if (!params->raw) {
        memcpy(data + offset, "UUUUUUU\xD5", 8);
        offset += 8;
    }

    if (params->data_size) {
        memcpy(data + offset, params->data, params->data_size);
        offset += params->data_size;
    }

    for (size_t n = 0; n < params->append_random; n++)
        data[offset++] = rand() & 0xFF;

    offset += params->append_zero + extra_zeros;

    if (!params->raw) {
        uint32_t crc = crc32(~(uint32_t)0, data + 8, offset - 8);
        memcpy(data + offset, &crc, 4);
        offset += 4;
    }

    assert(offset == size);

    if (params->num_packets)
        log_hexdump(dev->global->loghint, data, size);

    if (dev->fw_version < 0x106) {
        // Partial emulation with old firmware.
        uint32_t repeat = params->num_packets;
        if (!repeat) {
            free(data);
            data = NULL;
            size = 0;
            repeat = 1;
        }
        if (repeat == UINT32_MAX) {
            repeat = 15;
        } else {
            repeat = MIN(repeat - 1, 14);
        }
        gap = MIN(gap, 0xFFFF);
        bool r = device_inject_pkt_old(logfn, dev, ports, repeat, gap, data, size);
        free(data);
        return r ? 0 : -1;
    }

    device_cfg_lock(dev);

    unsigned enable_ports = 0;

    for (size_t port = 0; port < 2; port++) {
        if (!(ports & (1 << port)))
            continue;

        uint32_t reg_base = (2 + port) << 20;

        // Request disable sending.
        regs_write(logfn, dev, reg_base + 0, &(uint32_t){0}, 1);

        // Wait until sending is done. This polls, but normally it stops quickly
        // enough that all the USB ping-pong takes longer. Also, it might be
        // nice to employ a timeout for frozen devices, but hopefully that
        // happens during device firmware development at most.
        while (1) {
            uint32_t reg;
            if (!regs_read(logfn, dev, reg_base + 32, &reg, 1))
                goto error;

            if (!reg)
                break;
        }

        // Apply new parameters.

        uint32_t repeat = params->num_packets;
        if (repeat != UINT32_MAX)
            repeat -= 1;

        uint32_t corrupt_at = params->corrupt_at;
        if (!params->enable_corrupt)
            corrupt_at = UINT32_MAX;

        uint32_t offset = 0;        // (always 0 for now)
        uint32_t regs[] = {
            0,                      // send_enabled (set later)
            offset,                 // packet_offset
            size,                   // packet_size
            repeat,                 // packet_repeat
            gap,                    // packet_gap
            corrupt_at,             // packet_err_offset
            offset + params->loop_offset,
            params->loop_count,
        };
        size_t reg_count = dev->fw_version >= 0x107 ? 8 : 6;

        if (!regs_write(logfn, dev, reg_base, regs, reg_count))
            goto error;

        // Upload packet data.
        uint32_t addr = reg_base + 0x100 + offset / 4;
        if (!regs_write(logfn, dev, addr, (uint32_t *)data, full_size / 4))
            goto error;

        // Send enable if wanted.
        if (params->num_packets)
            enable_ports |= 1 << port;
    }

    if (enable_ports) {
        // Special command to synchronously set send_enabled to 1 on all ports.
        if (!regs_write(logfn, dev, (1 << 20) | 1, &(uint32_t){enable_ports}, 1))
            goto error;
    }

    free(data);
    device_cfg_unlock(dev);
    return 0;

error:
    free(data);
    device_cfg_unlock(dev);
    return -1;
}

// pre 1.06 firmware
static int device_disrupt_pkt_old(struct logfn logfn, struct device *dev, unsigned ports,
                                  const struct device_disrupt_params *params)
{
    bool drop = params->mode == DEVICE_DISRUPT_DROP;
    int num = MIN(params->num_packets, 0xFF);
    int skip = MIN(params->skip, (1 << 4));
    int offset = MIN(params->offset, (1 << 12));

    uint32_t cmd = ((ports & 3u) << (24 + 6)) | (drop << (24 + 5)) | (2 << 24) |
                   (num << 16) | (skip << 12) | offset;

    int r = device_config_raw(dev, &cmd, 1, NULL, NULL);
    if (r < 0)
        logline(logfn, "error: failed to send command\n");
    return r;
}

// Send packet disrupt command.
int device_disrupt_pkt(struct logfn logfn, struct device *dev, unsigned ports,
                       const struct device_disrupt_params *params)
{
    if (dev->fw_version < 0x106)
        return device_disrupt_pkt_old(logfn, dev, ports, params);

    device_cfg_lock(dev);

    for (size_t port = 0; port < 2; port++) {
        if (!(ports & (1 << port)))
            continue;

        uint32_t reg_base = (4 + port) << 20;

        // Apply new parameters.

        uint32_t raw_mode = 0;
        switch (params->mode) {
        case DEVICE_DISRUPT_BIT_FLIP:   raw_mode = 0; break;
        case DEVICE_DISRUPT_DROP:       raw_mode = 1; break;
        case DEVICE_DISRUPT_BIT_ERR:    raw_mode = 2; break;
        }

        uint32_t regs[] = {
            0,                      // control (set later)
            params->num_packets,    // packet_num
            params->skip,           // packet_skip
            params->offset,         // packet_offset
            raw_mode,               // packet_drop
        };

        if (!regs_write(logfn, dev, reg_base, regs, ARRAY_LENGTH(regs)))
            goto error;
    }

    if (ports) {
        // Special command to synchronously set control to 1 on all ports.
        // This is actually not truly synchronous.
        if (!regs_write(logfn, dev, (1 << 20) | 2, &(uint32_t){ports & 3u}, 1))
            goto error;
    }

    device_cfg_unlock(dev);
    return 0;

error:
    device_cfg_unlock(dev);
    return -1;
}

int device_get_port_state(struct logfn logfn, struct device *dev, unsigned port,
                          struct device_port_state *state)
{
    *state = (struct device_port_state){0};

    if ((port != DEV_PORT_A && port != DEV_PORT_B) || dev->fw_version < 0x106)
        return -1;

    int portidx = port - 1;
    int ret = -1;
    device_cfg_lock(dev);

    uint32_t reg_base = (2 + portidx) << 20;
    uint32_t regs[4];
    if (!regs_read(logfn, dev, reg_base + 32, regs, 4))
        goto error;

    bool inj_active = regs[0];
    state->inject_active = inj_active ? (regs[2] | (regs[1] & 1)) : 0;
    state->inject_count = regs[1] / 2;
    state->inject_dropped = regs[3];

    reg_base = (4 + portidx) << 20;
    if (!regs_read(logfn, dev, reg_base + 32, regs, 2))
        goto error;

    state->disrupt_active = regs[1];
    state->disrupt_affected = regs[0];

    if (dev->fw_version >= 0x107) {
        bool new_fields = dev->fw_version >= 0x109;
        size_t num_regs = new_fields ? 4 : 3;
        reg_base = (6 + portidx) << 20;
        if (!regs_read(logfn, dev, reg_base + 1, regs, num_regs))
            goto error;

        state->packets = regs[0];
        state->packets_valid = true;
        state->sym_error_bytes = regs[2];
        state->sym_error_bytes_valid = true;

        if (new_fields) {
            state->crc_error_count = regs[1];
            state->crc_error_count_valid = true;
            state->reset_count = regs[3];
            state->reset_count_valid = true;
        }
    }

    ret = 0;
error:
    device_cfg_unlock(dev);
    return ret;
}

int device_setting_read(struct logfn logfn, struct device *dev, uint32_t id,
                        uint32_t *out_val)
{
    int r = -1;
    uint32_t *rep = NULL;
    size_t rep_num = 0;
    device_cfg_lock(dev);

    uint32_t cmd = (6 << 24) |                  // command: setting r/w
                   (id & 0xFFFFFF);             // setting ID

    r = device_config_raw(dev, &cmd, 1, &rep, &rep_num);
    if (r < 0)
        goto done;

    if (rep_num != 3 || rep[1])
        goto done;

    *out_val = rep[2];
    r = 0;

done:
    if (r < 0)
        *out_val = 0;
    free(rep);
    device_cfg_unlock(dev);
    return r;
}

int device_setting_write(struct logfn logfn, struct device *dev, uint32_t id,
                        uint32_t val)
{
    int r = -1;
    uint32_t *rep = NULL;
    size_t rep_num = 0;
    device_cfg_lock(dev);

    uint32_t cmd[2] = {(1 << 30) |                  // W bit
                       (6 << 24) |                  // command: setting r/w
                       (id & 0xFFFFFF),             // setting ID
                       val};

    r = device_config_raw(dev, cmd, 2, &rep, &rep_num);
    if (r >= 0)
        r = (rep_num == 3 && !rep[1]) ? 0 : -1;

    free(rep);
    device_cfg_unlock(dev);
    return r;
}

void print_fw_update_instructions(struct logfn logfn, struct device *dev)
{
    logline(logfn, "To update the firmware, follow the instructions here:\n  %s\n",
            "https://intona.eu/en/doc/ethernet-debugger/#IN3032UG:EthernetDebuggerUserGuide-FirmwareUpdate");
    logline(logfn, "Firmware images are available for download here:\n  %s\n",
            "https://intona.eu/en/products/ethernet-debugger#downloads");
    logline(logfn, "The firmware version on this device is: %d.%02d\n",
            dev->fw_version >> 8, dev->fw_version & 0xFF);
}
