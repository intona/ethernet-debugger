// SPDX-License-Identifier: GPL-3.0-or-later
#include "device.h"
#include "global.h"
#include "usb_control.h"
#include "utils.h"

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
static int mdio_write(struct device *dev, int ports, int reg, int val)
{
    if (reg < 0 || reg > 0x3F || val < 0 || val > 0xFFFF || ports < 0 || ports > 3)
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

static int mdio_read(struct device *dev, int ports, int reg, int val[2])
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

    if (reg >= 0x40u || ports < 0 || ports > 3)
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

int device_mdio_read(struct device *dev, int ports, int reg)
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

int device_mdio_write(struct device *dev, int ports, int reg, int val)
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

        // Read register 19 (interrupt status register), which resets it.
        // Important, since IRQs are level triggered.
        device_mdio_read_both(dev, 19, regs);

        // ACK interrupt (interrupt logic outside of PHY).
        uint32_t ack_cmd = 4 << 24;
        device_config_raw(dev, &ack_cmd, 1, NULL, NULL);

        // Read register 17 (copper status) and update known PHY status.
        if (device_mdio_read_both(dev, 17, regs) >= 0) {
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

    LOG(dev->global, "Device debug output: %.*s\n", (int)size, s);
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
        goto fail;
    }

    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(libusb_get_device(udev), &desc))
        goto fail;

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

        if (libusb_open(usb_dev_ref, &handle) != 0) {
            libusb_unref_device(usb_dev_ref);
            LOG(global, "Could not not find or access device '%s' with libusb.\n",
                devname);
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

            // A silly way to ruse the code that checks for PID/VID.
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

    char name[USB_DEVICE_NAME_LEN];
    usb_get_device_name(libusb_get_device(handle), name, sizeof(name));
    LOG(global, "Device %s opened.\n", name);

    return device_open_with_handle(global, handle);
}

bool device_inject_pkt(struct logfn logfn, struct device *dev, int ports,
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
