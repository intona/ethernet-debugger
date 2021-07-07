// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "crc32.h"
#include "device.h"
#include "filters.h"
#include "fw_header.h"
#include "global.h"
#include "grabber.h"
#include "nose.h"
#include "usb_control.h"
#include "usb_io.h"
#include "utils.h"

// Wait this many seconds after a device reboot before trying to reopen.
#define USB_REBOOT_WAIT_SECS 4

// Test packets that are just "garbage". Physically no problem.
static const char testpkt1[8 + 64] = {
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xD5,
    0xAB, 0xCD, 0xEF, 0x12, 0x23, 0x43, 0x12, 0xEF,
    0x45, 0x54, 0x12, 0x55, 0x5D, 0x4F, 0xF8, 0xF9,
};
static const char testpkt2[8 + 64] = {
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xD5,
    0x5B, 0x4D, 0xFA, 0x5C, 0xD3, 0xE3, 0x18, 0x3F,
    0x4E, 0x74, 0x1E, 0x5A, 0xAD, 0x8F, 0xE8, 0xC3,
};

struct test_filter_ctx {
    bool encountered_ok;
    bool encountered_notok;
    struct {
        const void *expect_data;
        size_t expect_size;
    } phy[2];
};

static bool test_filter(struct grabber_filter *filt, struct grabber_packet *pkt)
{
    struct test_filter_ctx *ctx = filt->priv;
    int phy = pkt->iface->port;
    assert(phy == 0 || phy == 1);

    size_t expect_size = ctx->phy[phy].expect_size;
    const void *expect_data = ctx->phy[phy].expect_data;

    if (!expect_size)
        ctx->encountered_notok = true; // got packet but none expected

    if (expect_size) {
        if (ctx->encountered_ok) {
            ctx->encountered_notok = true; // not more than 1 packet expected
        } else if (expect_size != pkt->size ||
                   memcmp(expect_data, pkt->data, pkt->size) != 0)
        {
            ctx->encountered_notok = true;
        } else {
            ctx->encountered_ok = true;
        }
    }

    return true;
}

static void test_destroy(struct grabber_filter *filt)
{
}

static const struct grabber_filter_fns filter_test = {
    .filter = test_filter,
    .destroy = test_destroy,
};

// Like libusb_open_device_with_vid_pid(), but if device is a non-empty string,
// restrict the search for a device to this one (still check VID/PID).
// device_name should be as in device_open_opts.device_name.
static libusb_device_handle *open_device_with_vid_pid(libusb_context *ctx,
                                                      uint16_t vid, uint16_t pid,
                                                      char *device_name)
{
    if (device_name && device_name[0]) {
        libusb_device *dev = usb_find_device_any(ctx, device_name);
        if (!dev)
            return NULL;

        libusb_device_handle *res = NULL;

        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev, &desc))
            goto done;

        if (desc.idVendor != vid || desc.idProduct != pid)
            goto done;

        if (libusb_open(dev, &res) != 0)
            res = NULL;

    done:
        libusb_unref_device(dev);
        return res;
    } else {
        return libusb_open_device_with_vid_pid(ctx, vid, pid);
    }
}

static bool flash_serial(libusb_device_handle *usbdev, struct logfn log,
                         char *serial)
{
    struct fw_serial ser = { .magic = FW_SERIAL_MAGIC };
    snprintf(ser.serial, sizeof(ser.serial), "%s", serial);
    ser.crc = crc32(0, ((char *)&ser) + 8, sizeof(ser) - 8);

    uint8_t wdata[64] = {0};
    static_assert(sizeof(ser) <= sizeof(wdata), "");
    memcpy(wdata, &ser, sizeof(ser));

    uint8_t data[64];
    if (!usb_read_otp(usbdev, log, FW_FLASH_ADDRESS_SERIAL, data, sizeof(data)))
        return false;

    // Exit instead of trying to reprogram the same serial.
    if (memcmp(data, wdata, sizeof(data)) == 0)
        return true;

    for (size_t n = 0; n < sizeof(data); n++) {
        if (data[n] != 0xFF) {
            logline(log, "Serial area was written before:\n");
            log_hexdump(log, data, sizeof(data));
            return false;
        }
    }

    if (!usb_write_otp(usbdev, log, FW_FLASH_ADDRESS_SERIAL, wdata, sizeof(wdata)))
        return false;

    if (!usb_read_otp(usbdev, log, FW_FLASH_ADDRESS_SERIAL, data, sizeof(data)))
        return false;

    if (memcmp(data, wdata, sizeof(data)) != 0) {
        logline(log, "Serial data could not be written correctly.\n");
        return false;
    }

    // Lock the serial number region.
    uint32_t lock_bits = ~(uint32_t)0u;
    for (uint32_t b = 0; b < sizeof(wdata); b++)
        lock_bits &= ~(uint32_t)(1u << ((FW_FLASH_ADDRESS_SERIAL + b) / 32));
    if (!usb_write_otp(usbdev, log, 0x10, &lock_bits, 4))
        return false;

    // Some redundant tests to make sure it works.
    memset(data, 0, sizeof(data));

    // Don't spook anyone with the expected error.
    struct logfn null = {0};
    if (usb_write_otp(usbdev, null, FW_FLASH_ADDRESS_SERIAL, data, sizeof(data))) {
        logline(log, "Could write to locked serial number OTP area?\n");
        return false;
    }

    if (!usb_read_otp(usbdev, log, FW_FLASH_ADDRESS_SERIAL, data, sizeof(data)))
        return false;

    if (memcmp(data, wdata, sizeof(data)) != 0) {
        logline(log, "Serial data could not be written correctly (2).\n");
        return false;
    }

    return true;
}

static bool eeprom_access(struct device *dev, bool w, uint16_t addr,
                          void *buf, size_t sz)
{
    if (addr >= (1 << 12) || sz >= (1 << 12))
        return false;
    uint32_t cmd[32] = {(9 << 24) | addr | (sz << 12)};
    size_t in = 1;
    size_t out = 2;
    assert(sz <= sizeof(cmd) - 8);
    size_t words = (sz + 3) / 4;
    if (w) {
        memcpy(&cmd[1], buf, sz);
        in += words;
        cmd[0] |= (1 << 30);
    } else {
        out += words;
    }
    uint32_t *rep;
    size_t rep_num;
    if (device_config_raw(dev, cmd, in, &rep, &rep_num) < 0)
        return false;
    if (rep_num != out || rep[1]) {
        free(rep);
        return false;
    }
    if (!w)
        memcpy(buf, &rep[2], sz);
    free(rep);
    return true;
}

void run_init_and_test(struct global *global, char *device, char *serial)
{
    global->log = (struct logfn){stdout, logfn_stdio};

    struct logfn log = global->log;
    libusb_context *usbctx = usb_thread_libusb_context(global->usb_thr);

    void *fsbl = NULL;
    size_t fsbl_size = 0;
    void *fw = NULL;
    size_t fw_size = 0;

    if (!read_file("firmware.dat", &fw, &fw_size) && errno != ENOENT) {
        logline(log, "firmware.dat could not be read.\n");
        _Exit(21);
    }

    if (fw) {
        if (!read_file("fsbl.img", &fsbl, &fsbl_size)) {
            logline(log, "fsbl.img not found.\n");
            _Exit(21);
        }

        if (!fw_verify(log, fw, fw_size)) {
            logline(log, "firmware.dat is broken.\n");
            _Exit(21);
        }

        if (fsbl_size < 16 || memcmp(fsbl, "CY", 2) != 0) {
            logline(log, "fsbl.img is broken.\n");
            _Exit(21);
        }

        // Any cypress device? Switch to our own bootloader to access the flash.
        libusb_device_handle *usbdev =
            open_device_with_vid_pid(usbctx, 0x04b4, 0x00f3, device);
        if (usbdev) {
            // NB: this call fudges the image so that it won't boot the main fw
            //     from flash when it got loaded.
            if (!usb_program_cyboot(usbdev, log, fsbl, fsbl_size)) {
                logline(log, "Failed to program FSBL.\n");
                _Exit(17);
            }
            libusb_close(usbdev);

            // Give it time to re-enumerate
            sleep(USB_REBOOT_WAIT_SECS);
        }

        // Any FSBL-only device?
        usbdev = open_device_with_vid_pid(usbctx, FW_USB_FSBL_VID,
                                          FW_USB_FSBL_PID, device);
        if (usbdev) {
            if (!usb_set_flash_protection(usbdev, log, 0, 0)) {
                logline(log, "Failed to un-protect flash.\n");
                _Exit(19);
            }

            // (If the FSBL was already on the flash, update it.)
            if (!usb_write_flash(usbdev, log, 0, fsbl, fsbl_size)) {
                logline(log, "Failed to flash FSBL.\n");
                _Exit(19);
            }

            if (!usb_write_flash(usbdev, log, FW_BASE_ADDRESS_0 + FW_HEADER_OFFSET,
                                 fw, fw_size) ||
                !usb_write_flash(usbdev, log, FW_BASE_ADDRESS_1 + FW_HEADER_OFFSET,
                                 fw, fw_size))
            {
                logline(log, "Failed to flash main FW.\n");
                _Exit(19);
            }

            if (!usb_set_flash_protection(usbdev, log, 0, FW_BASE_ADDRESS_1)) {
                logline(log, "Failed to protect flash.\n");
                _Exit(19);
            }

            if (serial && serial[0]) {
                logline(log, "Writing serial number...\n");
                bool ok = flash_serial(usbdev, log, serial);
                logline(log, "...result: %s\n", ok ? "ok" : "failed");
            }

            // Make it boot the actual firmware.
            if (!usb_reboot(usbdev, log))
                _Exit(20);

            libusb_close(usbdev);

            sleep(USB_REBOOT_WAIT_SECS);
        }
    }

    struct device *dev = device_open(global, device);
    if (!dev)
        _Exit(1);

    if (dev->fw_version >= 0x106) {
        printf("Checking EEPROM...\n");

        if (!eeprom_access(dev, true, 13, "hello world", 11))
            _Exit(14);
        if (!eeprom_access(dev, true, 24, "blarrrgh", 8))
            _Exit(14);
        char buf[17];
        if (!eeprom_access(dev, false, 15, buf, 17))
            _Exit(14);
        if (memcmp(buf, "llo worldblarrrgh", 17))
            _Exit(15);

        // send reset command (clears and initializes EEPROM)
        uint32_t cmd = (7 << 24);
        uint32_t *res = NULL;
        size_t res_num = 0;
        int r = device_config_raw(dev, &cmd, 1, &res, &res_num);
        if (r < 0 || res_num < 2 || (res[1] & 0xFF))
            _Exit(16);
        free(res);

        if (!eeprom_access(dev, false, 0x63A, buf, 8))
            _Exit(14);
        if (memcmp(buf, &(uint64_t){(uint64_t)-1}, 8))
            _Exit(15);
    }

    logline(log, "Checking mdio...\n");

    // Test mdio: test register 17_24, because it can take arbitrary 16 bit data
    device_cfg_lock(dev);
    if (device_mdio_write(dev, DEV_PORT_ALL, 22, 17) < 0)
        _Exit(2);
    if (device_mdio_write(dev, DEV_PORT_A, 24, 0xABCD) < 0)
        _Exit(2);
    if (device_mdio_write(dev, DEV_PORT_B, 24, 0x1234) < 0)
        _Exit(2);
    int regs[2];
    if (device_mdio_read_both(dev, 24, regs) < 0)
        _Exit(3);
    if (regs[0] != 0xABCD || regs[1] != 0x1234)
        _Exit(4);
    if (device_mdio_write(dev, DEV_PORT_ALL, 24, 0xF0BA) < 0)
        _Exit(2);
    if (device_mdio_read_both(dev, 24, regs) < 0)
        _Exit(3);
    if (regs[0] != 0xF0BA || regs[1] != 0xF0BA)
        _Exit(4);
    device_cfg_unlock(dev);

    logline(log, "Configure disrupt...\n");

    // Disrupt command to both ports, prevents propagating test packets when
    // using a loopback cable.
    struct device_disrupt_params dp = {
        .num_packets = UINT32_MAX,
        .mode = DEVICE_DISRUPT_DROP,
    };
    if (device_disrupt_pkt(log, dev, 3u, &dp) < 0)
        _Exit(8);

    logline(log, "Starting capture, discarding input...\n");

    struct test_filter_ctx test_ctx = {0};
    struct grabber_filter test_filter = {
        .fns = &filter_test,
        .priv = &test_ctx,
    };
    struct grabber_filter *filters[] = {&test_filter};
    size_t num_filters = ARRAY_LENGTH(filters);

    struct grabber_options grab_opts = {
        .filename = HAVE_POSIX ? "/dev/null" : "nul",
        .soft_buffer = 128 * 1024,
        .usb_buffer = 128 * 1024,
        .device = dev,
        .filters = filters,
        .num_filters = num_filters,
    };
    grabber_start(global, &grab_opts);
    if (!dev->grabber)
        _Exit(9);

    // Ignore whatever was still stuck in the pipes from previous run.
    sleep(1);

    for (size_t port = 0; port < 2; port++) {

        // Sometimes in the very initial stage it behaves strange (dropping
        // packets, usually link not up yet), so test multiple times until it
        // works.
        for (size_t n = 0; n < 6; n++) {
            logline(log, "Checking port %zu...\n", port + 1);

            test_ctx = (struct test_filter_ctx){0};

            const void *payload = port ? testpkt2 : testpkt1;
            size_t size = port ? sizeof(testpkt2) : sizeof(testpkt1);

            struct device_inject_params params = {
                .num_packets = 1,
                .raw = 1,
                .data = payload,
                .data_size = size,
            };

            test_ctx.phy[port].expect_data = payload;
            test_ctx.phy[port].expect_size = size;

            // Inject through opposite port.
            size_t otherport = !port;
            if (device_inject_pkt(log, dev, 1 << otherport, &params) < 0)
                _Exit(10);

            sleep(1);

            if (!test_ctx.encountered_notok && test_ctx.encountered_ok)
                break;
        }

        if (test_ctx.encountered_notok)
            _Exit(11);
        if (!test_ctx.encountered_ok)
            _Exit(12);
    }

    // Disable disruptor
    dp.num_packets = 0;
    if (device_disrupt_pkt(log, dev, 3u, &dp) < 0)
        _Exit(13);

    printf("Checking serial number...\n");

    char devserial[256] = {0};
    struct libusb_device_descriptor desc;
    if (!libusb_get_device_descriptor(libusb_get_device(dev->dev), &desc) &&
        desc.iSerialNumber)
    {
        if (libusb_get_string_descriptor_ascii(dev->dev, desc.iSerialNumber,
                            (unsigned char *)devserial, sizeof(devserial)) < 0)
            devserial[0] = '\0';
    }

    if (serial && serial[0] && strcmp(serial, devserial) != 0) {
        logline(log, "All OK, but serial number is not correct.\n");
        _Exit(33);
    }

    logline(log, "All OK.\n");
    _Exit(32);
}
