// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crc32.h"
#include "fw_header.h"
#include "usb_control.h"
#include "utils.h"

static bool get_device_name(libusb_device *dev, char *buf, size_t buf_size,
                            bool any, bool serial)
{
    if (buf_size)
        buf[0] = '\0';

    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc))
        goto fail;

    if (!any && !(desc.idVendor == FW_USB_MAIN_VID &&
                  desc.idProduct == FW_USB_MAIN_PID))
        goto fail;

    if (serial) {
        if (!desc.iSerialNumber)
            goto fail;
        libusb_device_handle *handle = NULL;
        if (libusb_open(dev, &handle))
            goto fail;
        int r = libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber,
                                                   (unsigned char *)buf, buf_size);
        libusb_close(handle);
        if (r <= 0 || r >= buf_size)
            goto fail;
    } else {
        snprintf(buf, buf_size, "%d:%d:%d",
                 libusb_get_bus_number(dev),
                 libusb_get_port_number(dev),
                 libusb_get_device_address(dev));
    }
    return true;

fail:
    snprintf(buf, buf_size, "(unknown)");
    return false;
}

bool usb_get_device_name(libusb_device *dev, char *buf, size_t buf_size)
{
    return get_device_name(dev, buf, buf_size, false, false);
}

bool usb_get_device_serial(libusb_device *dev, char *buf, size_t buf_size)
{
    return get_device_name(dev, buf, buf_size, false, true);
}

static libusb_device *find_device(libusb_context *ctx, const char *name, bool any)
{
    libusb_device *res = NULL;
    libusb_device **list = NULL;
    libusb_get_device_list(ctx, &list);

    // As a minor optimization, query the serial number in a second pass, to
    // avoid querying the serial number from all the devices if it's avoidable.
    for (size_t serial = 0; serial < 2; serial++) {
        for (size_t n = 0; list && list[n]; n++) {
            char devname[USB_DEVICE_NAME_LEN];

            if (!get_device_name(list[n], devname, sizeof(devname), any, serial))
                continue;

            if (!name || strcmp(name, devname) == 0) {
                res = libusb_ref_device(list[n]);
                break;
            }
        }
    }

    libusb_free_device_list(list, 1);
    return res;
}

libusb_device *usb_find_device(libusb_context *ctx, const char *name)
{
    return find_device(ctx, name, false);
}

libusb_device *usb_find_device_any(libusb_context *ctx, const char *name)
{
    return find_device(ctx, name, true);
}

static bool spi_transfer_legacy(libusb_device_handle *dev, struct logfn lfn,
                                void *in, size_t in_size,
                                void *out, size_t out_size)
{
    // Technically, the out transfer just copies a buffer, that is then actually
    // sent with the in transfer.

    if (libusb_control_transfer(dev,
        LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
        0xA2,
        0,
        0,
        in,
        in_size,
        USB_TIMEOUT) < 0)
    {
        logline(lfn, "Could not transfer data to the device.\n");
        return false;
    }

    if (libusb_control_transfer(dev,
        LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_IN,
        0xA2,
        0,
        0,
        out,
        out_size,
        USB_TIMEOUT) < 0)
    {
        logline(lfn, "Could not transfer data from the device.\n");
        return false;
    }

    return true;
}

static bool spi_transfer(libusb_device_handle *dev, struct logfn lfn,
                         void *in, size_t in_size,
                         void *out, size_t out_size)
{
    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(libusb_get_device(dev), &desc))
        return false;

    if (desc.idVendor == FW_USB_FSBL_VID && desc.idProduct == FW_USB_FSBL_PID &&
        desc.bcdDevice < 0x101)
        return spi_transfer_legacy(dev, lfn, in, in_size, out, out_size);

    int e = libusb_control_transfer(dev,
        LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
        0xA6,
        out_size, // wValue
        0,
        in,
        in_size,
        USB_TIMEOUT);
    if (e != in_size) {
        logline(lfn, "Could not transfer data to the device (error %s).\n",
                libusb_error_name(e < 0 ? e : LIBUSB_ERROR_OTHER));
        return false;
    }

    // The out transfer performs all work. The in transfer can be used to
    // retrieve the read SPI data (requested by wValue) and the status. The
    // latter makes this transfer mandatory, because the FX3 apparently cannot
    // report errors for OUT transfers after the firmware has read the data.
    // In transfers with size 0 sometimes cause problem, over-read the buffer by
    // 1 if needed (the firmware will still return 0 bytes).
    e = libusb_control_transfer(dev,
        LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_IN,
        0xA6,
        0,
        0,
        out_size ? out : &(char){0},
        out_size ? out_size : 1,
        USB_TIMEOUT);
    if (e != out_size) {
        logline(lfn, "Could not transfer data from the device (error %s).\n",
                libusb_error_name(e < 0 ? e : LIBUSB_ERROR_OTHER));
        return false;
    }

    return true;
}

// Sanity-check status register before a read command.
static bool flash_prepare_read(libusb_device_handle *dev, struct logfn lfn)
{
    uint8_t cmd = 0x05; // read status register 1 (RDSR1)
    uint8_t reg;
    if (!spi_transfer(dev, lfn, &cmd, 1, &reg, 1))
        return false;

    // Check WIP bit (write in progress)
    if (reg & 1) {
        // Any write command is supposed to wait until WIP=0, so this is
        // probably a host programming error.
        logline(lfn, "Unexpected state: write in progress.\n");
        return false;
    }

    return true;
}

static bool flash_prepare_write(libusb_device_handle *dev, struct logfn lfn)
{
    uint8_t cmd = 0x82; // CLSR (clear status register), clears sticky error bits
    if (!spi_transfer(dev, lfn, &cmd, 1, NULL, 0))
        return false;

    cmd = 0x06; // write enable (WREN)
    if (!spi_transfer(dev, lfn, &cmd, 1, NULL, 0))
        return false;

    cmd = 0x05; // read status register 1 (RDSR1)
    uint8_t reg;
    if (!spi_transfer(dev, lfn, &cmd, 1, &reg, 1))
        return false;

    // Check WIP bit 1 (write in progress), WEL bit 2 (write enable latch)
    if ((reg & 1) || !(reg & 2)) {
        // Any write command is supposed to wait until WIP=0, so this is
        // probably a host programming error.
        // The WEL bit is set immediately by WREN, at least if WIP was 0.
        logline(lfn, "Unexpected flash state: status=%d.\n", reg);
        return false;
    }

    return true;
}

// Wait for the current operation to finish (WIP bit), check the status, and
// possibly log errors (implies CLSR was run for any command that sets these).
static bool flash_finish_write(libusb_device_handle *dev, struct logfn lfn)
{
    while (1) {
        uint8_t cmd = 0x05; // read status register 1 (RDSR1)
        uint8_t reg;
        if (!spi_transfer(dev, lfn, &cmd, 1, &reg, 1))
            return false;

        // Check WIP bit 0 (write in progress), E_ERR bit 5, P_ERR bit 6
        bool e_err = reg & (1 << 5);
        bool p_err = reg & (1 << 6);
        if (e_err || p_err) {
            if (e_err)
                logline(lfn, "Erase error occurred.\n");
            if (p_err)
                logline(lfn, "Programming error occurred.\n");
            cmd = 0x82;
            if (!spi_transfer(dev, lfn, &cmd, 1, NULL, 0))
                logline(lfn, "Failed to execute CLSR.\n");
            return false;
        }
        if (!(reg & 1))
            return true;
    }
}

// Sanity check status after any non-write operation.
static bool flash_finish_read(libusb_device_handle *dev, struct logfn lfn)
{
    // (Use this to sanity-check for stale WIP bits; probably a waste of time.)
    return flash_prepare_read(dev, lfn);
}

bool usb_write_flash(libusb_device_handle *dev, struct logfn lfn,
                     uint32_t address, const void *data, size_t size)
{
    uint8_t cmd;

    if (!flash_prepare_read(dev, lfn))
        return false;

    uint8_t id[0x40];
    cmd = 0x9F; // read identification (RDID)
    if (!spi_transfer(dev, lfn, &cmd, 1, id, sizeof(id)))
        return false;

    // Check Memory Interface Type (0x01), Density (i.e. capacity, 0x02), and
    // identification string (0x10-0x12).
    if (id[0x01] != 0x02 || id[0x02] != 0x17 || id[0x10] != 'Q' ||
        id[0x11] != 'R' || id[0x12] != 'Y')
    {
        logline(lfn, "Unsupported flash chip.\n");
        return false;
    }

    int sector_size = 64 * 1024;
    int page_size = 256;

    if (address & (sector_size - 1)) {
        logline(lfn, "Flash address must be sector-aligned.\n");
        return false;
    }

    int sector_start = address / sector_size;
    int sector_count = (size + sector_size - 1) / sector_size;
    int sector_end = sector_start + sector_count;

    logline(lfn, "Writing to: 0x%x (sectors %d-%d)\n", address, sector_start,
            sector_end);

    if (sector_start == 0) {
        // Painful 4 KB sector nonsense
        for (int n = 0; n < 8; n++) {
            logline(lfn, "Erasing sub-sector %d/8...\r", n);

            if (!flash_prepare_write(dev, lfn))
                return false;

            int addr = n * 4096;
            uint8_t erase_cmd[4] = {
                0x20, // parameter sector erase
                addr >> 16,
                (addr >> 8) & 0xFF,
                addr & 0xFF,
            };
            if (!spi_transfer(dev, lfn, erase_cmd, sizeof(erase_cmd), NULL, 0))
                return false;

            if (!flash_finish_write(dev, lfn))
                return false;
        }
    }

    for (int n = sector_start; n < sector_end; n++) {
        logline(lfn, "Erasing sector %d/%d...\r", n - sector_start, sector_count);

        if (!flash_prepare_write(dev, lfn))
            return false;

        // The messed up special 32KB sector is at 0x8000.
        int addr = n ? n * sector_size : 0x8000;
        uint8_t erase_cmd[4] = {
            0xD8, // sector erase
            addr >> 16,
            (addr >> 8) & 0xFF,
            addr & 0xFF,
        };
        if (!spi_transfer(dev, lfn, erase_cmd, sizeof(erase_cmd), NULL, 0))
            return false;

        if (!flash_finish_write(dev, lfn))
            return false;
    }

    int page_count = (size + page_size - 1) / page_size;
    for (int n = 0; n < page_count; n++) {
        logline(lfn, "Programming page %d/%d...\r", n, page_count);

        for (int repeat = 0; ; repeat++) {
            if (!flash_prepare_write(dev, lfn))
                return false;

            int offset = n * page_size;
            int addr = address + offset;
            uint8_t write_cmd[4 + 256] = {
                0x02, // page write
                addr >> 16,
                (addr >> 8) & 0xFF,
                addr & 0xFF,
            };
            int left = MIN(size - offset, 256);
            memcpy(write_cmd + 4, (char *)data + offset, left);
            if (!spi_transfer(dev, lfn, write_cmd, sizeof(write_cmd), NULL, 0))
                return false;

            if (!flash_finish_write(dev, lfn))
                return false;

            void *block = write_cmd + 4;

            uint8_t read_cmd[4] = {
                0x03, // page read
                addr >> 16,
                (addr >> 8) & 0xFF,
                addr & 0xFF,
            };
            uint8_t res[256] = {0};
            if (!spi_transfer(dev, lfn, read_cmd, sizeof(read_cmd),
                              res, sizeof(res)))
                return false;
            if (!flash_finish_read(dev, lfn))
                return false;
            if (memcmp(block, res, 256) == 0)
                break;

            if (repeat >= 10) {
                logline(lfn, "Writing failed. Should be:\n");
                log_hexdump(lfn, block, 256);
                logline(lfn, "Is:\n");
                log_hexdump(lfn, res, sizeof(res));
                return false;
            }
            logline(lfn, "...failed, retrying.\n");
        }
    }

    // Verify...
    for (int n = 0; n < page_count; n++) {
        logline(lfn, "Reading page %d/%d...\r", n, page_count);

        if (!flash_prepare_read(dev, lfn))
            return false;

        int offset = n * page_size;
        int addr = address + offset;

        uint8_t block[256] = {0};
        int left = MIN(size - offset, 256);
        memcpy(block, (char *)data + offset, left);

        uint8_t read_cmd[4] = {
            0x03, // page read
            addr >> 16,
            (addr >> 8) & 0xFF,
            addr & 0xFF,
        };
        uint8_t res[256] = {0};
        if (!spi_transfer(dev, lfn, read_cmd, sizeof(read_cmd), res, sizeof(res)))
            return false;
        if (!flash_finish_read(dev, lfn))
            return false;
        if (memcmp(block, res, 256) != 0) {
            logline(lfn, "Should be:\n");
            log_hexdump(lfn, block, sizeof(block));
            logline(lfn, "Is:\n");
            log_hexdump(lfn, res, sizeof(res));
            return false;
        }
    }

    return true;
}

bool usb_erase_flash_at(libusb_device_handle *dev, struct logfn lfn,
                        uint32_t address)
{
    int sector_size = 64 * 1024;

    // Only erase sub-sectors.
    if (address < 32 * 1024) {
        sector_size = 4 * 1024;
    } else if (address < 64 * 1024) {
        sector_size = 32 * 1024;
    }

    address = ALIGN_POW2(address, sector_size);

    logline(lfn, "Erasing sector of size %d at 0x%"PRIx32"...\n", sector_size,
            address);

    if (!flash_prepare_write(dev, lfn))
        return false;

    uint8_t erase_cmd[4] = {
        sector_size >= 32 * 1024 ? 0xD8 : 0x20,
        address >> 16,
        (address >> 8) & 0xFF,
        address & 0xFF,
    };
    if (!spi_transfer(dev, lfn, erase_cmd, sizeof(erase_cmd), NULL, 0))
        return false;
    return flash_finish_write(dev, lfn);
}

bool usb_read_flash(libusb_device_handle *dev, struct logfn lfn,
                    uint32_t address, void *data, size_t size)
{
    while (size) {
        if (!flash_prepare_read(dev, lfn))
            return false;

        size_t copy = MIN(4096, size);

        uint8_t read_cmd[4] = {
            0x03, // page read
            address >> 16,
            (address >> 8) & 0xFF,
            address & 0xFF,
        };
        if (!spi_transfer(dev, lfn, read_cmd, sizeof(read_cmd), data, copy))
            return false;
        if (!flash_finish_read(dev, lfn))
            return false;

        address += copy;
        data = (char *)data + copy;
        size -= copy;
    }

    return true;
}

bool usb_erase_flash(libusb_device_handle *dev, struct logfn lfn)
{
    logline(lfn, "Erasing flash...\n");

    if (!flash_prepare_write(dev, lfn))
        return false;

    uint8_t erase_cmd[1] = {
        0x60, // bulk erase
    };
    if (!spi_transfer(dev, lfn, erase_cmd, sizeof(erase_cmd), NULL, 0))
        return false;

    logline(lfn, "wait completion...\n");
    if (!flash_finish_write(dev, lfn))
        return false;

    return true;
}

bool usb_set_flash_protection(libusb_device_handle *dev, struct logfn lfn,
                              uint32_t start, uint32_t end)
{
    if (start > end || end > 0x00800000 ||
        (start & (0x10000 - 1)) || (end & (0x10000 - 1)))
        return false;

    logline(lfn, "Erasing protected sector list...\n");

    if (!flash_prepare_write(dev, lfn))
        return false;
    uint8_t clear_cmd = 0xE4; // PPB Erase (PPBE)
    if (!spi_transfer(dev, lfn, &clear_cmd, 1, NULL, 0))
        return false;
    if (!flash_finish_write(dev, lfn))
        return false;

    for (int s = start; s < end; s += 0x10000) {
        logline(lfn, "Protecting sector at 0x%"PRIx32"...\n", s);

        if (!flash_prepare_write(dev, lfn))
            return false;

        uint8_t set_cmd[4] = {
            0xFD, // PPB Program (PPBP)
            s >> 16,
            (s >> 8) & 0xFF,
            s & 0xFF,
        };
        if (!spi_transfer(dev, lfn, set_cmd, sizeof(set_cmd), NULL, 0))
            return false;
        if (!flash_finish_write(dev, lfn))
            return false;
    }

    if (start == end)
        logline(lfn, "Protection list cleared.\n");

    return true;
}

bool usb_write_otp(libusb_device_handle *dev, struct logfn lfn,
                   uint32_t address, const void *data, size_t size)
{
    if (address > 1024 || size > 1024 - address)
        return false;

    if (!flash_prepare_read(dev, lfn))
        return false;

    logline(lfn, "Writing to OTP: 0x%x (%zu bytes)\n", address, size);

    if (!flash_prepare_write(dev, lfn))
        return false;

    uint8_t write_cmd[4 + 1024] = {
        0x42, // OTP program
        address >> 16,
        (address >> 8) & 0xFF,
        address & 0xFF,
    };
    memcpy(write_cmd + 4, data, size);
    if (!spi_transfer(dev, lfn, write_cmd, 4 + size, NULL, 0))
        return false;
    if (!flash_finish_write(dev, lfn))
        return false;
    return true;
}

bool usb_read_otp(libusb_device_handle *dev, struct logfn lfn,
                  uint32_t address, void *data, size_t size)
{
    if (address > 1024 || size > 1024 - address)
        return false;

    if (!flash_prepare_read(dev, lfn))
        return false;

    uint8_t read_cmd[5] = {
        0x4B, // OTP read
        address >> 16,
        (address >> 8) & 0xFF,
        address & 0xFF,
        0, // fill dummy cycles (8 cycles by default => 1 byte)
    };
    if (!spi_transfer(dev, lfn, read_cmd, sizeof(read_cmd), data, size))
        return false;
    if (!flash_finish_read(dev, lfn))
        return false;
    return true;
}

bool usb_write_eeprom(libusb_device_handle *dev, struct logfn lfn,
                      uint16_t address, const void *data, size_t size)
{
    if (size > 0xFFFF)
        return false;

    if (libusb_control_transfer(dev,
        LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
        0xE1,
        0,
        0,
        (void *)data,
        size,
        USB_TIMEOUT) < 0)
        return false;

    if (libusb_control_transfer(dev,
        LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_IN,
        0xE1,
        address,
        0,
        NULL,
        0,
        USB_TIMEOUT) < 0)
        return false;

    return true;
}

bool usb_read_eeprom(libusb_device_handle *dev, struct logfn lfn,
                     uint16_t address, void *data, size_t size)
{
    if (size > 0xFFFF)
        return false;

    return libusb_control_transfer(dev,
        LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_IN,
        0xE0,
        address,
        0,
        data,
        size,
        USB_TIMEOUT) >= 0;
}

bool usb_program_cyboot(libusb_device_handle *dev, struct logfn lfn,
                        const void *data, size_t size)
{
    // This function follows Cypress doc. 001-76405 Rev J, 4.2.11. (No code copied.)
    uint64_t pos = 0;

    if (size < 4) {
        logline(lfn, "File too short.\n");
        return false;
    }

    uint16_t sig;
    memcpy(&sig, data, 2);
    if (sig != 0x5943) {
        logline(lfn, "Invalid signature, not a CY file.\n");
        return false;
    }

    pos = 4;

    while (1) {
        if (pos + 8 > size) {
            logline(lfn, "File cut off.\n");
            return false;
        }

        uint32_t len, addr;
        memcpy(&len, (char *)data + pos + 0, 4);
        memcpy(&addr, (char *)data + pos + 4, 4);
        pos += 8;

        // The last entry is 0 and signals the entrypoint. Perform a 0-sized
        // transfer (which jumps to the entrypoint) instead of exiting early.
        bool last = !len;

        len = len * 4;

        do {
            // The vendor specific write command transfers at most 4K at once.
            uint8_t block[4096];
            size_t copy = len;
            if (copy > 4096)
                copy = 4096;

            if (pos + copy > size) {
                logline(lfn, "File cut off.\n");
                return false;
            }

            memcpy(block, (char *)data + pos, copy);
            pos += copy;

            logline(lfn, "Writing %zd bytes to 0x%x...\n", copy, (unsigned)addr);

            // This makes our FSBL not boot from flash (important if you want to
            // reprogram a device). It'll break with other software that uses
            // this format.
            if (addr == FW_BOOTMEM_ADDRESS && copy >= 4) {
                uint32_t prev_magic;
                memcpy(&prev_magic, block, 4);
                if (prev_magic == FW_BOOTMEM_MAGIC) {
                    logline(lfn, "   (setting fw_bootmem.magic=FW_BOOTMEM_NOBOOT_MAGIC)\n");
                    uint32_t magic = FW_BOOTMEM_NOBOOT_MAGIC;
                    memcpy(block, &magic, 4);
                }
            }

            if (libusb_control_transfer(dev,
                LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
                0xA0,
                addr & 0xFFFFu,
                addr >> 16,
                block,
                copy,
                USB_TIMEOUT) < 0)
            {
                logline(lfn, "Could not transfer data to the device.\n");
                if (len == 0) {
                    logline(lfn, "(Ignoring, device is probably busy.)\n");
                    return true;
                }
                return false;
            }

            len -= copy;
            addr += copy;
        } while (len);

        if (last)
            break;
    }

    return true;
}

bool usb_reboot(libusb_device_handle *dev, struct logfn lfn)
{
    logline(lfn, "Reboot...\n");

    // Note: no error checking, since the device doesn't respond to the device
    // correctly ((probably, or not in time) since it reboots immediately.

    libusb_control_transfer(dev,
            LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
            0xB0,
            0x12,
            0x34,
            NULL,
            0,
            USB_TIMEOUT);
    return true;
}

static bool check_offsets(uint32_t img_size, uint32_t offset, uint32_t size)
{
    return offset <= img_size &&
           img_size - offset >= size &&
           offset >= sizeof(struct fw_header);
}

int fw_verify(struct logfn lfn, void *data, size_t size)
{
    size_t max_size = FW_BASE_ADDRESS_1 - FW_BASE_ADDRESS_0 - FW_HEADER_OFFSET;

    if (size > max_size) {
        logline(lfn, "Invalid firmware image (file too large).\n");
        return 0;
    }

    if (size < sizeof(struct fw_header)) {
        logline(lfn, "Invalid firmware image (file too small).\n");
        return 0;
    }

    struct fw_header *h = (void *)data;
    if (h->magic != FW_HEADER_MAGIC ||
        h->hcrc != crc32(0, ((char *)h) + 8, sizeof(*h) - 8) ||
        h->size != size ||
        !check_offsets(h->size, h->fw_offs, h->fw_size) ||
        !check_offsets(h->size, h->fpga_offs, h->fpga_size))
    {
        logline(lfn, "Invalid firmware image (broken header).\n");
        return 0;
    }

    if (h->fw_crc != crc32(0, (char *)data + h->fw_offs, h->fw_size) ||
        h->fpga_crc != crc32(0, (char *)data + h->fpga_offs, h->fpga_size))
    {
        logline(lfn, "Invalid firmware image (corrupted file).\n");
        return 0;
    }

    // I bet a beer that we never make use of this.
    if (h->vid != FW_USB_MAIN_VID || h->pid != FW_USB_MAIN_PID) {
        logline(lfn, "Firmware image is for an incompatible device.\n");
        return 0;
    }

    if (h->version >= (1 << 16) - 256) {
        logline(lfn, "Strange version field.\n");
        return 0;
    }

    return h->version + 256;
}
