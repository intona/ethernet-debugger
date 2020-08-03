// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef FW_HEADER_
#define FW_HEADER_

#include <stdint.h>

// Device VID/PID with full firmware loaded ("1G Sniffer")
#define FW_USB_MAIN_VID    0x7054
#define FW_USB_MAIN_PID    0x7080

// FSBL only ("1G Sniffer (NOFW)")
#define FW_USB_FSBL_VID    0x7054
#define FW_USB_FSBL_PID    0x7081

// Redundant firmware image base locations in flash.
#define FW_BASE_ADDRESS_0 0x00000000
#define FW_BASE_ADDRESS_1 0x00400000

// Maximum size of the flash for which this memory layout was made for.
#define FW_FLASH_END 0x00800000

// Offset from FW_BASE_ADDRESS_x to struct fw_header in flash.
// FW_BASE_ADRESS_0 requires this for the FSBL (since Cypress loads the FSBL
// from flash address 0) and the serial number. FW_BASE_ADDRESS_1 might use the
// free space for settings.
#define FW_HEADER_OFFSET 0x80000

#define FW_HEADER_MAGIC 0x424f4f46

// Located at FW_BASE_ADDRESS_x+FW_HEADER_OFFSET in flash. This is followed by
// firmware and FPGA images, as described by the header fields. All data is
// within start of the header and fw_header.size.
struct fw_header {
    uint32_t magic;     // FW_HEADER_MAGIC
    uint32_t hcrc;      // crc of fw_header, excluding first 8 bytes
    uint32_t size;      // size of all data, including fw_header
    uint16_t vid, pid;  // device intended for the firmware
    uint32_t version;   // software release version
    uint32_t fw_offs;   // bytes from start of header to ARM firmware
    uint32_t fw_size;   // size of ARM firmware in bytes
    uint32_t fw_crc;    // CRC of [0..fw_size]
    uint32_t fpga_offs; // bytes from start of header to FPGA bitstream
    uint32_t fpga_size; // size of FPGA bitstream in bytes
    uint32_t fpga_crc;  // CRC of [0..fpga_size]
    uint32_t unused[5]; // set to 0
};
_Static_assert(sizeof(struct fw_header) == 16 * 4, "");

// Address of the serial number in flash (OTP area), struct fw_serial.
#define FW_FLASH_ADDRESS_SERIAL 0x40

#define FW_SERIAL_MAGIC 0x53455249

struct fw_serial {
    uint32_t magic;     // FW_SERIAL_MAGIC
    uint32_t crc;       // crc of fw_serial, excluding first 8 bytes
    char serial[32];    // including terminating \0; padding shall be 0
};
_Static_assert(sizeof(struct fw_serial) == 40, "");

// Address of fw_bootmem in RAM (shared between FSBL and proper firmware).
#define FW_BOOTMEM_ADDRESS 0x4007FF00

#define FW_BOOTMEM_MAGIC 0x53545546

// This is used to make the FSBL _not_ boot the flash image. Typically used for
// resetting firmware (e.g. starting cypress FSBL by disabling the flash, then
// running our FSBL to reprogram the flash). The only reason to do this is so
// that we don't have to build 2 FSBL binaries (one which boots flash, and one
// which can be used to overwrite flash).
#define FW_BOOTMEM_NOBOOT_MAGIC 0x53025501

// 256 bytes memory region reserved for passing data from FSBL to proper
// firmware.
struct fw_bootmem {
    uint32_t magic;     // FW_BOOTMEM_MAGIC (usually)

    // Location and validated header from which the firmware was booted off.
    uint32_t fw_flash_load_address;
    struct fw_header boot_header;

    // Why is the serial address here, instead of being read by main fw?
    // Not much of a reason - just so we can reuse FSBL flash reading & crc code.
    char serial[32];

    uint8_t unused[152];
};
_Static_assert(sizeof(struct fw_bootmem) == 256, "");

#endif
