// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef USB_CONTROL_H_
#define USB_CONTROL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <libusb.h>

#include "utils.h"

// Generally used libusb timeout (ms).
#define USB_TIMEOUT 2000

// Maximum length of a device name.
#define USB_DEVICE_NAME_LEN 20

// Return the device "name" in buf (which has buf_size bytes space). The name
// is made up and specific to this function and usb_find_device(). It's supposed
// to be unique, but isn't stable. It must reference the physical port (for when
// the device is rebooted when loading the firmware).
// If the device is not relevant or otherwise failed, return false, and set buf
// to an empty string.
// buf_size is recommended to be USB_DEVICE_NAME_LEN, but can have any size.
// On failure (false returned), the device name is set to "(unknown)".
bool usb_get_device_name(libusb_device *dev, char *buf, size_t buf_size);

// Return the device that returns the same name with usb_get_device_name().
// name==NULL uses the first device with recognized PID/VID.
libusb_device *usb_find_device(libusb_context *ctx, const char *name);

// Like usb_find_device(), but do not check whether the found device is one of
// ours. (Will return a random device for name==NULL!)
libusb_device *usb_find_device_any(libusb_context *ctx, const char *name);

// Write the data with the specified size at the given address, no headers.
bool usb_write_flash(libusb_device_handle *dev, struct logfn lfn,
                     uint32_t address, const void *data, size_t size);

bool usb_read_flash(libusb_device_handle *dev, struct logfn lfn,
                    uint32_t address, void *data, size_t size);

// Erase the entire flash.
bool usb_erase_flash(libusb_device_handle *dev, struct logfn lfn);

// Erase sector at the given address. If the address is at the beginning of the
// flash, erase only corresponding sub-sector.
bool usb_erase_flash_at(libusb_device_handle *dev, struct logfn lfn,
                        uint32_t address);

// Overwrite non-volatile PPB bits with the ones implied by the range.
bool usb_set_flash_protection(libusb_device_handle *dev, struct logfn lfn,
                              uint32_t start, uint32_t end);

// One Time Program memory
bool usb_write_otp(libusb_device_handle *dev, struct logfn lfn,
                   uint32_t address, const void *data, size_t size);
bool usb_read_otp(libusb_device_handle *dev, struct logfn lfn,
                  uint32_t address, void *data, size_t size);

bool usb_write_eeprom(libusb_device_handle *dev, struct logfn lfn,
                      uint16_t address, const void *data, size_t size);

bool usb_read_eeprom(libusb_device_handle *dev, struct logfn lfn,
                     uint16_t address, void *data, size_t size);

// Write image in Cypress boot loader format to RAM. Reboots the device.
bool usb_program_cyboot(libusb_device_handle *dev, struct logfn lfn,
                        const void *data, size_t size);

// Trigger the firmware reboot mechanism.
bool usb_reboot(libusb_device_handle *dev, struct logfn lfn);

// Validate the firmware image (no USB access).
bool fw_verify(struct logfn lfn, void *data, size_t size);

// Write firmware to the device. Do not reboot. image: 0=fallback, 1=normal.
bool usb_fw_update(libusb_device_handle *dev, struct logfn lfn,
                   const char *fname, int image);

#endif
