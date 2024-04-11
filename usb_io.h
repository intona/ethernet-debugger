// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef USB_IO_H_
#define USB_IO_H_

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <libusb.h>

struct nofifier;
struct global;

// Starts an USB event loop thread.
struct usb_thread *usb_thread_create(struct global *global);

// All devices must have been closed before this.
void usb_thread_destroy(struct usb_thread *ctx);

// Return the libusb_context driven by this thread. This is valid until
// usb_thread_destroy() is called, which also destroys the context.
libusb_context *usb_thread_libusb_context(struct usb_thread *ctx);

// Add a reference for the given device. Newly opened devices start out with a
// refcount of 0 (as they are unknown to usb_thread), so the first
// usb_thread_device_ref() call "registers" the device, sets the refcount to 1,
// and will close the device with the next usb_thread_device_unref() call (or
// generally, if the refcount reaches 0).
void usb_thread_device_ref(struct usb_thread *ctx, libusb_device_handle *dev);

// Asynchronously close the device. This includes special tracking of on-going
// transfers (if you used usb_ep_*_add()), and closes it only when it's safe.
// The caller has to assume that dev has been destroyed.
// Unreffing a NULL dev is allowed.
// Unreffing a dev that was not "registered" with _ref will assert.
void usb_thread_device_unref(struct usb_thread *ctx, libusb_device_handle *dev);

// Triggered any time the device list has possibly changed due to USB hotplug
// events (devices added or removed).
struct notifier *usb_get_device_list_notifier(struct usb_thread *ctx);

struct usb_ep {
    // While an EP is "active" (after usb_ep_add()/before usb_ep_remove()), all
    // fields are read-only.
    libusb_device_handle *dev;
    int ep;
    // For any callbacks: reentrant calls back into this EP are not allowed.
    // For IN endpoints. Called from USB thread.
    void (*on_receive)(struct usb_ep *ep, void *data, size_t size);
    // For OUT endpoints. Called from USB thread.
    void (*on_sent)(struct usb_ep *ep, bool success);
    // For all types of callbacks: on fatal transfer errors. Called from USB
    // thread.
    void (*on_error)(struct usb_ep *ep, enum libusb_error error);

    // For free use by API user.
    void *user_data;

    // -- private; set while "active"
    struct usb_ep_priv *p;
};

// Allocate num transfers of the given packet size. Add ep to internal tracking,
// which attempts to free the API user from the need to wait for libusb's
// transfer callbacks on termination.
bool usb_ep_in_add(struct usb_thread *ctx, struct usb_ep *ep,
                   size_t num, size_t psize);

// Add OUT ep, see usb_ep_in_add().
bool usb_ep_out_add(struct usb_thread *ctx, struct usb_ep *ep,
                    size_t num, size_t psize);

// Create, submit, and "register" a transfer to an OUT endpoint. Unlike just
// doing the transfer manually with libusb_submit_transfer(), this attempts to
// make sure the transfer is properly canceled when usb_ep_remove() is called.
// Every successful call will end up with an on_sent eventually.
// Does not do any preallocation and the data is copied; this is suitable for
// low volume transfers only.
bool usb_ep_out_submit(struct usb_ep *ep, void *data, size_t size, unsigned timeout);

// How many packets are pending for transmission and not finished yet. Transfers
// can finish asynchronously while this function is returning, so this is only
// an upper bound.
size_t usb_ep_out_get_in_flight(struct usb_ep *ep);

// Stop serving any callbacks from the endpoint immediately. Remaining transfers
// are canceled and "orphaned".
// Must not be called reentrant from usb_ep callbacks.
// If an usb_ep callback is currently being called from the USB thread, this
// call will block until the call is done.
// No-OP if ep was never successfully added.
void usb_ep_remove(struct usb_ep *ep);

#endif
