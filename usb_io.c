// SPDX-License-Identifier: GPL-3.0-or-later
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "global.h"
#include "usb_io.h"
#include "usb_control.h"
#include "utils.h"

struct usb_thread {
    struct logfn log;
    libusb_context *usb_ctx;
    pthread_t thread;
    pthread_mutex_t lock;
    struct notifier *hotplug_notify;

    atomic_bool terminate;

    // -- protected by lock
    struct usb_ep_priv **eps;
    size_t num_eps;
    struct usb_dev **devs;
    size_t num_devs;
    libusb_device_handle **dead_devs;
    size_t num_dead_devs;
};

struct usb_ep_priv {
    struct usb_ep *ep;
    struct usb_thread *ctx;

    struct usb_dev *dev;

    // Registered transfers. Important (hacky) invariant: transfers that will
    // _not_ complete (never submitted, or completed/canceled with callback
    // already invoked) have libusb_transfer.callback set to NULL by us. We use
    // this to avoid needing another struct just to track such a flag.
    // (libusb does _not_ tell us whether a transfer is "in flight", and in
    // particular libusb_cancel_transfer() returns LIBUSB_ERROR_NOT_FOUND both
    // if the transfer was already canceled but not completed, and if it was
    // completed.)
    struct libusb_transfer **transfers;
    size_t num_transfers;

    // Allocated for transfers with an IN EP.
    void *packet_mem;
};

struct usb_dev {
    size_t refcount;
    libusb_device_handle *dev;
};

static bool ep_gc_if_done(struct usb_ep_priv *p);
static LIBUSB_CALL void transfer_cb(struct libusb_transfer *transfer);

libusb_context *usb_thread_libusb_context(struct usb_thread *ctx)
{
    return ctx->usb_ctx;
}

struct notifier *usb_get_device_list_notifier(struct usb_thread *ctx)
{
    return ctx->hotplug_notify;
}

static LIBUSB_CALL int hotplug_cb(libusb_context *libusbctx, libusb_device *device,
                                  libusb_hotplug_event event, void *user_data)
{
    struct usb_thread *ctx = user_data;
    notifier_trigger(ctx->hotplug_notify);
    return 0;
}

static void unref_dev(struct usb_thread *ctx, struct usb_dev *dev)
{
    if (!dev)
        return;

    assert(dev->refcount > 0);
    dev->refcount--;
    if (dev->refcount)
        return;

    size_t index = (size_t)-1;
    for (size_t n = 0; n < ctx->num_devs; n++) {
        if (ctx->devs[n] == dev) {
            index = n;
            break;
        }
    }
    assert(index != (size_t)-1); // must have been in the list
    ctx->devs[index] = ctx->devs[ctx->num_devs - 1];
    ctx->num_devs -= 1;

    XEXTEND_ARRAY(ctx->dead_devs, ctx->num_dead_devs, 1);
    ctx->dead_devs[ctx->num_dead_devs++] = dev->dev;
    free(dev);

    libusb_interrupt_event_handler(ctx->usb_ctx);
}

static struct usb_dev *find_dev(struct usb_thread *ctx, libusb_device_handle *dev)
{
    for (size_t n = 0; n < ctx->num_devs; n++) {
        if (ctx->devs[n]->dev == dev)
            return ctx->devs[n];
    }
    return NULL;
}

static struct usb_dev *ref_dev(struct usb_thread *ctx, libusb_device_handle *dev)
{
    struct usb_dev *ref = find_dev(ctx, dev);
    if (!ref) {
        XEXTEND_ARRAY(ctx->devs, ctx->num_devs, 1);
        ref = XALLOC_PTRTYPE(ref);
        ref->dev = dev;
        ctx->devs[ctx->num_devs++] = ref;
    }
    ref->refcount++;
    return ref;
}

void usb_thread_device_ref(struct usb_thread *ctx, libusb_device_handle *dev)
{
    pthread_mutex_lock(&ctx->lock);
    ref_dev(ctx, dev);
    pthread_mutex_unlock(&ctx->lock);
}

void usb_thread_device_unref(struct usb_thread *ctx, libusb_device_handle *dev)
{
    pthread_mutex_lock(&ctx->lock);
    struct usb_dev *ref = find_dev(ctx, dev);
    if (!ref && dev)
        assert(0); // trying to unref an unknown device
    unref_dev(ctx, ref);
    pthread_mutex_unlock(&ctx->lock);
}

static void gc_dead_devs(struct usb_thread *ctx)
{
    pthread_mutex_lock(&ctx->lock);
    for (size_t n = 0; n < ctx->num_dead_devs; n++)
        libusb_close(ctx->dead_devs[n]);
    ctx->num_dead_devs = 0;
    free(ctx->dead_devs);
    ctx->dead_devs = NULL;
    pthread_mutex_unlock(&ctx->lock);
}

static void *usb_thread(void *arg)
{
    struct usb_thread *ctx = arg;

    while (!ctx->terminate) {
        gc_dead_devs(ctx);

        int res = libusb_handle_events(ctx->usb_ctx);
        if (res != LIBUSB_SUCCESS)
            break;
    }

    return NULL;
}

struct usb_thread *usb_thread_create(struct global *global)
{
    struct usb_thread *ctx = ALLOC_PTRTYPE(ctx);
    if (!ctx)
        return NULL;

    ctx->log = global->log;

    pthread_mutex_init(&ctx->lock, NULL);

    ctx->hotplug_notify = notifier_xalloc();

    if (libusb_init(&ctx->usb_ctx)) {
        LOG(ctx, "Could not initialize libusb.\n");
        pthread_mutex_destroy(&ctx->lock);
        notifier_free(ctx->hotplug_notify);
        free(ctx);
        return NULL;
    }

    if (pthread_create(&ctx->thread, NULL, usb_thread, ctx)) {
        libusb_exit(ctx->usb_ctx);
        pthread_mutex_destroy(&ctx->lock);
        notifier_free(ctx->hotplug_notify);
        free(ctx);
        return NULL;
    }

    // This may fail; that's OK.
    libusb_hotplug_callback_handle hotplug_handle;
    libusb_hotplug_register_callback(ctx->usb_ctx,
                        LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
                        LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
                        LIBUSB_HOTPLUG_NO_FLAGS,
                        LIBUSB_HOTPLUG_MATCH_ANY,
                        LIBUSB_HOTPLUG_MATCH_ANY,
                        LIBUSB_HOTPLUG_MATCH_ANY,
                        hotplug_cb, ctx, &hotplug_handle);

    return ctx;
}

void usb_thread_destroy(struct usb_thread *ctx)
{
    if (!ctx)
        return;

    // Ask usb_thread to exit. Assume this makes libusb_handle_events() exit
    // immediately, even if we called this before libusb_handle_events() was
    // entered. (Which seems to be true.)
    ctx->terminate = true;
    libusb_interrupt_event_handler(ctx->usb_ctx);
    pthread_join(ctx->thread, NULL);

    // All EPs must have been removed by the user.
    pthread_mutex_lock(&ctx->lock);
    for (size_t n = 0; n < ctx->num_eps; n++)
        assert(!ctx->eps[n]->ep);
    pthread_mutex_unlock(&ctx->lock);

    // Wait for all transfers to finish (via transfer_cb); an EP is finally
    // removed when it has no more pending canceled (but "in-flight") transfers.
    while (1) {
        pthread_mutex_lock(&ctx->lock);
        if (!ctx->num_eps) {
            pthread_mutex_unlock(&ctx->lock);
            break;
        }
        pthread_mutex_unlock(&ctx->lock);

        int res = libusb_handle_events(ctx->usb_ctx);
        if (res != LIBUSB_SUCCESS)
            break;
    }

    gc_dead_devs(ctx);

    pthread_mutex_lock(&ctx->lock);
    assert(!ctx->num_eps);
    assert(!ctx->num_devs); // logic error
    assert(!ctx->num_dead_devs);
    pthread_mutex_unlock(&ctx->lock);

    libusb_exit(ctx->usb_ctx);
    free(ctx->eps);
    free(ctx->devs);
    pthread_mutex_destroy(&ctx->lock);
    notifier_free(ctx->hotplug_notify);
    free(ctx);
}

// Remove an EP "registration"; but do not actually remove it if there are still
// "orphaned" transfers going on.
// Returns true if actually removed and deallocated.
static bool ep_gc_if_done(struct usb_ep_priv *p)
{
    if (!p)
        return true;

    struct usb_thread *ctx = p->ctx;
    assert(!p->ep);

    for (size_t n = 0; n < p->num_transfers; n++) {
        if (p->transfers[n] && p->transfers[n]->callback)
            return false; // at least one transfer lives - delay to later

        // No callback will come (or transfer is NULL) -> free & clear.
        libusb_free_transfer(p->transfers[n]);
        p->transfers[n] = NULL;
    }

    free(p->packet_mem);

    size_t index = (size_t)-1;
    for (size_t n = 0; n < ctx->num_eps; n++) {
        if (ctx->eps[n] == p) {
            index = n;
            break;
        }
    }
    assert(index != (size_t)-1); // not found, should have existed

    ctx->eps[index] = ctx->eps[ctx->num_eps - 1];
    ctx->num_eps -= 1;

    unref_dev(ctx, p->dev);

    // Required by usb_thread_destroy().
    libusb_interrupt_event_handler(ctx->usb_ctx);

    free(p->transfers);
    free(p);
    return true;
}

// Must be called locked, and preferably only once.
static void ep_remove(struct usb_ep_priv *p)
{
    if (p->ep)
        p->ep->p = NULL;
    p->ep = NULL;

    for (size_t n = 0; n < p->num_transfers; n++) {
        if (p->transfers[n] && p->transfers[n]->callback)
            libusb_cancel_transfer(p->transfers[n]);
    }

    ep_gc_if_done(p);
}

static bool resubmit(struct usb_ep_priv *p, struct libusb_transfer *tr,
                     bool user_cb)
{
    assert(!tr->callback);
    // Set to something invalid to avoid confusion.
    tr->status = (enum libusb_transfer_status)-1;
    tr->callback = transfer_cb;
    int r = libusb_submit_transfer(tr);
    if (!r)
        return true;
    LOG(p->ctx, "USB submit error: %d (EP 0x%02x)\n", r, tr->endpoint);
    tr->callback = NULL;
    if (user_cb && p->ep && p->ep->on_error)
        p->ep->on_error(p->ep, r);
    return false;
}

static enum libusb_error status_to_error(enum libusb_transfer_status status)
{
    switch (status) {
    case LIBUSB_TRANSFER_COMPLETED: return LIBUSB_SUCCESS;
    case LIBUSB_TRANSFER_TIMED_OUT: return LIBUSB_ERROR_TIMEOUT;
    case LIBUSB_TRANSFER_STALL:     return LIBUSB_ERROR_PIPE;
    case LIBUSB_TRANSFER_NO_DEVICE: return LIBUSB_ERROR_NO_DEVICE;
    case LIBUSB_TRANSFER_OVERFLOW:  return LIBUSB_ERROR_OVERFLOW;
    default:                        return LIBUSB_ERROR_IO;
    }
}

static LIBUSB_CALL void transfer_cb(struct libusb_transfer *tr)
{
    struct usb_ep_priv *p = tr->user_data;
    struct usb_thread *ctx = p->ctx;

    pthread_mutex_lock(&ctx->lock);
    struct usb_ep *ep = p->ep;

    tr->callback = NULL;

    if (ep) {
        bool success = tr->status == LIBUSB_TRANSFER_COMPLETED;
        if (!success) {
            LOG(ctx, "USB transfer error: %d (EP 0x%02x)\n", tr->status, ep->ep);
            if (ep->on_error)
                ep->on_error(ep, status_to_error(tr->status));
        }
        // NB: lock is held during callback execution; which forces
        //     concurrent usb_ep_remove() calls to wait.
        if (ep->ep & 0x80) {
            if (ep->on_receive && success)
                ep->on_receive(ep, tr->buffer, tr->actual_length);
        } else {
            if (ep->on_sent)
                ep->on_sent(ep, success);
        }

        if (tr->flags & LIBUSB_TRANSFER_FREE_BUFFER) {
            // We also use this flag to remove the transfer itself.
            size_t index = (size_t)-1;
            for (size_t n = 0; n < p->num_transfers; n++) {
                if (p->transfers[n] == tr) {
                    index = n;
                    break;
                }
            }
            assert(index != (size_t)-1);
            p->transfers[index] = p->transfers[p->num_transfers - 1];
            p->num_transfers--;
            libusb_free_transfer(tr);
        } else if (tr->endpoint & 0x80) {
            if (!resubmit(p, tr, true))
                libusb_interrupt_event_handler(ctx->usb_ctx);
        }

    } else {
        ep_gc_if_done(p);
    }

    pthread_mutex_unlock(&ctx->lock);
}

static struct usb_ep_priv *ep_add(struct usb_thread *ctx, struct usb_ep *ep)
{
    assert(!ep->p);
    assert(!ctx->terminate);

    if (!EXTEND_ARRAY(ctx->eps, ctx->num_eps, 1))
        return NULL;

    struct usb_ep_priv *p = ALLOC_PTRTYPE(p);
    if (!p)
        return NULL;

    p->ctx = ctx;

    ctx->eps[ctx->num_eps++] = p;

    p->dev = ref_dev(ctx, ep->dev);

    // caller of usb_ep_in_add() must have held a reference already
    assert(p->dev->refcount > 1);

    return p;
}

bool usb_ep_in_add(struct usb_thread *ctx, struct usb_ep *ep,
                   size_t num, size_t psize)
{
    pthread_mutex_lock(&ctx->lock);
    bool success = false;

    struct usb_ep_priv *p = ep_add(ctx, ep);
    if (!p)
        goto done;

    p->packet_mem = calloc(num, psize);
    if (!p->packet_mem)
        goto done;

    if (!REALLOC_ARRAY(p->transfers, num))
        goto done;

    for (size_t n = 0; n < num; n++) {
        struct libusb_transfer *tr = libusb_alloc_transfer(0);
        if (!tr)
            goto done;
        p->transfers[p->num_transfers++] = tr;

        libusb_fill_bulk_transfer(tr, p->dev->dev, ep->ep,
            (unsigned char *)p->packet_mem + n * psize, psize, NULL, p, 0);

        if (!resubmit(p, tr, false))
            goto done;
    }

    success = true;
done:
    if (success) {
        ep->p = p;
        p->ep = ep;
    } else {
        ep_remove(p);
        p = NULL;
    }
    pthread_mutex_unlock(&ctx->lock);
    return success;
}

bool usb_ep_out_add(struct usb_thread *ctx, struct usb_ep *ep)
{
    pthread_mutex_lock(&ctx->lock);

    struct usb_ep_priv *p = ep_add(ctx, ep);
    if (p) {
        ep->p = p;
        p->ep = ep;
    }

    pthread_mutex_unlock(&ctx->lock);
    return !!ep->p;
}

bool usb_ep_out_submit(struct usb_ep *ep, void *data, size_t size, unsigned timeout)
{
    if (!ep->p)
        return false; // was never added

    struct usb_ep_priv *p = ep->p;
    struct usb_thread *ctx = p->ctx;
    bool success = false;

    pthread_mutex_lock(&ctx->lock);

    if (!EXTEND_ARRAY(p->transfers, p->num_transfers, 1))
        goto done;

    struct libusb_transfer *tr = libusb_alloc_transfer(0);
    if (!tr)
        goto done;

    // Frees the buffer; we also use it internally as flag to remove the
    // transfer itself completely.
    tr->flags |= LIBUSB_TRANSFER_FREE_BUFFER;

    void *data_copy = malloc(size);
    if (!data_copy) {
        libusb_free_transfer(tr);
        goto done;
    }
    memcpy(data_copy, data, size);

    libusb_fill_bulk_transfer(tr, p->dev->dev, ep->ep, data_copy, size,
                              NULL, p, 0);

    if (!resubmit(p, tr, false)) {
        libusb_free_transfer(tr);
        goto done;
    }

    p->transfers[p->num_transfers++] = tr;
    success = true;

done:
    pthread_mutex_unlock(&ctx->lock);
    return success;
}

void usb_ep_remove(struct usb_ep *ep)
{
    if (ep->p) {
        struct usb_ep_priv *p = ep->p;
        struct usb_thread *ctx = p->ctx;
        pthread_mutex_lock(&ctx->lock);
        ep_remove(p);
        pthread_mutex_unlock(&ctx->lock);
    }
}
