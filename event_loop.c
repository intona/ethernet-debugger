// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>

#include "buffer.h"
#include "event_loop.h"
#include "event_loop_internal.h"
#include "utils.h"

struct timer {
    struct event_loop_item *item;

    int timeout_ms;

    void *on_timer_ud;
    void (*on_timer)(void *ud, struct timer *t);
};

struct event {
    struct event_loop_item *item;

    bool trigger;

    // Protected by event loop lock.
    bool signaled;
    struct notifier *notifier;
    uint64_t notifier_id;

    void *on_signal_ud;
    void (*on_signal)(void *ud, struct event *ev);
};

struct pipe {
    struct event_loop_item *item;
    struct os_pipe os;

    unsigned flags; // combination of PIPE_FLAG_*
    bool close_on_write_done;
    bool can_accept;
    bool force_read; // if true, read one more bit of data, even if read_buf not empty

    struct buffer read_buf, write_buf;

    void *on_event_ud;
    void (*on_event)(void *ud, struct pipe *p, unsigned event);
};

struct event_loop_item {
    void (*prepare_wait)(struct event_loop_item *item);
    void (*after_wait)(struct event_loop_item *item);
    void (*work)(struct event_loop_item *item);

    struct event_loop *owner;
    void *priv;

    bool has_work;              // something changed; work() shopuld be run
    int64_t timeout;            // absolute get_monotonic_time_us(); 0 if none

    struct os_event_loop_item os;

    // Static storage for various types using event_loop_item out of laziness.
    // You'd normally malloc() them. Use ->priv to access them normally.
    union {
        struct timer st_timer;
        struct event st_event;
        struct pipe st_pipe;
    } alloc_;
};

struct message {
    void *ud;
    void (*cb)(void *ud);
};

struct event_loop {
    pthread_mutex_t lock;

    atomic_bool request_terminate;

    // -- Specifically protected by lock.
    bool wakeup;

    // -- Various locking policy.
    struct os_event_loop os;

    // -- Access from event loop thread only.

    bool running, terminating, exiting;

    void *on_terminate_ud;
    void (*on_terminate)(void *ud, struct event_loop *ev);

    void *on_idle_ud;
    void (*on_idle)(void *ud, struct event_loop *ev);

    struct event_loop_item *items[MAX_ITEMS];
    size_t num_items;
    bool items_list_changed;

    struct event_loop_item item_alloc[MAX_ITEMS]; // static storage

    struct message messages[MAX_MESSAGES];
    size_t num_messages;
};

struct event_loop *event_loop_create(void)
{
    struct event_loop *ev = XALLOC_PTRTYPE(ev);
    if (!ev)
        return NULL;
    if (!os_event_loop_init(&ev->os)) {
        os_event_loop_destroy(&ev->os);
        free(ev);
        return NULL;
    }
    pthread_mutex_init(&ev->lock, NULL);
    return ev;
}

static void wakeup_event_loop(struct event_loop *ev)
{
    bool need_wakeup = false;

    pthread_mutex_lock(&ev->lock);
    need_wakeup = !ev->wakeup;
    pthread_mutex_unlock(&ev->lock);

    if (need_wakeup)
        os_event_loop_wakeup(&ev->os);
}

static void event_loop_remove_item(struct event_loop_item *item)
{
    struct event_loop *ev = item->owner;
    assert(ev); // trying to remove destroyed item?
    for (size_t n = 0; n < ev->num_items; n++) {
        if (ev->items[n] == item) {
            ev->items[n] = ev->items[ev->num_items - 1];
            ev->num_items--;
            ev->os.items[n] = &ev->items[n]->os;
            ev->os.num_items = ev->num_items;
            item->owner = NULL;
            return;
        }
    }
    assert(0); // not found, not allowed
}

static struct event_loop_item *event_loop_add_item(struct event_loop *ev)
{
    for (size_t n = 0; n < MAX_ITEMS; n++) {
        if (!ev->item_alloc[n].owner) {
            struct event_loop_item *item = &ev->item_alloc[n];
            size_t pos = ev->num_items++;
            ev->items[pos] = item;
            ev->os.items[pos] = &item->os;
            ev->os.num_items = ev->num_items;
            *item = (struct event_loop_item){
                .owner = ev,
                .has_work = true,
                .os = {
                    .owner = &ev->os,
                },
            };
            ev->items_list_changed = true;
            return item;
        }
    }
    return NULL;
}

void event_loop_run(struct event_loop *ev)
{
    bool did_work = true;
    bool idle_done = false;
    assert(!ev->running);
    ev->running = true;

    while (!ev->exiting) {
        uint64_t timeout = UINT64_MAX;

        for (size_t n = 0; n < ev->num_items; n++) {
            struct event_loop_item *item = ev->items[n];

            if (item->prepare_wait)
                item->prepare_wait(item);

            if (item->timeout)
                timeout = MIN(timeout, item->timeout);

            if (item->has_work)
                timeout = 0;

            if (!timeout)
                did_work = true;
        }

        // The idle callback (see event_loop_set_on_idle()) should run if
        // nothing is going on. For simplicity (???) this is done in several
        // stages:
        //  1. check that no work is flagged (did_work == false here)
        //     if work is flagged, make sure that all work ends by forcing
        //     timeout = 0
        //  2. actually call idle callback (idle_done = true)
        //  3. check again that no work is flagged (timeout=0)
        //  4. finally call os_event_loop() with proper timeout
        if (did_work) {
            timeout = 0;
            did_work = false;
            idle_done = false;
        } else if (!idle_done) {
            if (ev->on_idle)
                ev->on_idle(ev->on_idle_ud, ev);
            // make it check for new work produced by on_idle() itself
            timeout = 0;
            idle_done = true;
        }

        os_event_loop_wait(&ev->os, timeout);

        bool want_terminate = false;

        pthread_mutex_lock(&ev->lock);
        ev->wakeup = false;
        bool req_term = ev->request_terminate;
        want_terminate = ev->terminating != req_term;
        ev->terminating = req_term;
        did_work |= want_terminate;
        pthread_mutex_unlock(&ev->lock);

        // Flag timeouts.
        int64_t now = get_monotonic_time_us();
        for (size_t n = 0; n < ev->num_items; n++) {
            struct event_loop_item *item = ev->items[n];

            if (item->after_wait)
                item->after_wait(item);

            if (item->timeout && item->timeout <= now) {
                item->timeout = 0;
                item->has_work = true;
                did_work = true;
            }
        }

        // Drain messages. We don't want to hold the lock while calling the
        // callback, so this is a little awkward.
        size_t message_pos = 0;
        while (1) {
            pthread_mutex_lock(&ev->lock);
            if (message_pos == ev->num_messages) {
                ev->num_messages = 0;
                pthread_mutex_unlock(&ev->lock);
                break;
            }
            struct message msg = ev->messages[message_pos++];
            pthread_mutex_unlock(&ev->lock);
            msg.cb(msg.ud);
            did_work = true;
        }

        if (want_terminate && ev->on_terminate) {
            ev->on_terminate(ev->on_terminate_ud, ev);
            did_work = true;
        }

        // Dispatch new work. Needs to be done "carefully", since user callbacks
        // are run, which can change around stuff (especially adding/removing
        // event loop items).
        ev->items_list_changed = true;
        while (ev->items_list_changed) {
            ev->items_list_changed = false;

            for (size_t n = 0; n < ev->num_items; n++) {
                struct event_loop_item *item = ev->items[n];

                item->has_work |= item->os.has_work;
                item->os.has_work = false;

                if (item->has_work) {
                    item->has_work = false;

                    if (item->work)
                        item->work(item);

                    did_work = true;

                    if (ev->items_list_changed)
                        break; // repeat
                }
            }
        }
    }

    assert(ev->running);
    ev->running = false;
}

// Deallocate ev. This is not allowed while event_loop_run() is being called.
void event_loop_destroy(struct event_loop *ev)
{
    if (!ev)
        return;

    assert(!ev->running);
    assert(!ev->num_items);

    os_event_loop_destroy(&ev->os);
    pthread_mutex_destroy(&ev->lock);
    free(ev);
}

void event_loop_request_terminate(struct event_loop *ev)
{
    ev->request_terminate = true;
    wakeup_event_loop(ev);
}

bool event_loop_is_terminate_pending(struct event_loop *ev)
{
    return ev->request_terminate;
}

void event_loop_exit(struct event_loop *ev)
{
    ev->exiting = true;
}

void event_loop_set_on_terminate(struct event_loop *ev, void *ud,
                        void (*on_terminate)(void *ud, struct event_loop *ev))
{
    ev->on_terminate_ud = ud;
    ev->on_terminate = on_terminate;
}

void event_loop_set_on_idle(struct event_loop *ev, void *ud,
                            void (*on_idle)(void *ud, struct event_loop *ev))
{
    ev->on_idle_ud = ud;
    ev->on_idle = on_idle;
}

bool event_loop_send_callback(struct event_loop *ev, void *ud, void (*cb)(void *ud))
{
    bool success = false;

    pthread_mutex_lock(&ev->lock);
    if (ev->num_messages < MAX_MESSAGES) {
        ev->messages[ev->num_messages++] = (struct message){
            .ud = ud,
            .cb = cb,
        };
        success = true;
    }
    pthread_mutex_unlock(&ev->lock);

    if (success)
        wakeup_event_loop(ev);

    return success;
}

static void timer_work(struct event_loop_item *item)
{
    struct timer *t = item->priv;
    if (!item->timeout && t->timeout_ms >= 0) {
        // Restart
        timer_start(t, t->timeout_ms);
        // Trigger
        if (t->on_timer)
            t->on_timer(t->on_timer_ud, t);
    }
}

struct timer *event_loop_create_timer(struct event_loop *ev)
{
    struct event_loop_item *item = event_loop_add_item(ev);
    if (!item)
        return NULL;
    item->priv = &item->alloc_.st_timer;
    item->work = timer_work;
    struct timer *t = item->priv;
    *t = (struct timer){
        .item = item,
        .timeout_ms = -1,
    };
    return t;
}

void timer_set_on_timer(struct timer *t, void *ud,
                        void (*on_timer)(void *ud, struct timer *t))
{
    t->on_timer_ud = ud;
    t->on_timer = on_timer;
}

void timer_start(struct timer *t, int timeout_ms)
{
    t->timeout_ms = MAX(timeout_ms, 0);
    t->item->timeout = get_monotonic_time_us() + t->timeout_ms * 1000;
}

void timer_stop(struct timer *t)
{
    t->timeout_ms = -1;
    t->item->timeout = 0;
}

void timer_destroy(struct timer *t)
{
    if (t)
        event_loop_remove_item(t->item);
}

static void event_after_wait(struct event_loop_item *item)
{
    struct event *ev = item->priv;

    pthread_mutex_lock(&ev->item->owner->lock);
    ev->trigger |= ev->signaled;
    ev->signaled = false;
    pthread_mutex_unlock(&ev->item->owner->lock);

    item->has_work |= ev->trigger;
}

static void event_work(struct event_loop_item *item)
{
    struct event *ev = item->priv;

    if (ev->on_signal && ev->trigger)
        ev->on_signal(ev->on_signal_ud, ev);

    ev->trigger = false;
}

struct event *event_loop_create_event(struct event_loop *ev)
{
    struct event_loop_item *item = event_loop_add_item(ev);
    if (!item)
        return NULL;
    item->priv = &item->alloc_.st_event;
    item->after_wait = event_after_wait;
    item->work = event_work;
    struct event *evt = item->priv;
    *evt = (struct event){
        .item = item,
    };
    return evt;
}

void event_set_on_signal(struct event *ev, void *ud,
                         void (*on_signal)(void *ud, struct event *ev))
{
    ev->on_signal_ud = ud;
    ev->on_signal = on_signal;
}

static void event_set(struct event *ev, bool signaled)
{
    bool need_wakeup = false;

    pthread_mutex_lock(&ev->item->owner->lock);
    if (ev->signaled != signaled) {
        ev->signaled = signaled;
        need_wakeup |= signaled; // only when triggered
    }
    pthread_mutex_unlock(&ev->item->owner->lock);

    if (need_wakeup)
        wakeup_event_loop(ev->item->owner);
}

void event_signal(struct event *ev)
{
    event_set(ev, true);
}

void event_reset(struct event *ev)
{
    event_set(ev, false);
}

static void ev_notifier_on_notify(void *ud)
{
    struct event *ev = ud;
    event_signal(ev);
}

static void ev_notifier_on_destroy(void *ud)
{
    struct event *ev = ud;
    pthread_mutex_lock(&ev->item->owner->lock);
    ev->notifier = NULL;
    pthread_mutex_unlock(&ev->item->owner->lock);
}

void event_set_notifier(struct event *ev, struct notifier *nf)
{
    bool need_signal = false;
    pthread_mutex_lock(&ev->item->owner->lock);

    if (ev->notifier != nf) {

        if (ev->notifier) {
            notifier_remove(ev->notifier, ev->notifier_id);
            ev->notifier = NULL;
        }

        if (nf) {
            ev->notifier = nf;
            ev->notifier_id = notifier_xadd(ev->notifier,
                ev, ev_notifier_on_notify, ev_notifier_on_destroy);
            int64_t count = 0;
            notifier_wait(ev->notifier, &count, NULL);
            need_signal |= count > 0;
        }
    }

    pthread_mutex_unlock(&ev->item->owner->lock);

    if (need_signal)
        event_signal(ev);
}

void event_destroy(struct event *ev)
{
    if (!ev)
        return;
    event_set_notifier(ev, NULL);
    event_loop_remove_item(ev->item);
}

static void pipe_work(struct event_loop_item *item)
{
    struct pipe *p = item->priv;

    unsigned events = 0;

    if (p->os.can_read) {
        if (p->flags & PIPE_FLAG_SERVE) {
            if (!p->can_accept)
                events |= PIPE_EVENT_NEW_CLIENT;
            p->can_accept = true;
        } else if (p->flags & PIPE_FLAG_READ) {
            if (p->read_buf.size && !p->force_read) {
                // ignore until something changes
            } else if (buffer_reserve(&p->read_buf, 4 * 1024)) {
                size_t r = os_pipe_read(&p->os, buffer_end(&p->read_buf),
                                        buffer_available_size(&p->read_buf));
                if (r) {
                    p->read_buf.size += r;
                    events |= PIPE_EVENT_NEW_DATA;
                    p->os.can_read = false; // retrigger
                }
            } else {
                events |= PIPE_EVENT_ERROR;
            }
            p->force_read = false;
        }
    }

    if (p->os.error || (events & PIPE_EVENT_ERROR)) {
        events |= PIPE_EVENT_ERROR;
        p->os.error = false;

        // Treat as closed.
        p->os.flags &= ~(unsigned)(PIPE_FLAG_READ | PIPE_FLAG_WRITE);
    }

    if (p->os.can_write && (p->flags & PIPE_FLAG_WRITE) && p->write_buf.size) {
        size_t r = os_pipe_write(&p->os, p->write_buf.data, p->write_buf.size);
        buffer_skip(&p->write_buf, r);
        if (!p->write_buf.size)
            events |= PIPE_EVENT_ALL_WRITTEN;
        p->os.can_write = false; // retrigger
    }

    if ((p->flags & PIPE_FLAG_READ) && !(p->os.flags & PIPE_FLAG_READ) &&
        !p->read_buf.size)
    {
        p->flags &= ~(unsigned)PIPE_FLAG_READ;
        events |= PIPE_EVENT_CLOSED_READ;
    }

    if ((p->flags & PIPE_FLAG_WRITE) && !(p->os.flags & PIPE_FLAG_WRITE)) {
        p->flags &= ~(unsigned)PIPE_FLAG_WRITE;
        events |= PIPE_EVENT_CLOSED_WRITE;
        if (p->write_buf.size)
            events |= PIPE_EVENT_ERROR;
        p->write_buf.size = 0;
    }

    if (p->close_on_write_done && (events & PIPE_EVENT_ALL_WRITTEN)) {
        pipe_destroy(p);
        return;
    }

    if (p->on_event && events)
        p->on_event(p->on_event_ud, p, events);
}

static struct pipe *alloc_pipe(struct event_loop *ev)
{
    struct event_loop_item *item = event_loop_add_item(ev);
    if (!item)
        return NULL;
    item->priv = &item->alloc_.st_pipe;
    item->work = pipe_work;
    struct pipe *p = item->priv;
    *p = (struct pipe){
        .item = item,
        .os = OS_PIPE_INIT,
    };
    p->os.item = &item->os;
    item->os.is_pipe = &p->os;
    return p;
}

struct pipe *event_loop_open_pipe(struct event_loop *ev, const char *filename,
                                  unsigned flags)
{
    if (flags & PIPE_FLAG_SERVE) {
        if (flags & ~(unsigned)PIPE_FLAG_SERVE)
            return NULL;
    } else if (flags & (PIPE_FLAG_READ | PIPE_FLAG_WRITE)) {
        if (flags & ~(unsigned)(PIPE_FLAG_READ | PIPE_FLAG_WRITE |
                                PIPE_FLAG_FILENAME_IS_FD | PIPE_FLAG_OPEN_BLOCK))
            return NULL;
    } else {
        return NULL;
    }

    struct pipe *p = alloc_pipe(ev);
    if (!p)
        return NULL;

    p->os.flags = p->flags = flags;
    p->os.filename = strdup(filename);
    if (!p->os.filename) {
        pipe_destroy(p);
        return NULL;
    }

    if (!os_pipe_init(&p->os)) {
        pipe_destroy(p);
        return NULL;
    }

    p->flags = p->os.flags;

    return p;
}

unsigned pipe_get_mode(struct pipe *p)
{
    return p->flags;
}

struct pipe *pipe_accept(struct pipe *p)
{
    p->can_accept = false;

    struct pipe *np = alloc_pipe(p->item->owner);
    if (!np)
        return NULL;

    if (!os_pipe_init_client(&np->os, &p->os)) {
        os_pipe_destroy(&np->os);
        return NULL;
    }

    np->flags = np->os.flags;
    return np;
}

void pipe_destroy(struct pipe *p)
{
    if (!p)
        return;
    os_pipe_destroy(&p->os);
    free((void *)p->os.filename);
    buffer_dealloc(&p->read_buf);
    buffer_dealloc(&p->write_buf);
    event_loop_remove_item(p->item);
}

void pipe_drain_destroy(struct pipe *p)
{
    if (p && p->write_buf.size) {
        p->close_on_write_done = true;
        p->on_event = NULL;
        return;
    }
    pipe_destroy(p);
}

void pipe_set_on_event(struct pipe *p, void *ud,
                       void (*on_event)(void *ud, struct pipe *p, unsigned events))
{
    p->on_event_ud = ud;
    p->on_event = on_event;
    p->item->has_work = true;
}

size_t pipe_read(struct pipe *p, void *buf, size_t buf_size)
{
    buf_size = MIN(buf_size, p->read_buf.size);
    if (buf_size && buf)
        memcpy(buf, p->read_buf.data, buf_size);
    buffer_skip(&p->read_buf, buf_size);
    if (buf_size)
        p->os.can_read = false; // retrigger
    return buf_size;
}

void pipe_peek(struct pipe *p, void **buf, size_t *buf_size)
{
    *buf = p->read_buf.data;
    *buf_size = p->read_buf.size;
}

void pipe_read_more(struct pipe *p)
{
    p->force_read = true;
}

bool pipe_write(struct pipe *p, void *buf, size_t buf_size)
{
    if (!(p->flags & PIPE_FLAG_WRITE))
        return false;
    if (!buf_size)
        return true;
    p->os.can_write = false; // retrigger
    return buffer_append(&p->write_buf, buf, buf_size);
}

bool pipe_get_all_written(struct pipe *p)
{
    return !p->write_buf.size;
}

bool pipe_isatty(struct pipe *p)
{
    return os_pipe_isatty(&p->os);
}
