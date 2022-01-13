// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef EVENT_LOOP_INTERNAL_H_
#define EVENT_LOOP_INTERNAL_H_

#include "event_loop.h"
#include "utils.h"

// Static limit on total number of event loop objects.
// For now, this simplifies a lot.
#define MAX_ITEMS 15
#define MAX_MESSAGES 10

#if !HAVE_POSIX

#include <windows.h>

#define OVERLAPPED_MAGIC 0xfcc1fb4614eef007

// Note: we cast OVERLAPPED received from os_event_loop.cport to this structure
//       to determine which operation this was.
struct overlapped_info {
    OVERLAPPED ol;      // pointer passed to win32 API
    uint64_t magic;
    bool pending;       // ol is _not_ available for use
    struct os_event_loop_item *item; // originating pipe/whatever
};

enum io_mode {
    IO_IOCP,
    IO_DIRECT,
    IO_CON_IN,
};

#endif

struct os_pipe {
    struct os_event_loop_item *item;
    const char *filename;           // non-NULL for PIPE_FLAG_SERVE

    unsigned flags;                 // PIPE_FLAG_* bit field; unset by OS code
                                    // on closed connection (or endpoint)

    bool error;                     // set on any fatal error

    bool can_write, can_read;       // set by OS code; common event loop code can
                                    // reset them; then they will be set again
                                    // immediately by OS code (level triggered),
                                    // but only a _change_ will wake it up.
                                    // Common code must never set them to true.

#if HAVE_POSIX
    int fd;
#else
    enum io_mode io_mode;
    HANDLE handle;
    bool close_handle;
    struct overlapped_info oi_r, oi_w, oi_s;
    size_t r_buf_size, w_buf_size;
    uint8_t *r_buf, *w_buf;
#endif
};

#if HAVE_POSIX
#define OS_PIPE_INIT { .fd = -1, }
#else
#define OS_PIPE_INIT { 0 }
#endif

struct os_event_loop_item {
    struct os_event_loop *owner;
    bool has_work;

    struct os_pipe *is_pipe;

#if HAVE_POSIX
    bool can_accept;
#else
#endif
};

struct os_event_loop {
    // -- Access from event loop thread only.
    // List managed by common code.
    struct os_event_loop_item *items[MAX_ITEMS];
    size_t num_items;

#if HAVE_POSIX
    // -- Immutable.
    int wakeup_pipe[2];
#else
    // -- Immutable.
    HANDLE wakeup_event;
    HANDLE ioport;
    pthread_mutex_t con_mutex;
    pthread_cond_t con_cond;
    struct os_pipe *con_pipe;
    uint8_t con_buf[64];
    size_t con_buf_avail;
    bool con_failed;
    bool con_req_stop;
    DWORD con_error;
    pthread_t con_thread;
#endif
};

bool os_event_loop_init(struct os_event_loop *el);
void os_event_loop_destroy(struct os_event_loop *el);
void os_event_loop_wait(struct os_event_loop *ml, int64_t timeout);
void os_event_loop_wakeup(struct os_event_loop *el);

bool os_pipe_init(struct os_pipe *p);
bool os_pipe_init_client(struct os_pipe *p, struct os_pipe *server);
void os_pipe_destroy(struct os_pipe *p);

// These are always non-blocking. Errors are signaled through os_pipe fields.
// If can_read/can_write are false, these just return 0.
size_t os_pipe_read(struct os_pipe *p, void *buf, size_t buf_size);
size_t os_pipe_write(struct os_pipe *p, void *buf, size_t buf_size);

bool os_pipe_isatty(struct os_pipe *p);

#endif
