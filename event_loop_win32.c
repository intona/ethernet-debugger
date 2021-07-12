// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <windows.h>

#include "event_loop_internal.h"
#include "utils.h"

// Used for the send and receive buffers. Since "overlapped" I/O requires that
// we do not modify the buffer, but we don't want a mess by making the common
// event loop code to try to guarantee this, we always copy into this buffer.
#define TMP_BUF_SIZE (32 * 1024)

bool os_event_loop_init(struct os_event_loop *el)
{
    pthread_mutex_init(&el->con_mutex, NULL);
    pthread_cond_init(&el->con_cond, NULL);

    el->wakeup_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (el->wakeup_event == INVALID_HANDLE_VALUE)
        return false;

    el->ioport = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!el->ioport)
        return false;

    return true;
}

void os_event_loop_destroy(struct os_event_loop *el)
{
    CloseHandle(el->wakeup_event);
    pthread_cond_destroy(&el->con_cond);
    pthread_mutex_destroy(&el->con_mutex);
}

static void handle_io_cp_result(struct os_event_loop *el,
                                struct overlapped_info *oi,
                                BOOL ret, DWORD error, DWORD res)
{
    assert(!oi->pending);
    struct os_event_loop_item *item = oi->item;

    if (ret)
        error = 0;

    if (item->is_pipe) {
        struct os_pipe *p = item->is_pipe;

        if (oi == &p->oi_s) {
            if (error == ERROR_PIPE_CONNECTED)
                error = 0; // Windows likes being funny
            if (error) {
                p->error = true;
            } else {
                p->can_read = true;
                item->has_work = true;
            }
        } else if (oi == &p->oi_r) {
            if (error == ERROR_BROKEN_PIPE) {
                p->flags &= ~(unsigned)PIPE_FLAG_READ;
            } else if (error) {
                p->error = true;
            } else {
                p->r_buf_size = res;
            }
            if (p->r_buf_size) {
                p->can_read = true;
                item->has_work = true;
            }
        } else if (oi == &p->oi_w) {
            if (error == ERROR_NO_DATA) {
                p->flags &= ~(unsigned)PIPE_FLAG_WRITE;
            } else {
                p->error |= !!error;
            }
            p->w_buf_size = 0;
            p->can_write = true;
            item->has_work = true;
        } else {
            assert(0);
        }

        item->has_work |= p->error;
    }

    oi->ol = (OVERLAPPED){0};
}

// Handle result after an async. I/O call was made. This normally sets only the
// pending flag. But if it completes with a synchronous error, it gets no
// completion notification, and we need to handle it directly.
static void handle_io_result(struct os_event_loop *el,
                             struct overlapped_info *oi,
                             BOOL ret, DWORD error, DWORD res)
{
    assert(!oi->pending);
    if (!ret && error == ERROR_IO_PENDING) {
        // Should never happen; or caller error (not using handle_io_ov_result()).
        assert(false);
    } else {
        handle_io_cp_result(el, oi, ret, error, res);
    }
}

// Using overlapped I/O with IOCP behave slightly differently: a success result
// (not pending) will end up in a IOCP notification anyway.
// Errors might (?) still yield a direct result, this is unknown.
static void handle_io_ov_result(struct os_event_loop *el,
                                struct overlapped_info *oi,
                                BOOL ret, DWORD error)
{
    assert(!oi->pending);
    if (ret || error == ERROR_IO_PENDING) {
        oi->pending = true;
    } else {
        handle_io_cp_result(el, oi, ret, error, 0);
    }
}

void os_event_loop_wait(struct os_event_loop *el, int64_t timeout)
{
    for (size_t n = 0; n < el->num_items; n++) {
        struct os_event_loop_item *item = el->items[n];

        if (item->is_pipe) {
            struct os_pipe *p = item->is_pipe;

            if (p->io_mode == IO_IOCP) {
                if (p->flags & PIPE_FLAG_SERVE) {
                    if (!p->oi_s.pending && !p->can_read) {
                        BOOL ret = ConnectNamedPipe(p->handle, &p->oi_s.ol);
                        handle_io_ov_result(el, &p->oi_s, ret, GetLastError());
                    }
                }

                if (p->flags & PIPE_FLAG_READ) {
                    if (!p->oi_r.pending && !p->r_buf_size) {
                        // Start new read operation.
                        BOOL ret = ReadFile(p->handle, p->r_buf, TMP_BUF_SIZE,
                                            NULL, &p->oi_r.ol);
                        handle_io_ov_result(el, &p->oi_r, ret, GetLastError());
                    }
                }

                if (!p->oi_w.pending && (p->flags & PIPE_FLAG_WRITE) &&
                    p->w_buf_size)
                {
                    // Start new write operation.
                    BOOL ret = WriteFile(p->handle, p->w_buf, p->w_buf_size,
                                         NULL, &p->oi_w.ol);
                    handle_io_ov_result(el, &p->oi_w, ret, GetLastError());
                }
            } else if (p->io_mode == IO_DIRECT) {
                if ((p->flags & PIPE_FLAG_READ) && !p->r_buf_size) {
                    DWORD readres;
                    BOOL ret = ReadFile(p->handle, p->r_buf, TMP_BUF_SIZE,
                                        &readres, NULL);
                    handle_io_result(el, &p->oi_r, ret, GetLastError(), readres);
                }

                if ((p->flags & PIPE_FLAG_WRITE) && p->w_buf_size) {
                    DWORD writeres;
                    BOOL ret = WriteFile(p->handle, p->w_buf, p->w_buf_size,
                                         &writeres, NULL);
                    handle_io_result(el, &p->oi_w, ret, GetLastError(), writeres);
                }
            } else if (p->io_mode == IO_CON_IN) {
                assert(el->con_pipe == p);
                pthread_mutex_lock(&el->con_mutex);
                BOOL ret = !el->con_failed;
                DWORD readres = ret && !p->r_buf_size ? el->con_buf_avail : 0;
                if (readres) {
                    assert(readres <= TMP_BUF_SIZE);
                    memcpy(p->r_buf, el->con_buf, readres);
                    el->con_buf_avail = 0;
                }
                if (!ret || readres)
                    handle_io_result(el, &p->oi_r, ret, el->con_error, readres);
                pthread_cond_broadcast(&el->con_cond);
                pthread_mutex_unlock(&el->con_mutex);
            }

            // refresh if it was reset by common code
            if (p->r_buf_size && !p->can_read) {
                p->can_read = true;
                item->has_work = true;
            }
            if (!p->w_buf_size && !p->can_write) {
                p->can_write = true;
                item->has_work = true;
            }
        }

        if (item->has_work)
            timeout = 0;
    }

    uint64_t now = get_monotonic_time_us();
    DWORD wait_ms = INFINITE;
    if (timeout < now) {
        wait_ms = 0;
    } else {
        uint64_t wait_ms64 = (timeout - now) / 1000;
        if (wait_ms64 < INT32_MAX)
            wait_ms = wait_ms64;
    }

    HANDLE handles[] = {el->wakeup_event, el->ioport};
    DWORD r = WaitForMultipleObjects(ARRAY_LENGTH(handles), handles, FALSE, wait_ms);

    switch (r) {
    case WAIT_OBJECT_0:
    case WAIT_TIMEOUT:
        // Nothing to do, just re-serve event loop items.
        break;
    case WAIT_OBJECT_0 + 1: {
        // Service I/O completion port.
        while (1) {
            ULONG_PTR key = 0;
            OVERLAPPED *ol;
            DWORD res;
            BOOL ret = GetQueuedCompletionStatus(el->ioport, &res, &key, &ol, 0);
            if (!ol)
                break;
            DWORD err = GetLastError();
            struct overlapped_info *oi = (struct overlapped_info *)ol;
            assert(oi->magic == OVERLAPPED_MAGIC);
            assert(oi->pending);
            oi->pending = false;
            handle_io_cp_result(el, oi, ret, err, res);
        }
        break;
    }
    default:
        assert(0);
    }
}

void os_event_loop_wakeup(struct os_event_loop *el)
{
    SetEvent(el->wakeup_event);
}

static bool init_pipe(struct os_pipe *p)
{
    p->r_buf = malloc(TMP_BUF_SIZE * 2);
    if (!p->r_buf)
        return false;
    p->w_buf = p->r_buf + TMP_BUF_SIZE;
    p->oi_r = (struct overlapped_info){
        .item = p->item,
        .magic = OVERLAPPED_MAGIC,
    };
    p->oi_w = (struct overlapped_info){
        .item = p->item,
        .magic = OVERLAPPED_MAGIC,
    };
    p->oi_s = (struct overlapped_info){
        .item = p->item,
        .magic = OVERLAPPED_MAGIC,
    };
    p->io_mode = IO_IOCP;
    p->close_handle = true;
    return true;
}

static void create_new_server_pipe(struct os_pipe *p)
{
    assert(!p->handle);

    p->handle = CreateNamedPipeA(p->filename, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, 16, 16, 0, NULL);

    if (p->handle == INVALID_HANDLE_VALUE)
        p->handle = NULL;
}

static bool add_to_iocp(struct os_pipe *p)
{
    return CreateIoCompletionPort(p->handle, p->item->owner->ioport, 0, 0);
}

static void *con_thread(void *ptr)
{
    struct os_event_loop *ev = ptr;

    while (1) {
        uint8_t buf[64];

        pthread_mutex_lock(&ev->con_mutex);
        while (ev->con_buf_avail && !ev->con_req_stop)
            pthread_cond_wait(&ev->con_cond, &ev->con_mutex);
        bool dead = ev->con_req_stop;
        pthread_mutex_unlock(&ev->con_mutex);

        if (dead)
            break;

        DWORD readres = 0, errres = 0;
        if (!ReadFile(ev->con_pipe->handle, &buf, sizeof(buf), &readres, NULL)) {
            errres = GetLastError();
            dead = true;
            readres = 0;
        }

        pthread_mutex_lock(&ev->con_mutex);
        ev->con_buf_avail = readres;
        memcpy(ev->con_buf, buf, readres);
        ev->con_failed = dead;
        ev->con_error = errres;
        pthread_mutex_unlock(&ev->con_mutex);
        os_event_loop_wakeup(ev);

        if (dead)
            break;
    }

    return NULL;
}

static void con_stop(struct os_event_loop *ev)
{
    assert(ev->con_pipe);

    pthread_mutex_lock(&ev->con_mutex);
    ev->con_req_stop = true;
    bool might_be_blocked = !ev->con_failed && !ev->con_buf_avail;
    pthread_cond_broadcast(&ev->con_cond);
    pthread_mutex_unlock(&ev->con_mutex);

    if (might_be_blocked) {
        // Try to unblock the ReadFile() call.
        // This uses the same hack as libuv uses.
        // In theory, we want to send it only if the call is really blocked. In some
        // cases, the event might not be read by us, but by cmd.exe (after we
        // exited); this is an unavoidable race condition.
        DWORD w = 0;
        INPUT_RECORD rec = {
            .EventType = KEY_EVENT,
            .Event = {
                .KeyEvent = {
                    .bKeyDown = TRUE,
                    .wRepeatCount = 1,
                    .uChar = {
                        .UnicodeChar = L'\r',
                    },
                },
            },
        };
        WriteConsoleInputW(ev->con_pipe->handle, &rec, 1, &w);
    }

    pthread_join(ev->con_thread, NULL);
    ev->con_pipe = NULL;
}

bool os_pipe_init(struct os_pipe *p)
{
    struct os_event_loop *ev = p->item->owner;

    if (!init_pipe(p))
        return false;

    if (p->flags & PIPE_FLAG_SERVE) {
        create_new_server_pipe(p);
        if (!p->handle)
            return false;
    } else if (strcmp(p->filename, "/dev/stdin") == 0) {
        if (ev->con_pipe)
            return false; // only at most 1
        ev->con_pipe = p;
        p->handle = GetStdHandle(STD_INPUT_HANDLE);
        p->io_mode = IO_CON_IN;
        p->close_handle = false;
        if (pthread_create(&ev->con_thread, NULL, con_thread, ev)) {
            ev->con_pipe = NULL;
            return false;
        }
    } else if (strcmp(p->filename, "/dev/stdout") == 0) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        // Call a random simple console API to check whether it's a console.
        if (!GetConsoleMode(h, &(DWORD){0}))
            return false; // probably not a console, refuse function
        p->handle = h;
        p->io_mode = IO_DIRECT; // just assume it's essentially non-blocking
        p->close_handle = false;
    } else {
        DWORD access = 0;
        if (p->flags & PIPE_FLAG_READ)
            access |= GENERIC_READ;
        if (p->flags & PIPE_FLAG_WRITE)
            access |= GENERIC_WRITE;
        p->handle = CreateFileA(p->filename, access, 0,
            NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    }

    assert(p->handle != NULL); // let's hope
    if (p->handle == INVALID_HANDLE_VALUE) {
        p->handle = NULL;
        return false;
    }

    if (p->io_mode == IO_IOCP && !add_to_iocp(p))
        return false;

    return true;
}

bool os_pipe_isatty(struct os_pipe *p)
{
    return p->io_mode == IO_CON_IN;
}

bool os_pipe_init_client(struct os_pipe *p, struct os_pipe *server)
{
    if (!init_pipe(p))
        return false;

    if (!server->can_read)
        return false;
    server->can_read = false;

    // Unlike with unix domain sockets, the "listening" socket handle becomes
    // the handle to communicate with, and you need to create a new listening
    // handle. If the latter fails, disconnect and restore it as server handle.
    p->handle = server->handle;
    server->handle = NULL;
    create_new_server_pipe(server);
    if (server->handle && !add_to_iocp(server)) {
        CloseHandle(server->handle);
        server->handle = NULL;
    }
    if (!server->handle) {
        DisconnectNamedPipe(p->handle);
        server->handle = p->handle;
        p->handle = NULL;
        return false;
    }

    p->flags = PIPE_FLAG_READ | PIPE_FLAG_WRITE;
    return true;
}

void os_pipe_destroy(struct os_pipe *p)
{
    struct os_event_loop *ev = p->item->owner;

    if (ev->con_pipe == p)
        con_stop(ev);

    if (p->close_handle)
        CloseHandle(p->handle);
    free(p->r_buf);
}

size_t os_pipe_read(struct os_pipe *p, void *buf, size_t buf_size)
{
    if (!p->can_read)
        return 0;
    assert(!p->oi_r.pending);

    size_t copy = MIN(buf_size, p->r_buf_size);
    if (!copy)
        return 0;

    memcpy(buf, p->r_buf, copy);
    memmove(buf, buf + copy, p->r_buf_size - copy);
    p->r_buf_size -= copy;
    p->can_read = p->r_buf_size > 0;
    return copy;
}

size_t os_pipe_write(struct os_pipe *p, void *buf, size_t buf_size)
{
    if (!p->can_write)
        return 0;
    assert(!p->oi_w.pending);
    assert(!p->w_buf_size);

    size_t copy = MIN(buf_size, TMP_BUF_SIZE);
    if (!copy)
        return 0;

    memcpy(p->w_buf, buf, copy);
    p->w_buf_size = copy;
    p->can_write = false;
    return copy;
}

char *pipe_format_pipe_path(const char *name)
{
    return xasprintf("\\\\.\\pipe\\%s", name);
}
