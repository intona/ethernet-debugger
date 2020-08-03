// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <limits.h>
#include <poll.h>
#include <unistd.h>

#include "event_loop_internal.h"
#include "utils.h"

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

bool os_event_loop_init(struct os_event_loop *el)
{
    if (pipe(el->wakeup_pipe)) {
        el->wakeup_pipe[0] = el->wakeup_pipe[1] = -1;
        return false;
    }
    for (size_t n = 0; n < 2; n++) {
        fcntl(el->wakeup_pipe[n], F_SETFD, O_CLOEXEC);
        fcntl(el->wakeup_pipe[n], F_SETFL, O_NONBLOCK);
    }
    return true;
}

void os_event_loop_destroy(struct os_event_loop *el)
{
    if (el->wakeup_pipe[0] >= 0)
        close(el->wakeup_pipe[0]);
    if (el->wakeup_pipe[1] >= 0)
        close(el->wakeup_pipe[1]);
}

void os_event_loop_wait(struct os_event_loop *el, int64_t timeout)
{
    struct pollfd poll_fds[MAX_ITEMS + 1];
    struct os_event_loop_item *poll_fds_item[MAX_ITEMS]; // map poll_fds index
    size_t num_poll_fds = 0;

    for (size_t n = 0; n < el->num_items; n++) {
        struct os_event_loop_item *item = el->items[n];
        struct pollfd poll_fd = {.fd = -1};

        if (item->is_pipe) {
            struct os_pipe *p = item->is_pipe;

            // Add only if still connected (avoids POLLHUP).
            if (p->flags & (PIPE_FLAG_READ | PIPE_FLAG_WRITE | PIPE_FLAG_SERVE))
                poll_fd.fd = p->fd;

            if (!p->can_read && (p->flags & (PIPE_FLAG_READ | PIPE_FLAG_SERVE)))
                poll_fd.events |= POLLIN;

            if (!p->can_write && (p->flags & PIPE_FLAG_WRITE))
                poll_fd.events |= POLLOUT;
        }

        if (poll_fd.fd >= 0) {
            poll_fds_item[num_poll_fds] = item;
            poll_fds[num_poll_fds] = poll_fd;
            num_poll_fds += 1;
        }
    }

    poll_fds[num_poll_fds++] = (struct pollfd){
        .fd = el->wakeup_pipe[0],
        .events = POLLIN,
    };

    uint64_t now = get_monotonic_time_us();
    int poll_timeout = -1;
    if (timeout < now) {
        poll_timeout = 0;
    } else {
        uint64_t wait_ms = (timeout - now) / 1000;
        if (wait_ms < INT_MAX)
            poll_timeout = wait_ms;
    }

    poll(poll_fds, num_poll_fds, poll_timeout);

    // Wakeup pipe. This must happen first, or a full pipe will make it lose
    // wakeups.
    if (poll_fds[num_poll_fds - 1].revents) {
        char t[16];
        while (read(el->wakeup_pipe[0], t, sizeof(t)) > 0) {} // clear
    }

    // Flag poll() results.
    for (size_t n = 0; n < num_poll_fds - 1; n++) {
        struct os_event_loop_item *item = poll_fds_item[n];
        int revents = poll_fds[n].revents;

        if (item->is_pipe) {
            struct os_pipe *p = item->is_pipe;

            p->can_read |= !!(revents & POLLIN);
            p->can_write |= !!(revents & POLLOUT);
            if ((revents & POLLHUP) && !(revents & POLLIN))
                p->flags &= ~(unsigned)(PIPE_FLAG_READ | PIPE_FLAG_WRITE);
            item->has_work |= !!revents; // only on changes
        }
    }
}

void os_event_loop_wakeup(struct os_event_loop *el)
{
    (void)write(el->wakeup_pipe[1], &(char){0}, 1); // interrupt poll()
}

static int make_socket(void)
{
#ifdef SOCK_NONBLOCK
    return socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd >= 0)
        fcntl(fd, F_SETFL, O_NONBLOCK);
    return fd;
#endif
}

bool os_pipe_init(struct os_pipe *p)
{
    // Don't kill us when trying to read() from a closed connection.
    struct sigaction new_action = {
        .sa_handler = SIG_IGN,
    };
    sigemptyset(&new_action.sa_mask);
    sigaction(SIGPIPE, &new_action, NULL);

    struct sockaddr_un addr = { .sun_family = AF_UNIX, };
    size_t path_len = strlen(p->filename);
    size_t addr_len = 0;
    if (path_len < sizeof(addr.sun_path)) {
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", p->filename);
        addr.sun_path[path_len] = '\0';
        addr_len = sizeof(addr);
    }

    if (p->flags & PIPE_FLAG_SERVE) {
        if (!addr_len)
            return false;

        unlink(p->filename);

        p->fd = make_socket();
        if (p->fd < 0)
            return false;

        if (bind(p->fd, (struct sockaddr *)&addr, addr_len) < 0)
            return false;

        if (listen(p->fd, 10) < 0)
            return false;
    } else {
        struct stat st;
        if (p->flags & PIPE_FLAG_FILENAME_IS_FD) {
            char *end;
            long l = strtoul(p->filename, &end, 0);
            if (end[0] || l < 0 || l > INT_MAX)
                return false;
            p->fd = l;
        } else if (!stat(p->filename, &st) && S_ISSOCK(st.st_mode)) {
            if (!addr_len)
                return false;
            // In UNIX, everything is a file, except when it's only half a file.
            p->fd = make_socket();
            if (p->fd < 0)
                return false;

            if (connect(p->fd, (struct sockaddr *)&addr, addr_len) < 0)
                return false;
        } else if (strcmp(p->filename, "/dev/stdin") == 0) {
            // Not all UNIXes have /dev/stdin, so treat it specially.
            p->fd = dup(0); // we want to close() it later, so just dup() it
        } else if (strcmp(p->filename, "/dev/stdout") == 0) {
            // As above.
            p->fd = dup(1);
        } else {
            int unix_flags = O_CLOEXEC;
            // O_NONBLOCK is specifically for making open() itself not block.
            if (!(p->flags & PIPE_FLAG_OPEN_BLOCK))
                unix_flags |= O_NONBLOCK;

            if ((p->flags & PIPE_FLAG_READ) && (p->flags & PIPE_FLAG_WRITE)) {
                unix_flags |= O_RDWR;
            } else if (p->flags & PIPE_FLAG_READ) {
                unix_flags |= O_RDONLY;
            } else if (p->flags & PIPE_FLAG_WRITE) {
                unix_flags |= O_WRONLY;
            }

            p->fd = open(p->filename, unix_flags, 0);
            if (p->fd >= 0)
                fcntl(p->fd, F_SETFL, O_NONBLOCK);
        }
    }

    if (p->fd < 0)
        return false;

    return true;
}

bool os_pipe_init_client(struct os_pipe *p, struct os_pipe *server)
{
    if (!server->can_read)
        return false;
    server->can_read = false;

    p->fd = accept(server->fd, NULL, NULL);
    if (p->fd < 0)
        return false;

    fcntl(p->fd, F_SETFL, O_NONBLOCK);

    p->flags = PIPE_FLAG_READ | PIPE_FLAG_WRITE;
    return true;
}

void os_pipe_destroy(struct os_pipe *p)
{
    if (p->fd >= 0)
        close(p->fd);
}

size_t os_pipe_read(struct os_pipe *p, void *buf, size_t buf_size)
{
    if (!p->can_read || !buf_size)
        return 0;
    p->can_read = false;

    ssize_t r = read(p->fd, buf, buf_size);
    if (r < 0) {
        p->error = true;
        r = 0;
    } else if (r == 0) {
        p->flags &= ~(unsigned)PIPE_FLAG_READ;
    }

    return r;
}

size_t os_pipe_write(struct os_pipe *p, void *buf, size_t buf_size)
{
    if (!p->can_write || !buf_size)
        return 0;
    p->can_write = false;

    ssize_t r = write(p->fd, buf, buf_size);
    if (r < 0) {
        if (errno == EPIPE) {
            p->flags &= ~(unsigned)PIPE_FLAG_WRITE;
        } else {
            p->error = true;
        }
        r = 0;
    }

    return r;
}

char *pipe_format_pipe_path(const char *name)
{
    return xasprintf("/tmp/%s.socket", name);
}
