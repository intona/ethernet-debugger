// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef EVENT_LOOP_H_
#define EVENT_LOOP_H_

#include <stdbool.h>
#include <stddef.h>

struct notifier;

// This is intended to manage multiple pipes/sockets using a single thread, and
// in a portable way between POSIX and win32.
// It's intended for low-performance stuff. It's not adequate for high
// performance (too much copying, single threaded), or high connection counts
// (it's just... simple).
// Conventions:
//  - Callback-driven (unfortunately; restriction of C).
//  - For single threaded use cases, but has mechanisms to interact with other
//    threads.
//  - API is not thread-safe. But some functions marked as thread-safe are.
//  - The event loop itself is callback-driven.
//  - Nothing within the event loop or the user callbacks ever blocks.
//  - Callbacks are never called recursively (and only from the event loop
//    directly) to avoid reentrancy issues.
//  - All callbacks have user-data attached ("ud" parameter), which is not
//    interpreted, and passed to the associated callback only.
//  - Most callbacks can free the object they were called from (for example:
//    an on_timer(ud, t) callback can call timer_destroy(t)).
struct event_loop;

// Returns NULL on failure (OOM).
struct event_loop *event_loop_create(void);

// Enter the event loop, and return only when it's terminated.
void event_loop_run(struct event_loop *ev);

// Deallocate ev. This is not allowed while event_loop_run() is being called.
void event_loop_destroy(struct event_loop *ev);

// This sends a thread-safe signal to the event loop that it should exit. It will
// do so once all outstanding work is finished.
// This function is thread-safe and can be called from any thread.
void event_loop_request_terminate(struct event_loop *ev);

// Whether something else called event_loop_request_terminate().
bool event_loop_is_terminate_pending(struct event_loop *ev);

// This makes the event loop exit. Normally, if you want to shut it down
// properly, you should call event_loop_request_terminate(), and the
// on_terminate callback should call this function after it has made sure
// everything is properly deinitialized.
// Objects that still exist on exit are destroyed automatically, and before
// event_loop_run() returns.
void event_loop_exit(struct event_loop *ev);

// Set callback for event_loop_request_terminate(). This is always called from
// the event loop. It is called only once (and further requests do nothing). It
// is expected that this function either calls event_loop_exit(), or causes it
// to be called at a later point (e.g. if the exit process involves further
// waiting on external events).
void event_loop_set_on_terminate(struct event_loop *ev, void *ud,
                        void (*on_terminate)(void *ud, struct event_loop *ev));

// Set callback to run if the event loop would wait for some future event (such
// as input arriving, more data being written to output, timer timeouts). This
// is explicitly not called if there are any events or timeouts to be handled,
// only if the lowest level OS wait call (such as poll()) is most likely
// actually going to wait.
// The callback itself should be careful about not creating new work all the
// time, because this would cause the idle loop be called again after the new
// work has been handled. This could lead to burning CPU time for no reason.
// The callback is called very often, since wait times between events can be
// very short. The main purpose of the callback is to check the main loop logic
// for conditions, which can be changed by anything in the main loop, but which
// can be delayed until the main loop returns to doing nothing.
void event_loop_set_on_idle(struct event_loop *ev, void *ud,
                            void (*on_idle)(void *ud, struct event_loop *ev));

// Asynchronously invoke a callback on the event loop. This basically queues a
// message to the event loop, which then calls cb(). Typically, this function
// will return long before cb() runs, and you need to be careful.
// Returns false on failure (OOM).
bool event_loop_send_callback(struct event_loop *ev, void *ud, void (*cb)(void *ud));

// Periodic timer integrated into the event loop.
struct timer;

// Create a timer object. This does nothing on its own until parameters are set.
// Returns NULL on failure.
struct timer *event_loop_create_timer(struct event_loop *ev);

// Callback when the timeout elapses.
void timer_set_on_timer(struct timer *t, void *ud,
                        void (*on_timer)(void *ud, struct timer *t));

// Start or reset the timer. It fires after timeout_ms milliseconds, and
// restarts the timer before the on_timer callback is called (i.e. periodic).
// If you don't want a periodic timer, call timer_stop() in on_timer().
// timeout_ms<0 behaves like timeout_ms==0, which calls on_timer immediately.
void timer_start(struct timer *t, int timeout_ms);

// Do not call on_timer() anymore.
void timer_stop(struct timer *t);

// Deallocate t.
void timer_destroy(struct timer *t);

// A binary semaphore, useful for signaling from external threads to the event
// loop.
struct event;

// Returns NULL on failure.
struct event *event_loop_create_event(struct event_loop *ev);

// Set the function which will be called by the event loop if the event changes
// from not signaled to signaled. This resets the event before this is called.
void event_set_on_signal(struct event *ev, void *ud,
                         void (*on_signal)(void *ud, struct event *ev));

// This puts the event into the signaled state. It makes the event loop call the
// on_signal() callback. Signaling an already signaled event does nothing.
// This function is thread-safe and can be called from any thread.
void event_signal(struct event *ev);

// This removes the signaled state from the event.
// This function is thread-safe and can be called from any thread.
void event_reset(struct event *ev);

// Register the event to a notifier. If the notifier is triggered, then
// event_signal() is automatically called. If the notifier was triggered before
// this call, the event is immediately signaled.
// Destroying either the event or the notifier, or setting a different notifier
// (or NULL) safely disconnects them.
void event_set_notifier(struct event *ev, struct notifier *nf);

// Destroy the event; ev becomes invalid.
void event_destroy(struct event *ev);

// Usually a FD (POSIX) or HANDLE (win32).
struct pipe;

enum {
    PIPE_FLAG_READ = (1 << 0),  // can read from it
    PIPE_FLAG_WRITE = (1 << 1), // can write to it
    PIPE_FLAG_SERVE = (1 << 2), // neither; only accepts connections
    // For event_loop_open_pipe():
    // filename is a decimal number with a FD to use.
    PIPE_FLAG_FILENAME_IS_FD = (1 << 3),
    // if opening a FIFO, do not use O_NONBLOCK on opening
    // (does not affect other I/O; anything but opening is still async)
    PIPE_FLAG_OPEN_BLOCK = (1 << 4),
};

enum {
    // There is new data available for pipe_read().
    PIPE_EVENT_NEW_DATA     = (1 << 0),
    // Write buffer is empty (can be used to get some flow control).
    PIPE_EVENT_ALL_WRITTEN  = (1 << 1),
    // Read end was closed.
    // At least unix domain sockets (like most sockets) can close only one end
    // of the pipe, for example you could not write anymore, but still read,
    // and you may still want to read what's left. In this case, it pretends the
    // read end is still open as long as there is received data buffered.
    PIPE_EVENT_CLOSED_READ  = (1 << 2),
    // Write end was closed.
    PIPE_EVENT_CLOSED_WRITE = (1 << 3),
    // Any kind of true error (including OOM or OS errors).
    PIPE_EVENT_ERROR        = (1 << 4),
    // pipe_accept() will (most likely) return a new connection.
    PIPE_EVENT_NEW_CLIENT   = (1 << 5),
};

// Open FIFO/unix domain socket/named FIFO. If PIPE_FLAG_SERVE, this creates a
// unix domain socket (UNIX) or named FIFO (win32).
//  flags: combination of PIPE_FLAG_*.
// Returns NULL on failure.
struct pipe *event_loop_open_pipe(struct event_loop *ev, const char *filename,
                                  unsigned flags);

// Query connection read/write mode. Strictly returns only bit combinations of
// PIPE_FLAG_READ/PIPE_FLAG_WRITE/PIPE_FLAG_SERVE, or 0 if fully disconnected.
unsigned pipe_get_mode(struct pipe *p);

// Set a callback to be invoked if anything changes, such as new data arriving.
// events it a bit mask of PIPE_EVENT_* flags (multiple events can happen at the
// same time).
void pipe_set_on_event(struct pipe *p, void *ud,
                       void (*on_event)(void *ud, struct pipe *p, unsigned events));

// Copy buf_size bytes from the internal read buffer, and return how many bytes
// could be read. May return less than requested. Does not wait/block.
// If buf==NULL, then simply skip buf_size bytes in the current buffer.
size_t pipe_read(struct pipe *p, void *buf, size_t buf_size);

// Return the internal read buffer. *buf_size is set to the size of the valid
// part of the buffer, which contains data that was not read by the user yet.
// The pointer is valid until the next read buffer access to this pipe, or until
// the pipe is destroyed, or until the next event loop iteration.
void pipe_peek(struct pipe *p, void **buf, size_t *buf_size);

// Instruct the event loop to read more data, even if there's still data in the
// read buffer.
void pipe_read_more(struct pipe *p);

// Append buf[0..buf_size] to the internal write buffer. The write buffer has a
// potentially unbounded size, and writing only fails if memory allocation
// fails.
// Returns success (failure only on OOM or if pipe closed).
bool pipe_write(struct pipe *p, void *buf, size_t buf_size);

// Return true if the write buffer is currently empty. Can be used for flow
// control.
bool pipe_get_all_written(struct pipe *p);

// Call istty() or equivalent on the underlying OS handle.
// errno is always invalid after this call.
bool pipe_isatty(struct pipe *p);

// Returns non-NULL if PIPE_EVENT_NEW_CLIENT event was flagged. May still return
// NULL otherwise, e.g. if there was an error on creating the new client handle.
// The caller owns the new pipe object, and is responsible for destroying it,
// managing events, etc.
// Requires pipe with PIPE_FLAG_SERVE.
struct pipe *pipe_accept(struct pipe *p);

// Close and destroy the pipe. After this call, p is invalid, and the user must
// not access it. (Internally, the struct may be kept a bit longer, as the
// event loop asynchronously closes it.)
// A pipe server stops serving, but client connections created from it are
// unaffected.
void pipe_destroy(struct pipe *p);

// Like pipe_destroy(), but let the event loop write the remaining buffered
// data, if possible. This does not block.
// You will not know about the success of the write operations.
// Like with pipe_destroy(), the p pointer is considered invalid immediately,
// even if it may linger around for a while.
void pipe_drain_destroy(struct pipe *p);

// Add OS-specific prefixes/suffixes that are normally required or expected.
// UNIX, this prepends "/tmp/" and appends ".socket" (although no UNIX has such
// a requirement), while for win32 it prepends the abstract pipe namespace (they
// can't even be on the filesystem, so for win32, event_loop_open_pipe()
// requires such a path).
// The return value must be free'd with free().
char *pipe_format_pipe_path(const char *name);

#endif
