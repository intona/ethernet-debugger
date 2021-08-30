// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef UTILS_H_
#define UTILS_H_

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// NB: it would be better to given these a prefix to avoid clashes.
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define CLAMP(v, min, max) ((v) < (min) ? (min) : ((v) > (max) ? (max) : (v)))

// Return val such that it is aligned to align, rounding down if necessary.
// align must be a power of 2.
#define ALIGN_POW2(val, align) ((val) & ~((align) - 1))

#define ARRAY_LENGTH(arr) (sizeof(arr) / sizeof((arr)[0]))

#if defined(_WIN32)
#define HAVE_POSIX 0
#else
#define HAVE_POSIX 1
#endif

#ifdef __GNUC__
    #if defined(__MINGW32__)
        #define PRINTF_FORMAT(a, b) __attribute__((format(gnu_printf, a, b)))
    #else
        #define PRINTF_FORMAT(a, b) __attribute__((format(printf, a, b)))
    #endif
#else
    #define PRINTF_FORMAT(a, b)
#endif

struct logfn {
    void *ctx;
    void (*fn)(void *ctx, const char *fmt, va_list va);
};

// Output text through the logfn. The convention is that the text as produced
// by printf(fmt, ...) contains exactly one line, terminated with a '\n'.
PRINTF_FORMAT(2, 3)
void logline(struct logfn ctx, const char *fmt, ...);

// For convenience: can be used with any kind of context struct, as long as
// that struct has a "struct logfn log;" field.
// Another convention is to terminate it with '\r', which depending on the log
// sink will actually output \r for e.g. showing progress messages.
#define LOG(ctx, ...) logline((ctx)->log, __VA_ARGS__)

// Similar convention as with LOG(), but (by convention) lower verbosity level.
#define HINT(ctx, ...) logline((ctx)->loghint, __VA_ARGS__)

// Write output to stdio. ctx is a FILE*. If ctx==NULL, stderr is used.
void logfn_stdio(void *ctx, const char *fmt, va_list va);

// Like snprintf(), but write the string to the position starting at buf[offset].
// If offset is out of bounds, do not write anything. The function returns the
// end offset of the string (possibly out of bounds), or a negative value on
// error (only if vsnprintf() failed).
PRINTF_FORMAT(4, 5)
int snprintf_append(char *buf, size_t size, int offset, const char *format, ...);

// Return the current wall-clock time (CLOCK_REALTIME) in microseconds.
uint64_t get_time_us(void);

// Return the current monotonic time (CLOCK_MONOTONIC) in microseconds.
uint64_t get_monotonic_time_us(void);

// Dump the given binary data as hex to stdout.
void hexdump(void *data, size_t size);

// hexdump() to logfn() calls.
void log_hexdump(struct logfn ctx, void *data, size_t size);

// Called by the x* functions (and X* macros) when out of memory. Never returns.
void report_oom(size_t size, const char *file, int line);

// Attempt to reallocate an array using the given sizes (a bit like calloc()
// and realloc()). On failure, this returns the _old_ pointer, and sets errno.
// On success, errno is set to 0.
// If elem_size*num_elems==0, then allocate 1 byte.
//  ptr: current array pointer, or NULL
//  elem_size, num_elems: total array byte size is elem_size*num_elems
//  returns: ptr on failure, or new array pointer on success
void *try_realloc_array(void *ptr, size_t elem_size, size_t num_elems);

// Reallocates the given array and returns success.
#define REALLOC_ARRAY(arr, count) \
    ((arr) = try_realloc_array((arr), sizeof((arr)[0]), count), !errno)

// Reallocates the given array by adding a (positive) integer "add" to the
// array count. Use for overflow-safe array appending.
// "count" is not changed, but on success you can safely "count += add;".
#define EXTEND_ARRAY(arr, count, add) \
    ((add) < (size_t)-1 - (count) \
        ? ((arr) = try_realloc_array((arr), sizeof((arr)[0]), (count) + (add)), !errno) \
        : (false))

// Like EXTEND_ARRAY(), but crash on failure.
#define XEXTEND_ARRAY(arr, count, add) do { \
    if (!EXTEND_ARRAY(arr, count, add)) \
        report_oom((size_t)-1, __FILE__, __LINE__); \
    } while(0)

// Allocate T on the heap. This initialized the memory with 0.
#define ALLOC(T) ((T *)calloc(sizeof(T), 1))

// Allocate T on the heap. This initialized the memory with 0.
// On allocation failure, crash the process.
#define XALLOC(T) ((T *)xalloc(sizeof(T)))

void *xalloc_impl(size_t size, const char *file, int line);

// Like malloc(), but 1. always zero memory, 2. crash the process on OOM.
#define xalloc(s) xalloc_impl((s), __FILE__, __LINE__)

// This macro returns the type of its argument. Since this is non-standard, the
// fallback returns void*.
#ifdef __GNUC__
#define TYPEOF(ptrtype) __typeof__(ptrtype)
#else
#define TYPEOF(ptrtype) void *
#endif

// Allocate for the given pointer. Helpful idiom for:
//  some_type *var = ALLOC_PTRTYPE(var);
#define ALLOC_PTRTYPE(ptr) ((TYPEOF(ptr))calloc(sizeof(*(ptr)), 1))

// Like ALLOC_PTRTYPE(), but crash the process on OOM.
#define XALLOC_PTRTYPE(ptr) ((TYPEOF(ptr))xalloc(sizeof(*(ptr))))

char *xstrdup_impl(const char *s, const char *file, int line);

// Like strdup(), but 1. if s==NULL, return NULL, 2. crash the process on OOM
#define xstrdup(s) xstrdup_impl(s, __FILE__, __LINE__)

void *xmemdup_impl(void *d, size_t s, const char *file, int line);

// Return a newly xalloc'ed copy of the pointer d of size s. If s==0, always
// returns NULL.
#define xmemdup(d, s) xmemdup_impl(d, s, __FILE__, __LINE__)

// Like asprintf(), but crash the process on OOM.
#define xasprintf(...) xasprintf_impl(__FILE__, __LINE__, __VA_ARGS__)

PRINTF_FORMAT(3, 4)
char *xasprintf_impl(const char *file, int line, const char *fmt, ...);

PRINTF_FORMAT(3, 4)
char *stack_sprintf_impl(char *buf, size_t buf_size, const char *fmt, ...);

// Allocate a string of length SIZE on the stack, call snprintf() with the
// remaining arguments on it, and return the string. The string is valid until
// the end of the scope (C99 compound literal). If the formatted string is too
// long for the buffer, it is cut off (and still 0-terminated). Example:
//      char *foo = stack_sprintf(20, "hello %s", "world");
#define stack_sprintf(SIZE, ...) \
    stack_sprintf_impl((char[SIZE]){0}, SIZE, __VA_ARGS__)

// Return smallest power of 2 with res>=v. Returns 0 for v==0 and v>2^sizebits/2.
size_t round_up_power_of_2(size_t v);
// Return largest power of 2 with res<=v. Returns 0 for v==0.
size_t round_down_power_of_2(size_t v);

// Return whether s ends with suffix (always returns true if suffix==""). If
// out_end is not NULL, then *out_end is set to s+(strlen(s)-strlen(suffix)) on
// true, or not touched if false is returned.
bool str_ends_with(const char *s, const char *suffix, char **out_end);

// Return whether s starts with prefix (always returns true if prefix==""). If
// out_rest is not NULL, then *out_rest is set to s+strlen(prefix) on true,
// or not touched if false is returned.
bool str_starts_with(const char *s, const char *prefix, char **out_rest);

// An appendable buffer. This is meant for writing to a fixed buffer, while
// keeping track of the write position, and making sure it will not just write
// out of bounds. (The intention is that overflows are guaranteed not to happen,
// so the bounds checks are done for easier debugging only.)
// All functions are inline for performance-paranoia.
struct wbuf {
    uint8_t *ptr;
    size_t pos;
    size_t size;
};

static inline void wbuf_write(struct wbuf *w, const void *data, size_t size)
{
    assert(w->size - w->pos >= size);
    memcpy(w->ptr + w->pos, data, size);
    w->pos += size;
}

#define WBUF_DEF_WRITE_FN(name, T)                      \
    static inline void (name)(struct wbuf *w, T v) {    \
        wbuf_write(w, &v, sizeof(v));                   \
    }

WBUF_DEF_WRITE_FN(wbuf_write8, uint8_t)
WBUF_DEF_WRITE_FN(wbuf_write16, uint16_t)
WBUF_DEF_WRITE_FN(wbuf_write32, uint32_t)
WBUF_DEF_WRITE_FN(wbuf_write64, uint64_t)

static inline void wbuf_write_pad32(struct wbuf *w)
{
    while (w->pos & 3) {
        assert(w->pos < w->size);
        w->ptr[w->pos++] = 0;
    }
}

#ifdef __MINGW32__
char *strndup(const char *s, size_t n);
#endif

// Read a file into memory. Returns success.
// On success, sets *data and *size to the file contents. (If *size==0, then
// still *data!=NULL.) Use free() to deallocate *data.
// errno is set on failure (clobbered on success).
bool read_file(const char *fname, void **data, size_t *size);

// Parse the given hex string in some vaguely defined way.
// Currently supported syntax:
// - Variant A: 0xABCDEF12 0xABCDEF12 (list of 32 bit words)
// - Variant B: ABCDEF (list of 8 bit words, no whitespace)
//  lfn: error logging
//  in: the hex string
//  out_data: set to a malloc()ed byte array on success
//  out_size: set to size of out_data on success
//  returns: true on success (out_* set), false on failure (out_* untouched)
bool parse_hex(struct logfn lfn, const char *in, uint8_t **out_data,
               size_t *out_size);

struct notifier;
struct notifier_user;

// A notifier is a glorified list of callbacks.
// The 'x' means it crashes on OOM instead of returning NULL.
struct notifier *notifier_xalloc(void);

// Deallocate nf. Call on_destroy callbacks. NOP if NULL is passed.
void notifier_free(struct notifier *nf);

// Add a callbacks to internal list. NULL callbacks are ignored. Returns a
// non-0 ID that can be passed to notifier_remove().
// From the callbacks, you are not allowed to access the nf object at all.
// The 'x' means it crashes on OOM instead of returning NULL.
uint64_t notifier_xadd(struct notifier *nf, void *ud,
                       void (*on_notify)(void *ud),
                       void (*on_destroy)(void *ud));

// Remove an ID returned by notifier_xadd(). Passing 0 does nothing (in this
// case nf==NULL is also OK). UB if user does not belong to nf.
void notifier_remove(struct notifier *nf, uint64_t user);

// Call all on_notify callbacks.
void notifier_trigger(struct notifier *nf);

// Block until notifier_trigger() has at least been called trigger_counter times
// (in total, since notifier_xalloc() was called), or CLOCK_REALTIME has
// progressed past the time in "until". In all cases, *trigger_counter will
// contain the current number of trigger calls.
// The counter is to avoid race conditions: without it, you might block forever
// if the trigger happens after you've checked the state and before the wait
// function acquires its internal lock.
// Passing until==NULL is allowed and will not block.
void notifier_wait(struct notifier *nf, int64_t *trigger_counter,
                   const struct timespec *until);

#endif
