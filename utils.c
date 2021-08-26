// SPDX-License-Identifier: GPL-3.0-or-later
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "utils.h"

void logline(struct logfn fn, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    if (fn.fn)
        fn.fn(fn.ctx, fmt, va);
    va_end(va);
}

void logfn_stdio(void *ctx, const char *fmt, va_list va)
{
    vfprintf(ctx ? ctx : stderr, fmt, va);
}

int snprintf_append(char *buf, size_t size, int offset, const char *format, ...)
{
    if (offset >= 0 || (size_t)offset < size) {
        buf += offset;
        size -= offset;
    } else {
        size = 0;
    }

    va_list va;
    va_start(va, format);
    int r = vsnprintf(buf, size, format, va);
    if (r >= 0) {
        offset += r;
    } else {
        offset = r;
    }
    va_end(va);

    return offset;
}

uint64_t get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

uint64_t get_monotonic_time_us(void)
{
    struct timespec tp = {0};
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return tp.tv_sec * 1000000ULL + tp.tv_nsec / 1000UL;
}

void hexdump(void *data, size_t size)
{
    struct logfn fn = {stdout, logfn_stdio};
    log_hexdump(fn, data, size);
}

void log_hexdump(struct logfn ctx, void *data, size_t size)
{
    uint8_t *b = data;
    size_t pos = 0;
    while (1) {
        char l[90] = "";
        int o = 0;
        o = snprintf_append(l, sizeof(l), o, "%04zx: ", pos);
        size_t len = size - pos < 16 ? size - pos : 16;
        for (size_t n = 0; n < 16; n++) {
            if (!(n % 4))
                o = snprintf_append(l, sizeof(l), o, " ");
            if (n < len) {
                o = snprintf_append(l, sizeof(l), o, " %02x", b[pos + n]);
            } else {
                o = snprintf_append(l, sizeof(l), o, "   ");
            }
        }
        char ascii[17] = "";
        for (size_t n = 0; n < len; n++) {
            unsigned char c = b[pos + n];
            if (c < 32 || c >= 127)
                c = '.';
            ascii[n] = c;
        }
        o = snprintf_append(l, sizeof(l), o, "   |%s|\n", ascii);
        logline(ctx, "%s", l);
        pos += len;
        if (pos >= size)
            break;
    }
}

void *try_realloc_array(void *ptr, size_t elem_size, size_t num_elems)
{
    if (elem_size && (size_t)-1 / elem_size < num_elems) {
        errno = ENOMEM;
        return ptr;
    }
    size_t total = MAX(elem_size * num_elems, 1);
    void *nptr = realloc(ptr, total);
    if (!nptr) {
        errno = ENOMEM;
        return ptr;
    }
    errno = 0;
    return nptr;
}

void report_oom(size_t size, const char *file, int line)
{
    fprintf(stderr, "%s:%d: out of memory when allocating %zu bytes. Bye.\n",
            file, line, size);
    abort();
}

void *xalloc_impl(size_t size, const char *file, int line)
{
    void *r = calloc(size, 1);
    if (!r)
        report_oom(size, file, line);
    return r;
}

char *xstrdup_impl(const char *s, const char *file, int line)
{
    if (!s)
        return NULL;
    char *r = strdup(s);
    if (!r)
        report_oom(strlen(s), file, line);
    return r;
}

void *xmemdup_impl(void *d, size_t s, const char *file, int line)
{
    if (!s)
        return NULL;
    void *n = xalloc_impl(s, file, line);
    memcpy(n, d, s);
    return n;
}

char *xasprintf_impl(const char *file, int line, const char *fmt, ...)
{
    int cnt;
    char *res;

    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    cnt = vsnprintf("", 0, fmt, ap);
    if (cnt <= 0)
        cnt = 1;
    res = xalloc_impl(cnt + 1u, file, line);
    vsnprintf(res, cnt + 1u, fmt, ap2);
    va_end(ap2);
    va_end(ap);

    return res;
}

char *stack_sprintf_impl(char *buf, size_t buf_size, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, buf_size, fmt, va);
    va_end(va);
    return buf;
}

size_t round_up_power_of_2(size_t v)
{
    if (!v)
        return 0;
    for (size_t bit = 0; bit < sizeof(v) * 8; bit++) {
        size_t pow2 = ((size_t)1) << bit;
        if (pow2 >= v)
            return pow2;
    }
    return 0;
}

size_t round_down_power_of_2(size_t v)
{
    size_t up = round_up_power_of_2(v);
    if (!up && v)
        return ((size_t)1) << (sizeof(v) * 8 - 1);
    if (up > v)
        return up / 2;
    return up;
}

bool str_ends_with(const char *s, const char *suffix, char **out_end)
{
    size_t s_len = strlen(s);
    size_t suffix_len = strlen(suffix);
    if (suffix_len > s_len)
        return false;
    const char *end = s + (s_len - suffix_len);
    if (strcmp(end, suffix) != 0)
        return false;
    if (out_end)
        *out_end = (char *)end;
    return true;
}

bool str_starts_with(const char *s, const char *prefix, char **out_rest)
{
    size_t s_len = strlen(s);
    size_t prefix_len = strlen(prefix);
    if (prefix_len > s_len)
        return false;
    if (memcmp(s, prefix, prefix_len) != 0)
        return false;
    if (out_rest)
        *out_rest = (char *)s + prefix_len;
    return true;
}

#ifdef __MINGW32__
char *strndup(const char *s, size_t n)
{
    size_t l = strnlen(s, n);
    char *r = malloc(l + 1);
    if (r) {
        memcpy(r, s, l);
        r[l] = '\0';
    }
    return r;
}
#endif

bool read_file(const char *fname, void **out_data, size_t *out_size)
{
    bool ok = false;
    FILE *f = NULL;
    size_t alloc_size = 1;
    uint8_t *data = xalloc(alloc_size);
    int err = ENOMEM;

    f = fopen(fname, "rb");
    if (!f) {
        err = errno;
        goto error;
    }

    size_t size = 0;
    while (!feof(f) && !ferror(f)) {
        if (size == alloc_size) {
            size_t inc = 1024 * 1024; // 1MB increments, low effort
            inc = MIN(inc, ((size_t)-1) - alloc_size);
            if (!inc)
                goto error;
            void *nptr = realloc(data, alloc_size + inc);
            if (!nptr)
                goto error;
            data = nptr;
            alloc_size += inc;
        }
        size += fread(data + size, 1, alloc_size - size, f);
    }

    if (ferror(f)) {
        err = EIO;
        goto error;
    }

    *out_data = data;
    *out_size = size;
    data = NULL;
    ok = true;

error:
    free(data);
    if (f)
        fclose(f);
    errno = err;
    return ok;
}

static int from_hex(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool parse_hex(struct logfn lfn, const char *in, uint8_t **out_data,
               size_t *out_size)
{
    uint8_t *data = NULL;
    size_t size = 0;

    while (in[0]) {
        if (strncmp(in, "0x", 2) == 0) {
            // As LE hex number.
            char *end = 0;
            uint32_t v = strtoul(in, &end, 0);
            if (end[0] && end[0] != ' ') {
                logline(lfn, "error: single hex number expected\n");
                goto fail;
            }
            XEXTEND_ARRAY(data, size, 4);
            memcpy(&data[size], &v, 4);
            size += 4;
            in = end[0] ? end + 1 : end;
        } else {
            int a = from_hex(in[0]);
            int b = from_hex(in[1]);
            if (a < 0 || b < 0) {
                logline(lfn, "error: hex digits expected\n");
                goto fail;
            }
            XEXTEND_ARRAY(data, size, 1);
            data[size++] = (a << 4) | b;
            in += 2;
        }
    }

    *out_data = data;
    *out_size = size;
    return true;

fail:
    free(data);
    return false;
}

struct notifier_item {
    uint64_t id;
    void *ud;
    void (*on_notify)(void *ud);
    void (*on_destroy)(void *ud);
};

struct notifier {
    pthread_mutex_t lock;
    pthread_cond_t wakeup;

    int64_t trigger_count;
    uint64_t new_id;

    struct notifier_item *items;
    size_t num_items;
};

struct notifier *notifier_xalloc(void)
{
    struct notifier *nf = XALLOC_PTRTYPE(nf);
    pthread_mutex_init(&nf->lock, NULL);
    pthread_cond_init(&nf->wakeup, NULL);
    return nf;
}

void notifier_free(struct notifier *nf)
{
    if (!nf)
        return;

    pthread_mutex_lock(&nf->lock);
    for (size_t n = 0; n < nf->num_items; n++)
        nf->items[n].on_destroy(nf->items[n].ud);
    pthread_mutex_unlock(&nf->lock);

    pthread_mutex_destroy(&nf->lock);
    pthread_cond_destroy(&nf->wakeup);
    free(nf->items);
    free(nf);
}

static void on_notify_dummy(void *ud)
{
}

uint64_t notifier_xadd(struct notifier *nf, void *ud,
                       void (*on_notify)(void *ud),
                       void (*on_destroy)(void *ud))
{
    pthread_mutex_lock(&nf->lock);

    XEXTEND_ARRAY(nf->items, nf->num_items, 1);
    uint64_t id = ++nf->new_id;

    nf->items[nf->num_items++] = (struct notifier_item){
        .id = id,
        .ud = ud,
        .on_notify = on_notify ? on_notify : on_notify_dummy,
        .on_destroy = on_destroy ? on_destroy : on_notify_dummy,
    };

    pthread_mutex_unlock(&nf->lock);

    return id;
}

void notifier_remove(struct notifier *nf, uint64_t user)
{
    if (!user)
        return;

    pthread_mutex_lock(&nf->lock);
    for (size_t n = 0; n < nf->num_items; n++) {
        if (nf->items[n].id == user)
            nf->items[n] = nf->items[nf->num_items - 1];
        nf->num_items--;
        pthread_mutex_unlock(&nf->lock);
        return;
    }
    assert(0);
}

void notifier_trigger(struct notifier *nf)
{
    pthread_mutex_lock(&nf->lock);
    nf->trigger_count++;
    for (size_t n = 0; n < nf->num_items; n++)
        nf->items[n].on_notify(nf->items[n].ud);
    pthread_cond_broadcast(&nf->wakeup);
    pthread_mutex_unlock(&nf->lock);
}

void notifier_wait(struct notifier *nf, int64_t *trigger_counter,
                   const struct timespec *until)
{
    pthread_mutex_lock(&nf->lock);

    while (nf->trigger_count == *trigger_counter && until) {
        if (pthread_cond_timedwait(&nf->wakeup, &nf->lock, until))
            break;
    }

    *trigger_counter = nf->trigger_count;

    pthread_mutex_unlock(&nf->lock);
}
