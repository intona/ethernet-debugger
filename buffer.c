// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"

size_t buffer_available_size(struct buffer *buf)
{
    size_t offset = buf->data - buf->alloc;
    return buf->alloc_size - (offset + buf->size);
}

bool buffer_reserve(struct buffer *buf, size_t size)
{
    if (buffer_available_size(buf) < size) {
        if (buf->size + size <= buf->alloc_size) {
            // shift the current buffer to the start to make use of free space
            // (without needing a complex ringbuffer)
            if (buf->size)
                memmove(buf->alloc, buf->data, buf->size);
            buf->data = buf->alloc;
        } else {
            size_t alloc_size = buf->size + size;
            void *new_data = malloc(alloc_size);
            if (!new_data)
                return false;

            if (buf->size)
                memcpy(new_data, buf->data, buf->size);

            free(buf->alloc);

            buf->alloc = buf->data = new_data;
            buf->alloc_size = alloc_size;
        }
    }

    return true;
}

void buffer_dealloc(struct buffer *buf)
{
    free(buf->alloc);
    *buf = (struct buffer){0};
}

void *buffer_end(struct buffer *buf)
{
    return (char *)buf->data + buf->size;
}

bool buffer_append(struct buffer *buf, const void *data, size_t size)
{
    if (!buffer_reserve(buf, size))
        return false;

    memcpy(buffer_end(buf), data, size);
    buf->size += size;
    return true;
}

bool buffer_append_str(struct buffer *buf, const char *str)
{
    if (!str)
        return NULL;
    return buffer_append(buf, str, strlen(str));
}

void buffer_skip(struct buffer *buf, size_t size)
{
    assert(size <= buf->size);
    buf->data = (char *)buf->data + size;
    buf->size -= size;
    if (!buf->size)
        buf->data = buf->alloc;
}
