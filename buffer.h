// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef BUFFER_H_
#define BUFFER_H_

#include <stddef.h>
#include <stdbool.h>

struct buffer {
    void *data;         // current start of data
    size_t size;        // current valid size of data starting at data ptr
    void *alloc;        // actual memory allocation
    size_t alloc_size;  // size of memory allocation
};

// Return the number of bytes that can be appended to the end of the currently
// used data (what buffer_end() returns) without requiring buffer_reserve().
size_t buffer_available_size(struct buffer *buf);

// On success, you can append size bytes at buf->data+buf->size.
bool buffer_reserve(struct buffer *buf, size_t size);

// Free the memory managed by the buffer, and reset all fields.
// Does not include free(buf).
void buffer_dealloc(struct buffer *buf);

// Return pointer right after the currently used data.
void *buffer_end(struct buffer *buf);

// Extend the buffer and copy the data to the end of the buffer.
// Returns false if memory allocation fails.
bool buffer_append(struct buffer *buf, const void *data, size_t size);

// Append a C string (without '\0').
bool buffer_append_str(struct buffer *buf, const char *str);

// Remove the given number of bytes from the beginning.
void buffer_skip(struct buffer *buf, size_t size);

#endif
