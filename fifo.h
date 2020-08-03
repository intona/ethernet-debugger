// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef FIFO_H_
#define FIFO_H_

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct byte_fifo {
    atomic_uint_fast64_t pos_wr;
    atomic_uint_fast64_t pos_rd;
    uint8_t *data;
    size_t size; // size of data allocation; must be power of 2
};

// Overwrite *fifo with an initialized and allocated FIFO of the given power of
// 2 size. Returns false and does nothing if allocation fails.
bool byte_fifo_alloc(struct byte_fifo *fifo, size_t size);

// Free the data buffer referenced by fifo and clear *fifo.
// Does not free fifo struct itself.
void byte_fifo_dealloc(struct byte_fifo *fifo);

// Get number of bytes currently in the FIFO. Note that this is either an upper
// bound (if you call it from the producer) or a lower bound (if you call it
// from the consumer). Not being aware of this will lead to race conditions.
size_t byte_fifo_get_available(struct byte_fifo *fifo);

// Return number of bytes that can be written. Note that this is either a lower
// bound (if you call it from the producer) or an upper bound (if you call it
// from the consumer). Not being aware of this will lead to race conditions.
size_t byte_fifo_get_free(struct byte_fifo *fifo);

struct byte_fifo_iov {
    const void *data;
    size_t size;
};

// Write the given items[0..num_items] to the FIFO, but only if there is enough
// space for all of them.
// This is "atomic" as in byte_fifo_read() can read either all items, or
// nothing.
// Return false if nothing could be written, true if all could be written.
bool byte_fifo_write_atomic_v(struct byte_fifo *fifo,
                              struct byte_fifo_iov *items,
                              size_t num_items);

// Write data1, then data2; but only if enough space is available for both.
// This is "atomic" as in byte_fifo_read() observes only 1 write (it can either
// read both fully, or nothing).
// Return false if nothing could be written, true if all could be written.
bool byte_fifo_write_atomic_2(struct byte_fifo *fifo,
                              const void *data1, size_t size1,
                              const void *data2, size_t size2);

// Write data; but only if enough space is available.
// This is "atomic" as in byte_fifo_read() can read either all of data[0..size],
// or nothing.
// Return false if nothing could be written, true if all could be written.
bool byte_fifo_write_atomic(struct byte_fifo *fifo,
                            const void *data, size_t size);

// Read data; this will copy up to size bytes from the FIFO (as much as
// possible), removes the data from the FIFO, and returns the number of copied
// and removed bytes.
size_t byte_fifo_read(struct byte_fifo *fifo, void *data, size_t size);

// Like byte_fifo_read(), but do not discard the data from the FIFO.
size_t byte_fifo_peek(struct byte_fifo *fifo, void *data, size_t size);

// Exactly like byte_fifo_read(), but discard read data.
size_t byte_fifo_skip(struct byte_fifo *fifo, size_t size);

#endif
