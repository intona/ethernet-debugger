// SPDX-License-Identifier: GPL-3.0-or-later
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "fifo.h"

bool byte_fifo_alloc(struct byte_fifo *fifo, size_t size)
{
    assert(size && !(size & (size - 1))); // must be power of 2

    void *ptr = malloc(size);
    if (!ptr)
        return false;

    *fifo = (struct byte_fifo){
        .data = ptr,
        .size = size,
    };

    return true;
}

void byte_fifo_dealloc(struct byte_fifo *fifo)
{
    free(fifo->data);
    *fifo = (struct byte_fifo){0};
}

size_t byte_fifo_get_available(struct byte_fifo *fifo)
{
    return fifo->pos_wr - fifo->pos_rd;
}

size_t byte_fifo_get_free(struct byte_fifo *fifo)
{
    return fifo->size - byte_fifo_get_available(fifo);
}

bool byte_fifo_write_atomic_v(struct byte_fifo *fifo,
                              struct byte_fifo_iov *items,
                              size_t num_items)
{
    size_t size = 0;
    for (size_t n = 0; n < num_items; n++)
        size += items[n].size;

    size_t bytes_left = byte_fifo_get_free(fifo);
    if (size > bytes_left)
        return false;

    size_t pos_offset = fifo->pos_wr & (fifo->size - 1);

    for (size_t n = 0; n < num_items; n++) {

        size_t size_a = items[n].size;
        if (items[n].size > fifo->size - pos_offset)
            size_a = fifo->size - pos_offset;
        memcpy(fifo->data + pos_offset, items[n].data, size_a);
        size_t size_b = items[n].size - size_a;
        memcpy(fifo->data, (uint8_t *)items[n].data + size_a, size_b);

        pos_offset = (pos_offset + size_a + size_b) & (fifo->size - 1);
    }

    fifo->pos_wr += size;

    return true;
}

bool byte_fifo_write_atomic_2(struct byte_fifo *fifo,
                              const void *data1, size_t size1,
                              const void *data2, size_t size2)
{
    struct byte_fifo_iov items[] = {
        {data1, size1},
        {data2, size2},
    };
    return byte_fifo_write_atomic_v(fifo, items, sizeof(items) / sizeof(items[0]));
}

bool byte_fifo_write_atomic(struct byte_fifo *fifo,
                            const void *data, size_t size)
{
    struct byte_fifo_iov items[] = {
        {data, size},
    };
    return byte_fifo_write_atomic_v(fifo, items, sizeof(items) / sizeof(items[0]));
}

size_t byte_fifo_peek(struct byte_fifo *fifo, void *data, size_t size)
{
    size_t bytes_left = byte_fifo_get_available(fifo);
    if (size > bytes_left)
        size = bytes_left;

    if (!size)
        return 0;

    size_t pos_offset = fifo->pos_rd & (fifo->size - 1);

    size_t size_a = size;
    if (size > fifo->size - pos_offset)
        size_a = fifo->size - pos_offset;
    memcpy(data, fifo->data + pos_offset, size_a);
    size_t size_b = size - size_a;
    memcpy((uint8_t *)data + size_a, fifo->data, size_b);

    return size;
}

size_t byte_fifo_read(struct byte_fifo *fifo, void *data, size_t size)
{
    size_t read = byte_fifo_peek(fifo, data, size);
    if (read)
        fifo->pos_rd += read;
    return read;
}

size_t byte_fifo_skip(struct byte_fifo *fifo, size_t size)
{
    size_t bytes_left = byte_fifo_get_available(fifo);
    if (size > bytes_left)
        size = bytes_left;
    if (size)
        fifo->pos_rd += size;
    return size;
}
