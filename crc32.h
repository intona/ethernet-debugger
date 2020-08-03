// License: see crc32.c
#ifndef CRC32_H_
#define CRC32_H_

#include <inttypes.h>
#include <stddef.h>

uint32_t crc32(uint32_t crc, const void *buf, size_t size);

#endif
