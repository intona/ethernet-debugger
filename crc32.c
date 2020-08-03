/*
 * Derived from: https://create.stephan-brumme.com/crc32/
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * Possibly taken from:
 *
 * https://github.com/antire-book/antire_book/blob/master/chap_6_debugger/dontpanic/computeChecksums/src/crc32.c
 *
 * Minor parts possibly taken from Gary Brown's crc32 implementation:
 *
 *  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 */

#include "crc32.h"

// example usage:
//  uint32_t crc = 0UL;
//  crc = crc32(~crc, data, len);
//  crc = crc32(~crc, next_data, len);
//  return crc;
uint32_t crc32(uint32_t crc, const void *buf, size_t size)
{
    const uint8_t *current = (const uint8_t *)buf;

    while (size-- > 0) {
        crc ^= *current++;

        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (-((int32_t)(crc & 1)) & 0xEDB88320); // using zlib's CRC32 polynomial
    }

    return ~crc;
}
