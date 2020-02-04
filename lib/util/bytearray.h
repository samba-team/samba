/*
 * Macros for handling integer types in byte arrays
 *
 * This file is originally from the libssh.org project
 *
 * Copyright (c) 2018 Andreas Schneider <asn@cryptomilk.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef _BYTEARRAY_H
#define _BYTEARRAY_H

#define _DATA_BYTE_CONST(data, pos) \
    ((uint8_t)(((const uint8_t *)(data))[(pos)]))

#define _DATA_BYTE(data, pos) \
    (((uint8_t *)(data))[(pos)])

/*
 * These macros pull or push integer values from byte arrays stored in
 * little-endian byte order.
 */
#define PULL_LE_U8(data, pos) \
    (_DATA_BYTE_CONST(data, pos))
#define PULL_LE_I8(data, pos) \
    (int8_t)PULL_LE_U8(data, pos)

#define PULL_LE_U16(data, pos) \
    ((uint16_t)PULL_LE_U8(data, pos) | ((uint16_t)(PULL_LE_U8(data, (pos) + 1))) << 8)
#define PULL_LE_I16(data, pos) \
    (int16_t)PULL_LE_U16(data, pos)

#define PULL_LE_U32(data, pos) \
    ((uint32_t)(PULL_LE_U16(data, pos) | ((uint32_t)PULL_LE_U16(data, (pos) + 2)) << 16))
#define PULL_LE_I32(data, pos) \
    (int32_t)PULL_LE_U32(data, pos)

#define PULL_LE_U64(data, pos) \
    ((uint64_t)(PULL_LE_U32(data, pos) | ((uint64_t)PULL_LE_U32(data, (pos) + 4)) << 32))
#define PULL_LE_I64(data, pos) \
    (int64_t)PULL_LE_U64(data, pos)


#define PUSH_LE_U8(data, pos, val) \
    (_DATA_BYTE(data, pos) = ((uint8_t)(val)))
#define PUSH_LE_I8(data, pos, val) \
    PUSH_LE_U8(data, pos, val)

#define PUSH_LE_U16(data, pos, val) \
    (PUSH_LE_U8((data), (pos), (uint8_t)((uint16_t)(val) & 0xff)), PUSH_LE_U8((data), (pos) + 1, (uint8_t)((uint16_t)(val) >> 8)))
#define PUSH_LE_I16(data, pos, val) \
    PUSH_LE_U16(data, pos, val)

#define PUSH_LE_U32(data, pos, val) \
    (PUSH_LE_U16((data), (pos), (uint16_t)((uint32_t)(val) & 0xffff)), PUSH_LE_U16((data), (pos) + 2, (uint16_t)((uint32_t)(val) >> 16)))
#define PUSH_LE_I32(data, pos, val) \
    PUSH_LE_U32(data, pos, val)

#define PUSH_LE_U64(data, pos, val) \
    (PUSH_LE_U32((data), (pos), (uint32_t)((uint64_t)(val) & 0xffffffff)), PUSH_LE_U32((data), (pos) + 4, (uint32_t)((uint64_t)(val) >> 32)))
#define PUSH_LE_I64(data, pos, val) \
    PUSH_LE_U64(data, pos, val)



/*
 * These macros pull or push integer values from byte arrays stored in
 * big-endian byte order (network byte order).
 */
#define PULL_BE_U8(data, pos) \
    (_DATA_BYTE_CONST(data, pos))
#define PULL_BE_I8(data, pos) \
    (int8_t)PULL_BE_U8(data, pos)

#define PULL_BE_U16(data, pos) \
    ((((uint16_t)(PULL_BE_U8(data, pos))) << 8) | (uint16_t)PULL_BE_U8(data, (pos) + 1))
#define PULL_BE_I16(data, pos) \
    (int16_t)PULL_BE_U16(data, pos)

#define PULL_BE_U32(data, pos) \
    ((((uint32_t)PULL_BE_U16(data, pos)) << 16) | (uint32_t)(PULL_BE_U16(data, (pos) + 2)))
#define PULL_BE_I32(data, pos) \
    (int32_t)PULL_BE_U32(data, pos)

#define PULL_BE_U64(data, pos) \
    ((((uint64_t)PULL_BE_U32(data, pos)) << 32) | (uint64_t)(PULL_BE_U32(data, (pos) + 4)))
#define PULL_BE_I64(data, pos) \
    (int64_t)PULL_BE_U64(data, pos)



#define PUSH_BE_U8(data, pos, val) \
    (_DATA_BYTE(data, pos) = ((uint8_t)(val)))
#define PUSH_BE_I8(data, pos, val) \
    PUSH_BE_U8(data, pos, val)

#define PUSH_BE_U16(data, pos, val) \
    (PUSH_BE_U8((data), (pos), (uint8_t)(((uint16_t)(val)) >> 8)), PUSH_BE_U8((data), (pos) + 1, (uint8_t)((val) & 0xff)))
#define PUSH_BE_I16(data, pos, val) \
    PUSH_BE_U16(data, pos, val)

#define PUSH_BE_U32(data, pos, val) \
    (PUSH_BE_U16((data), (pos), (uint16_t)(((uint32_t)(val)) >> 16)), PUSH_BE_U16((data), (pos) + 2, (uint16_t)((val) & 0xffff)))
#define PUSH_BE_I32(data, pos, val) \
    PUSH_BE_U32(data, pos, val)

#define PUSH_BE_U64(data, pos, val) \
    (PUSH_BE_U32((data), (pos), (uint32_t)(((uint64_t)(val)) >> 32)), PUSH_BE_U32((data), (pos) + 4, (uint32_t)((val) & 0xffffffff)))
#define PUSH_BE_I64(data, pos, val) \
    PUSH_BE_U64(data, pos, val)

#endif /* _BYTEARRAY_H */
