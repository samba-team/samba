/*
 * Copyright (C) 2015 THL A29 Limited, a Tencent company, and Milo Yip.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <config.h>
#include <assert.h>

#include "roken.h"

#if defined(_MSC_VER)
#include <intrin.h>
#if defined(_WIN64)
#pragma intrinsic(_BitScanReverse64)
#else
#pragma intrinsic(_BitScanReverse)
#endif
#endif

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_clzll(uint64_t x)
{
#if defined(_MSC_VER)
    unsigned long r = 0;
#elif !(defined(__GNUC__) && __GNUC__ >= 4)
    int r = 0;
#endif

    assert(x != 0);

#if defined(_MSC_VER)
# if defined(_WIN64)
    _BitScanReverse64(&r, x);
# else
    if (_BitScanReverse(&r, (uint32_t)(x >> 32)))
        return 63 - (r + 32);
    _BitScanReverse(&r, (uint32_t)(x & 0xFFFFFFFF));
# endif

    return 63 - r;
#elif (defined(__GNUC__) && __GNUC__ >= 4)
    return __builtin_clzll(x);
#else
    while (!(x & ((uint64_t)1 << 63))) {
        x <<= 1;
        ++r;
    }

    return r;
#endif /* _MSC_VER || __GNUC__ */
}
