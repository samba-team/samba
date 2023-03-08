/*
 * Copyright (c) 2004-2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <config.h>
#include "roken.h"
#include <ctype.h>
#include "hex.h"

static const char hexchar[16] = "0123456789ABCDEF";

static inline int
pos(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    return -1;
}

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
hex_encode(const void *data, size_t size, char **str)
{
    const unsigned char *q = data;
    size_t i;
    char *p;

    p = calloc(size + 1, 2);
    if (p == NULL) {
        *str = NULL;
	return -1;
    }

    for (i = 0; i < size; i++) {
	p[i * 2] = hexchar[(*q >> 4) & 0xf];
	p[i * 2 + 1] = hexchar[*q & 0xf];
	q++;
    }
    p[i * 2] = '\0';
    *str = p;

    return i * 2;
}

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
hex_decode(const char *str, void *data, size_t len)
{
    size_t l;
    unsigned char *p = data;
    size_t i;
    int d;

    l = strlen(str);

    /* check for overflow, same as (l+1)/2 but overflow safe */
    if ((l/2) + (l&1) > len)
	return -1;

    if (l & 1) {
        if ((d = pos(str[0])) == -1)
            return -1;
	p[0] = d;
	str++;
	p++;
    }
    for (i = 0; i < l / 2; i++) {
        if ((d = pos(str[i * 2])) == -1)
            return -1;
	p[i] = d << 4;
        if ((d = pos(str[(i * 2) + 1])) == -1)
            return -1;
	p[i] |= d;
    }
    return i + (l & 1);
}
