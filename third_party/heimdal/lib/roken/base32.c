/*
 * Copyright (c) 2020 Kungliga Tekniska Högskolan
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef TEST
#include <stdio.h>
#include <getarg.h>
#include <err.h>
#endif
#include "base32.h"
#include "roken.h"

static const unsigned char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const unsigned char base32op_chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_base32_encode(const void *data, int size, char **str, enum rk_base32_flags flags)
{
    const unsigned char *chars =
        (flags & RK_BASE32_FLAG_PRESERVE_ORDER) ? base32op_chars :
                                                  base32_chars;
    uint64_t c;
    char *s, *p;
    int i;
    const unsigned char *q;

    if (size > INT_MAX/8 || size < 0) {
	*str = NULL;
        errno = ERANGE;
	return -1;
    }

    p = s = malloc(((size + 5 - 1) / 5) * 8 + 1);
    if (p == NULL) {
        *str = NULL;
	return -1;
    }
    q = (const unsigned char *) data;

    for (i = 0; i < size;) {
        /* 5 bytes of input will give us 8 output bytes' worth of bits */
	c = q[i++];
	c <<= 8;
	if (i < size)
	    c += q[i];
	i++;
	c <<= 8;
	if (i < size)
	    c += q[i];
	i++;
	c <<= 8;
	if (i < size)
	    c += q[i];
	i++;
	c <<= 8;
	if (i < size)
	    c += q[i];
	i++;
	p[0] = chars[(c & 0x00000000f800000000ULL) >> 35];
	p[1] = chars[(c & 0x0000000007c0000000ULL) >> 30];
	p[2] = chars[(c & 0x00000000003e000000ULL) >> 25];
	p[3] = chars[(c & 0x000000000001f00000ULL) >> 20];
	p[4] = chars[(c & 0x0000000000000f8000ULL) >> 15];
	p[5] = chars[(c & 0x000000000000007c00ULL) >> 10];
	p[6] = chars[(c & 0x0000000000000003e0ULL) >> 5];
	p[7] = chars[(c & 0x00000000000000001fULL) >> 0];
        switch (i - size) {
        case 4: p[2] = p[3] = '=';  HEIM_FALLTHROUGH;
        case 3: p[4] = '=';         HEIM_FALLTHROUGH;
        case 2: p[5] = p[6] = '=';  HEIM_FALLTHROUGH;
        case 1: p[7] = '=';         HEIM_FALLTHROUGH;
        default:                    break;
        }
	p += 8;
    }
    *p = 0;
    *str = s;
    return (int) strlen(s);
}

#define DECODE_ERROR ((uint64_t)-1)

static int
pos(char c, int preserve_order)
{
    /* EBCDIC need not apply */
    if (preserve_order) {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'A' && c <= 'V')
            return c - 'A' + ('9' - '0') + 1;
    } else {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= '2' && c <= '7')
            return c - '2' + ('Z' - 'A') + 1;
    }
    return -1;
}

static uint64_t
token_decode(const char *token, enum rk_base32_flags flags)
{
    uint64_t marker = 0;
    uint64_t val = 0;
    int preserve_order = !!(flags & RK_BASE32_FLAG_PRESERVE_ORDER);
    int i, c;

    for (i = 0; i < 8 && token[i] != '\0'; i++) {
	val <<= 5;
	if (token[i] == '=')
	    marker++;
	else if (marker)
	    return DECODE_ERROR;
	else if ((c = pos(token[i], preserve_order)) == -1 &&
            (flags & RK_BASE32_FLAG_STOP_ON_GARBAGE))
            break;
        else if (c == -1)
            return DECODE_ERROR;
        else
            val |= c;
    }
    if (i < 8 || marker > 6)
	return DECODE_ERROR;
    return (marker << 40) | val;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_base32_decode(const char *str, void *data, enum rk_base32_flags flags)
{
    const char *p;
    unsigned char *q;
    int preserve_order = !!(flags & RK_BASE32_FLAG_PRESERVE_ORDER);

    q = data;
    for (p = str; *p && (*p == '=' || pos(*p, preserve_order) != -1); p += 8) {
	uint64_t val = token_decode(p, flags);
	uint64_t marker = (val >> 40) & 0xffULL;

	if (val == DECODE_ERROR) {
            errno = EINVAL;
	    return -1;
        }
	*q++ = (val >> 32) & 0xffULL;
	if (marker < 6)
	    *q++ = (val >> 24) & 0xffULL;
	if (marker < 4)
	    *q++ = (val >> 16) & 0xffULL;
	if (marker < 3)
	    *q++ = (val >> 8) & 0xffULL;
	if (marker < 1)
	    *q++ = val & 0xffULL;
        if (marker && !(flags & RK_BASE32_FLAG_INTERIOR_PADDING_OK))
            break;
    }
    if (q - (unsigned char *) data > INT_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    return q - (unsigned char *) data;
}

#ifdef TEST
static int interior_padding_ok;
static int preserve_order_flag;
static int stop_on_garbage;
static int decode_flag;
static int help_flag;

/*
 * The short options are compatible with a subset of the FreeBSD contrib
 * vis(1).  Heimdal additions have long option names only.
 */
static struct getargs args[] = {
    { "preserve-order", 'P', arg_flag, &preserve_order_flag,
        "Use order-preserving alphabet", NULL },
    { "interior-padding-ok", 'O', arg_flag, &interior_padding_ok,
        "Decode concatenated padded base32 strings as one", NULL },
    { "stop-on-garbage", 'G', arg_flag, &stop_on_garbage,
        "Do not error on garbage", NULL },
    { "decode", 'd', arg_flag, &decode_flag, "Decode", NULL },
    { "help", 'h', arg_flag, &help_flag, "Print help message", NULL },
};
static size_t num_args = sizeof(args)/sizeof(args[0]);

int
main(int argc, char **argv)
{
    enum rk_base32_flags flags = 0;
    unsigned char *buf = NULL;
    size_t buflen = 0;
    size_t bufsz = 0;
    int goptind = 0;
    int ret;

    setprogname("rkbase32");
    if (getarg(args, num_args, argc, argv, &goptind) || help_flag) {
        arg_printusage(args, num_args, NULL, "FILE | -");
        return help_flag ? 0 : 1;
    }

    argc -= goptind;
    argv += goptind;

    flags |= preserve_order_flag ? RK_BASE32_FLAG_PRESERVE_ORDER : 0;
    flags |= interior_padding_ok ? RK_BASE32_FLAG_INTERIOR_PADDING_OK : 0;
    flags |= stop_on_garbage ? RK_BASE32_FLAG_STOP_ON_GARBAGE : 0;

    if (help_flag)
        return arg_printusage(args, num_args, NULL, "FILE | -- -"), 0;
    if (argc != 1)
        return arg_printusage(args, num_args, NULL, "FILE | -- -"), 1;

    if (strcmp(argv[0], "-") == 0) {
        unsigned char *tmp;
        unsigned char d[4096];
        size_t bytes;

        while (!feof(stdin) && !ferror(stdin)) {
            bytes = fread(d, 1, sizeof(d), stdin);
            if (bytes == 0)
                continue;
            if (buflen + bytes > bufsz) {
                if ((tmp = realloc(buf, bufsz + (bufsz >> 2) + sizeof(d))) == NULL)
                    err(1, "Could not read stdin");
                buf = tmp;
                bufsz = bufsz + (bufsz >> 2) + sizeof(d);
            }
            memcpy(buf + buflen, d, bytes);
            buflen += bytes;
        }
        if (ferror(stdin))
            err(1, "Could not read stdin");
    } else {
        void *d;

        if ((errno = rk_undumpdata(argv[0], &d, &bufsz)))
            err(1, "Could not read %s", argv[0]);
        buflen = bufsz;
        buf = d;
    }

    if (decode_flag) {
        unsigned char *d;

        if (buflen == bufsz) {
            unsigned char *tmp;

            if ((tmp = realloc(buf, bufsz + 1)) == NULL)
                err(1, "Could not decode data");
            buf = tmp;
            bufsz++;
        }
        buf[buflen] = '\0';

        if ((d = malloc(buflen * 5 / 8 + 4)) == NULL)
            err(1, "Could not decode data");

        if ((ret = rk_base32_decode((const char *)buf, d, flags)) < 0)
            err(1, "Could not decode data");
        if (fwrite(d, ret, 1, stdout) != 1)
            err(1, "Could not write decoded data");
        free(d);
    } else if (buf) { /* buf can be NULL if we read from an empty file */
        char *e;

        if ((ret = rk_base32_encode(buf, buflen, &e, flags)) < 0)
            err(1, "Could not encode data");
        if (fwrite(e, ret, 1, stdout) != 1)
            err(1, "Could not write decoded data");
        free(e);
        if (fwrite("\n", 1, 1, stdout) != 1)
            err(1, "Could not write decoded data");
    }
    free(buf);
    return 0;
}
#endif
