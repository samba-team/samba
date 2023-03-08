/*
 * Copyright (c) 1995-2001 Kungliga Tekniska Högskolan
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
#include "base64.h"
#include "roken.h"

#define base64_chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static int
pos(char c)
{
#if 'A' == '\301'
    const char *p;
    for (p = base64_chars; *p; p++)
	if (*p == c)
	    return p - base64_chars;
    return -1;
#else
    if (c >= 'A' && c <= 'Z')
	return c - 'A';
    if (c >= 'a' && c <= 'z')
	return ('Z' + 1 - 'A') + c - 'a';
    if (c >= '0' && c <= '9')
	return ('Z' + 1 - 'A') +
	       ('z' + 1 - 'a') + c - '0';
    if (c == '+')
	return 62;
    if (c == '/')
	return 63;
    return -1;
#endif
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_base64_encode(const void *data, int size, char **str)
{
    char *s, *p;
    int i;
    int c;
    const unsigned char *q;

    if (size > INT_MAX/4 || size < 0) {
	*str = NULL;
        errno = ERANGE;
	return -1;
    }

    p = s = (char *) malloc(size * 4 / 3 + 4);
    if (p == NULL) {
        *str = NULL;
	return -1;
    }
    q = (const unsigned char *) data;

    for (i = 0; i < size;) {
	c = q[i++];
	c *= 256;
	if (i < size)
	    c += q[i];
	i++;
	c *= 256;
	if (i < size)
	    c += q[i];
	i++;
	p[0] = base64_chars[(c & 0x00fc0000) >> 18];
	p[1] = base64_chars[(c & 0x0003f000) >> 12];
	p[2] = base64_chars[(c & 0x00000fc0) >> 6];
	p[3] = base64_chars[(c & 0x0000003f) >> 0];
	if (i > size)
	    p[3] = '=';
	if (i > size + 1)
	    p[2] = '=';
	p += 4;
    }
    *p = 0;
    *str = s;
    return (int) strlen(s);
}

#define DECODE_ERROR 0xffffffff

static unsigned int
token_decode(const char *token)
{
    int i;
    unsigned int val = 0;
    int marker = 0;
    for (i = 0; i < 4 && token[i] != '\0'; i++) {
	val *= 64;
	if (token[i] == '=')
	    marker++;
	else if (marker > 0)
	    return DECODE_ERROR;
	else
	    val += pos(token[i]);
    }
    if (i < 4 || marker > 2)
	return DECODE_ERROR;
    return (marker << 24) | val;
}

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_base64_decode(const char *str, void *data)
{
    const char *p;
    unsigned char *q;

    q = data;
    for (p = str; *p && (*p == '=' || pos(*p) != -1); p += 4) {
	unsigned int val = token_decode(p);
	unsigned int marker = (val >> 24) & 0xff;
	if (val == DECODE_ERROR) {
            errno = EINVAL;
	    return -1;
        }
	*q++ = (val >> 16) & 0xff;
	if (marker < 2)
	    *q++ = (val >> 8) & 0xff;
	if (marker < 1)
	    *q++ = val & 0xff;
    }
    if (q - (unsigned char *) data > INT_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    return q - (unsigned char *) data;
}

#ifdef TEST
static int decode_flag;
static int help_flag;

/*
 * The short options are compatible with a subset of the FreeBSD contrib
 * vis(1).  Heimdal additions have long option names only.
 */
static struct getargs args[] = {
    { "decode", 'd', arg_flag, &decode_flag, "Decode", NULL },
    { "help", 'h', arg_flag, &help_flag, "Print help message", NULL },
};
static size_t num_args = sizeof(args)/sizeof(args[0]);

int
main(int argc, char **argv)
{
    unsigned char *buf = NULL;
    size_t buflen = 0;
    size_t bufsz = 0;
    int goptind = 0;
    int ret;

    setprogname("rkbase64");
    if (getarg(args, num_args, argc, argv, &goptind) || help_flag) {
        arg_printusage(args, num_args, NULL, "FILE | -");
        return help_flag ? 0 : 1;
    }

    argc -= goptind;
    argv += goptind;

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

        if ((d = malloc(buflen * 3 / 4 + 4)) == NULL)
            err(1, "Could not decode data");

        if ((ret = rk_base64_decode((const char *)buf, d)) < 0)
            err(1, "Could not decode data");
        if (fwrite(d, ret, 1, stdout) != 1)
            err(1, "Could not write decoded data");
        free(d);
    } else if (buf) { /* buf can be NULL if we read from an empty file */
        char *e;

        if ((ret = rk_base64_encode(buf, buflen, &e)) < 0)
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
