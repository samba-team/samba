/*
 * Copyright (c) 2003 - 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include "der_locl.h"
#include "heim_asn1.h"
#include <vis.h>
#include <vis-extras.h>

RCSID("$Id$");

int ASN1CALL
encode_heim_any(unsigned char *p, size_t len,
		const heim_any *data, size_t *size)
{
    return der_put_octet_string (p, len, data, size);
}

int ASN1CALL
decode_heim_any(const unsigned char *p, size_t len,
		heim_any *data, size_t *size)
{
    size_t len_len, length, l;
    Der_class thisclass;
    Der_type thistype;
    unsigned int thistag;
    int e;

    memset(data, 0, sizeof(*data));

    e = der_get_tag (p, len, &thisclass, &thistype, &thistag, &l);
    if (e) return e;
    if (l > len)
	return ASN1_OVERFLOW;
    e = der_get_length(p + l, len - l, &length, &len_len);
    if (e) return e;
    if (length == ASN1_INDEFINITE) {
        if (len < len_len + l)
	    return ASN1_OVERFLOW;
	length = len - (len_len + l);
    } else {
	if (len < length + len_len + l)
	    return ASN1_OVERFLOW;
    }

    data->data = malloc(length + len_len + l);
    if (data->data == NULL)
	return ENOMEM;
    data->length = length + len_len + l;
    memcpy(data->data, p, length + len_len + l);

    if (size)
	*size = length + len_len + l;

    return 0;
}

void ASN1CALL
free_heim_any(heim_any *data)
{
    der_free_octet_string(data);
}

char * ASN1CALL
print_heim_any(const heim_any *data, int flags)
{
    char *s2 = NULL;
    char *s = der_print_octet_string(data, 0);
    int r = -1;

    (void)flags;
    if (s)
        r = rk_strasvis(&s2, s, VIS_CSTYLE|VIS_TAB|VIS_NL, "\"");
    free(s);
    s = NULL;
    if (r > -1)
        (void) asprintf(&s, "\"%s\"", s2);
    free(s2);
    return s;
}

size_t ASN1CALL
length_heim_any(const heim_any *data)
{
    return data->length;
}

int ASN1CALL
copy_heim_any(const heim_any *from, heim_any *to)
{
    return der_copy_octet_string(from, to);
}

int ASN1CALL
encode_HEIM_ANY(unsigned char *p, size_t len,
		const heim_any *data, size_t *size)
{
    return encode_heim_any(p, len, data, size);
}

int ASN1CALL
decode_HEIM_ANY(const unsigned char *p, size_t len,
		heim_any *data, size_t *size)
{
    return decode_heim_any(p, len, data, size);
}

void ASN1CALL
free_HEIM_ANY(heim_any *data)
{
    der_free_octet_string(data);
}

char * ASN1CALL
print_HEIM_ANY(const heim_any *data, int flags)
{
    char *s2 = NULL;
    char *s = der_print_octet_string(data, 0);
    int r = -1;

    (void)flags;
    if (s)
        r = rk_strasvis(&s2, s, VIS_CSTYLE|VIS_TAB|VIS_NL, "\"");
    free(s);
    s = NULL;
    if (r > -1)
        (void) asprintf(&s, "\"%s\"", s2);
    free(s2);
    return s;
}

size_t ASN1CALL
length_HEIM_ANY(const heim_any *data)
{
    return data->length;
}

int ASN1CALL
copy_HEIM_ANY(const heim_any *from, heim_any *to)
{
    return der_copy_octet_string(from, to);
}

int ASN1CALL
encode_heim_any_set(unsigned char *p, size_t len,
		    const heim_any_set *data, size_t *size)
{
    return der_put_octet_string (p, len, data, size);
}

int ASN1CALL
decode_heim_any_set(const unsigned char *p, size_t len,
		heim_any_set *data, size_t *size)
{
    return der_get_octet_string(p, len, data, size);
}

void ASN1CALL
free_heim_any_set(heim_any_set *data)
{
    der_free_octet_string(data);
}

char * ASN1CALL
print_heim_any_set(const heim_any_set *data, int flags)
{
    char *s2 = NULL;
    char *s = der_print_octet_string(data, 0);
    int r = -1;

    (void)flags;
    if (s)
        r = rk_strasvis(&s2, s, VIS_CSTYLE|VIS_TAB|VIS_NL, "\"");
    free(s);
    s = NULL;
    if (r > -1)
        (void) asprintf(&s, "\"%s\"", s2);
    free(s2);
    return s;
}

size_t ASN1CALL
length_heim_any_set(const heim_any *data)
{
    return data->length;
}

int ASN1CALL
copy_heim_any_set(const heim_any_set *from, heim_any_set *to)
{
    return der_copy_octet_string(from, to);
}

int ASN1CALL
heim_any_cmp(const heim_any_set *p, const heim_any_set *q)
{
    return der_heim_octet_string_cmp(p, q);
}

int ASN1CALL
encode_HEIM_ANY_SET(unsigned char *p, size_t len,
		    const heim_any_set *data, size_t *size)
{
    return encode_heim_any_set(p, len, data, size);
}

int ASN1CALL
decode_HEIM_ANY_SET(const unsigned char *p, size_t len,
                    heim_any_set *data, size_t *size)
{
    return decode_heim_any_set(p, len, data, size);
}

void ASN1CALL
free_HEIM_ANY_SET(heim_any_set *data)
{
    der_free_octet_string(data);
}

char * ASN1CALL
print_HEIM_ANY_SET(const heim_any_set *data, int flags)
{
    char *s2 = NULL;
    char *s = der_print_octet_string(data, 0);
    int r = -1;

    (void)flags;
    if (s)
        r = rk_strasvis(&s2, s, VIS_CSTYLE|VIS_TAB|VIS_NL, "\"");
    free(s);
    s = NULL;
    if (r > -1)
        (void) asprintf(&s, "\"%s\"", s2);
    free(s2);
    return s;
}

size_t ASN1CALL
length_HEIM_ANY_SET(const heim_any *data)
{
    return data->length;
}

int ASN1CALL
copy_HEIM_ANY_SET(const heim_any_set *from, heim_any_set *to)
{
    return der_copy_octet_string(from, to);
}

int ASN1CALL
HEIM_ANY_cmp(const heim_any_set *p, const heim_any_set *q)
{
    return der_heim_octet_string_cmp(p, q);
}
