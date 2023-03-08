/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
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

RCSID("$Id$");

int ASN1CALL
der_copy_general_string (const heim_general_string *from,
			 heim_general_string *to)
{
    *to = strdup(*from);
    if(*to == NULL)
	return ENOMEM;
    return 0;
}

int ASN1CALL
der_copy_integer (const int *from, int *to)
{
    *to = *from;
    return 0;
}

int ASN1CALL
der_copy_integer64 (const int64_t *from, int64_t *to)
{
    *to = *from;
    return 0;
}

int ASN1CALL
der_copy_unsigned (const unsigned *from, unsigned *to)
{
    *to = *from;
    return 0;
}

int ASN1CALL
der_copy_unsigned64 (const uint64_t *from, uint64_t *to)
{
    *to = *from;
    return 0;
}

int ASN1CALL
der_copy_generalized_time (const time_t *from, time_t *to)
{
    *to = *from;
    return 0;
}

int ASN1CALL
der_copy_utctime (const time_t *from, time_t *to)
{
    *to = *from;
    return 0;
}

int ASN1CALL
der_copy_utf8string (const heim_utf8_string *from, heim_utf8_string *to)
{
    return der_copy_general_string(from, to);
}

int ASN1CALL
der_copy_printable_string (const heim_printable_string *from,
		       heim_printable_string *to)
{
    assert(from->length == 0 || (from->length > 0 && from->data != NULL));
    to->data = malloc(from->length + 1);
    if (to->data == NULL) {
	to->length = 0;
	return ENOMEM;
    }
    to->length = from->length;
    if (to->length > 0)
	memcpy(to->data, from->data, to->length);
    ((char *)to->data)[to->length] = '\0';
    return 0;
}

int ASN1CALL
der_copy_ia5_string (const heim_ia5_string *from,
		     heim_ia5_string *to)
{
    return der_copy_printable_string(from, to);
}

int ASN1CALL
der_copy_bmp_string (const heim_bmp_string *from, heim_bmp_string *to)
{
    assert(from->length == 0 || (from->length > 0 && from->data != NULL));
    if (from->length == 0)
	to->data = calloc(1, sizeof(from->data[0]));
    else
	to->data = malloc(from->length * sizeof(from->data[0]));
    if (to->data == NULL) {
	to->length = 0;
	return ENOMEM;
    }
    to->length = from->length;
    if (to->length > 0)
	memcpy(to->data, from->data, to->length * sizeof(to->data[0]));
    return 0;
}

int ASN1CALL
der_copy_universal_string (const heim_universal_string *from,
			   heim_universal_string *to)
{
    assert(from->length == 0 || (from->length > 0 && from->data != NULL));
    if (from->length == 0)
	to->data = calloc(1, sizeof(from->data[0]));
    else
	to->data = malloc(from->length * sizeof(from->data[0]));
    if (to->data == NULL) {
	to->length = 0;
	return ENOMEM;
    }
    to->length = from->length;
    if (to->length > 0)
	memcpy(to->data, from->data, to->length * sizeof(to->data[0]));
    return 0;
}

int ASN1CALL
der_copy_visible_string (const heim_visible_string *from,
			 heim_visible_string *to)
{
    return der_copy_general_string(from, to);
}

int ASN1CALL
der_copy_octet_string (const heim_octet_string *from, heim_octet_string *to)
{
    assert(from->length == 0 || (from->length > 0 && from->data != NULL));
    if (from->length == 0) {
        if (from->data == NULL) {
            *to = *from;
            return 0;
        }
	to->data = calloc(1, 1);
    } else
	to->data = malloc(from->length);
    if (to->data == NULL) {
	to->length = 0;
	return ENOMEM;
    }
    to->length = from->length;
    if (to->length > 0)
	memcpy(to->data, from->data, to->length);
    return 0;
}

int ASN1CALL
der_copy_heim_integer (const heim_integer *from, heim_integer *to)
{
    assert(from->length == 0 || (from->length > 0 && from->data != NULL));
    if (from->length == 0)
	to->data = calloc(1, 1);
    else
	to->data = malloc(from->length);
    if (to->data == NULL) {
	to->length = 0;
	return ENOMEM;
    }
    to->length = from->length;
    if (to->length > 0)
	memcpy(to->data, from->data, to->length);
    to->negative = from->negative;
    return 0;
}

int ASN1CALL
der_copy_oid (const heim_oid *from, heim_oid *to)
{
    if (from->length == 0) {
	to->length = 0;
	to->components = calloc(1, sizeof(*from->components));
	if (to->components == NULL)
	    return ENOMEM;
	return 0;
    }
    assert(from->components != NULL);
    to->components = malloc(from->length * sizeof(*from->components));
    if (to->components == NULL) {
	to->length = 0;
	return ENOMEM;
    }
    to->length = from->length;
    memcpy(to->components, from->components,
	   to->length * sizeof(*to->components));
    return 0;
}

int ASN1CALL
der_copy_bit_string (const heim_bit_string *from, heim_bit_string *to)
{
    size_t len;

    assert(from->length == 0 || (from->length > 0 && from->data != NULL));

    len = (from->length + 7) / 8;
    if (len == 0)
	to->data = calloc(1, 1);
    else
	to->data = malloc(len);
    if (to->data == NULL) {
	to->length = 0;
	return ENOMEM;
    }
    to->length = from->length;
    if (len > 0)
	memcpy(to->data, from->data, len);
    return 0;
}
