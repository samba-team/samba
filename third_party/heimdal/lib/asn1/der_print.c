/*
 * Copyright (c) 2021 Kungliga Tekniska Högskolan
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
#include "hex.h"

RCSID("$Id$");

char * ASN1CALL
der_print_general_string(const heim_general_string *str, int flags)
{
    return strdup(*str);
}

char * ASN1CALL
der_print_boolean(const int *i, int flags)
{
    return *i ? strdup("true") : strdup("false");
}

char * ASN1CALL
der_print_integer(const int *i, int flags)
{
    char *s = NULL;

    if (asprintf(&s, "%d", *i) == -1 || s == NULL)
        return NULL;
    return s;
}

char * ASN1CALL
der_print_integer64(const int64_t *i, int flags)
{
    char *s = NULL;

    if (asprintf(&s, "%lld", (long long)*i) == -1 || s == NULL)
        return NULL;
    return s;
}

char * ASN1CALL
der_print_unsigned(const unsigned *u, int flags)
{
    char *s = NULL;

    if (asprintf(&s, "%u", *u) == -1 || s == NULL)
        return NULL;
    return s;
}

char * ASN1CALL
der_print_unsigned64(const uint64_t *u, int flags)
{
    char *s = NULL;

    if (asprintf(&s, "%llu", (long long)*u) == -1 || s == NULL)
        return NULL;
    return s;
}

char * ASN1CALL
der_print_generalized_time(const time_t *t, int flags)
{
    struct tm tms;
    char str[sizeof("1970-01-01T00:00:00Z")];

#ifdef WIN32
    if (gmtime_s(&tms, t) != 0 ||
        strftime(str, sizeof(str), "%Y-%m-%dT%H:%M:%SZ", &tms) == 0)
        return NULL;
#else
    if (strftime(str, sizeof(str), "%Y-%m-%dT%H:%M:%SZ", gmtime_r(t, &tms)) == 0)
        return NULL;
#endif
    return strdup(str);
}

char * ASN1CALL
der_print_utctime(const time_t *t, int flags)
{
    struct tm tms;
    char str[sizeof("1970-01-01T00:00:00Z")];

#ifdef WIN32
    if (gmtime_s(&tms, t) != 0 ||
        strftime(str, sizeof(str), "%Y-%m-%dT%H:%M:%SZ", &tms) == 0)
        return NULL;
#else
    if (strftime(str, sizeof(str), "%Y-%m-%dT%H:%M:%SZ", gmtime_r(t, &tms)) == 0)
        return NULL;
#endif
    return strdup(str);
}


char * ASN1CALL
der_print_utf8string(const heim_utf8_string *str, int flags)
{
    return strdup(*str);
}

char * ASN1CALL
der_print_printable_string(const heim_printable_string *str, int flags)
{
    return strndup(str->data, str->length);
}

char * ASN1CALL
der_print_ia5_string(const heim_ia5_string *str, int flags)
{
    return strndup(str->data, str->length);
}

char * ASN1CALL
der_print_bmp_string(const heim_bmp_string *k, int flags)
{
    return strdup("<BMPString-not-supported>");
}

char * ASN1CALL
der_print_universal_string(const heim_universal_string *k, int flags)
{
    return strdup("<UniversalString-not-supported>");
}

char * ASN1CALL
der_print_visible_string(const heim_visible_string *str, int flags)
{
    return strdup(*str);
}

char * ASN1CALL
der_print_octet_string(const heim_octet_string *k, int flags)
{
    char *s = NULL;

    (void) hex_encode(k->data, k->length, &s);
    return s;
}

char * ASN1CALL
der_print_heim_integer(const heim_integer *k, int flags)
{
    char *s = NULL;

    (void) der_print_hex_heim_integer(k, &s);
    return s;
}

char * ASN1CALL
der_print_oid(const heim_oid *k, int flags)
{
    struct rk_strpool *r = NULL;
    const char *sym = NULL;
    char *s = NULL;
    size_t i;

    (void) der_print_heim_oid(k, '.', &s);

    if (!s)
        return NULL;
    r = rk_strpoolprintf(r, "{\"_type\":\"OBJECT IDENTIFIER\","
                         "\"oid\":\"%s\","
                         "\"components\":[",
                         s);
    free(s);
    for (i = 0; i < k->length; i++)
        r = rk_strpoolprintf(r, "%s%u", i ? "," : "", k->components[i]);
    if (r)
        r = rk_strpoolprintf(r, "]");
    (void) der_find_heim_oid_by_oid(k, &sym);
    if (sym && r) {
        if ((s = strdup(sym))) {
            for (i = 0; s[i]; i++)
                if (s[i] == '_')
                    s[i] = '-';
        }
        r = rk_strpoolprintf(r, ",\"name\":\"%s\"", s ? s : sym);
        free(s);
    }
    if (r)
        r = rk_strpoolprintf(r, "}");
    return rk_strpoolcollect(r);
}

char * ASN1CALL
der_print_bit_string(const heim_bit_string *k, int flags)
{
    char *s2 = NULL;
    char *s = NULL;

    (void) hex_encode(k->data, k->length / 8, &s);
    if (asprintf(&s2, "%llu:%s", (unsigned long long)k->length, s) == -1 || !s2)
        s2 = NULL;
    free(s);
    return s2;
}
