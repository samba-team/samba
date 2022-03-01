/*
 * Copyright (c) 2019 Kungliga Tekniska Högskolan
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

#include "der_locl.h"
#include <hex.h>

#include "cms_asn1.h"
#include "crmf_asn1.h"
#include "digest_asn1.h"
#include "krb5_asn1.h"
#include "kx509_asn1.h"
#include "ocsp_asn1.h"
#include "pkcs10_asn1.h"
#include "pkcs12_asn1.h"
#include "pkcs8_asn1.h"
#include "pkcs9_asn1.h"
#include "pkinit_asn1.h"
#include "rfc2459_asn1.h"
#include "rfc4108_asn1.h"


struct sym_oid {
    const char *sym;
    const heim_oid *oid;
};

#ifndef WIN32
#define DEFINE_OID_WITH_NAME(sym) \
    { #sym, &asn1_oid_ ## sym },

static const struct sym_oid sym_oids[] = {
#include "cms_asn1_oids.c"
#include "crmf_asn1_oids.c"
#include "digest_asn1_oids.c"
#include "krb5_asn1_oids.c"
#include "kx509_asn1_oids.c"
#include "ocsp_asn1_oids.c"
#include "pkcs10_asn1_oids.c"
#include "pkcs12_asn1_oids.c"
#include "pkcs8_asn1_oids.c"
#include "pkcs9_asn1_oids.c"
#include "pkinit_asn1_oids.c"
#include "rfc2459_asn1_oids.c"
#include "rfc4108_asn1_oids.c"
};

static size_t num_sym_oids = sizeof(sym_oids) / sizeof(sym_oids[0]);

#undef DEFINE_OID_WITH_NAME

#define init_sym_oids()

#else

/*
 * We can't use C99 non-literal initializers for static objects in the Windows
 * build...
 */

static struct sym_oid *sym_oids;
static size_t num_sym_oids;

#define DEFINE_OID_WITH_NAME(sym) (c++);
static size_t
count_sym_oids(void)
{
    size_t c = 0;
#include "cms_asn1_oids.c"
#include "crmf_asn1_oids.c"
#include "digest_asn1_oids.c"
#include "krb5_asn1_oids.c"
#include "kx509_asn1_oids.c"
#include "ocsp_asn1_oids.c"
#include "pkcs10_asn1_oids.c"
#include "pkcs12_asn1_oids.c"
#include "pkcs8_asn1_oids.c"
#include "pkcs9_asn1_oids.c"
#include "pkinit_asn1_oids.c"
#include "rfc2459_asn1_oids.c"
    return c;
}
#undef DEFINE_OID_WITH_NAME

#define DEFINE_OID_WITH_NAME(s) \
    tmp[i].sym = #s; \
    tmp[i++].oid = &asn1_oid_ ## s;

static void
init_sym_oids(void)
{
    static struct sym_oid *tmp;
    size_t i = 0;
    size_t c;

    if (!sym_oids &&
        (c = count_sym_oids()) &&
        (tmp = calloc(c, sizeof(tmp[0])))) {
#include "cms_asn1_oids.c"
#include "crmf_asn1_oids.c"
#include "digest_asn1_oids.c"
#include "krb5_asn1_oids.c"
#include "kx509_asn1_oids.c"
#include "ocsp_asn1_oids.c"
#include "pkcs10_asn1_oids.c"
#include "pkcs12_asn1_oids.c"
#include "pkcs8_asn1_oids.c"
#include "pkcs9_asn1_oids.c"
#include "pkinit_asn1_oids.c"
#include "rfc2459_asn1_oids.c"
        num_sym_oids = c;
        sym_oids = tmp;
    }
}
#undef DEFINE_OID_WITH_NAME

#endif

static struct sym_oid *sym_oids_sorted_by_name;
static struct sym_oid *sym_oids_sorted_by_oid;

static int
sym_cmp_name(const void *va, const void *vb)
{
    const struct sym_oid *a = va;
    const struct sym_oid *b = vb;

    return (strcmp(a->sym, b->sym));
}

static int
sym_cmp_oid(const void *va, const void *vb)
{
    const struct sym_oid *a = va;
    const struct sym_oid *b = vb;

    return der_heim_oid_cmp(a->oid, b->oid);
}

static struct sym_oid *
sort_sym_oids(int (*cmp)(const void *, const void *))
{
    struct sym_oid *tmp;

    init_sym_oids();
    if ((tmp = calloc(num_sym_oids, sizeof(tmp[0]))) == NULL)
        return NULL;

    memcpy(tmp, sym_oids, num_sym_oids * sizeof(tmp[0]));
    qsort(tmp, num_sym_oids, sizeof(struct sym_oid), cmp);
    return tmp;
}

static int
fix_oid_name(const char **namep, char **freeme)
{
    char *dash = strchr(*namep, '-');

    *freeme = NULL;
    if (dash == NULL)
        return 0;
    if ((*freeme = strdup(*namep)) == NULL)
        return ENOMEM;
    *namep = *freeme;
    for (dash = strchr(*namep, '-'); dash; dash = strchr(dash, '-'))
        *dash = '_';
    return 0;
}

int ASN1CALL
der_find_heim_oid_by_name(const char *str, const heim_oid **oid)
{
    size_t right = num_sym_oids - 1;
    size_t left = 0;
    char *s = NULL;
    int ret;

    *oid = NULL;
    if (sym_oids_sorted_by_name == NULL &&
        (sym_oids_sorted_by_name = sort_sym_oids(sym_cmp_name)) == NULL)
        return ENOMEM;

    if ((ret = fix_oid_name(&str, &s)))
        return ret;

    while (left <= right) {
        size_t mid = left + (right - left) / 2;
        int cmp;

        cmp = strcmp(str, sym_oids_sorted_by_name[mid].sym);
        if (cmp == 0) {
            *oid = sym_oids_sorted_by_name[mid].oid;
            free(s);
            return 0;
        }
        if (cmp < 0 && mid > 0) {/* avoid underflow */
            right = mid - 1;
        } else if (cmp < 0) {
            free(s);
            return -1;
        } else {
            left = mid + 1;
        }
    }
    free(s);
    return -1;
}

int ASN1CALL
der_find_or_parse_heim_oid(const char *str, const char *sep, heim_oid *oid)
{
    const heim_oid *found = NULL;

    switch (der_find_heim_oid_by_name(str, &found)) {
    case 0: return der_copy_oid(found, oid);
    case -1: return der_parse_heim_oid(str, sep, oid);
    default: return ENOMEM;
    }
}

int ASN1CALL
der_find_heim_oid_by_oid(const heim_oid *oid, const char **name)
{
    size_t right = num_sym_oids;
    size_t left = 0;

    *name = NULL;
    if (sym_oids_sorted_by_oid == NULL &&
        (sym_oids_sorted_by_oid = sort_sym_oids(sym_cmp_oid)) == NULL)
        return ENOMEM;

    while (left <= right) {
        size_t mid = (left + right) >> 1;
        int cmp;

        cmp = der_heim_oid_cmp(oid, sym_oids_sorted_by_oid[mid].oid);
        if (cmp == 0) {
            *name = sym_oids_sorted_by_oid[mid].sym;
            return 0;
        }
        if (cmp < 0 && mid)
            right = mid - 1;
        else if (cmp < 0)
            return -1;
        else if (mid < num_sym_oids - 1)
            left = mid + 1;
        else
            return -1;
    }
    return -1;
}

int ASN1CALL
der_match_heim_oid_by_name(const char *str, int *c, const heim_oid **oid)
{
    size_t i;
    char *s = NULL;
    int ret;

    if ((ret = fix_oid_name(&str, &s)))
        return ret;

    if (*c < 0)
        *c = 0;

    init_sym_oids();
    for (i = (size_t)*c; i < num_sym_oids; i++) {
        /*
         * XXX We need a lib/roken strcasestr(), or maybe we should support
         * globbing here.
         */
        if (strstr(sym_oids[i].sym, str)) {
            *oid = sym_oids[i].oid;
            free(s);
            if (i >= INT_MAX)
                return -1;
            *c = i + 1; /* num_sym_oids is much less than INT_MAX */
            return 0;
        }
    }
    free(s);
    return -1;
}

/* Warning: der_print_heim_oid_sym() will not round-trip */

int ASN1CALL
der_print_heim_oid_sym(const heim_oid *oid, char delim, char **strp)
{
    const char *sym;
    char *s1 = NULL;
    char *s2 = NULL;
    char *p;
    int ret;

    if (der_find_heim_oid_by_oid(oid, &sym))
        return der_print_heim_oid(oid, delim, strp);

    if ((ret = der_print_heim_oid(oid, delim, &s1)))
        return ret;
    if (asprintf(&s2, "%s (%s)", s1, sym) == -1 || s2 == NULL) {
        *strp = s1;
        return 0;
    }
    for (p = s2 + strlen(s1) + 1; *p; p++) {
        if (*p == '_')
            *p = '-';
    }
    *strp = s2;
    free(s1);
    return 0;
}
