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

/*
 * This plugin authorizes requested certificate SANs and EKUs by checking for
 * existence of files of the form:
 *
 *
 *      /<path>/<princ>/<ext>-<value>
 *
 * where <path> is the value of:
 *
 *      [kdc] simple_csr_authorizer_directory = PATH
 *
 * <princ> is a requesting client principal name with all characters other than
 * alphanumeric, '-', '_', and non-leading '.' URL-encoded.
 *
 * <ext> is one of:
 *
 *  - pkinit        (SAN)
 *  - xmpp          (SAN)
 *  - email         (SAN)
 *  - ms-upn        (SAN)
 *  - dnsname       (SAN)
 *  - eku           (EKU OID)
 *
 * and <value> is a display form of the SAN or EKU OID, with SANs URL-encoded
 * just like principal names (see above).
 *
 * OIDs are of the form "1.2.3.4.5".
 *
 * Only digitalSignature and nonRepudiation key usage values are permitted.
 */
#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <roken.h>
#include <krb5.h>
#include <hx509.h>
#include <kdc.h>
#include <common_plugin.h>
#include <csr_authorizer_plugin.h>

/*
 * string_encode_sz() and string_encode() encode a string to be safe for use as
 * a file name.  They function very much like URL encoders, but '~' also gets
 * encoded, and '@', '-', '_', and non-leading '.' do not.
 *
 * A corresponding decoder is not needed.
 */
static size_t
string_encode_sz(const char *in)
{
    size_t sz = strlen(in);
    int first = 1;

    while (*in) {
        char c = *(in++);

        switch (c) {
        case '@':
        case '-':
        case '_':
            break;
        case '.':
            if (first)
                sz += 2;
            break;
        default:
            if (!isalnum(c))
                sz += 2;
        }
        first = 0;
    }
    return sz;
}

static char *
string_encode(const char *in)
{
    size_t len = strlen(in);
    size_t sz = string_encode_sz(in);
    size_t i, k;
    char *s;
    int first = 1;

    if ((s = malloc(sz + 1)) == NULL)
        return NULL;
    s[sz] = '\0';

    for (i = k = 0; i < len; i++, first = 0) {
        unsigned char c = ((const unsigned char *)in)[i];

        switch (c) {
        case '@':
        case '-':
        case '_':
            s[k++] = c;
            break;
        case '.':
            if (first) {
                s[k++] = '%';
                s[k++] = "0123456789abcdef"[(c&0xff)>>4];
                s[k++] = "0123456789abcdef"[(c&0x0f)];
            } else {
                s[k++] = c;
            }
            break;
        default:
            if (isalnum(c)) {
                s[k++] = c;
            } else  {
                s[k++] = '%';
                s[k++] = "0123456789abcdef"[(c&0xff)>>4];
                s[k++] = "0123456789abcdef"[(c&0x0f)];
            }
        }
    }
    return s;
}

static void
frees(char **s)
{
    free(*s);
    *s = NULL;
}

static KRB5_LIB_CALL krb5_error_code
authorize(void *ctx,
          krb5_context context,
          const char *app,
          hx509_request csr,
          krb5_const_principal client,
          krb5_boolean *result)
{
    krb5_error_code ret;
    hx509_context hx509ctx = NULL;
    KeyUsage ku;
    const char *d;
    size_t i;
    char *princ = NULL;
    char *s = NULL;

    if ((d = krb5_config_get_string(context, NULL, app ? app : "kdc",
                                    "simple_csr_authorizer_directory",
                                    NULL)) == NULL)
        return KRB5_PLUGIN_NO_HANDLE;

    if ((ret = hx509_context_init(&hx509ctx)))
        return ret;

    if ((ret = krb5_unparse_name(context, client, &princ)))
        goto out;

    s = string_encode(princ);
    free(princ);
    princ = NULL;
    if (s == NULL)
        goto enomem;

    princ = s;
    s = NULL;

    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;
        struct stat st;
        const char *prefix;
        char *san;
        char *p;

        ret = hx509_request_get_san(csr, i, &san_type, &s);
        if (ret)
            break;
        switch (san_type) {
        case HX509_SAN_TYPE_EMAIL:
            prefix = "email";
            break;
        case HX509_SAN_TYPE_DNSNAME:
            prefix = "dnsname";
            break;
        case HX509_SAN_TYPE_XMPP:
            prefix = "xmpp";
            break;
        case HX509_SAN_TYPE_PKINIT:
            prefix = "pkinit";
            break;
        case HX509_SAN_TYPE_MS_UPN:
            prefix = "ms-upn";
            break;
        default:
            ret = ENOTSUP;
            break;
        }
        if (ret)
            break;

        if ((san = string_encode(s)) == NULL ||
            asprintf(&p, "%s/%s/%s-%s", d, princ, prefix, san) == -1 ||
            p == NULL) {
            free(san);
            goto enomem;
        }
        ret = stat(p, &st) == -1 ? errno : 0;
        free(san);
        free(p);
        frees(&s);
        if (ret)
            goto skip;
        ret = hx509_request_authorize_san(csr, i);
    }
    frees(&s);
    if (ret == HX509_NO_ITEM)
        ret = 0;
    if (ret)
        goto out;

    for (i = 0; ret == 0; i++) {
        struct stat st;
        char *p;

        ret = hx509_request_get_eku(csr, i, &s);
        if (ret)
            break;
        if (asprintf(&p, "%s/%s/eku-%s", d, princ, s) == -1 || p == NULL)
            goto enomem;
        ret = stat(p, &st) == -1 ? errno : 0;
        free(p);
        frees(&s);
        if (ret)
            goto skip;
        ret = hx509_request_authorize_eku(csr, i);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;
    if (ret)
        goto out;

    ku = int2KeyUsage(0);
    ku.digitalSignature = 1;
    ku.nonRepudiation = 1;
    hx509_request_authorize_ku(csr, ku);

    *result = TRUE;
    ret = 0;
    goto out;

skip:
    /* Allow another plugin to get a crack at this */
    ret = KRB5_PLUGIN_NO_HANDLE;
    goto out;

enomem:
    ret = krb5_enomem(context);
    goto out;

out:
    hx509_context_free(&hx509ctx);
    free(princ);
    free(s);
    return ret;
}

static KRB5_LIB_CALL krb5_error_code
simple_csr_authorizer_init(krb5_context context, void **c)
{
    *c = NULL;
    return 0;
}

static KRB5_LIB_CALL void
simple_csr_authorizer_fini(void *c)
{
}

static krb5plugin_csr_authorizer_ftable plug_desc =
    { 1, simple_csr_authorizer_init, simple_csr_authorizer_fini, authorize };

static krb5plugin_csr_authorizer_ftable *plugs[] = { &plug_desc };

static uintptr_t
simple_csr_authorizer_get_instance(const char *libname)
{
    if (strcmp(libname, "krb5") == 0)
        return krb5_get_instance(libname);
    if (strcmp(libname, "kdc") == 0)
        return kdc_get_instance(libname);
    if (strcmp(libname, "hx509") == 0)
        return hx509_get_instance(libname);
    return 0;
}

krb5_plugin_load_ft kdc_csr_authorizer_plugin_load;

krb5_error_code KRB5_CALLCONV
kdc_csr_authorizer_plugin_load(heim_pcontext context,
                               krb5_get_instance_func_t *get_instance,
                               size_t *num_plugins,
                               krb5_plugin_common_ftable_cp **plugins)
{
    *get_instance = simple_csr_authorizer_get_instance;
    *num_plugins = sizeof(plugs) / sizeof(plugs[0]);
    *plugins = (krb5_plugin_common_ftable_cp *)plugs;
    return 0;
}
