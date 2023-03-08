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
 * This plugin authorizes requested certificate SANs and EKUs by calling a
 * service over IPC (Unix domain sockets on Linux/BSD/Illumos).
 *
 * The IPC protocol is request/response, with requests and responses sent as
 *
 *      <length><string>
 *
 * where the <length> is 4 bytes, unsigned binary in network byte order, and
 * <string> is an array of <length> bytes and does NOT include a NUL
 * terminator.
 *
 * Requests are of the form:
 *
 *      check <princ> <exttype>=<extvalue> ...
 *
 * where <princ> is a URL-escaped principal name, <exttype> is one of:
 *
 *  - san_pkinit
 *  - san_xmpp
 *  - san_email
 *  - san_ms_upn
 *  - san_dnsname
 *  - eku
 *
 * and <extvalue> is a URL-escaped string representation of the SAN or OID.
 *
 * OIDs are in the form 1.2.3.4.5.6.
 *
 * Only characters other than alphanumeric, '@', '.', '-', '_', and '/' are
 * URL-encoded.
 *
 * Responses are any of:
 *
 *  - granted
 *  - denied
 *  - error message
 *
 * Example:
 *
 *  C->S: check jane@TEST.H5L.SE san_dnsname=jane.foo.test.h5l.se eku=1.3.6.1.5.5.7.3.1
 *  S->C: granted
 *
 * Only digitalSignature and nonRepudiation key usages are allowed.  Requested
 * key usages are not sent to the CSR authorizer IPC server.
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
#include <heim-ipc.h>
#include <krb5.h>
#include <hx509.h>
#include <kdc.h>
#include <common_plugin.h>
#include <csr_authorizer_plugin.h>

/*
 * string_encode_sz() and string_encode() encode principal names and such to be
 * safe for use in our IPC text messages.  They function very much like URL
 * encoders, but '~' also gets encoded, and '.' and '@' do not.
 *
 * An unescaper is not needed here.
 */
static size_t
string_encode_sz(const char *in)
{
    size_t sz = strlen(in);

    while (*in) {
        char c = *(in++);

        switch (c) {
        case '@':
        case '.':
        case '-':
        case '_':
        case '/':
            continue;
        default:
            if (isalnum(c))
                continue;
            sz += 2;
        }
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

    if ((s = malloc(sz + 1)) == NULL)
        return NULL;
    s[sz] = '\0';

    for (i = k = 0; i < len; i++) {
        unsigned char c = ((const unsigned char *)in)[i];

        switch (c) {
        case '@':
        case '.':
        case '-':
        case '_':
        case '/':
            s[k++] = c;
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

static int
cmd_append(struct rk_strpool **cmd, const char *s0, ...)
{
    va_list ap;
    const char *arg;
    int ret = 0;

    if ((*cmd = rk_strpoolprintf(*cmd, "%s", s0)) == NULL)
        return ENOMEM;

    va_start(ap, s0);
    while ((arg = va_arg(ap, const char *))) {
        char *s;

        if ((s = string_encode(arg)) == NULL) {
            rk_strpoolfree(*cmd);
	    *cmd = NULL;
	    ret = ENOMEM;
	    goto out;
	}
        *cmd = rk_strpoolprintf(*cmd, "%s", s);
        free(s);
        if (*cmd == NULL) {
            ret = ENOMEM;
	    goto out;
	}
    }

 out:
    va_end(ap);
    return ret;
}

/* Like strpbrk(), but from the end of the string */
static char *
strrpbrk(char *s, const char *accept)
{
    char *last = NULL;
    char *p = s;

    do {
        p = strpbrk(p, accept);
        if (p != NULL) {
            last = p;
            p++;
        }
    } while (p != NULL);
    return last;
}

/*
 * For /get-tgts we need to support partial authorization of requests.  The
 * hx509_request APIs support that.
 *
 * Here we just step through the IPC server's response and mark the
 * corresponding request elements authorized so that /get-tgts can issue or not
 * issue TGTs according to which requested principals are authorized and which
 * are not.
 */
static int
mark_piecemeal_authorized(krb5_context context,
                          hx509_request csr,
                          heim_octet_string *rep)
{
    size_t san_idx = 0;
    size_t eku_idx = 0;
    char *s, *p, *rep2, *tok, *next = NULL;
    int slow_path = 0;
    int partial = 0;
    int ret = 0;

    /* We have a data, but we want a C string */
    if ((rep2 = strndup(rep->data, rep->length)) == NULL)
        return krb5_enomem(context);

    /* The first token should be "denied"; skip it */
    if ((s = strchr(rep2, ' ')) == NULL) {
        free(rep2);
        return EACCES;
    }
    s++;

    while ((tok = strtok_r(s, ",", &next))) {
        hx509_san_type san_type, san_type2;
        char *s2 = NULL;

        s = NULL; /* for strtok_r() */

        if (strncmp(tok, "eku=", sizeof("eku=") -1) == 0) {
            /*
             * Very simplistic handling of partial authz for EKUs:
             *
             *  - denial of an EKU -> deny the whole request
             *  - else below mark all EKUs approved
             */
            if (strstr(tok, ":denied")) {
                krb5_set_error_message(context, EACCES, "CSR denied because "
                                       "EKU denied: %s", tok);
                ret = EACCES;
                break;
            }
            continue;
        }

        /*
         * For SANs we check that the nth SAN in the response matches the nth
         * SAN in the hx509_request.
         */

        if (strncmp(tok, "san_pkinit=", sizeof("san_pkinit=") - 1) == 0) {
            tok += sizeof("san_pkinit=") - 1;
            san_type = HX509_SAN_TYPE_PKINIT;
        } else if (strncmp(tok, "san_dnsname=", sizeof("san_dnsname=") -1) == 0) {
            tok += sizeof("san_dnsname=") - 1;
            san_type = HX509_SAN_TYPE_DNSNAME;
        } else if (strncmp(tok, "san_email=", sizeof("san_email=") -1) == 0) {
            tok += sizeof("san_email=") - 1;
            san_type = HX509_SAN_TYPE_EMAIL;
        } else if (strncmp(tok, "san_xmpp=", sizeof("san_xmpp=") -1) == 0) {
            tok += sizeof("san_xmpp=") - 1;
            san_type = HX509_SAN_TYPE_XMPP;
        } else if (strncmp(tok, "san_ms_upn=", sizeof("san_ms_upn=") -1) == 0) {
            tok += sizeof("san_ms_upn=") - 1;
            san_type = HX509_SAN_TYPE_MS_UPN;
        } else {
            krb5_set_error_message(context, EACCES, "CSR denied because could "
                                   "not parse token in response: %s", tok);
            ret = EACCES;
            break;
        }

        /*
         * This token has to end in ":granted" or ":denied".  Using our
         * `strrpbrk()' means we can deal with principals names that have ':'
         * in them.
         */
        if ((p = strrpbrk(tok, ":")) == NULL) {
            san_idx++;
            continue;
        }
        *(p++) = '\0';

        /* Now we get the nth SAN from the authorization */
        ret = hx509_request_get_san(csr, san_idx, &san_type2, &s2);
        if (ret == HX509_NO_ITEM) {
            /* See below */
            slow_path = 1;
            break;
        }

        /* And we check that it matches the SAN in this token */
        if (ret == 0) {
            if (san_type != san_type2 ||
                strcmp(tok, s2) != 0) {
                /*
                 * We expect the tokens in the reply to be in the same order as
                 * in the request.  If not, we must take a slow path where we
                 * have to sort requests and responses then iterate them in
                 * order.
                 */
                slow_path = 1;
                hx509_xfree(s2);
                break;
            }
            hx509_xfree(s2);

            if (strcmp(p, "granted") == 0) {
                ret = hx509_request_authorize_san(csr, san_idx);
            } else {
                partial = 1;
                ret = hx509_request_reject_san(csr, san_idx);
            }
            if (ret)
                break;
        }
        san_idx++;
    }

    if (slow_path) {
        /*
         * FIXME?  Implement the slow path?
         *
         * Basically, we'd get all the SANs from the request into an array of
         * {SAN, index} and sort that array, then all the SANs from the
         * response into an array and sort it, then step a cursor through both,
         * using the index from the first to mark SANs in the request
         * authorized or rejected.
         */
        krb5_set_error_message(context, EACCES, "CSR denied because "
                               "authorizer service did not include all "
                               "piecemeal grants/denials in order");
        ret = EACCES;
    }

    /* Mark all the EKUs authorized */
    for (eku_idx = 0; ret == 0; eku_idx++)
        ret = hx509_request_authorize_eku(csr, eku_idx);
    if (ret == HX509_NO_ITEM)
        ret = 0;
    if (ret == 0 && partial) {
        krb5_set_error_message(context, EACCES, "CSR partially authorized");
        ret = EACCES;
    }

    free(rep2);
    return ret;
}

static krb5_error_code mark_authorized(hx509_request);

static int
call_svc(krb5_context context,
         heim_ipc ipc,
         hx509_request csr,
         const char *cmd,
         int piecemeal_check_ok)
{
    heim_octet_string req, resp;
    int ret;

    req.data = (void *)(uintptr_t)cmd;
    req.length = strlen(cmd);
    resp.length = 0;
    resp.data = NULL;
    ret = heim_ipc_call(ipc, &req, &resp, NULL);

    /* Check for all granted case */
    if (ret == 0 &&
        resp.length == sizeof("granted") - 1 &&
        strncasecmp(resp.data, "granted", sizeof("granted") - 1) == 0) {
        free(resp.data);
        return mark_authorized(csr); /* Full approval */
    }

    /* Check for "denied ..." piecemeal authorization case */
    if ((ret == 0 || ret == EACCES || ret == KRB5_PLUGIN_NO_HANDLE) &&
        piecemeal_check_ok &&
        resp.length > sizeof("denied") - 1 &&
        strncasecmp(resp.data, "denied", sizeof("denied") - 1) == 0) {
        /* Piecemeal authorization */
        ret = mark_piecemeal_authorized(context, csr, &resp);

        /* mark_piecemeal_authorized() should return EACCES; just in case: */
        if (ret == 0)
            ret = EACCES;
        free(resp.data);
        return ret;
    }

    /* All other failure cases */

    if (resp.data == NULL || resp.length == 0) {
        krb5_set_error_message(context, ret, "CSR authorizer IPC service "
                               "failed silently");
        free(resp.data);
        return EACCES;
    }

    if (resp.length == sizeof("ignore") - 1 &&
        strncasecmp(resp.data, "ignore", sizeof("ignore") - 1) == 0) {
        /*
         * In this case the server is saying "I can't handle this request, try
         * some other authorizer plugin".
         */
        free(resp.data);
        return KRB5_PLUGIN_NO_HANDLE;
    }

    if (resp.length == sizeof("denied") - 1 &&
        strncasecmp(resp.data, "denied", sizeof("denied") - 1) == 0) {
        krb5_set_error_message(context, ret, "CSR authorizer rejected %s",
                               cmd);
        free(resp.data);
        return EACCES;
    }

    if (resp.length > INT_MAX)
        krb5_set_error_message(context, ret, "CSR authorizer rejected %s", cmd);
    else
        krb5_set_error_message(context, ret, "CSR authorizer rejected %s: %.*s",
                               cmd, resp.length, resp.data);

    free(resp.data);
    return ret;
}

static void
frees(char **s)
{
    free(*s);
    *s = NULL;
}

static krb5_error_code
mark_authorized(hx509_request csr)
{
    size_t i;
    char *s;
    int ret = 0;

    for (i = 0; ret == 0; i++) {
        ret = hx509_request_get_eku(csr, i, &s);
        if (ret == 0)
            hx509_request_authorize_eku(csr, i);
        frees(&s);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;

    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;
        ret = hx509_request_get_san(csr, i, &san_type, &s);
        if (ret == 0)
            hx509_request_authorize_san(csr, i);
        frees(&s);
    }
    return ret == HX509_NO_ITEM ? 0 : ret;
}

static KRB5_LIB_CALL krb5_error_code
authorize(void *ctx,
          krb5_context context,
          const char *app,
          hx509_request csr,
          krb5_const_principal client,
          krb5_boolean *result)
{
    struct rk_strpool *cmd = NULL;
    krb5_error_code ret;
    hx509_context hx509ctx = NULL;
    heim_ipc ipc = NULL;
    const char *svc;
    KeyUsage ku;
    size_t i;
    char *princ = NULL;
    char *s = NULL;
    int do_check = 0;
    int piecemeal_check_ok = 1;

    if ((svc = krb5_config_get_string_default(context, NULL,
                                              "ANY:org.h5l.csr_authorizer",
                                              app ? app : "kdc",
                                              "ipc_csr_authorizer", "service",
                                              NULL)) == NULL)
        return KRB5_PLUGIN_NO_HANDLE;

    if ((ret = heim_ipc_init_context(svc, &ipc))) {
        /*
         * If the IPC authorizer is optional, then fallback on whatever is
         * next.
         */
        if (krb5_config_get_bool_default(context, NULL, FALSE,
                                         app ? app : "kdc",
                                         "ipc_csr_authorizer", "optional",
                                         NULL))
            return KRB5_PLUGIN_NO_HANDLE;
	krb5_set_error_message(context, ret, "Could not set up IPC client "
                               "end-point for service %s", svc);
        return ret;
    }

    if ((ret = hx509_context_init(&hx509ctx)))
        goto out;

    if ((ret = krb5_unparse_name(context, client, &princ)))
        goto out;

    if ((ret = cmd_append(&cmd, "check ", princ, NULL)))
        goto enomem;
    frees(&princ);

    for (i = 0; ret == 0; i++) {
        hx509_san_type san_type;
        size_t p;

        ret = hx509_request_get_san(csr, i, &san_type, &s);
        if (ret)
            break;

        /*
         * We cannot do a piecemeal check if any of the SANs could make the
         * response ambiguous.
         */
        p = strcspn(s, ",= ");
        if (s[p] != '\0')
            piecemeal_check_ok = 0;
        if (piecemeal_check_ok && strstr(s, ":granted") != NULL)
            piecemeal_check_ok = 0;

        switch (san_type) {
        case HX509_SAN_TYPE_EMAIL:
            if ((ret = cmd_append(&cmd, " san_email=", s, NULL)))
                goto enomem;
            do_check = 1;
            break;
        case HX509_SAN_TYPE_DNSNAME:
            if ((ret = cmd_append(&cmd, " san_dnsname=", s, NULL)))
                goto enomem;
            do_check = 1;
            break;
        case HX509_SAN_TYPE_XMPP:
            if ((ret = cmd_append(&cmd, " san_xmpp=", s, NULL)))
                goto enomem;
            do_check = 1;
            break;
        case HX509_SAN_TYPE_PKINIT:
            if ((ret = cmd_append(&cmd, " san_pkinit=", s, NULL)))
                goto enomem;
            do_check = 1;
            break;
        case HX509_SAN_TYPE_MS_UPN:
            if ((ret = cmd_append(&cmd, " san_ms_upn=", s, NULL)))
                goto enomem;
            do_check = 1;
            break;
        default:
            if ((ret = hx509_request_reject_san(csr, i)))
                goto out;
            break;
        }
        frees(&s);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;
    if (ret)
        goto out;

    for (i = 0; ret == 0; i++) {
        ret = hx509_request_get_eku(csr, i, &s);
        if (ret)
            break;
        if ((ret = cmd_append(&cmd, " eku=", s, NULL)))
            goto enomem;
        do_check = 1;
        frees(&s);
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;
    if (ret)
        goto out;

    ku = int2KeyUsage(0);
    ku.digitalSignature = 1;
    ku.nonRepudiation = 1;
    hx509_request_authorize_ku(csr, ku);

    if (do_check) {
        s = rk_strpoolcollect(cmd);
        cmd = NULL;
        if (s == NULL)
            goto enomem;
        if ((ret = call_svc(context, ipc, csr, s, piecemeal_check_ok)))
            goto out;
    } /* else there was nothing to check -> permit */

    *result = TRUE;
    ret = 0;
    goto out;

enomem:
    ret = krb5_enomem(context);
    goto out;

out:
    heim_ipc_free_context(ipc);
    hx509_context_free(&hx509ctx);
    if (cmd)
        rk_strpoolfree(cmd);
    free(princ);
    free(s);
    return ret;
}

static KRB5_LIB_CALL krb5_error_code
ipc_csr_authorizer_init(krb5_context context, void **c)
{
    *c = NULL;
    return 0;
}

static KRB5_LIB_CALL void
ipc_csr_authorizer_fini(void *c)
{
}

static krb5plugin_csr_authorizer_ftable plug_desc =
    { 1, ipc_csr_authorizer_init, ipc_csr_authorizer_fini, authorize };

static krb5plugin_csr_authorizer_ftable *plugs[] = { &plug_desc };

static uintptr_t
ipc_csr_authorizer_get_instance(const char *libname)
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
    *get_instance = ipc_csr_authorizer_get_instance;
    *num_plugins = sizeof(plugs) / sizeof(plugs[0]);
    *plugins = (krb5_plugin_common_ftable_cp *)plugs;
    return 0;
}
