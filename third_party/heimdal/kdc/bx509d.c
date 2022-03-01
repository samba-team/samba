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
 * This file implements a RESTful HTTPS API to an online CA, as well as an
 * HTTP/Negotiate token issuer.
 *
 * Users are authenticated with bearer tokens.
 *
 * This is essentially a RESTful online CA sharing code with the KDC's kx509
 * online CA, and also a proxy for PKINIT and GSS-API (Negotiate).
 *
 * To get a key certified:
 *
 *  GET /bx509?csr=<base64-encoded-PKCS#10-CSR>
 *
 * To get an HTTP/Negotiate token:
 *
 *  GET /bnegotiate?target=<acceptor-principal>
 *
 * which, if authorized, produces a Negotiate token (base64-encoded, as
 * expected, with the "Negotiate " prefix, ready to be put in an Authorization:
 * header).
 *
 * TBD:
 *  - rewrite to not use libmicrohttpd but an alternative more appropriate to
 *    Heimdal's license (though libmicrohttpd will do)
 *  - /bx509 should include the certificate chain
 *  - /bx509 should support HTTP/Negotiate
 *  - there should be an end-point for fetching an issuer's chain
 *  - maybe add /bkrb5 which returns a KRB-CRED with the user's TGT
 *
 * NOTES:
 *  - We use krb5_error_code values as much as possible.  Where we need to use
 *    MHD_NO because we got that from an mhd function and cannot respond with
 *    an HTTP response, we use (krb5_error_code)-1, and later map that to
 *    MHD_NO.
 *
 *    (MHD_NO is an ENOMEM-cannot-even-make-a-static-503-response level event.)
 */

#define _XOPEN_SOURCE_EXTENDED  1
#define _DEFAULT_SOURCE  1
#define _BSD_SOURCE  1
#define _GNU_SOURCE  1

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <microhttpd.h>
#include "kdc_locl.h"
#include "token_validator_plugin.h"
#include <getarg.h>
#include <roken.h>
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <hx509.h>
#include "../lib/hx509/hx_locl.h"
#include <hx509-private.h>

#define heim_pcontext krb5_context
#define heim_pconfig krb5_context
#include <heimbase-svc.h>

#if MHD_VERSION < 0x00097002 || defined(MHD_YES)
/* libmicrohttpd changed these from int valued macros to an enum in 0.9.71 */
#ifdef MHD_YES
#undef MHD_YES
#undef MHD_NO
#endif
enum MHD_Result { MHD_NO = 0, MHD_YES = 1 };
#define MHD_YES 1
#define MHD_NO 0
typedef int heim_mhd_result;
#else
typedef enum MHD_Result heim_mhd_result;
#endif

enum k5_creds_kind { K5_CREDS_EPHEMERAL, K5_CREDS_CACHED };

typedef struct bx509_request_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;

    struct MHD_Connection *connection;
    krb5_times token_times;
    time_t req_life;
    hx509_request req;
    const char *for_cname;
    const char *target;
    const char *redir;
    enum k5_creds_kind cckind;
    char *pkix_store;
    char *ccname;
    char *freeme1;
    krb5_addresses tgt_addresses; /* For /get-tgt */
    char frombuf[128];
} *bx509_request_desc;

static void
audit_trail(bx509_request_desc r, krb5_error_code ret)
{
    const char *retname = NULL;

    /* Get a symbolic name for some error codes */
#define CASE(x) case x : retname = #x; break
    switch (ret) {
    CASE(ENOMEM);
    CASE(EACCES);
    CASE(HDB_ERR_NOT_FOUND_HERE);
    CASE(HDB_ERR_WRONG_REALM);
    CASE(HDB_ERR_EXISTS);
    CASE(HDB_ERR_KVNO_NOT_FOUND);
    CASE(HDB_ERR_NOENTRY);
    CASE(HDB_ERR_NO_MKEY);
    CASE(KRB5KDC_ERR_BADOPTION);
    CASE(KRB5KDC_ERR_CANNOT_POSTDATE);
    CASE(KRB5KDC_ERR_CLIENT_NOTYET);
    CASE(KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN);
    CASE(KRB5KDC_ERR_ETYPE_NOSUPP);
    CASE(KRB5KDC_ERR_KEY_EXPIRED);
    CASE(KRB5KDC_ERR_NAME_EXP);
    CASE(KRB5KDC_ERR_NEVER_VALID);
    CASE(KRB5KDC_ERR_NONE);
    CASE(KRB5KDC_ERR_NULL_KEY);
    CASE(KRB5KDC_ERR_PADATA_TYPE_NOSUPP);
    CASE(KRB5KDC_ERR_POLICY);
    CASE(KRB5KDC_ERR_PREAUTH_FAILED);
    CASE(KRB5KDC_ERR_PREAUTH_REQUIRED);
    CASE(KRB5KDC_ERR_SERVER_NOMATCH);
    CASE(KRB5KDC_ERR_SERVICE_EXP);
    CASE(KRB5KDC_ERR_SERVICE_NOTYET);
    CASE(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    CASE(KRB5KDC_ERR_TRTYPE_NOSUPP);
    CASE(KRB5KRB_ERR_RESPONSE_TOO_BIG);
    /* XXX Add relevant error codes */
    case 0:
        retname = "SUCCESS";
        break;
    default:
        retname = NULL;
        break;
    }

    /* Let's save a few bytes */
    if (retname && strncmp("KRB5KDC_", retname, sizeof("KRB5KDC_") - 1) == 0)
        retname += sizeof("KRB5KDC_") - 1;
#undef PREFIX
    heim_audit_trail((heim_svc_req_desc)r, ret, retname);
}

static krb5_log_facility *logfac;
static pthread_key_t k5ctx;

static krb5_error_code
get_krb5_context(krb5_context *contextp)
{
    krb5_error_code ret;

    if ((*contextp = pthread_getspecific(k5ctx)))
        return 0;
    if ((ret = krb5_init_context(contextp)))
        return *contextp = NULL, ret;
    (void) pthread_setspecific(k5ctx, *contextp);
    return *contextp ? 0 : ENOMEM;
}

static int port = -1;
static int help_flag;
static int daemonize;
static int daemon_child_fd = -1;
static int verbose_counter;
static int version_flag;
static int reverse_proxied_flag;
static int thread_per_client_flag;
struct getarg_strings audiences;
static const char *cert_file;
static const char *priv_key_file;
static const char *cache_dir;
static char *impersonation_key_fn;

static krb5_error_code resp(struct bx509_request_desc *, int,
                            enum MHD_ResponseMemoryMode, const char *,
                            const void *, size_t, const char *);
static krb5_error_code bad_req(struct bx509_request_desc *, krb5_error_code, int,
                               const char *, ...)
                               HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 4, 5));

static krb5_error_code bad_enomem(struct bx509_request_desc *, krb5_error_code);
static krb5_error_code bad_400(struct bx509_request_desc *, krb5_error_code, char *);
static krb5_error_code bad_401(struct bx509_request_desc *, char *);
static krb5_error_code bad_403(struct bx509_request_desc *, krb5_error_code, char *);
static krb5_error_code bad_404(struct bx509_request_desc *, const char *);
static krb5_error_code bad_405(struct bx509_request_desc *, const char *);
static krb5_error_code bad_500(struct bx509_request_desc *, krb5_error_code, const char *);
static krb5_error_code bad_503(struct bx509_request_desc *, krb5_error_code, const char *);

static int
validate_token(struct bx509_request_desc *r)
{
    krb5_error_code ret;
    krb5_principal cprinc = NULL;
    const char *token;
    const char *host;
    char token_type[64]; /* Plenty */
    char *p;
    krb5_data tok;
    size_t host_len, brk, i;

    memset(&r->token_times, 0, sizeof(r->token_times));
    host = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                       MHD_HTTP_HEADER_HOST);
    if (host == NULL)
        return bad_400(r, EINVAL, "Host header is missing");

    /* Exclude port number here (IPv6-safe because of the below) */
    host_len = ((p = strchr(host, ':'))) ? p - host : strlen(host);

    token = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                        MHD_HTTP_HEADER_AUTHORIZATION);
    if (token == NULL)
        return bad_401(r, "Authorization token is missing");
    brk = strcspn(token, " \t");
    if (token[brk] == '\0' || brk > sizeof(token_type) - 1)
        return bad_401(r, "Authorization token is missing");
    memcpy(token_type, token, brk);
    token_type[brk] = '\0';
    token += brk + 1;
    tok.length = strlen(token);
    tok.data = (void *)(uintptr_t)token;

    for (i = 0; i < audiences.num_strings; i++)
        if (strncasecmp(host, audiences.strings[i], host_len) == 0 &&
            audiences.strings[i][host_len] == '\0')
            break;
    if (i == audiences.num_strings)
        return bad_403(r, EINVAL, "Host: value is not accepted here");

    r->sname = strdup(host); /* No need to check for ENOMEM here */

    ret = kdc_validate_token(r->context, NULL /* realm */, token_type, &tok,
                             (const char **)&audiences.strings[i], 1,
                             &cprinc, &r->token_times);
    if (ret)
        return bad_403(r, ret, "Token validation failed");
    if (cprinc == NULL)
        return bad_403(r, ret, "Could not extract a principal name "
                       "from token");
    ret = krb5_unparse_name(r->context, cprinc, &r->cname);
    krb5_free_principal(r->context, cprinc);
    if (ret)
        return bad_503(r, ret, "Could not parse principal name");
    return ret;
}

static void
generate_key(hx509_context context,
             const char *key_name,
             const char *gen_type,
             unsigned long gen_bits,
             char **fn)
{
    struct hx509_generate_private_context *key_gen_ctx = NULL;
    hx509_private_key key = NULL;
    hx509_certs certs = NULL;
    hx509_cert cert = NULL;
    int ret;

    if (strcmp(gen_type, "rsa") != 0)
        errx(1, "Only RSA keys are supported at this time");

    if (asprintf(fn, "PEM-FILE:%s/.%s_priv_key.pem",
                 cache_dir, key_name) == -1 ||
        *fn == NULL)
        err(1, "Could not set up private key for %s", key_name);

    ret = _hx509_generate_private_key_init(context,
                                           ASN1_OID_ID_PKCS1_RSAENCRYPTION,
                                           &key_gen_ctx);
    if (ret == 0)
        ret = _hx509_generate_private_key_bits(context, key_gen_ctx, gen_bits);
    if (ret == 0)
        ret = _hx509_generate_private_key(context, key_gen_ctx, &key);
    if (ret == 0)
        cert = hx509_cert_init_private_key(context, key, NULL);
    if (ret == 0)
        ret = hx509_certs_init(context, *fn,
                               HX509_CERTS_CREATE | HX509_CERTS_UNPROTECT_ALL,
                               NULL, &certs);
    if (ret == 0)
        ret = hx509_certs_add(context, certs, cert);
    if (ret == 0)
        ret = hx509_certs_store(context, certs, 0, NULL);
    if (ret)
        hx509_err(context, 1, ret, "Could not generate and save private key "
                  "for %s", key_name);

    _hx509_generate_private_key_free(&key_gen_ctx);
    hx509_private_key_free(&key);
    hx509_certs_free(&certs);
    hx509_cert_free(cert);
}

static void
k5_free_context(void *ctx)
{
    krb5_free_context(ctx);
}

#ifndef HAVE_UNLINKAT
static int
unlink1file(const char *dname, const char *name)
{
    char p[PATH_MAX];

    if (strlcpy(p, dname, sizeof(p)) < sizeof(p) &&
        strlcat(p, "/", sizeof(p)) < sizeof(p) &&
        strlcat(p, name, sizeof(p)) < sizeof(p))
        return unlink(p);
    return ERANGE;
}
#endif

static void
rm_cache_dir(void)
{
    struct dirent *e;
    DIR *d;

    /*
     * This works, but not on Win32:
     *
     *  (void) simple_execlp("rm", "rm", "-rf", cache_dir, NULL);
     *
     * We make no directories in `cache_dir', so we need not recurse.
     */
    if ((d = opendir(cache_dir)) == NULL)
        return;

    while ((e = readdir(d))) {
#ifdef HAVE_UNLINKAT
        /*
         * Because unlinkat() takes a directory FD, implementing one for
         * libroken is tricky at best.  Instead we might want to implement an
         * rm_dash_rf() function in lib/roken.
         */
        (void) unlinkat(dirfd(d), e->d_name, 0);
#else
        (void) unlink1file(cache_dir, e->d_name);
#endif
    }
    (void) closedir(d);
    (void) rmdir(cache_dir);
}

static krb5_error_code
mk_pkix_store(char **pkix_store)
{
    char *s = NULL;
    int ret = ENOMEM;
    int fd;

    *pkix_store = NULL;
    if (asprintf(&s, "PEM-FILE:%s/pkix-XXXXXX", cache_dir) == -1 ||
        s == NULL) {
        free(s);
        return ret;
    }
    /*
     * This way of using mkstemp() isn't safer than mktemp(), but we want to
     * quiet the warning that we'd get if we used mktemp().
     */
    if ((fd = mkstemp(s + sizeof("PEM-FILE:") - 1)) == -1) {
        free(s);
        return errno;
    }
    (void) close(fd);
    *pkix_store = s;
    return 0;
}

/*
 * XXX Shouldn't be a body, but a status message.  The body should be
 * configurable to be from a file.  MHD doesn't give us a way to set the
 * response status message though, just the body.
 */
static krb5_error_code
resp(struct bx509_request_desc *r,
     int http_status_code,
     enum MHD_ResponseMemoryMode rmmode,
     const char *content_type,
     const void *body,
     size_t bodylen,
     const char *token)
{
    struct MHD_Response *response;
    int mret = MHD_YES;

    (void) gettimeofday(&r->tv_end, NULL);
    if (http_status_code == MHD_HTTP_OK ||
        http_status_code == MHD_HTTP_TEMPORARY_REDIRECT)
        audit_trail(r, 0);

    response = MHD_create_response_from_buffer(bodylen, rk_UNCONST(body),
                                               rmmode);
    if (response == NULL)
        return -1;
    mret = MHD_add_response_header(response, MHD_HTTP_HEADER_CACHE_CONTROL,
                                   "no-store, max-age=0");
    if (mret == MHD_YES && http_status_code == MHD_HTTP_UNAUTHORIZED) {
        mret = MHD_add_response_header(response,
                                       MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                                       "Bearer");
        if (mret == MHD_YES)
            mret = MHD_add_response_header(response,
                                           MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                                           "Negotiate");
    } else if (mret == MHD_YES && http_status_code == MHD_HTTP_TEMPORARY_REDIRECT) {
        const char *redir;

        /* XXX Move this */
        redir = MHD_lookup_connection_value(r->connection, MHD_GET_ARGUMENT_KIND,
                                            "redirect");
        mret = MHD_add_response_header(response, MHD_HTTP_HEADER_LOCATION,
                                       redir);
        if (mret != MHD_NO && token)
            mret = MHD_add_response_header(response,
                                           MHD_HTTP_HEADER_AUTHORIZATION,
                                           token);
    }
    if (mret == MHD_YES && content_type) {
        mret = MHD_add_response_header(response,
                                       MHD_HTTP_HEADER_CONTENT_TYPE,
                                       content_type);
    }
    if (mret == MHD_YES)
        mret = MHD_queue_response(r->connection, http_status_code, response);
    MHD_destroy_response(response);
    return mret == MHD_NO ? -1 : 0;
}

static krb5_error_code
bad_reqv(struct bx509_request_desc *r,
         krb5_error_code code,
         int http_status_code,
         const char *fmt,
         va_list ap)
{
    krb5_error_code ret;
    krb5_context context = NULL;
    const char *k5msg = NULL;
    const char *emsg = NULL;
    char *formatted = NULL;
    char *msg = NULL;

    heim_audit_setkv_number((heim_svc_req_desc)r, "http-status-code",
			    http_status_code);
    (void) gettimeofday(&r->tv_end, NULL);
    if (code == ENOMEM) {
        if (r->context)
            krb5_log_msg(r->context, logfac, 1, NULL, "Out of memory");
        audit_trail(r, code);
        return resp(r, http_status_code, MHD_RESPMEM_PERSISTENT,
                    NULL, fmt, strlen(fmt), NULL);
    }

    if (code) {
        if (r->context)
            emsg = k5msg = krb5_get_error_message(r->context, code);
        else
            emsg = strerror(code);
    }

    ret = vasprintf(&formatted, fmt, ap) == -1;
    if (code) {
        if (ret > -1 && formatted)
            ret = asprintf(&msg, "%s: %s (%d)", formatted, emsg, (int)code);
    } else {
        msg = formatted;
        formatted = NULL;
    }
    heim_audit_addreason((heim_svc_req_desc)r, "%s", msg);
    audit_trail(r, code);
    krb5_free_error_message(context, k5msg);

    if (ret == -1 || msg == NULL) {
        if (context)
            krb5_log_msg(r->context, logfac, 1, NULL, "Out of memory");
        return resp(r, MHD_HTTP_SERVICE_UNAVAILABLE, MHD_RESPMEM_PERSISTENT,
                    NULL, "Out of memory", sizeof("Out of memory") - 1, NULL);
    }

    ret = resp(r, http_status_code, MHD_RESPMEM_MUST_COPY,
               NULL, msg, strlen(msg), NULL);
    free(formatted);
    free(msg);
    return ret == -1 ? -1 : code;
}

static krb5_error_code
bad_req(struct bx509_request_desc *r,
        krb5_error_code code,
        int http_status_code,
        const char *fmt,
        ...)
{
    krb5_error_code ret;
    va_list ap;

    va_start(ap, fmt);
    ret = bad_reqv(r, code, http_status_code, fmt, ap);
    va_end(ap);
    return ret;
}

static krb5_error_code
bad_enomem(struct bx509_request_desc *r, krb5_error_code ret)
{
    return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                   "Out of memory");
}

static krb5_error_code
bad_400(struct bx509_request_desc *r, int ret, char *reason)
{
    return bad_req(r, ret, MHD_HTTP_BAD_REQUEST, "%s", reason);
}

static krb5_error_code
bad_401(struct bx509_request_desc *r, char *reason)
{
    return bad_req(r, EACCES, MHD_HTTP_UNAUTHORIZED, "%s", reason);
}

static krb5_error_code
bad_403(struct bx509_request_desc *r, krb5_error_code ret, char *reason)
{
    return bad_req(r, ret, MHD_HTTP_FORBIDDEN, "%s", reason);
}

static krb5_error_code
bad_404(struct bx509_request_desc *r, const char *name)
{
    return bad_req(r, ENOENT, MHD_HTTP_NOT_FOUND,
                   "Resource not found: %s", name);
}

static krb5_error_code
bad_405(struct bx509_request_desc *r, const char *method)
{
    return bad_req(r, EPERM, MHD_HTTP_METHOD_NOT_ALLOWED,
                   "Method not supported: %s", method);
}

static krb5_error_code
bad_500(struct bx509_request_desc *r,
        krb5_error_code ret,
        const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_INTERNAL_SERVER_ERROR,
                   "Internal error: %s", reason);
}

static krb5_error_code
bad_503(struct bx509_request_desc *r,
        krb5_error_code ret,
        const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                   "Service unavailable: %s", reason);
}

static krb5_error_code
good_bx509(struct bx509_request_desc *r)
{
    krb5_error_code ret;
    const char *fn;
    size_t bodylen;
    void *body;

    /*
     * This `fn' thing is just to quiet linters that think "hey, strchr() can
     * return NULL so...", but here we've build `r->pkix_store' and know it has
     * a ':'.
     */
    if (r->pkix_store == NULL)
        return bad_503(r, EINVAL, "Internal error"); /* Quiet warnings */
    fn = strchr(r->pkix_store, ':');
    fn = fn ? fn + 1 : r->pkix_store;
    ret = rk_undumpdata(fn, &body, &bodylen);
    if (ret)
        return bad_503(r, ret, "Could not recover issued certificate "
                       "from PKIX store");

    (void) gettimeofday(&r->tv_end, NULL);
    ret = resp(r, MHD_HTTP_OK, MHD_RESPMEM_MUST_COPY, "application/x-pem-file",
               body, bodylen, NULL);
    free(body);
    return ret;
}

static heim_mhd_result
bx509_param_cb(void *d,
               enum MHD_ValueKind kind,
               const char *key,
               const char *val)
{
    struct bx509_request_desc *r = d;
    heim_oid oid = { 0, 0 };

    if (strcmp(key, "eku") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS, "requested_eku",
                         "%s", val);
        r->error_code = der_parse_heim_oid(val, ".", &oid);
        if (r->error_code == 0)
            r->error_code = hx509_request_add_eku(r->context->hx509ctx, r->req, &oid);
        der_free_oid(&oid);
    } else if (strcmp(key, "dNSName") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_dNSName", "%s", val);
        r->error_code = hx509_request_add_dns_name(r->context->hx509ctx, r->req, val);
    } else if (strcmp(key, "rfc822Name") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_rfc822Name", "%s", val);
        r->error_code = hx509_request_add_email(r->context->hx509ctx, r->req, val);
    } else if (strcmp(key, "xMPPName") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_xMPPName", "%s", val);
        r->error_code = hx509_request_add_xmpp_name(r->context->hx509ctx, r->req,
                                             val);
    } else if (strcmp(key, "krb5PrincipalName") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_krb5PrincipalName", "%s", val);
        r->error_code = hx509_request_add_pkinit(r->context->hx509ctx, r->req,
                                          val);
    } else if (strcmp(key, "ms-upn") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_ms_upn", "%s", val);
        r->error_code = hx509_request_add_ms_upn_name(r->context->hx509ctx, r->req,
                                               val);
    } else if (strcmp(key, "registeredID") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_registered_id", "%s", val);
        r->error_code = der_parse_heim_oid(val, ".", &oid);
        if (r->error_code == 0)
            r->error_code = hx509_request_add_registered(r->context->hx509ctx, r->req,
                                                  &oid);
        der_free_oid(&oid);
    } else if (strcmp(key, "csr") == 0 && val) {
        heim_audit_setkv_bool((heim_svc_req_desc)r, "requested_csr", TRUE);
        r->error_code = 0; /* Handled upstairs */
    } else if (strcmp(key, "lifetime") == 0 && val) {
        r->req_life = parse_time(val, "day");
    } else {
        /* Produce error for unknown params */
        heim_audit_setkv_bool((heim_svc_req_desc)r, "requested_unknown", TRUE);
        krb5_set_error_message(r->context, r->error_code = ENOTSUP,
                               "Query parameter %s not supported", key);
    }
    return r->error_code == 0 ? MHD_YES : MHD_NO /* Stop iterating */;
}

static krb5_error_code
authorize_CSR(struct bx509_request_desc *r,
              krb5_data *csr,
              krb5_const_principal p)
{
    krb5_error_code ret;

    ret = hx509_request_parse_der(r->context->hx509ctx, csr, &r->req);
    if (ret)
        return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not parse CSR");
    r->error_code = 0;
    (void) MHD_get_connection_values(r->connection, MHD_GET_ARGUMENT_KIND,
                                     bx509_param_cb, r);
    ret = r->error_code;
    if (ret)
        return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not handle query parameters");

    ret = kdc_authorize_csr(r->context, "bx509", r->req, p);
    if (ret)
        return bad_403(r, ret, "Not authorized to requested certificate");
    return ret;
}

/*
 * hx509_certs_iter_f() callback to assign a private key to the first cert in a
 * store.
 */
static int HX509_LIB_CALL
set_priv_key(hx509_context context, void *d, hx509_cert c)
{
    (void) _hx509_cert_assign_key(c, (hx509_private_key)d);
    return -1; /* stop iteration */
}

static krb5_error_code
store_certs(hx509_context context,
            const char *store,
            hx509_certs store_these,
            hx509_private_key key)
{
    krb5_error_code ret;
    hx509_certs certs = NULL;

    ret = hx509_certs_init(context, store, HX509_CERTS_CREATE, NULL,
                           &certs);
    if (ret == 0) {
        if (key)
            (void) hx509_certs_iter_f(context, store_these, set_priv_key, key);
        hx509_certs_merge(context, certs, store_these);
    }
    if (ret == 0)
        hx509_certs_store(context, certs, 0, NULL);
    hx509_certs_free(&certs);
    return ret;
}

/* Setup a CSR for bx509() */
static krb5_error_code
do_CA(struct bx509_request_desc *r, const char *csr)
{
    krb5_error_code ret = 0;
    krb5_principal p;
    hx509_certs certs = NULL;
    krb5_data d;
    ssize_t bytes;
    char *csr2, *q;

    /*
     * Work around bug where microhttpd decodes %2b to + then + to space.  That
     * bug does not affect other base64 special characters that get URI
     * %-encoded.
     */
    if ((csr2 = strdup(csr)) == NULL)
        return bad_enomem(r, ENOMEM);
    for (q = strchr(csr2, ' '); q; q = strchr(q + 1, ' '))
        *q = '+';

    ret = krb5_parse_name(r->context, r->cname, &p);
    if (ret) {
        free(csr2);
        return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not parse principal name");
    }

    /* Set CSR */
    if ((d.data = malloc(strlen(csr2))) == NULL) {
        krb5_free_principal(r->context, p);
        free(csr2);
        return bad_enomem(r, ENOMEM);
    }

    bytes = rk_base64_decode(csr2, d.data);
    free(csr2);
    if (bytes < 0)
        ret = errno;
    else
        d.length = bytes;
    if (ret) {
        krb5_free_principal(r->context, p);
        free(d.data);
        return bad_500(r, ret, "Invalid base64 encoding of CSR");
    }

    /*
     * Parses and validates the CSR, adds external extension requests from
     * query parameters, then checks authorization.
     */
    ret = authorize_CSR(r, &d, p);
    free(d.data);
    d.data = 0;
    d.length = 0;
    if (ret) {
        krb5_free_principal(r->context, p);
        return ret; /* authorize_CSR() calls bad_req() */
    }

    /* Issue the certificate */
    ret = kdc_issue_certificate(r->context, "bx509", logfac, r->req, p,
                                &r->token_times, r->req_life,
                                1 /* send_chain */, &certs);
    krb5_free_principal(r->context, p);
    if (ret) {
        if (ret == KRB5KDC_ERR_POLICY || ret == EACCES)
            return bad_403(r, ret,
                           "Certificate request denied for policy reasons");
        return bad_500(r, ret, "Certificate issuance failed");
    }

    /* Setup PKIX store */
    if ((ret = mk_pkix_store(&r->pkix_store)))
        return bad_500(r, ret,
                       "Could not create PEM store for issued certificate");

    ret = store_certs(r->context->hx509ctx, r->pkix_store, certs, NULL);
    hx509_certs_free(&certs);
    if (ret)
        return bad_500(r, ret, "Failed to convert issued"
                       " certificate and chain to PEM");
    return 0;
}

/* Copied from kdc/connect.c */
static void
addr_to_string(krb5_context context,
               struct sockaddr *addr,
               char *str,
               size_t len)
{
    krb5_error_code ret;
    krb5_address a;

    ret = krb5_sockaddr2address(context, addr, &a);
    if (ret == 0) {
        ret = krb5_print_address(&a, str, len, &len);
        krb5_free_address(context, &a);
    }
    if (ret)
        snprintf(str, len, "<family=%d>", addr->sa_family);
}

static krb5_error_code
set_req_desc(struct MHD_Connection *connection,
             const char *url,
             struct bx509_request_desc *r)
{
    const union MHD_ConnectionInfo *ci;
    const char *token;
    krb5_error_code ret;

    memset(r, 0, sizeof(*r));
    (void) gettimeofday(&r->tv_start, NULL);

    ret = get_krb5_context(&r->context);
    r->connection = connection;
    r->request.data = "<HTTP-REQUEST>";
    r->request.length = sizeof("<HTTP-REQUEST>");
    r->from = r->frombuf;
    r->tgt_addresses.len = 0;
    r->tgt_addresses.val = 0;
    r->hcontext = r->context ? r->context->hcontext : NULL;
    r->config = NULL;
    r->logf = logfac;
    r->reqtype = url;
    r->target = r->redir = NULL;
    r->pkix_store = NULL;
    r->for_cname = NULL;
    r->freeme1 = NULL;
    r->reason = NULL;
    r->ccname = NULL;
    r->reply = NULL;
    r->sname = NULL;
    r->cname = NULL;
    r->addr = NULL;
    r->req = NULL;
    r->req_life = 0;
    r->error_code = ret;
    r->kv = heim_dict_create(10);
    r->attributes = heim_dict_create(1);
    if (ret == 0 && (r->kv == NULL || r->attributes == NULL))
        r->error_code = ret = ENOMEM;
    ci = MHD_get_connection_info(connection,
                                 MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci) {
        r->addr = ci->client_addr;
        addr_to_string(r->context, r->addr, r->frombuf, sizeof(r->frombuf));
    }

    heim_audit_addkv((heim_svc_req_desc)r, 0, "method", "GET");
    heim_audit_addkv((heim_svc_req_desc)r, 0, "endpoint", "%s", r->reqtype);
    token = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                        MHD_HTTP_HEADER_AUTHORIZATION);
    if (token && r->kv) {
        const char *token_end;

        if ((token_end = strchr(token, ' ')) == NULL ||
            (token_end - token) > INT_MAX || (token_end - token) < 2)
            heim_audit_addkv((heim_svc_req_desc)r, 0, "auth", "<unknown>");
        else
            heim_audit_addkv((heim_svc_req_desc)r, 0, "auth", "%.*s",
                             (int)(token_end - token), token);

    }

    return ret;
}

static void
clean_req_desc(struct bx509_request_desc *r)
{
    if (!r)
        return;
    if (r->pkix_store) {
        const char *fn = strchr(r->pkix_store, ':');

        /*
         * This `fn' thing is just to quiet linters that think "hey, strchr() can
         * return NULL so...", but here we've build `r->pkix_store' and know it has
         * a ':'.
         */
        fn = fn ? fn + 1 : r->pkix_store;
        (void) unlink(fn);
    }
    krb5_free_addresses(r->context, &r->tgt_addresses);
    hx509_request_free(&r->req);
    heim_release(r->reason);
    heim_release(r->kv);
    if (r->ccname && r->cckind == K5_CREDS_EPHEMERAL) {
        const char *fn = r->ccname;

        if (strncmp(fn, "FILE:", sizeof("FILE:") - 1) == 0)
            fn += sizeof("FILE:") - 1;
        (void) unlink(fn);
    }
    free(r->pkix_store);
    free(r->freeme1);
    free(r->ccname);
    free(r->cname);
    free(r->sname);
}

/* Implements GETs of /bx509 */
static krb5_error_code
bx509(struct bx509_request_desc *r)
{
    krb5_error_code ret;
    const char *csr;

    /* Get required inputs */
    csr = MHD_lookup_connection_value(r->connection, MHD_GET_ARGUMENT_KIND,
                                      "csr");
    if (csr == NULL)
        return bad_400(r, EINVAL, "CSR is missing");

    if ((ret = validate_token(r)))
        return ret; /* validate_token() calls bad_req() */

    if (r->cname == NULL)
        return bad_403(r, EINVAL,
                       "Could not extract principal name from token");

    /* Parse CSR, add extensions from parameters, authorize, issue cert */
    if ((ret = do_CA(r, csr)))
        return ret;

    /* Read and send the contents of the PKIX store */
    krb5_log_msg(r->context, logfac, 1, NULL, "Issued certificate to %s",
                 r->cname);
    return good_bx509(r);
}

/*
 * princ_fs_encode_sz() and princ_fs_encode() encode a principal name to be
 * safe for use as a file name.  They function very much like URL encoders, but
 * '~' and '.' also get encoded, and '@' does not.
 *
 * A corresponding decoder is not needed.
 *
 * XXX Maybe use krb5_cc_default_for()!
 */
static size_t
princ_fs_encode_sz(const char *in)
{
    size_t sz = strlen(in);

    while (*in) {
        unsigned char c = *(const unsigned char *)(in++);

        if (isalnum(c))
            continue;
        switch (c) {
        case '@':
        case '-':
        case '_':
            continue;
        default:
            sz += 2;
        }
    }
    return sz;
}

static char *
princ_fs_encode(const char *in)
{
    size_t len = strlen(in);
    size_t sz = princ_fs_encode_sz(in);
    size_t i, k;
    char *s;

    if ((s = malloc(sz + 1)) == NULL)
        return NULL;
    s[sz] = '\0';

    for (i = k = 0; i < len; i++) {
        char c = in[i];

        switch (c) {
        case '@':
        case '-':
        case '_':
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


/*
 * Find an existing, live ccache for `princ' in `cache_dir' or acquire Kerberos
 * creds for `princ' with PKINIT and put them in a ccache in `cache_dir'.
 */
static krb5_error_code
find_ccache(krb5_context context, const char *princ, char **ccname)
{
    krb5_error_code ret = ENOMEM;
    krb5_ccache cc = NULL;
    time_t life;
    char *s = NULL;

    *ccname = NULL;

    /*
     * Name the ccache after the principal.  The principal may have special
     * characters in it, such as / or \ (path component separarot), or shell
     * special characters, so princ_fs_encode() it to make a ccache name.
     */
    if ((s = princ_fs_encode(princ)) == NULL ||
        asprintf(ccname, "FILE:%s/%s.cc", cache_dir, s) == -1 ||
        *ccname == NULL) {
        free(s);
        return ENOMEM;
    }
    free(s);

    if ((ret = krb5_cc_resolve(context, *ccname, &cc))) {
        /* krb5_cc_resolve() suceeds even if the file doesn't exist */
        free(*ccname);
        *ccname = NULL;
        cc = NULL;
    }

    /* Check if we have a good enough credential */
    if (ret == 0 &&
        (ret = krb5_cc_get_lifetime(context, cc, &life)) == 0 && life > 60) {
        krb5_cc_close(context, cc);
        return 0;
    }
    if (cc)
        krb5_cc_close(context, cc);
    return ret ? ret : ENOENT;
}

static krb5_error_code
get_ccache(struct bx509_request_desc *r, krb5_ccache *cc, int *won)
{
    krb5_error_code ret = 0;
    char *temp_ccname = NULL;
    const char *fn = NULL;
    time_t life;
    int fd = -1;

    /*
     * Open and lock a .new ccache file.  Use .new to avoid garbage files on
     * crash.
     *
     * We can race with other threads to do this, so we loop until we
     * definitively win or definitely lose the race.  We win when we have a) an
     * open FD that is b) flock'ed, and c) we observe with lstat() that the
     * file we opened and locked is the same as on disk after locking.
     *
     * We don't close the FD until we're done.
     *
     * If we had a proper anon MEMORY ccache, we could instead use that for a
     * temporary ccache, and then the initialization of and move to the final
     * FILE ccache would take care to mkstemp() and rename() into place.
     * fcc_open() basically does a similar thing.
     */
    *cc = NULL;
    *won = -1;
    if (asprintf(&temp_ccname, "%s.ccnew", r->ccname) == -1 ||
        temp_ccname == NULL)
        ret = ENOMEM;
    if (ret == 0)
        fn = temp_ccname + sizeof("FILE:") - 1;
    if (ret == 0) do {
        struct stat st1, st2;
        /*
         * Open and flock the temp ccache file.
         *
         * XXX We should really a) use _krb5_xlock(), or move that into
         * lib/roken anyways, b) abstract this loop into a utility function in
         * lib/roken.
         */
        if (fd != -1) {
            (void) close(fd);
            fd = -1;
        }
        errno = 0;
        memset(&st1, 0, sizeof(st1));
        memset(&st2, 0xff, sizeof(st2));
        if (ret == 0 &&
            ((fd = open(fn, O_RDWR | O_CREAT, 0600)) == -1 ||
             flock(fd, LOCK_EX) == -1 ||
             (lstat(fn, &st1) == -1 && errno != ENOENT) ||
             fstat(fd, &st2) == -1))
            ret = errno;
        if (ret == 0 && errno == 0 &&
            st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
            if (S_ISREG(st1.st_mode))
                break;
            if (unlink(fn) == -1)
                ret = errno;
        }
    } while (ret == 0);

    /* Check if we lost any race to acquire Kerberos creds */
    if (ret == 0)
        ret = krb5_cc_resolve(r->context, temp_ccname, cc);
    if (ret == 0) {
        ret = krb5_cc_get_lifetime(r->context, *cc, &life);
        if (ret == 0 && life > 60)
            *won = 0; /* We lost the race, but we win: we get to do less work */
        *won = 1;
        ret = 0;
    }
    free(temp_ccname);
    if (fd != -1)
        (void) close(fd); /* Drops the flock */
    return ret;
}

/*
 * Acquire credentials for `princ' using PKINIT and the PKIX credentials in
 * `pkix_store', then place the result in the ccache named `ccname' (which will
 * be in our own private `cache_dir').
 *
 * XXX This function could be rewritten using gss_acquire_cred_from() and
 * gss_store_cred_into() provided we add new generic cred store key/value pairs
 * for PKINIT.
 */
static krb5_error_code
do_pkinit(struct bx509_request_desc *r, enum k5_creds_kind kind)
{
    krb5_get_init_creds_opt *opt = NULL;
    krb5_init_creds_context ctx = NULL;
    krb5_error_code ret = 0;
    krb5_ccache temp_cc = NULL;
    krb5_ccache cc = NULL;
    krb5_principal p = NULL;
    const char *crealm;
    const char *cname = r->for_cname ? r->for_cname : r->cname;

    if (kind == K5_CREDS_CACHED) {
        int won = -1;

        ret = get_ccache(r, &temp_cc, &won);
        if (ret || !won)
            goto out;
        /*
         * We won the race to do PKINIT.  Setup to acquire Kerberos creds with
         * PKINIT.
         *
         * We should really make sure that gss_acquire_cred_from() can do this
         * for us.  We'd add generic cred store key/value pairs for PKIX cred
         * store, trust anchors, and so on, and acquire that way, then
         * gss_store_cred_into() to save it in a FILE ccache.
         */
    } else {
        ret = krb5_cc_new_unique(r->context, "FILE", NULL, &temp_cc);
    }

    if (ret == 0)
        ret = krb5_parse_name(r->context, cname, &p);
    if (ret == 0)
        crealm = krb5_principal_get_realm(r->context, p);
    if (ret == 0)
        ret = krb5_get_init_creds_opt_alloc(r->context, &opt);
    if (ret == 0)
        krb5_get_init_creds_opt_set_default_flags(r->context, "kinit", crealm,
                                                  opt);
    if (ret == 0 && kind == K5_CREDS_EPHEMERAL &&
        !krb5_config_get_bool_default(r->context, NULL, TRUE,
                                      "get-tgt", "no_addresses", NULL)) {
        krb5_addresses addr;

        ret = _krb5_parse_address_no_lookup(r->context, r->frombuf, &addr);
        if (ret == 0)
            ret = krb5_append_addresses(r->context, &r->tgt_addresses,
                                        &addr);
    }
    if (ret == 0 && r->tgt_addresses.len == 0)
        ret = krb5_get_init_creds_opt_set_addressless(r->context, opt, 1);
    else
        krb5_get_init_creds_opt_set_address_list(opt, &r->tgt_addresses);
    if (ret == 0)
        ret = krb5_get_init_creds_opt_set_pkinit(r->context, opt, p,
                                                 r->pkix_store,
                                                 NULL,  /* pkinit_anchor */
                                                 NULL,  /* anchor_chain */
                                                 NULL,  /* pkinit_crl */
                                                 0,     /* flags */
                                                 NULL,  /* prompter */
                                                 NULL,  /* prompter data */
                                                 NULL   /* password */);
    if (ret == 0)
        ret = krb5_init_creds_init(r->context, p,
                                   NULL /* prompter */,
                                   NULL /* prompter data */,
                                   0 /* start_time */,
                                   opt, &ctx);

    /*
     * Finally, do the AS exchange w/ PKINIT, extract the new Kerberos creds
     * into temp_cc, and rename into place.  Note that krb5_cc_move() closes
     * the source ccache, so we set temp_cc = NULL if it succeeds.
     */
    if (ret == 0)
        ret = krb5_init_creds_get(r->context, ctx);
    if (ret == 0)
        ret = krb5_init_creds_store(r->context, ctx, temp_cc);
    if (kind == K5_CREDS_CACHED) {
        if (ret == 0)
            ret = krb5_cc_resolve(r->context, r->ccname, &cc);
        if (ret == 0)
            ret = krb5_cc_move(r->context, temp_cc, cc);
        if (ret == 0)
            temp_cc = NULL;
    } else if (ret == 0 && kind == K5_CREDS_EPHEMERAL) {
        ret = krb5_cc_get_full_name(r->context, temp_cc, &r->ccname);
    }

out:
    if (ctx)
        krb5_init_creds_free(r->context, ctx);
    krb5_get_init_creds_opt_free(r->context, opt);
    krb5_free_principal(r->context, p);
    krb5_cc_close(r->context, temp_cc);
    krb5_cc_close(r->context, cc);
    return ret;
}

static krb5_error_code
load_priv_key(krb5_context context, const char *fn, hx509_private_key *key)
{
    hx509_private_key *keys = NULL;
    krb5_error_code ret;
    hx509_certs certs = NULL;

    *key = NULL;
    ret = hx509_certs_init(context->hx509ctx, fn, 0, NULL, &certs);
    if (ret == ENOENT)
        return 0;
    if (ret == 0)
        ret = _hx509_certs_keys_get(context->hx509ctx, certs, &keys);
    if (ret == 0 && keys[0] == NULL)
        ret = ENOENT; /* XXX Better error please */
    if (ret == 0)
        *key = _hx509_private_key_ref(keys[0]);
    if (ret)
        krb5_set_error_message(context, ret, "Could not load private "
                               "impersonation key from %s for PKINIT: %s", fn,
                               hx509_get_error_string(context->hx509ctx, ret));
    _hx509_certs_keys_free(context->hx509ctx, keys);
    hx509_certs_free(&certs);
    return ret;
}

static krb5_error_code
k5_do_CA(struct bx509_request_desc *r)
{
    SubjectPublicKeyInfo spki;
    hx509_private_key key = NULL;
    krb5_error_code ret = 0;
    krb5_principal p = NULL;
    hx509_request req = NULL;
    hx509_certs certs = NULL;
    KeyUsage ku = int2KeyUsage(0);
    const char *cname = r->for_cname ? r->for_cname : r->cname;

    memset(&spki, 0, sizeof(spki));
    ku.digitalSignature = 1;

    /* Make a CSR (halfway -- we don't need to sign it here) */
    /* XXX Load impersonation key just once?? */
    ret = load_priv_key(r->context, impersonation_key_fn, &key);
    if (ret == 0)
    ret = hx509_request_init(r->context->hx509ctx, &req);
    if (ret == 0)
        ret = krb5_parse_name(r->context, cname, &p);
    if (ret == 0)
        ret = hx509_private_key2SPKI(r->context->hx509ctx, key, &spki);
    if (ret == 0)
        hx509_request_set_SubjectPublicKeyInfo(r->context->hx509ctx, req,
                                               &spki);
    free_SubjectPublicKeyInfo(&spki);
    if (ret == 0)
        ret = hx509_request_add_pkinit(r->context->hx509ctx, req, cname);
    if (ret == 0)
        ret = hx509_request_add_eku(r->context->hx509ctx, req,
                                    &asn1_oid_id_pkekuoid);

    /* Mark it authorized */
    if (ret == 0)
        ret = hx509_request_authorize_san(req, 0);
    if (ret == 0)
        ret = hx509_request_authorize_eku(req, 0);
    if (ret == 0)
        hx509_request_authorize_ku(req, ku);

    /* Issue the certificate */
    if (ret == 0)
        ret = kdc_issue_certificate(r->context, "get-tgt", logfac, req, p,
                                    &r->token_times, r->req_life,
                                    1 /* send_chain */, &certs);
    krb5_free_principal(r->context, p);
    hx509_request_free(&req);
    p = NULL;

    if (ret == KRB5KDC_ERR_POLICY || ret == EACCES) {
        hx509_private_key_free(&key);
        return bad_403(r, ret,
                       "Certificate request denied for policy reasons");
    }
    if (ret == ENOMEM) {
        hx509_private_key_free(&key);
        return bad_503(r, ret, "Certificate issuance failed");
    }
    if (ret) {
        hx509_private_key_free(&key);
        return bad_500(r, ret, "Certificate issuance failed");
    }

    /* Setup PKIX store and extract the certificate chain into it */
    ret = mk_pkix_store(&r->pkix_store);
    if (ret == 0)
        ret = store_certs(r->context->hx509ctx, r->pkix_store, certs, key);
    hx509_private_key_free(&key);
    hx509_certs_free(&certs);
    if (ret)
        return bad_500(r, ret,
                       "Could not create PEM store for issued certificate");
    return 0;
}

/* Get impersonated Kerberos credentials for `cprinc' */
static krb5_error_code
k5_get_creds(struct bx509_request_desc *r, enum k5_creds_kind kind)
{
    krb5_error_code ret;
    const char *cname = r->for_cname ? r->for_cname : r->cname;

    /* If we have a live ccache for `cprinc', we're done */
    r->cckind = kind;
    if (kind == K5_CREDS_CACHED &&
        (ret = find_ccache(r->context, cname, &r->ccname)) == 0)
        return ret; /* Success */

    /*
     * Else we have to acquire a credential for them using their bearer token
     * for authentication (and our keytab / initiator credentials perhaps).
     */
    if ((ret = k5_do_CA(r)))
        return ret; /* k5_do_CA() calls bad_req() */

    if (ret == 0 && (ret = do_pkinit(r, kind)))
        ret = bad_403(r, ret,
                      "Could not acquire Kerberos credentials using PKINIT");
    return ret;
}

/* Accumulate strings */
static void
acc_str(char **acc, char *adds, size_t addslen)
{
    char *tmp;
    int l = addslen <= INT_MAX ? (int)addslen : INT_MAX;

    if (asprintf(&tmp, "%s%s%.*s",
                 *acc ? *acc : "",
                 *acc ? "; " : "", l, adds) > -1 &&
        tmp) {
        free(*acc);
        *acc = tmp;
    }
}

static char *
fmt_gss_error(OM_uint32 code, gss_OID mech)
{
    gss_buffer_desc buf;
    OM_uint32 major, minor;
    OM_uint32 type = mech == GSS_C_NO_OID ? GSS_C_GSS_CODE: GSS_C_MECH_CODE;
    OM_uint32 more = 0;
    char *r = NULL;

    do {
        major = gss_display_status(&minor, code, type, mech, &more, &buf);
        if (!GSS_ERROR(major))
            acc_str(&r, (char *)buf.value, buf.length);
        gss_release_buffer(&minor, &buf);
    } while (!GSS_ERROR(major) && more);
    return r ? r : "Out of memory while formatting GSS-API error";
}

static char *
fmt_gss_errors(const char *r, OM_uint32 major, OM_uint32 minor, gss_OID mech)
{
    char *ma, *mi, *s;

    ma = fmt_gss_error(major, GSS_C_NO_OID);
    mi = mech == GSS_C_NO_OID ? NULL : fmt_gss_error(minor, mech);
    if (asprintf(&s, "%s: %s%s%s", r, ma, mi ? ": " : "", mi ? mi : "") > -1 &&
        s) {
        free(ma);
        free(mi);
        return s;
    }
    free(mi);
    return ma;
}

/* GSS-API error */
static krb5_error_code
bad_req_gss(struct bx509_request_desc *r,
            OM_uint32 major,
            OM_uint32 minor,
            gss_OID mech,
            int http_status_code,
            const char *reason)
{
    krb5_error_code ret;
    char *msg = fmt_gss_errors(reason, major, minor, mech);

    if (major == GSS_S_BAD_NAME || major == GSS_S_BAD_NAMETYPE)
        http_status_code = MHD_HTTP_BAD_REQUEST;

    ret = resp(r, http_status_code, MHD_RESPMEM_MUST_COPY, NULL,
               msg, strlen(msg), NULL);
    free(msg);
    return ret;
}

/* Make an HTTP/Negotiate token */
static krb5_error_code
mk_nego_tok(struct bx509_request_desc *r,
            char **nego_tok,
            size_t *nego_toksz)
{
    gss_key_value_element_desc kv[1] = { { "ccache", r->ccname } };
    gss_key_value_set_desc store = { 1, kv };
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t iname = GSS_C_NO_NAME;
    gss_name_t aname = GSS_C_NO_NAME;
    OM_uint32 major, minor, junk;
    krb5_error_code ret; /* More like a system error code here */
    const char *cname = r->for_cname ? r->for_cname : r->cname;
    char *token_b64 = NULL;

    *nego_tok = NULL;
    *nego_toksz = 0;

    /* Import initiator name */
    name.length = strlen(cname);
    name.value = rk_UNCONST(cname);
    major = gss_import_name(&minor, &name, GSS_KRB5_NT_PRINCIPAL_NAME, &iname);
    if (major != GSS_S_COMPLETE)
        return bad_req_gss(r, major, minor, GSS_C_NO_OID,
                           MHD_HTTP_SERVICE_UNAVAILABLE,
                           "Could not import cprinc parameter value as "
                           "Kerberos principal name");

    /* Import target acceptor name */
    name.length = strlen(r->target);
    name.value = rk_UNCONST(r->target);
    major = gss_import_name(&minor, &name, GSS_C_NT_HOSTBASED_SERVICE, &aname);
    if (major != GSS_S_COMPLETE) {
        (void) gss_release_name(&junk, &iname);
        return bad_req_gss(r, major, minor, GSS_C_NO_OID,
                           MHD_HTTP_SERVICE_UNAVAILABLE,
                           "Could not import target parameter value as "
                           "Kerberos principal name");
    }

    /* Acquire a credential from the given ccache */
    major = gss_add_cred_from(&minor, cred, iname, GSS_KRB5_MECHANISM,
                              GSS_C_INITIATE, GSS_C_INDEFINITE, 0, &store,
                              &cred, NULL, NULL, NULL);
    (void) gss_release_name(&junk, &iname);
    if (major != GSS_S_COMPLETE) {
        (void) gss_release_name(&junk, &aname);
        return bad_req_gss(r, major, minor, GSS_KRB5_MECHANISM,
                           MHD_HTTP_FORBIDDEN, "Could not acquire credentials "
                           "for requested cprinc");
    }

    major = gss_init_sec_context(&minor, cred, &ctx, aname,
                                 GSS_KRB5_MECHANISM, 0, GSS_C_INDEFINITE,
                                 NULL, GSS_C_NO_BUFFER, NULL, &token, NULL,
                                 NULL);
    (void) gss_delete_sec_context(&junk, &ctx, GSS_C_NO_BUFFER);
    (void) gss_release_name(&junk, &aname);
    (void) gss_release_cred(&junk, &cred);
    if (major != GSS_S_COMPLETE)
        return bad_req_gss(r, major, minor, GSS_KRB5_MECHANISM,
                           MHD_HTTP_SERVICE_UNAVAILABLE, "Could not acquire "
                           "Negotiate token for requested target");

    /* Encode token, output */
    ret = rk_base64_encode(token.value, token.length, &token_b64);
    (void) gss_release_buffer(&junk, &token);
    if (ret > 0)
        ret = asprintf(nego_tok, "Negotiate %s", token_b64);
    free(token_b64);
    if (ret < 0 || *nego_tok == NULL)
        return bad_req(r, errno, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not allocate memory for encoding Negotiate "
                       "token");
    *nego_toksz = ret;
    return 0;
}

static krb5_error_code
bnegotiate_get_target(struct bx509_request_desc *r)
{
    const char *target;
    const char *redir;
    const char *referer; /* misspelled on the wire, misspelled here, FYI */
    const char *authority;
    const char *local_part;
    char *s1 = NULL;
    char *s2 = NULL;

    target = MHD_lookup_connection_value(r->connection, MHD_GET_ARGUMENT_KIND,
                                         "target");
    redir = MHD_lookup_connection_value(r->connection, MHD_GET_ARGUMENT_KIND,
                                        "redirect");
    referer = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                          MHD_HTTP_HEADER_REFERER);
    if (target != NULL && redir == NULL) {
        r->target = target;
        return 0;
    }
    if (target == NULL && redir == NULL)
        return bad_400(r, EINVAL,
                       "Query missing 'target' or 'redirect' parameter value");
    if (target != NULL && redir != NULL)
        return bad_403(r, EACCES,
                       "Only one of 'target' or 'redirect' parameter allowed");
    if (redir != NULL && referer == NULL)
        return bad_403(r, EACCES,
                       "Redirect request without Referer header nor allowed");

    if (strncmp(referer, "https://", sizeof("https://") - 1) != 0 ||
        strncmp(redir, "https://", sizeof("https://") - 1) != 0)
        return bad_403(r, EACCES,
                       "Redirect requests permitted only for https referrers");

    /* Parse out authority from each URI, redirect and referrer */
    authority = redir + sizeof("https://") - 1;
    if ((local_part = strchr(authority, '/')) == NULL)
        local_part = authority + strlen(authority);
    if ((s1 = strndup(authority, local_part - authority)) == NULL)
        return bad_enomem(r, ENOMEM);

    authority = referer + sizeof("https://") - 1;
    if ((local_part = strchr(authority, '/')) == NULL)
        local_part = authority + strlen(authority);
    if ((s2 = strndup(authority, local_part - authority)) == NULL) {
        free(s1);
        return bad_enomem(r, ENOMEM);
    }

    /* Both must match */
    if (strcasecmp(s1, s2) != 0) {
        free(s2);
        free(s1);
        return bad_403(r, EACCES, "Redirect request does not match referer");
    }
    free(s2);

    if (strchr(s1, '@')) {
        free(s1);
        return bad_403(r, EACCES,
                       "Redirect request authority has login information");
    }

    /* Extract hostname portion of authority and format GSS name */
    if (strchr(s1, ':'))
        *strchr(s1, ':') = '\0';
    if (asprintf(&r->freeme1, "HTTP@%s", s1) == -1 || r->freeme1 == NULL) {
        free(s1);
        return bad_enomem(r, ENOMEM);
    }

    r->target = r->freeme1;
    r->redir = redir;
    free(s1);
    return 0;
}

/*
 * Implements /bnegotiate end-point.
 *
 * Query parameters (mutually exclusive):
 *
 *  - target=<name>
 *  - redirect=<URL-encoded-URL>
 *
 * If the redirect query parameter is set then the Referer: header must be as
 * well, and the authority of the redirect and Referer URIs must be the same.
 */
static krb5_error_code
bnegotiate(struct bx509_request_desc *r)
{
    krb5_error_code ret;
    size_t nego_toksz = 0;
    char *nego_tok = NULL;

    ret = bnegotiate_get_target(r);
    if (ret == 0) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS, "target", "%s",
                         r->target ? r->target : "<unknown>");
        heim_audit_setkv_bool((heim_svc_req_desc)r, "redir", !!r->redir);
        ret = validate_token(r);
    }
    /* bnegotiate_get_target() and validate_token() call bad_req() */
    if (ret)
        return ret;

    /*
     * Make sure we have Kerberos credentials for cprinc.  If we have them
     * cached from earlier, this will be fast (all local), else it will involve
     * taking a file lock and talking to the KDC using kx509 and PKINIT.
     *
     * Perhaps we could use S4U instead, which would speed up the slow path a
     * bit.
     */
    ret = k5_get_creds(r, K5_CREDS_CACHED);
    if (ret)
        return ret;

    /* Acquire the Negotiate token and output it */
    if (ret == 0 && r->ccname != NULL)
        ret = mk_nego_tok(r, &nego_tok, &nego_toksz);

    if (ret == 0) {
        /* Look ma', Negotiate as an OAuth-like token system! */
        if (r->redir)
            ret = resp(r, MHD_HTTP_TEMPORARY_REDIRECT, MHD_RESPMEM_PERSISTENT,
                       NULL, "", 0, nego_tok);
        else
            ret = resp(r, MHD_HTTP_OK, MHD_RESPMEM_MUST_COPY,
                       "application/x-negotiate-token", nego_tok, nego_toksz,
                       NULL);
    }

    free(nego_tok);
    return ret;
}

static krb5_error_code
authorize_TGT_REQ(struct bx509_request_desc *r)
{
    krb5_principal p = NULL;
    krb5_error_code ret;
    const char *for_cname = r->for_cname ? r->for_cname : r->cname;

    if (for_cname == r->cname || strcmp(r->cname, r->for_cname) == 0)
        return 0;

    ret = krb5_parse_name(r->context, r->cname, &p);
    if (ret == 0)
        ret = hx509_request_init(r->context->hx509ctx, &r->req);
    if (ret)
        return bad_500(r, ret, "Out of resources");
    heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                     "requested_krb5PrincipalName", "%s", for_cname);
    ret = hx509_request_add_eku(r->context->hx509ctx, r->req,
                                ASN1_OID_ID_PKEKUOID);
    if (ret == 0)
        ret = hx509_request_add_pkinit(r->context->hx509ctx, r->req,
                                       for_cname);
    if (ret == 0)
        ret = kdc_authorize_csr(r->context, "get-tgt", r->req, p);
    krb5_free_principal(r->context, p);
    hx509_request_free(&r->req);
    if (ret)
        return bad_403(r, ret, "Not authorized to requested TGT");
    return ret;
}

static heim_mhd_result
get_tgt_param_cb(void *d,
                 enum MHD_ValueKind kind,
                 const char *key,
                 const char *val)
{
    struct bx509_request_desc *r = d;

    if (strcmp(key, "address") == 0 && val) {
        if (!krb5_config_get_bool_default(r->context, NULL,
                                         FALSE,
                                         "get-tgt", "allow_addresses", NULL)) {
            krb5_set_error_message(r->context, r->error_code = ENOTSUP,
                                   "Query parameter %s not allowed", key);
        } else {
            krb5_addresses addresses;

            r->error_code = _krb5_parse_address_no_lookup(r->context, val,
                                                   &addresses);
            if (r->error_code == 0)
                r->error_code = krb5_append_addresses(r->context, &r->tgt_addresses,
                                               &addresses);
            krb5_free_addresses(r->context, &addresses);
        }
    } else if (strcmp(key, "cname") == 0) {
        /* Handled upstairs */
        ;
    } else if (strcmp(key, "lifetime") == 0 && val) {
        r->req_life = parse_time(val, "day");
    } else {
        /* Produce error for unknown params */
        heim_audit_setkv_bool((heim_svc_req_desc)r, "requested_unknown", TRUE);
        krb5_set_error_message(r->context, r->error_code = ENOTSUP,
                               "Query parameter %s not supported", key);
    }
    return r->error_code == 0 ? MHD_YES : MHD_NO /* Stop iterating */;
}

/*
 * Implements /get-tgt end-point.
 *
 * Query parameters (mutually exclusive):
 *
 *  - cname=<name> (client principal name, if not the same as the authenticated
 *                  name, then this will be impersonated if allowed)
 */
static krb5_error_code
get_tgt(struct bx509_request_desc *r)
{
    krb5_error_code ret;
    size_t bodylen;
    const char *fn;
    void *body;

    r->for_cname = MHD_lookup_connection_value(r->connection,
                                               MHD_GET_ARGUMENT_KIND, "cname");
    if (r->for_cname && r->for_cname[0] == '\0')
        r->for_cname = NULL;
    ret = validate_token(r);
    if (ret == 0)
        ret = authorize_TGT_REQ(r);
    /* validate_token() and authorize_TGT_REQ() call bad_req() */
    if (ret)
        return ret;

    r->error_code = 0;
    (void) MHD_get_connection_values(r->connection, MHD_GET_ARGUMENT_KIND,
                                     get_tgt_param_cb, r);
    ret = r->error_code;

    /* k5_get_creds() calls bad_req() */
    if (ret == 0)
        ret = k5_get_creds(r, K5_CREDS_EPHEMERAL);
    if (ret)
        return ret;

    fn = strchr(r->ccname, ':');
    if (fn == NULL)
        return bad_500(r, ret, "Impossible error");
    fn++;
    if ((errno = rk_undumpdata(fn, &body, &bodylen)))
        return bad_503(r, ret, "Could not get TGT");

    ret = resp(r, MHD_HTTP_OK, MHD_RESPMEM_MUST_COPY,
               "application/x-krb5-ccache", body, bodylen, NULL);
    free(body);
    return ret;
}

static krb5_error_code
health(const char *method, struct bx509_request_desc *r)
{
    if (strcmp(method, "HEAD") == 0)
        return resp(r, MHD_HTTP_OK, MHD_RESPMEM_PERSISTENT, NULL, "", 0, NULL);
    return resp(r, MHD_HTTP_OK, MHD_RESPMEM_PERSISTENT, NULL,
                "To determine the health of the service, use the /bx509 "
                "end-point.\n",
                sizeof("To determine the health of the service, use the "
                       "/bx509 end-point.\n") - 1, NULL);

}

/* Implements the entirety of this REST service */
static heim_mhd_result
route(void *cls,
      struct MHD_Connection *connection,
      const char *url,
      const char *method,
      const char *version,
      const char *upload_data,
      size_t *upload_data_size,
      void **ctx)
{
    static int aptr = 0;
    struct bx509_request_desc r;
    int ret;

    if (*ctx == NULL) {
        /*
         * This is the first call, right after headers were read.
         *
         * We must return quickly so that any 100-Continue might be sent with
         * celerity.
         *
         * We'll get called again to really do the processing.  If we handled
         * POSTs then we'd also get called with upload_data != NULL between the
         * first and last calls.  We need to keep no state between the first
         * and last calls, but we do need to distinguish first and last call,
         * so we use the ctx argument for this.
         */
        *ctx = &aptr;
        return MHD_YES;
    }

    if ((ret = set_req_desc(connection, url, &r)))
        return bad_503(&r, ret, "Could not initialize request state");
    if ((strcmp(method, "HEAD") == 0 || strcmp(method, "GET") == 0) &&
        (strcmp(url, "/health") == 0 || strcmp(url, "/") == 0))
        ret = health(method, &r);
    else if (strcmp(method, "GET") != 0)
        ret = bad_405(&r, method);
    else if (strcmp(url, "/get-cert") == 0 ||
             strcmp(url, "/bx509") == 0) /* old name */
        ret = bx509(&r);
    else if (strcmp(url, "/get-negotiate-token") == 0 ||
             strcmp(url, "/bnegotiate") == 0) /* old name */
        ret = bnegotiate(&r);
    else if (strcmp(url, "/get-tgt") == 0)
        ret = get_tgt(&r);
    else
        ret = bad_404(&r, url);

    clean_req_desc(&r);
    return ret == -1 ? MHD_NO : MHD_YES;
}

static struct getargs args[] = {
    { "help", 'h', arg_flag, &help_flag, "Print usage message", NULL },
    { "version", '\0', arg_flag, &version_flag, "Print version", NULL },
    { NULL, 'H', arg_strings, &audiences,
        "expected token audience(s) of bx509 service", "HOSTNAME" },
    { "daemon", 'd', arg_flag, &daemonize, "daemonize", "daemonize" },
    { "daemon-child", 0, arg_flag, &daemon_child_fd, NULL, NULL }, /* priv */
    { "reverse-proxied", 0, arg_flag, &reverse_proxied_flag,
        "reverse proxied", "listen on 127.0.0.1 and do not use TLS" },
    { NULL, 'p', arg_integer, &port, "PORT", "port number (default: 443)" },
    { "cache-dir", 0, arg_string, &cache_dir,
        "cache directory", "DIRECTORY" },
    { "cert", 0, arg_string, &cert_file,
        "certificate file path (PEM)", "HX509-STORE" },
    { "private-key", 0, arg_string, &priv_key_file,
        "private key file path (PEM)", "HX509-STORE" },
    { "thread-per-client", 't', arg_flag, &thread_per_client_flag,
        "thread per-client", "use thread per-client" },
    { "verbose", 'v', arg_counter, &verbose_counter, "verbose", "run verbosely" }
};

static int
usage(int e)
{
    arg_printusage(args, sizeof(args) / sizeof(args[0]), "bx509",
        "\nServes RESTful GETs of /bx509 and /bnegotiate,\n"
        "performing corresponding kx509 and, possibly, PKINIT requests\n"
        "to the KDCs of the requested realms (or just the given REALM).\n");
    exit(e);
}

static int sigpipe[2] = { -1, -1 };

static void
sighandler(int sig)
{
    char c = sig;
    while (write(sigpipe[1], &c, sizeof(c)) == -1 && errno == EINTR)
        ;
}

static void
bx509_openlog(krb5_context context,
              const char *svc,
              krb5_log_facility **fac)
{
    char **s = NULL, **p;

    krb5_initlog(context, "bx509d", fac);
    s = krb5_config_get_strings(context, NULL, svc, "logging", NULL);
    if (s == NULL)
        s = krb5_config_get_strings(context, NULL, "logging", svc, NULL);
    if (s) {
        for(p = s; *p; p++)
            krb5_addlog_dest(context, *fac, *p);
        krb5_config_free_strings(s);
    } else {
        char *ss;
        if (asprintf(&ss, "0-1/FILE:%s/%s", hdb_db_dir(context),
            KDC_LOG_FILE) < 0)
            err(1, "out of memory");
        krb5_addlog_dest(context, *fac, ss);
        free(ss);
    }
    krb5_set_warn_dest(context, *fac);
}

static const char *sysplugin_dirs[] =  {
#ifdef _WIN32
    "$ORIGIN",
#else
    "$ORIGIN/../lib/plugin/kdc",
#endif
#ifdef __APPLE__
    LIBDIR "/plugin/kdc",
#endif
    NULL
};

static void
load_plugins(krb5_context context)
{
    const char * const *dirs = sysplugin_dirs;
#ifndef _WIN32
    char **cfdirs;

    cfdirs = krb5_config_get_strings(context, NULL, "kdc", "plugin_dir", NULL);
    if (cfdirs)
        dirs = (const char * const *)cfdirs;
#endif

    /* XXX kdc? */
    _krb5_load_plugins(context, "kdc", (const char **)dirs);

#ifndef _WIN32
    krb5_config_free_strings(cfdirs);
#endif
}

int
main(int argc, char **argv)
{
    unsigned int flags = MHD_USE_THREAD_PER_CONNECTION; /* XXX */
    struct sockaddr_in sin;
    struct MHD_Daemon *previous = NULL;
    struct MHD_Daemon *current = NULL;
    struct sigaction sa;
    krb5_context context = NULL;
    MHD_socket sock = MHD_INVALID_SOCKET;
    char *priv_key_pem = NULL;
    char *cert_pem = NULL;
    char sig;
    int optidx = 0;
    int ret;

    setprogname("bx509d");
    if (getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
        usage(1);
    if (help_flag)
        usage(0);
    if (version_flag) {
        print_version(NULL);
        exit(0);
    }
    if (argc > optidx) /* Add option to set a URI local part prefix? */
        usage(1);
    if (port < 0)
        errx(1, "Port number must be given");

    if (audiences.num_strings == 0) {
        char localhost[MAXHOSTNAMELEN];

        ret = gethostname(localhost, sizeof(localhost));
        if (ret == -1)
            errx(1, "Could not determine local hostname; use --audience");

        if ((audiences.strings =
                 calloc(1, sizeof(audiences.strings[0]))) == NULL ||
            (audiences.strings[0] = strdup(localhost)) == NULL)
            err(1, "Out of memory");
        audiences.num_strings = 1;
    }

    if (daemonize && daemon_child_fd == -1)
        daemon_child_fd = roken_detach_prep(argc, argv, "--daemon-child");
    daemonize = 0;

    argc -= optidx;
    argv += optidx;
    if (argc != 0)
        usage(1);

    if ((errno = pthread_key_create(&k5ctx, k5_free_context)))
        err(1, "Could not create thread-specific storage");

    if ((errno = get_krb5_context(&context)))
        err(1, "Could not init krb5 context");

    bx509_openlog(context, "bx509d", &logfac);
    load_plugins(context);

    if (cache_dir == NULL) {
        char *s = NULL;

        if (asprintf(&s, "%s/bx509d-XXXXXX",
                     getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp") == -1 ||
            s == NULL ||
            (cache_dir = mkdtemp(s)) == NULL)
            err(1, "could not create temporary cache directory");
        if (verbose_counter)
            fprintf(stderr, "Note: using %s as cache directory\n", cache_dir);
        atexit(rm_cache_dir);
        setenv("TMPDIR", cache_dir, 1);
    }

    generate_key(context->hx509ctx, "impersonation", "rsa", 2048, &impersonation_key_fn);

again:
    if (cert_file && !priv_key_file)
        priv_key_file = cert_file;

    if (cert_file) {
        hx509_cursor cursor = NULL;
        hx509_certs certs = NULL;
        hx509_cert cert = NULL;
        time_t min_cert_life = 0;
        size_t len;
        void *s;

        ret = hx509_certs_init(context->hx509ctx, cert_file, 0, NULL, &certs);
        if (ret == 0)
            ret = hx509_certs_start_seq(context->hx509ctx, certs, &cursor);
        while (ret == 0 &&
               (ret = hx509_certs_next_cert(context->hx509ctx, certs,
                                            cursor, &cert)) == 0 && cert) {
            time_t notAfter = 0;

            if (!hx509_cert_have_private_key_only(cert) &&
                (notAfter = hx509_cert_get_notAfter(cert)) <= time(NULL) + 30)
                errx(1, "One or more certificates in %s are expired",
                     cert_file);
            if (notAfter) {
                notAfter -= time(NULL);
                if (notAfter < 600)
                    warnx("One or more certificates in %s expire soon",
                          cert_file);
                /* Reload 5 minutes prior to expiration */
                if (notAfter < min_cert_life || min_cert_life < 1)
                    min_cert_life = notAfter;
            }
            hx509_cert_free(cert);
        }
        if (certs)
            (void) hx509_certs_end_seq(context->hx509ctx, certs, cursor);
        if (min_cert_life > 4)
            alarm(min_cert_life >> 1);
        hx509_certs_free(&certs);
        if (ret)
            hx509_err(context->hx509ctx, 1, ret,
                      "could not read certificate from %s", cert_file);

        if ((errno = rk_undumpdata(cert_file, &s, &len)) ||
            (cert_pem = strndup(s, len)) == NULL)
            err(1, "could not read certificate from %s", cert_file);
        if (strlen(cert_pem) != len)
            err(1, "NULs in certificate file contents: %s", cert_file);
        free(s);
    }

    if (priv_key_file) {
        size_t len;
        void *s;

        if ((errno = rk_undumpdata(priv_key_file, &s, &len)) ||
            (priv_key_pem = strndup(s, len)) == NULL)
            err(1, "could not read private key from %s", priv_key_file);
        if (strlen(priv_key_pem) != len)
            err(1, "NULs in private key file contents: %s", priv_key_file);
        free(s);
    }

    if (verbose_counter > 1)
        flags |= MHD_USE_DEBUG;
    if (thread_per_client_flag)
        flags |= MHD_USE_THREAD_PER_CONNECTION;


    if (pipe(sigpipe) == -1)
        err(1, "Could not set up key/cert reloading");
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    if (reverse_proxied_flag) {
        /*
         * We won't use TLS in the reverse proxy case, so no need to reload
         * certs.  But we'll still read them if given, and alarm() will get
         * called.
         */
        (void) signal(SIGHUP, SIG_IGN);
        (void) signal(SIGUSR1, SIG_IGN);
        (void) signal(SIGALRM, SIG_IGN);
    } else {
        (void) sigaction(SIGHUP, &sa, NULL);    /* Reload key & cert */
        (void) sigaction(SIGUSR1, &sa, NULL);   /* Reload key & cert */
        (void) sigaction(SIGALRM, &sa, NULL);   /* Reload key & cert */
    }
    (void) sigaction(SIGINT, &sa, NULL);    /* Graceful shutdown */
    (void) sigaction(SIGTERM, &sa, NULL);   /* Graceful shutdown */
    (void) signal(SIGPIPE, SIG_IGN);

    if (previous)
        sock = MHD_quiesce_daemon(previous);

    if (reverse_proxied_flag) {
        /*
         * XXX IPv6 too.  Create the sockets and tell MHD_start_daemon() about
         * them.
         */
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        current = MHD_start_daemon(flags, port,
                                   NULL, NULL,
                                   route, (char *)NULL,
                                   MHD_OPTION_SOCK_ADDR, &sin,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_END);
    } else if (sock != MHD_INVALID_SOCKET) {
        /*
         * Certificate/key rollover: reuse the listen socket returned by
         * MHD_quiesce_daemon().
         */
        current = MHD_start_daemon(flags | MHD_USE_SSL, port,
                                   NULL, NULL,
                                   route, (char *)NULL,
                                   MHD_OPTION_HTTPS_MEM_KEY, priv_key_pem,
                                   MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_LISTEN_SOCKET, sock,
                                   MHD_OPTION_END);
        sock = MHD_INVALID_SOCKET;
    } else {
        current = MHD_start_daemon(flags | MHD_USE_SSL, port,
                                   NULL, NULL,
                                   route, (char *)NULL,
                                   MHD_OPTION_HTTPS_MEM_KEY, priv_key_pem,
                                   MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   MHD_OPTION_END);
    }
    if (current == NULL)
        err(1, "Could not start bx509 REST service");

    if (previous) {
        MHD_stop_daemon(previous);
        previous = NULL;
    }

    if (verbose_counter)
        fprintf(stderr, "Ready!\n");
    if (daemon_child_fd != -1)
        roken_detach_finish(NULL, daemon_child_fd);

    /* Wait for signal, possibly SIGALRM, to reload certs and/or exit */
    while ((ret = read(sigpipe[0], &sig, sizeof(sig))) == -1 &&
           errno == EINTR)
        ;

    free(priv_key_pem);
    free(cert_pem);
    priv_key_pem = NULL;
    cert_pem = NULL;

    if (ret == 1 && (sig == SIGHUP || sig == SIGUSR1 || sig == SIGALRM)) {
        /* Reload certs and restart service gracefully */
        previous = current;
        current = NULL;
        goto again;
    }

    MHD_stop_daemon(current);
    _krb5_unload_plugins(context, "kdc");
    pthread_key_delete(k5ctx);
    return 0;
}
