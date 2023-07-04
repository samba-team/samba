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

/*
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
#include <kadm5/admin.h>
#include <kadm5/private.h>
#include <kadm5/kadm5_err.h>

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

#define BODYLEN_IS_STRLEN (~0)

/*
 * Libmicrohttpd is not the easiest API to use.  It's got issues.
 *
 * One of the issues is how responses are handled, and the return value of the
 * resource handler (MHD_NO -> close the connection, MHD_YES -> send response).
 * Note that the handler could return MHD_YES without having set an HTTP
 * response.
 *
 * There's memory management issues as well.
 *
 * Here we have to be careful about return values.
 *
 * Some of the functions defined here return just a krb5_error_code without
 * having set an HTTP response on error.
 * Others do set an HTTP response on error.
 * The convention is to either set an HTTP response on error, or not at all,
 * but not a mix of errors where for some the function will set a response and
 * for others it won't.
 *
 * We do use some system error codes to stand in for errors here.
 * Specifically:
 *
 *  - EACCES -> authorization failed
 *  - EINVAL -> bad API usage
 *  - ENOSYS -> missing CSRF token but CSRF token required
 *
 * FIXME: We should rely only on krb5_set_error_message() and friends and make
 *        error responses only in route(), mapping krb5_error_code values to
 *        HTTP status codes.  This would simplify the error handling convention
 *        here.
 */

struct free_tend_list {
    void *freeme1;
    void *freeme2;
    struct free_tend_list *next;
};

/* Our request description structure */
typedef struct kadmin_request_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;

    struct MHD_Connection *connection;
    krb5_times token_times;
    /*
     * FIXME
     *
     * Currently we re-use the authz framework from bx509d, using an
     * `hx509_request' instance (an abstraction for CSRs) to represent the
     * request because that is what the authz plugin uses that implements the
     * policy we want checked here.
     *
     * This is inappropriate in the long-term in two ways:
     *
     *  - the policy for certificates deals in SANs and EKUs, whereas the
     *    policy for ext_keytab deals in host-based service principal names,
     *    and there is not a one-to-one mapping of service names to EKUs;
     *
     *  - using a type from libhx509 for representing requests for things that
     *    aren't certificates is really not appropriate no matter how similar
     *    the use cases for this all might be.
     *
     * What we need to do is develop a library that can represent requests for
     * credentials via naming attributes like SANs and Kerberos principal
     * names, but more arbitrary still than what `hx509_request' supports, and
     * then invokes a plugin.
     *
     * Also, we might want to develop an in-tree authorization solution that is
     * richer than what kadmin.acl supports now, storing grants in HDB entries
     * and/or similar places.
     *
     * For expediency we use `hx509_request' here for now, impedance mismatches
     * be damned.
     */
    hx509_request req;          /* For authz only */
    struct free_tend_list *free_list;
    struct MHD_PostProcessor *pp;
    heim_array_t service_names;
    heim_array_t hostnames;
    heim_array_t spns;
    krb5_principal cprinc;
    krb5_keytab keytab;
    krb5_storage *sp;
    void *kadm_handle;
    char *realm;
    char *keytab_name;
    char *freeme1;
    char *enctypes;
    char *cache_control;
    char *csrf_token;
    const char *method;
    krb5_timestamp pw_end;
    size_t post_data_size;
    unsigned int response_set:1;
    unsigned int materialize:1;
    unsigned int rotate_now:1;
    unsigned int rotate:1;
    unsigned int revoke:1;
    unsigned int create:1;
    unsigned int ro:1;
    unsigned int is_self:1;
    char frombuf[128];
} *kadmin_request_desc;

static void
audit_trail(kadmin_request_desc r, krb5_error_code ret)
{
    const char *retname = NULL;

    /*
     * Get a symbolic name for some error codes.
     *
     * Really, libcom_err should have a primitive for this, and ours could, but
     * we can't use a system libcom_err if we extend ours.
     */
#define CASE(x) case x : retname = #x; break
    switch (ret) {
    case ENOSYS: retname = "ECSRFTOKENREQD"; break;
    CASE(EINVAL);
    CASE(ENOMEM);
    CASE(EACCES);
    CASE(HDB_ERR_NOT_FOUND_HERE);
    CASE(HDB_ERR_WRONG_REALM);
    CASE(HDB_ERR_EXISTS);
    CASE(HDB_ERR_KVNO_NOT_FOUND);
    CASE(HDB_ERR_NOENTRY);
    CASE(HDB_ERR_NO_MKEY);
    CASE(KRB5_KDC_UNREACH);
    CASE(KADM5_FAILURE);
    CASE(KADM5_AUTH_GET);
    CASE(KADM5_AUTH_ADD);
    CASE(KADM5_AUTH_MODIFY);
    CASE(KADM5_AUTH_DELETE);
    CASE(KADM5_AUTH_INSUFFICIENT);
    CASE(KADM5_BAD_DB);
    CASE(KADM5_DUP);
    CASE(KADM5_RPC_ERROR);
    CASE(KADM5_NO_SRV);
    CASE(KADM5_BAD_HIST_KEY);
    CASE(KADM5_NOT_INIT);
    CASE(KADM5_UNK_PRINC);
    CASE(KADM5_UNK_POLICY);
    CASE(KADM5_BAD_MASK);
    CASE(KADM5_BAD_CLASS);
    CASE(KADM5_BAD_LENGTH);
    CASE(KADM5_BAD_POLICY);
    CASE(KADM5_BAD_PRINCIPAL);
    CASE(KADM5_BAD_AUX_ATTR);
    CASE(KADM5_BAD_HISTORY);
    CASE(KADM5_BAD_MIN_PASS_LIFE);
    CASE(KADM5_PASS_Q_TOOSHORT);
    CASE(KADM5_PASS_Q_CLASS);
    CASE(KADM5_PASS_Q_DICT);
    CASE(KADM5_PASS_Q_GENERIC);
    CASE(KADM5_PASS_REUSE);
    CASE(KADM5_PASS_TOOSOON);
    CASE(KADM5_POLICY_REF);
    CASE(KADM5_INIT);
    CASE(KADM5_BAD_PASSWORD);
    CASE(KADM5_PROTECT_PRINCIPAL);
    CASE(KADM5_BAD_SERVER_HANDLE);
    CASE(KADM5_BAD_STRUCT_VERSION);
    CASE(KADM5_OLD_STRUCT_VERSION);
    CASE(KADM5_NEW_STRUCT_VERSION);
    CASE(KADM5_BAD_API_VERSION);
    CASE(KADM5_OLD_LIB_API_VERSION);
    CASE(KADM5_OLD_SERVER_API_VERSION);
    CASE(KADM5_NEW_LIB_API_VERSION);
    CASE(KADM5_NEW_SERVER_API_VERSION);
    CASE(KADM5_SECURE_PRINC_MISSING);
    CASE(KADM5_NO_RENAME_SALT);
    CASE(KADM5_BAD_CLIENT_PARAMS);
    CASE(KADM5_BAD_SERVER_PARAMS);
    CASE(KADM5_AUTH_LIST);
    CASE(KADM5_AUTH_CHANGEPW);
    CASE(KADM5_BAD_TL_TYPE);
    CASE(KADM5_MISSING_CONF_PARAMS);
    CASE(KADM5_BAD_SERVER_NAME);
    CASE(KADM5_KS_TUPLE_NOSUPP);
    CASE(KADM5_SETKEY3_ETYPE_MISMATCH);
    CASE(KADM5_DECRYPT_USAGE_NOSUPP);
    CASE(KADM5_POLICY_OP_NOSUPP);
    CASE(KADM5_KEEPOLD_NOSUPP);
    CASE(KADM5_AUTH_GET_KEYS);
    CASE(KADM5_ALREADY_LOCKED);
    CASE(KADM5_NOT_LOCKED);
    CASE(KADM5_LOG_CORRUPT);
    CASE(KADM5_LOG_NEEDS_UPGRADE);
    CASE(KADM5_BAD_SERVER_HOOK);
    CASE(KADM5_SERVER_HOOK_NOT_FOUND);
    CASE(KADM5_OLD_SERVER_HOOK_VERSION);
    CASE(KADM5_NEW_SERVER_HOOK_VERSION);
    CASE(KADM5_READ_ONLY);
    case 0:
        retname = "SUCCESS";
        break;
    default:
        retname = NULL;
        break;
    }
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

    ret = krb5_init_context(contextp);
    /* XXX krb5_set_log_dest(), warn_dest, debug_dest */
    if (ret == 0)
        (void) pthread_setspecific(k5ctx, *contextp);
    return ret;
}

typedef enum {
    CSRF_PROT_UNSPEC            = 0,
    CSRF_PROT_GET_WITH_HEADER   = 1,
    CSRF_PROT_GET_WITH_TOKEN    = 2,
    CSRF_PROT_POST_WITH_HEADER  = 8,
    CSRF_PROT_POST_WITH_TOKEN   = 16,
} csrf_protection_type;

static csrf_protection_type csrf_prot_type = CSRF_PROT_UNSPEC;
static int port = -1;
static int help_flag;
static int allow_GET_flag = -1;
static int daemonize;
static int daemon_child_fd = -1;
static int local_hdb;
static int local_hdb_read_only;
static int read_only;
static int verbose_counter;
static int version_flag;
static int reverse_proxied_flag;
static int thread_per_client_flag;
struct getarg_strings audiences;
static getarg_strings csrf_prot_type_strs;
static const char *csrf_header = "X-CSRF";
static const char *cert_file;
static const char *priv_key_file;
static const char *cache_dir;
static const char *realm;
static const char *hdb;
static const char *primary_server_URI;
static const char *kadmin_server;
static const char *writable_kadmin_server;
static const char *stash_file;
static const char *kadmin_client_name = "httpkadmind/admin";
static const char *kadmin_client_keytab;
static struct getarg_strings auth_types;

#define set_conf(c, f, v, b) \
    if (v) { \
        if (((c).f = strdup(v)) == NULL) \
            goto enomem; \
        conf.mask |= b; \
    }

/*
 * Does NOT set an HTTP response, naturally, as it doesn't even have access to
 * the connection.
 */
static krb5_error_code
get_kadm_handle(krb5_context context,
                const char *want_realm,
                int want_write,
                void **kadm_handle)
{
    kadm5_config_params conf;
    krb5_error_code ret;

    /*
     * If the caller wants to write and we are configured to redirect in that
     * case, then trigger a redirect by returning KADM5_READ_ONLY.
     */
    if (want_write && local_hdb_read_only && primary_server_URI)
        return KADM5_READ_ONLY;
    if (want_write && read_only)
        return KADM5_READ_ONLY;

    /*
     * Configure kadm5 connection.
     *
     * Note that all of these are optional, and will be found in krb5.conf or,
     * in some cases, in DNS, as needed.
     */
    memset(&conf, 0, sizeof(conf));
    conf.realm = NULL;
    conf.dbname = NULL;
    conf.stash_file = NULL;
    conf.admin_server = NULL;
    conf.readonly_admin_server = NULL;
    set_conf(conf, realm, want_realm, KADM5_CONFIG_REALM);
    set_conf(conf, dbname, hdb, KADM5_CONFIG_DBNAME);
    set_conf(conf, stash_file, stash_file, KADM5_CONFIG_STASH_FILE);

    /*
     * If we have a local HDB we'll use it if we can.  If the local HDB is
     * read-only and the caller wants to write, then we won't use the local
     * HDB, naturally.
     */
    if (local_hdb && (!local_hdb_read_only || !want_write)) {
        ret = kadm5_s_init_with_password_ctx(context,
                                             kadmin_client_name,
                                             NULL, /* password */
                                             NULL, /* service_name */
                                             &conf,
                                             0,    /* struct_version */
                                             0,    /* api_version */
                                             kadm_handle);
        goto out;
    }

    /*
     * Remote connection.  This will connect to a read-only kadmind if
     * possible, and if so, reconnect to a writable kadmind as needed.
     *
     * Note that kadmin_client_keytab can be an HDB: or HDBGET: keytab.
     */
    if (writable_kadmin_server)
        set_conf(conf, admin_server, writable_kadmin_server, KADM5_CONFIG_ADMIN_SERVER);
    if (kadmin_server)
        set_conf(conf, readonly_admin_server, kadmin_server,
                 KADM5_CONFIG_READONLY_ADMIN_SERVER);
    ret = kadm5_c_init_with_skey_ctx(context,
                                     kadmin_client_name,
                                     kadmin_client_keytab,
                                     KADM5_ADMIN_SERVICE,
                                     &conf,
                                     0, /* struct_version */
                                     0, /* api_version */
                                     kadm_handle);
    goto out;

enomem:
    ret = krb5_enomem(context);

out:
    free(conf.readonly_admin_server);
    free(conf.admin_server);
    free(conf.stash_file);
    free(conf.dbname);
    free(conf.realm);
    return ret;
}

static krb5_error_code resp(kadmin_request_desc, int, krb5_error_code,
                            enum MHD_ResponseMemoryMode, const char *,
                            const void *, size_t, const char *);
static krb5_error_code bad_req(kadmin_request_desc, krb5_error_code, int,
                               const char *, ...)
                               HEIMDAL_PRINTF_ATTRIBUTE((__printf__, 4, 5));

static krb5_error_code bad_enomem(kadmin_request_desc, krb5_error_code);
static krb5_error_code bad_400(kadmin_request_desc, krb5_error_code, const char *);
static krb5_error_code bad_401(kadmin_request_desc, const char *);
static krb5_error_code bad_403(kadmin_request_desc, krb5_error_code, const char *);
static krb5_error_code bad_404(kadmin_request_desc, krb5_error_code, const char *);
static krb5_error_code bad_405(kadmin_request_desc, const char *);
/*static krb5_error_code bad_500(kadmin_request_desc, krb5_error_code, const char *);*/
static krb5_error_code bad_503(kadmin_request_desc, krb5_error_code, const char *);

static int
validate_token(kadmin_request_desc r)
{
    krb5_error_code ret;
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
                             &r->cprinc, &r->token_times);
    if (ret)
        return bad_403(r, ret, "Token validation failed");
    if (r->cprinc == NULL)
        return bad_403(r, ret,
                       "Could not extract a principal name from token");
    ret = krb5_unparse_name(r->context, r->cprinc, &r->cname);
    if (ret)
        return bad_503(r, ret,
                       "Could not extract a principal name from token");
    return 0;
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

/*
 * Work around older libmicrohttpd not strduping response header values when
 * set.
 */
static HEIMDAL_THREAD_LOCAL struct redirect_uri {
    char uri[4096];
    size_t len;
    size_t first_param;
    int valid;
} redirect_uri;

static void
redirect_uri_appends(struct redirect_uri *redirect,
                     const char *s)
{
    size_t sz, len;
    char *p;

    if (!redirect->valid || redirect->len >= sizeof(redirect->uri) - 1) {
        redirect->valid = 0;
        return;
    }
    /* Optimize strlcpy by using redirect->uri + redirect->len */
    p = redirect->uri + redirect->len;
    sz = sizeof(redirect->uri) - redirect->len;
    if ((len = strlcpy(p, s, sz)) >= sz)
        redirect->valid = 0;
    else
        redirect->len += len;
}

static heim_mhd_result
make_redirect_uri_param_cb(void *d,
                           enum MHD_ValueKind kind,
                           const char *key,
                           const char *val)
{
    struct redirect_uri *redirect = d;

    redirect_uri_appends(redirect, redirect->first_param ? "?" : "&");
    redirect_uri_appends(redirect, key);
    if (val) {
        redirect_uri_appends(redirect, "=");
        redirect_uri_appends(redirect, val);
    }
    redirect->first_param = 0;
    return MHD_YES;
}

static const char *
make_redirect_uri(kadmin_request_desc r, const char *base)
{
    redirect_uri.len = 0;
    redirect_uri.uri[0] = '\0';
    redirect_uri.valid = 1;
    redirect_uri.first_param = 1;

    redirect_uri_appends(&redirect_uri, base); /* Redirect to primary URI base */
    redirect_uri_appends(&redirect_uri, r->reqtype); /* URI local-part */
    (void) MHD_get_connection_values(r->connection, MHD_GET_ARGUMENT_KIND,
                                     make_redirect_uri_param_cb,
                                     &redirect_uri);
    return redirect_uri.valid ? redirect_uri.uri : NULL;
}


/*
 * XXX Shouldn't be a body, but a status message.  The body should be
 * configurable to be from a file.  MHD doesn't give us a way to set the
 * response status message though, just the body.
 *
 * Calls audit_trail().
 *
 * Returns -1 if something terrible happened, which should ultimately cause
 * route() to return MHD_NO, which should cause libmicrohttpd to close the
 * connection to the user-agent.
 *
 * Returns 0 in all other cases.
 */
static krb5_error_code
resp(kadmin_request_desc r,
     int http_status_code,
     krb5_error_code ret,
     enum MHD_ResponseMemoryMode rmmode,
     const char *content_type,
     const void *body,
     size_t bodylen,
     const char *token)
{
    struct MHD_Response *response;
    int mret = MHD_YES;

    if (r->response_set) {
        krb5_log_msg(r->context, logfac, 1, NULL,
                     "Internal error; attempted to set a second response");
        return 0;
    }

    (void) gettimeofday(&r->tv_end, NULL);
    audit_trail(r, ret);

    if (body && bodylen == BODYLEN_IS_STRLEN)
        bodylen = strlen(body);

    response = MHD_create_response_from_buffer(bodylen, rk_UNCONST(body),
                                               rmmode);
    if (response == NULL)
        return -1;
    mret = MHD_add_response_header(response, MHD_HTTP_HEADER_AGE, "0");
    if (mret == MHD_YES && http_status_code == MHD_HTTP_OK) {
        krb5_timestamp now;

        free(r->cache_control);
        r->cache_control = NULL;
        krb5_timeofday(r->context, &now);
        if (r->pw_end && r->pw_end > now) {
            if (asprintf(&r->cache_control, "no-store, max-age=%lld",
                         (long long)r->pw_end - now) == -1 ||
                r->cache_control == NULL)
                /* Soft handling of ENOMEM here */
                mret = MHD_add_response_header(response,
                                               MHD_HTTP_HEADER_CACHE_CONTROL,
                                               "no-store, max-age=3600");
            else
                mret = MHD_add_response_header(response,
                                               MHD_HTTP_HEADER_CACHE_CONTROL,
                                               r->cache_control);

        } else
            mret = MHD_add_response_header(response,
                                           MHD_HTTP_HEADER_CACHE_CONTROL,
                                           "no-store, max-age=0");
    } else {
        /* Shouldn't happen */
        mret = MHD_add_response_header(response, MHD_HTTP_HEADER_CACHE_CONTROL,
                                       "no-store, max-age=0");
    }
    if (mret == MHD_YES && http_status_code == MHD_HTTP_UNAUTHORIZED) {
        size_t i;

        if (auth_types.num_strings < 1)
            http_status_code = MHD_HTTP_SERVICE_UNAVAILABLE;
        else
            for (i = 0; mret == MHD_YES && i < auth_types.num_strings; i++)
                mret = MHD_add_response_header(response,
                                               MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                                               auth_types.strings[i]);
    } else if (mret == MHD_YES && http_status_code == MHD_HTTP_TEMPORARY_REDIRECT) {
        const char *redir = make_redirect_uri(r, primary_server_URI);

        if (redir)
            mret = MHD_add_response_header(response, MHD_HTTP_HEADER_LOCATION,
                                           redir);
        else
            /* XXX Find a way to set a new response body; log */
            http_status_code = MHD_HTTP_SERVICE_UNAVAILABLE;
    }

    if (mret == MHD_YES && r->csrf_token)
        mret = MHD_add_response_header(response,
                                       "X-CSRF-Token",
                                       r->csrf_token);

    if (mret == MHD_YES && content_type) {
        mret = MHD_add_response_header(response,
                                       MHD_HTTP_HEADER_CONTENT_TYPE,
                                       content_type);
    }
    if (mret != MHD_NO)
        mret = MHD_queue_response(r->connection, http_status_code, response);
    MHD_destroy_response(response);
    r->response_set = 1;
    return mret == MHD_NO ? -1 : 0;
}

static krb5_error_code
bad_reqv(kadmin_request_desc r,
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

    context = r->context;
    if (r->hcontext && r->kv)
        heim_audit_setkv_number((heim_svc_req_desc)r, "http-status-code",
				http_status_code);
    (void) gettimeofday(&r->tv_end, NULL);
    if (code == ENOMEM) {
        if (context)
            krb5_log_msg(context, logfac, 1, NULL, "Out of memory");
        return resp(r, http_status_code, code, MHD_RESPMEM_PERSISTENT,
                    NULL, fmt, BODYLEN_IS_STRLEN, NULL);
    }

    if (code) {
        if (context)
            emsg = k5msg = krb5_get_error_message(context, code);
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
    if (r->hcontext)
        heim_audit_addreason((heim_svc_req_desc)r, "%s", formatted);
    krb5_free_error_message(context, k5msg);

    if (ret == -1 || msg == NULL) {
        if (context)
            krb5_log_msg(context, logfac, 1, NULL, "Out of memory");
        return resp(r, MHD_HTTP_SERVICE_UNAVAILABLE, ENOMEM,
                    MHD_RESPMEM_PERSISTENT, NULL,
                    "Out of memory", BODYLEN_IS_STRLEN, NULL);
    }

    ret = resp(r, http_status_code, code, MHD_RESPMEM_MUST_COPY,
               NULL, msg, BODYLEN_IS_STRLEN, NULL);
    free(formatted);
    free(msg);
    return ret == -1 ? -1 : code;
}

static krb5_error_code
bad_req(kadmin_request_desc r,
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
bad_enomem(kadmin_request_desc r, krb5_error_code ret)
{
    return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                   "Out of memory");
}

static krb5_error_code
bad_400(kadmin_request_desc r, int ret, const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_BAD_REQUEST, "%s", reason);
}

static krb5_error_code
bad_401(kadmin_request_desc r, const char *reason)
{
    return bad_req(r, EACCES, MHD_HTTP_UNAUTHORIZED, "%s", reason);
}

static krb5_error_code
bad_403(kadmin_request_desc r, krb5_error_code ret, const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_FORBIDDEN, "%s", reason);
}

static krb5_error_code
bad_404(kadmin_request_desc r, krb5_error_code ret, const char *name)
{
    return bad_req(r, ret, MHD_HTTP_NOT_FOUND,
                   "Resource not found: %s", name);
}

static krb5_error_code
bad_405(kadmin_request_desc r, const char *method)
{
    return bad_req(r, EPERM, MHD_HTTP_METHOD_NOT_ALLOWED,
                   "Method not supported: %s", method);
}

static krb5_error_code
bad_413(kadmin_request_desc r)
{
    return bad_req(r, E2BIG, MHD_HTTP_METHOD_NOT_ALLOWED,
                   "POST request body too large");
}

static krb5_error_code
bad_method_want_POST(kadmin_request_desc r)
{
    return bad_req(r, EPERM, MHD_HTTP_METHOD_NOT_ALLOWED,
                   "Use POST for making changes to principals");
}

#if 0
static krb5_error_code
bad_500(kadmin_request_desc r,
        krb5_error_code ret,
        const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_INTERNAL_SERVER_ERROR,
                   "Internal error: %s", reason);
}
#endif

static krb5_error_code
bad_503(kadmin_request_desc r,
        krb5_error_code ret,
        const char *reason)
{
    return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                   "Service unavailable: %s", reason);
}

static krb5_error_code
good_ext_keytab(kadmin_request_desc r)
{
    krb5_error_code ret;
    size_t bodylen;
    void *body;
    char *p;

    if (!r->keytab_name || !(p = strchr(r->keytab_name, ':')))
        return bad_503(r, EINVAL, "Internal error (no keytab produced)");
    p++;
    if (strncmp(p, cache_dir, strlen(cache_dir)) != 0)
        return bad_503(r, EINVAL, "Internal error");
    ret = rk_undumpdata(p, &body, &bodylen);
    if (ret)
        return bad_503(r, ret, "Could not recover keytab from temp file");

    ret = resp(r, MHD_HTTP_OK, 0, MHD_RESPMEM_MUST_COPY,
               "application/octet-stream", body, bodylen, NULL);
    free(body);
    return ret;
}

static krb5_error_code
check_service_name(kadmin_request_desc r, const char *name)
{
    if (name == NULL || name[0] == '\0' ||
        strchr(name, '/') || strchr(name, '\\') || strchr(name, '@') ||
        strcmp(name, "krbtgt") == 0 ||
        strcmp(name, "iprop") == 0 ||
        strcmp(name, "kadmin") == 0 ||
        strcmp(name, "hprop") == 0 ||
        strcmp(name, "WELLKNOWN") == 0 ||
        strcmp(name, "K") == 0) {
        krb5_set_error_message(r->context, EACCES,
                               "No one is allowed to fetch keys for "
                               "Heimdal service %s", name);
        return EACCES;
    }
    if (strcmp(name, "root") != 0 &&
        strcmp(name, "host") != 0 &&
        strcmp(name, "exceed") != 0)
        return 0;
    if (krb5_config_get_bool_default(r->context, NULL, FALSE,
                                     "ext_keytab",
                                     "csr_authorizer_handles_svc_names",
                                     NULL))
        return 0;
    krb5_set_error_message(r->context, EACCES,
                           "No one is allowed to fetch keys for "
                           "service \"%s\" because of authorizer "
                           "limitations", name);
    return EACCES;
}

static heim_mhd_result
param_cb(void *d,
         enum MHD_ValueKind kind,
         const char *key,
         const char *val)
{
    kadmin_request_desc r = d;
    krb5_error_code ret = 0;
    heim_string_t s = NULL;

    /*
     * Multi-valued params:
     *
     *  - spn=<service>/<hostname>
     *  - dNSName=<hostname>
     *  - service=<service>
     *
     * Single-valued params:
     *
     *  - realm=<REALM>
     *  - materialize=true  -- create a concrete princ where it's virtual
     *  - enctypes=...      -- key-salt types
     *  - revoke=true       -- delete old keys (concrete princs only)
     *  - rotate=true       -- change keys (no-op for virtual princs)
     *  - create=true       -- create a concrete princ
     *  - ro=true           -- perform no writes
     */

    if (strcmp(key, "realm") == 0 && val) {
        if (!r->realm && !(r->realm = strdup(val)))
            ret = krb5_enomem(r->context);
    } else if (strcmp(key, "materialize") == 0  ||
               strcmp(key, "revoke") == 0       ||
               strcmp(key, "rotate") == 0       ||
               strcmp(key, "create") == 0       ||
               strcmp(key, "ro") == 0) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_option", "%s", key);
        if (!val || strcmp(val, "true") != 0)
            krb5_set_error_message(r->context, ret = EINVAL,
                                   "get-keys \"%s\" q-param accepts "
                                   "only \"true\"", key);
        else if (strcmp(key, "materialize") == 0)
            r->materialize = 1;
        else if (strcmp(key, "revoke") == 0)
            r->revoke = 1;
        else if (strcmp(key, "rotate") == 0)
            r->rotate = 1;
        else if (strcmp(key, "create") == 0)
            r->create = 1;
        else if (strcmp(key, "ro") == 0)
            r->ro = 1;
    } else if (strcmp(key, "dNSName") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_dNSName", "%s", val);
        if (r->is_self) {
            krb5_set_error_message(r->context, ret = EACCES,
                                   "only one service may be requested for self");
        } else if (strchr(val, '.') == NULL) {
            krb5_set_error_message(r->context, ret = EACCES,
                                   "dNSName must have at least one '.' in it");
        } else {
            s = heim_string_create(val);
            if (!s)
                ret = krb5_enomem(r->context);
            else
                ret = heim_array_append_value(r->hostnames, s);
        }
        if (ret == 0)
            ret = hx509_request_add_dns_name(r->context->hx509ctx, r->req, val);
    } else if (strcmp(key, "service") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_service", "%s", val);
        if (r->is_self)
            krb5_set_error_message(r->context, ret = EACCES,
                                   "use \"spn\" for self");
        else
            ret = check_service_name(r, val);
        if (ret == 0) {
            s = heim_string_create(val);
            if (!s)
                ret = krb5_enomem(r->context);
            else
                ret = heim_array_append_value(r->service_names, s);
        }
    } else if (strcmp(key, "enctypes") == 0 && val) {
        r->enctypes = strdup(val);
        if (!(r->enctypes = strdup(val)))
            ret = krb5_enomem(r->context);
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_enctypes", "%s", val);
    } else if (r->is_self && strcmp(key, "spn") == 0 && val) {
        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_spn", "%s", val);
        krb5_set_error_message(r->context, ret = EACCES,
                               "only one service may be requested for self");
    } else if (strcmp(key, "spn") == 0 && val) {
        krb5_principal p = NULL;
        const char *hostname = "";

        heim_audit_addkv((heim_svc_req_desc)r, KDC_AUDIT_VIS,
                         "requested_spn", "%s", val);

        ret = krb5_parse_name_flags(r->context, val,
                                    KRB5_PRINCIPAL_PARSE_NO_DEF_REALM, &p);
        if (ret == 0 && krb5_principal_get_realm(r->context, p) == NULL)
            ret = krb5_principal_set_realm(r->context, p,
                                           r->realm ? r->realm : realm);

        /*
         * The SPN has to have two components.
         *
         * TODO: Support more components?  Support AD-style NetBIOS computer
         *       account names?
         */
        if (ret == 0 && krb5_principal_get_num_comp(r->context, p) != 2)
            ret = ENOTSUP;

        /*
         * Allow only certain service names.  Except that when
         * the SPN == the requestor's principal name then allow the "host"
         * service name.
         */
        if (ret == 0) {
            const char *service =
                krb5_principal_get_comp_string(r->context, p, 0);

            if (strcmp(service, "host") == 0 &&
                krb5_principal_compare(r->context, p, r->cprinc) &&
                !r->is_self &&
                heim_array_get_length(r->hostnames) == 0 &&
                heim_array_get_length(r->spns) == 0) {
                r->is_self = 1;
            } else
                ret = check_service_name(r, service);
        }
        if (ret == 0 && !krb5_principal_compare(r->context, p, r->cprinc))
            ret = check_service_name(r,
                                     krb5_principal_get_comp_string(r->context,
                                                                    p, 0));
        if (ret == 0) {
            hostname = krb5_principal_get_comp_string(r->context, p, 1);
            if (!hostname || !strchr(hostname, '.'))
                krb5_set_error_message(r->context, ret = ENOTSUP,
                                       "Only host-based service names supported");
        }
        if (ret == 0 && r->realm)
            ret = krb5_principal_set_realm(r->context, p, r->realm);
        else if (ret == 0 && realm)
            ret = krb5_principal_set_realm(r->context, p, realm);
        if (ret == 0)
            ret = hx509_request_add_dns_name(r->context->hx509ctx, r->req,
                                             hostname);
        if (ret == 0 && !(s = heim_string_create(val)))
            ret = krb5_enomem(r->context);
        if (ret == 0)
            ret = heim_array_append_value(r->spns, s);
        krb5_free_principal(r->context, p);

#if 0
        /* The authorizer probably doesn't know what to do with this */
        ret = hx509_request_add_pkinit(r->context->hx509ctx, r->req, val);
#endif
    } else {
        /* Produce error for unknown params */
        heim_audit_setkv_bool((heim_svc_req_desc)r, "requested_unknown", TRUE);
        krb5_set_error_message(r->context, ret = ENOTSUP,
                               "Query parameter %s not supported", key);
    }
    if (ret && !r->error_code)
        r->error_code = ret;
    heim_release(s);
    return ret ? MHD_NO /* Stop iterating */ : MHD_YES;
}

static krb5_error_code
authorize_req(kadmin_request_desc r)
{
    krb5_error_code ret;

    r->is_self = 0;
    ret = hx509_request_init(r->context->hx509ctx, &r->req);
    if (ret)
        return bad_enomem(r, ret);
    (void) MHD_get_connection_values(r->connection, MHD_GET_ARGUMENT_KIND,
                                     param_cb, r);
    ret = r->error_code;
    if (ret == EACCES)
        return bad_403(r, ret, "Not authorized to requested principal(s)");
    if (ret)
        return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Could not handle query parameters");
    if (r->is_self)
        ret = 0;
    else
        ret = kdc_authorize_csr(r->context, "ext_keytab", r->req, r->cprinc);
    if (ret == EACCES || ret == EINVAL || ret == ENOTSUP ||
        ret == KRB5KDC_ERR_POLICY)
        return bad_403(r, ret, "Not authorized to requested principal(s)");
    if (ret)
        return bad_req(r, ret, MHD_HTTP_SERVICE_UNAVAILABLE,
                       "Error checking authorization");
    return ret;
}

static krb5_error_code
make_keytab(kadmin_request_desc r)
{
    krb5_error_code ret = 0;
    int fd = -1;

    r->keytab_name = NULL;
    if (asprintf(&r->keytab_name, "FILE:%s/kt-XXXXXX", cache_dir) == -1 ||
        r->keytab_name == NULL)
        ret = krb5_enomem(r->context);
    if (ret == 0)
        fd = mkstemp(r->keytab_name + sizeof("FILE:") - 1);
    if (ret == 0 && fd == -1)
        ret = errno;
    if (ret == 0)
        ret = krb5_kt_resolve(r->context, r->keytab_name, &r->keytab);
    if (fd != -1)
        (void) close(fd);
    return ret;
}

static krb5_error_code
write_keytab(kadmin_request_desc r,
             kadm5_principal_ent_rec *princ,
             const char *unparsed)
{
    krb5_error_code ret = 0;
    krb5_keytab_entry key;
    size_t i;

    if (princ->n_key_data <= 0)
        return 0;

    if (kadm5_some_keys_are_bogus(princ->n_key_data, &princ->key_data[0])) {
        krb5_warn(r->context, ret,
                  "httpkadmind running with insufficient kadmin privilege "
                  "for extracting keys for %s", unparsed);
        krb5_log_msg(r->context, logfac, 1, NULL,
                  "httpkadmind running with insufficient kadmin privilege "
                  "for extracting keys for %s", unparsed);
        return EACCES;
    }

    memset(&key, 0, sizeof(key));
    for (i = 0; ret == 0 && i < princ->n_key_data; i++) {
        krb5_key_data *kd = &princ->key_data[i];

        key.principal = princ->principal;
        key.vno = kd->key_data_kvno;
        key.keyblock.keytype = kd->key_data_type[0];
        key.keyblock.keyvalue.length = kd->key_data_length[0];
        key.keyblock.keyvalue.data = kd->key_data_contents[0];

        /*
         * FIXME kadm5 doesn't give us set_time here.  If it gave us the
         * KeyRotation metadata, we could compute it.  But this might be a
         * concrete principal with concrete keys, in which case we can't.
         *
         * To fix this we need to extend the protocol and the API.
         */
        key.timestamp = time(NULL);

        ret = krb5_kt_add_entry(r->context, r->keytab, &key);
    }
    if (ret)
        krb5_warn(r->context, ret,
                  "Failed to write keytab entries for %s", unparsed);

    return ret;
}

static void
random_password(krb5_context context, char *buf, size_t buflen)
{
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,";
    char p[32];
    size_t i;
    char b;

    buflen--;
    for (i = 0; i < buflen; i++) {
        if (i % sizeof(p) == 0)
            krb5_generate_random_block(p, sizeof(p));
        b = p[i % sizeof(p)];
        buf[i] = chars[b % (sizeof(chars) - 1)];
    }
    buf[i] = '\0';
}

static krb5_error_code
make_kstuple(krb5_context context,
             kadm5_principal_ent_rec *p,
             krb5_key_salt_tuple **kstuple,
             size_t *n_kstuple)
{
    size_t i;

    *kstuple = 0;
    *n_kstuple = 0;

    if (p->n_key_data < 1)
        return 0;
    *kstuple = calloc(p->n_key_data, sizeof (**kstuple));
    for (i = 0; *kstuple && i < p->n_key_data; i++) {
        if (p->key_data[i].key_data_kvno == p->kvno) {
            (*kstuple)[i].ks_enctype = p->key_data[i].key_data_type[0];
            (*kstuple)[i].ks_salttype = p->key_data[i].key_data_type[1];
            (*n_kstuple)++;
        }
    }
    return *kstuple ? 0 :krb5_enomem(context);
}

/* Copied from kadmin/util.c */
struct units kdb_attrs[] = {
    { "auth-data-reqd",         KRB5_KDB_AUTH_DATA_REQUIRED },
    { "no-auth-data-reqd",      KRB5_KDB_NO_AUTH_DATA_REQUIRED },
    { "disallow-client",        KRB5_KDB_DISALLOW_CLIENT },
    { "virtual",                KRB5_KDB_VIRTUAL },
    { "virtual-keys",           KRB5_KDB_VIRTUAL_KEYS },
    { "allow-digest",           KRB5_KDB_ALLOW_DIGEST },
    { "allow-kerberos4",        KRB5_KDB_ALLOW_KERBEROS4 },
    { "trusted-for-delegation", KRB5_KDB_TRUSTED_FOR_DELEGATION },
    { "ok-as-delegate",         KRB5_KDB_OK_AS_DELEGATE },
    { "new-princ",              KRB5_KDB_NEW_PRINC },
    { "support-desmd5",         KRB5_KDB_SUPPORT_DESMD5 },
    { "pwchange-service",       KRB5_KDB_PWCHANGE_SERVICE },
    { "disallow-svr",           KRB5_KDB_DISALLOW_SVR },
    { "requires-pw-change",     KRB5_KDB_REQUIRES_PWCHANGE },
    { "requires-hw-auth",       KRB5_KDB_REQUIRES_HW_AUTH },
    { "requires-pre-auth",      KRB5_KDB_REQUIRES_PRE_AUTH },
    { "disallow-all-tix",       KRB5_KDB_DISALLOW_ALL_TIX },
    { "disallow-dup-skey",      KRB5_KDB_DISALLOW_DUP_SKEY },
    { "disallow-proxiable",     KRB5_KDB_DISALLOW_PROXIABLE },
    { "disallow-renewable",     KRB5_KDB_DISALLOW_RENEWABLE },
    { "disallow-tgt-based",     KRB5_KDB_DISALLOW_TGT_BASED },
    { "disallow-forwardable",   KRB5_KDB_DISALLOW_FORWARDABLE },
    { "disallow-postdated",     KRB5_KDB_DISALLOW_POSTDATED },
    { NULL, 0 }
};

/*
 * Determine the default/allowed attributes for some new principal.
 */
static krb5_flags
create_attributes(kadmin_request_desc r, krb5_const_principal p)
{
    krb5_error_code ret;
    const char *srealm = krb5_principal_get_realm(r->context, p);
    const char *svc;
    const char *hn;

    /* Has to be a host-based service principal (for now) */
    if (krb5_principal_get_num_comp(r->context, p) != 2)
        return 0;

    hn = krb5_principal_get_comp_string(r->context, p, 1);
    svc = krb5_principal_get_comp_string(r->context, p, 0);

    while (hn && strchr(hn, '.') != NULL) {
        kadm5_principal_ent_rec nsprinc;
        krb5_principal nsp;
        uint64_t a = 0;
        const char *as;

        /* Try finding a virtual host-based service principal namespace */
        memset(&nsprinc, 0, sizeof(nsprinc));
        ret = krb5_make_principal(r->context, &nsp, srealm,
                                  KRB5_WELLKNOWN_NAME, HDB_WK_NAMESPACE,
                                  svc, hn, NULL);
        if (ret == 0)
            ret = kadm5_get_principal(r->kadm_handle, nsp, &nsprinc,
                                      KADM5_PRINCIPAL | KADM5_ATTRIBUTES);
        krb5_free_principal(r->context, nsp);
        if (ret == 0) {
            /* Found one; use it even if disabled, but drop that attribute */
            a = nsprinc.attributes & ~KRB5_KDB_DISALLOW_ALL_TIX;
            kadm5_free_principal_ent(r->kadm_handle, &nsprinc);
            return a;
        }

        /* Fallback on krb5.conf */
        as = krb5_config_get_string(r->context, NULL, "ext_keytab",
                                    "new_hostbased_service_principal_attributes",
                                    svc, hn, NULL);
        if (as) {
            a = parse_flags(as, kdb_attrs, 0);
            if (a == (uint64_t)-1) {
                krb5_warnx(r->context, "Invalid value for [ext_keytab] "
                           "new_hostbased_service_principal_attributes");
                return 0;
            }
            return a;
        }

        hn = strchr(hn + 1, '.');
    }

    return 0;
}

/*
 * Get keys for one principal.
 *
 * Does NOT set an HTTP response.
 */
static krb5_error_code
get_keys1(kadmin_request_desc r, const char *pname)
{
    kadm5_principal_ent_rec princ;
    krb5_key_salt_tuple *kstuple = NULL;
    krb5_error_code ret = 0;
    krb5_principal p = NULL;
    uint32_t mask =
        KADM5_PRINCIPAL | KADM5_KVNO | KADM5_MAX_LIFE | KADM5_MAX_RLIFE |
        KADM5_PW_EXPIRATION | KADM5_ATTRIBUTES | KADM5_KEY_DATA |
        KADM5_TL_DATA;
    uint32_t create_mask = mask & ~(KADM5_KEY_DATA | KADM5_TL_DATA);
    size_t nkstuple = 0;
    int change = 0;
    int refetch = 0;
    int freeit = 0;

    memset(&princ, 0, sizeof(princ));
    princ.key_data = NULL;
    princ.tl_data = NULL;

    ret = krb5_parse_name(r->context, pname, &p);
    if (ret == 0 && r->realm)
        ret = krb5_principal_set_realm(r->context, p, r->realm);
    else if (ret == 0 && realm)
        ret = krb5_principal_set_realm(r->context, p, realm);
    if (ret == 0 && r->enctypes)
        ret = krb5_string_to_keysalts2(r->context, r->enctypes,
                                       &nkstuple, &kstuple);
    if (ret == 0)
        ret = kadm5_get_principal(r->kadm_handle, p, &princ, mask);
    if (ret == 0) {
        freeit = 1;

        /*
         * If princ is virtual and we're not asked to materialize, ignore
         * requests to rotate.
         */
        if (!r->materialize &&
            (princ.attributes & (KRB5_KDB_VIRTUAL_KEYS | KRB5_KDB_VIRTUAL))) {
            r->rotate = 0;
            r->revoke = 0;
        }
    }

    change = !r->ro && (r->rotate || r->revoke);

    /* Handle create / materialize options */
    if (ret == KADM5_UNK_PRINC && r->create) {
        char pw[128];

        memset(&princ, 0, sizeof(princ));
        princ.attributes = create_attributes(r, p);

        if (read_only)
            ret = KADM5_READ_ONLY;
        else
            ret = strcmp(r->method, "POST") == 0 ? 0 : ENOSYS; /* XXX */
        if (ret == 0 && local_hdb && local_hdb_read_only) {
            /* Make sure we can write */
            kadm5_destroy(r->kadm_handle);
            r->kadm_handle = NULL;
            ret = get_kadm_handle(r->context, r->realm, 1 /* want_write */,
                                  &r->kadm_handle);
        }
        /*
         * Some software is allergic to kvno 1, assuming that kvno 1 implies
         * half-baked service principal.  We've some vague recollection of
         * something similar for kvno 2, so let's start at 3.
         */
        princ.kvno = 3;
        princ.tl_data = NULL;
        princ.key_data = NULL;
        princ.max_life = 24 * 3600;                /* XXX Make configurable */
        princ.max_renewable_life = princ.max_life; /* XXX Make configurable */

        random_password(r->context, pw, sizeof(pw));
        princ.principal = p;     /* Borrow */
        if (ret == 0)
            ret = kadm5_create_principal_3(r->kadm_handle, &princ, create_mask,
                                           nkstuple, kstuple, pw);
        princ.principal = NULL;  /* Return */
        refetch = 1;
        freeit = 1;
    } else if (ret == 0 && r->materialize &&
               (princ.attributes & KRB5_KDB_VIRTUAL)) {

        if (read_only)
            ret = KADM5_READ_ONLY;
        else
            ret = strcmp(r->method, "POST") == 0 ? 0 : ENOSYS; /* XXX */
        if (ret == 0 && local_hdb && local_hdb_read_only) {
            /* Make sure we can write */
            kadm5_destroy(r->kadm_handle);
            r->kadm_handle = NULL;
            ret = get_kadm_handle(r->context, r->realm, 1 /* want_write */,
                                  &r->kadm_handle);
        }
        princ.attributes |= KRB5_KDB_MATERIALIZE;
        princ.attributes &= ~KRB5_KDB_VIRTUAL;
        /*
         * XXX If there are TL data which should be re-encoded and sent as
         * KRB5_TL_EXTENSION, then this call will fail with KADM5_BAD_TL_TYPE.
         *
         * We should either drop those TLs, re-encode them, or make
         * perform_tl_data() handle them.  (New extensions should generally go
         * as KRB5_TL_EXTENSION so that non-critical ones can be set on
         * principals via old kadmind programs that don't support them.)
         *
         * What we really want is a kadm5 utility function to convert some TLs
         * to KRB5_TL_EXTENSION and drop all others.
         */
        if (ret == 0)
            ret = kadm5_create_principal(r->kadm_handle, &princ, mask, "");
        refetch = 1;
    } /* else create/materialize q-params are superfluous */

    /* Handle rotate / revoke options */
    if (ret == 0 && change) {
        krb5_keyblock *k = NULL;
        size_t i;
        int n_k = 0;
        int keepold = r->revoke ? 0 : 1;

        if (read_only)
            ret = KADM5_READ_ONLY;
        else
            ret = strcmp(r->method, "POST") == 0 ? 0 : ENOSYS; /* XXX */
        if (ret == 0 && local_hdb && local_hdb_read_only) {
            /* Make sure we can write */
            kadm5_destroy(r->kadm_handle);
            r->kadm_handle = NULL;
            ret = get_kadm_handle(r->context, r->realm, 1 /* want_write */,
                                  &r->kadm_handle);
        }

        /* Use requested enctypes or same ones as princ already had keys for */
        if (ret == 0 && kstuple == NULL)
            ret = make_kstuple(r->context, &princ, &kstuple, &nkstuple);

        /* Set new keys */
        if (ret == 0)
            ret = kadm5_randkey_principal_3(r->kadm_handle, p, keepold,
                                            nkstuple, kstuple, &k, &n_k);
        refetch = 1;
        for (i = 0; n_k > 0 && i < n_k; i++)
            krb5_free_keyblock_contents(r->context, &k[i]);
        free(kstuple);
        free(k);
    }

    if (ret == 0 && refetch) {
        /* Refetch changed principal */
        if (freeit)
            kadm5_free_principal_ent(r->kadm_handle, &princ);
        freeit = 0;
        ret = kadm5_get_principal(r->kadm_handle, p, &princ, mask);
        if (ret == 0)
            freeit = 1;
    }

    if (ret == 0)
        ret = write_keytab(r, &princ, pname);

    if (ret == 0) {
        /*
         * We will use the principal's password expiration to work out the
         * value for the max-age Cache-Control.
         *
         * Virtual service principals will have their `pw_expiration' set to a
         * time when the client should refetch keys.
         *
         * Concrete service principals will generally not have a non-zero
         * `pw_expiration', but if we have a new_service_key_delay, then we'll
         * use half of it as the max-age Cache-Control.
         */
        if (princ.pw_expiration == 0) {
            krb5_timestamp nskd =
                krb5_config_get_time_default(r->context, NULL, 0, "hdb",
                                             "new_service_key_delay", NULL);
            if (nskd)
                princ.pw_expiration = time(NULL) + (nskd >> 1);
        }

        /*
         * This service can be used to fetch more than one principal's keys, so
         * the max-age Cache-Control should be derived from the soonest-
         * "expiring" principal.
         */
        if (r->pw_end == 0 ||
            (princ.pw_expiration < r->pw_end && princ.pw_expiration > time(NULL)))
            r->pw_end = princ.pw_expiration;
    }
    if (freeit)
        kadm5_free_principal_ent(r->kadm_handle, &princ);
    krb5_free_principal(r->context, p);
    return ret;
}

static krb5_error_code check_csrf(kadmin_request_desc);

/*
 * Calls get_keys1() to extract each requested principal's keys.
 *
 * When this returns a response will have been set.
 */
static krb5_error_code
get_keysN(kadmin_request_desc r)
{
    krb5_error_code ret;
    size_t nhosts;
    size_t nsvcs;
    size_t nspns;
    size_t i, k;

    /* Parses and validates the request, then checks authorization */
    ret = authorize_req(r);
    if (ret)
        return ret; /* authorize_req() calls bad_req() on error */

    /*
     * If we have a r->kadm_handle already it's because we validated a CSRF
     * token.  It may not be a handle to a realm we wanted though.
     */
    if (r->kadm_handle)
        kadm5_destroy(r->kadm_handle);
    r->kadm_handle = NULL;
    ret = get_kadm_handle(r->context, r->realm ? r->realm : realm,
                          0 /* want_write */, &r->kadm_handle);
    if (ret)
        return bad_404(r, ret, "Could not connect to realm");

    nhosts = heim_array_get_length(r->hostnames);
    nsvcs = heim_array_get_length(r->service_names);
    nspns = heim_array_get_length(r->spns);
    if (!nhosts && !nspns)
        return bad_403(r, EINVAL, "No service principals requested");

    if (nhosts && !nsvcs) {
        heim_string_t s;

        if ((s = heim_string_create("HTTP")) == NULL)
            ret = krb5_enomem(r->context);
        if (ret == 0)
            ret = heim_array_append_value(r->service_names, s);
        heim_release(s);
        nsvcs = 1;
        if (ret)
            return bad_503(r, ret, "Out of memory");
    }

    if (nspns + nsvcs * nhosts >
        krb5_config_get_int_default(r->context, NULL, 400,
                                    "ext_keytab", "get_keys_max_spns", NULL))
        return bad_403(r, EINVAL, "Requested keys for too many principals");

    ret = make_keytab(r);
    for (i = 0; ret == 0 && i < nsvcs; i++) {
        const char *svc =
            heim_string_get_utf8(
                heim_array_get_value(r->service_names, i));

        for (k = 0; ret == 0 && k < nhosts; k++) {
            krb5_principal p = NULL;
            const char *hostname =
                heim_string_get_utf8(
                    heim_array_get_value(r->hostnames, k));
            char *spn = NULL;

            ret = krb5_make_principal(r->context, &p,
                                      r->realm ? r->realm : realm,
                                      svc, hostname, NULL);
            if (ret == 0)
                ret = krb5_unparse_name(r->context, p, &spn);
            if (ret == 0)
                ret = get_keys1(r, spn);
            krb5_free_principal(r->context, p);
            free(spn);
        }
    }
    for (i = 0; ret == 0 && i < nspns; i++) {
        ret = get_keys1(r,
                        heim_string_get_utf8(heim_array_get_value(r->spns,
                                                                  i)));
    }
    switch (ret) {
    case -1:
        /* Can't happen */
        krb5_log_msg(r->context, logfac, 1, NULL,
                     "Failed to extract keys for unknown reasons");
        if (r->response_set)
            return MHD_YES;
        return bad_503(r, ret, "Could not get keys");
    case ENOSYS:
        /* Our convention */
        return bad_method_want_POST(r);
    case KADM5_READ_ONLY:
        if (primary_server_URI) {
            krb5_log_msg(r->context, logfac, 1, NULL,
                         "Redirect %s to primary server", r->cname);
            return resp(r, MHD_HTTP_TEMPORARY_REDIRECT, KADM5_READ_ONLY,
                        MHD_RESPMEM_PERSISTENT, NULL, "", 0, NULL);
        } else {
            krb5_log_msg(r->context, logfac, 1, NULL, "HDB is read-only");
            return bad_403(r, ret, "HDB is read-only");
        }
    case 0:
        krb5_log_msg(r->context, logfac, 1, NULL, "Sent keytab to %s",
                     r->cname);
        return good_ext_keytab(r);
    default:
        return bad_503(r, ret, "Could not get keys");
    }
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

static void clean_req_desc(kadmin_request_desc);

static krb5_error_code
set_req_desc(struct MHD_Connection *connection,
             const char *method,
             const char *url,
             kadmin_request_desc *rp)
{
    const union MHD_ConnectionInfo *ci;
    kadmin_request_desc r;
    const char *token;
    krb5_error_code ret;

    *rp = NULL;
    if ((r = calloc(1, sizeof(*r))) == NULL)
        return ENOMEM;

    (void) gettimeofday(&r->tv_start, NULL);
    if ((ret = get_krb5_context(&r->context))) {
        free(r);
        return ret;
    }
    /* HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS fields */
    r->request.data = "<HTTP-REQUEST>";
    r->request.length = sizeof("<HTTP-REQUEST>");
    r->from = r->frombuf;
    r->free_list = NULL;
    r->config = NULL;
    r->logf = logfac;
    r->reqtype = url;
    r->reason = NULL;
    r->reply = NULL;
    r->sname = NULL;
    r->cname = NULL;
    r->addr = NULL;
    r->kv = heim_dict_create(10);
    r->pp = NULL;
    r->attributes = heim_dict_create(1);
    /* Our fields */
    r->connection = connection;
    r->kadm_handle = NULL;
    r->hcontext = r->context->hcontext;
    r->service_names = heim_array_create();
    r->hostnames = heim_array_create();
    r->spns = heim_array_create();
    r->keytab_name = NULL;
    r->enctypes = NULL;
    r->cache_control = NULL;
    r->freeme1 = NULL;
    r->method = method;
    r->cprinc = NULL;
    r->req = NULL;
    r->sp = NULL;
    ci = MHD_get_connection_info(connection,
                                 MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci) {
        r->addr = ci->client_addr;
        addr_to_string(r->context, r->addr, r->frombuf, sizeof(r->frombuf));
    }

    if (r->kv) {
        heim_audit_addkv((heim_svc_req_desc)r, 0, "method", "GET");
        heim_audit_addkv((heim_svc_req_desc)r, 0, "endpoint", "%s", r->reqtype);
    }
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

    if (ret == 0 && r->kv == NULL) {
        krb5_log_msg(r->context, logfac, 1, NULL, "Out of memory");
        ret = r->error_code = ENOMEM;
    }
    if (ret == 0)
        *rp = r;
    else
        clean_req_desc(r);
    return ret;
}

static void
clean_req_desc(kadmin_request_desc r)
{
    if (!r)
        return;

    if (r->keytab)
        krb5_kt_destroy(r->context, r->keytab);
    else if (r->keytab_name && strchr(r->keytab_name, ':'))
        (void) unlink(strchr(r->keytab_name, ':') + 1);
    if (r->kadm_handle)
        kadm5_destroy(r->kadm_handle);
    if (r->pp)
        MHD_destroy_post_processor(r->pp);
    hx509_request_free(&r->req);
    heim_release(r->service_names);
    heim_release(r->attributes);
    heim_release(r->hostnames);
    heim_release(r->reason);
    heim_release(r->spns);
    heim_release(r->kv);
    krb5_free_principal(r->context, r->cprinc);
    free(r->cache_control);
    free(r->keytab_name);
    free(r->csrf_token);
    free(r->enctypes);
    free(r->freeme1);
    free(r->cname);
    free(r->sname);
    free(r->realm);
    free(r);
}

static void
cleanup_req(void *cls,
            struct MHD_Connection *connection,
            void **con_cls,
            enum MHD_RequestTerminationCode toe)
{
    kadmin_request_desc r = *con_cls;

    (void)cls;
    (void)connection;
    (void)toe;
    clean_req_desc(r);
    *con_cls = NULL;
}

/* Implements GETs of /get-keys */
static krb5_error_code
get_keys(kadmin_request_desc r)
{
    if (r->cname == NULL || r->cprinc == NULL)
        return bad_401(r, "Could not extract principal name from token");
    return get_keysN(r); /* Sets an HTTP response */
}

/* Implements GETs of /get-config */
static krb5_error_code
get_config(kadmin_request_desc r)
{

    kadm5_principal_ent_rec princ;
    krb5_error_code ret;
    krb5_principal p = NULL;
    uint32_t mask = KADM5_PRINCIPAL | KADM5_TL_DATA;
    krb5_tl_data *tl_next;
    const char *pname;
    /* Default configuration for principals that have none set: */
    size_t bodylen = sizeof("include /etc/krb5.conf\n") - 1;
    void *body = "include /etc/krb5.conf\n";
    int freeit = 0;

    if (r->cname == NULL || r->cprinc == NULL)
        return bad_401(r, "Could not extract principal name from token");
    /*
     * No authorization needed -- configs are public.  Though we do require
     * authentication (above).
     */

    ret = get_kadm_handle(r->context, r->realm ? r->realm : realm,
                          0 /* want_write */, &r->kadm_handle);
    if (ret)
        return bad_503(r, ret, "Could not access KDC database");

    memset(&princ, 0, sizeof(princ));
    princ.key_data = NULL;
    princ.tl_data = NULL;

    pname = MHD_lookup_connection_value(r->connection, MHD_GET_ARGUMENT_KIND,
                                        "princ");
    if (pname == NULL)
        pname = r->cname;
    ret = krb5_parse_name(r->context, pname, &p);
    if (ret == 0) {
        ret = kadm5_get_principal(r->kadm_handle, p, &princ, mask);
        if (ret == 0) {
            freeit = 1;
            for (tl_next = princ.tl_data; tl_next; tl_next = tl_next->tl_data_next) {
                if (tl_next->tl_data_type != KRB5_TL_KRB5_CONFIG)
                    continue;
                bodylen = tl_next->tl_data_length;
                body = tl_next->tl_data_contents;
                break;
            }
        } else {
            r->error_code = ret;
            return bad_404(r, ret, "/get-config");
        }
    }

    if (ret == 0) {
        krb5_log_msg(r->context, logfac, 1, NULL,
                     "Returned krb5.conf contents to %s", r->cname);
        ret = resp(r, MHD_HTTP_OK, 0, MHD_RESPMEM_MUST_COPY,
                   "application/text", body, bodylen, NULL);
    } else {
        ret = bad_503(r, ret, "Could not retrieve principal configuration");
    }
    if (freeit)
        kadm5_free_principal_ent(r->kadm_handle, &princ);
    krb5_free_principal(r->context, p);
    return ret;
}

static krb5_error_code
mac_csrf_token(kadmin_request_desc r, krb5_storage *sp)
{
    kadm5_principal_ent_rec princ;
    krb5_error_code ret;
    krb5_principal p = NULL;
    krb5_data data;
    char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = sizeof(mac);
    HMAC_CTX *ctx = NULL;
    size_t i = 0;
    int freeit = 0;

    memset(&princ, 0, sizeof(princ));
    ret = krb5_storage_to_data(sp, &data);
    if (r->kadm_handle == NULL)
        ret = get_kadm_handle(r->context,
                              r->realm ? r->realm : realm,
                              0 /* want_write */,
                              &r->kadm_handle);
    if (ret == 0)
        ret = krb5_make_principal(r->context, &p,
                                  r->realm ? r->realm : realm,
                                  "WELLKNOWN", "CSRFTOKEN", NULL);
    if (ret == 0)
        ret = kadm5_get_principal(r->kadm_handle, p, &princ, 
                                  KADM5_PRINCIPAL | KADM5_KVNO |
                                  KADM5_KEY_DATA);
    if (ret == 0)
        freeit = 1;
    if (ret == 0 && princ.n_key_data < 1)
        ret = KADM5_UNK_PRINC;
    if (ret == 0)
        for (i = 0; i < princ.n_key_data; i++)
            if (princ.key_data[i].key_data_kvno == princ.kvno)
                break;
    if (ret == 0 && i == princ.n_key_data)
        i = 0; /* Weird, but can't happen */

    if (ret == 0 && (ctx = HMAC_CTX_new()) == NULL)
            ret = krb5_enomem(r->context);
    /* HMAC the token body and the client principal name */
    if (ret == 0) {
        if (HMAC_Init_ex(ctx, princ.key_data[i].key_data_contents[0],
                         princ.key_data[i].key_data_length[0], EVP_sha256(),
                         NULL) == 0) {
            HMAC_CTX_cleanup(ctx);
            ret = krb5_enomem(r->context);
        } else {
            HMAC_Update(ctx, data.data, data.length);
            HMAC_Update(ctx, r->cname, strlen(r->cname));
            HMAC_Final(ctx, mac, &maclen);
            HMAC_CTX_cleanup(ctx);
            krb5_data_free(&data);
            data.length = maclen;
            data.data = mac;
            if (krb5_storage_write(sp, mac, maclen) != maclen)
                ret = krb5_enomem(r->context);
        }
    }
    krb5_free_principal(r->context, p);
    if (freeit)
        kadm5_free_principal_ent(r->kadm_handle, &princ);
    if (ctx)
        HMAC_CTX_free(ctx);
    return ret;
}

static krb5_error_code
make_csrf_token(kadmin_request_desc r,
                const char *given,
                char **token,
                int64_t *age)
{
    krb5_error_code ret = 0;
    unsigned char given_decoded[128];
    krb5_storage *sp = NULL;
    krb5_data data;
    ssize_t dlen = -1;
    uint64_t nonce;
    int64_t t = 0;


    *age = 0;
    data.data = NULL;
    data.length = 0;
    if (given) {
        size_t len = strlen(given);

        if (len >= sizeof(given_decoded))
            ret = ERANGE;
        if (ret == 0 && (dlen = rk_base64_decode(given, &given_decoded)) <= 0)
            ret = errno;
        if (ret == 0 &&
            (sp = krb5_storage_from_mem(given_decoded, dlen)) == NULL)
            ret = krb5_enomem(r->context);
        if (ret == 0)
            ret = krb5_ret_int64(sp, &t);
        if (ret == 0)
            ret = krb5_ret_uint64(sp, &nonce);
        krb5_storage_free(sp);
        sp = NULL;
        if (ret == 0)
            *age = time(NULL) - t;
    } else {
        t = time(NULL);
        krb5_generate_random_block((void *)&nonce, sizeof(nonce));
    }

    if (ret == 0 && (sp = krb5_storage_emem()) == NULL)
        ret = krb5_enomem(r->context);
    if (ret == 0)
        ret = krb5_store_int64(sp, t);
    if (ret == 0)
        ret = krb5_store_uint64(sp, nonce);
    if (ret == 0)
        ret = mac_csrf_token(r, sp);
    if (ret == 0)
        ret = krb5_storage_to_data(sp, &data);
    if (ret == 0 && data.length > INT_MAX)
        ret = ERANGE;
    if (ret == 0 &&
        rk_base64_encode(data.data, data.length, token) < 0)
        ret = errno;
    krb5_storage_free(sp);
    krb5_data_free(&data);
    return ret;
}

/*
 * Returns system or krb5_error_code on error, but also calls resp() or bad_*()
 * on error.
 */
static krb5_error_code
check_csrf(kadmin_request_desc r)
{
    krb5_error_code ret;
    const char *given;
    int64_t age;
    size_t givenlen, expectedlen;

    if ((((csrf_prot_type & CSRF_PROT_GET_WITH_HEADER) &&
          strcmp(r->method, "GET") == 0) ||
         ((csrf_prot_type & CSRF_PROT_POST_WITH_HEADER) &&
          strcmp(r->method, "POST") == 0)) &&
        MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                    csrf_header) == NULL) {
        ret = bad_req(r, EACCES, MHD_HTTP_FORBIDDEN,
                      "Request must have header \"%s\"", csrf_header);
        return ret == -1 ? MHD_NO : MHD_YES;
    }

    if (strcmp(r->method, "GET") == 0 &&
        !(csrf_prot_type & CSRF_PROT_GET_WITH_TOKEN))
        return 0;
    if (strcmp(r->method, "POST") == 0 &&
        !(csrf_prot_type & CSRF_PROT_POST_WITH_TOKEN))
        return 0;

    given = MHD_lookup_connection_value(r->connection, MHD_HEADER_KIND,
                                        "X-CSRF-Token");
    ret = make_csrf_token(r, given, &r->csrf_token, &age);
    if (ret)
        return bad_503(r, ret, "Could not create a CSRF token");
    /*
     * If CSRF token needed but missing, call resp() directly, bypassing
     * bad_403(), to return a 403 with an expected CSRF token in the response.
     */
    if (given == NULL) {
        (void) resp(r, MHD_HTTP_FORBIDDEN, ENOSYS, MHD_RESPMEM_PERSISTENT,
                    NULL, "CSRF token needed; copy the X-CSRF-Token: response "
                    "header to your next POST", BODYLEN_IS_STRLEN, NULL);
        return ENOSYS;
    }

    /* Validate the CSRF token for this request */
    givenlen = strlen(given);
    expectedlen = strlen(r->csrf_token);
    if (givenlen != expectedlen || ct_memcmp(given, r->csrf_token, givenlen)) {
        (void) bad_403(r, EACCES, "Invalid CSRF token");
        return EACCES;
    }
    if (age > 300) { /* XXX */
        (void) bad_403(r, EACCES, "CSRF token too old");
        return EACCES;
    }
    return 0;
}

static krb5_error_code
health(const char *method, kadmin_request_desc r)
{
    if (strcmp(method, "HEAD") == 0) {
        return resp(r, MHD_HTTP_OK, 0, MHD_RESPMEM_PERSISTENT, NULL, "", 0,
                    NULL);
    }
    return resp(r, MHD_HTTP_OK, 0, MHD_RESPMEM_PERSISTENT, NULL,
                "To determine the health of the service, use the /get-config "
                "end-point.\n", BODYLEN_IS_STRLEN, NULL);

}

static heim_mhd_result
ip(void *cls,
   enum MHD_ValueKind kind,
   const char *key,
   const char *content_name,
   const char *content_type,
   const char *transfer_encoding,
   const char *val,
   uint64_t off,
   size_t size)
{
    kadmin_request_desc r = cls;
    struct free_tend_list *ftl = calloc(1, sizeof(*ftl));
    char *keydup = strdup(key);
    char *valdup = strndup(val, size);

    (void)content_name;         /* MIME attachment name */
    (void)content_type;
    (void)transfer_encoding;
    (void)off;                  /* Offset in POST data */

    /* We're going to MHD_set_connection_value(), but we need copies */
    if (ftl == NULL || keydup == NULL || valdup == NULL) {
        free(ftl);
        free(keydup);
        free(valdup);
        return MHD_NO;
    }
    ftl->freeme1 = keydup;
    ftl->freeme2 = valdup;
    ftl->next = r->free_list;
    r->free_list = ftl;

    return MHD_set_connection_value(r->connection, MHD_GET_ARGUMENT_KIND,
                                    keydup, valdup);
}

typedef krb5_error_code (*handler)(struct kadmin_request_desc *);

struct route {
    const char *local_part;
    handler h;
} routes[] = {
    { "/get-keys", get_keys },
    { "/get-config", get_config },
};

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
    struct kadmin_request_desc *r = *ctx;
    size_t i;
    int ret;

    if (r == NULL) {
        /*
         * This is the first call, right after headers were read.
         *
         * We must return quickly so that any 100-Continue might be sent with
         * celerity.  We want to make sure to send any 401s early, so we check
         * WWW-Authenticate now, not later.
         *
         * We'll get called again to really do the processing.  If we're
         * handling a POST then we'll also get called with upload_data != NULL,
         * possibly multiple times.
         */
        if ((ret = set_req_desc(connection, method, url, &r)))
            return MHD_NO;
        *ctx = r;

        /*
         * All requests other than /health require authentication and CSRF
         * protection.
         */
        if (strcmp(url, "/health") == 0)
            return MHD_YES;

        /* Authenticate and do CSRF protection */
        ret = validate_token(r);
        if (ret == 0)
            ret = check_csrf(r);

        /*
         * As this is the initial call to this handler, we must return now.
         *
         * If authentication or CSRF protection failed then we'll already have
         * enqueued a 401, 403, or 5xx response and then we're done.
         *
         * If both authentication and CSRF protection succeeded then no
         * response has been queued up and we'll get called again to finally
         * process the request, then this entire if block will not be executed.
         */
        return ret == -1 ? MHD_NO : MHD_YES;
    }

    /* Validate HTTP method */
    if (strcmp(method, "GET") != 0 &&
        strcmp(method, "POST") != 0 &&
        strcmp(method, "HEAD") != 0) {
        return bad_405(r, method) == -1 ? MHD_NO : MHD_YES;
    }

    if ((strcmp(method, "HEAD") == 0 || strcmp(method, "GET") == 0) &&
        (strcmp(url, "/health") == 0 || strcmp(url, "/") == 0)) {
        /* /health end-point -- no authentication, no CSRF, no nothing */
        return health(method, r) == -1 ? MHD_NO : MHD_YES;
    }

    if (strcmp(method, "POST") == 0 && *upload_data_size != 0) {
        /*
         * Consume all the POST body and set form data as MHD_GET_ARGUMENT_KIND
         * (as if they had been URI query parameters).
         *
         * We have to do this before we can MHD_queue_response() as MHD will
         * not consume the rest of the request body on its own, so it's an
         * error to MHD_queue_response() before we've done this, and if we do
         * then MHD just closes the connection.
         *
         * 4KB should be more than enough buffer space for all the keys we
         * expect.
         */
        if (r->pp == NULL)
            r->pp = MHD_create_post_processor(connection, 4096, ip, r);
        if (r->pp == NULL) {
            ret = bad_503(r, errno ? errno : ENOMEM,
                          "Could not consume POST data");
            return ret == -1 ? MHD_NO : MHD_YES;
        }
        if (r->post_data_size + *upload_data_size > 1UL<<17) {
            return bad_413(r) == -1 ? MHD_NO : MHD_YES;
        }
        r->post_data_size += *upload_data_size;
        if (MHD_post_process(r->pp, upload_data,
                             *upload_data_size) == MHD_NO) {
            ret = bad_503(r, errno ? errno : ENOMEM,
                          "Could not consume POST data");
            return ret == -1 ? MHD_NO : MHD_YES;
        }
        *upload_data_size = 0;
        return MHD_YES;
    }

    /*
     * Either this is a HEAD, a GET, or a POST whose request body has now been
     * received completely and processed.
     */

    /* Allow GET? */
    if (strcmp(method, "GET") == 0 && !allow_GET_flag) {
        /* No */
        return bad_405(r, method) == -1 ? MHD_NO : MHD_YES;
    }

    for (i = 0; i < sizeof(routes)/sizeof(routes[0]); i++) {
        if (strcmp(url, routes[i].local_part) != 0)
            continue;
        if (MHD_lookup_connection_value(r->connection,
                                        MHD_HEADER_KIND,
                                        "Referer") != NULL) {
            ret = bad_req(r, EACCES, MHD_HTTP_FORBIDDEN,
                          "GET from browser not allowed");
            return ret == -1 ? MHD_NO : MHD_YES;
        }
        if (strcmp(method, "HEAD") == 0)
            ret = resp(r, MHD_HTTP_OK, 0, MHD_RESPMEM_PERSISTENT, NULL, "", 0,
                       NULL);
        else
            ret = routes[i].h(r);
        return ret == -1 ? MHD_NO : MHD_YES;
    }

    ret = bad_404(r, ENOENT, url);
    return ret == -1 ? MHD_NO : MHD_YES;
}

static struct getargs args[] = {
    { "help", 'h', arg_flag, &help_flag, "Print usage message", NULL },
    { "version", '\0', arg_flag, &version_flag, "Print version", NULL },
    { NULL, 'H', arg_strings, &audiences,
        "expected token audience(s) of the service", "HOSTNAME" },
    { "allow-GET", 0, arg_negative_flag,
        &allow_GET_flag, NULL, NULL },
    { "csrf-header", 0, arg_string, &csrf_header,
        "required request header", "HEADER-NAME" },
    { "daemon", 'd', arg_flag, &daemonize, "daemonize", "daemonize" },
    { "daemon-child", 0, arg_flag, &daemon_child_fd, NULL, NULL }, /* priv */
    { "reverse-proxied", 0, arg_flag, &reverse_proxied_flag,
        "reverse proxied", "listen on 127.0.0.1 and do not use TLS" },
    { NULL, 'p', arg_integer, &port, "PORT", "port number (default: 443)" },
    { "temp-dir", 0, arg_string, &cache_dir,
        "cache directory", "DIRECTORY" },
    { "cert", 0, arg_string, &cert_file,
        "certificate file path (PEM)", "HX509-STORE" },
    { "private-key", 0, arg_string, &priv_key_file,
        "private key file path (PEM)", "HX509-STORE" },
    { "thread-per-client", 't', arg_flag, &thread_per_client_flag, "thread per-client", NULL },
    { "realm", 0, arg_string, &realm, "realm", "REALM" },
    { "hdb", 0, arg_string, &hdb, "HDB filename", "PATH" },
    { "read-only-admin-server", 0, arg_string, &kadmin_server,
        "Name of read-only kadmin server", "HOST[:PORT]" },
    { "writable-admin-server", 0, arg_string, &writable_kadmin_server,
        "Name of writable kadmin server", "HOST[:PORT]" },
    { "primary-server-uri", 0, arg_string, &primary_server_URI,
        "Name of primary httpkadmind server for HTTP redirects", "URL" },
    { "local", 'l', arg_flag, &local_hdb,
        "Use a local HDB as read-only", NULL },
    { "local-read-only", 0, arg_flag, &local_hdb_read_only,
        "Use a local HDB as read-only", NULL },
    { "read-only", 0, arg_flag, &read_only, "Allow no writes", NULL },
    { "stash-file", 0, arg_string, &stash_file,
        "Stash file for HDB", "PATH" },
    { "kadmin-client-name", 0, arg_string, &kadmin_client_name,
        "Client name for remote kadmind", "PRINCIPAL" },
    { "kadmin-client-keytab", 0, arg_string, &kadmin_client_keytab,
        "Keytab with client credentials for remote kadmind", "KEYTAB" },
    { "token-authentication-type", 'T', arg_strings, &auth_types,
        "Token authentication type(s) supported", "HTTP-AUTH-TYPE" },
    { "verbose", 'v', arg_counter, &verbose_counter, "verbose", "run verbosely" }
};

static int
usage(int e)
{
    arg_printusage(args, sizeof(args) / sizeof(args[0]), "httpkadmind",
        "\nServes an HTTP API for getting (and rotating) service "
        "principal keys, and other kadmin-like operations\n");
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
my_openlog(krb5_context context,
           const char *svc,
           krb5_log_facility **fac)
{
    char **s = NULL, **p;

    krb5_initlog(context, "httpkadmind", fac);
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

static void
get_csrf_prot_type(krb5_context context)
{
    char * const *strs = csrf_prot_type_strs.strings;
    size_t n = csrf_prot_type_strs.num_strings;
    size_t i;
    char **freeme = NULL;

    if (csrf_header == NULL)
        csrf_header = krb5_config_get_string(context, NULL, "bx509d",
                                             "csrf_protection_csrf_header",
                                             NULL);

    if (n == 0) {
        char * const *p;

        strs = freeme = krb5_config_get_strings(context, NULL, "bx509d",
                                                "csrf_protection_type", NULL);
        for (p = strs; p && p; p++)
            n++;
    }

    for (i = 0; i < n; i++) {
        if (strcmp(strs[i], "GET-with-header") == 0)
            csrf_prot_type |= CSRF_PROT_GET_WITH_HEADER;
        else if (strcmp(strs[i], "GET-with-token") == 0)
            csrf_prot_type |= CSRF_PROT_GET_WITH_TOKEN;
        else if (strcmp(strs[i], "POST-with-header") == 0)
            csrf_prot_type |= CSRF_PROT_POST_WITH_HEADER;
        else if (strcmp(strs[i], "POST-with-token") == 0)
            csrf_prot_type |= CSRF_PROT_POST_WITH_TOKEN;
    }
    free(freeme);

    /*
     * For GETs we default to no CSRF protection as our GETable resources are
     * safe and idempotent and we count on the browser not to make the
     * responses available to cross-site requests.
     *
     * But, really, we don't want browsers even making these requests since, if
     * the browsers behave correctly, then there's no point, and if they don't
     * behave correctly then that could be catastrophic.  Of course, there's no
     * guarantee that a browser won't have other catastrophic bugs, but still,
     * we should probably change this default in the future:
     *
     *  if (!(csrf_prot_type & CSRF_PROT_GET_WITH_HEADER) &&
     *      !(csrf_prot_type & CSRF_PROT_GET_WITH_TOKEN))
     *      csrf_prot_type |= <whatever-the-new-default-should-be>;
     */

    /*
     * For POSTs we default to CSRF protection with anti-CSRF tokens even
     * though out POSTable resources are safe and idempotent when POSTed and we
     * could count on the browser not to make the responses available to
     * cross-site requests.
     */
    if (!(csrf_prot_type & CSRF_PROT_POST_WITH_HEADER) &&
        !(csrf_prot_type & CSRF_PROT_POST_WITH_TOKEN))
        csrf_prot_type |= CSRF_PROT_POST_WITH_TOKEN;
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
    void *kadm_handle;
    char *priv_key_pem = NULL;
    char *cert_pem = NULL;
    char sig;
    int optidx = 0;
    int ret;

    setprogname("httpkadmind");
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

    if (writable_kadmin_server == NULL && kadmin_server == NULL &&
        !local_hdb && !local_hdb_read_only)
        errx(1, "One of --local or --local-read-only must be given, or a "
             "remote kadmind must be given");

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
        err(1, "Could not init krb5 context (config file issue?)");

    get_csrf_prot_type(context);

    if (!realm) {
        char *s;

        ret = krb5_get_default_realm(context, &s);
        if (ret)
            krb5_err(context, 1, ret, "Could not determine default realm");
        realm = s;
    }

    if ((errno = get_kadm_handle(context, realm, 0 /* want_write */,
                                 &kadm_handle)))
        err(1, "Could not connect to HDB");
    kadm5_destroy(kadm_handle);
    kadm_handle = NULL;

    my_openlog(context, "httpkadmind", &logfac);
    load_plugins(context);

    if (cache_dir == NULL) {
        char *s = NULL;

        if (asprintf(&s, "%s/httpkadmind-XXXXXX",
                     getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp") == -1 ||
            s == NULL ||
            (cache_dir = mkdtemp(s)) == NULL)
            err(1, "could not create temporary cache directory");
        if (verbose_counter)
            fprintf(stderr, "Note: using %s as cache directory\n", cache_dir);
        atexit(rm_cache_dir);
        setenv("TMPDIR", cache_dir, 1);
    }

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
         *
         * XXX We should be able to re-read krb5.conf and such on SIGHUP.
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
                                   /*
                                    * This is a connection access callback.  We
                                    * don't use it.
                                    */
                                   NULL, NULL,
                                   /* This is our request handler */
                                   route, (char *)NULL,
                                   MHD_OPTION_SOCK_ADDR, &sin,
                                   MHD_OPTION_CONNECTION_LIMIT, (unsigned int)200,
                                   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)10,
                                   /* This is our request cleanup handler */
                                   MHD_OPTION_NOTIFY_COMPLETED, cleanup_req, NULL,
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
                                   MHD_OPTION_NOTIFY_COMPLETED, cleanup_req, NULL,
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
                                   MHD_OPTION_NOTIFY_COMPLETED, cleanup_req, NULL,
                                   MHD_OPTION_END);
    }
    if (current == NULL)
        err(1, "Could not start kadmin REST service");

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
