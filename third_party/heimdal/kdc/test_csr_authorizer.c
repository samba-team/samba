/*
 * Copyright (c) 2022 Kungliga Tekniska Högskolan
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
#include "kdc_locl.h"
#include <heim-ipc.h>

/*
 * This program implements two things:
 *
 *  - a utility for testing the `kdc_authorize_csr()' function and the plugins
 *    that uses,
 *
 * and
 *
 *  - a server for the IPC authorizer.
 *
 * For the latter, requested certificate SANs and EKUs are authorized by
 * checking for existence of files of the form:
 *
 *      /<path>/<princ>/<ext>-<value>
 *
 * where <path> is given as an option.
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

static int help_flag;
static int version_flag;
static int daemon_flag;
static int daemon_child_flag = -1;
static int ignore_flag = 0;
static int server_flag = 0;
static const char *app_string = "kdc";
static const char *socket_dir;
static const char *authz_dir;

struct getargs args[] = {
    {   "help",     'h',    arg_flag,   &help_flag,
        "Print usage message", NULL },
    {   "version",  'v',    arg_flag,   &version_flag,
        "Print version", NULL },
    {   "app",      'a',    arg_string, &app_string,
        "App to test (kdc or bx509); default: kdc", "APPNAME" },
    {   "socket-dir", 'S',  arg_string, &socket_dir,
        "IPC socket directory", "DIR" },
    {   "authorization-dir", 'A',  arg_string, &authz_dir,
        "authorization directory", "DIR" },
    {   "server",   '\0',    arg_flag, &server_flag,
        "Server mode", NULL },
    {   "ignore",   'I',    arg_flag, &ignore_flag,
        "ignore requests", NULL },
    {   "daemon",   'd',    arg_flag, &daemon_flag,
        "daemonize", NULL },
    {   "daemon-child",   '\0',    arg_flag, &daemon_child_flag,
        "internal-use-only option", NULL },
};
size_t num_args = sizeof(args) / sizeof(args[0]);

static int
usage(int e)
{
    arg_printusage(args, num_args, NULL, "PATH-TO-DER-CSR PRINCIPAL");
    fprintf(stderr,
            "\tExercise CSR authorization plugins for a given CSR for a\n"
            "\tgiven principal.\n\n"
            "\tServer-mode (--server) looks for files in the \n"
            "\t--authorization-dir DIR directory named:\n"
            "\n"
            "\t\teku=OID\n"
            "\t\tsan_pkinit=PRINCIPAL\n"
            "\t\tsan_ms_upn=PRINCIPAL\n"
            "\t\tsan_dnsname=DOMAINNAME\n"
            "\t\tsan_xmpp=JABBER-ID\n"
            "\t\tsan_email=EMAIL\n"
            "\n"
            "\tClient-mode positional arguments are:\n\n"
            "\t\tPATH-TO-DER-CSR PRETEND-CLIENT-PRINCIPAL [...]\n\n"
            "\twhere {...} are requested features that must be granted\n"
            "\tif the request is only partially authorized.\n\n"
            "\tClient example:\n\t\t%s PKCS10:/tmp/csr.der foo@TEST.H5L.SE\n",
            getprogname());
    exit(e);
    return e;
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

    _krb5_load_plugins(context, "kdc", (const char **)dirs);

#ifndef _WIN32
    krb5_config_free_strings(cfdirs);
#endif
}

static char *string_encode(const char *);
static int stat_authz(const char *, const char *);

static krb5_error_code
authorize(const char *subject, const char *thing)
{
    krb5_error_code ret;
    char *s = NULL;

    s = string_encode(subject);
    if (s == NULL)
        return ENOMEM;

    ret = stat_authz(s, thing);
    if (ret == ENOENT)
        ret = stat_authz(s, "all");
    if (ret == ENOENT)
        ret = EACCES;
    free(s);
    return ret;
}

static void
service(void *ctx,
        const heim_octet_string *req,
        const heim_icred cred,
        heim_ipc_complete complete_cb,
        heim_sipc_call complete_cb_data)
{
    krb5_error_code ret = 0;
    struct rk_strpool *result = NULL;
    krb5_data rep;
    const char *subject;
    char *cmd;
    char *next = NULL;
    char *res = NULL;
    char *tok;
    char *s;
    int none_granted = 1;
    int all_granted = 1;
    int first = 1;

    /*
     * A krb5_context and log facility for logging would be nice, but this is
     * all just for testing.
     */

    (void)ctx;

    cmd = strndup(req->data, req->length);
    if (cmd == NULL)
        errx(1, "Out of memory");

    if (strncmp(cmd, "check ", sizeof("check ") - 1) != 0) {
        rep.data = "Invalid request command (must be \"check ...\")";
        rep.length = sizeof("Invalid request command (must be \"check ...\")") - 1;
        (*complete_cb)(complete_cb_data, EINVAL, &rep);
        free(cmd);
        return;
    }

    s = cmd + sizeof("check ") - 1;
    subject = strtok_r(s, " ", &next);
    s = NULL;

    while ((tok = strtok_r(s, " ", &next))) {
        int ret2;

        ret2 = authorize(subject, tok);
        result = rk_strpoolprintf(result, "%s%s:%s",
                                  first ? "" : ",",
                                  tok,
                                  ret2 == 0 ? "granted" : "denied");
        if (ret2 == 0)
            none_granted = 0;
        else
            all_granted = 0;

        if (ret2 != 0 && ret == 0)
            ret = ret2;

        first = 0;
    }
    free(cmd);

    if (ret == 0 && all_granted) {
        rk_strpoolfree(result);

        rep.data = "granted";
        rep.length = sizeof("granted") - 1;
        (*complete_cb)(complete_cb_data, 0, &rep);
        return;
    }

    if (none_granted && ignore_flag) {
        rk_strpoolfree(result);

        rep.data = "ignore";
        rep.length = sizeof("ignore") - 1;
        (*complete_cb)(complete_cb_data, KRB5_PLUGIN_NO_HANDLE, &rep);
        return;
    }

    s = rk_strpoolcollect(result); /* frees `result' */
    if (s == NULL) {
        rep.data = "denied out-of-memory";
        rep.length = sizeof("denied out-of-memory") - 1;
        (*complete_cb)(complete_cb_data, KRB5_PLUGIN_NO_HANDLE, &rep);
        return;
    }

    if (asprintf(&res, "denied %s", s) == -1)
        errx(1, "Out of memory");
    if (res == NULL)
        errx(1, "Out of memory");

    rep.data = res;
    rep.length = strlen(res);

    (*complete_cb)(complete_cb_data, ret, &rep);
    free(res);
    free(s);
}

static char *
make_feature_argument(const char *kind,
                      hx509_san_type san_type,
                      const char *value)
{
    const char *san_type_str = NULL;
    char *s = NULL;

    if (strcmp(kind, "san") != 0) {
        if (asprintf(&s, "%s=%s", kind, value) == -1 || s == NULL)
            errx(1, "Out of memory");
        return s;
    }

    switch (san_type) {
    case HX509_SAN_TYPE_EMAIL:
        san_type_str = "email";
        break;
    case HX509_SAN_TYPE_DNSNAME:
        san_type_str = "dnsname";
        break;
    case HX509_SAN_TYPE_DN:
        san_type_str = "dn";
        break;
    case HX509_SAN_TYPE_REGISTERED_ID:
        san_type_str = "registered_id";
        break;
    case HX509_SAN_TYPE_XMPP:
        san_type_str = "xmpp";
        break;
    case HX509_SAN_TYPE_PKINIT:
    case HX509_SAN_TYPE_MS_UPN:
        san_type_str = "pkinit";
        break;
    case HX509_SAN_TYPE_DNSSRV:
        san_type_str = "dnssrv";
        break;
    default:
        warnx("SAN type not supported");
        return "";
    }

    if (asprintf(&s, "san_%s=%s", san_type_str, value) == -1 || s == NULL)
        errx(1, "Out of memory");
    return s;
}

int
main(int argc, char **argv)
{
    krb5_log_facility *logf;
    krb5_error_code ret;
    krb5_context context;
    hx509_request csr;
    krb5_principal princ = NULL;
    const char *argv0 = argv[0];
    int optidx = 0;

    setprogname(argv[0]);
    if (getarg(args, num_args, argc, argv, &optidx))
        return usage(1);
    if (help_flag)
        return usage(0);
    if (version_flag) {
        print_version(argv[0]);
        return 0;
    }

    if ((errno = krb5_init_context(&context)))
        err(1, "Could not initialize krb5_context");
    if ((ret = krb5_initlog(context, argv0, &logf)) ||
        (ret = krb5_addlog_dest(context, logf, "0-5/STDERR")))
        krb5_err(context, 1, ret, "Could not set up logging to stderr");
    load_plugins(context);

    if (server_flag && daemon_flag)
        daemon_child_flag = roken_detach_prep(argc, argv, "--daemon-child");

    argc -= optidx;
    argv += optidx;

    if (socket_dir)
        setenv("HEIM_IPC_DIR", socket_dir, 1);

    if (server_flag) {
        const char *svc;
        heim_sipc un;

        rk_pidfile(NULL);

        svc = krb5_config_get_string(context, NULL,
                                     app_string ? app_string : "kdc",
                                     "ipc_csr_authorizer", "service", NULL);
        if (svc == NULL)
            svc = "org.h5l.csr_authorizer";

        /* `service' is our request handler; `argv' is its callback data */
        ret = heim_sipc_service_unix(svc, service, NULL, &un);
        if (ret)
            krb5_err(context, 1, ret,
                     "Could not setup service on Unix domain socket "
                     "%s/.heim_%s-socket", socket_dir, svc);

        roken_detach_finish(NULL, daemon_child_flag);

        /* Enter the IPC event loop */
        heim_ipc_main();
        return 0;
    }

    /* Client mode */
    if (argc < 2)
        usage(1);

    /* Parse the given CSR */
    if ((ret = hx509_request_parse(context->hx509ctx, argv[0], &csr)))
        krb5_err(context, 1, ret, "Could not parse PKCS#10 CSR from %s", argv[0]);

    /*
     * Parse the client principal that we'll pretend is an authenticated client
     * principal.
     */
    if ((ret = krb5_parse_name(context, argv[1], &princ)))
        krb5_err(context, 1, ret, "Could not parse principal %s", argv[1]);

    /* Call the authorizer */
    ret = kdc_authorize_csr(context, app_string, csr, princ);

    if (ret) {
        unsigned n = hx509_request_count_unauthorized(csr);
        size_t i, k;
        int ret2 = 0;
        int good = -1;

        /*
         * Check partial approval of SANs.
         *
         * Iterate over the SANs in the request, and for each check if a) it
         * was granted, b) it's on the remainder of our argv[].
         */
        for (i = 0; ret2 == 0; i++) {
            hx509_san_type san_type;
            char *feature = NULL;
            char *san = NULL;
            int granted;

            ret2 = hx509_request_get_san(csr, i, &san_type, &san);
            if (ret2)
                break;

            feature = make_feature_argument("san", san_type, san);

            granted = hx509_request_san_authorized_p(csr, i);
            for (k = 2; k < argc; k++) {
                if (strcmp(feature, argv[k]) != 0)
                    continue;

                /* The SAN is on our command line */
                if (granted && good == -1)
                    good = 1;
                else if (!granted)
                    good = 0;
                break;
            }

            hx509_xfree(san);
        }

        /* Check partial approval of EKUs */
        for (i = 0; ret2 == 0; i++) {
            char *feature = NULL;
            char *eku = NULL;
            int granted;

            ret2 = hx509_request_get_eku(csr, i, &eku);
            if (ret2)
                break;

            feature = make_feature_argument("eku", 0, eku);

            granted = hx509_request_eku_authorized_p(csr, i);
            for (k = 2; k < argc; k++) {
                if (strcmp(feature, argv[k]) != 0)
                    continue;

                /* The SAN is on our command line */
                if (granted && good == -1)
                    good = 1;
                else if (!granted)
                    good = 0;
                break;
            }

            hx509_xfree(eku);
        }

        if (good != 1) {
            krb5_free_principal(context, princ);
            _krb5_unload_plugins(context, "kdc");
            hx509_request_free(&csr);
            krb5_err(context, 1, ret,
                     "Authorization failed with %u rejected features", n);
        }
    }

    printf("Authorized!\n");
    krb5_free_principal(context, princ);
    _krb5_unload_plugins(context, "kdc");
    krb5_free_context(context);
    hx509_request_free(&csr);
    return 0;
}

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
            if (!isalnum((unsigned char)c))
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

static int
stat_authz(const char *subject,
           const char *thing)
{
    struct stat st;
    char *p = NULL;
    int ret;

    if (authz_dir == NULL)
        return KRB5_PLUGIN_NO_HANDLE;
    if (thing)
        ret = asprintf(&p, "%s/%s/%s", authz_dir, subject, thing);
    else
        ret = asprintf(&p, "%s/%s", authz_dir, subject);
    if (ret == -1 || p == NULL)
        return ENOMEM;
    ret = stat(p, &st);
    free(p);
    return ret == 0 ? 0 : errno;
}
