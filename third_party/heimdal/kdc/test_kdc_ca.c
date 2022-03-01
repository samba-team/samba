#include "kdc_locl.h"

static int authorized_flag;
static int help_flag;
static char *lifetime_string;
static const char *app_string = "kdc";
static int version_flag;

struct getargs args[] = {
    {   "authorized",   'A',    arg_flag,   &authorized_flag,
        "Assume CSR is authorized", NULL },
    {   "lifetime",     'l',    arg_string, &lifetime_string,
        "Certificate lifetime desired", "TIME" },
    {   "help",         'h',    arg_flag,   &help_flag,
        "Print usage message", NULL },
    {   "app",          'a',    arg_string, &app_string,
        "Application name (kdc or bx509); default: kdc", "APPNAME" },
    {   "version",      'v',    arg_flag,   &version_flag,
        "Print version", NULL }
};
size_t num_args = sizeof(args) / sizeof(args[0]);

static int
usage(int e)
{
    arg_printusage(args, num_args, NULL,
                   "PRINC PKCS10:/path/to/der/CSR [HX509-STORE]");
    fprintf(stderr,
            "\n\tTest kx509/bx509 online CA issuer functionality.\n"
            "\n\tIf --authorized / -A not given, then authorizer plugins\n"
            "\twill be invoked.\n"
            "\n\tUse --app kdc to test the kx509 configuration.\n"
            "\tUse --app bx509 to test the bx509 configuration.\n\n\t"
            "Example: %s foo@TEST.H5L.SE PKCS10:/tmp/csr PEM-FILE:/tmp/cert\n",
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

int
main(int argc, char **argv)
{
    krb5_log_facility *logf = NULL;
    krb5_error_code ret;
    krb5_principal p = NULL;
    krb5_context context;
    krb5_times t;
    hx509_request req = NULL;
    hx509_certs store = NULL;
    hx509_certs certs = NULL;
    const char *argv0 = argv[0];
    const char *out = "MEMORY:junk-it";
    time_t req_life = 0;
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

    argc -= optidx;
    argv += optidx;

    if (argc < 3 || argc > 4)
        usage(1);

    if ((errno = krb5_init_context(&context)))
        err(1, "Could not initialize krb5_context");
    if ((ret = krb5_initlog(context, argv0, &logf)) ||
        (ret = krb5_addlog_dest(context, logf, "0-5/STDERR")))
        krb5_err(context, 1, ret, "Could not set up logging to stderr");
    load_plugins(context);
    if ((ret = krb5_parse_name(context, argv[0], &p)))
        krb5_err(context, 1, ret, "Could not parse principal %s", argv[0]);
    if ((ret = hx509_request_parse(context->hx509ctx, argv[1], &req)))
        krb5_err(context, 1, ret, "Could not parse PKCS#10 CSR from %s", argv[1]);

    if (authorized_flag) {
        KeyUsage ku = int2KeyUsage(0);
        size_t i;
        char *s;

        /* Mark all the things authorized */
        ku.digitalSignature = 1;
        hx509_request_authorize_ku(req, ku);

        for (i = 0; ret == 0; i++) {
            ret = hx509_request_get_eku(req, i, &s);
            free(s); s = NULL;
            if (ret == 0)
                hx509_request_authorize_eku(req, i);
        }
        if (ret == HX509_NO_ITEM)
            ret = 0;

        for (i = 0; ret == 0; i++) {
            hx509_san_type san_type;

            ret = hx509_request_get_san(req, i, &san_type, &s);
            free(s); s = NULL;
            if (ret == 0)
                hx509_request_authorize_san(req, i);
        }
        if (ret && ret != HX509_NO_ITEM)
            krb5_err(context, 1, ret,
                     "Failed to mark requested extensions authorized");
    } else if ((ret = kdc_authorize_csr(context, app_string, req, p))) {
        krb5_err(context, 1, ret,
                 "Requested certificate extensions rejected by policy");
    }

    memset(&t, 0, sizeof(t));
    t.starttime = time(NULL);
    t.endtime = t.starttime + 3600;
    req_life = lifetime_string ? parse_time(lifetime_string, "day") : 0;
    if ((ret = kdc_issue_certificate(context, app_string, logf, req, p, &t,
                                     req_life, 1, &certs)))
        krb5_err(context, 1, ret, "Certificate issuance failed");

    if (argv[2])
        out = argv[2];

    if ((ret = hx509_certs_init(context->hx509ctx, out, HX509_CERTS_CREATE,
                                NULL, &store)) ||
        (ret = hx509_certs_merge(context->hx509ctx, store, certs)) ||
        (ret = hx509_certs_store(context->hx509ctx, store, 0, NULL)))
        /*
         * If the store is a MEMORY store, say, we're really not being asked to
         * store -- we're just testing the online CA functionality without
         * wanting to inspect the result.
         */
        if (ret != HX509_UNSUPPORTED_OPERATION)
            krb5_err(context, 1, ret,
                     "Could not store certificate and chain in %s", out);
    _krb5_unload_plugins(context, "kdc");
    krb5_free_principal(context, p);
    krb5_free_context(context);
    hx509_request_free(&req);
    hx509_certs_free(&store);
    hx509_certs_free(&certs);
    return 0;
}
