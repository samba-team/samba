/*
 * Copyright (c) 2015 Cryptonector LLC.
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
 * 3. The name Cryptonector LLC may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <roken.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <gssapi.h>
#include <err.h>
#include <getarg.h>

static void
print_gss_err(OM_uint32 stat, int status_type, gss_OID mech)
{
    gss_buffer_desc str;
    OM_uint32 maj;
    OM_uint32 min;
    OM_uint32 msg_ctx = 0;
    int first = 1;

    do {
        maj = gss_display_status(&min, stat, status_type, mech, &msg_ctx,
                                 &str);
        if (maj != GSS_S_COMPLETE) {
            fprintf(stderr, "Error displaying GSS %s error (%lu): %lu, %lu",
                    status_type == GSS_C_GSS_CODE ? "major" : "minor",
                    (unsigned long)stat, (unsigned long)maj,
                    (unsigned long)min);
            return;
        }
        if (first) {
            fprintf(stderr, "GSS %s error: %.*s\n",
                    status_type == GSS_C_GSS_CODE ? "major" : "minor",
                    (int)str.length, (char *)str.value);
            first = 0;
        } else {
            fprintf(stderr, "\t%.*s\n", (int)str.length, (char *)str.value);
        }
        gss_release_buffer(&min, &str);
    } while (msg_ctx != 0);
}

static void
print_gss_errs(OM_uint32 major, OM_uint32 minor, gss_OID mech)
{
    print_gss_err(major, GSS_C_GSS_CODE, GSS_C_NO_OID);
    print_gss_err(major, GSS_C_MECH_CODE, mech);
}

static void
gss_err(int exitval, OM_uint32 major, OM_uint32 minor, gss_OID mech,
        const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vwarnx(fmt, args);
    va_end(args);
    print_gss_errs(major, minor, mech);
    exit(exitval);
}

static int version_flag         = 0;
static int help_flag            = 0;
static int env_flag             = 0;
static int def_flag             = 0;
static int overwrite_flag       = 0;

static struct getargs args[] = {
    {"version", 0,      arg_flag,       &version_flag, "print version", NULL },
    {"help",    0,      arg_flag,       &help_flag,  NULL, NULL },
    {"env",     'e',    arg_flag,       &env_flag,
     "output env settings", NULL },
    {"default", 0,      arg_flag,       &def_flag,
     "switch credential store default principal", NULL },
    {"overwrite", 0,    arg_flag,       &overwrite_flag,
     "overwrite matching credential", NULL },
};

static void
usage(int ret)
{
    arg_printusage(args, sizeof(args)/sizeof(*args),
                   NULL, "from_ccache to_ccache");
    exit(ret);
}

int
main(int argc, char **argv)
{
    OM_uint32 major, minor;
    gss_cred_id_t from_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t to_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_key_value_element_desc from_elements, to_elements;
    gss_key_value_set_desc from, to;
    gss_buffer_set_t env = GSS_C_NO_BUFFER_SET;
    OM_uint32 store_flags = 0;
    int optidx = 0;

    setprogname(argv[0]);
    if (getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
        usage(1);

    if (help_flag)
        usage (0);

    if (version_flag){
        print_version(NULL);
        exit(0);
    }

    if (def_flag)
        store_flags |= GSS_C_STORE_CRED_DEFAULT;
    if (overwrite_flag)
        store_flags |= GSS_C_STORE_CRED_OVERWRITE;

    argc -= optidx;
    argv += optidx;

    if (argc < 2)
        errx(1, "required arguments missing");
    if (argc > 2)
        errx(1, "too many arguments");

    from_elements.key = "ccache";
    from_elements.value = argv[0];
    from.count = 1;
    from.elements = &from_elements;

    to_elements.key = "ccache";
    to_elements.value = argv[1];
    to.count = 1;
    to.elements = &to_elements;

    major = gss_add_cred_from(&minor, GSS_C_NO_CREDENTIAL, GSS_C_NO_NAME,
			      GSS_KRB5_MECHANISM, GSS_C_INITIATE,
			      GSS_C_INDEFINITE, GSS_C_INDEFINITE,
			      &from, &from_cred, NULL, NULL, NULL);
    if (major != GSS_S_COMPLETE)
        gss_err(1, major, minor, GSS_KRB5_MECHANISM,
                "failed to acquire creds from %s", argv[0]);

    major = gss_store_cred_into2(&minor, from_cred, GSS_C_INITIATE,
                                 GSS_KRB5_MECHANISM, store_flags, &to, NULL,
                                 NULL, env_flag ? &env : NULL);
    if (major != GSS_S_COMPLETE)
        gss_err(1, major, minor, GSS_KRB5_MECHANISM,
                "failed to store creds into %s", argv[1]);

    if (env_flag) {
        size_t i;
        int got_krb5ccname = 0;

        if (env == GSS_C_NO_BUFFER_SET)
            warnx("No environment settings");

        for (i = 0; env != GSS_C_NO_BUFFER_SET && i < env->count; i++) {
            got_krb5ccname = got_krb5ccname ||
                (env->elements[i].length > sizeof("KRB5CCNAME=") &&
                 strncmp((const char *)env->elements[i].value, "KRB5CCNAME=",
                         sizeof("KRB5CCNAME=") - 1) == 0);
            printf("%.*s\n", (int)env->elements[i].length,
                   (const char *)env->elements[i].value);
        }
        (void) gss_release_buffer_set(&minor, &env);

        if (!got_krb5ccname)
            errx(1, "KRB5CCNAME environment variable not set by "
                 "gss_store_cred_into2()");
    }

    (void) gss_release_cred(&minor, &from_cred);
    (void) gss_release_cred(&minor, &to_cred);

    major = gss_add_cred(&minor, GSS_C_NO_CREDENTIAL, GSS_C_NO_NAME,
                         GSS_KRB5_MECHANISM, GSS_C_INITIATE, GSS_C_INDEFINITE,
                         GSS_C_INDEFINITE, &cred, NULL, NULL, NULL);
    if (major != GSS_S_COMPLETE)
        gss_err(1, major, minor, GSS_KRB5_MECHANISM,
                "failed to acquire creds from %s", argv[1]);
    (void) gss_release_cred(&minor, &cred);

    return 0;
}
