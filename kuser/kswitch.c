/*
 * Copyright (c) 2008 Kungliga Tekniska Högskolan
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

#include "kuser_locl.h"

RCSID("$Id$");

/*
 *
 */

static int version_flag		= 0;
static int help_flag		= 0;
static char *cache;
static char *principal;
static char *type;

static struct getargs args[] = {
    { "type",			't', arg_string, &type,
      "type of credential cache", "type" },
    { "cache",			'c', arg_string, &cache,
      "name of credential cache", "cache" },
    { "principal",		'p', arg_string, &principal,
      "name of principal", "principal" },
    { "version", 		0,   arg_flag, &version_flag, 
      "print version", NULL },
    { "help",			0,   arg_flag, &help_flag, NULL, NULL}
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args), NULL, "");
    exit (ret);
}

int
main (int argc, char **argv)
{
    const krb5_cc_ops *ops;
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache id;
    int optidx = 0;
    char *str;

    setprogname (argv[0]);

    ret = krb5_init_context (&context);
    if (ret == KRB5_CONFIG_BADFORMAT)
	errx (1, "krb5_init_context failed to parse configuration file");
    else if (ret)
	errx(1, "krb5_init_context failed: %d", ret);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);
    
    if (help_flag)
	usage (0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    argc -= optidx;
    argv += optidx;

    if (argc != 0)
	usage (1);

    if (cache == NULL)
	krb5_errx(context, 1, "No cache name given");

    ops = krb5_cc_get_prefix_ops(context, type);
    if (ops == NULL)
	krb5_err (context, 1, 0, "krb5_cc_get_prefix_ops");

    asprintf(&str, "%s:%s", ops->prefix, cache);
    if (str == NULL)
	krb5_errx(context, 1, "out of memory");

    ret = krb5_cc_resolve(context, str, &id);
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_resolve: %s", str);

    free(str);

    ret = krb5_cc_switch(context, id);
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_switch");

    krb5_cc_close(context, id);

    return 0;
}
