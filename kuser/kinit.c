/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
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

int forwardable;
int renewable;
int version_flag = 0;
int help_flag = 0;
char *lifetime = NULL;
char *server = NULL;

struct getargs args[] = {
    { "forwardable",		'f', arg_flag, &forwardable, 
      "get forwardable tickets", NULL },
    { "renewable",		'r', arg_flag, &renewable, 
      "get renewable tickets", NULL },
    { "lifetime",		'l', arg_string, &lifetime,
      "lifetime of tickets", "seconds"},
    { "server", 		'S', arg_string, &server,
      "server to get ticket for", "principal" },
    { "version", 		0,   arg_flag, &version_flag, 
      NULL, NULL },
    { "help",			0,   arg_flag, &help_flag, 
      NULL, NULL}
};

static void
usage (int ret)
{
    arg_printusage (args,
		    sizeof(args)/sizeof(*args),
		    "[principal]");
    exit (ret);
}

int
main (int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_ccache  ccache;
    krb5_principal principal;
    krb5_creds cred;
    int optind = 0;
    krb5_get_init_creds_opt opt;

    set_progname (argv[0]);
    memset(&cred, 0, sizeof(cred));
    
    ret = krb5_init_context (&context);
    if (ret)
	errx(1, "krb5_init_context failed: %u", ret);
  
    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optind))
	usage(1);
    
    if (help_flag)
	usage (0);

    if(version_flag) {
	print_version(NULL);
	exit(0);
    }

    krb5_get_init_creds_opt_init (&opt);
    
    if (forwardable)
	krb5_get_init_creds_opt_set_forwardable (&opt, forwardable);
    if (renewable)
	krb5_get_init_creds_opt_set_renew_life (&opt, 1 << 30);

    if (lifetime) {
	int tmp = parse_time (lifetime, NULL);
	if (tmp < 0)
	    errx (1, "unparsable time: %s", lifetime);

	krb5_get_init_creds_opt_set_tkt_life (&opt, tmp);
    }

    argc -= optind;
    argv += optind;

    if (argc > 1)
	usage (1);

    ret = krb5_cc_default (context, &ccache);
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_default");

    if (argv[0]) {
	ret = krb5_parse_name (context, argv[0], &principal);
	if (ret)
	    krb5_err (context, 1, ret, "krb5_parse_name");
    } else
	principal = NULL;

    ret = krb5_get_init_creds_password (context,
					&cred,
					principal,
					NULL,
					krb5_prompter_posix,
					NULL,
					0,
					server,
					&opt);
    switch(ret){
    case 0:
	break;
    case KRB5KDC_ERR_NONE: /* XXX hack in krb5_get_init_creds_password */
	exit(1);
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
    case KRB5KRB_AP_ERR_MODIFIED:
	krb5_errx(context, 1, "Password incorrect");
	break;
    default:
	krb5_err(context, 1, ret, "krb5_get_init_creds");
    }

    ret = krb5_cc_initialize (context, ccache, cred.client);
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_initialize");
    
    ret = krb5_cc_store_cred (context, ccache, &cred);
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_store_cred");
    krb5_free_creds_contents (context, &cred);
    krb5_cc_close (context, ccache);
    krb5_free_context (context);
    return 0;
}
