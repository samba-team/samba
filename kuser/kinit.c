/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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
#include <getarg.h>

int forwardable;
int preauth = 1;
int renewable;
int version_flag = 0;
int help_flag = 0;

struct getargs args[] = {
    { "forwardable",		'f', arg_flag, &forwardable, 
      "get forwardable tickets", NULL },
    { "preauthentication",	'p', arg_negative_flag, &preauth, 
      "disable preauthentication", NULL },
    { "renewable",		'r', arg_flag, &renewable, 
      "get renewable tickets", NULL },
    { "version", 		0,   arg_flag, &version_flag, 
      "print version", NULL },
    { "help",			0,   arg_flag, &help_flag, 
      NULL, NULL}
};

static void
usage (void)
{
    arg_printusage (args,
		    sizeof(args)/sizeof(*args),
		    "[principal]");
    exit (1);
}

int
main (int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_ccache  ccache;
    krb5_principal principal;
    krb5_principal server;
    krb5_creds cred;
    krb5_preauthtype pre_auth_types[] = {KRB5_PADATA_ENC_TIMESTAMP};
    int c;
    char *realm;
    char pwbuf[128];
    
    union {
	krb5_flags i;
	KDCOptions f;
    }options;
    int optind = 0;

    set_progname (argv[0]);
    memset(&cred, 0, sizeof(cred));
    options.i = 0;
    
    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optind))
	usage();
    
    if (help_flag)
	usage ();

    if(version_flag){
	printf("%s (%s-%s)\n", __progname, PACKAGE, VERSION);
	exit(0);
    }

    options.f.forwardable = forwardable;

    if(renewable){
	options.f.renewable = 1;
	cred.times.renew_till = 1 << 30;
    }
    argc -= optind;
    argv += optind;

    ret = krb5_init_context (&context);
    if (ret)
	errx (1, "krb5_init_context: %s", krb5_get_err_text(context, ret));
  
    ret = krb5_cc_default (context, &ccache);
    if (ret)
	errx (1, "krb5_cc_default: %s", krb5_get_err_text(context, ret));
  
    ret = krb5_get_default_realm (context, &realm);
    if (ret)
	errx (1, "krb5_get_default_realm: %s",
	      krb5_get_err_text(context, ret));

    if(argv[0]){
	ret = krb5_parse_name (context, argv[0], &principal);
	if (ret)
	    errx (1, "krb5_parse_name: %s", krb5_get_err_text(context, ret));
    }else{
	struct passwd *pw;

	pw = getpwuid(getuid());
	ret = krb5_build_principal(context, &principal,
				   strlen(realm), realm,
				   pw->pw_name, NULL);
	if (ret)
	    errx (1, "krb5_build_principal: %s",
		  krb5_get_err_text(context, ret));
    }
    free(realm);

    ret = krb5_cc_initialize (context, ccache, principal);
    if (ret)
	errx (1, "krb5_cc_initialize: %s",
	      krb5_get_err_text(context, ret));

    cred.client = principal;
    cred.times.endtime = 0;

    ret = krb5_build_principal_ext (context,
				    &server,
				    strlen(principal->realm),
				    principal->realm,
				    strlen("krbtgt"),
				    "krbtgt",
				    strlen(principal->realm),
				    principal->realm,
				    NULL);
    if (ret)
	errx (1, "krb5_build_principal_ext: %s",
	      krb5_get_err_text(context, ret));

    server->name.name_type = KRB5_NT_SRV_INST;

    cred.client = principal;
    cred.server = server;
    cred.times.endtime = 0;

    
    {
	char *p;
	char *prompt;
	krb5_unparse_name(context, principal, &p);
	asprintf(&prompt, "%s's Password: ", p);
	free(p);
	des_read_pw_string(pwbuf, sizeof(pwbuf), prompt, 0);
	free(prompt);
    }


    ret = krb5_get_in_tkt_with_password (context,
					 options.i,
					 NULL,
					 NULL,
					 preauth ? pre_auth_types : NULL,
					 pwbuf,
					 ccache,
					 &cred,
					 NULL);
    memset(pwbuf, 0, sizeof(pwbuf));
    if (ret)
	errx (1, "krb5_get_in_tkt_with_password: %s",
	      krb5_get_err_text(context, ret));

    krb5_free_principal (context, principal);
    krb5_free_principal (context, server);
    krb5_free_ccache (context, ccache);
    krb5_free_context (context);
    return 0;
}
