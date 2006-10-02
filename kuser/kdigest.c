/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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
#include <kdigest-commands.h>
#include <hex.h>
#include "crypto-headers.h"

static int version_flag = 0;
static int help_flag	= 0;
static char *ccache_string;
static krb5_ccache id;

static struct getargs args[] = {
    {"ccache",	0,	arg_string,	&ccache_string, "credential cache", NULL },
    {"version",	0,	arg_flag,	&version_flag, "print version", NULL },
    {"help",	0,	arg_flag,	&help_flag,  NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args),
		    NULL, "");
    exit (ret);
}

static krb5_context context;

int
server_init(struct server_init_options *opt, int argc, char ** argv)
{
    krb5_error_code ret;
    krb5_digest digest;

    if (strcasecmp(opt->type_string, "CHAP") != 0)
	errx(1, "type not CHAP");

    
    ret = krb5_digest_alloc(context, &digest);
    if (ret)
	krb5_err(context, 1, ret, "digest_alloc");

    ret = krb5_digest_set_type(context, digest, opt->type_string);
    if (ret)
	krb5_err(context, 1, ret, "krb5_digest_set_type");

    if (opt->cb_type_string && opt->cb_value_string) {
	ret = krb5_digest_set_server_cb(context, digest, 
					opt->cb_type_string,
					opt->cb_value_string);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_digest_set_server_cb");
    }
    ret = krb5_digest_init_request(context,
				   digest,
				   opt->kerberos_realm_string,
				   id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_digest_init_request");

    printf("type=%s\n", opt->type_string);
    printf("server-nonce=%s\n", 
	   krb5_digest_get_server_nonce(context, digest));
    {
	const char *s = krb5_digest_get_identifier(context, digest);
	if (s)
	    printf("identifier=%s\n", s);
    }
    printf("opaque=%s\n", krb5_digest_get_opaque(context, digest));

    return 0;
}

int
server_request(struct server_request_options *opt, int argc, char **argv)
{
    krb5_error_code ret;
    krb5_digest digest;
    const char *h;

    if (opt->server_nonce_string == NULL)
	errx(1, "server nonce missing");
    if (opt->type_string == NULL)
	errx(1, "type missing");
    if (opt->opaque_string == NULL)
	errx(1, "opaque missing");

    ret = krb5_digest_alloc(context, &digest);
    if (ret)
	krb5_err(context, 1, ret, "digest_alloc");

    if (strcasecmp(opt->type_string, "CHAP") == 0) {
	if (opt->server_identifier_string == NULL)
	    errx(1, "server identifier missing");

	ret = krb5_digest_set_identifier(context, digest, 
					 opt->server_identifier_string);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_digest_set_type");
    }

    ret = krb5_digest_set_type(context, digest, opt->type_string);
    if (ret)
	krb5_err(context, 1, ret, "krb5_digest_set_type");

    ret = krb5_digest_set_username(context, digest, opt->username_string);
    if (ret)
	krb5_err(context, 1, ret, "krb5_digest_set_username");

    ret = krb5_digest_set_server_nonce(context, digest, 
				       opt->server_nonce_string);
    if (ret)
	krb5_err(context, 1, ret, "krb5_digest_set_server_nonce");

    ret = krb5_digest_set_opaque(context, digest, opt->opaque_string);
    if (ret)
	krb5_err(context, 1, ret, "krb5_digest_set_opaque");

    ret = krb5_digest_request(context, digest,
			      opt->kerberos_realm_string, id);
    if (ret)
	krb5_err(context, 1, ret, "krb5_digest_request");

    h = krb5_digest_get_responseData(context, digest);

    printf("responseData=%s\n", h);
    printf("tickets=no\n");

    return 0;
}

int
client_request(struct client_request_options *opt, int argc, char **argv)
{
    char *server_nonce, server_identifier;
    ssize_t size;
    MD5_CTX ctx;
    char md[16], *h;

    if (opt->server_nonce_string == NULL)
	errx(1, "server nonce missing");
    if (opt->server_identifier_string == NULL)
	errx(1, "server identifier missing");
    if (opt->password_string == NULL)
	errx(1, "password missing");

    if (opt->opaque_string == NULL)
	errx(1, "opaque missing");

    size = strlen(opt->server_nonce_string);
    server_nonce = malloc(size);
    if (server_nonce == NULL)
	errx(1, "server_nonce");

    size = hex_decode(opt->server_nonce_string, server_nonce, size);
    if (size <= 0) 
	errx(1, "server nonce wrong");

    if (hex_decode(opt->server_identifier_string, &server_identifier, 1) != 1)
	errx(1, "server identifier wrong length");

    MD5_Init(&ctx);
    MD5_Update(&ctx, &server_identifier, 1);
    MD5_Update(&ctx, opt->password_string, strlen(opt->password_string));
    MD5_Update(&ctx, server_nonce, size);
    MD5_Final(md, &ctx);

    hex_encode(md, 16, &h);

    printf("responseData=%s\n", h);

    return 0;
}

/*
 *
 */

int
help(void *opt, int argc, char **argv)
{
    sl_slc_help(commands, argc, argv);
    return 0;
}

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    int optidx = 0;

    setprogname(argv[0]);

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

    if (argc == 0) {
	help(NULL, argc, argv);
	return 1;
    }

    if (ccache_string) {
	ret = krb5_cc_resolve(context, ccache_string, &id);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_cc_resolve");
    }

    ret = sl_command (commands, argc, argv);
    if (ret == -1) {
	help(NULL, argc, argv);
	return 1;
    }
    return ret;
}
