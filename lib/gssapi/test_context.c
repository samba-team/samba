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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
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

#include "krb5/gsskrb5_locl.h"
#include <err.h>
#include <getarg.h>

RCSID("$Id$");

static char *type_string;
static char *mech_string;
static int dns_canon_flag = -1;
static int mutual_auth_flag = 0;
static int dce_style_flag = 0;
static int version_flag = 0;
static int verbose_flag = 0;
static int help_flag	= 0;

static char *gssapi_err(OM_uint32 maj_stat, OM_uint32 min_stat, 
			gss_OID mech)
{
	OM_uint32 disp_min_stat, disp_maj_stat;
	gss_buffer_desc maj_error_message;
	gss_buffer_desc min_error_message;
	OM_uint32 msg_ctx = 0;

	char *ret = NULL;

	maj_error_message.value = NULL;
	min_error_message.value = NULL;
	
	disp_maj_stat = gss_display_status(&disp_min_stat, maj_stat, GSS_C_GSS_CODE,
			   mech, &msg_ctx, &maj_error_message);
	disp_maj_stat = gss_display_status(&disp_min_stat, min_stat, GSS_C_MECH_CODE,
			   mech, &msg_ctx, &min_error_message);
	asprintf(&ret, "%s: %s", (char *)maj_error_message.value, (char *)min_error_message.value);

	gss_release_buffer(&disp_min_stat, &maj_error_message);
	gss_release_buffer(&disp_min_stat, &min_error_message);

	return ret;
}


static void
loop(gss_OID mechoid,
     gss_OID nameoid, const char *target,
     gss_ctx_id_t *sctx, gss_ctx_id_t *cctx)
{
    int server_done = 0, client_done = 0;
    OM_uint32 maj_stat, min_stat;
    gss_name_t gss_target_name;
    gss_buffer_desc input_token, output_token;
    OM_uint32 flags = 0, ret_cflags, ret_sflags;
    gss_cred_id_t deleg_cred = GSS_C_NO_CREDENTIAL;
    gss_OID mechoid_out;

    if (mutual_auth_flag)
	flags |= GSS_C_MUTUAL_FLAG;
    if (dce_style_flag)
	flags |= GSS_C_DCE_STYLE;

    input_token.value = rk_UNCONST(target);
    input_token.length = strlen(target);

    maj_stat = gss_import_name(&min_stat,
			       &input_token,
			       nameoid,
			       &gss_target_name);
    if (GSS_ERROR(maj_stat))
	err(1, "import name creds failed with: %d", maj_stat);

    input_token.length = 0;
    input_token.value = NULL;

    while (!server_done || !client_done) {

	maj_stat = gss_init_sec_context(&min_stat,
					GSS_C_NO_CREDENTIAL,
					cctx,
					gss_target_name,
					mechoid, 
					flags,
					0, 
					NULL,
					&input_token,
					NULL,
					&output_token,
					&ret_cflags,
					NULL);
	if (GSS_ERROR(maj_stat))
	    errx(1, "init_sec_context: %s",
		 gssapi_err(maj_stat, min_stat, mechoid));
	if (maj_stat & GSS_S_CONTINUE_NEEDED)
	    ;
	else
	    client_done = 1;

	if (client_done && server_done)
	    break;

	if (input_token.length != 0)
	    gss_release_buffer(&min_stat, &input_token);

	maj_stat = gss_accept_sec_context(&min_stat,
					  sctx,
					  GSS_C_NO_CREDENTIAL,
					  &output_token,
					  GSS_C_NO_CHANNEL_BINDINGS,
					  NULL,
					  &mechoid_out,
					  &input_token,
					  &ret_sflags,
					  NULL,
					  &deleg_cred);
	if (GSS_ERROR(maj_stat))
		errx(1, "accept_sec_context: %s",
		     gssapi_err(maj_stat, min_stat, mechoid_out));

	if (verbose_flag)
	    printf("%.*s", (int)input_token.length, (char *)input_token.value);

	if (output_token.length != 0)
	    gss_release_buffer(&min_stat, &output_token);

	if (maj_stat & GSS_S_CONTINUE_NEEDED)
	    ;
	else
	    server_done = 1;
    }	
    if (output_token.length != 0)
	gss_release_buffer(&min_stat, &output_token);
    if (input_token.length != 0)
	gss_release_buffer(&min_stat, &input_token);
    gss_release_name(&min_stat, &gss_target_name);
}

static void
wrapunwrap(gss_ctx_id_t cctx, gss_ctx_id_t sctx, gss_OID mechoid)
{
    gss_buffer_desc input_token, output_token, output_token2;
    OM_uint32 min_stat, maj_stat;
    int32_t flags = 0;
    gss_qop_t qop_state;
    int conf_state;

    input_token.value = "foo";
    input_token.length = 3;

    maj_stat = gss_wrap(&min_stat, cctx, flags, 0, &input_token,
			&conf_state, &output_token);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_wrap failed: %s",
	     gssapi_err(maj_stat, min_stat, mechoid));

    maj_stat = gss_unwrap(&min_stat, sctx, &output_token,
			  &output_token2, &conf_state, &qop_state);
    if (maj_stat != GSS_S_COMPLETE)
	errx(1, "gss_unwrap failed: %s",
	     gssapi_err(maj_stat, min_stat, mechoid));
}



static struct getargs args[] = {
    {"name-type",0,	arg_string, &type_string,  "type of name", NULL },
    {"mech-type",0,	arg_string, &mech_string,  "type of mech", NULL },
    {"dns-canonicalize",0,arg_negative_flag, &dns_canon_flag, 
     "use dns to canonicalize", NULL },
    {"mutual-auth",0,	arg_flag,	&mutual_auth_flag,"mutual auth", NULL },
    {"dce-style",0,	arg_flag,	&dce_style_flag, "dce-style", NULL },
    {"version",	0,	arg_flag,	&version_flag, "print version", NULL },
    {"verbose",	'v',	arg_flag,	&verbose_flag, "verbose", NULL },
    {"help",	0,	arg_flag,	&help_flag,  NULL, NULL }
};

static void
usage (int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args),
		    NULL, "service@host");
    exit (ret);
}

int
main(int argc, char **argv)
{
    int optind = 0;
    OM_uint32 min_stat, maj_stat;
    gss_ctx_id_t cctx, sctx;
    void *ctx;
    gss_OID nameoid, mechoid;

    setprogname(argv[0]);

    cctx = sctx = GSS_C_NO_CONTEXT;

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optind))
	usage(1);
    
    if (help_flag)
	usage (0);

    if(version_flag){
	print_version(NULL);
	exit(0);
    }

    argc -= optind;
    argv += optind;

    if (argc != 1)
	usage(1);

    if (dns_canon_flag != -1)
	gsskrb5_set_dns_canonicalize(dns_canon_flag);

    if (type_string == NULL)
	nameoid = GSS_C_NT_HOSTBASED_SERVICE;
    else if (strcmp(type_string, "hostbased-service") == 0)
	nameoid = GSS_C_NT_HOSTBASED_SERVICE;
    else if (strcmp(type_string, "krb5-principal-name") == 0)
	nameoid = GSS_KRB5_NT_PRINCIPAL_NAME;
    else
	errx(1, "%s not suppported", type_string);

    if (mech_string == NULL)
	mechoid = GSS_KRB5_MECHANISM;
    else if (strcmp(mech_string, "krb5") == 0)
	mechoid = GSS_KRB5_MECHANISM;
    else if (strcmp(mech_string, "spnego") == 0)
	mechoid = GSS_SPNEGO_MECHANISM;
    else if (strcmp(mech_string, "sasl-digest-md5") == 0)
	mechoid = GSS_SASL_DIGEST_MD5_MECHANISM;
    else
	errx(1, "%s not suppported", mech_string);

    loop(mechoid, nameoid, argv[0], &sctx, &cctx);
    
    if (gss_oid_equal(mechoid, GSS_KRB5_MECHANISM)) {
	time_t time, skew;
	gss_buffer_desc authz_data;
	krb5_keyblock *keyblock;
	krb5_timestamp now;
	krb5_error_code ret;

	ret = krb5_timeofday(_gsskrb5_context, &now);
	if (ret) 
		errx(1, "krb5_timeofday failed");
	
	/* client */
	maj_stat = gss_krb5_export_lucid_sec_context(&min_stat,
						     &cctx,
						     1, /* version */
						     &ctx);
	if (maj_stat != GSS_S_COMPLETE)
		errx(1, "gss_krb5_export_lucid_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, mechoid));
	
	
	maj_stat = gss_krb5_free_lucid_sec_context(&maj_stat, ctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_krb5_free_lucid_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, mechoid));
	
	/* server */
	maj_stat = gss_krb5_export_lucid_sec_context(&min_stat,
						     &sctx,
						     1, /* version */
						     &ctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_krb5_export_lucid_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, mechoid));
	maj_stat = gss_krb5_free_lucid_sec_context(&min_stat, ctx);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gss_krb5_free_lucid_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, mechoid));

 	maj_stat = gsskrb5_extract_authtime_from_sec_context(&min_stat,
							     sctx,
							     &time);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gsskrb5_extract_authtime_from_sec_context failed: %s",
		     gssapi_err(maj_stat, min_stat, mechoid));

	skew = abs(time - now);
	if (skew > krb5_get_max_time_skew(_gsskrb5_context)) {
	    errx(1, "gsskrb5_extract_authtime_from_sec_context failed: "
		 "time skew too great %llu > %llu", 
		 (unsigned long long)skew, 
		 (unsigned long long)krb5_get_max_time_skew(_gsskrb5_context));
	}

 	maj_stat = gsskrb5_extract_service_keyblock(&min_stat,
						    sctx,
						    &keyblock);
	if (maj_stat != GSS_S_COMPLETE)
	    errx(1, "gsskrb5_export_service_keyblock failed: %s",
		     gssapi_err(maj_stat, min_stat, mechoid));

	krb5_free_keyblock(_gsskrb5_context, keyblock);

 	maj_stat = gsskrb5_get_subkey(&min_stat,
				      sctx,
				      &keyblock);
	if (maj_stat != GSS_S_COMPLETE 
	    && (!(maj_stat == GSS_S_FAILURE && min_stat == GSS_KRB5_S_KG_NO_SUBKEY)))
	    errx(1, "gsskrb5_get_subkey failed: %s",
		     gssapi_err(maj_stat, min_stat, mechoid));

	if (maj_stat == GSS_S_COMPLETE)
	    krb5_free_keyblock(_gsskrb5_context, keyblock);

 	maj_stat = gsskrb5_get_initiator_subkey(&min_stat,
						sctx,
						&keyblock);
	if (maj_stat != GSS_S_COMPLETE 
	    && (!(maj_stat == GSS_S_FAILURE && min_stat == GSS_KRB5_S_KG_NO_SUBKEY)))
	    errx(1, "gsskrb5_get_initiator_subkey failed: %s",
		     gssapi_err(maj_stat, min_stat, mechoid));

	if (maj_stat == GSS_S_COMPLETE)
	    krb5_free_keyblock(_gsskrb5_context, keyblock);

 	maj_stat = gsskrb5_extract_authz_data_from_sec_context(&min_stat,
							       sctx,
							       128,
							       &authz_data);
	if (maj_stat == GSS_S_COMPLETE)
	    gss_release_buffer(&min_stat, &authz_data);

	wrapunwrap(cctx, sctx, mechoid);
	wrapunwrap(sctx, cctx, mechoid);
    }

    gss_delete_sec_context(&min_stat, &cctx, NULL);
    gss_delete_sec_context(&min_stat, &sctx, NULL);

    return 0;
}
