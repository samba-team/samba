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

#include "kadm5_locl.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

RCSID("$Id$");

static void
set_funcs(kadm5_client_context *c)
{
#define SET(C, F) (C)->funcs.F = kadm5 ## _c_ ## F
    SET(c, chpass_principal);
    SET(c, chpass_principal);
    SET(c, create_principal);
    SET(c, delete_principal);
    SET(c, destroy);
    SET(c, flush);
    SET(c, get_principal);
    SET(c, get_principals);
    SET(c, get_privs);
    SET(c, modify_principal);
    SET(c, randkey_principal);
    SET(c, rename_principal);
}

kadm5_ret_t
_kadm5_c_init_context(kadm5_client_context **ctx, 
		      kadm5_config_params *params,
		      krb5_context context)
{
    *ctx = malloc(sizeof(**ctx));
    if(*ctx == NULL)
	return ENOMEM;
    memset(*ctx, 0, sizeof(**ctx));
    set_funcs(*ctx);
    (*ctx)->context = context;
    if(params->mask & KADM5_CONFIG_REALM)
	(*ctx)->realm = strdup(params->realm);
    else
	krb5_get_default_realm((*ctx)->context, &(*ctx)->realm);
    if(params->mask & KADM5_CONFIG_ADMIN_SERVER)
	(*ctx)->admin_server = strdup(params->admin_server);
    else{
	const char *h = krb5_config_get_string(context,
					       NULL, 
					       "realms", 
					       (*ctx)->realm, 
					       "admin_server", 
					       NULL);
	if(h == NULL)
	    return KADM5_NO_SRV; /* XXX */
	(*ctx)->admin_server = strdup(h);
    }
	    
    initialize_kadm5_error_table_r(&context->et_list);
    return 0;
}

static krb5_error_code
get_cred_cache(krb5_context context, krb5_ccache *cc, 
	       const char *client_name, krb5_prompter_fct prompter)
{
    krb5_ccache id;
    krb5_creds in, *out = NULL;
    krb5_principal client, server = NULL;
    krb5_error_code ret;
    
    if(client_name == NULL) {
	ret = krb5_cc_default(context, &id);
	ret = krb5_cc_get_principal(context, id, &client);
	ret = krb5_parse_name(context, KADM5_ADMIN_SERVICE, &server);
	memset(&in, 0, sizeof(in));
	in.client = client;
	in.server = server;
	ret = krb5_get_credentials(context, 0, id, &in, &out);
	if(out != NULL)
	    krb5_free_creds(context, out);
	if(ret == 0) {
	    *cc = id;
	    goto out;
	}
	krb5_cc_close(context, id);
    } else 
	krb5_parse_name(context, client_name, &client);
    ret = krb5_cc_gen_new(context, &krb5_mcc_ops, &id);

    {
	krb5_creds cred;
	krb5_get_init_creds_opt opt;
	krb5_get_init_creds_opt_init (&opt);
	ret = krb5_get_init_creds_password (context,
					    &cred,
					    client,
					    NULL,
					    prompter,
					    NULL,
					    0,
					    KADM5_ADMIN_SERVICE,
					    &opt);
	switch(ret){
	case 0:
	    break;
	case KRB5KDC_ERR_NONE: /* XXX hack in krb5_get_init_creds_password */
	    exit(1);
	case KRB5KRB_AP_ERR_BAD_INTEGRITY:
	case KRB5KRB_AP_ERR_MODIFIED:
	    ret = KADM5_BAD_PASSWORD;
	    break;
	default:
	    krb5_err(context, 1, ret, "krb5_get_init_creds");
	}
	if(ret) {
	    goto out;
	}
	ret = krb5_cc_initialize (context, id, cred.client);
	if (ret)
	    return ret;
	
	ret = krb5_cc_store_cred (context, id, &cred);
	if (ret)
	    return ret;
	krb5_free_creds_contents (context, &cred);
	*cc = id;
    }
    
out:
    krb5_free_principal(context, client);
    krb5_free_principal(context, server);
    return ret;
}


kadm5_ret_t 
kadm5_c_init_with_password_ctx(krb5_context context,
			       char *client_name, 
			       char *pass,
			       char *service_name,
			       kadm5_config_params *realm_params,
			       unsigned long struct_version,
			       unsigned long api_version,
			       void **server_handle)
{
    kadm5_ret_t ret;
    kadm5_client_context *ctx;
    krb5_principal server;
    krb5_ccache cc;
    int s;
    struct sockaddr_in sin;
    struct hostent *hp;
    ret = _kadm5_c_init_context(&ctx, realm_params, context);
    if(ret)
	return ret;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0)
	return KADM5_FAILURE;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = krb5_getportbyname (context, "kerberos-adm", "tcp", 749);
    hp = gethostbyname(ctx->admin_server);
    if(hp == NULL)
	return KADM5_BAD_SERVER_NAME;
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    if(connect(s, (struct sockaddr*)&sin, sizeof(sin)) < 0){
	close(s);
	return KADM5_RPC_ERROR;
    }
    ret = get_cred_cache(context, &cc, client_name, krb5_prompter_posix);
    krb5_parse_name(context, KADM5_ADMIN_SERVICE, &server);
    ctx->ac = NULL;
    ret = krb5_sendauth(context, &ctx->ac, &s, KADMIN_APPL_VERSION, NULL, 
			server, AP_OPTS_MUTUAL_REQUIRED, 
			NULL, NULL, cc, NULL, NULL, NULL);
    krb5_free_principal(context, server);
    krb5_cc_close(context, cc);
    if(ret){
	close(s);
	return KADM5_FAILURE;
    }
    ctx->sock = s;
    *server_handle = ctx;
    return 0;
}

kadm5_ret_t 
kadm5_c_init_with_password(char *client_name, 
			   char *pass,
			   char *service_name,
			   kadm5_config_params *realm_params,
			   unsigned long struct_version,
			   unsigned long api_version,
			   void **server_handle)
{
    krb5_context context;
    kadm5_ret_t ret;
    kadm5_server_context *ctx;

    krb5_init_context(&context);
    ret = kadm5_c_init_with_password_ctx(context, 
					 client_name, 
					 pass, 
					 service_name, 
					 realm_params, 
					 struct_version, 
					 api_version, 
					 server_handle);
    if(ret){
	krb5_free_context(context);
	return ret;
    }
    ctx = *server_handle;
    ctx->my_context = 1;
    return 0;
}

#if 0
kadm5_ret_t 
kadm5_init_with_skey(char *client_name, char *keytab,
		     char *service_name,
		     kadm5_config_params *realm_params,
		     unsigned long struct_version,
		     unsigned long api_version,
		     void **server_handle)
{
}

kadm5_ret_t 
kadm5_init(char *client_name, char *pass,
	   char *service_name,
	   kadm5_config_params *realm_params,
	   unsigned long struct_version,
	   unsigned long api_version,
	   void **server_handle)
{
}

kadm5_ret_t 
kadm5_init_with_creds(char *client_name,
		      krb5_ccache ccache,
		      char *service_name,
		      kadm5_config_params *params,
		      krb5_ui_4 struct_version,
		      krb5_ui_4 api_version,
		      void **server_handle)
{
}


#endif
