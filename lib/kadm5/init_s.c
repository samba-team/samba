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

#include "kadm5_locl.h"

RCSID("$Id$");

kadm5_ret_t 
kadm5_s_init_with_password_ctx(krb5_context context,
			       char *client_name, 
			       char *pass,
			       char *service_name,
			       kadm5_config_params *realm_params,
			       unsigned long struct_version,
			       unsigned long api_version,
			       void **server_handle)
{
    kadm5_ret_t ret;
    kadm5_server_context *ctx;
    ret = _kadm5_s_init_context(&ctx, realm_params, context);
    if(ret)
	return ret;
    ret = hdb_create(ctx->context, &ctx->db, NULL);
    if(ret)
	return ret;
    ret = hdb_set_master_key (ctx->context, 
			      ctx->db, NULL); /* XXX get from conf */
    if(ret)
	return ret;
    
    ret = krb5_parse_name(ctx->context, client_name, &ctx->caller);
    if(ret)
	return ret;
    
    *server_handle = ctx;
    return 0;
}

kadm5_ret_t 
kadm5_s_init_with_password(char *client_name, 
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
    ret = kadm5_s_init_with_password_ctx(context, 
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
