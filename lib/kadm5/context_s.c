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
_kadm5_s_init_context(kadm5_server_context **ctx, 
		      kadm5_config_params *params,
		      krb5_context context)
{
    *ctx = malloc(sizeof(**ctx));
    if(*ctx == NULL)
	return ENOMEM;
    memset(*ctx, 0, sizeof(**ctx));
    (*ctx)->context = context;
    initialize_kadm5_error_table(&context->et_list);
#if 0
#define is_set(M) (params->mask & KADM5_CONFIG_ ## M)
    if(is_set(REALM))
	ctx->config.realm = strdup(params->realm);
    else
	krb5_get_default_realm(ctx->context, &ctx->config.realm);
    if(is_set(PROFILE)) 
	ctx->config.params = strdup(params->profile);
    
    if(is_set(KADMIND_PORT))
	ctx->config.kadmind_port = params->kadmind_port;
    else
	ctx->config.kadmind_port = 749;
    if(is_set(ADMIN_SERVER))
	ctx->config.admin_server = strdup(params->admin_server);
    if(is_set(DBNAME))
	ctx->config.dbname = strdup(params->dbname);
    if(is_set(ADBNAME))
	ctx->config.adbname = strdup(params->adbname);
    if(is_set(ADB_LOCKFILE))
	ctx->config.adb_lockfile = strdup(params->adb_lockfile);
    if(is_set(ACL_FILE))
	ctx->config.acl_file = strdup(params->acl_file);
    if(is_set(DICT_FILE))
	ctx->config.dict_file = strdup(params->dict_file);
    if(is_set(ADMIN_KEYTAB))
	ctx->config.admin_keytab = strdup(params->admin_keytab);
    if(is_set(MKEY_FROM_KEYBOARD))
	ctx->config.mkey_from_keyboard = params->mkey_from_keyboard;
    if(is_set(STASH_FILE))
	ctx->config.stash_file = strdup(params->stash_file);
    if(is_set(MKEY_NAME))
	ctx->config.mkey_name = strdup(params->mkey_name);
    
    krb5_enctype enctype;
    krb5_deltat max_life;
    krb5_deltat max_rlife;
    krb5_timestamp expiration;
    krb5_flags flags;
    krb5_key_salt_tuple *keysalts;
    krb5_int32 num_keysalts;
#endif    
    return 0;
}
