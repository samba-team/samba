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
kadmind_dispatch(void *kadm_handle, krb5_storage *sp)
{
    kadm5_ret_t ret;
    int32_t cmd, mask, tmp;
    kadm5_server_context *context = kadm_handle;
    char client[128], name[128], name2[128];
    char *op = "";
    krb5_principal princ, princ2;
    kadm5_principal_ent_rec ent;
    char *password, *exp;
    krb5_keyblock *new_keys;
    int n_keys;
    char **princs;
    int n_princs;
    
    krb5_unparse_name_fixed(context->context, context->caller, 
			    client, sizeof(client));
    
    krb5_ret_int32(sp, &cmd);
    switch(cmd){
    case kadm_get:{
	op = "GET";
	ret = krb5_ret_principal(sp, &princ);
	if(ret)
	    goto fail;
	ret = krb5_ret_int32(sp, &mask);
	if(ret){
	    krb5_free_principal(context->context, princ);
	    goto fail;
	}
	krb5_unparse_name_fixed(context->context, princ, name, sizeof(name));
	krb5_warnx(context->context, "%s: %s %s", client, op, name);
	ret = _kadm5_acl_check_permission(context, KADM5_PRIV_GET);
	if(ret){
	    krb5_free_principal(context->context, princ);
	    goto fail;
	}
	ret = kadm5_get_principal(kadm_handle, princ, &ent, mask);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	if(ret == 0){
	    kadm5_store_principal_ent(sp, &ent);
	    kadm5_free_principal_ent(kadm_handle, &ent);
	}
	krb5_free_principal(context->context, princ);
	break;
    }
    case kadm_delete:{
	op = "DELETE";
	ret = krb5_ret_principal(sp, &princ);
	if(ret)
	    goto fail;
	krb5_unparse_name_fixed(context->context, princ, name, sizeof(name));
	krb5_warnx(context->context, "%s: %s %s", client, op, name);
	ret = _kadm5_acl_check_permission(context, KADM5_PRIV_DELETE);
	if(ret){
	    krb5_free_principal(context->context, princ);
	    goto fail;
	}
	ret = kadm5_delete_principal(kadm_handle, princ);
	krb5_free_principal(context->context, princ);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	break;
    }
    case kadm_create:{
	op = "CREATE";
	ret = kadm5_ret_principal_ent(sp, &ent);
	if(ret)
	    goto fail;
	ret = krb5_ret_int32(sp, &mask);
	if(ret){
	    kadm5_free_principal_ent(context->context, &ent);
	    goto fail;
	}
	ret = krb5_ret_string(sp, &password);
	if(ret){
	    kadm5_free_principal_ent(context->context, &ent);
	    goto fail;
	}
	krb5_unparse_name_fixed(context->context, ent.principal, 
				name, sizeof(name));
	krb5_warnx(context->context, "%s: %s %s", client, op, name);
	ret = _kadm5_acl_check_permission(context, KADM5_PRIV_ADD);
	if(ret){
	    kadm5_free_principal_ent(context->context, &ent);
	    memset(password, 0, strlen(password));
	    free(password);
	    goto fail;
	}
	ret = kadm5_create_principal(kadm_handle, &ent, 
				     mask, password);
	kadm5_free_principal_ent(kadm_handle, &ent);
	memset(password, 0, strlen(password));
	free(password);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	break;
    }
    case kadm_modify:{
	op = "MODIFY";
	ret = kadm5_ret_principal_ent(sp, &ent);
	if(ret)
	    goto fail;
	ret = krb5_ret_int32(sp, &mask);
	if(ret){
	    kadm5_free_principal_ent(context, &ent);
	    goto fail;
	}
	krb5_unparse_name_fixed(context->context, ent.principal, 
				name, sizeof(name));
	krb5_warnx(context->context, "%s: %s %s", client, op, name);
	ret = _kadm5_acl_check_permission(context, KADM5_PRIV_MODIFY);
	if(ret){
	    kadm5_free_principal_ent(context, &ent);
	    goto fail;
	}
	ret = kadm5_modify_principal(kadm_handle, &ent, mask);
	kadm5_free_principal_ent(kadm_handle, &ent);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	break;
    }
    case kadm_rename:{
	op = "RENAME";
	ret = krb5_ret_principal(sp, &princ);
	if(ret)
	    goto fail;
	ret = krb5_ret_principal(sp, &princ2);
	if(ret){
	    krb5_free_principal(context->context, princ);
	    goto fail;
	}
	krb5_unparse_name_fixed(context->context, princ, name, sizeof(name));
	krb5_unparse_name_fixed(context->context, princ2, name2, sizeof(name2));
	krb5_warnx(context->context, "%s: %s %s -> %s", 
		   client, op, name, name2);
	ret = _kadm5_acl_check_permission(context, 
					 KADM5_PRIV_ADD|KADM5_PRIV_DELETE);
	if(ret){
	    krb5_free_principal(context->context, princ);
	    goto fail;
	}
	ret = kadm5_rename_principal(kadm_handle, princ, princ2);
	krb5_free_principal(context->context, princ);
	krb5_free_principal(context->context, princ2);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	break;
    }
    case kadm_chpass:{
	op = "CHPASS";
	ret = krb5_ret_principal(sp, &princ);
	if(ret)
	    goto fail;
	ret = krb5_ret_string(sp, &password);
	if(ret){
	    krb5_free_principal(context->context, princ);
	    goto fail;
	}
	krb5_unparse_name_fixed(context->context, princ, name, sizeof(name));
	krb5_warnx(context->context, "%s: %s %s", client, op, name);
	ret = _kadm5_acl_check_permission(context, KADM5_PRIV_CPW);
	if(ret){
	    krb5_free_principal(context->context, princ);
	    goto fail;
	}
	ret = kadm5_chpass_principal(kadm_handle, princ, password);
	krb5_free_principal(context->context, princ);
	memset(password, 0, strlen(password));
	free(password);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	break;
    }
    case kadm_randkey:{
	op = "RANDKEY";
	ret = krb5_ret_principal(sp, &princ);
	if(ret)
	    goto fail;
	krb5_unparse_name_fixed(context->context, princ, name, sizeof(name));
	krb5_warnx(context->context, "%s: %s %s", client, op, name);
	ret = _kadm5_acl_check_permission(context, KADM5_PRIV_CPW);
	if(ret){
	    krb5_free_principal(context->context, princ);
	    goto fail;
	}
	ret = kadm5_randkey_principal(kadm_handle, princ, 
				      &new_keys, &n_keys);
	krb5_free_principal(context->context, princ);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	if(ret == 0){
	    int i;
	    krb5_store_int32(sp, n_keys);
	    for(i = 0; i < n_keys; i++){
		krb5_store_keyblock(sp, new_keys[i]);
		krb5_free_keyblock(context->context, &new_keys[i]);
	    }
	}
	break;
    }
    case kadm_get_privs:{
	ret = kadm5_get_privs(kadm_handle, &mask);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	if(ret == 0)
	    krb5_store_int32(sp, mask);
	break;
    }
    case kadm_get_princs:{
	op = "LIST";
	ret = krb5_ret_int32(sp, &tmp);
	if(ret)
	    goto fail;
	if(tmp){
	    ret = krb5_ret_string(sp, &exp);
	    if(ret)
		goto fail;
	}else
	    exp = NULL;
	krb5_warnx(context->context, "%s: %s %s", client, op, exp ? exp : "*");
	ret = _kadm5_acl_check_permission(context, KADM5_PRIV_LIST);
	if(ret){
	    free(exp);
	    goto fail;
	}
	ret = kadm5_get_principals(kadm_handle, exp, &princs, &n_princs);
	free(exp);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, ret);
	if(ret == 0){
	    int i;
	    krb5_store_int32(sp, n_princs);
	    for(i = 0; i < n_princs; i++)
		krb5_store_string(sp, princs[i]);
	    kadm5_free_name_list(kadm_handle, princs, &n_princs);
	}
	break;
    }
    default:
	krb5_warnx(context->context, "%s: UNKNOWN OP %d", client, cmd);
	sp->seek(sp, 0, SEEK_SET);
	krb5_store_int32(sp, KADM5_FAILURE);
	break;
    }
    return 0;
fail:
    krb5_warnx(context->context, "%s", op);
    sp->seek(sp, 0, SEEK_SET);
    krb5_store_int32(sp, ret);
    return 0;
}
