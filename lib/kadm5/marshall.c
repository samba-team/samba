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
kadm5_store_key_data(krb5_storage *sp,
		     krb5_key_data *key)
{
    krb5_data c;
    krb5_store_int32(sp, key->key_data_ver);
    krb5_store_int32(sp, key->key_data_kvno);
    krb5_store_int32(sp, key->key_data_type[0]);
    c.length = key->key_data_length[0];
    c.data = key->key_data_contents[0];
    krb5_store_data(sp, c);
    krb5_store_int32(sp, key->key_data_type[1]);
    c.length = key->key_data_length[1];
    c.data = key->key_data_contents[1];
    krb5_store_data(sp, c);
    return 0;
}

kadm5_ret_t
kadm5_ret_key_data(krb5_storage *sp,
		   krb5_key_data *key)
{
    krb5_data c;
    int32_t tmp;
    krb5_ret_int32(sp, &tmp);
    key->key_data_ver = tmp;
    krb5_ret_int32(sp, &tmp);
    key->key_data_kvno = tmp;
    krb5_ret_int32(sp, &tmp);
    key->key_data_type[0] = tmp;
    krb5_ret_data(sp, &c);
    key->key_data_length[0] = c.length;
    key->key_data_contents[0] = c.data;
    krb5_ret_int32(sp, &tmp);
    key->key_data_type[1] = tmp;
    krb5_ret_data(sp, &c);
    key->key_data_length[1] = c.length;
    key->key_data_contents[1] = c.data;
    return 0;
}

kadm5_ret_t
kadm5_store_tl_data(krb5_storage *sp,
		    krb5_tl_data *tl)
{
    krb5_data c;
    krb5_store_int32(sp, tl->tl_data_type);
    c.length = tl->tl_data_length;
    c.data = tl->tl_data_contents;
    krb5_store_data(sp, c);
    return 0;
}

kadm5_ret_t
kadm5_ret_tl_data(krb5_storage *sp,
		  krb5_tl_data *tl)
{
    krb5_data c;
    int32_t tmp;
    krb5_ret_int32(sp, &tmp);
    tl->tl_data_type = tmp;
    krb5_ret_data(sp, &c);
    tl->tl_data_length = c.length;
    tl->tl_data_contents = c.data;
    return 0;
}

kadm5_ret_t
kadm5_store_principal_ent(krb5_storage *sp,
			  kadm5_principal_ent_t princ)
{
    int i;
    krb5_store_principal(sp, princ->principal);
    krb5_store_int32(sp, princ->princ_expire_time);
    krb5_store_int32(sp, princ->last_pwd_change);
    krb5_store_int32(sp, princ->pw_expiration);
    krb5_store_int32(sp, princ->max_life);
    krb5_store_int32(sp, princ->mod_name != NULL);
    if(princ->mod_name)
	krb5_store_principal(sp, princ->mod_name);
    krb5_store_int32(sp, princ->mod_date);
    krb5_store_int32(sp, princ->attributes);
    krb5_store_int32(sp, princ->kvno);
    krb5_store_int32(sp, princ->mkvno);
    krb5_store_int32(sp, princ->policy != NULL);
    if(princ->policy)
	krb5_store_string(sp, princ->policy);
    krb5_store_int32(sp, princ->aux_attributes);
    krb5_store_int32(sp, princ->max_renewable_life);
    krb5_store_int32(sp, princ->last_success);
    krb5_store_int32(sp, princ->last_failed);
    krb5_store_int32(sp, princ->fail_auth_count);
    krb5_store_int32(sp, princ->n_key_data);
    for(i = 0; i < princ->n_key_data; i++)
	kadm5_store_key_data(sp, &princ->key_data[i]);
    krb5_store_int32(sp, princ->n_tl_data);
    {
	krb5_tl_data *tp;
	for(tp = princ->tl_data; tp; tp = tp->tl_data_next)
	    kadm5_store_tl_data(sp, tp);
    }
    return 0;
}

kadm5_ret_t
kadm5_ret_principal_ent(krb5_storage *sp,
			kadm5_principal_ent_t princ)
{
    int i;
    int32_t tmp;
    krb5_ret_principal(sp, &princ->principal);
    
    krb5_ret_int32(sp, &tmp);
    princ->princ_expire_time = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->last_pwd_change = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->pw_expiration = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->max_life = tmp;
    krb5_ret_int32(sp, &tmp);
    if(tmp)
	krb5_ret_principal(sp, &princ->mod_name);
    else
	princ->mod_name = NULL;
    krb5_ret_int32(sp, &tmp);
    princ->mod_date = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->attributes = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->kvno = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->mkvno = tmp;
    krb5_ret_int32(sp, &tmp);
    if(tmp)
	krb5_ret_string(sp, &princ->policy);
    else
	princ->policy = NULL;
    krb5_ret_int32(sp, &tmp);
    princ->aux_attributes = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->max_renewable_life = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->last_success = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->last_failed = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->fail_auth_count = tmp;
    krb5_ret_int32(sp, &tmp);
    princ->n_key_data = tmp;
    princ->key_data = malloc(princ->n_key_data * sizeof(*princ->key_data));
    for(i = 0; i < princ->n_key_data; i++)
	kadm5_ret_key_data(sp, &princ->key_data[i]);
    krb5_ret_int32(sp, &tmp);
    princ->tl_data = NULL;
    for(i = 0; i < princ->n_tl_data; i++){
	krb5_tl_data *tp = malloc(sizeof(*tp));
	kadm5_ret_tl_data(sp, tp);
	tp->tl_data_next = princ->tl_data;
	princ->tl_data = tp;
    }
    return 0;
}

