/*
 * Copyright (c) 1997, 1998, 1999 Kungliga Tekniska Högskolan
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

/*
 * Set the keys of `ent' to the string-to-key of `password'
 */

kadm5_ret_t
_kadm5_set_keys(kadm5_server_context *context,
		hdb_entry *ent, 
		const char *password)
{
    int i;
    kadm5_ret_t ret = 0;
    Key *key;

    for(i = 0; i < ent->keys.len; i++) {
	key = &ent->keys.val[i];
	free(key->mkvno);
	key->mkvno = NULL;
	if(key->salt && 
	   key->salt->type == hdb_pw_salt &&
	   (key->salt->salt.length != 0 ||
	    !krb5_config_get_bool(context->context, NULL, 
				  "kadmin", "use_v4_salt", NULL))){
	    /* zap old salt, possibly keeping version 4 salts */
	    free_Salt(key->salt);
	    free (key->salt);
	    key->salt = NULL;
	}
	krb5_free_keyblock_contents(context->context, &key->key);
	/* XXX check for DES key and AFS3 salt? */
	if(key->salt) {
	    krb5_salt salt;
	    salt.salttype = key->salt->type;
	    salt.saltvalue = key->salt->salt;
	    ret = krb5_string_to_key_salt(context->context,
					  key->key.keytype,
					  password, 
					  salt,
					  &key->key);
	} else
	    ret = krb5_string_to_key(context->context,
				     key->key.keytype,
				     password, 
				     ent->principal,
				     &key->key);
	if(ret) {
	    krb5_warn(context->context, ret, "string-to-key failed");
	    break;
	}
    }
    ent->kvno++;
    return ret;
}

/*
 * Set the keys of `ent' to (`n_key_data', `key_data')
 */

kadm5_ret_t
_kadm5_set_keys2(hdb_entry *ent, 
		 int16_t n_key_data, 
		 krb5_key_data *key_data)
{
    krb5_error_code ret;
    int i;

    ent->keys.len = n_key_data;
    ent->keys.val = malloc(ent->keys.len * sizeof(*ent->keys.val));
    if(ent->keys.val == NULL)
	return ENOMEM;
    for(i = 0; i < n_key_data; i++) {
	ent->keys.val[i].mkvno = NULL;
	ent->keys.val[i].key.keytype = key_data[i].key_data_type[0];
	ret = krb5_data_copy(&ent->keys.val[i].key.keyvalue,
			     key_data[i].key_data_contents[0],
			     key_data[i].key_data_length[0]);
	if(ret)
	    return ret;
	if(key_data[i].key_data_ver == 2) {
	    Salt *salt;
	    salt = malloc(sizeof(*salt));
	    if(salt == NULL)
		return ENOMEM;
	    ent->keys.val[i].salt = salt;
	    salt->type = key_data[i].key_data_type[1];
	    krb5_data_copy(&salt->salt, 
			   key_data[i].key_data_contents[1],
			   key_data[i].key_data_length[1]);
	} else
	    ent->keys.val[i].salt = NULL;
    }
    ent->kvno++;
    return 0;
}
