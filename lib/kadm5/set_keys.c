/*
 * Copyright (c) 1997 - 2001, 2003 Kungliga Tekniska Högskolan
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

#include "kadm5_locl.h"

RCSID("$Id$");

/* 
 * for each entry in `default_keys' try to parse it as a sequence
 * of etype:salttype:salt, syntax of this if something like:
 * [(des|des3|etype):](pw-salt|afs3)[:string], if etype is omitted it
 *      means all etypes, and if string is omitted is means the default
 * string (for that principal). Additional special values:
 *	v5 == pw-salt, and
 *	v4 == des:pw-salt:
 *	afs or afs3 == des:afs3-salt
 */

static krb5_error_code
parse_key_set(krb5_context context, const char *key, 
	      krb5_enctype **enctypes, size_t *num_enctypes, 
	      krb5_salt *salt, krb5_principal principal)
{
    const char *p;
    char buf[3][256];
    int num_buf = 0;
    int i;
    static krb5_enctype e; /* XXX */
    krb5_error_code ret;
    
    /* the 3 DES types must be first */
    krb5_enctype all_etypes[] = { 
	ETYPE_DES_CBC_MD5,
	ETYPE_DES_CBC_MD4,
	ETYPE_DES_CBC_CRC,
#ifdef ENABLE_AES
	ETYPE_AES256_CTS_HMAC_SHA1_96,
#endif
	ETYPE_ARCFOUR_HMAC_MD5,
	ETYPE_DES3_CBC_SHA1
    };

    p = key;

    *enctypes = NULL;
    *num_enctypes = 0;

    /* split p in a list of :-separated strings */
    for(num_buf = 0; num_buf < 3; num_buf++)
	if(strsep_copy(&p, ":", buf[num_buf], sizeof(buf[num_buf])) == -1)
	    break;

    salt->saltvalue.data = NULL;
    salt->saltvalue.length = 0;

    for(i = 0; i < num_buf; i++) {
	if(*enctypes == NULL) {
	    /* this might be a etype specifier */
	    /* XXX there should be a string_to_etypes handling
	       special cases like `des' and `all' */
	    if(strcmp(buf[i], "des") == 0) {
		*enctypes = all_etypes;
		*num_enctypes = 3;
		continue;
	    } else if(strcmp(buf[i], "des3") == 0) {
		e = ETYPE_DES3_CBC_SHA1;
		*enctypes = &e;
		*num_enctypes = 1;
		continue;
	    } else {
		ret = krb5_string_to_enctype(context, buf[i], &e);
		if (ret == 0) {
		    *enctypes = &e;
		    *num_enctypes = 1;
		    continue;
		}
	    }
	}

	if(salt->salttype == 0) {
	    /* interpret string as a salt specifier, if no etype
	       is set, this sets default values */
	    /* XXX should perhaps use string_to_salttype, but that
	       interface sucks */
	    if(strcmp(buf[i], "pw-salt") == 0) {
		if(*enctypes == NULL) {
		    *enctypes = all_etypes;
		    *num_enctypes = sizeof(all_etypes)/sizeof(all_etypes[0]);
		}
		salt->salttype = KRB5_PW_SALT;
	    } else if(strcmp(buf[i], "afs3-salt") == 0) {
		if(*enctypes == NULL) {
		    *enctypes = all_etypes;
		    *num_enctypes = 3;
		}
		salt->salttype = KRB5_AFS3_SALT;
	    }
	} else {
	    /* if there is a final string, use it as the string to
	       salt with, this is mostly useful with null salt for
	       v4 compat, and a cell name for afs compat */
	    salt->saltvalue.data = buf[i];
	    salt->saltvalue.length = strlen(buf[i]);
	}
    }
    
    if(*enctypes == NULL || salt->salttype == 0) {
	krb5_set_error_string(context, "bad value for default_keys `%s'", key);
	return EINVAL;
    }
    
    /* if no salt was specified make up default salt */
    if(salt->saltvalue.data == NULL) {
	if(salt->salttype == KRB5_PW_SALT)
	    ret = krb5_get_pw_salt(context, principal, salt);
	else if(salt->salttype == KRB5_AFS3_SALT) {
	    krb5_realm *realm = krb5_princ_realm(context, principal);
	    salt->saltvalue.data = strdup(*realm);
	    if(salt->saltvalue.data == NULL) {
		krb5_set_error_string(context, "out of memory while "
				      "parsing salt specifiers");
		return ENOMEM;
	    }
	    strlwr(salt->saltvalue.data);
	    salt->saltvalue.length = strlen(*realm);
	}
    }

    return 0;
}

static kadm5_ret_t
add_enctype_to_key_set(Key **key_set, size_t *nkeyset, 
		       krb5_enctype enctype, krb5_salt *salt)
{
    kadm5_ret_t ret;
    Key key, *tmp;

    memset(&key, 0, sizeof(key));

    tmp = realloc(*key_set, (*nkeyset + 1) * sizeof((*key_set)[0]));
    if (tmp == NULL)
	return ENOMEM;
    
    *key_set = tmp;

    key.key.keytype = enctype;
    key.key.keyvalue.length = 0;
    key.key.keyvalue.data = NULL;
    
    if (salt) {
	key.salt = malloc(sizeof(*key.salt));
	if (key.salt == NULL) {
	    free_Key(&key);
	    return ENOMEM;
	}
	
	key.salt->type = salt->salttype;
	krb5_data_zero (&key.salt->salt);
	
	ret = krb5_data_copy(&key.salt->salt, 
			     salt->saltvalue.data, 
			     salt->saltvalue.length);
	if (ret) {
	    free_Key(&key);
	    return ret;
	}
    } else
	key.salt = NULL;
    
    (*key_set)[*nkeyset] = key;
    
    *nkeyset += 1;

    return 0;
}


/*
 * Generate the `key_set' from the [kadmin]default_keys statement. If
 * `no_salt' is set, salt is not important (and will not be set) since
 * its random keys that is going to be created.
 */

kadm5_ret_t
_kadm5_generate_key_set(krb5_context context, krb5_principal principal,
			Key **ret_key_set, size_t *nkeyset, int no_salt)
{
    char **ktypes, **kp;
    krb5_error_code ret;
    Key *k, *key_set;
    int i, j;
    char *default_keytypes[] = {
	"des:pw-salt",
#ifdef ENABLE_AES
	"aes256-cts-hmac-sha1-96:pw-salt",
#endif
	"des3-cbc-sha1:pw-salt",
	"arcfour-hmac-md5:pw-salt",
	NULL
    };
    
    ktypes = krb5_config_get_strings(context, NULL, "kadmin",
				     "default_keys", NULL);
    if (ktypes == NULL)
	ktypes = default_keytypes;

    if (ktypes == NULL)
	abort();

    *ret_key_set = key_set = NULL;
    *nkeyset = 0;

    ret = 0;
 
    for(kp = ktypes; kp && *kp; kp++) {
	const char *p;
	krb5_salt salt;
	krb5_enctype *enctypes;
	size_t num_enctypes;

	p = *kp;
	/* check alias */
	if(strcmp(p, "v5") == 0)
	    p = "pw-salt";
	else if(strcmp(p, "v4") == 0)
	    p = "des:pw-salt:";
	else if(strcmp(p, "afs") == 0 || strcmp(p, "afs3") == 0)
	    p = "des:afs3-salt";

	memset(&salt, 0, sizeof(salt));

	ret = parse_key_set(context, p,
			    &enctypes, &num_enctypes, &salt, principal);
	if (ret) {
	    krb5_warnx(context, "bad value for default_keys `%s'", *kp);
	    continue;
	}

	for (i = 0; i < num_enctypes; i++) {
	    /* find duplicates */
	    for (j = 0; j < *nkeyset; j++) {

		k = &key_set[j];

		if (k->key.keytype == enctypes[i]) {
		    if (no_salt)
			break;
		    if (k->salt == NULL && salt.salttype == KRB5_PW_SALT)
			break;
		    if (k->salt->type == salt.salttype &&
			k->salt->salt.length == salt.saltvalue.length &&
			memcmp(k->salt->salt.data, salt.saltvalue.data, 
			       salt.saltvalue.length) == 0)
			break;
		}
	    }
	    /* not a duplicate, lets add it */
	    if (j == *nkeyset) {
		ret = add_enctype_to_key_set(&key_set, nkeyset, enctypes[i], 
					     no_salt ? NULL : &salt);
		if (ret)
		    goto out;
	    }
	}
    }
    
 out:
    if (ret) {
	krb5_warn(context, ret, 
		  "failed to parse the [kadmin]default_keys values");

	for (i = 0; i < *nkeyset; i++)
	    free_Key(&key_set[i]);
	free(key_set);
    } else if (*nkeyset == 0) {
	krb5_warnx(context, 
		   "failed to parse any of the [kadmin]default_keys values");
	ret = EINVAL; /* XXX */
    }

    *ret_key_set = key_set;

    return ret;
}

/*
 * Set the keys of `ent' to the string-to-key of `password'
 */

kadm5_ret_t
_kadm5_set_keys(kadm5_server_context *context,
		hdb_entry *ent, 
		const char *password)
{
    kadm5_ret_t ret;
    size_t num_keys;
    Key *keys;
    int i;

    ret = _kadm5_generate_key_set(context->context, ent->principal,
				  &keys, &num_keys, 0);
    if (ret)
	return ret;

    for (i = 0; i < num_keys; i++) {
	krb5_salt salt;

	salt.salttype = keys[i].salt->type;
	salt.saltvalue.length = keys[i].salt->salt.length;
	salt.saltvalue.data = keys[i].salt->salt.data;

	ret = krb5_string_to_key_salt (context->context,
				       keys[i].key.keytype,
				       password,
				       salt,
				       &keys[i].key);

	if(ret)
	    break;
    }

    if(ret) {
	_kadm5_free_keys (context, num_keys, keys);
	return ret;
    }
    
    _kadm5_free_keys (context, ent->keys.len, ent->keys.val);
    ent->keys.val = keys;
    ent->keys.len = num_keys;
    return 0;
}

/*
 * Set the keys of `ent' to (`n_key_data', `key_data')
 */

kadm5_ret_t
_kadm5_set_keys2(kadm5_server_context *context,
		 hdb_entry *ent, 
		 int16_t n_key_data, 
		 krb5_key_data *key_data)
{
    krb5_error_code ret;
    int i;
    unsigned len;
    Key *keys;

    len  = n_key_data;
    keys = malloc (len * sizeof(*keys));
    if (keys == NULL)
	return ENOMEM;

    _kadm5_init_keys (keys, len);

    for(i = 0; i < n_key_data; i++) {
	keys[i].mkvno = NULL;
	keys[i].key.keytype = key_data[i].key_data_type[0];
	ret = krb5_data_copy(&keys[i].key.keyvalue,
			     key_data[i].key_data_contents[0],
			     key_data[i].key_data_length[0]);
	if(ret)
	    goto out;
	if(key_data[i].key_data_ver == 2) {
	    Salt *salt;

	    salt = malloc(sizeof(*salt));
	    if(salt == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    keys[i].salt = salt;
	    salt->type = key_data[i].key_data_type[1];
	    krb5_data_copy(&salt->salt, 
			   key_data[i].key_data_contents[1],
			   key_data[i].key_data_length[1]);
	} else
	    keys[i].salt = NULL;
    }
    _kadm5_free_keys (context, ent->keys.len, ent->keys.val);
    ent->keys.len = len;
    ent->keys.val = keys;
    return 0;
 out:
    _kadm5_free_keys (context, len, keys);
    return ret;
}

/*
 * Set the keys of `ent' to `n_keys, keys'
 */

kadm5_ret_t
_kadm5_set_keys3(kadm5_server_context *context,
		 hdb_entry *ent,
		 int n_keys,
		 krb5_keyblock *keyblocks)
{
    krb5_error_code ret;
    int i;
    unsigned len;
    Key *keys;

    len  = n_keys;
    keys = malloc (len * sizeof(*keys));
    if (keys == NULL)
	return ENOMEM;

    _kadm5_init_keys (keys, len);

    for(i = 0; i < n_keys; i++) {
	keys[i].mkvno = NULL;
	ret = krb5_copy_keyblock_contents (context->context,
					   &keyblocks[i],
					   &keys[i].key);
	if(ret)
	    goto out;
	keys[i].salt = NULL;
    }
    _kadm5_free_keys (context, ent->keys.len, ent->keys.val);
    ent->keys.len = len;
    ent->keys.val = keys;
    return 0;
 out:
    _kadm5_free_keys (context, len, keys);
    return ret;
}

/*
 *
 */

static int
is_des_key_p(int keytype)
{
    return keytype == ETYPE_DES_CBC_CRC ||
    	keytype == ETYPE_DES_CBC_MD4 ||
	keytype == ETYPE_DES_CBC_MD5;
}


/*
 * Set the keys of `ent' to random keys and return them in `n_keys'
 * and `new_keys'.
 */

kadm5_ret_t
_kadm5_set_keys_randomly (kadm5_server_context *context,
			  hdb_entry *ent,
			  krb5_keyblock **new_keys,
			  int *n_keys)
{
   krb5_keyblock *kblock = NULL;
   kadm5_ret_t ret = 0;
   int i, des_keyblock;
   size_t num_keys;
   Key *keys;

   ret = _kadm5_generate_key_set(context->context, ent->principal,
				  &keys, &num_keys, 1);
   if (ret)
	return ret;

   kblock = malloc(num_keys * sizeof(kblock[0]));
   if (kblock == NULL) {
	ret = ENOMEM;
	_kadm5_free_keys (context, num_keys, keys);
	return ret;
   }
   memset(kblock, 0, num_keys * sizeof(kblock[0]));

   des_keyblock = -1;
   for (i = 0; i < num_keys; i++) {

	/* 
	 * To make sure all des keys are the the same we generate only
	 * the first one and then copy key to all other des keys.
	 */

	if (des_keyblock != -1 && is_des_key_p(keys[i].key.keytype)) {
	    ret = krb5_copy_keyblock_contents (context->context,
					       &kblock[des_keyblock],
					       &kblock[i]);
	    if (ret)
		goto out;
	} else {
	    ret = krb5_generate_random_keyblock (context->context,
						 keys[i].key.keytype,
						 &kblock[i]);
	    if (ret)
		goto out;

	    if (is_des_key_p(keys[i].key.keytype))
		des_keyblock = i;
	}

	ret = krb5_copy_keyblock_contents (context->context,
					   &kblock[i],
					   &keys[i].key);
	if (ret)
	    goto out;
   }

out:
   if(ret) {
	for (i = 0; i < num_keys; ++i)
	    krb5_free_keyblock_contents (context->context, &kblock[i]);
	free(kblock);
	_kadm5_free_keys (context, num_keys, keys);
	return ret;
   }
   
   _kadm5_free_keys (context, ent->keys.len, ent->keys.val);
   ent->keys.val = keys;
   ent->keys.len = num_keys;
   *new_keys     = kblock;
   *n_keys       = num_keys;

   return 0;
}
