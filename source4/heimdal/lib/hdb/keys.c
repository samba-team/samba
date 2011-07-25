
/*
 * Copyright (c) 1997 - 2011 Kungliga Tekniska Högskolan
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

#include "hdb_locl.h"

/*
 * free all the memory used by (len, keys)
 */

void
hdb_free_keys(krb5_context context, int len, Key *keys)
{
    size_t i;

    for (i = 0; i < len; i++) {
	free(keys[i].mkvno);
	keys[i].mkvno = NULL;
	if (keys[i].salt != NULL) {
	    free_Salt(keys[i].salt);
	    free(keys[i].salt);
	    keys[i].salt = NULL;
	}
	krb5_free_keyblock_contents(context, &keys[i].key);
    }
    free (keys);
}

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

static const krb5_enctype des_etypes[] = {
    KRB5_ENCTYPE_DES_CBC_MD5,
    KRB5_ENCTYPE_DES_CBC_MD4,
    KRB5_ENCTYPE_DES_CBC_CRC
};

static const krb5_enctype all_etypes[] = {
    KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96,
    KRB5_ENCTYPE_ARCFOUR_HMAC_MD5,
    KRB5_ENCTYPE_DES3_CBC_SHA1
};

static krb5_error_code
parse_key_set(krb5_context context, const char *key,
	      krb5_enctype **ret_enctypes, size_t *ret_num_enctypes,
	      krb5_salt *salt, krb5_principal principal)
{
    const char *p;
    char buf[3][256];
    int num_buf = 0;
    int i, num_enctypes = 0;
    krb5_enctype e;
    const krb5_enctype *enctypes = NULL;
    krb5_error_code ret;

    p = key;

    *ret_enctypes = NULL;
    *ret_num_enctypes = 0;

    /* split p in a list of :-separated strings */
    for(num_buf = 0; num_buf < 3; num_buf++)
	if(strsep_copy(&p, ":", buf[num_buf], sizeof(buf[num_buf])) == -1)
	    break;

    salt->saltvalue.data = NULL;
    salt->saltvalue.length = 0;

    for(i = 0; i < num_buf; i++) {
	if(enctypes == NULL && num_buf > 1) {
	    /* this might be a etype specifier */
	    /* XXX there should be a string_to_etypes handling
	       special cases like `des' and `all' */
	    if(strcmp(buf[i], "des") == 0) {
		enctypes = des_etypes;
		num_enctypes = sizeof(des_etypes)/sizeof(des_etypes[0]);
	    } else if(strcmp(buf[i], "des3") == 0) {
		e = KRB5_ENCTYPE_DES3_CBC_SHA1;
		enctypes = &e;
		num_enctypes = 1;
	    } else {
		ret = krb5_string_to_enctype(context, buf[i], &e);
		if (ret == 0) {
		    enctypes = &e;
		    num_enctypes = 1;
		} else
		    return ret;
	    }
	    continue;
	}
	if(salt->salttype == 0) {
	    /* interpret string as a salt specifier, if no etype
	       is set, this sets default values */
	    /* XXX should perhaps use string_to_salttype, but that
	       interface sucks */
	    if(strcmp(buf[i], "pw-salt") == 0) {
		if(enctypes == NULL) {
		    enctypes = all_etypes;
		    num_enctypes = sizeof(all_etypes)/sizeof(all_etypes[0]);
		}
		salt->salttype = KRB5_PW_SALT;
	    } else if(strcmp(buf[i], "afs3-salt") == 0) {
		if(enctypes == NULL) {
		    enctypes = des_etypes;
		    num_enctypes = sizeof(des_etypes)/sizeof(des_etypes[0]);
		}
		salt->salttype = KRB5_AFS3_SALT;
	    }
	    continue;
	}

	{
	    /* if there is a final string, use it as the string to
	       salt with, this is mostly useful with null salt for
	       v4 compat, and a cell name for afs compat */
	    salt->saltvalue.data = strdup(buf[i]);
	    if (salt->saltvalue.data == NULL) {
		krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
		return ENOMEM;
	    }
	    salt->saltvalue.length = strlen(buf[i]);
	}
    }

    if(enctypes == NULL || salt->salttype == 0) {
	krb5_set_error_message(context, EINVAL, "bad value for default_keys `%s'", key);
	return EINVAL;
    }

    /* if no salt was specified make up default salt */
    if(salt->saltvalue.data == NULL) {
	if(salt->salttype == KRB5_PW_SALT)
	    ret = krb5_get_pw_salt(context, principal, salt);
	else if(salt->salttype == KRB5_AFS3_SALT) {
	    krb5_const_realm realm = krb5_principal_get_realm(context, principal);
	    salt->saltvalue.data = strdup(realm);
	    if(salt->saltvalue.data == NULL) {
		krb5_set_error_message(context, ENOMEM,
				       "out of memory while "
				       "parsing salt specifiers");
		return ENOMEM;
	    }
	    strlwr(salt->saltvalue.data);
	    salt->saltvalue.length = strlen(realm);
	}
    }

    *ret_enctypes = malloc(sizeof(enctypes[0]) * num_enctypes);
    if (*ret_enctypes == NULL) {
	krb5_free_salt(context, *salt);
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }
    memcpy(*ret_enctypes, enctypes, sizeof(enctypes[0]) * num_enctypes);
    *ret_num_enctypes = num_enctypes;

    return 0;
}


/**
 * This function adds an HDB entry's current keyset to the entry's key
 * history.  The current keyset is left alone; the caller is responsible
 * for freeing it.
 *
 * @param context   Context
 * @param entry	    HDB entry
 */
krb5_error_code
hdb_add_current_keys_to_history(krb5_context context, hdb_entry *entry)
{
    krb5_boolean replace = FALSE;
    krb5_error_code ret;
    HDB_extension *ext;
    hdb_keyset newkey;
    time_t newtime;


    ext = hdb_find_extension(entry, choice_HDB_extension_data_hist_keys);
    if (ext == NULL) {
	replace = TRUE;
	ext = calloc(1, sizeof (*ext));
	if (ext == NULL)
	    return krb5_enomem(context);

	ext->data.element = choice_HDB_extension_data_hist_keys;
    }

    /*
     * Copy in newest old keyset
     */

    ret = hdb_entry_get_pw_change_time(entry, &newtime);
    if (ret)
	goto out;

    memset(&newkey, 0, sizeof(newkey));
    newkey.keys = entry->keys;
    newkey.kvno = entry->kvno;
    newkey.set_time = &newtime;

    ret = add_HDB_Ext_KeySet(&ext->data.u.hist_keys, &newkey);
    if (ret)
	goto out;

    if (replace) {
	/* hdb_replace_extension() deep-copies ext; what a waste */
	ret = hdb_replace_extension(context, entry, ext);
	if (ret)
	    goto out;
    }

 out:
    if (replace && ext) {
	free_HDB_extension(ext);
	free(ext);
    }
    return ret;
}


static krb5_error_code
add_enctype_to_key_set(Key **key_set, size_t *nkeyset,
		       krb5_enctype enctype, krb5_salt *salt)
{
    krb5_error_code ret;
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
	key.salt = calloc(1, sizeof(*key.salt));
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


static
krb5_error_code
ks_tuple2str(krb5_context context, int n_ks_tuple,
	     krb5_key_salt_tuple *ks_tuple, char ***ks_tuple_strs)
{
	size_t i;
	char **ksnames;
	char *ename, *sname;
	krb5_error_code rc = KRB5_PROG_ETYPE_NOSUPP;

	*ks_tuple_strs = NULL;
	if (n_ks_tuple < 1)
		return 0;

	if ((ksnames = calloc(n_ks_tuple, sizeof (*ksnames))) == NULL)
		return (errno);

	for (i = 0; i < n_ks_tuple; i++) {
	    if (krb5_enctype_to_string(context, ks_tuple[i].ks_enctype, &ename))
		goto out;
	    if (krb5_salttype_to_string(context, ks_tuple[i].ks_enctype,
					ks_tuple[i].ks_salttype, &sname))
		goto out;

	    if (asprintf(&ksnames[i], "%s:%s", ename, sname) == -1) {
		    rc = errno;
		    free(ename);
		    free(sname);
		    goto out;
	    }
	    free(ename);
	    free(sname);
	}

	*ks_tuple_strs = ksnames;
	rc = 0;

out:
	for (i = 0; i < n_ks_tuple; i++)
		free(ksnames[i]);
	free(ksnames);
	return (rc);
}

/*
 * Generate the `key_set' from the [kadmin]default_keys statement. If
 * `no_salt' is set, salt is not important (and will not be set) since
 * it's random keys that is going to be created.
 */

krb5_error_code
hdb_generate_key_set(krb5_context context, krb5_principal principal,
		     int n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
		     Key **ret_key_set, size_t *nkeyset, int no_salt)
{
    char **ktypes = NULL;
    char **kp;
    krb5_error_code ret;
    Key *k, *key_set;
    size_t i, j;
    char **ks_tuple_strs;
    static const char *default_keytypes[] = {
	"aes256-cts-hmac-sha1-96:pw-salt",
	"des3-cbc-sha1:pw-salt",
	"arcfour-hmac-md5:pw-salt",
	NULL
    };

    if ((ret = ks_tuple2str(context, n_ks_tuple, ks_tuple, &ks_tuple_strs)))
	    return ret;

    if (ks_tuple_strs == NULL)
	ktypes = krb5_config_get_strings(context, NULL, "kadmin",
					 "default_keys", NULL);
    if (ktypes == NULL)
	ktypes = (char **)(intptr_t)default_keytypes;

    *ret_key_set = key_set = NULL;
    *nkeyset = 0;

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
	else if (strcmp(p, "arcfour-hmac-md5") == 0)
	    p = "arcfour-hmac-md5:pw-salt";

	memset(&salt, 0, sizeof(salt));

	ret = parse_key_set(context, p,
			    &enctypes, &num_enctypes, &salt, principal);
	if (ret) {
	    krb5_warn(context, ret, "bad value for default_keys `%s'", *kp);
	    ret = 0;
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
		if (ret) {
		    free(enctypes);
		    krb5_free_salt(context, salt);
		    goto out;
		}
	    }
	}
	free(enctypes);
	krb5_free_salt(context, salt);
    }

    *ret_key_set = key_set;

 out:
    if (ktypes != (char **)(intptr_t)default_keytypes)
	krb5_config_free_strings(ktypes);

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

    return ret;
}


krb5_error_code
hdb_generate_key_set_password(krb5_context context,
			      krb5_principal principal,
			      const char *password,
			      Key **keys, size_t *num_keys)
{
    krb5_error_code ret;
    size_t i;

    ret = hdb_generate_key_set(context, principal, 0, NULL,
				keys, num_keys, 0);
    if (ret)
	return ret;

    for (i = 0; i < (*num_keys); i++) {
	krb5_salt salt;

	salt.salttype = (*keys)[i].salt->type;
	salt.saltvalue.length = (*keys)[i].salt->salt.length;
	salt.saltvalue.data = (*keys)[i].salt->salt.data;

	ret = krb5_string_to_key_salt (context,
				       (*keys)[i].key.keytype,
				       password,
				       salt,
				       &(*keys)[i].key);

	if(ret)
	    break;
    }

    if(ret) {
	hdb_free_keys (context, *num_keys, *keys);
	return ret;
    }
    return ret;
}
