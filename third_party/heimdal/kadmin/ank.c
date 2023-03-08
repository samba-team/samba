/*
 * Copyright (c) 1997-2006 Kungliga Tekniska Högskolan
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

#include "kadmin_locl.h"
#include "kadmin-commands.h"

/* No useful password policies for namespaces */
#define NSPOLICY "default"

/*
 * fetch the default principal corresponding to `princ'
 */

static krb5_error_code
get_default (kadm5_server_context *contextp,
	     krb5_principal princ,
	     kadm5_principal_ent_t default_ent)
{
    krb5_error_code ret;
    krb5_principal def_principal;
    krb5_const_realm realm = krb5_principal_get_realm(contextp->context, princ);

    ret = krb5_make_principal (contextp->context, &def_principal,
			       realm, "default", NULL);
    if (ret)
	return ret;
    ret = kadm5_get_principal (contextp, def_principal, default_ent,
			       KADM5_PRINCIPAL_NORMAL_MASK);
    krb5_free_principal (contextp->context, def_principal);
    return ret;
}

/*
 * Add the principal `name' to the database.
 * Prompt for all data not given by the input parameters.
 */

static krb5_error_code
add_one_principal(const char *name,
                  int rand_key,
                  int rand_password,
                  int use_defaults,
                  char *password,
                  char *policy,
                  size_t nkstuple,
                  krb5_key_salt_tuple *kstuple,
                  krb5_key_data *key_data,
                  const char *max_ticket_life,
                  const char *max_renewable_life,
                  const char *attributes,
                  const char *expiration,
                  const char *pw_expiration)
{
    krb5_error_code ret;
    kadm5_principal_ent_rec princ, defrec;
    kadm5_principal_ent_rec *default_ent = NULL;
    krb5_principal princ_ent = NULL;
    krb5_timestamp pw_expire;
    int mask = 0;
    int default_mask = 0;
    char pwbuf[1024];
    char *princ_name = NULL;

    memset(&princ, 0, sizeof(princ));
    ret = krb5_parse_name(context, name, &princ_ent);
    if (ret) {
	krb5_warn(context, ret, "krb5_parse_name");
	return ret;
    }

    if (rand_password) {
	ret = krb5_unparse_name(context, princ_ent, &princ_name);
	if (ret) {
	    krb5_warn(context, ret, "krb5_parse_name");
	    goto out;
	}
    }
    princ.principal = princ_ent;
    mask |= KADM5_PRINCIPAL;

    ret = set_entry(context, &princ, &mask,
		    max_ticket_life, max_renewable_life,
		    expiration, pw_expiration, attributes, policy);
    if (ret)
	goto out;

    default_ent = &defrec;
    ret = get_default (kadm_handle, princ_ent, default_ent);
    if (ret) {
	default_ent  = NULL;
	default_mask = 0;
    } else {
	default_mask = KADM5_ATTRIBUTES | KADM5_MAX_LIFE | KADM5_MAX_RLIFE |
	    KADM5_PRINC_EXPIRE_TIME | KADM5_PW_EXPIRATION;
    }

    if(use_defaults)
	set_defaults(&princ, &mask, default_ent, default_mask);
    else
	if(edit_entry(&princ, &mask, default_ent, default_mask))
	    goto out;
    if(rand_key || key_data) {
	princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
	mask |= KADM5_ATTRIBUTES;
	random_password (pwbuf, sizeof(pwbuf));
	password = pwbuf;
    } else if (rand_password) {
	random_password (pwbuf, sizeof(pwbuf));
	password = pwbuf;
    } else if(password == NULL) {
	char *prompt;
	int aret;

	ret = krb5_unparse_name(context, princ_ent, &princ_name);
	if (ret)
	    goto out;
	aret = asprintf (&prompt, "%s's Password: ", princ_name);
	if (aret == -1) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "out of memory");
	    goto out;
	}
	ret = UI_UTIL_read_pw_string (pwbuf, sizeof(pwbuf), prompt,
				      UI_UTIL_FLAG_VERIFY |
				      UI_UTIL_FLAG_VERIFY_SILENT);
	free (prompt);
	if (ret) {
	    ret = KRB5_LIBOS_BADPWDMATCH;
	    krb5_set_error_message(context, ret, "failed to verify password");
	    goto out;
	}
	password = pwbuf;
    }

    ret = kadm5_create_principal(kadm_handle, &princ, mask, password);
    if(ret) {
	krb5_warn(context, ret, "kadm5_create_principal");
	goto out;
    }
    /* Save requested password expiry before it's clobbered */
    pw_expire = princ.pw_expiration;
    if (rand_key) {
	krb5_keyblock *new_keys;
	int n_keys, i;
	ret = kadm5_randkey_principal_3(kadm_handle, princ_ent, 0,
                                        nkstuple, kstuple, &new_keys, &n_keys);
	if(ret){
	    krb5_warn(context, ret, "kadm5_randkey_principal");
	    n_keys = 0;
	}
	for(i = 0; i < n_keys; i++)
	    krb5_free_keyblock_contents(context, &new_keys[i]);
	if (n_keys > 0)
	    free(new_keys);
        ret = kadm5_get_principal(kadm_handle, princ_ent, &princ,
                                  KADM5_PRINCIPAL | KADM5_KVNO |
                                      KADM5_ATTRIBUTES);
        if (ret) {
            krb5_warn(context, ret, "kadm5_get_principal");
            goto out;
        }
        krb5_free_principal(context, princ_ent);
        princ_ent = princ.principal;
	princ.attributes &= (~KRB5_KDB_DISALLOW_ALL_TIX);
	princ.pw_expiration = pw_expire;
	/*
	 * Updating kvno w/o key data and vice-versa gives _kadm5_setup_entry()
	 * and _kadm5_set_keys2() headaches.  But we used to, so we handle
	 * this in in those two functions.  Might as well leave this code as
	 * it was then.
	 */
	princ.kvno = 1;
	kadm5_modify_principal(kadm_handle, &princ,
			       KADM5_PW_EXPIRATION | KADM5_ATTRIBUTES | KADM5_KVNO);
    } else if (key_data) {
	ret = kadm5_chpass_principal_with_key (kadm_handle, princ_ent,
					       3, key_data);
	if (ret) {
	    krb5_warn(context, ret, "kadm5_chpass_principal_with_key");
	}
	kadm5_get_principal(kadm_handle, princ_ent, &princ,
			    KADM5_PRINCIPAL | KADM5_ATTRIBUTES);
        krb5_free_principal(context, princ_ent);
        princ_ent = princ.principal;
	princ.attributes &= (~KRB5_KDB_DISALLOW_ALL_TIX);
	princ.pw_expiration = pw_expire;
	kadm5_modify_principal(kadm_handle, &princ,
			       KADM5_PW_EXPIRATION | KADM5_ATTRIBUTES);
    } else if (rand_password) {
	printf ("added %s with password \"%s\"\n", princ_name, password);
    }
out:
    free(princ_name);
    kadm5_free_principal_ent(kadm_handle, &princ); /* frees princ_ent */
    if(default_ent)
	kadm5_free_principal_ent (kadm_handle, default_ent);
    if (password != NULL) {
	size_t len = strlen(password);
	memset_s(password, len, 0, len);
    }
    return ret;
}

/*
 * parse the string `key_string' into `key', returning 0 iff succesful.
 */

/*
 * the ank command
 */

/*
 * Parse arguments and add all the principals.
 */

int
add_new_key(struct add_options *opt, int argc, char **argv)
{
    krb5_error_code ret = 0;
    krb5_key_salt_tuple *kstuple = NULL;
    krb5_key_data key_data[3];
    krb5_key_data *kdp = NULL;
    const char *enctypes;
    size_t i, nkstuple;
    int num;

    num = 0;
    if (opt->random_key_flag)
	++num;
    if (opt->random_password_flag)
	++num;
    if (opt->password_string)
	++num;
    if (opt->key_string)
	++num;

    if (num > 1) {
	fprintf (stderr, "give only one of "
		"--random-key, --random-password, --password, --key\n");
	return 1;
    }

    enctypes = opt->enctypes_string;
    if (enctypes == NULL || enctypes[0] == '\0')
        enctypes = krb5_config_get_string(context, NULL, "libdefaults",
                                          "supported_enctypes", NULL);
    if (enctypes == NULL || enctypes[0] == '\0')
        enctypes = "aes128-cts-hmac-sha1-96";
    ret = krb5_string_to_keysalts2(context, enctypes, &nkstuple, &kstuple);
    if (ret) {
        fprintf(stderr, "enctype(s) unknown\n");
        return ret;
    }


    if (opt->key_string) {
	const char *error;

	if (parse_des_key (opt->key_string, key_data, &error)) {
	    fprintf(stderr, "failed parsing key \"%s\": %s\n",
		    opt->key_string, error);
            free(kstuple);
	    return 1;
	}
	kdp = key_data;
    }

    for(i = 0; i < argc; i++) {
        ret = add_one_principal(argv[i],
                                opt->random_key_flag,
                                opt->random_password_flag,
                                opt->use_defaults_flag,
                                opt->password_string,
                                opt->policy_string,
                                nkstuple,
                                kstuple,
                                kdp,
                                opt->max_ticket_life_string,
                                opt->max_renewable_life_string,
                                opt->attributes_string,
                                opt->expiration_time_string,
                                opt->pw_expiration_time_string);
	if (ret) {
	    krb5_warn (context, ret, "adding %s", argv[i]);
	    break;
	}
    }
    if (kdp) {
	int16_t dummy = 3;
	kadm5_free_key_data (kadm_handle, &dummy, key_data);
    }
    free(kstuple);
    return ret != 0;
}

static krb5_error_code
kstuple2etypes(kadm5_principal_ent_rec *rec,
               int *maskp,
               size_t nkstuple,
               krb5_key_salt_tuple *kstuple)
{
    krb5_error_code ret;
    HDB_EncTypeList etypes;
    krb5_data buf;
    size_t len, i;

    etypes.len = 0;
    if ((etypes.val = calloc(nkstuple, sizeof(etypes.val[0]))) == NULL)
        return krb5_enomem(context);
    for (i = 0; i < nkstuple; i++)
        etypes.val[i] = kstuple[i].ks_enctype;
    ASN1_MALLOC_ENCODE(HDB_EncTypeList, buf.data, buf.length,
                       &etypes, &len, ret);
    if (ret == 0)
        add_tl(rec, KRB5_TL_ETYPES, &buf);
    free(etypes.val);
    if (ret == 0)
        (*maskp) |= KADM5_TL_DATA;
    return ret;
}

/*
 * Add the namespace `name' to the database.
 * Prompt for all data not given by the input parameters.
 */
static krb5_error_code
add_one_namespace(const char *name,
                  size_t nkstuple,
                  krb5_key_salt_tuple *kstuple,
                  const char *max_ticket_life,
                  const char *max_renewable_life,
                  const char *key_rotation_epoch,
                  const char *key_rotation_period,
                  const char *attributes)
{
    krb5_error_code ret;
    kadm5_principal_ent_rec princ;
    krb5_principal princ_ent = NULL;
    int mask = 0;
    int default_mask = 0;
    HDB_extension ext;
    krb5_data buf;
    const char *comp0;
    const char *comp1;
    time_t kre;
    char pwbuf[1024];
    krb5_deltat krp;

    if (!key_rotation_epoch) {
	krb5_warnx(context, "key rotation epoch defaulted to \"now\"");
        key_rotation_epoch = "now";
    }
    if (!key_rotation_period) {
	krb5_warnx(context, "key rotation period defaulted to \"5d\"");
        key_rotation_period = "5d";
    }
    if ((ret = str2time_t(key_rotation_epoch, &kre)) != 0) {
	krb5_warn(context, ret, "invalid rotation epoch: %s",
                  key_rotation_epoch);
        return ret;
    }
    if (ret == 0 && (ret = str2deltat(key_rotation_period, &krp)) != 0) {
	krb5_warn(context, ret, "invalid rotation period: %s",
                  key_rotation_period);
        return ret;
    }

    if (ret == 0) {
        memset(&princ, 0, sizeof(princ));
        princ.kvno = 1;
        ret = krb5_parse_name(context, name, &princ_ent);
        if (ret)
            krb5_warn(context, ret, "krb5_parse_name");
	else
	    princ.principal = princ_ent;
    }
    if (ret != 0)
	return ret;

    /*
     * Check that namespace has exactly one component, and prepend
     * WELLKNOWN/HOSTBASED-NAMESPACE
     */
    if (krb5_principal_get_num_comp(context, princ_ent) != 2
        || (comp0 = krb5_principal_get_comp_string(context, princ_ent, 0)) == 0
        || (comp1 = krb5_principal_get_comp_string(context, princ_ent, 1)) == 0
        || *comp0 == 0 || *comp1 == 0
        || strcmp(comp0, "krbtgt") == 0)
	krb5_warn(context, ret = EINVAL,
                  "namespaces must have exactly two non-empty components "
                  "like host-base principal names");
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, princ_ent, 2, comp0);
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, princ_ent, 3, comp1);
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, princ_ent, 0,
                                             "WELLKNOWN");
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, princ_ent, 1,
                                             HDB_WK_NAMESPACE);

    /* Set up initial key rotation extension */
    if (ret == 0) {
        KeyRotation kr;
        size_t size;

        /* Setup key rotation metadata in a convenient way */
        kr.flags = int2KeyRotationFlags(0);
        kr.base_key_kvno = 1;
        /*
         * Avoid kvnos 0/1/2 which don't normally appear in fully created
         * principals.
         */
        kr.base_kvno = 3;

        /* XXX: Sanity check */
        kr.epoch = kre;
        kr.period = krp;

        memset(&ext, 0, sizeof(ext));
        ext.mandatory = FALSE;
        ext.data.element =  choice_HDB_extension_data_key_rotation;
        ext.data.u.key_rotation.len = 1;
        ext.data.u.key_rotation.val = &kr;

        ASN1_MALLOC_ENCODE(HDB_extension, buf.data, buf.length,
                           &ext, &size, ret);
        add_tl(&princ, KRB5_TL_EXTENSION, &buf);
        mask |= KADM5_TL_DATA;
    }

    if (ret == 0) {
        mask |= KADM5_PRINCIPAL | KADM5_KVNO;

        ret = set_entry(context, &princ, &mask,
                        max_ticket_life, max_renewable_life,
                        "never", "never", attributes, NSPOLICY);
    }
    if (ret == 0)
        ret = edit_entry(&princ, &mask, NULL, default_mask);

    if (ret == 0)
        ret = kstuple2etypes(&princ, &mask, nkstuple, kstuple);

    /* XXX Shouldn't need a password for this */
    random_password(pwbuf, sizeof(pwbuf));
    if (ret == 0) {
        ret = kadm5_create_principal_3(kadm_handle, &princ, mask,
                                       nkstuple, kstuple, pwbuf);
        if (ret)
            krb5_warn(context, ret, "kadm5_create_principal_3");
    }

    kadm5_free_principal_ent(kadm_handle, &princ); /* frees princ_ent */
    memset(pwbuf, 0, sizeof(pwbuf));
    return ret;
}

int
add_new_namespace(struct add_namespace_options *opt, int argc, char **argv)
{
    krb5_error_code ret = 0;
    krb5_key_salt_tuple *kstuple = NULL;
    const char *enctypes;
    size_t i, nkstuple;

    if (argc < 1) {
        fprintf(stderr, "at least one namespace name required\n");
        return 1;
    }

    enctypes = opt->enctypes_string;
    if (enctypes == NULL || enctypes[0] == '\0')
        enctypes = krb5_config_get_string(context, NULL, "libdefaults",
                                          "supported_enctypes", NULL);
    if (enctypes == NULL || enctypes[0] == '\0')
        enctypes = "aes128-cts-hmac-sha1-96";
    ret = krb5_string_to_keysalts2(context, enctypes, &nkstuple, &kstuple);
    if (ret) {
        fprintf(stderr, "enctype(s) unknown\n");
        return ret;
    }

    for (i = 0; i < argc; i++) {
        ret = add_one_namespace(argv[i], nkstuple, kstuple,
                                opt->max_ticket_life_string,
                                opt->max_renewable_life_string,
                                opt->key_rotation_epoch_string,
                                opt->key_rotation_period_string,
                                opt->attributes_string);
	if (ret) {
	    krb5_warn(context, ret, "adding namespace %s", argv[i]);
	    break;
	}
    }

    free(kstuple);
    return ret != 0;
}
