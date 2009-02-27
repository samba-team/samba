/*
 * Copyright (c) 1997 - 2009 Kungliga Tekniska Högskolan
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

#define KRB5_DEPRECATED

#include "krb5_locl.h"

#ifndef HEIMDAL_SMALLER

/**
 * Same as krb5_data_free().
 *
 * @param context Kerberos 5 context.
 * @param data krb5_data to free.
 *
 * @ingroup krb5
 */

void KRB5_LIB_FUNCTION
krb5_free_data_contents(krb5_context context, krb5_data *data)
  KRB5_DEPRECATED
{
    krb5_data_free(data);
}

/*
 * First take the configured list of etypes for `keytype' if available,
 * else, do `krb5_keytype_to_enctypes'.
 */

krb5_error_code KRB5_LIB_FUNCTION
krb5_keytype_to_enctypes_default (krb5_context context,
				  krb5_keytype keytype,
				  unsigned *len,
				  krb5_enctype **val)
    KRB5_DEPRECATED
{
    unsigned int i, n;
    krb5_enctype *ret;

    if (keytype != KEYTYPE_DES || context->etypes_des == NULL)
	return krb5_keytype_to_enctypes (context, keytype, len, val);

    for (n = 0; context->etypes_des[n]; ++n)
	;
    ret = malloc (n * sizeof(*ret));
    if (ret == NULL && n != 0) {
	krb5_set_error_message(context, ENOMEM, N_("malloc: out of memory", ""));
	return ENOMEM;
    }
    for (i = 0; i < n; ++i)
	ret[i] = context->etypes_des[i];
    *len = n;
    *val = ret;
    return 0;
}


static struct {
    const char *name;
    krb5_keytype type;
} keys[] = {
    { "null", ENCTYPE_NULL },
    { "des", ETYPE_DES_CBC_CRC },
    { "des3", ETYPE_OLD_DES3_CBC_SHA1 },
    { "aes-128", ETYPE_AES128_CTS_HMAC_SHA1_96 },
    { "aes-256", ETYPE_AES256_CTS_HMAC_SHA1_96 },
    { "arcfour", ETYPE_ARCFOUR_HMAC_MD5 },
    { "arcfour-56", ETYPE_ARCFOUR_HMAC_MD5_56 }
};

static int num_keys = sizeof(keys) / sizeof(keys[0]);

krb5_error_code KRB5_LIB_FUNCTION
krb5_keytype_to_string(krb5_context context,
		       krb5_keytype keytype,
		       char **string)
    KRB5_DEPRECATED
{
    const char *name;
    int i;

    for(i = 0; i < num_keys; i++) {
	if(keys[i].type == keytype) {
	    name = keys[i].name;
	    break;
	}
    }

    if(i >= num_keys) {
	krb5_set_error_message(context, KRB5_PROG_KEYTYPE_NOSUPP,
			       "key type %d not supported", keytype);
	return KRB5_PROG_KEYTYPE_NOSUPP;
    }
    *string = strdup(name);
    if(*string == NULL) {
	krb5_set_error_message(context, ENOMEM,
			       N_("malloc: out of memory", ""));
	return ENOMEM;
    }
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_string_to_keytype(krb5_context context,
		       const char *string,
		       krb5_keytype *keytype)
    KRB5_DEPRECATED
{
    char *end;
    int i;

    for(i = 0; i < num_keys; i++)
	if(strcasecmp(keys[i].name, string) == 0){
	    *keytype = keys[i].type;
	    return 0;
	}

    /* check if the enctype is a number */
    *keytype = strtol(string, &end, 0);
    if(*end == '\0' && *keytype != 0) {
	if (krb5_enctype_valid(context, *keytype) == 0)
	    return 0;
    }

    krb5_set_error_message(context, KRB5_PROG_KEYTYPE_NOSUPP,
			   "key type %s not supported", string);
    return KRB5_PROG_KEYTYPE_NOSUPP;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_password_key_proc (krb5_context context,
			krb5_enctype type,
			krb5_salt salt,
			krb5_const_pointer keyseed,
			krb5_keyblock **key)
    KRB5_DEPRECATED
{
    krb5_error_code ret;
    const char *password = (const char *)keyseed;
    char buf[BUFSIZ];

    *key = malloc (sizeof (**key));
    if (*key == NULL) {
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }
    if (password == NULL) {
	if(UI_UTIL_read_pw_string (buf, sizeof(buf), "Password: ", 0)) {
	    free (*key);
	    krb5_clear_error_message(context);
	    return KRB5_LIBOS_PWDINTR;
	}
	password = buf;
    }
    ret = krb5_string_to_key_salt (context, type, password, salt, *key);
    memset (buf, 0, sizeof(buf));
    return ret;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_get_in_tkt_with_password (krb5_context context,
			       krb5_flags options,
			       krb5_addresses *addrs,
			       const krb5_enctype *etypes,
			       const krb5_preauthtype *pre_auth_types,
			       const char *password,
			       krb5_ccache ccache,
			       krb5_creds *creds,
			       krb5_kdc_rep *ret_as_reply)
    KRB5_DEPRECATED
{
     return krb5_get_in_tkt (context,
			     options,
			     addrs,
			     etypes,
			     pre_auth_types,
			     krb5_password_key_proc,
			     password,
			     NULL,
			     NULL,
			     creds,
			     ccache,
			     ret_as_reply);
}

static krb5_error_code
krb5_skey_key_proc (krb5_context context,
		    krb5_enctype type,
		    krb5_salt salt,
		    krb5_const_pointer keyseed,
		    krb5_keyblock **key)
{
    return krb5_copy_keyblock (context, keyseed, key);
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_get_in_tkt_with_skey (krb5_context context,
			   krb5_flags options,
			   krb5_addresses *addrs,
			   const krb5_enctype *etypes,
			   const krb5_preauthtype *pre_auth_types,
			   const krb5_keyblock *key,
			   krb5_ccache ccache,
			   krb5_creds *creds,
			   krb5_kdc_rep *ret_as_reply)
    KRB5_DEPRECATED
{
    if(key == NULL)
	return krb5_get_in_tkt_with_keytab (context,
					    options,
					    addrs,
					    etypes,
					    pre_auth_types,
					    NULL,
					    ccache,
					    creds,
					    ret_as_reply);
    else
	return krb5_get_in_tkt (context,
				options,
				addrs,
				etypes,
				pre_auth_types,
				krb5_skey_key_proc,
				key,
				NULL,
				NULL,
				creds,
				ccache,
				ret_as_reply);
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_keytab_key_proc (krb5_context context,
		      krb5_enctype enctype,
		      krb5_salt salt,
		      krb5_const_pointer keyseed,
		      krb5_keyblock **key)
    KRB5_DEPRECATED
{
    krb5_keytab_key_proc_args *args  = rk_UNCONST(keyseed);
    krb5_keytab keytab = args->keytab;
    krb5_principal principal  = args->principal;
    krb5_error_code ret;
    krb5_keytab real_keytab;
    krb5_keytab_entry entry;

    if(keytab == NULL)
	krb5_kt_default(context, &real_keytab);
    else
	real_keytab = keytab;

    ret = krb5_kt_get_entry (context, real_keytab, principal,
			     0, enctype, &entry);

    if (keytab == NULL)
	krb5_kt_close (context, real_keytab);

    if (ret)
	return ret;

    ret = krb5_copy_keyblock (context, &entry.keyblock, key);
    krb5_kt_free_entry(context, &entry);
    return ret;
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_get_in_tkt_with_keytab (krb5_context context,
			     krb5_flags options,
			     krb5_addresses *addrs,
			     const krb5_enctype *etypes,
			     const krb5_preauthtype *pre_auth_types,
			     krb5_keytab keytab,
			     krb5_ccache ccache,
			     krb5_creds *creds,
			     krb5_kdc_rep *ret_as_reply)
    KRB5_DEPRECATED
{
    krb5_keytab_key_proc_args a;

    a.principal = creds->client;
    a.keytab    = keytab;

    return krb5_get_in_tkt (context,
			    options,
			    addrs,
			    etypes,
			    pre_auth_types,
			    krb5_keytab_key_proc,
			    &a,
			    NULL,
			    NULL,
			    creds,
			    ccache,
			    ret_as_reply);
}

static krb5_boolean
convert_func(krb5_context conxtext, void *funcctx, krb5_principal principal)
{
    krb5_boolean (*func)(krb5_context, krb5_principal) = funcctx;
    return (*func)(conxtext, principal);
}

krb5_error_code KRB5_LIB_FUNCTION
krb5_425_conv_principal_ext(krb5_context context,
			    const char *name,
			    const char *instance,
			    const char *realm,
			    krb5_boolean (*func)(krb5_context, krb5_principal),
			    krb5_boolean resolve,
			    krb5_principal *principal)
    KRB5_DEPRECATED
{
    return krb5_425_conv_principal_ext2(context,
					name,
					instance,
					realm,
					func ? convert_func : NULL,
					func,
					resolve,
					principal);
}


krb5_error_code KRB5_LIB_FUNCTION
krb5_425_conv_principal(krb5_context context,
			const char *name,
			const char *instance,
			const char *realm,
			krb5_principal *princ)
    KRB5_DEPRECATED
{
    krb5_boolean resolve = krb5_config_get_bool(context,
						NULL,
						"libdefaults",
						"v4_instance_resolve",
						NULL);

    return krb5_425_conv_principal_ext(context, name, instance, realm,
				       NULL, resolve, princ);
}

#endif /* HEIMDAL_SMALLER */
