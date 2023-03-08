/*
 * Copyright (c) 1997-2002 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"
#include "hdb_locl.h"

int
hdb_principal2key(krb5_context context, krb5_const_principal p, krb5_data *key)
{
    Principal new;
    size_t len = 0;
    int ret;

    ret = copy_Principal(p, &new);
    if(ret)
	return ret;
    new.name.name_type = 0;

    ASN1_MALLOC_ENCODE(Principal, key->data, key->length, &new, &len, ret);
    if (ret == 0 && key->length != len)
	krb5_abortx(context, "internal asn.1 encoder error");
    free_Principal(&new);
    return ret;
}

int
hdb_key2principal(krb5_context context, krb5_data *key, krb5_principal p)
{
    return decode_Principal(key->data, key->length, p, NULL);
}

int
hdb_entry2value(krb5_context context, const hdb_entry *ent, krb5_data *value)
{
    size_t len = 0;
    int ret;

    ASN1_MALLOC_ENCODE(HDB_entry, value->data, value->length, ent, &len, ret);
    if (ret == 0 && value->length != len)
	krb5_abortx(context, "internal asn.1 encoder error");
    return ret;
}

int
hdb_value2entry(krb5_context context, krb5_data *value, hdb_entry *ent)
{
    return decode_HDB_entry(value->data, value->length, ent, NULL);
}

int
hdb_entry_alias2value(krb5_context context,
		      const hdb_entry_alias *alias,
		      krb5_data *value)
{
    size_t len = 0;
    int ret;

    ASN1_MALLOC_ENCODE(HDB_entry_alias, value->data, value->length,
		       alias, &len, ret);
    if (ret == 0 && value->length != len)
	krb5_abortx(context, "internal asn.1 encoder error");
    return ret;
}

int
hdb_value2entry_alias(krb5_context context, krb5_data *value,
		      hdb_entry_alias *ent)
{
    return decode_HDB_entry_alias(value->data, value->length, ent, NULL);
}

/*
 * Some old databases may not have stored the salt with each key, which will
 * break clients when aliases or canonicalization are used. Generate a
 * default salt based on the real principal name in the entry to handle
 * this case.
 */
static krb5_error_code
add_default_salts(krb5_context context, HDB *db, hdb_entry *entry)
{
    krb5_error_code ret;
    size_t i;
    krb5_salt pwsalt;

    ret = krb5_get_pw_salt(context, entry->principal, &pwsalt);
    if (ret)
	return ret;

    for (i = 0; i < entry->keys.len; i++) {
	Key *key = &entry->keys.val[i];

	if (key->salt != NULL ||
	    _krb5_enctype_requires_random_salt(context, key->key.keytype))
	    continue;

	key->salt = calloc(1, sizeof(*key->salt));
	if (key->salt == NULL) {
	    ret = krb5_enomem(context);
	    break;
	}

	key->salt->type = KRB5_PADATA_PW_SALT;

	ret = krb5_data_copy(&key->salt->salt,
			     pwsalt.saltvalue.data,
			     pwsalt.saltvalue.length);
	if (ret)
	    break;
    }

    krb5_free_salt(context, pwsalt);

    return ret;
}

static krb5_error_code
fetch_entry_or_alias(krb5_context context,
                     HDB *db,
                     krb5_const_principal principal,
                     unsigned flags,
                     hdb_entry *entry)
{
    HDB_EntryOrAlias eoa;
    krb5_principal enterprise_principal = NULL;
    krb5_data key, value;
    krb5_error_code ret;

    value.length = 0;
    value.data = 0;
    key = value;

    if (principal->name.name_type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
	if (principal->name.name_string.len != 1) {
	    ret = KRB5_PARSE_MALFORMED;
	    krb5_set_error_message(context, ret, "malformed principal: "
				   "enterprise name with %d name components",
				   principal->name.name_string.len);
	    return ret;
	}
	ret = krb5_parse_name(context, principal->name.name_string.val[0],
			      &enterprise_principal);
	if (ret)
	    return ret;
	principal = enterprise_principal;
    }

    ret = hdb_principal2key(context, principal, &key);
    if (ret == 0)
        ret = db->hdb__get(context, db, key, &value);
    if (ret == 0)
        ret = decode_HDB_EntryOrAlias(value.data, value.length, &eoa, NULL);
    if (ret == 0 && eoa.element == choice_HDB_EntryOrAlias_entry) {
        *entry = eoa.u.entry;
        entry->aliased = 0;
    } else if (ret == 0 && eoa.element == choice_HDB_EntryOrAlias_alias) {
        krb5_data_free(&key);
	ret = hdb_principal2key(context, eoa.u.alias.principal, &key);
        if (ret == 0) {
	    krb5_data_free(&value);
            ret = db->hdb__get(context, db, key, &value);
	}
        if (ret == 0)
            /* No alias chaining */
            ret = hdb_value2entry(context, &value, entry);
	krb5_free_principal(context, eoa.u.alias.principal);
        entry->aliased = 1;
    } else if (ret == 0)
        ret = ENOTSUP;
    if (ret == 0 && enterprise_principal) {
	/*
	 * Whilst Windows does not canonicalize enterprise principal names if
	 * the canonicalize flag is unset, the original specification in
	 * draft-ietf-krb-wg-kerberos-referrals-03.txt says we should.
	 */
	entry->flags.force_canonicalize = 1;
    }

#if 0
    /* HDB_F_GET_ANY indicates request originated from KDC (not kadmin) */
    if (ret == 0 && eoa.element == choice_HDB_EntryOrAlias_alias &&
        (flags & (HDB_F_CANON|HDB_F_GET_ANY)) == 0) {

        /* `principal' was alias but canon not req'd */
        free_HDB_entry(entry);
        ret = HDB_ERR_NOENTRY;
    }
#endif

    krb5_free_principal(context, enterprise_principal);
    krb5_data_free(&value);
    krb5_data_free(&key);
    principal = enterprise_principal = NULL;
    return ret;
}

/*
 * We have only one type of aliases in our HDB entries, but we really need two:
 * hard and soft.
 *
 * Hard aliases should be treated as if they were distinct principals with the
 * same keys.
 *
 * Soft aliases should be treated as configuration to issue referrals, and they
 * can only result in referrals to other realms.
 *
 * Rather than add a type of aliases, we'll use a convention where the form of
 * the target of the alias indicates whether the alias is hard or soft.
 *
 * TODO We could also use an attribute of the aliased entry.
 */
static int
is_soft_alias_p(krb5_context context,
                krb5_const_principal principal,
                unsigned int flags,
                hdb_entry *h)
{
    /* Target is a WELLKNOWN/REFERRALS/TARGET/... -> soft alias */
    if (krb5_principal_get_num_comp(context, h->principal) >= 3 &&
        strcmp(krb5_principal_get_comp_string(context, h->principal, 0),
               KRB5_WELLKNOWN_NAME) == 0 &&
        strcmp(krb5_principal_get_comp_string(context, h->principal, 1),
               "REFERRALS") == 0 &&
        strcmp(krb5_principal_get_comp_string(context, h->principal, 2),
               "TARGET") == 0)
        return 1;

    /*
     * Pre-8.0 we had only soft aliases for a while, and one site used aliases
     * of referrals-targetNN@TARGET-REALM.
     */
    if (krb5_principal_get_num_comp(context, h->principal) == 1 &&
        strncmp("referrals-target",
                krb5_principal_get_comp_string(context, h->principal, 0),
                sizeof("referrals-target") - 1) == 0)
        return 1;

    /* All other cases are hard aliases */
    return 0;
}

krb5_error_code
_hdb_fetch_kvno(krb5_context context, HDB *db, krb5_const_principal principal,
		unsigned flags, krb5_kvno kvno, hdb_entry *entry)
{
    krb5_error_code ret;
    int soft_aliased = 0;
    int same_realm;

    ret = fetch_entry_or_alias(context, db, principal, flags, entry);
    if (ret)
        return ret;

    if ((flags & HDB_F_DECRYPT) && (flags & HDB_F_ALL_KVNOS)) {
	/* Decrypt the current keys */
	ret = hdb_unseal_keys(context, db, entry);
	if (ret) {
	    hdb_free_entry(context, db, entry);
	    return ret;
	}
	/* Decrypt the key history too */
	ret = hdb_unseal_keys_kvno(context, db, 0, flags, entry);
	if (ret) {
	    hdb_free_entry(context, db, entry);
	    return ret;
	}
    } else if ((flags & HDB_F_DECRYPT)) {
	if ((flags & HDB_F_KVNO_SPECIFIED) == 0 || kvno == entry->kvno) {
	    /* Decrypt the current keys */
	    ret = hdb_unseal_keys(context, db, entry);
	    if (ret) {
		hdb_free_entry(context, db, entry);
		return ret;
	    }
	} else {
	    if ((flags & HDB_F_ALL_KVNOS))
		kvno = 0;
	    /*
	     * Find and decrypt the keys from the history that we want,
	     * and swap them with the current keys
	     */
	    ret = hdb_unseal_keys_kvno(context, db, kvno, flags, entry);
	    if (ret) {
		hdb_free_entry(context, db, entry);
		return ret;
	    }
	}
    }
    if ((flags & HDB_F_FOR_AS_REQ) && (flags & HDB_F_GET_CLIENT)) {
	/*
	 * Generate default salt for any principals missing one; note such
	 * principals could include those for which a random (non-password)
	 * key was generated, but given the salt will be ignored by a keytab
	 * client it doesn't hurt to include the default salt.
	 */
	ret = add_default_salts(context, db, entry);
	if (ret) {
	    hdb_free_entry(context, db, entry);
	    return ret;
	}
    }

    if (!entry->aliased)
        return 0;

    soft_aliased = is_soft_alias_p(context, principal, flags, entry);

    /* Never return HDB_ERR_WRONG_REALM to kadm5 or other non-KDC callers */
    if ((flags & HDB_F_ADMIN_DATA))
        return 0;

    same_realm = krb5_realm_compare(context, principal, entry->principal);

    if (entry->aliased && !soft_aliased) {
        /*
         * This is a hard alias.  We'll make the entry's name be the same as
         * the alias.
         *
         * Except, we allow for disabling this for same-realm aliases, mainly
         * for our tests.
         */
        if (same_realm &&
            krb5_config_get_bool_default(context, NULL, FALSE, "hdb",
                                         "same_realm_aliases_are_soft", NULL))
            return 0;

        /* EPNs are always soft */
        if (principal->name.name_type != KRB5_NT_ENTERPRISE_PRINCIPAL) {
            krb5_free_principal(context, entry->principal);
            ret = krb5_copy_principal(context, principal, &entry->principal);
            if (ret) {
                hdb_free_entry(context, db, entry);
                return ret;
            }
        }
        return 0;
    }

    /* Same realm -> not a referral, therefore this is a hard alias */
    if (same_realm) {
        if (soft_aliased) {
            /* Soft alias to the same realm?!  No. */
            hdb_free_entry(context, db, entry);
            return HDB_ERR_NOENTRY;
        }
        return 0;
    }

    /* Not same realm && not hard alias */
    return HDB_ERR_WRONG_REALM;
}

static krb5_error_code
hdb_remove_aliases(krb5_context context, HDB *db, krb5_data *key)
{
    const HDB_Ext_Aliases *aliases;
    krb5_error_code code;
    hdb_entry oldentry;
    krb5_data value;
    size_t i;

    code = db->hdb__get(context, db, *key, &value);
    if (code == HDB_ERR_NOENTRY)
	return 0;
    else if (code)
	return code;

    code = hdb_value2entry(context, &value, &oldentry);
    krb5_data_free(&value);
    if (code)
	return code;

    code = hdb_entry_get_aliases(&oldentry, &aliases);
    if (code || aliases == NULL) {
	free_HDB_entry(&oldentry);
	return code;
    }
    for (i = 0; i < aliases->aliases.len; i++) {
	krb5_data akey;

	code = hdb_principal2key(context, &aliases->aliases.val[i], &akey);
        if (code == 0) {
            code = db->hdb__del(context, db, akey);
            krb5_data_free(&akey);
            if (code == HDB_ERR_NOENTRY)
                code = 0;
        }
	if (code) {
	    free_HDB_entry(&oldentry);
	    return code;
	}
    }
    free_HDB_entry(&oldentry);
    return 0;
}

static krb5_error_code
hdb_add_aliases(krb5_context context, HDB *db,
		unsigned flags, hdb_entry *entry)
{
    const HDB_Ext_Aliases *aliases;
    krb5_error_code code;
    krb5_data key, value;
    size_t i;

    code = hdb_entry_get_aliases(entry, &aliases);
    if (code || aliases == NULL)
	return code;

    for (i = 0; i < aliases->aliases.len; i++) {
	hdb_entry_alias entryalias;
	entryalias.principal = entry->principal;

	code = hdb_entry_alias2value(context, &entryalias, &value);
	if (code)
	    return code;

	code = hdb_principal2key(context, &aliases->aliases.val[i], &key);
        if (code == 0) {
            code = db->hdb__put(context, db, flags, key, value);
            krb5_data_free(&key);
            if (code == HDB_ERR_EXISTS)
                /*
                 * Assuming hdb_check_aliases() was called, this must be a
                 * duplicate in the alias list.
                 */
                code = 0;
        }
	krb5_data_free(&value);
	if (code)
	    return code;
    }
    return 0;
}

/* Check if new aliases are already used for other entries */
static krb5_error_code
hdb_check_aliases(krb5_context context, HDB *db, hdb_entry *entry)
{
    const HDB_Ext_Aliases *aliases = NULL;
    HDB_EntryOrAlias eoa;
    krb5_data akey, value;
    size_t i;
    int ret;

    memset(&eoa, 0, sizeof(eoa));
    krb5_data_zero(&value);
    akey = value;

    ret = hdb_entry_get_aliases(entry, &aliases);
    for (i = 0; ret == 0 && aliases && i < aliases->aliases.len; i++) {
	ret = hdb_principal2key(context, &aliases->aliases.val[i], &akey);
        if (ret == 0)
            ret = db->hdb__get(context, db, akey, &value);
        if (ret == 0)
            ret = decode_HDB_EntryOrAlias(value.data, value.length, &eoa, NULL);
        if (ret == 0 && eoa.element != choice_HDB_EntryOrAlias_entry &&
            eoa.element != choice_HDB_EntryOrAlias_alias)
            ret = ENOTSUP;
        if (ret == 0 && eoa.element == choice_HDB_EntryOrAlias_entry)
            /* New alias names an existing non-alias entry in the HDB */
            ret = HDB_ERR_EXISTS;
        if (ret == 0 && eoa.element == choice_HDB_EntryOrAlias_alias &&
            !krb5_principal_compare(context, eoa.u.alias.principal,
                                    entry->principal))
            /* New alias names an existing alias of a different entry */
            ret = HDB_ERR_EXISTS;
        if (ret == HDB_ERR_NOENTRY) /* from db->hdb__get */
            /* New alias is a name that doesn't exist in the HDB */
            ret = 0;

        free_HDB_EntryOrAlias(&eoa);
	krb5_data_free(&value);
        krb5_data_free(&akey);
    }
    return ret;
}

/*
 * Many HDB entries don't have `etypes' setup.  Historically we use the
 * enctypes of the selected keyset as the entry's supported enctypes, but that
 * is problematic.  By doing this at store time and, if need be, at fetch time,
 * we can make sure to stop deriving supported etypes from keys in the long
 * run.  We also need kadm5/kadmin support for etypes.  We'll use this function
 * there to derive etypes when using a kadm5_principal_ent_t that lacks the new
 * TL data for etypes.
 */
krb5_error_code
hdb_derive_etypes(krb5_context context, hdb_entry *e, HDB_Ext_KeySet *base_keys)
{
    krb5_error_code ret = 0;
    size_t i, k, netypes;
    HDB_extension *ext;

    if (!base_keys &&
        (ext = hdb_find_extension(e, choice_HDB_extension_data_hist_keys)))
        base_keys = &ext->data.u.hist_keys;

    netypes = e->keys.len;
    if (netypes == 0 && base_keys) {
        /* There's no way that base_keys->val[i].keys.len == 0, but hey */
        for (i = 0; netypes == 0 && i < base_keys->len; i++)
            netypes = base_keys->val[i].keys.len;
    }

    if (netypes == 0)
        return 0;

    if (e->etypes != NULL) {
        free(e->etypes->val);
        e->etypes->len = 0;
        e->etypes->val = 0;
    } else if ((e->etypes = calloc(1, sizeof(e->etypes[0]))) == NULL) {
        ret = krb5_enomem(context);
    }
    if (ret == 0 &&
        (e->etypes->val = calloc(netypes, sizeof(e->etypes->val[0]))) == NULL)
        ret = krb5_enomem(context);
    if (ret) {
        free(e->etypes);
        e->etypes = 0;
        return ret;
    }
    e->etypes->len = netypes;
    for (i = 0; i < e->keys.len && i < netypes; i++)
        e->etypes->val[i] = e->keys.val[i].key.keytype;
    if (!base_keys || i)
        return 0;
    for (k = 0; i == 0 && k < base_keys->len; k++) {
        if (!base_keys->val[k].keys.len)
            continue;
        for (; i < base_keys->val[k].keys.len; i++)
            e->etypes->val[i] = base_keys->val[k].keys.val[i].key.keytype;
    }
    return 0;
}

krb5_error_code
_hdb_store(krb5_context context, HDB *db, unsigned flags, hdb_entry *entry)
{
    krb5_data key, value;
    int code;

    if (entry->flags.do_not_store ||
	entry->flags.force_canonicalize)
	return HDB_ERR_MISUSE;
    /* check if new aliases already is used */
    code = hdb_check_aliases(context, db, entry);
    if (code)
	return code;

    if ((flags & HDB_F_PRECHECK) && (flags & HDB_F_REPLACE))
        return 0;

    if ((flags & HDB_F_PRECHECK)) {
        code = hdb_principal2key(context, entry->principal, &key);
        if (code)
            return code;
        code = db->hdb__get(context, db, key, &value);
        krb5_data_free(&key);
        if (code == 0)
            krb5_data_free(&value);
        if (code == HDB_ERR_NOENTRY)
            return 0;
        return code ? code : HDB_ERR_EXISTS;
    }

    if ((entry->etypes == NULL || entry->etypes->len == 0) &&
        (code = hdb_derive_etypes(context, entry, NULL)))
        return code;

    if (entry->generation == NULL) {
	struct timeval t;
	entry->generation = malloc(sizeof(*entry->generation));
	if(entry->generation == NULL) {
	    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	    return ENOMEM;
	}
	gettimeofday(&t, NULL);
	entry->generation->time = t.tv_sec;
	entry->generation->usec = t.tv_usec;
	entry->generation->gen = 0;
    } else
	entry->generation->gen++;

    code = hdb_seal_keys(context, db, entry);
    if (code)
	return code;

    code = hdb_principal2key(context, entry->principal, &key);
    if (code)
        return code;

    /* remove aliases */
    code = hdb_remove_aliases(context, db, &key);
    if (code) {
	krb5_data_free(&key);
	return code;
    }
    code = hdb_entry2value(context, entry, &value);
    if (code == 0)
        code = db->hdb__put(context, db, flags & HDB_F_REPLACE, key, value);
    krb5_data_free(&value);
    krb5_data_free(&key);
    if (code)
	return code;

    code = hdb_add_aliases(context, db, flags, entry);

    return code;
}

krb5_error_code
_hdb_remove(krb5_context context, HDB *db,
            unsigned flags, krb5_const_principal principal)
{
    krb5_data key, value;
    HDB_EntryOrAlias eoa;
    int is_alias = -1;
    int code;

    /*
     * We only allow deletion of entries by canonical name.  To remove an
     * alias use kadm5_modify_principal().
     *
     * We need to determine if this is an alias.  We decode as a
     * HDB_EntryOrAlias, which is expensive -- we could decode as a
     * HDB_entry_alias instead and assume it's an entry if decoding fails...
     */

    code = hdb_principal2key(context, principal, &key);
    if (code == 0)
        code = db->hdb__get(context, db, key, &value);
    if (code == 0) {
        code = decode_HDB_EntryOrAlias(value.data, value.length, &eoa, NULL);
        krb5_data_free(&value);
    }
    if (code == 0) {
        is_alias = eoa.element == choice_HDB_EntryOrAlias_entry ? 0 : 1;
        free_HDB_EntryOrAlias(&eoa);
    }

    if ((flags & HDB_F_PRECHECK)) {
        if (code == 0 && is_alias)
            krb5_set_error_message(context, code = HDB_ERR_NOENTRY,
                                   "Cannot delete alias of principal");
        krb5_data_free(&key);
        return code;
    }

    if (code == 0)
        code = hdb_remove_aliases(context, db, &key);
    if (code == 0)
        code = db->hdb__del(context, db, key);
    krb5_data_free(&key);
    return code;
}

/* PRF+(K_base, pad, keylen(etype)) */
static krb5_error_code
derive_Key1(krb5_context context,
            krb5_data *pad,
            EncryptionKey *base,
            krb5int32 etype,
            EncryptionKey *nk)
{
    krb5_error_code ret;
    krb5_crypto crypto = NULL;
    krb5_data out;
    size_t len;

    out.data = 0;
    out.length = 0;

    ret = krb5_enctype_keysize(context, base->keytype, &len);
    if (ret == 0)
        ret = krb5_crypto_init(context, base, 0, &crypto);
    if (ret == 0)
        ret = krb5_crypto_prfplus(context, crypto, pad, len, &out);
    if (crypto)
        krb5_crypto_destroy(context, crypto);
    if (ret == 0)
        ret = krb5_random_to_key(context, etype, out.data, out.length, nk);
    krb5_data_free(&out);
    return ret;
}

/* PRF+(PRF+(K_base, princ, keylen(etype)), kvno, keylen(etype)) */
/* XXX Make it PRF+(PRF+(K_base, princ, keylen(K_base.etype)), and lift it, kvno, keylen(etype)) */
static krb5_error_code
derive_Key(krb5_context context,
           const char *princ,
           krb5uint32 kvno,
           EncryptionKey *base,
           krb5int32 etype,
           Key *nk)
{
    krb5_error_code ret = 0;
    EncryptionKey intermediate;
    krb5_data pad;

    nk->salt = NULL;
    nk->mkvno = NULL;
    nk->key.keytype = 0;
    nk->key.keyvalue.data = 0;
    nk->key.keyvalue.length = 0;

    intermediate.keytype = 0;
    intermediate.keyvalue.data = 0;
    intermediate.keyvalue.length = 0;
    if (princ) {
        /* Derive intermediate key for the given principal */
        /* XXX Lift to optimize? */
        pad.data = (void *)(uintptr_t)princ;
        pad.length = strlen(princ);
        ret = derive_Key1(context, &pad, base, etype, &intermediate);
        if (ret == 0)
            base = &intermediate;
    } /* else `base' is already an intermediate key for the desired princ */

    /* Derive final key for `kvno' from intermediate key */
    kvno = htonl(kvno);
    pad.data = &kvno;
    pad.length = sizeof(kvno);
    if (ret == 0)
        ret = derive_Key1(context, &pad, base, etype, &nk->key);
    free_EncryptionKey(&intermediate);
    return ret;
}

/*
 * PRF+(PRF+(K_base, princ, keylen(etype)), kvno, keylen(etype)) for one
 * enctype.
 */
static krb5_error_code
derive_Keys(krb5_context context,
            const char *princ,
            krb5uint32 kvno,
            krb5int32 etype,
            const Keys *base,
            Keys *dk)

{
    krb5_error_code ret = 0;
    size_t i;
    Key nk;

    dk->len = 0;
    dk->val = 0;
    
    /*
     * The enctypes of the base keys is the list of enctypes to derive keys
     * for.  Still, we derive all keys from the first base key.
     */
    for (i = 0; ret == 0 && i < base->len; i++) {
        if (etype != KRB5_ENCTYPE_NULL && etype != base->val[i].key.keytype)
            continue;
        ret = derive_Key(context, princ, kvno, &base->val[0].key,
                         base->val[i].key.keytype, &nk);
        if (ret)
            break;
        ret = add_Keys(dk, &nk);
        free_Key(&nk);
        /*
         * FIXME We need to finish kdc/kadm5/kadmin support for the `etypes' so
         * we can reduce the number of keys in keytabs to just those in current
         * use and only of *one* enctype.
         *
         * What we could do is derive *one* key and for the others output a
         * one-byte key of the intended enctype (which will never work).
         *
         * We'll never need any keys but the first one...
         */
    }

    if (ret)
        free_Keys(dk);
    return ret;
}

/* Helper for derive_keys_for_kr() */
static krb5_error_code
derive_keyset(krb5_context context,
              const Keys *base_keys,
              const char *princ,
              krb5int32 etype,
              krb5uint32 kvno,
              KerberosTime set_time, /* "now" */
              hdb_keyset *dks)
{
    dks->kvno = kvno;
    dks->keys.val = 0;
    dks->set_time = malloc(sizeof(*(dks->set_time)));
    if (dks->set_time == NULL)
        return krb5_enomem(context);
    *dks->set_time = set_time;
    return derive_Keys(context, princ, kvno, etype, base_keys, &dks->keys);
}

/* Possibly derive and install in `h' a keyset identified by `t' */
static krb5_error_code
derive_keys_for_kr(krb5_context context,
                   hdb_entry *h,
                   HDB_Ext_KeySet *base_keys,
                   int is_current_keyset,
                   int rotation_period_offset,
                   const char *princ,
                   krb5int32 etype,
                   krb5uint32 kvno_wanted,
                   KerberosTime t,
                   struct KeyRotation *krp)
{
    krb5_error_code ret;
    hdb_keyset dks;
    KerberosTime set_time, n;
    krb5uint32 kvno;
    size_t i;

    if (rotation_period_offset < -1 || rotation_period_offset > 1)
        return EINVAL; /* wat */

    /*
     * Compute `kvno' and `set_time' given `t' and `krp'.
     *
     * There be signed 32-bit time_t dragons here.
     *
     * (t - krp->epoch < 0) is better than (krp->epoch < t), making us more
     * tolerant of signed 32-bit time_t here near 2038.  Of course, we have
     * signed 32-bit time_t dragons elsewhere.
     *
     * We don't need to check for n == 0 && rotation_period_offset < 0 because
     * only derive_keys_for_current_kr() calls us with non-zero rotation period
     * offsets, and it will never call us in that case.
     */
    if (t - krp->epoch < 0)
        return 0; /* This KR is not relevant yet */
    n = (t - krp->epoch) / krp->period;
    n += rotation_period_offset;
    set_time = krp->epoch + krp->period * n;
    kvno = krp->base_kvno + n;

    /*
     * Since this principal is virtual, or has virtual keys, we're going to
     * derive a "password expiration time" for it in order to help httpkadmind
     * and other tools figure out when to request keys again.
     *
     * The kadm5 representation of principals does not include the set_time of
     * keys/keysets, so we can't have httpkadmind derive a Cache-Control from
     * that without adding yet another "TL data".  Since adding TL data is a
     * huge pain, we'll just use the `pw_end' field of `HDB_entry' to
     * communicate when this principal's keys will change next.
     */
    if (h->pw_end[0] == 0) {
        KerberosTime used = (t - krp->epoch) % krp->period;
        KerberosTime left = krp->period - used;

        /*
         * If `h->pw_end[0]' == 0 then this must be the current period of the
         * current KR we're deriving keys for.  See upstairs.
         *
         * If there's more than a quarter of this time period left, then we'll
         * set `h->pw_end[0]' to one quarter before the end of this time
         * period.  Else we'll set it to 1/4 after (we'll be including the next
         * set of derived keys, so there's no harm in waiting that long to
         * refetch).
         */
        if (left > krp->period >> 2)
            h->pw_end[0] = set_time + krp->period - (krp->period >> 2);
        else
            h->pw_end[0] = set_time + krp->period + (krp->period >> 2);
    }


    /*
     * Do not waste cycles computing keys not wanted or needed.
     * A past kvno is too old if its set_time + rotation period is in the past
     * by more than half a rotation period, since then no service ticket
     * encrypted with keys of that kvno can still be extant.
     *
     * A future kvno is not coming up soon enough if we're more than a quarter
     * of the rotation period away from it.
     *
     * Recall: the assumption for virtually-keyed principals is that services
     * fetch their future keys frequently enough that they'll never miss having
     * the keys they need.
     */
    if (!is_current_keyset || rotation_period_offset != 0) {
        if ((kvno_wanted && kvno != kvno_wanted) ||
            t - (set_time + krp->period + (krp->period >> 1)) > 0 ||
            (set_time - t > 0 && (set_time - t) > (krp->period >> 2)))
            return 0;
    }

    for (i = 0; i < base_keys->len; i++) {
        if (base_keys->val[i].kvno == krp->base_key_kvno)
            break;
    }
    if (i == base_keys->len) {
        /* Base key not found! */
        if (kvno_wanted || is_current_keyset) {
            krb5_set_error_message(context, ret = HDB_ERR_KVNO_NOT_FOUND,
                                   "Base key version %u not found for %s",
                                   krp->base_key_kvno, princ);
            return ret;
        }
        return 0;
    }

    ret = derive_keyset(context, &base_keys->val[i].keys, princ, etype, kvno,
                        set_time, &dks);
    if (ret == 0)
        ret = hdb_install_keyset(context, h, is_current_keyset, &dks);

    free_HDB_keyset(&dks);
    return ret;
}

/* Derive and install current keys, and possibly preceding or next keys */
static krb5_error_code
derive_keys_for_current_kr(krb5_context context,
                           hdb_entry *h, 
                           HDB_Ext_KeySet *base_keys,
                           const char *princ,
                           unsigned int flags,
                           krb5int32 etype,
                           krb5uint32 kvno_wanted,
                           KerberosTime t,
                           struct KeyRotation *krp,
                           KerberosTime future_epoch)
{
    krb5_error_code ret;

    /* derive_keys_for_kr() for current kvno and install as the current keys */
    ret = derive_keys_for_kr(context, h, base_keys, 1, 0, princ, etype,
                             kvno_wanted, t, krp);
    if (!(flags & HDB_F_ALL_KVNOS))
        return ret;

    /* */


    /*
     * derive_keys_for_kr() for prev kvno if still needed -- it can only be
     * needed if the prev kvno's start time is within this KR's epoch.
     *
     * Note that derive_keys_for_kr() can return without doing anything if this
     * is isn't the current keyset.  So these conditions need not be
     * sufficiently narrow.
     */
    if (ret == 0 && t - krp->epoch >= krp->period)
        ret = derive_keys_for_kr(context, h, base_keys, 0, -1, princ, etype,
                                 kvno_wanted, t, krp);
    /*
     * derive_keys_for_kr() for next kvno if near enough, but only if it
     * doesn't start after the next KR's epoch.
     */
    if (future_epoch &&
        t - krp->epoch >= 0 /* We know!  Hint to the compiler */) {
        KerberosTime next_kvno_start, n;

        n = (t - krp->epoch) / krp->period;
        next_kvno_start = krp->epoch + krp->period * (n + 1);
        if (future_epoch - next_kvno_start <= 0)
            return ret;
    }
    if (ret == 0)
        ret = derive_keys_for_kr(context, h, base_keys, 0, 1, princ, etype,
                                 kvno_wanted, t, krp);
    return ret;
}

/*
 * Derive and install all keysets in `h' that `princ' needs at time `now'.
 *
 * This mutates the entry `h' to
 *
 * a) not have base keys,
 * b) have keys derived from the base keys according to
 * c) the key rotation periods for the base principal (possibly the same
 *    principal if it's a concrete principal with virtual keys), and the
 *    requested time, enctype, and kvno (all of which are optional, with zero
 *    implying some default).
 *
 * Arguments:
 *
 *  - `flags' is the flags passed to `hdb_fetch_kvno()'
 *  - `princ' is the name of the principal we'll end up with in `entry'
 *  - `h_is_namespace' indicates whether `h' is for a namespace or a concrete
 *     principal (that might nonetheless have virtual/derived keys)
 *  - `t' is the time such that the derived keys are for kvnos needed at `t'
 *  - `etype' indicates what enctype to derive keys for (0 for all enctypes in
 *    `entry->etypes')
 *  - `kvno' requests a particular kvno, or all if zero
 *
 * The caller doesn't know if the principal needs key derivation -- we make
 * that determination in this function.
 *
 * Note that this function is fully deterministic for any given set of
 * arguments and HDB contents.
 *
 * Definitions:
 *
 *  - A keyset is a set of keys for a single kvno.
 *  - A keyset is relevant IFF:
 *     - it is the keyset for a time period identified by `t' in a
 *       corresponding KR
 *     - it is a keyset for a past time period for which there may be extant,
 *       not-yet-expired tickets that a service may need to decrypt
 *     - it is a keyset for an upcoming time period that a service will need to
 *       fetch before that time period becomes current, that way the service
 *       can have keytab entries for those keys in time for when the KDC starts
 *       encrypting service tickets to those keys
 *
 * This function derives the keyset(s) for the current KR first.  The idea is
 * to optimize the order of resulting keytabs so that the most likely keys to
 * be used come first.
 *
 * Invariants:
 *
 *  - KR metadata is sane because sanity is checked for when storing HDB
 *    entries
 *  - KRs are sorted by epoch in descending order; KR #0's epoch is the most
 *    recent
 *  - KR periods are non-zero (we divide by period)
 *  - kvnos are numerically ordered and correspond to time periods
 *     - within each KR, the kvnos for larger times are larger than (or equal
 *       to) the kvnos of earlier times
 *     - at KR boundaries, the first kvno of the newer boundary is larger than
 *       the kvno of the last time period of the previous KR
 *  - the time `t' must fall into exactly one KR period
 *  - the time `t' must fall into exactly one period within a KR period
 *  - at most two kvnos will be relevant from the KR that `t' falls into
 *    (the current kvno for `t', and possibly either the preceding, or the
 *    next)
 *  - at most one kvno from non-current KRs will be derived: possibly one for a
 *    preceding KR, and possibly one from an upcoming KR
 *
 * There can be:
 *
 *  - no KR extension (not a namespace principal, and no virtual keys)
 *  - 1, 2, or 3 KRs (see above)
 *  - the newest KR may have the `deleted' flag, meaning "does not exist after
 *    this epoch"
 *
 * Note that the last time period in any older KR can be partial.
 *
 * Timeline diagram:
 *
 *   .......|--+--+...+--|---+---+---+...+--|----+...
 *         T20          T10 T11 RT12    T1n     T01
 *     ^    ^  ^  ^   ^  ^               ^ T00
 *     |    |  | T22 T2n |               |  ^
 *     ^    | T21        |               |  |
 *   princ  |  |        epoch of         | epoch of
 *    did   |  |        middle KR        | newest epoch
 *    not   |  |                         |
 *   exist! | start of                  Note that T1n
 *          | second kvno               is shown as shorter
 *          | in 1st epoch              than preceding periods
 *          |
 *          ^
 *         first KR's
 *         epoch, and start
 *         of its first kvno
 *
 * Tmn == the start of the Mth KR's Nth time period.
 *        (higher M -> older KR; lower M -> newer KR)
 *        (N is the reverse: lower N -> older time period in KR)
 * T20 == start of oldest KR -- no keys before this time will be derived.
 * T2n == last time period in oldest KR
 * T10 == start of middle KR
 * T1n == last time period in middle KR
 * T00 == start of newest KR
 * T0n == current time period in newest KR for wall clock time
 */
static krb5_error_code
derive_keys(krb5_context context,
            unsigned flags,
            krb5_const_principal princ,
            int h_is_namespace,
            krb5_timestamp t,
            krb5int32 etype,
            krb5uint32 kvno,
            hdb_entry *h)
{
    HDB_Ext_KeyRotation kr;
    HDB_Ext_KeySet base_keys;
    krb5_error_code ret = 0;
    size_t current_kr, future_kr, past_kr, i;
    char *p = NULL;
    int valid = 1;

    if (!h_is_namespace && !h->flags.virtual_keys)
        return 0;
    h->flags.virtual = 1;

    kr.len = 0;
    kr.val = 0;
    if (ret == 0) {
        const HDB_Ext_KeyRotation *ckr;

        /* Installing keys invalidates `ckr', so we copy it */
        ret = hdb_entry_get_key_rotation(context, h, &ckr);
        if (!ckr)
            return ret;
        if (ret == 0)
            ret = copy_HDB_Ext_KeyRotation(ckr, &kr);
    }

    /* Get the base keys from the entry, and remove them */
    base_keys.val = 0;
    base_keys.len = 0;
    if (ret == 0)
        ret = _hdb_remove_base_keys(context, h, &base_keys, &kr);

    /* Make sure we have h->etypes */
    if (ret == 0 && !h->etypes)
        ret = hdb_derive_etypes(context, h, &base_keys);

    /* Keys not desired?  Don't derive them! */
    if (ret || !(flags & HDB_F_DECRYPT)) {
        free_HDB_Ext_KeyRotation(&kr);
        free_HDB_Ext_KeySet(&base_keys);
        return ret;
    }

    /* The principal name will be used in key derivation and error messages */
    if (ret == 0)
        ret = krb5_unparse_name(context, princ, &p);

    /* Sanity check key rotations, determine current & last kr */
    if (ret == 0 && kr.len < 1)
        krb5_set_error_message(context, ret = HDB_ERR_NOENTRY,
                               "no key rotation periods for %s", p);
    if (ret == 0)
        current_kr = future_kr = past_kr = kr.len;
    else
        current_kr = future_kr = past_kr = 1;

    /*
     * Identify a current, next, and previous KRs if there are any.
     *
     * There can be up to three KRs, ordered by epoch, descending, making up a
     * timeline like:
     *
     *   ...|---------|--------|------>
     *   ^  |         |        |
     *   |  |         |        |
     *   |  |         |        Newest KR (kr.val[0])
     *   |  |         Middle KR (kr.val[1])
     *   |  Oldest (last) KR (kr.val[2])
     *   |
     *   Before the begging of time for this namespace
     *
     * We step through these from future towards past looking for the best
     * future, current, and past KRs.  The best current KR is one that has its
     * epoch nearest to `t' but in the past of `t'.
     *
     * We validate KRs before storing HDB entries with the KR extension, so we
     * can assume they are valid here.  However, we do some validity checking,
     * and if they're not valid, we pick the best current KR and ignore the
     * others.
     *
     * In principle there cannot be two future KRs, but this function is
     * deterministic and takes a time value, so it should not enforce this just
     * so we can test.  Enforcement of such rules should be done at store time.
     */
    for (i = 0; ret == 0 && i < kr.len; i++) {
        /* Minimal validation: order and period */
        if (i && kr.val[i - 1].epoch - kr.val[i].epoch <= 0) {
            future_kr = past_kr = kr.len;
            valid = 0;
        }
        if (!kr.val[i].period) {
            future_kr = past_kr = kr.len;
            valid = 0;
            continue;
        }
        if (t - kr.val[i].epoch >= 0) {
            /*
             * `t' is in the future of this KR's epoch, so it's a candidate for
             * either current or past KR.
             */
            if (current_kr == kr.len)
                current_kr = i; /* First curr KR candidate; should be best */
            else if (kr.val[current_kr].epoch - kr.val[i].epoch < 0)
                current_kr = i; /* Invalid KRs, but better curr KR cand. */
            else if (valid && past_kr == kr.len)
                past_kr = i;
        } else if (valid) {
            /* This KR is in the future of `t', a candidate for next KR */
            future_kr = i;
        }
    }
    if (ret == 0 && current_kr == kr.len)
        /* No current KR -> too soon */
        krb5_set_error_message(context, ret = HDB_ERR_NOENTRY,
                               "Too soon for virtual principal to exist");

    /* Check that the principal has not been marked deleted */
    if (ret == 0 && current_kr < kr.len && kr.val[current_kr].flags.deleted)
        krb5_set_error_message(context, ret = HDB_ERR_NOENTRY,
                               "virtual principal %s does not exist "
                               "because last key rotation period "
                               "marks deletion", p);

    /* See `derive_keys_for_kr()' */
    if (h->pw_end == NULL &&
        (h->pw_end = calloc(1, sizeof(h->pw_end[0]))) == NULL)
        ret = krb5_enomem(context);

    /*
     * Derive and set in `h' its current kvno and current keys.
     *
     * This will set h->kvno as well.
     *
     * This may set up to TWO keysets for the current key rotation period:
     *  - current keys (h->keys and h->kvno)
     *  - possibly one future
     *    OR
     *    possibly one past keyset in hist_keys for the current_kr
     */
    if (ret == 0 && current_kr < kr.len)
        ret = derive_keys_for_current_kr(context, h, &base_keys, p, flags,
                                         etype, kvno, t, &kr.val[current_kr],
                                         current_kr ? kr.val[0].epoch : 0);

    /*
     * Derive and set in `h' its future keys for next KR if it is soon to be
     * current.
     *
     * We want to derive keys for the first kvno of the next (future) KR if
     * it's sufficiently close to `t', meaning within 1 period of the current
     * KR, but we want these keys to be available sooner, so 1.5 of the current
     * period.
     */
    if (ret == 0 && future_kr < kr.len && (flags & HDB_F_ALL_KVNOS))
        ret = derive_keys_for_kr(context, h, &base_keys, 0, 0, p, etype, kvno,
                                 kr.val[future_kr].epoch, &kr.val[future_kr]);

    /*
     * Derive and set in `h' its past keys for the previous KR if its last time
     * period could still have extant, unexpired service tickets encrypted in
     * its keys.
     */
    if (ret == 0 && past_kr < kr.len && (flags & HDB_F_ALL_KVNOS))
        ret = derive_keys_for_kr(context, h, &base_keys, 0, 0, p, etype, kvno,
                                 kr.val[current_kr].epoch - 1, &kr.val[past_kr]);

    /*
     * Impose a bound on h->max_life so that [when the KDC is the caller]
     * the KDC won't issue tickets longer lived than this.
     */
    if (ret == 0 && !h->max_life &&
        (h->max_life = calloc(1, sizeof(h->max_life[0]))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && *h->max_life > kr.val[current_kr].period >> 1)
        *h->max_life = kr.val[current_kr].period >> 1;

    if (ret == 0 && h->pw_end[0] == 0)
        /* Shouldn't happen */
        h->pw_end[0] = kr.val[current_kr].epoch +
            kr.val[current_kr].period *
            (1 + (t - kr.val[current_kr].epoch) / kr.val[current_kr].period);

    free_HDB_Ext_KeyRotation(&kr);
    free_HDB_Ext_KeySet(&base_keys);
    free(p);
    return ret;
}

/*
 * Pick a best kvno for the given principal at the given time.
 *
 * Implements the [hdb] new_service_key_delay configuration parameter.
 *
 * In order for disparate keytab provisioning systems such as OSKT and our own
 * kadmin ext_keytab and httpkadmind's get-keys to coexist, we need to be able
 * to force keys set by the former to not become current keys until users of
 * the latter have had a chance to fetch those keys into their keytabs.  To do
 * this we have to search the list of keys in the entry looking for the newest
 * keys older than `now - db->new_service_key_delay'.
 *
 * The context is that OSKT's krb5_keytab is very happy to change keys in a way
 * that requires all members of a cluster to rekey together.  If one also
 * wishes to have cluster members that opt out of this and just fetch current,
 * past, and future keys periodically, then the keys set by OSKT must not come
 * into effect until all the opt-out members have had a chance to fetch the new
 * keys.
 *
 * The assumption is that services will fetch new keys periodically, say, every
 * four hours.  Then one can set `[hdb] new_service_key_delay = 8h' in the
 * configuration and new keys set by OSKT will not be used until 8h after they
 * are set.
 *
 * Naturally, this applies only to concrete principals with concrete keys.
 */
static krb5_error_code
pick_kvno(krb5_context context,
          HDB *db,
          unsigned flags,
          krb5_timestamp now,
          krb5uint32 kvno,
          hdb_entry *h)
{
    HDB_extension *ext;
    HDB_Ext_KeySet keys;
    time_t current = 0;
    time_t best;
    size_t i;

    /*
     * If we want a specific kvno, or if the caller doesn't want new keys
     * delayed, or if there's no new-key delay configured, or we're not
     * fetching for use as a service principal, then we're out.
     */
    if (!(flags & HDB_F_DELAY_NEW_KEYS) || kvno || h->flags.virtual ||
        h->flags.virtual_keys || db->new_service_key_delay <= 0)
        return 0;

    /* No history -> current keyset is the only one and therefore the best */
    ext = hdb_find_extension(h, choice_HDB_extension_data_hist_keys);
    if (!ext)
        return 0;

    /* Assume the current keyset is the best to start with */
    (void) hdb_entry_get_pw_change_time(h, &current);
    if (current == 0 && h->modified_by)
        current = h->modified_by->time;
    if (current == 0)
        current = h->created_by.time;

    /* Current keyset starts out as best */
    best = current;
    kvno = h->kvno;

    /* Look for a better keyset in the history */
    keys = ext->data.u.hist_keys;
    for (i = 0; i < keys.len; i++) {
        /* No set_time?  Ignore.  Too new?  Ignore */
        if (!keys.val[i].set_time ||
            keys.val[i].set_time[0] + db->new_service_key_delay > now)
            continue;

        /*
         * Ignore the keyset with kvno 1 when the entry has better kvnos
         * because kadmin's `ank -r' command immediately changes the keys.
         */
        if (kvno > 1 && keys.val[i].kvno == 1)
            continue;

        /*
         * This keyset's set_time older than the previous best?  Ignore.
         * However, if the current best is the entry's current and that one
         * is too new, then don't ignore this one.
         */
        if (keys.val[i].set_time[0] < best &&
            (best != current || current + db->new_service_key_delay < now))
            continue;

        /*
         * If two good enough keysets have the same set_time, take the keyset
         * with the highest kvno.
         */
        if (keys.val[i].set_time[0] == best && keys.val[i].kvno <= kvno)
            continue;

        /*
         * This keyset is clearly more current than the previous best keyset
         * but still old enough to use for encrypting tickets with.
         */
        best = keys.val[i].set_time[0];
        kvno = keys.val[i].kvno;
    }
    return hdb_change_kvno(context, kvno, h);
}

/*
 * Make a WELLKNOWN/HOSTBASED-NAMESPACE/${svc}/${hostname} or
 * WELLKNOWN/HOSTBASED-NAMESPACE/${svc}/${hostname}/${domainname} principal
 * object, with the service and hostname components take from `wanted', but if
 * the service name is not in the list `db->virtual_hostbased_princ_svcs[]'
 * then use "_" (wildcard) instead.  This way we can have different attributes
 * for different services in the same namespaces.
 *
 * For example, virtual hostbased service names for the "host" service might
 * have ok-as-delegate set, but ones for the "HTTP" service might not.
 */
static krb5_error_code
make_namespace_princ(krb5_context context,
                     HDB *db,
                     krb5_const_principal wanted,
                     krb5_principal *namespace)
{
    krb5_error_code ret = 0;
    const char *realm = krb5_principal_get_realm(context, wanted);
    const char *comp0 = krb5_principal_get_comp_string(context, wanted, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, wanted, 1);
    const char *comp2 = krb5_principal_get_comp_string(context, wanted, 2);
    char * const *svcs = db->virtual_hostbased_princ_svcs;
    size_t i;

    *namespace = NULL;
    if (comp0 == NULL || comp1 == NULL)
        return EINVAL;
    if (strcmp(comp0, "krbtgt") == 0)
        return 0;

    for (i = 0; svcs && svcs[i]; i++) {
        if (strcmp(comp0, svcs[i]) == 0) {
            comp0 = svcs[i];
            break;
        }
    }
    if (!svcs || !svcs[i])
        comp0 = "_";

    /* First go around, need a namespace princ.  Make it! */
    ret = krb5_build_principal(context, namespace, strlen(realm),
                                realm, KRB5_WELLKNOWN_NAME,
                                HDB_WK_NAMESPACE, comp0, NULL);
    if (ret == 0)
        ret = krb5_principal_set_comp_string(context, *namespace, 3, comp1);
    if (ret == 0 && comp2)
        /* Support domain-based names */
        ret = krb5_principal_set_comp_string(context, *namespace, 4, comp2);
    /* Caller frees `*namespace' on error */
    return ret;
}

static int
is_namespace_princ_p(krb5_context context,
                     krb5_const_principal princ)
{
    return
        krb5_principal_get_num_comp(context, princ) >= 4
        && strcmp(krb5_principal_get_comp_string(context, princ, 0),
                  KRB5_WELLKNOWN_NAME) == 0
        && strcmp(krb5_principal_get_comp_string(context, princ, 1),
                  HDB_WK_NAMESPACE) == 0;
}

/* See call site */
static krb5_error_code
rewrite_hostname(krb5_context context,
                 krb5_const_principal wanted_princ,
                 krb5_const_principal ns_princ,
                 krb5_const_principal found_ns_princ,
                 char **s)
{
    const char *ns_host_part, *wanted_host_part, *found_host_part;
    const char *p, *r;
    size_t ns_host_part_len, wanted_host_part_len;

    wanted_host_part = krb5_principal_get_comp_string(context, wanted_princ, 1);
    wanted_host_part_len = strlen(wanted_host_part);
    if (wanted_host_part_len > 256) {
	krb5_set_error_message(context, HDB_ERR_NOENTRY,
                               "Aliases of host-based principals longer than "
                               "256 bytes not supported");
        return HDB_ERR_NOENTRY;
    }

    ns_host_part = krb5_principal_get_comp_string(context, ns_princ, 3);
    ns_host_part_len = strlen(ns_host_part);

    /* Find `ns_host_part' as the tail of `wanted_host_part' */
    for (r = p = strstr(wanted_host_part, ns_host_part);
         r && strnlen(r, ns_host_part_len + 1) > ns_host_part_len;
         p = (r = strstr(r, ns_host_part)) ? r : p)
        ;
    if (!p || strnlen(p, ns_host_part_len + 1) != ns_host_part_len)
        return HDB_ERR_NOENTRY; /* Can't happen */
    if (p == wanted_host_part || p[-1] != '.')
        return HDB_ERR_NOENTRY;

    found_host_part =
        krb5_principal_get_comp_string(context, found_ns_princ, 3);
    return
        asprintf(s, "%.*s%s", (int)(p - wanted_host_part), wanted_host_part,
                 found_host_part) < 0 ||
        *s == NULL ? krb5_enomem(context) : 0;
}

/*
 * Fix `h->principal' to match the desired `princ' in the namespace
 * `nsprinc' (which is either the same as `h->principal' or an alias
 * of it).
 */
static krb5_error_code
fix_princ_name(krb5_context context,
               krb5_const_principal princ,
               krb5_const_principal nsprinc,
               hdb_entry *h)
{
    krb5_error_code ret = 0;
    char *s = NULL;

    if (!nsprinc)
        return 0;
    if (krb5_principal_get_num_comp(context, princ) < 2)
        return HDB_ERR_NOENTRY;

    /* `nsprinc' must be a namespace principal */

    if (krb5_principal_compare(context, nsprinc, h->principal)) {
        /*
         * `h' is the HDB entry for `nsprinc', and `nsprinc' is its canonical
         * name.
         *
         * Set the entry's principal name to the desired name.  The keys will
         * be fixed next (upstairs, but don't forget to!).
         */
        free_Principal(h->principal);
        return copy_Principal(princ, h->principal);
    }

    if (!is_namespace_princ_p(context, h->principal)) {
        /*
         * The alias is a namespace, but the canonical name is not.  WAT.
         *
         * Well, the KDC will just issue a referral anyways, so we can leave
         * `h->principal' as is...
         *
         * Remove all of `h's keys just in case, and leave
         * `h->principal' as-is.
         */
        free_Keys(&h->keys);
        (void) hdb_entry_clear_password(context, h);
        return hdb_clear_extension(context, h,
                                   choice_HDB_extension_data_hist_keys);
    }

    /*
     * A namespace alias of a namespace entry.
     *
     * We'll want to rewrite the original principal accordingly.
     *
     * E.g., if the caller wanted host/foo.ns.test.h5l.se and we
     * found WELLKNOWN/HOSTBASED-NAMESPACE/ns.test.h5l.se is an
     * alias of WELLKNOWN/HOSTBASED-NAMESPACE/ns.example.org, then
     * we'll want to treat host/foo.ns.test.h5l.se as an alias of
     * host/foo.ns.example.org.
     */
    if (krb5_principal_get_num_comp(context, h->principal) !=
        2 + krb5_principal_get_num_comp(context, princ))
        ret = HDB_ERR_NOENTRY; /* Only host-based services for now */
    if (ret == 0)
        ret = rewrite_hostname(context, princ, nsprinc, h->principal, &s);
    if (ret == 0) {
        krb5_free_principal(context, h->principal);
        h->principal = NULL;
        ret = krb5_make_principal(context, &h->principal,
                                  krb5_principal_get_realm(context, princ),
                                  krb5_principal_get_comp_string(context,
                                                                 princ, 0),
                                  s,
                                  NULL);
    }
    free(s);
    return ret;
}

/* Wrapper around db->hdb_fetch_kvno() that implements virtual princs/keys */
static krb5_error_code
fetch_it(krb5_context context,
         HDB *db,
         krb5_const_principal princ,
         unsigned flags,
         krb5_timestamp t,
         krb5int32 etype,
         krb5uint32 kvno,
         hdb_entry *ent)
{
    krb5_const_principal tmpprinc = princ;
    krb5_principal nsprinc = NULL;
    krb5_error_code ret = 0;
    const char *comp0 = krb5_principal_get_comp_string(context, princ, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, princ, 1);
    const char *tmp;
    size_t mindots = db->virtual_hostbased_princ_ndots;
    size_t maxdots = db->virtual_hostbased_princ_maxdots;
    size_t hdots = 0;
    char *host = NULL;
    int do_search = 0;

    if (!db->enable_virtual_hostbased_princs)
        maxdots = mindots = 0;
    if (db->enable_virtual_hostbased_princs && comp1 &&
        strcmp("krbtgt", comp0) != 0 && strcmp(KRB5_WELLKNOWN_NAME, comp0) != 0) {
        char *htmp;

        if ((host = strdup(comp1)) == NULL)
            return krb5_enomem(context);

        /* Strip out any :port */
        htmp = strchr(host, ':');
        if (htmp) {
            if (strchr(htmp + 1, ':')) {
                /* Extra ':'s?  No virtualization for you! */
                free(host);
                host = NULL;
                htmp = NULL;
            } else {
                *htmp = '\0';
            }
        }
        /* Count dots in `host' */
        for (hdots = 0, htmp = host; htmp && *htmp; htmp++)
            if (*htmp == '.')
                hdots++;

        do_search = 1;
    }

    tmp = host ? host : comp1;
    for (ret = HDB_ERR_NOENTRY; ret == HDB_ERR_NOENTRY; tmpprinc = nsprinc) {
        krb5_error_code ret2 = 0;

        /*
         * We break out of this loop with ret == 0 only if we found the HDB
         * entry we were looking for or the HDB entry for a matching namespace.
         *
         * Otherwise we break out with ret != 0, typically HDB_ERR_NOENTRY.
         *
         * First time through we lookup the principal as given.
         *
         * Next we lookup a namespace principal, stripping off hostname labels
         * from the left until we find one or get tired of looking or run out
         * of labels.
         */
	ret = db->hdb_fetch_kvno(context, db, tmpprinc, flags, kvno, ent);
        if (ret == 0 && nsprinc && ent->flags.invalid) {
            free_HDB_entry(ent);
            ret = HDB_ERR_NOENTRY;
        }
	if (ret != HDB_ERR_NOENTRY || hdots == 0 || hdots < mindots || !tmp ||
            !do_search)
            break;

        /*
         * Breadcrumb:
         *
         *  - if we found a concrete principal, but it's been marked
         *    as now-virtual, then we must keep going
         *
         * But this will be coded in the future.
         *
         * Maybe we can take attributes from the concrete principal...
         */

        /*
         * The namespace's hostname will not have more labels than maxdots + 1.
         * Thus we truncate immediately down to maxdots + 1 if we haven't yet.
         *
         * Example: with maxdots == 3,
         *          foo.bar.baz.app.blah.example -> baz.app.blah.example
         */
        while (maxdots && hdots > maxdots && tmp) {
            tmp = strchr(tmp, '.');
            /* tmp != NULL because maxdots > 0; we check to quiet linters */
            if (tmp == NULL) {
                ret = HDB_ERR_NOENTRY;
                goto out;
            }
            tmp++;
            hdots--;
        }

        if (nsprinc == NULL)
            /* First go around, need a namespace princ.  Make it! */
            ret2 = make_namespace_princ(context, db, tmpprinc, &nsprinc);

        /* Update the hostname component of the namespace principal */
        if (ret2 == 0)
            ret2 = krb5_principal_set_comp_string(context, nsprinc, 3, tmp);
        if (ret2)
            ret = ret2;

        if (tmp) {
            /* Strip off left-most label for the next go-around */
            if ((tmp = strchr(tmp, '.')))
                tmp++;
            hdots--;
        } /* else we'll break out after the next db->hdb_fetch_kvno() call */
    }

    /*
     * If unencrypted keys were requested, derive them.  There may not be any
     * key derivation to do, but that's decided in derive_keys().
     */
    if (ret == 0 || ret == HDB_ERR_WRONG_REALM) {
        krb5_error_code save_ret = ret;

        /* Fix the principal name if namespaced */
        ret = fix_princ_name(context, princ, nsprinc, ent);

        /* Derive keys if namespaced or virtual */
        if (ret == 0)
            ret = derive_keys(context, flags, princ, !!nsprinc, t, etype, kvno,
                              ent);
        /* Pick the best kvno for this principal at the given time */
        if (ret == 0)
            ret = pick_kvno(context, db, flags, t, kvno, ent);
        if (ret == 0)
            ret = save_ret;
    }

out:
    if (ret != 0 && ret != HDB_ERR_WRONG_REALM)
        hdb_free_entry(context, db, ent);
    krb5_free_principal(context, nsprinc);
    free(host);
    return ret;
}

/**
 * Fetch a principal's HDB entry, possibly generating virtual keys from base
 * keys according to strict key rotation schedules.  If a time is given, other
 * than HDB I/O, this function is pure, thus usable for testing.
 *
 * HDB writers should use `db->hdb_fetch_kvno()' to avoid materializing virtual
 * principals.
 *
 * HDB readers should use this function rather than `db->hdb_fetch_kvno()'
 * unless they only want to see concrete principals and not bother generating
 * any virtual keys.
 *
 * @param context Context
 * @param db HDB
 * @param principal Principal name
 * @param flags Fetch flags
 * @param t For virtual keys, use this as the point in time (use zero to mean "now")
 * @param etype Key enctype (use KRB5_ENCTYPE_NULL to mean "preferred")
 * @param kvno Key version number (use zero to mean "current")
 * @param h Output HDB entry
 *
 * @return Zero or HDB_ERR_WRONG_REALM on success, an error code otherwise.
 */
krb5_error_code
hdb_fetch_kvno(krb5_context context,
               HDB *db,
               krb5_const_principal principal,
               unsigned int flags,
               krb5_timestamp t,
               krb5int32 etype,
               krb5uint32 kvno,
               hdb_entry *h)
{
    krb5_error_code ret;
    krb5_timestamp now;

    krb5_timeofday(context, &now);

    flags |= kvno ? HDB_F_KVNO_SPECIFIED : 0; /* XXX is this needed */
    ret = fetch_it(context, db, principal, flags, t ? t : now, etype, kvno, h);
    if (ret == 0 && t == 0 && h->flags.virtual &&
        h->pw_end && h->pw_end[0] < now) {
        /*
         * This shouldn't happen!
         *
         * Do not allow h->pw_end[0] to be in the past for virtual principals
         * outside testing.  This is just to prevent the AS/TGS from failing.
         */
        h->pw_end[0] = now + 3600;
    }
    if (ret == HDB_ERR_NOENTRY)
	krb5_set_error_message(context, ret, "no such entry found in hdb");
    return ret;
}

size_t ASN1CALL
length_hdb_keyset(HDB_keyset *data)
{
    return length_HDB_keyset(data);
}

size_t ASN1CALL
length_hdb_entry(HDB_entry *data)
{
    return length_HDB_entry(data);
}

size_t ASN1CALL
length_hdb_entry_alias(HDB_entry_alias *data)
{
    return length_HDB_entry_alias(data);
}

void ASN1CALL
free_hdb_keyset(HDB_keyset *data)
{
    free_HDB_keyset(data);
}

void ASN1CALL
free_hdb_entry(HDB_entry *data)
{
    free_HDB_entry(data);
}

void ASN1CALL
free_hdb_entry_alias(HDB_entry_alias *data)
{
    free_HDB_entry_alias(data);
}

size_t ASN1CALL
copy_hdb_keyset(const HDB_keyset *from, HDB_keyset *to)
{
    return copy_HDB_keyset(from, to);
}

size_t ASN1CALL
copy_hdb_entry(const HDB_entry *from, HDB_entry *to)
{
    return copy_HDB_entry(from, to);
}

size_t ASN1CALL
copy_hdb_entry_alias(const HDB_entry_alias *from, HDB_entry_alias *to)
{
    return copy_HDB_entry_alias(from, to);
}

int ASN1CALL
decode_hdb_keyset(const unsigned char *p,
                  size_t len,
                  HDB_keyset *data,
                  size_t *size)
{
    return decode_HDB_keyset(p, len, data, size);
}

int ASN1CALL
decode_hdb_entry(const unsigned char *p,
                 size_t len,
                 HDB_entry *data,
                 size_t *size)
{
    return decode_HDB_entry(p, len, data, size);
}

int ASN1CALL
decode_hdb_entry_alias(const unsigned char *p,
                       size_t len,
                       HDB_entry_alias *data,
                       size_t *size)
{
    return decode_HDB_entry_alias(p, len, data, size);
}

int ASN1CALL
encode_hdb_keyset(unsigned char *p,
                  size_t len,
                  const HDB_keyset *data,
                  size_t *size)
{
    return encode_HDB_keyset(p, len, data, size);
}

int ASN1CALL
encode_hdb_entry(unsigned char *p,
                 size_t len,
                 const HDB_entry *data,
                 size_t *size)
{
    return encode_HDB_entry(p, len, data, size);
}

int ASN1CALL
encode_hdb_entry_alias(unsigned char *p,
                       size_t len,
                       const HDB_entry_alias *data,
                       size_t *size)
{
    return encode_HDB_entry_alias(p, len, data, size);
}
