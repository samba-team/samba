/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
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

#include <krb5_locl.h>
#include "kadm5_locl.h"
#include <assert.h>

RCSID("$Id$");

static kadm5_ret_t
add_tl_data(kadm5_principal_ent_t ent, int16_t type,
	    const void *data, size_t size)
{
    krb5_tl_data *tl;

    tl = calloc(1, sizeof(*tl));
    if (tl == NULL)
	return _kadm5_error_code(ENOMEM);

    tl->tl_data_type = type;
    tl->tl_data_length = size;
    tl->tl_data_contents = malloc(size);
    if (tl->tl_data_contents == NULL && size != 0) {
	free(tl);
	return _kadm5_error_code(ENOMEM);
    }
    memcpy(tl->tl_data_contents, data, size);

    tl->tl_data_next = ent->tl_data;
    ent->tl_data = tl;
    ent->n_tl_data++;

    return 0;
}

static
krb5_error_code
copy_keyset_to_kadm5(kadm5_server_context *context, krb5_kvno kvno,
		     size_t n_keys, Key *keys, krb5_salt *salt,
		     kadm5_principal_ent_t out)
{
    size_t i;
    Key *key;
    krb5_key_data *kd;
    krb5_data *sp;
    krb5_error_code ret = 0;

    for (i = 0; i < n_keys; i++) {
	key = &keys[i];
	kd = &out->key_data[out->n_key_data];
	kd->key_data_ver = 2;
	kd->key_data_kvno = kvno;
	kd->key_data_type[0] = key->key.keytype;
	if(key->salt)
	    kd->key_data_type[1] = key->salt->type;
	else
	    kd->key_data_type[1] = KRB5_PADATA_PW_SALT;
	/* setup key */
	kd->key_data_length[0] = key->key.keyvalue.length;
	kd->key_data_contents[0] = malloc(kd->key_data_length[0]);
	if(kd->key_data_contents[0] == NULL && kd->key_data_length[0] != 0){
	    ret = krb5_enomem(context->context);
	    break;
	}
	memcpy(kd->key_data_contents[0], key->key.keyvalue.data,
	       kd->key_data_length[0]);
	/* setup salt */
	if(key->salt)
	    sp = &key->salt->salt;
	else
	    sp = &salt->saltvalue;
	kd->key_data_length[1] = sp->length;
	kd->key_data_contents[1] = malloc(kd->key_data_length[1]);
	if(kd->key_data_length[1] != 0
	   && kd->key_data_contents[1] == NULL) {
	    memset(kd->key_data_contents[0], 0, kd->key_data_length[0]);
	    ret = krb5_enomem(context->context);
	    break;
	}
	memcpy(kd->key_data_contents[1], sp->data, kd->key_data_length[1]);
	out->n_key_data++;
    }

    return ret;
}

kadm5_ret_t
kadm5_s_get_principal(void *server_handle,
		      krb5_principal princ,
		      kadm5_principal_ent_t out,
		      uint32_t mask)
{
    kadm5_server_context *context = server_handle;
    kadm5_ret_t ret;
    hdb_entry ent;
    unsigned int flags = HDB_F_GET_ANY | HDB_F_ADMIN_DATA;

    if ((mask & KADM5_KEY_DATA) || (mask & KADM5_KVNO))
        flags |= HDB_F_ALL_KVNOS | HDB_F_DECRYPT;

    memset(&ent, 0, sizeof(ent));
    memset(out, 0, sizeof(*out));

    if (!context->keep_open) {
        ret = context->db->hdb_open(context->context, context->db, O_RDONLY, 0);
	if (ret)
	    return ret;
    }

    /*
     * We may want to attempt to recover the log on read operations, but we
     * because the HDB/log lock order is reversed on slaves, in order to avoid
     * lock contention from kadm5srv apps we need to make sure that the the HDB
     * open for read-write is optimistic and attempts only a non-blocking lock,
     * and if it doesn't get it then it should fallback to read-only.  But we
     * don't have that option in the hdb_open() interface at this time.
     *
     * For now we won't attempt to recover the log.
     */

    ret = hdb_fetch_kvno(context->context, context->db, princ, flags,
                         0 /*timestamp*/, 0/*etype*/, 0/*kvno*/, &ent);

    if (!context->keep_open)
	context->db->hdb_close(context->context, context->db);
    if(ret)
	return _kadm5_error_code(ret);

    if(mask & KADM5_PRINCIPAL)
	ret  = krb5_copy_principal(context->context, ent.principal,
				   &out->principal);
    if(ret)
	goto out;
    if(mask & KADM5_PRINC_EXPIRE_TIME && ent.valid_end)
	out->princ_expire_time = *ent.valid_end;
    if(mask & KADM5_PW_EXPIRATION && ent.pw_end)
	out->pw_expiration = *ent.pw_end;
    if(mask & KADM5_LAST_PWD_CHANGE)
	hdb_entry_get_pw_change_time(&ent, &out->last_pwd_change);
    if(mask & KADM5_ATTRIBUTES){
	out->attributes |= ent.flags.postdate ? 0 : KRB5_KDB_DISALLOW_POSTDATED;
	out->attributes |= ent.flags.forwardable ? 0 : KRB5_KDB_DISALLOW_FORWARDABLE;
	out->attributes |= ent.flags.initial ? KRB5_KDB_DISALLOW_TGT_BASED : 0;
	out->attributes |= ent.flags.renewable ? 0 : KRB5_KDB_DISALLOW_RENEWABLE;
	out->attributes |= ent.flags.proxiable ? 0 : KRB5_KDB_DISALLOW_PROXIABLE;
	out->attributes |= ent.flags.invalid ? KRB5_KDB_DISALLOW_ALL_TIX : 0;
	out->attributes |= ent.flags.require_preauth ? KRB5_KDB_REQUIRES_PRE_AUTH : 0;
	out->attributes |= ent.flags.require_pwchange ? KRB5_KDB_REQUIRES_PWCHANGE : 0;
	out->attributes |= ent.flags.client ? 0 : KRB5_KDB_DISALLOW_CLIENT;
	out->attributes |= ent.flags.server ? 0 : KRB5_KDB_DISALLOW_SVR;
	out->attributes |= ent.flags.change_pw ? KRB5_KDB_PWCHANGE_SERVICE : 0;
	out->attributes |= ent.flags.ok_as_delegate ? KRB5_KDB_OK_AS_DELEGATE : 0;
	out->attributes |= ent.flags.trusted_for_delegation ? KRB5_KDB_TRUSTED_FOR_DELEGATION : 0;
	out->attributes |= ent.flags.allow_kerberos4 ? KRB5_KDB_ALLOW_KERBEROS4 : 0;
	out->attributes |= ent.flags.allow_digest ? KRB5_KDB_ALLOW_DIGEST : 0;
	out->attributes |= ent.flags.virtual_keys ? KRB5_KDB_VIRTUAL_KEYS : 0;
	out->attributes |= ent.flags.virtual ? KRB5_KDB_VIRTUAL : 0;
	out->attributes |= ent.flags.no_auth_data_reqd ? KRB5_KDB_NO_AUTH_DATA_REQUIRED : 0;
	out->attributes |= ent.flags.auth_data_reqd ? KRB5_KDB_AUTH_DATA_REQUIRED : 0;
    }
    if(mask & KADM5_MAX_LIFE) {
	if(ent.max_life)
	    out->max_life = *ent.max_life;
	else
	    out->max_life = INT_MAX;
    }
    if(mask & KADM5_MOD_TIME) {
	if(ent.modified_by)
	    out->mod_date = ent.modified_by->time;
	else
	    out->mod_date = ent.created_by.time;
    }
    if(mask & KADM5_MOD_NAME) {
	if(ent.modified_by) {
	    if (ent.modified_by->principal != NULL)
		ret = krb5_copy_principal(context->context,
					  ent.modified_by->principal,
					  &out->mod_name);
	} else if(ent.created_by.principal != NULL)
	    ret = krb5_copy_principal(context->context,
				      ent.created_by.principal,
				      &out->mod_name);
	else
	    out->mod_name = NULL;
    }
    if(ret)
	goto out;

    if(mask & KADM5_KVNO)
	out->kvno = ent.kvno;
    if(mask & KADM5_MKVNO) {
	size_t n;
	out->mkvno = 0; /* XXX */
	for(n = 0; n < ent.keys.len; n++)
	    if(ent.keys.val[n].mkvno) {
		out->mkvno = *ent.keys.val[n].mkvno; /* XXX this isn't right */
		break;
	    }
    }
#if 0 /* XXX implement */
    if(mask & KADM5_AUX_ATTRIBUTES)
	;
    if(mask & KADM5_LAST_SUCCESS)
	;
    if(mask & KADM5_LAST_FAILED)
	;
    if(mask & KADM5_FAIL_AUTH_COUNT)
	;
#endif
    if(mask & KADM5_POLICY) {
	HDB_extension *ext;

	ext = hdb_find_extension(&ent, choice_HDB_extension_data_policy);
	if (ext == NULL) {
	    out->policy = strdup("default");
	    /* It's OK if we retun NULL instead of "default" */
	} else {
	    out->policy = strdup(ext->data.u.policy);
	    if (out->policy == NULL) {
		ret = krb5_enomem(context->context);
		goto out;
	    }
	}
    }
    if(mask & KADM5_MAX_RLIFE) {
	if(ent.max_renew)
	    out->max_renewable_life = *ent.max_renew;
	else
	    out->max_renewable_life = INT_MAX;
    }
    if(mask & KADM5_KEY_DATA){
	size_t i;
	size_t n_keys = ent.keys.len;
	krb5_salt salt;
	HDB_extension *ext;
	HDB_Ext_KeySet *hist_keys = NULL;

	/* Don't return stale keys to kadm5 clients */
	ret = hdb_prune_keys(context->context, &ent);
	if (ret)
	    goto out;
	ext = hdb_find_extension(&ent, choice_HDB_extension_data_hist_keys);
	if (ext != NULL)
	    hist_keys = &ext->data.u.hist_keys;

	krb5_get_pw_salt(context->context, ent.principal, &salt);
	for (i = 0; hist_keys != NULL && i < hist_keys->len; i++)
	    n_keys += hist_keys->val[i].keys.len;
	out->key_data = malloc(n_keys * sizeof(*out->key_data));
	if (out->key_data == NULL && n_keys != 0) {
	    ret = krb5_enomem(context->context);
	    goto out;
	}
	out->n_key_data = 0;
	ret = copy_keyset_to_kadm5(context, ent.kvno, ent.keys.len,
				   ent.keys.val, &salt, out);
	if (ret)
	    goto out;
	for (i = 0; hist_keys != NULL && i < hist_keys->len; i++) {
	    ret = copy_keyset_to_kadm5(context, hist_keys->val[i].kvno,
				       hist_keys->val[i].keys.len,
				       hist_keys->val[i].keys.val,
				       &salt, out);
	    if (ret)
		goto out;
	}
	krb5_free_salt(context->context, salt);
	assert( out->n_key_data == n_keys );
    }
    assert(ret == 0);
    if(mask & KADM5_TL_DATA) {
	time_t last_pw_expire;
	const HDB_Ext_PKINIT_acl *acl;
	const HDB_Ext_Aliases *aliases;
        const HDB_Ext_KeyRotation *kr;
        heim_octet_string krb5_config;

        if (ent.etypes) {
            krb5_data buf;
            size_t len;

            ASN1_MALLOC_ENCODE(HDB_EncTypeList, buf.data, buf.length,
                               ent.etypes, &len, ret);
            if (ret == 0) {
                ret = add_tl_data(out, KRB5_TL_ETYPES, buf.data, buf.length);
                free(buf.data);
            }
            if (ret)
                goto out;
        }

	ret = hdb_entry_get_pw_change_time(&ent, &last_pw_expire);
	if (ret == 0 && last_pw_expire) {
	    unsigned char buf[4];
	    _krb5_put_int(buf, last_pw_expire, sizeof(buf));
	    ret = add_tl_data(out, KRB5_TL_LAST_PWD_CHANGE, buf, sizeof(buf));
            if (ret)
                goto out;
	}

        ret = hdb_entry_get_krb5_config(&ent, &krb5_config);
        if (ret == 0 && krb5_config.length) {
            ret = add_tl_data(out, KRB5_TL_KRB5_CONFIG, krb5_config.data,
                              krb5_config.length);
            if (ret)
                goto out;
        }
	/*
	 * If the client was allowed to get key data, let it have the
	 * password too.
	 */
	if (mask & KADM5_KEY_DATA) {
	    heim_utf8_string pw;

            /* XXX But not if the client doesn't have ext-keys */
	    ret = hdb_entry_get_password(context->context,
					 context->db, &ent, &pw);
	    if (ret == 0) {
		ret = add_tl_data(out, KRB5_TL_PASSWORD, pw, strlen(pw) + 1);
		free(pw);
                if (ret)
                    goto out;
	    }
	    krb5_clear_error_message(context->context);
	}

        ret = hdb_entry_get_pkinit_acl(&ent, &acl);
	if (ret == 0 && acl) {
	    krb5_data buf;
	    size_t len;

	    ASN1_MALLOC_ENCODE(HDB_Ext_PKINIT_acl, buf.data, buf.length,
				acl, &len, ret);
	    if (ret)
		goto out;
	    if (len != buf.length)
		krb5_abortx(context->context,
			    "internal ASN.1 encoder error");
	    ret = add_tl_data(out, KRB5_TL_PKINIT_ACL, buf.data, buf.length);
	    free(buf.data);
	    if (ret)
		goto out;
	}

        ret = hdb_entry_get_aliases(&ent, &aliases);
	if (ret == 0 && aliases) {
	    krb5_data buf;
	    size_t len;

	    ASN1_MALLOC_ENCODE(HDB_Ext_Aliases, buf.data, buf.length,
			       aliases, &len, ret);
	    if (ret)
		goto out;
	    if (len != buf.length)
		krb5_abortx(context->context,
			    "internal ASN.1 encoder error");
	    ret = add_tl_data(out, KRB5_TL_ALIASES, buf.data, buf.length);
	    free(buf.data);
	    if (ret)
		goto out;
	}

        ret = hdb_entry_get_key_rotation(context->context, &ent, &kr);
	if (ret == 0 && kr) {
	    krb5_data buf;
	    size_t len;

	    ASN1_MALLOC_ENCODE(HDB_Ext_KeyRotation, buf.data, buf.length,
			       kr, &len, ret);
            if (ret == 0)
                ret = add_tl_data(out, KRB5_TL_KEY_ROTATION, buf.data, buf.length);
	    free(buf.data);
	}
    }

 out:
    if (ret)
        kadm5_free_principal_ent(context, out);
    hdb_free_entry(context->context, context->db, &ent);

    return _kadm5_error_code(ret);
}
