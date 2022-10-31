/*
 * Copyright (c) 1997-2001 Kungliga Tekniska Högskolan
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

static kadm5_ret_t
get_default(kadm5_server_context *context, krb5_principal princ,
	    kadm5_principal_ent_t def)
{
    kadm5_ret_t ret;
    krb5_principal def_principal;
    krb5_const_realm realm = krb5_principal_get_realm(context->context, princ);

    ret = krb5_make_principal(context->context, &def_principal,
			      realm, "default", NULL);
    if (ret)
	return ret;
    ret = kadm5_s_get_principal(context, def_principal, def,
				KADM5_PRINCIPAL_NORMAL_MASK);
    krb5_free_principal (context->context, def_principal);

    if (ret) {
        /* Copy defaults from kadmin/init.c */
        memset(def, 0, sizeof(*def));
        def->max_life = 24 * 60 * 60;
        def->max_renewable_life = 7 * def->max_life;
        def->attributes = KRB5_KDB_DISALLOW_ALL_TIX;
    }
    return ret;
}

static kadm5_ret_t
create_principal(kadm5_server_context *context,
		 kadm5_principal_ent_t princ,
		 uint32_t mask,
		 hdb_entry *ent,
		 uint32_t required_mask,
		 uint32_t forbidden_mask)
{
    kadm5_ret_t ret;
    kadm5_principal_ent_rec defrec, *defent;
    uint32_t def_mask;

    memset(ent, 0, sizeof(*ent));
    if((mask & required_mask) != required_mask)
	return KADM5_BAD_MASK;
    if((mask & forbidden_mask))
	return KADM5_BAD_MASK;
    if((mask & KADM5_POLICY) && strcmp(princ->policy, "default"))
	/* XXX no real policies for now */
	return KADM5_UNK_POLICY;
    ret  = krb5_copy_principal(context->context, princ->principal,
			       &ent->principal);
    if(ret)
	return ret;

    defent = &defrec;
    ret = get_default(context, princ->principal, defent);
    if(ret) {
	defent   = NULL;
	def_mask = 0;
    } else {
	def_mask = KADM5_ATTRIBUTES | KADM5_MAX_LIFE | KADM5_MAX_RLIFE;
    }

    ret = _kadm5_setup_entry(context,
			     ent, mask | def_mask,
			     princ, mask,
			     defent, def_mask);
    if(defent)
	kadm5_free_principal_ent(context, defent);
    if (ret)
	return ret;

    ent->created_by.time = time(NULL);

    return krb5_copy_principal(context->context, context->caller,
			       &ent->created_by.principal);
}

struct create_principal_hook_ctx {
    kadm5_server_context *context;
    enum kadm5_hook_stage stage;
    krb5_error_code code;
    kadm5_principal_ent_t princ;
    uint32_t mask;
    const char *password;
};

static krb5_error_code KRB5_LIB_CALL
create_principal_hook_cb(krb5_context context,
			 const void *hook,
			 void *hookctx,
			 void *userctx)
{
    krb5_error_code ret;
    const struct kadm5_hook_ftable *ftable = hook;
    struct create_principal_hook_ctx *ctx = userctx;

    ret = ftable->create(context, hookctx,
			 ctx->stage, ctx->code, ctx->princ,
			 ctx->mask, ctx->password);
    if (ret != 0 && ret != KRB5_PLUGIN_NO_HANDLE)
	_kadm5_s_set_hook_error_message(ctx->context, ret, "create",
					hook, ctx->stage);

    /* only pre-commit plugins can abort */
    if (ret == 0 || ctx->stage == KADM5_HOOK_STAGE_POSTCOMMIT)
	ret = KRB5_PLUGIN_NO_HANDLE;

    return ret;
}

static kadm5_ret_t
create_principal_hook(kadm5_server_context *context,
		      enum kadm5_hook_stage stage,
		      krb5_error_code code,
		      kadm5_principal_ent_t princ,
		      uint32_t mask,
		      const char *password)
{
    krb5_error_code ret;
    struct create_principal_hook_ctx ctx;

    ctx.context = context;
    ctx.stage = stage;
    ctx.code = code;
    ctx.princ = princ;
    ctx.mask = mask;
    ctx.password = password;

    ret = _krb5_plugin_run_f(context->context, &kadm5_hook_plugin_data,
			     0, &ctx, create_principal_hook_cb);
    if (ret == KRB5_PLUGIN_NO_HANDLE)
	ret = 0;

    return ret;
}

kadm5_ret_t
kadm5_s_create_principal_with_key(void *server_handle,
				  kadm5_principal_ent_t princ,
				  uint32_t mask)
{
    kadm5_ret_t ret;
    hdb_entry ent;
    kadm5_server_context *context = server_handle;

    if ((mask & KADM5_KVNO) == 0) {
	/* create_principal() through _kadm5_setup_entry(), will need this */
	princ->kvno = 1;
	mask |= KADM5_KVNO;
    }

    ret = create_principal_hook(context, KADM5_HOOK_STAGE_PRECOMMIT,
				0, princ, mask, NULL);
    if (ret)
	return ret;

    ret = create_principal(context, princ, mask, &ent,
			   KADM5_PRINCIPAL | KADM5_KEY_DATA,
			   KADM5_LAST_PWD_CHANGE | KADM5_MOD_TIME
			   | KADM5_MOD_NAME | KADM5_MKVNO
			   | KADM5_AUX_ATTRIBUTES
			   | KADM5_POLICY_CLR | KADM5_LAST_SUCCESS
			   | KADM5_LAST_FAILED | KADM5_FAIL_AUTH_COUNT);
    if (ret)
        return ret;

    if (!context->keep_open) {
        ret = context->db->hdb_open(context->context, context->db, O_RDWR, 0);
        if (ret) {
            hdb_free_entry(context->context, context->db, &ent);
            return ret;
        }
    }

    ret = kadm5_log_init(context);
    if (ret)
        goto out;

    ret = hdb_seal_keys(context->context, context->db, &ent);
    if (ret)
	goto out2;

    /*
     * This logs the change for iprop and writes to the HDB.
     *
     * Creation of would-be virtual principals w/o the materialize flag will be
     * rejected in kadm5_log_create().
     */
    ret = kadm5_log_create(context, &ent);

    (void) create_principal_hook(context, KADM5_HOOK_STAGE_POSTCOMMIT,
				 ret, princ, mask, NULL);

 out2:
    (void) kadm5_log_end(context);
 out:
    if (!context->keep_open) {
        kadm5_ret_t ret2;
        ret2 = context->db->hdb_close(context->context, context->db);
        if (ret == 0 && ret2 != 0)
            ret = ret2;
    }
    hdb_free_entry(context->context, context->db, &ent);
    return _kadm5_error_code(ret);
}


kadm5_ret_t
kadm5_s_create_principal(void *server_handle,
			 kadm5_principal_ent_t princ,
			 uint32_t mask,
			 int n_ks_tuple,
			 krb5_key_salt_tuple *ks_tuple,
			 const char *password)
{
    kadm5_ret_t ret;
    hdb_entry ent;
    kadm5_server_context *context = server_handle;
    int use_pw = 1;

    if ((mask & KADM5_ATTRIBUTES) &&
        (princ->attributes & (KRB5_KDB_VIRTUAL_KEYS | KRB5_KDB_VIRTUAL)) &&
        !(princ->attributes & KRB5_KDB_MATERIALIZE)) {
        ret = KADM5_DUP; /* XXX */
        goto out;
    }
    if ((mask & KADM5_ATTRIBUTES) &&
        (princ->attributes & KRB5_KDB_VIRTUAL_KEYS) &&
        (princ->attributes & KRB5_KDB_VIRTUAL)) {
        ret = KADM5_DUP; /* XXX */
        goto out;
    }

    if ((mask & KADM5_ATTRIBUTES) &&
        (princ->attributes & KRB5_KDB_VIRTUAL) &&
        (princ->attributes & KRB5_KDB_MATERIALIZE))
        princ->attributes &= ~(KRB5_KDB_MATERIALIZE | KRB5_KDB_VIRTUAL);

    if (password[0] == '\0' && (mask & KADM5_KEY_DATA) && princ->n_key_data && 
        !kadm5_all_keys_are_bogus(princ->n_key_data, princ->key_data))
        use_pw = 0;

    if (use_pw && _kadm5_enforce_pwqual_on_admin_set_p(context)) {
	krb5_data pwd_data;
	const char *pwd_reason;

	pwd_data.data = rk_UNCONST(password);
	pwd_data.length = strlen(password);

	pwd_reason = kadm5_check_password_quality(context->context,
						  princ->principal, &pwd_data);
	if (pwd_reason != NULL) {
	    krb5_set_error_message(context->context, KADM5_PASS_Q_DICT, "%s", pwd_reason);
	    return KADM5_PASS_Q_DICT;
	}
    }

    if ((mask & KADM5_KVNO) == 0) {
	/* create_principal() through _kadm5_setup_entry(), will need this */
	princ->kvno = 1;
	mask |= KADM5_KVNO;
    }

    ret = create_principal_hook(context, KADM5_HOOK_STAGE_PRECOMMIT,
				0, princ, mask, password);
    if (ret)
	return ret;

    if (use_pw)
        ret = create_principal(context, princ, mask, &ent,
                               KADM5_PRINCIPAL,
                               KADM5_LAST_PWD_CHANGE | KADM5_MOD_TIME
                               | KADM5_MOD_NAME | KADM5_MKVNO
                               | KADM5_AUX_ATTRIBUTES | KADM5_KEY_DATA
                               | KADM5_POLICY_CLR | KADM5_LAST_SUCCESS
                               | KADM5_LAST_FAILED | KADM5_FAIL_AUTH_COUNT);
    else
        ret = create_principal(context, princ, mask, &ent,
                               KADM5_PRINCIPAL | KADM5_KEY_DATA,
                               KADM5_LAST_PWD_CHANGE | KADM5_MOD_TIME
                               | KADM5_MOD_NAME | KADM5_MKVNO
                               | KADM5_AUX_ATTRIBUTES
                               | KADM5_POLICY_CLR | KADM5_LAST_SUCCESS
                               | KADM5_LAST_FAILED | KADM5_FAIL_AUTH_COUNT);
    if (ret)
        return ret;

    if (!context->keep_open) {
        ret = context->db->hdb_open(context->context, context->db, O_RDWR, 0);
        if (ret) {
            hdb_free_entry(context->context, context->db, &ent);
            return ret;
        }
    }

    ret = kadm5_log_init(context);
    if (ret)
        goto out;

    free_Keys(&ent.keys);

    if (use_pw) {
        ret = _kadm5_set_keys(context, &ent, n_ks_tuple, ks_tuple, password);
        if (ret)
            goto out2;
    }

    ret = hdb_seal_keys(context->context, context->db, &ent);
    if (ret)
	goto out2;

    /* This logs the change for iprop and writes to the HDB */
    ret = kadm5_log_create(context, &ent);

    (void) create_principal_hook(context, KADM5_HOOK_STAGE_POSTCOMMIT,
				 ret, princ, mask, password);

 out2:
    (void) kadm5_log_end(context);
 out:
    if (!context->keep_open) {
        kadm5_ret_t ret2;
        ret2 = context->db->hdb_close(context->context, context->db);
        if (ret == 0 && ret2 != 0)
            ret = ret2;
    }
    hdb_free_entry(context->context, context->db, &ent);
    return _kadm5_error_code(ret);
}

