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

#include "kadm5_locl.h"

RCSID("$Id$");

struct chpass_principal_hook_ctx {
    kadm5_server_context *context;
    enum kadm5_hook_stage stage;
    krb5_error_code code;
    krb5_const_principal princ;
    uint32_t flags;
    size_t n_ks_tuple;
    krb5_key_salt_tuple *ks_tuple;
    const char *password;
};

static krb5_error_code KRB5_LIB_CALL
chpass_principal_hook_cb(krb5_context context,
			 const void *hook,
			 void *hookctx,
			 void *userctx)
{
    krb5_error_code ret;
    const struct kadm5_hook_ftable *ftable = hook;
    struct chpass_principal_hook_ctx *ctx = userctx;

    ret = ftable->chpass(context, hookctx,
			 ctx->stage, ctx->code, ctx->princ,
			 ctx->flags, ctx->n_ks_tuple, ctx->ks_tuple,
			 ctx->password);
    if (ret != 0 && ret != KRB5_PLUGIN_NO_HANDLE)
	_kadm5_s_set_hook_error_message(ctx->context, ret, "chpass",
					hook, ctx->stage);

    /* only pre-commit plugins can abort */
    if (ret == 0 || ctx->stage == KADM5_HOOK_STAGE_POSTCOMMIT)
	ret = KRB5_PLUGIN_NO_HANDLE;

    return ret;
}

static kadm5_ret_t
chpass_principal_hook(kadm5_server_context *context,
		      enum kadm5_hook_stage stage,
		      krb5_error_code code,
		      krb5_const_principal princ,
		      uint32_t flags,
		      size_t n_ks_tuple,
		      krb5_key_salt_tuple *ks_tuple,
		      const char *password)
{
    krb5_error_code ret;
    struct chpass_principal_hook_ctx ctx;

    ctx.context = context;
    ctx.stage = stage;
    ctx.code = code;
    ctx.princ = princ;
    ctx.flags = flags;
    ctx.n_ks_tuple = n_ks_tuple;
    ctx.ks_tuple = ks_tuple;
    ctx.password = password;

    ret = _krb5_plugin_run_f(context->context, &kadm5_hook_plugin_data,
			     0, &ctx, chpass_principal_hook_cb);
    if (ret == KRB5_PLUGIN_NO_HANDLE)
	ret = 0;

    return ret;
}

static kadm5_ret_t
change(void *server_handle,
       krb5_principal princ,
       int keepold,
       int n_ks_tuple,
       krb5_key_salt_tuple *ks_tuple,
       const char *password,
       int cond)
{
    kadm5_server_context *context = server_handle;
    hdb_entry ent;
    kadm5_ret_t ret;
    Key *keys;
    size_t num_keys;
    int existsp = 0;
    uint32_t hook_flags = 0;

    memset(&ent, 0, sizeof(ent));

    if (krb5_principal_compare(context->context, princ, context->caller) ||
	_kadm5_enforce_pwqual_on_admin_set_p(context)) {
	krb5_data pwd_data;
	const char *pwd_reason;

	pwd_data.data = rk_UNCONST(password);
	pwd_data.length = strlen(password);

	pwd_reason = kadm5_check_password_quality(context->context,
						  princ, &pwd_data);
	if (pwd_reason != NULL) {
	    krb5_set_error_message(context->context, KADM5_PASS_Q_GENERIC, "%s", pwd_reason);
	    return KADM5_PASS_Q_GENERIC;
	}
    }

    if (!context->keep_open) {
	ret = context->db->hdb_open(context->context, context->db, O_RDWR, 0);
	if(ret)
	    return ret;
    }

    ret = kadm5_log_init(context);
    if (ret)
        goto out;

    ret = context->db->hdb_fetch_kvno(context->context, context->db, princ,
                                      HDB_F_DECRYPT|HDB_F_GET_ANY|HDB_F_ADMIN_DATA,
                                      0, &ent);
    if (ret)
	goto out2;

    if (keepold)
	hook_flags |= KADM5_HOOK_FLAG_KEEPOLD;
    if (cond)
	hook_flags |= KADM5_HOOK_FLAG_CONDITIONAL;
    ret = chpass_principal_hook(context, KADM5_HOOK_STAGE_PRECOMMIT,
				0, princ, hook_flags,
				n_ks_tuple, ks_tuple, password);
    if (ret)
	goto out3;

    if (keepold || cond) {
	/*
	 * We save these for now so we can handle password history checking;
	 * we handle keepold further below.
	 */
	ret = hdb_add_current_keys_to_history(context->context, &ent);
	if (ret)
	    goto out3;
    }

    if (context->db->hdb_capability_flags & HDB_CAP_F_HANDLE_PASSWORDS) {
	ret = context->db->hdb_password(context->context, context->db,
					&ent, password, cond);
	if (ret)
	    goto out3;
    } else {

	num_keys = ent.keys.len;
	keys     = ent.keys.val;

	ent.keys.len = 0;
	ent.keys.val = NULL;

	ret = _kadm5_set_keys(context, &ent, n_ks_tuple, ks_tuple,
			      password);
	if(ret) {
	    _kadm5_free_keys(context->context, num_keys, keys);
	    goto out3;
	}
	_kadm5_free_keys(context->context, num_keys, keys);

	if (cond) {
	    HDB_extension *ext;

	    ext = hdb_find_extension(&ent, choice_HDB_extension_data_hist_keys);
	    if (ext != NULL)
		existsp = _kadm5_exists_keys_hist(ent.keys.val,
						  ent.keys.len,
						  &ext->data.u.hist_keys);
	}

	if (existsp) {
	    ret = KADM5_PASS_REUSE;
	    krb5_set_error_message(context->context, ret,
				   "Password reuse forbidden");
	    goto out3;
	}
    }
    ent.kvno++;

    ent.flags.require_pwchange = 0;

    if (!keepold) {
	HDB_extension ext;

	memset(&ext, 0, sizeof (ext));
        ext.mandatory = FALSE;
	ext.data.element = choice_HDB_extension_data_hist_keys;
	ret = hdb_replace_extension(context->context, &ent, &ext);
	if (ret)
	    goto out3;
    }

    ret = hdb_seal_keys(context->context, context->db, &ent);
    if (ret)
        goto out3;

    ret = _kadm5_set_modifier(context, &ent);
    if(ret)
	goto out3;

    ret = _kadm5_bump_pw_expire(context, &ent);
    if (ret)
	goto out3;

    /* This logs the change for iprop and writes to the HDB */
    ret = kadm5_log_modify(context, &ent,
                           KADM5_ATTRIBUTES | KADM5_PRINCIPAL |
                           KADM5_MOD_NAME | KADM5_MOD_TIME |
                           KADM5_KEY_DATA | KADM5_KVNO |
                           KADM5_PW_EXPIRATION | KADM5_TL_DATA);

    (void) chpass_principal_hook(context, KADM5_HOOK_STAGE_POSTCOMMIT,
				 ret, princ, hook_flags,
				 n_ks_tuple, ks_tuple, password);

 out3:
    hdb_free_entry(context->context, context->db, &ent);
 out2:
    (void) kadm5_log_end(context);
 out:
    if (!context->keep_open) {
        kadm5_ret_t ret2;
        ret2 = context->db->hdb_close(context->context, context->db);
        if (ret == 0 && ret2 != 0)
            ret = ret2;
    }
    return _kadm5_error_code(ret);
}



/*
 * change the password of `princ' to `password' if it's not already that.
 */

kadm5_ret_t
kadm5_s_chpass_principal_cond(void *server_handle,
			      krb5_principal princ,
			      int keepold,
			      const char *password)
{
    return change (server_handle, princ, keepold, 0, NULL, password, 1);
}

/*
 * change the password of `princ' to `password'
 */

kadm5_ret_t
kadm5_s_chpass_principal(void *server_handle,
			 krb5_principal princ,
			 int keepold,
			 int n_ks_tuple,
			 krb5_key_salt_tuple *ks_tuple,
			 const char *password)
{
    return change (server_handle, princ, keepold,
	n_ks_tuple, ks_tuple, password, 0);
}

struct chpass_principal_with_key_hook_ctx {
    kadm5_server_context *context;
    enum kadm5_hook_stage stage;
    krb5_error_code code;
    krb5_const_principal princ;
    uint32_t flags;
    size_t n_key_data;
    krb5_key_data *key_data;
};

static krb5_error_code KRB5_LIB_CALL
chpass_principal_with_key_hook_cb(krb5_context context,
				  const void *hook,
				  void *hookctx,
				  void *userctx)
{
    krb5_error_code ret;
    const struct kadm5_hook_ftable *ftable = hook;
    struct chpass_principal_with_key_hook_ctx *ctx = userctx;

    ret = ftable->chpass_with_key(context, hookctx,
				  ctx->stage, ctx->code, ctx->princ,
				  ctx->flags, ctx->n_key_data, ctx->key_data);
    if (ret != 0 && ret != KRB5_PLUGIN_NO_HANDLE)
	_kadm5_s_set_hook_error_message(ctx->context, ret, "chpass_with_key",
					hook, ctx->stage);

    /* only pre-commit plugins can abort */
    if (ret == 0 || ctx->stage == KADM5_HOOK_STAGE_POSTCOMMIT)
	ret = KRB5_PLUGIN_NO_HANDLE;

    return ret;
}

static kadm5_ret_t
chpass_principal_with_key_hook(kadm5_server_context *context,
			       enum kadm5_hook_stage stage,
			       krb5_error_code code,
			       krb5_const_principal princ,
			       uint32_t flags,
			       size_t n_key_data,
			       krb5_key_data *key_data)
{
    krb5_error_code ret;
    struct chpass_principal_with_key_hook_ctx ctx;

    ctx.context = context;
    ctx.stage = stage;
    ctx.code = code;
    ctx.princ = princ;
    ctx.flags = flags;
    ctx.n_key_data = n_key_data;
    ctx.key_data = key_data;

    ret = _krb5_plugin_run_f(context->context, &kadm5_hook_plugin_data,
			     0, &ctx, chpass_principal_with_key_hook_cb);
    if (ret == KRB5_PLUGIN_NO_HANDLE)
	ret = 0;

    return ret;
}

/*
 * change keys for `princ' to `keys'
 */

kadm5_ret_t
kadm5_s_chpass_principal_with_key(void *server_handle,
				  krb5_principal princ,
				  int keepold,
				  int n_key_data,
				  krb5_key_data *key_data)
{
    kadm5_server_context *context = server_handle;
    hdb_entry ent;
    kadm5_ret_t ret;
    uint32_t hook_flags = 0;

    memset(&ent, 0, sizeof(ent));
    if (!context->keep_open) {
	ret = context->db->hdb_open(context->context, context->db, O_RDWR, 0);
	if(ret)
	    return ret;
    }

    ret = kadm5_log_init(context);
    if (ret)
        goto out;

    ret = context->db->hdb_fetch_kvno(context->context, context->db, princ,
                                      HDB_F_GET_ANY|HDB_F_ADMIN_DATA, 0, &ent);
    if (ret == HDB_ERR_NOENTRY)
	goto out2;

    if (keepold)
	hook_flags |= KADM5_HOOK_FLAG_KEEPOLD;
    ret = chpass_principal_with_key_hook(context, KADM5_HOOK_STAGE_PRECOMMIT,
					 0, princ, hook_flags,
					 n_key_data, key_data);
    if (ret)
	goto out3;

    if (keepold) {
	ret = hdb_add_current_keys_to_history(context->context, &ent);
	if (ret)
	    goto out3;
    }
    ret = _kadm5_set_keys2(context, &ent, n_key_data, key_data);
    if (ret)
	goto out3;
    ent.kvno++;
    ret = _kadm5_set_modifier(context, &ent);
    if (ret)
	goto out3;
    ret = _kadm5_bump_pw_expire(context, &ent);
    if (ret)
	goto out3;

    if (keepold) {
	ret = hdb_seal_keys(context->context, context->db, &ent);
	if (ret)
	    goto out3;
    } else {
	HDB_extension ext;

	memset(&ext, 0, sizeof (ext));
	ext.mandatory = FALSE;
	ext.data.element = choice_HDB_extension_data_hist_keys;
	ext.data.u.hist_keys.len = 0;
	ext.data.u.hist_keys.val = NULL;
	hdb_replace_extension(context->context, &ent, &ext);
    }

    /* This logs the change for iprop and writes to the HDB */
    ret = kadm5_log_modify(context, &ent,
                           KADM5_PRINCIPAL | KADM5_MOD_NAME |
                           KADM5_MOD_TIME | KADM5_KEY_DATA | KADM5_KVNO |
                           KADM5_PW_EXPIRATION | KADM5_TL_DATA);

    (void) chpass_principal_with_key_hook(context, KADM5_HOOK_STAGE_POSTCOMMIT,
					  ret, princ, hook_flags,
					  n_key_data, key_data);

 out3:
    hdb_free_entry(context->context, context->db, &ent);
 out2:
    (void) kadm5_log_end(context);
 out:
    if (!context->keep_open) {
        kadm5_ret_t ret2;
        ret2 = context->db->hdb_close(context->context, context->db);
        if (ret == 0 && ret2 != 0)
            ret = ret2;
    }
    return _kadm5_error_code(ret);
}

/*
 * Returns TRUE if password quality should be checked when passwords are
 * being set or changed by administrators. This includes principal creation.
 */
krb5_boolean
_kadm5_enforce_pwqual_on_admin_set_p(kadm5_server_context *contextp)
{
    if (_kadm5_is_kadmin_service_p(contextp))
	return FALSE;

    return krb5_config_get_bool_default(contextp->context, NULL, TRUE,
                                        "password_quality",
                                        "enforce_on_admin_set", NULL);
}
