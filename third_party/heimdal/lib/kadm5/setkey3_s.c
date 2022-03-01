/*
 * Copyright (c) 1997-2001, 2003, 2005-2006 Kungliga Tekniska Högskolan
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

struct setkey_principal_hook_ctx {
    kadm5_server_context *context;
    enum kadm5_hook_stage stage;
    krb5_error_code code;
    krb5_const_principal princ;
    uint32_t flags;
    size_t n_ks_tuple;
    krb5_key_salt_tuple *ks_tuple;
    size_t n_keys;
    krb5_keyblock *keys;
};

static krb5_error_code KRB5_LIB_CALL
setkey_principal_hook_cb(krb5_context context,
			 const void *hook,
			 void *hookctx,
			 void *userctx)
{
    krb5_error_code ret;
    const struct kadm5_hook_ftable *ftable = hook;
    struct setkey_principal_hook_ctx *ctx = userctx;

    ret = ftable->set_keys(context, hookctx,
			   ctx->stage, ctx->code,
			   ctx->princ, ctx->flags,
			   ctx->n_ks_tuple, ctx->ks_tuple,
			   ctx->n_keys, ctx->keys);
    if (ret != 0 && ret != KRB5_PLUGIN_NO_HANDLE)
	_kadm5_s_set_hook_error_message(ctx->context, ret, "setkey",
					hook, ctx->stage);

    /* only pre-commit plugins can abort */
    if (ret == 0 || ctx->stage == KADM5_HOOK_STAGE_POSTCOMMIT)
	ret = KRB5_PLUGIN_NO_HANDLE;

    return ret;
}

static kadm5_ret_t
setkey_principal_hook(kadm5_server_context *context,
		      enum kadm5_hook_stage stage,
		      krb5_error_code code,
		      krb5_const_principal princ,
		      uint32_t flags,
		      size_t n_ks_tuple,
		      krb5_key_salt_tuple *ks_tuple,
		      size_t n_keys,
		      krb5_keyblock *keyblocks)
{
    krb5_error_code ret;
    struct setkey_principal_hook_ctx ctx;

    ctx.context = context;
    ctx.stage = stage;
    ctx.code = code;
    ctx.princ = princ;
    ctx.flags = flags;
    ctx.n_ks_tuple = n_ks_tuple;
    ctx.ks_tuple = ks_tuple;
    ctx.n_keys = n_keys;
    ctx.keys = keyblocks;

    ret = _krb5_plugin_run_f(context->context, &kadm5_hook_plugin_data,
			     0, &ctx, setkey_principal_hook_cb);
    if (ret == KRB5_PLUGIN_NO_HANDLE)
	ret = 0;

    return ret;
}

/**
 * Server-side function to set new keys for a principal.
 */
kadm5_ret_t
kadm5_s_setkey_principal_3(void *server_handle,
			   krb5_principal princ,
			   krb5_boolean keepold,
			   int n_ks_tuple,
			   krb5_key_salt_tuple *ks_tuple,
			   krb5_keyblock *keyblocks, int n_keys)
{
    kadm5_server_context *context = server_handle;
    hdb_entry ent;
    kadm5_ret_t ret = 0;
    size_t i;

    memset(&ent, 0, sizeof(ent));
    if (!context->keep_open)
	ret = context->db->hdb_open(context->context, context->db, O_RDWR, 0);
    if (ret)
	return ret;

    ret = kadm5_log_init(context);
    if (ret) {
        if (!context->keep_open)
            context->db->hdb_close(context->context, context->db);
        return ret;
    }

    /* NOTE: We do not use hdb_fetch_kvno() here (maybe we should?) */
    ret = context->db->hdb_fetch_kvno(context->context, context->db, princ,
                                      HDB_F_DECRYPT|HDB_F_GET_ANY|HDB_F_ADMIN_DATA,
                                      0, &ent);
    if (ret) {
        (void) kadm5_log_end(context);
        if (!context->keep_open)
            context->db->hdb_close(context->context, context->db);
        return ret;
    }

    ret = setkey_principal_hook(context, KADM5_HOOK_STAGE_PRECOMMIT, 0,
				princ, keepold ? KADM5_HOOK_FLAG_KEEPOLD : 0,
				n_ks_tuple, ks_tuple, n_keys, keyblocks);
    if (ret) {
        (void) kadm5_log_end(context);
        if (!context->keep_open)
            context->db->hdb_close(context->context, context->db);
        return ret;
    }

    if (keepold) {
        ret = hdb_add_current_keys_to_history(context->context, &ent);
    } else
	ret = hdb_clear_extension(context->context, &ent,
				  choice_HDB_extension_data_hist_keys);

    /*
     * Though in practice all real calls to this function will pass an empty
     * ks_tuple, and cannot in any case employ any salts that require
     * additional data, we go the extra mile to set any requested salt type
     * along with a zero length salt value.  While we're at it we check that
     * each ks_tuple's enctype matches the corresponding key enctype.
     */
    if (ret == 0) {
	free_Keys(&ent.keys);
	for (i = 0; i < n_keys; ++i) {
	    Key k;
	    Salt s;

	    k.mkvno = 0;
	    k.key = keyblocks[i];
	    if (n_ks_tuple == 0)
		k.salt = 0;
	    else {
		if (ks_tuple[i].ks_enctype != keyblocks[i].keytype) {
		    ret = KADM5_SETKEY3_ETYPE_MISMATCH;
		    break;
		}
		s.type = ks_tuple[i].ks_salttype;
		s.salt.data = 0;
		s.opaque = 0;
		k.salt = &s;
	    }
	    if ((ret = add_Keys(&ent.keys, &k)) != 0)
		break;
	}
    }

    if (ret == 0) {
	ent.kvno++;
	ent.flags.require_pwchange = 0;
	hdb_entry_set_pw_change_time(context->context, &ent, 0);
	hdb_entry_clear_password(context->context, &ent);

	if ((ret = hdb_seal_keys(context->context, context->db,
				 &ent)) == 0
	    && (ret = _kadm5_set_modifier(context, &ent)) == 0
	    && (ret = _kadm5_bump_pw_expire(context, &ent)) == 0)
	    ret = kadm5_log_modify(context, &ent,
                                   KADM5_ATTRIBUTES | KADM5_PRINCIPAL |
                                   KADM5_MOD_NAME | KADM5_MOD_TIME |
                                   KADM5_KEY_DATA | KADM5_KVNO |
                                   KADM5_PW_EXPIRATION | KADM5_TL_DATA);
    }

    (void) setkey_principal_hook(context, KADM5_HOOK_STAGE_POSTCOMMIT, ret,
				 princ, keepold, n_ks_tuple, ks_tuple,
				 n_keys, keyblocks);

    hdb_free_entry(context->context, context->db, &ent);
    (void) kadm5_log_end(context);
    if (!context->keep_open)
	context->db->hdb_close(context->context, context->db);
    return _kadm5_error_code(ret);
}
