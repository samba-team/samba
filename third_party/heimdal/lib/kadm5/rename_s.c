/*
 * Copyright (c) 1997 - 2001, 2003, 2005 - 2005 Kungliga Tekniska Högskolan
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

struct rename_principal_hook_ctx {
    kadm5_server_context *context;
    enum kadm5_hook_stage stage;
    krb5_error_code code;
    krb5_const_principal source, target;
};

static krb5_error_code KRB5_LIB_CALL
rename_principal_hook_cb(krb5_context context,
			 const void *hook,
			 void *hookctx,
			 void *userctx)
{
    krb5_error_code ret;
    const struct kadm5_hook_ftable *ftable = hook;
    struct rename_principal_hook_ctx *ctx = userctx;

    ret = ftable->rename(context, hookctx,
			 ctx->stage, ctx->code,
			 ctx->source, ctx->target);
    if (ret != 0 && ret != KRB5_PLUGIN_NO_HANDLE)
	_kadm5_s_set_hook_error_message(ctx->context, ret, "rename",
					hook, ctx->stage);

    /* only pre-commit plugins can abort */
    if (ret == 0 || ctx->stage == KADM5_HOOK_STAGE_POSTCOMMIT)
	ret = KRB5_PLUGIN_NO_HANDLE;

    return ret;
}

static kadm5_ret_t
rename_principal_hook(kadm5_server_context *context,
		      enum kadm5_hook_stage stage,
		      krb5_error_code code,
		      krb5_const_principal source,
		      krb5_const_principal target)
{
    krb5_error_code ret;
    struct rename_principal_hook_ctx ctx;

    ctx.context = context;
    ctx.stage = stage;
    ctx.code = code;
    ctx.source = source;
    ctx.target = target;

    ret = _krb5_plugin_run_f(context->context, &kadm5_hook_plugin_data,
			     0, &ctx, rename_principal_hook_cb);
    if (ret == KRB5_PLUGIN_NO_HANDLE)
	ret = 0;

    return ret;
}

kadm5_ret_t
kadm5_s_rename_principal(void *server_handle,
			 krb5_principal source,
			 krb5_principal target)
{
    kadm5_server_context *context = server_handle;
    kadm5_ret_t ret;
    hdb_entry ent;
    krb5_principal oldname;
    size_t i;

    memset(&ent, 0, sizeof(ent));
    if (krb5_principal_compare(context->context, source, target))
	return KADM5_DUP; /* XXX is this right? */
    if (!context->keep_open) {
	ret = context->db->hdb_open(context->context, context->db, O_RDWR, 0);
	if(ret)
	    return ret;
    }

    ret = kadm5_log_init(context);
    if (ret)
        goto out;

    /* NOTE: We do not use hdb_fetch_kvno() here */
    ret = context->db->hdb_fetch_kvno(context->context, context->db,
                                      source,
                                      HDB_F_DECRYPT|HDB_F_GET_ANY|HDB_F_ADMIN_DATA,
                                      0, &ent);
    if (ret)
	goto out2;
    oldname = ent.principal;

    ret = rename_principal_hook(context, KADM5_HOOK_STAGE_PRECOMMIT,
				0, source, target);
    if (ret)
	goto out3;

    ret = _kadm5_set_modifier(context, &ent);
    if (ret)
	goto out3;
    {
	/* fix salt */
	Salt salt;
	krb5_salt salt2;
	memset(&salt, 0, sizeof(salt));
	ret = krb5_get_pw_salt(context->context, source, &salt2);
        if (ret)
            goto out3;
	salt.type = hdb_pw_salt;
	salt.salt = salt2.saltvalue;
	for(i = 0; i < ent.keys.len; i++){
	    if(ent.keys.val[i].salt == NULL){
		ent.keys.val[i].salt =
		    malloc(sizeof(*ent.keys.val[i].salt));
		if (ent.keys.val[i].salt == NULL)
		    ret = krb5_enomem(context->context);
                else
                    ret = copy_Salt(&salt, ent.keys.val[i].salt);
		if (ret)
		    break;
	    }
	}
	krb5_free_salt(context->context, salt2);
    }
    if (ret)
	goto out3;

    /* Borrow target */
    ent.principal = target;
    ret = hdb_seal_keys(context->context, context->db, &ent);
    if (ret)
	goto out3;

    /* This logs the change for iprop and writes to the HDB */
    ret = kadm5_log_rename(context, source, &ent);

    (void) rename_principal_hook(context, KADM5_HOOK_STAGE_POSTCOMMIT,
				 ret, source, target);

 out3:
    ent.principal = oldname; /* Unborrow target */
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

