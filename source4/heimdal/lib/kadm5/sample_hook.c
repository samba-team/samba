/*
 * Copyright (c) 2018-2019, AuriStor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>

#include <krb5.h>
#include <stdio.h>
#include <string.h>

#include "admin.h"
#include "kadm5-hook.h"

/*
 * Sample kadm5 hook plugin that just logs when it is called. Install it
 * somewhere and configure the path in the [kadmin] section of krb5.conf.
 * e.g.
 *
 * [kadmin]
 *  plugin_dir = /usr/local/heimdal/lib/plugin/kadm5
 *
 */

static char sample_data_1, sample_data_2;

static krb5_error_code
sample_log(krb5_context context,
	   void *data,
	   enum kadm5_hook_stage stage,
	   const char *tag,
	   krb5_error_code code,
	   krb5_const_principal princ)
{
    char *p = NULL;
    int which = 0;

    /* verify we get called with the right contex tpointer */
    if (data == &sample_data_1)
	which = 1;
    else if (data == &sample_data_2)
	which = 2;

    assert(which != 0);

    /* code should always be zero on pre-commit */
    assert(code == 0 || stage == KADM5_HOOK_STAGE_POSTCOMMIT);

    if (princ)
	(void) krb5_unparse_name(context, princ, &p);

    krb5_warn(context, code, "sample_hook_%d: %s %s hook princ '%s'", which, tag,
	      stage == KADM5_HOOK_STAGE_PRECOMMIT ? "pre-commit" : "post-commit",
	      p != NULL ? p : "<unknown>");

    krb5_xfree(p);

    /* returning zero and KRB5_PLUGIN_NO_HANDLE are the same for hook plugins */
    return 0;
}

static krb5_error_code KRB5_CALLCONV
sample_init_1(krb5_context context, void **data)
{
    *data = &sample_data_1;
    krb5_warn(context, 0, "sample_hook_1: initializing");
    return 0;
}

static krb5_error_code KRB5_CALLCONV
sample_init_2(krb5_context context, void **data)
{
    *data = &sample_data_2;
    krb5_warn(context, 0, "sample_hook_2: initializing");
    return 0;
}

static void KRB5_CALLCONV
sample_fini(void *data)
{
    krb5_warn(NULL, 0, "sample_fini: finalizing");
}

static krb5_error_code KRB5_CALLCONV
sample_chpass_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   krb5_const_principal princ,
		   uint32_t flags,
		   size_t n_ks_tuple,
		   krb5_key_salt_tuple *ks_tuple,
		   const char *password)
{
    return sample_log(context, data, stage, "chpass", code, princ);
}

static krb5_error_code KRB5_CALLCONV
sample_chpass_with_key_hook(krb5_context context,
			    void *data,
			    enum kadm5_hook_stage stage,
			    krb5_error_code code,
			    krb5_const_principal princ,
			    uint32_t flags,
			    size_t n_key_data,
			    krb5_key_data *key_data)
{
    return sample_log(context, data, stage, "chpass_with_key", code, princ);
}

static krb5_error_code KRB5_CALLCONV
sample_create_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   kadm5_principal_ent_t ent,
		   uint32_t mask,
		   const char *password)
{
    return sample_log(context, data, stage, "create", code, ent->principal);
}

static krb5_error_code KRB5_CALLCONV
sample_modify_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   kadm5_principal_ent_t ent,
		   uint32_t mask)
{
    return sample_log(context, data, stage, "modify", code, ent->principal);
}

static krb5_error_code KRB5_CALLCONV
sample_delete_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   krb5_const_principal princ)
{
    return sample_log(context, data, stage, "delete", code, princ);
}

static krb5_error_code KRB5_CALLCONV
sample_randkey_hook(krb5_context context,
		    void *data,
		    enum kadm5_hook_stage stage,
		    krb5_error_code code,
		    krb5_const_principal princ)
{
    return sample_log(context, data, stage, "randkey", code, princ);
}

static krb5_error_code KRB5_CALLCONV
sample_rename_hook(krb5_context context,
		   void *data,
		   enum kadm5_hook_stage stage,
		   krb5_error_code code,
		   krb5_const_principal source,
		   krb5_const_principal target)
{
    return sample_log(context, data, stage, "rename", code, source);
}

static krb5_error_code KRB5_CALLCONV
sample_set_keys_hook(krb5_context context,
		     void *data,
		     enum kadm5_hook_stage stage,
		     krb5_error_code code,
		     krb5_const_principal princ,
		     uint32_t flags,
		     size_t n_ks_tuple,
		     krb5_key_salt_tuple *ks_tuple,
		     size_t n_keys,
		     krb5_keyblock *keyblocks)
{
    return sample_log(context, data, stage, "set_keys", code, princ);
}

static krb5_error_code KRB5_CALLCONV
sample_prune_hook(krb5_context context,
		  void *data,
		  enum kadm5_hook_stage stage,
		  krb5_error_code code,
		  krb5_const_principal princ,
		  int kvno)
{
    return sample_log(context, data, stage, "prune", code, princ);
}


static const kadm5_hook_ftable sample_hook_1 = {
    KADM5_HOOK_VERSION_V1,
    sample_init_1,
    sample_fini,
    "sample_hook_1",
    "Heimdal",
    sample_chpass_hook,
    sample_chpass_with_key_hook,
    sample_create_hook,
    sample_modify_hook,
    sample_delete_hook,
    sample_randkey_hook,
    sample_rename_hook,
    sample_set_keys_hook,
    sample_prune_hook,
};

static const kadm5_hook_ftable sample_hook_2 = {
    KADM5_HOOK_VERSION_V1,
    sample_init_2,
    sample_fini,
    "sample_hook_2",
    "Heimdal",
    sample_chpass_hook,
    sample_chpass_with_key_hook,
    sample_create_hook,
    sample_modify_hook,
    sample_delete_hook,
    sample_randkey_hook,
    sample_rename_hook,
    sample_set_keys_hook,
    sample_prune_hook,
};

/* Arrays of pointers, because hooks may be different versions/sizes */
static const kadm5_hook_ftable *const sample_hooks[] = {
    &sample_hook_1,
    &sample_hook_2,
};

krb5_error_code
kadm5_hook_plugin_load(krb5_context context,
		       krb5_get_instance_func_t *get_instance,
		       size_t *num_hooks,
		       const kadm5_hook_ftable *const **hooks);

static uintptr_t KRB5_LIB_CALL
sample_hook_get_instance(const char *libname)
{
    if (strcmp(libname, "kadm5") == 0)
	return kadm5_get_instance(libname);
    else if (strcmp(libname, "krb5") == 0)
	return krb5_get_instance(libname);

    return 0;
}

krb5_error_code
kadm5_hook_plugin_load(krb5_context context,
		       krb5_get_instance_func_t *get_instance,
		       size_t *num_hooks,
		       const kadm5_hook_ftable *const **hooks)
{
    *get_instance = sample_hook_get_instance;
    *num_hooks = sizeof(sample_hooks) / sizeof(sample_hooks[0]);
    *hooks = sample_hooks;

    return 0;
}
