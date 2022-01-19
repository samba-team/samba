/*
 * Copyright (c) 2018, AuriStor, Inc.
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

#include "kadm5_locl.h"

static const char *kadm5_hook_plugin_deps[] = {
    "kadm5",
    "krb5",
    NULL
};

struct heim_plugin_data kadm5_hook_plugin_data = {
    "kadm5",
    "kadm5_hook",
    KADM5_HOOK_VERSION_V1,
    kadm5_hook_plugin_deps,
    kadm5_get_instance
};
    
void
_kadm5_s_set_hook_error_message(kadm5_server_context *context,
				krb5_error_code ret,
				const char *op,
				const struct kadm5_hook_ftable *hook,
				enum kadm5_hook_stage stage)
{
    assert(ret != 0);

    krb5_set_error_message(context->context, ret,
			       "%s hook `%s' failed %s-commit",
			       op, hook->name,
			       stage == KADM5_HOOK_STAGE_PRECOMMIT ? "pre" : "post");
}

kadm5_ret_t
_kadm5_s_init_hooks(kadm5_server_context *ctx)
{
    krb5_context context = ctx->context;
    char **dirs;

    dirs = krb5_config_get_strings(context, NULL, "kadmin",
				   "plugin_dir", NULL);
    if (dirs == NULL)
	return 0;

    _krb5_load_plugins(context, "kadm5", (const char **)dirs);
    krb5_config_free_strings(dirs);

    return 0;
}

void
_kadm5_s_free_hooks(kadm5_server_context *ctx)
{
    _krb5_unload_plugins(ctx->context, "kadm5");
}

uintptr_t KRB5_LIB_CALL
kadm5_get_instance(const char *libname)
{
    static const char *instance = "libkadm5";

    if (strcmp(libname, "kadm5") == 0)
	return (uintptr_t)instance;
    else if (strcmp(libname, "krb5") == 0)
	return krb5_get_instance(libname);

    return 0;
}
