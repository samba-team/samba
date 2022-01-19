/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"

static int have_plugin = 0;

/*
 * Pick the first WINDC module that we find.
 */

static const char *windc_plugin_deps[] = {
    "kdc",
    "krb5",
    "hdb",
    NULL
};

static struct heim_plugin_data windc_plugin_data = {
    "krb5",
    "windc",
    KRB5_WINDC_PLUGIN_MINOR,
    windc_plugin_deps,
    kdc_get_instance
};

static krb5_error_code KRB5_LIB_CALL
load(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    have_plugin = 1;
    return KRB5_PLUGIN_NO_HANDLE;
}

krb5_error_code
krb5_kdc_windc_init(krb5_context context)
{
    (void)_krb5_plugin_run_f(context, &windc_plugin_data, 0, NULL, load);

    return 0;
}

struct generate_uc {
    hdb_entry_ex *client;
    hdb_entry_ex *server;
    const krb5_keyblock *reply_key;
    uint64_t pac_attributes;
    krb5_pac *pac;
};

static krb5_error_code KRB5_LIB_CALL
generate(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    krb5plugin_windc_ftable *ft = (krb5plugin_windc_ftable *)plug;
    struct generate_uc *uc = (struct generate_uc *)userctx;    

    if (ft->pac_generate == NULL)
	return KRB5_PLUGIN_NO_HANDLE;

    return ft->pac_generate((void *)plug, context,
			    uc->client,
			    uc->server,
			    uc->reply_key,
			    uc->pac_attributes,
			    uc->pac);
}


krb5_error_code
_kdc_pac_generate(krb5_context context,
		  hdb_entry_ex *client,
		  hdb_entry_ex *server,
		  const krb5_keyblock *reply_key,
		  uint64_t pac_attributes,
		  krb5_pac *pac)
{
    krb5_error_code ret = 0;
    struct generate_uc uc;

    *pac = NULL;

    if (krb5_config_get_bool_default(context, NULL, FALSE, "realms",
				     client->entry.principal->realm,
				     "disable_pac", NULL))
	return 0;

    if (have_plugin) {
	uc.client = client;
	uc.server = server;
	uc.reply_key = reply_key;
	uc.pac = pac;
	uc.pac_attributes = pac_attributes;

	ret = _krb5_plugin_run_f(context, &windc_plugin_data,
				 0, &uc, generate);
	if (ret != KRB5_PLUGIN_NO_HANDLE)
	    return ret;
	ret = 0;
    }

    if (*pac == NULL)
	ret = krb5_pac_init(context, pac);

    return ret;
}

struct verify_uc {
    krb5_principal client_principal;
    krb5_principal delegated_proxy_principal;
    hdb_entry_ex *client;
    hdb_entry_ex *server;
    hdb_entry_ex *krbtgt;
    krb5_pac *pac;
};

static krb5_error_code KRB5_LIB_CALL
verify(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    krb5plugin_windc_ftable *ft = (krb5plugin_windc_ftable *)plug;
    struct verify_uc *uc = (struct verify_uc *)userctx;
    krb5_error_code ret;

    if (ft->pac_verify == NULL)
	return KRB5_PLUGIN_NO_HANDLE;

    ret = ft->pac_verify((void *)plug, context,
			 uc->client_principal,
			 uc->delegated_proxy_principal,
			 uc->client, uc->server, uc->krbtgt, uc->pac);
    return ret;
}

krb5_error_code
_kdc_pac_verify(krb5_context context,
		const krb5_principal client_principal,
		const krb5_principal delegated_proxy_principal,
		hdb_entry_ex *client,
		hdb_entry_ex *server,
		hdb_entry_ex *krbtgt,
		krb5_pac *pac)
{
    struct verify_uc uc;

    if (!have_plugin)
	return KRB5_PLUGIN_NO_HANDLE;

    uc.client_principal = client_principal;
    uc.delegated_proxy_principal = delegated_proxy_principal;
    uc.client = client;
    uc.server = server;
    uc.krbtgt = krbtgt;
    uc.pac = pac;

    return _krb5_plugin_run_f(context, &windc_plugin_data,
			     0, &uc, verify);
}

static krb5_error_code KRB5_LIB_CALL
check(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    krb5plugin_windc_ftable *ft = (krb5plugin_windc_ftable *)plug;

    if (ft->client_access == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->client_access((void *)plug, userctx);
}

krb5_error_code
_kdc_check_access(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin) {
        ret = _krb5_plugin_run_f(r->context, &windc_plugin_data,
                                 0, r, check);
    }

    if (ret == KRB5_PLUGIN_NO_HANDLE)
        return kdc_check_flags(r, r->req.msg_type == krb_as_req,
                               r->client, r->server);
    return ret;
}

static krb5_error_code KRB5_LIB_CALL
finalize(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    krb5plugin_windc_ftable *ft = (krb5plugin_windc_ftable *)plug;

    if (ft->finalize_reply == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->finalize_reply((void *)plug, (astgs_request_t)userctx);
}

krb5_error_code
_kdc_finalize_reply(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin)
        ret = _krb5_plugin_run_f(r->context, &windc_plugin_data, 0, r, finalize);

    if (ret == KRB5_PLUGIN_NO_HANDLE)
        ret = 0;

    return ret;
}

uintptr_t KRB5_CALLCONV
kdc_get_instance(const char *libname)
{
    static const char *instance = "libkdc";

    if (strcmp(libname, "kdc") == 0)
        return (uintptr_t)instance;
    else if (strcmp(libname, "hdb") == 0)
	return hdb_get_instance(libname);
    else if (strcmp(libname, "krb5") == 0)
        return krb5_get_instance(libname);
    else if (strcmp(libname, "gssapi") == 0)
        return gss_get_instance(libname);

    return 0;
}
