/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions (c) 2021, 2022 PADL Software Pty Ltd.
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
 * Pick the first KDC plugin module that we find.
 */

static const char *kdc_plugin_deps[] = {
    "kdc",
    "krb5",
    "hdb",
    NULL
};

static struct heim_plugin_data kdc_plugin_data = {
    "krb5",
    "kdc",
    KRB5_PLUGIN_KDC_VERSION_12,
    kdc_plugin_deps,
    kdc_get_instance
};

static krb5_error_code KRB5_LIB_CALL
load(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    have_plugin = 1;
    return KRB5_PLUGIN_NO_HANDLE;
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
krb5_kdc_plugin_init(krb5_context context)
{
    (void)_krb5_plugin_run_f(context, &kdc_plugin_data, 0, NULL, load);

    return 0;
}

struct generate_uc {
    astgs_request_t r;
    hdb_entry *client;
    hdb_entry *server;
    const krb5_keyblock *reply_key;
    uint64_t pac_attributes;
    krb5_pac *pac;
};

static krb5_error_code KRB5_LIB_CALL
generate(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;
    struct generate_uc *uc = (struct generate_uc *)userctx;    

    if (ft->pac_generate == NULL)
	return KRB5_PLUGIN_NO_HANDLE;

    return ft->pac_generate((void *)plug,
			    uc->r,
			    uc->client,
			    uc->server,
			    uc->reply_key,
			    uc->pac_attributes,
			    uc->pac);
}


krb5_error_code
_kdc_pac_generate(astgs_request_t r,
		  hdb_entry *client,
		  hdb_entry *server,
		  const krb5_keyblock *reply_key,
		  uint64_t pac_attributes,
		  krb5_pac *pac)
{
    krb5_error_code ret = 0;
    struct generate_uc uc;

    *pac = NULL;

    if (krb5_config_get_bool_default(r->context, NULL, FALSE, "realms",
				     client->principal->realm,
				     "disable_pac", NULL))
	return 0;

    if (have_plugin) {
	uc.r = r;
	uc.client = client;
	uc.server = server;
	uc.reply_key = reply_key;
	uc.pac = pac;
	uc.pac_attributes = pac_attributes;

	ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data,
				 0, &uc, generate);
	if (ret != KRB5_PLUGIN_NO_HANDLE)
	    return ret;
	ret = 0;
    }

    if (*pac == NULL)
	ret = krb5_pac_init(r->context, pac);

    return ret;
}

struct verify_uc {
    astgs_request_t r;
    krb5_const_principal client_principal;
    hdb_entry *delegated_proxy;
    hdb_entry *client;
    hdb_entry *server;
    hdb_entry *krbtgt;
    EncTicketPart *ticket;
    krb5_pac pac;
};

static krb5_error_code KRB5_LIB_CALL
verify(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;
    struct verify_uc *uc = (struct verify_uc *)userctx;
    krb5_error_code ret;

    if (ft->pac_verify == NULL)
	return KRB5_PLUGIN_NO_HANDLE;

    ret = ft->pac_verify((void *)plug,
			 uc->r,
			 uc->client_principal,
			 uc->delegated_proxy,
			 uc->client, uc->server, uc->krbtgt,
			 uc->ticket, uc->pac);
    return ret;
}

krb5_error_code
_kdc_pac_verify(astgs_request_t r,
		krb5_const_principal client_principal,
		hdb_entry *delegated_proxy,
		hdb_entry *client,
		hdb_entry *server,
		hdb_entry *krbtgt,
		EncTicketPart *ticket,
		krb5_pac pac)
{
    struct verify_uc uc;

    if (!have_plugin)
	return KRB5_PLUGIN_NO_HANDLE;

    uc.r = r;
    uc.client_principal = client_principal;
    uc.delegated_proxy = delegated_proxy;
    uc.client = client;
    uc.server = server;
    uc.krbtgt = krbtgt;
    uc.ticket = ticket,
    uc.pac = pac;

    return _krb5_plugin_run_f(r->context, &kdc_plugin_data,
			     0, &uc, verify);
}

struct update_uc {
    astgs_request_t r;
    krb5_const_principal client_principal;
    hdb_entry *delegated_proxy;
    krb5_const_pac delegated_proxy_pac;
    hdb_entry *client;
    hdb_entry *server;
    hdb_entry *krbtgt;
    krb5_pac *pac;
};

static krb5_error_code KRB5_LIB_CALL
update(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;
    struct update_uc *uc = (struct update_uc *)userctx;
    krb5_error_code ret;

    if (ft->pac_update == NULL)
	return KRB5_PLUGIN_NO_HANDLE;

    ret = ft->pac_update((void *)plug,
			 uc->r,
			 uc->client_principal,
			 uc->delegated_proxy,
			 uc->delegated_proxy_pac,
			 uc->client, uc->server, uc->krbtgt, uc->pac);
    return ret;
}

krb5_error_code
_kdc_pac_update(astgs_request_t r,
		krb5_const_principal client_principal,
		hdb_entry *delegated_proxy,
		krb5_const_pac delegated_proxy_pac,
		hdb_entry *client,
		hdb_entry *server,
		hdb_entry *krbtgt,
		krb5_pac *pac)
{
    struct update_uc uc;

    if (!have_plugin)
	return KRB5_PLUGIN_NO_HANDLE;

    uc.r = r;
    uc.client_principal = client_principal;
    uc.delegated_proxy = delegated_proxy;
    uc.delegated_proxy_pac = delegated_proxy_pac;
    uc.client = client;
    uc.server = server;
    uc.krbtgt = krbtgt;
    uc.pac = pac;

    return _krb5_plugin_run_f(r->context, &kdc_plugin_data,
			     0, &uc, update);
}

static krb5_error_code KRB5_LIB_CALL
check(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;

    if (ft->client_access == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->client_access((void *)plug, userctx);
}

krb5_error_code
_kdc_check_access(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin) {
        ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data,
                                 0, r, check);
    }

    if (ret == KRB5_PLUGIN_NO_HANDLE)
        return kdc_check_flags(r, r->req.msg_type == krb_as_req,
                               r->client, r->server);
    return ret;
}

static krb5_error_code KRB5_LIB_CALL
referral_policy(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;

    if (ft->referral_policy == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->referral_policy((void *)plug, userctx);
}

krb5_error_code
_kdc_referral_policy(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin)
        ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data, 0, r, referral_policy);

    return ret;
}

static krb5_error_code KRB5_LIB_CALL
hwauth_policy(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = plug;

    if (ft->hwauth_policy == NULL) {
	return KRB5_PLUGIN_NO_HANDLE;
    }
    return ft->hwauth_policy((void *)plug, userctx);
}

krb5_error_code
_kdc_hwauth_policy(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin) {
	ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data, 0, r, hwauth_policy);
    }

    if (ret == KRB5_PLUGIN_NO_HANDLE) {
	ret = 0;
    }

    return ret;
}

static krb5_error_code KRB5_LIB_CALL
finalize_reply(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;

    if (ft->finalize_reply == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->finalize_reply((void *)plug, userctx);
}

krb5_error_code
_kdc_finalize_reply(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin)
        ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data, 0, r, finalize_reply);

    if (ret == KRB5_PLUGIN_NO_HANDLE)
        ret = 0;

    return ret;
}

static krb5_error_code KRB5_LIB_CALL
audit(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_kdc_ftable *ft = (const krb5plugin_kdc_ftable *)plug;

    if (ft->audit == NULL)
	return KRB5_PLUGIN_NO_HANDLE;
    return ft->audit((void *)plug, userctx);
}

krb5_error_code
_kdc_plugin_audit(astgs_request_t r)
{
    krb5_error_code ret = KRB5_PLUGIN_NO_HANDLE;

    if (have_plugin)
        ret = _krb5_plugin_run_f(r->context, &kdc_plugin_data, 0, r, audit);

    if (ret == KRB5_PLUGIN_NO_HANDLE)
        ret = 0;

    return ret;
}

KDC_LIB_FUNCTION uintptr_t KDC_LIB_CALL
kdc_get_instance(const char *libname)
{
    static const char *instance = "libkdc";

    if (strcmp(libname, "kdc") == 0)
        return (uintptr_t)instance;
    else if (strcmp(libname, "hdb") == 0)
	return hdb_get_instance(libname);
    else if (strcmp(libname, "krb5") == 0)
        return krb5_get_instance(libname);

    return 0;
}

/*
 * Minimum API surface wrapper for libheimbase object types so it
 * may remain a private interface, yet plugins can interact with
 * objects.
 */

KDC_LIB_FUNCTION kdc_object_t KDC_LIB_CALL
kdc_object_alloc(size_t size, const char *name, kdc_type_dealloc dealloc)
{
    return heim_alloc(size, name, dealloc);
}

KDC_LIB_FUNCTION kdc_object_t KDC_LIB_CALL
kdc_object_retain(kdc_object_t o)
{
    return heim_retain(o);
}

KDC_LIB_FUNCTION void KDC_LIB_CALL
kdc_object_release(kdc_object_t o)
{
    heim_release(o);
}

KDC_LIB_FUNCTION kdc_object_t KDC_LIB_CALL
kdc_bool_create(krb5_boolean v)
{
    return heim_bool_create(v);
}

KDC_LIB_FUNCTION krb5_boolean KDC_LIB_CALL
kdc_bool_get_value(kdc_object_t o)
{
    return heim_bool_val(o);
}

struct kdc_array_iterator_trampoline_data {
    kdc_array_iterator_t iter;
    void *data;
};

/*
 * Calling convention shim to avoid needing to update all internal
 * consumers of heim_array_iterate_f()
 */
static void
_kdc_array_iterator_trampoline(kdc_object_t o, void *data, int *stop)
{
    struct kdc_array_iterator_trampoline_data *t = data;

    t->iter(o, t->data, stop);
}

KDC_LIB_FUNCTION void KDC_LIB_CALL
kdc_array_iterate(kdc_array_t a, void *d, kdc_array_iterator_t iter)
{
    struct kdc_array_iterator_trampoline_data t;

    t.iter = iter;
    t.data = d;

    heim_array_iterate_f((heim_array_t)a, &t, _kdc_array_iterator_trampoline);
}

KDC_LIB_FUNCTION size_t KDC_LIB_CALL
kdc_array_get_length(kdc_array_t a)
{
    return heim_array_get_length((heim_array_t)a);
}

KDC_LIB_FUNCTION kdc_object_t KDC_LIB_CALL
kdc_array_get_value(heim_array_t a, size_t i)
{
    return heim_array_get_value((heim_array_t)a, i);
}

KDC_LIB_FUNCTION kdc_object_t KDC_LIB_CALL
kdc_array_copy_value(heim_array_t a, size_t i)
{
    return heim_array_copy_value((heim_array_t)a, i);
}

KDC_LIB_FUNCTION kdc_string_t KDC_LIB_CALL
kdc_string_create(const char *s)
{
    return (kdc_string_t)heim_string_create(s);
}

KDC_LIB_FUNCTION const char * KDC_LIB_CALL
kdc_string_get_utf8(kdc_string_t s)
{
    return heim_string_get_utf8((heim_string_t)s);
}

KDC_LIB_FUNCTION kdc_data_t
kdc_data_create(const void *d, size_t len)
{
    return (kdc_data_t)heim_data_create(d, len);
}

KDC_LIB_FUNCTION const krb5_data * KDC_LIB_CALL
kdc_data_get_data(kdc_data_t d)
{
    return heim_data_get_data((heim_data_t)d);
}

KDC_LIB_FUNCTION kdc_number_t KDC_LIB_CALL
kdc_number_create(int64_t v)
{
    return (kdc_number_t)heim_number_create(v);
}

KDC_LIB_FUNCTION int64_t KDC_LIB_CALL
kdc_number_get_value(kdc_number_t n)
{
    return heim_number_get_long((heim_number_t)n);
}

/*
 * Plugin accessors
 */

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_request_add_reply_padata(astgs_request_t r, PA_DATA *md)
{
    heim_assert(r->rep.padata != NULL, "reply padata not allocated");
    return add_METHOD_DATA(r->rep.padata, md);
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_request_add_encrypted_padata(astgs_request_t r, PA_DATA *md)
{
    if (r->ek.encrypted_pa_data == NULL) {
	r->ek.encrypted_pa_data = calloc(1, sizeof *(r->ek.encrypted_pa_data));
	if (r->ek.encrypted_pa_data == NULL) {
	    return ENOMEM;
	}
    }

    return add_METHOD_DATA(r->ek.encrypted_pa_data, md);
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_request_add_pac_buffer(astgs_request_t r,
			   uint32_t pactype,
			   const krb5_data *d)
{
    krb5_error_code ret;
    krb5_pac pac;

    if (r->pac == NULL) {
	ret = krb5_pac_init(r->context, &pac);
	if (ret)
	    return ret;
    } else
	pac = heim_retain(r->pac);

    ret = krb5_pac_add_buffer(r->context, pac, pactype, d);
    if (ret == 0 && r->pac == NULL)
	r->pac = pac;
    else
	heim_release(pac);

    return ret;
}

/*
 * Override the e-data field to be returned in an error reply. The data will be
 * owned by the KDC and eventually will be freed with krb5_data_free().
 */
KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_request_set_e_data(astgs_request_t r, heim_octet_string e_data)
{
    krb5_data_free(&r->e_data);
    r->e_data = e_data;

    return 0;
}

#undef _KDC_REQUEST_GET_ACCESSOR
#define _KDC_REQUEST_GET_ACCESSOR(R, T, f)		    \
    KDC_LIB_FUNCTION T KDC_LIB_CALL			    \
    kdc_request_get_ ## f(R r)				    \
    {							    \
	return r->f;					    \
    }

#undef _KDC_REQUEST_SET_ACCESSOR
#define _KDC_REQUEST_SET_ACCESSOR(R, T, f)		    \
    KDC_LIB_FUNCTION void KDC_LIB_CALL			    \
    kdc_request_set_ ## f(R r, T v)			    \
    {							    \
	r->f = v;					    \
    }

#undef _KDC_REQUEST_GET_ACCESSOR_PTR
#define _KDC_REQUEST_GET_ACCESSOR_PTR(R, T,  f)		    \
    KDC_LIB_FUNCTION const T KDC_LIB_CALL		    \
    kdc_request_get_ ## f(R r)				    \
    {							    \
	return r->f;					    \
    }

#undef _KDC_REQUEST_SET_ACCESSOR_PTR
#define _KDC_REQUEST_SET_ACCESSOR_PTR(R, T, t, f)	    \
    KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL	    \
    kdc_request_set_ ## f(R r, const T v)		    \
    {							    \
	krb5_error_code ret;				    \
	T tmp;						    \
							    \
	if (v == r->f)					    \
	    return 0;					    \
	else if (v) {					    \
	    ret = copy_##t(v, &tmp);			    \
	    if (ret)					    \
		return ret;				    \
	} else						    \
	    tmp = NULL;					    \
							    \
	free_##t(r->f);					    \
	r->f = tmp;					    \
							    \
	return 0;					    \
    }

#undef _KDC_REQUEST_GET_ACCESSOR_STRUCT
#define _KDC_REQUEST_GET_ACCESSOR_STRUCT(R, T, f)	    \
    KDC_LIB_FUNCTION const T * KDC_LIB_CALL		    \
    kdc_request_get_ ## f(R r)				    \
    {							    \
	return &r->f;					    \
    }

#undef _KDC_REQUEST_SET_ACCESSOR_STRUCT
#define _KDC_REQUEST_SET_ACCESSOR_STRUCT(R, T, t, f)	    \
    KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL	    \
    kdc_request_set_ ## f(R r, const T *v)		    \
    {							    \
	krb5_error_code ret;				    \
	T tmp;						    \
							    \
	if (v == NULL)					    \
	    return EINVAL;				    \
	else if (v == &r->f)				    \
	    return 0;					    \
							    \
	ret = copy_##t(v, &tmp);			    \
	if (ret)					    \
	    return ret;					    \
							    \
	free_##t(&r->f);				    \
	r->f = tmp;					    \
							    \
	return 0;					    \
    }

static krb5_error_code
copy_string_ptr(const char *src, char **dst)
{
    *dst = strdup(src);
    if (*dst == NULL)
	return ENOMEM;

    return 0;
}

static void
free_string_ptr(char *s)
{
    free(s);
}

static krb5_error_code
copy_Principal_ptr(krb5_const_principal src, krb5_principal *dst)
{
    krb5_error_code ret;
    krb5_principal p;

    *dst = NULL;

    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return ENOMEM;

    ret = copy_Principal(src, p);
    if (ret == 0)
	*dst = p;
    else
	free(p);

    return ret;
}

static void
free_Principal_ptr(krb5_principal p)
{
    if (p) {
	free_Principal(p);
	free(p);
    }
}

static krb5_error_code
copy_pac(const struct krb5_pac_data *src, struct krb5_pac_data **dst)
{
    /* FIXME use heim_copy() when it exists */
    *dst = (krb5_pac)heim_retain((heim_object_t)src);
    return 0;
}

static void
free_pac(struct krb5_pac_data *o)
{
    heim_release(o);
}

static krb5_error_code
copy_keyblock(const EncryptionKey *src, EncryptionKey *dst)
{
    return copy_EncryptionKey(src, dst);
}

static void
free_keyblock(EncryptionKey *key)
{
    krb5_free_keyblock_contents(NULL, key);
}

#undef HEIMDAL_KDC_KDC_ACCESSORS_H
#include "kdc-accessors.h"

#undef _KDC_REQUEST_GET_ACCESSOR
#undef _KDC_REQUEST_SET_ACCESSOR

#undef _KDC_REQUEST_GET_ACCESSOR_PTR
#undef _KDC_REQUEST_SET_ACCESSOR_PTR
#define _KDC_REQUEST_SET_ACCESSOR_PTR(R, T, t, f)	    \
    void						    \
    _kdc_request_set_ ## f ## _nocopy(R r, T *v)	    \
    {							    \
	if (*v != r->f) {				    \
	    free_##t(r->f);				    \
	    r->f = *v;					    \
	}						    \
	*v = NULL;					    \
    }

#undef _KDC_REQUEST_GET_ACCESSOR_STRUCT
#undef _KDC_REQUEST_SET_ACCESSOR_STRUCT
#define _KDC_REQUEST_SET_ACCESSOR_STRUCT(R, T, t, f)	    \
    void						    \
    _kdc_request_set_ ## f ## _nocopy(R r, T *v)	    \
    {							    \
	if (v != &r->f) {				    \
	    free_##t(&r->f);				    \
	    r->f = *v;					    \
	}						    \
	memset(v, 0, sizeof(*v));			    \
    }

#undef HEIMDAL_KDC_KDC_ACCESSORS_H
#include "kdc-accessors.h"

KDC_LIB_FUNCTION const HDB * KDC_LIB_CALL
kdc_request_get_explicit_armor_clientdb(astgs_request_t r)
{
    return r->explicit_armor_present ? r->armor_clientdb : NULL;
}

KDC_LIB_FUNCTION const hdb_entry * KDC_LIB_CALL
kdc_request_get_explicit_armor_client(astgs_request_t r)
{
    return r->explicit_armor_present ? r->armor_client : NULL;
}

KDC_LIB_FUNCTION const Principal * KDC_LIB_CALL
kdc_request_get_explicit_armor_client_principal(astgs_request_t r)
{
    return r->explicit_armor_present ? r->armor_client_principal : NULL;
}

KDC_LIB_FUNCTION const hdb_entry * KDC_LIB_CALL
kdc_request_get_explicit_armor_server(astgs_request_t r)
{
    return r->explicit_armor_present ? r->armor_server : NULL;
}

KDC_LIB_FUNCTION krb5_const_pac KDC_LIB_CALL
kdc_request_get_explicit_armor_pac(astgs_request_t r)
{
    return r->explicit_armor_present ? r->armor_pac : NULL;
}
