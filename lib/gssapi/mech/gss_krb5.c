/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_krb5.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"
RCSID("$Id$");

#include <krb5.h>


OM_uint32
gss_krb5_copy_ccache(OM_uint32 *minor_status,
		     gss_cred_id_t cred,
		     krb5_ccache out)
{
    krb5_context context;
    OM_uint32 ret;
    krb5_error_code kret;
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;
    const char *prefix;

    ret = gss_inquire_cred_by_oid(minor_status,
				  cred,
				  GSS_KRB5_COPY_CCACHE_X,
				  &data_set);
    if (ret) {
	return ret;
    }

    if (data_set == GSS_C_NO_BUFFER_SET ||
	data_set->count != 2) {
	gss_release_buffer_set(minor_status, &data_set);
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    prefix = (const char *)data_set->elements[0].value;

    kret = krb5_init_context(&context);
    if (out->ops == NULL) {
	*minor_status = ENOENT;
	gss_release_buffer_set(minor_status, &data_set);
	return GSS_S_FAILURE;
    }

    out->ops = krb5_cc_get_prefix_ops(context, prefix);
    krb5_free_context(context);
    if (out->ops == NULL) {
	*minor_status = ENOENT;
	gss_release_buffer_set(minor_status, &data_set);
	return GSS_S_FAILURE;
    }

    out->data.data = data_set->elements[1].value;
    out->data.length = data_set->elements[1].length;
    data_set->elements[1].value = NULL;
    data_set->elements[1].length = 0;

    data_set->count--;

    gss_release_buffer_set(minor_status, &data_set);

    return ret;
}

OM_uint32
gss_krb5_import_cred(OM_uint32 *minor_status,
		     krb5_ccache id,
		     krb5_principal keytab_principal,
		     krb5_keytab keytab,
		     gss_cred_id_t *cred)
{
    gss_buffer_desc buffer;
    OM_uint32 major_status;
    krb5_context context;
    krb5_error_code ret;
    krb5_storage *sp;
    krb5_data data;
    char *str;

    ret = krb5_init_context(&context);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    sp = krb5_storage_emem();
    if (sp == NULL) {
	*minor_status = ENOMEM;
	major_status = GSS_S_FAILURE;
	goto out;
    }

    if (id) {
	ret = krb5_cc_get_full_name(context, id, &str);
	if (ret == 0) {
	    ret = krb5_store_string(sp, str);
	    free(str);
	}
    } else
	ret = krb5_store_string(sp, "");
    if (ret) {
	*minor_status = ret;
	major_status = GSS_S_FAILURE;
	goto out;
    }

    if (keytab_principal) {
	ret = krb5_unparse_name(context, keytab_principal, &str);
	if (ret == 0) {
	    ret = krb5_store_string(sp, str);
	    free(str);
	}
    } else
	krb5_store_string(sp, "");
    if (ret) {
	*minor_status = ret;
	major_status = GSS_S_FAILURE;
	goto out;
    }


    if (keytab) {
	ret = krb5_kt_get_full_name(context, keytab, &str);
	if (ret == 0) {
	    ret = krb5_store_string(sp, str);
	    free(str);
	}
    } else
	krb5_store_string(sp, "");
    if (ret) {
	*minor_status = ret;
	major_status = GSS_S_FAILURE;
	goto out;
    }

    krb5_storage_to_data(sp, &data);

    buffer.value = data.data;
    buffer.length = data.length;
    
    major_status = gss_set_cred_option(minor_status,
				       cred,
				       GSS_KRB5_IMPORT_CRED_X,
				       &buffer);
    krb5_data_free(&data);
out:
    if (sp)
	krb5_storage_free(sp);
    krb5_free_context(context);
    return major_status;
}

#if 0
OM_uint32
gsskrb5_register_acceptor_identity(const char *identity)
{
	gssapi_mech_interface m;

	_gss_load_mech();
	SLIST_FOREACH(m, &_gss_mechs, gm_link) {
		if (m->gm_krb5_register_acceptor_identity)
			m->gm_krb5_register_acceptor_identity(identity);
	}

	return (GSS_S_COMPLETE);
}

OM_uint32
gss_krb5_copy_ccache(OM_uint32 *minor_status,
    gss_cred_id_t cred_handle,
    struct krb5_ccache_data *out)
{
	struct _gss_mechanism_cred *mcp;
	struct _gss_cred *cred = (struct _gss_cred *) cred_handle;
	gssapi_mech_interface m;

	*minor_status = 0;

	SLIST_FOREACH(mcp, &cred->gc_mc, gmc_link) {
		m = mcp->gmc_mech;
		if (m->gm_krb5_copy_ccache)
			return (m->gm_krb5_copy_ccache(minor_status,
				mcp->gmc_cred, out));
	}

	return (GSS_S_FAILURE);
}

OM_uint32
gss_krb5_compat_des3_mic(OM_uint32 *minor_status,
    gss_ctx_id_t context_handle, int flag)
{
	struct _gss_context *ctx = (struct _gss_context *) context_handle;
	gssapi_mech_interface m = ctx->gc_mech;

	*minor_status = 0;

	if (m->gm_krb5_compat_des3_mic)
		return (m->gm_krb5_compat_des3_mic(minor_status,
			ctx->gc_ctx, flag));

	return (GSS_S_FAILURE);
}
#endif

