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
#include <roken.h>


OM_uint32
gss_krb5_copy_ccache(OM_uint32 *minor_status,
		     gss_cred_id_t cred,
		     krb5_ccache out)
{
    gss_buffer_set_t data_set = GSS_C_NO_BUFFER_SET;
    krb5_context context;
    krb5_error_code kret;
    krb5_ccache id;
    OM_uint32 ret;
    char *str;

    ret = gss_inquire_cred_by_oid(minor_status,
				  cred,
				  GSS_KRB5_COPY_CCACHE_X,
				  &data_set);
    if (ret)
	return ret;

    if (data_set == GSS_C_NO_BUFFER_SET || data_set->count != 1) {
	gss_release_buffer_set(minor_status, &data_set);
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    kret = krb5_init_context(&context);
    if (kret) {
	*minor_status = kret;
	gss_release_buffer_set(minor_status, &data_set);
	return GSS_S_FAILURE;
    }

    kret = asprintf(&str, "%.*s", (int)data_set->elements[0].length,
		    (char *)data_set->elements[0].value);
    gss_release_buffer_set(minor_status, &data_set);
    if (kret == -1) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    kret = krb5_cc_resolve(context, str, &id);
    free(str);
    if (kret) {
	*minor_status = kret;
	return GSS_S_FAILURE;
    }

    kret = krb5_cc_copy_cache(context, id, out);
    krb5_cc_close(context, id);
    krb5_free_context(context);
    if (kret) {
	*minor_status = kret;
	return GSS_S_FAILURE;
    }

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

    *cred = GSS_C_NO_CREDENTIAL;

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

OM_uint32
gsskrb5_register_acceptor_identity(const char *identity)
{
        struct _gss_mech_switch	*m;
	gss_buffer_desc buffer;
	OM_uint32 junk;

	_gss_load_mech();

	buffer.value = rk_UNCONST(identity);
	buffer.length = strlen(identity);

	SLIST_FOREACH(m, &_gss_mechs, gm_link) {
		if (m->gm_mech.gm_set_sec_context_option == NULL)
			continue;
		m->gm_mech.gm_set_sec_context_option(&junk, NULL,
		    GSS_KRB5_REGISTER_ACCEPTOR_IDENTITY_X, &buffer);
	}

	return (GSS_S_COMPLETE);
}
