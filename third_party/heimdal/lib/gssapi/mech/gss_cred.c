/*
 * Copyright (c) 2017 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mech_locl.h"
#include <krb5.h>

static OM_uint32
store_mech_oid_and_oid_set(OM_uint32 *minor_status,
			   krb5_storage *sp,
			   gss_const_OID mech,
			   gss_const_OID_set oids)
{
    OM_uint32 ret;
    size_t i, len;

    ret = _gss_mg_store_oid(minor_status, sp, mech);
    if (ret)
	return ret;

    for (i = 0, len = 0; i < oids->count; i++)
	len += 4 + oids->elements[i].length;

    *minor_status = krb5_store_uint32(sp, len);
    if (*minor_status)
	return GSS_S_FAILURE;

    for (i = 0; i < oids->count; i++) {
	ret = _gss_mg_store_oid(minor_status, sp, &oids->elements[i]);
	if (ret)
	    return ret;
    }

    return GSS_S_COMPLETE;
}


/*
 * format: any number of:
 *     mech-len: int32
 *     mech-data: char * (not alligned)
 *     cred-len: int32
 *     cred-data char * (not alligned)
 *
 * where neg_mechs is encoded for GSS_SPNEGO_MECHANISM
*/

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_export_cred(OM_uint32 * minor_status,
		gss_cred_id_t cred_handle,
		gss_buffer_t token)
{
    struct _gss_cred *cred = (struct _gss_cred *)cred_handle;
    struct _gss_mechanism_cred *mc;
    gss_buffer_desc buffer;
    krb5_error_code ret;
    krb5_ssize_t bytes;
    krb5_storage *sp;
    OM_uint32 major;
    krb5_data data;

    _mg_buffer_zero(token);

    if (cred == NULL) {
	*minor_status = 0;
	return GSS_S_NO_CRED;
    }

    HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link) {
	if (mc->gmc_mech->gm_export_cred == NULL) {
	    *minor_status = 0;
	    gss_mg_set_error_string(&mc->gmc_mech->gm_mech_oid,
				    GSS_S_NO_CRED, *minor_status,
				    "Credential doesn't support exporting");
	    return GSS_S_NO_CRED;
	}
    }

    sp = krb5_storage_emem();
    if (sp == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link) {
	major = mc->gmc_mech->gm_export_cred(minor_status,
					     mc->gmc_cred, &buffer);
	if (major) {
	    krb5_storage_free(sp);
	    return major;
	}

	if (buffer.length) {
	    bytes = krb5_storage_write(sp, buffer.value, buffer.length);
	    if (bytes < 0 || (size_t)bytes != buffer.length) {
		_gss_secure_release_buffer(minor_status, &buffer);
		krb5_storage_free(sp);
		*minor_status = EINVAL;
		return GSS_S_FAILURE;
	    }
	}
	_gss_secure_release_buffer(minor_status, &buffer);
    }

    if (cred->gc_neg_mechs != GSS_C_NO_OID_SET) {
	major = store_mech_oid_and_oid_set(minor_status, sp,
					   GSS_SPNEGO_MECHANISM,
					   cred->gc_neg_mechs);
	if (major != GSS_S_COMPLETE) {
	    krb5_storage_free(sp);
	    return major;
	}
    }

    ret = krb5_storage_to_data(sp, &data);
    krb5_storage_free(sp);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    if (data.length == 0) {
	*minor_status = 0;
	gss_mg_set_error_string(GSS_C_NO_OID,
				GSS_S_NO_CRED, *minor_status,
				"Credential was not exportable");
	return GSS_S_NO_CRED;
    }

    token->value = data.data;
    token->length = data.length;

    return GSS_S_COMPLETE;
}

static OM_uint32
import_oid_set(OM_uint32 *minor_status,
	       gss_const_buffer_t token,
	       gss_OID_set *oids)
{
    OM_uint32 major, junk;
    krb5_storage *sp = NULL;

    *oids = GSS_C_NO_OID_SET;

    if (token->length == 0)
	return GSS_S_COMPLETE;

    major = gss_create_empty_oid_set(minor_status, oids);
    if (major != GSS_S_COMPLETE)
	goto out;

    sp = krb5_storage_from_readonly_mem(token->value, token->length);
    if (sp == NULL) {
	*minor_status = ENOMEM;
	major = GSS_S_FAILURE;
	goto out;
    }

    while (1) {
	gss_OID oid;

	major = _gss_mg_ret_oid(minor_status, sp, &oid);
	if (*minor_status == (OM_uint32)HEIM_ERR_EOF)
	    break;
	else if (major)
	    goto out;

	major = gss_add_oid_set_member(minor_status, oid, oids);
	if (major != GSS_S_COMPLETE)
	    goto out;
    }

    major = GSS_S_COMPLETE;
    *minor_status = 0;

out:
    if (major != GSS_S_COMPLETE)
	gss_release_oid_set(&junk, oids);
    krb5_storage_free(sp);

    return major;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_import_cred(OM_uint32 * minor_status,
		gss_buffer_t token,
		gss_cred_id_t * cred_handle)
{
    gssapi_mech_interface m;
    struct _gss_cred *cred;
    krb5_storage *sp = NULL;
    OM_uint32 major, junk;

    *cred_handle = GSS_C_NO_CREDENTIAL;

    if (token->length == 0) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    sp = krb5_storage_from_readonly_mem(token->value, token->length);
    if (sp == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    cred = _gss_mg_alloc_cred();
    if (cred == NULL) {
	krb5_storage_free(sp);
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    *cred_handle = (gss_cred_id_t)cred;

    while(1) {
	struct _gss_mechanism_cred *mc;
	gss_buffer_desc buffer;
	gss_cred_id_t mcred;
	gss_OID oid;

	major = _gss_mg_ret_oid(minor_status, sp, &oid);
	if (*minor_status == (OM_uint32)HEIM_ERR_EOF)
	    break;
	else if (major != GSS_S_COMPLETE)
	    goto out;

	m = __gss_get_mechanism(oid);
	if (!m) {
	    *minor_status = 0;
	    major = GSS_S_BAD_MECH;
	    goto out;
	}

	if (m->gm_import_cred == NULL) {
	    *minor_status = 0;
	    major = GSS_S_BAD_MECH;
	    goto out;
	}

	major = _gss_mg_ret_buffer(minor_status, sp, &buffer);
	if (major != GSS_S_COMPLETE)
	    goto out;

	if (buffer.value == NULL) {
	    major = GSS_S_DEFECTIVE_TOKEN;
	    goto out;
	}

	if (gss_oid_equal(&m->gm_mech_oid, GSS_SPNEGO_MECHANISM)) {
	    major = import_oid_set(minor_status, &buffer, &cred->gc_neg_mechs);
	    gss_release_buffer(&junk, &buffer);
	    if (major != GSS_S_COMPLETE)
		goto out;
	    else
		continue;
	}

	major = m->gm_import_cred(minor_status, &buffer, &mcred);
	gss_release_buffer(&junk, &buffer);
	if (major != GSS_S_COMPLETE)
	    goto out;

	mc = calloc(1, sizeof(struct _gss_mechanism_cred));
	if (mc == NULL) {
	    *minor_status = EINVAL;
	    major = GSS_S_FAILURE;
	    goto out;
	}

	mc->gmc_mech = m;
	mc->gmc_mech_oid = &m->gm_mech_oid;
	mc->gmc_cred = mcred;

	HEIM_TAILQ_INSERT_TAIL(&cred->gc_mc, mc, gmc_link);
    }
    krb5_storage_free(sp);
    sp = NULL;

    if (HEIM_TAILQ_EMPTY(&cred->gc_mc)) {
	major = GSS_S_NO_CRED;
	goto out;
    }

    return GSS_S_COMPLETE;

 out:
    if (sp)
	krb5_storage_free(sp);

    gss_release_cred(&junk, cred_handle);

    return major;

}

