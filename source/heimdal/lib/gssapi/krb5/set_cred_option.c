/*
 * Copyright (c) 2004, PADL Software Pty Ltd.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5/gsskrb5_locl.h"

RCSID("$Id: set_cred_option.c,v 1.4 2006/10/24 20:14:13 lha Exp $");

static gss_OID_desc gss_krb5_import_cred_x_oid_desc =
{9, (void *)"\x2b\x06\x01\x04\x01\xa9\x4a\x13\x04"}; /* XXX */

gss_OID GSS_KRB5_IMPORT_CRED_X = &gss_krb5_import_cred_x_oid_desc;

static OM_uint32
import_cred(OM_uint32 *minor_status,
            gss_cred_id_t *cred_handle,
            const gss_buffer_t value)
{
    OM_uint32 major_stat;
    krb5_error_code ret;
    krb5_principal keytab_principal = NULL;
    krb5_keytab keytab = NULL;
    krb5_storage *sp = NULL;
    krb5_ccache id = NULL;
    char *str;

    if (cred_handle == NULL || *cred_handle != GSS_C_NO_CREDENTIAL) {
	*minor_status = 0;
	return GSS_S_FAILURE;
    }

    sp = krb5_storage_from_mem(value->value, value->length);
    if (sp == NULL) {
	*minor_status = 0;
	return GSS_S_FAILURE;
    }

    /* credential cache name */
    ret = krb5_ret_string(sp, &str);
    if (ret) {
	*minor_status = ret;
	major_stat =  GSS_S_FAILURE;
	goto out;
    }
    if (str[0]) {
	ret = krb5_cc_resolve(_gsskrb5_context, str, &id);
	if (ret) {
	    *minor_status = ret;
	    major_stat =  GSS_S_FAILURE;
	    goto out;
	}
    }
    free(str);
    str = NULL;

    /* keytab principal name */
    ret = krb5_ret_string(sp, &str);
    if (ret == 0 && str[0])
	ret = krb5_parse_name(_gsskrb5_context, str, &keytab_principal);
    if (ret) {
	*minor_status = ret;
	major_stat = GSS_S_FAILURE;
	goto out;
    }
    free(str);
    str = NULL;

    /* keytab principal */
    ret = krb5_ret_string(sp, &str);
    if (ret) {
	*minor_status = ret;
	major_stat =  GSS_S_FAILURE;
	goto out;
    }
    if (str[0]) {
	ret = krb5_kt_resolve(_gsskrb5_context, str, &keytab);
	if (ret) {
	    *minor_status = ret;
	    major_stat =  GSS_S_FAILURE;
	    goto out;
	}
    }
    free(str);
    str = NULL;

    major_stat = _gsskrb5_import_cred(minor_status, id, keytab_principal,
				      keytab, cred_handle);
out:
    if (id)
	krb5_cc_close(_gsskrb5_context, id);
    if (keytab_principal)
	krb5_free_principal(_gsskrb5_context, keytab_principal);
    if (keytab)
	krb5_kt_close(_gsskrb5_context, keytab);
    if (str)
	free(str);
    if (sp)
	krb5_storage_free(sp);

    return major_stat;
}


OM_uint32
_gsskrb5_set_cred_option
           (OM_uint32 *minor_status,
            gss_cred_id_t *cred_handle,
            const gss_OID desired_object,
            const gss_buffer_t value)
{
    GSSAPI_KRB5_INIT ();

    if (value == GSS_C_NO_BUFFER) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    if (gss_oid_equal(desired_object, GSS_KRB5_IMPORT_CRED_X)) {
	return import_cred(minor_status, cred_handle, value);
    }

    *minor_status = EINVAL;
    return GSS_S_FAILURE;
}
