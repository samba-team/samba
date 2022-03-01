/*
 * Copyright (c) 2019-2020, AuriStor, Inc.
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

#include "sanon_locl.h"

static int
is_anonymous_identity_p(gss_buffer_t name_string, gss_OID name_type)
{
    if (gss_oid_equal(name_type, GSS_C_NT_ANONYMOUS))
	return TRUE;
    else if ((name_type == GSS_C_NO_OID ||
	      gss_oid_equal(name_type, GSS_C_NT_USER_NAME) ||
	      gss_oid_equal(name_type, GSS_KRB5_NT_PRINCIPAL_NAME)) &&
	buffer_equal_p(name_string, _gss_sanon_wellknown_user_name))
	return TRUE;
    else if (gss_oid_equal(name_type, GSS_C_NT_HOSTBASED_SERVICE) &&
	buffer_equal_p(name_string, _gss_sanon_wellknown_service_name))
	return TRUE;

    return FALSE;
}

static krb5_error_code
storage_ret_der_oid(krb5_storage *sp, gss_OID_desc *oid)
{
    krb5_error_code ret;
    uint16_t der_oid_len;
    uint8_t oid_len, tag;

    oid->length = 0;
    oid->elements = NULL;

    ret = krb5_ret_uint16(sp, &der_oid_len);
    if (ret == 0)
        ret = krb5_ret_uint8(sp, &tag);
    if (ret == 0)
        ret = krb5_ret_uint8(sp, &oid_len);
    if (ret)
	return ret;
    if (tag != 0x06)
	return EINVAL;

    if (der_oid_len != 2 + oid_len)
	return EINVAL;

    oid->elements = malloc(oid_len);
    if (oid->elements == NULL)
	return ENOMEM;

    if (krb5_storage_read(sp, oid->elements, oid_len) != oid_len) {
	free(oid->elements);
	oid->elements = NULL;
	oid->length = 0;
	return EINVAL;
    }

    oid->length = oid_len;

    return 0;
}

static OM_uint32
import_export_name(OM_uint32 *minor,
		   const gss_buffer_t input_name_buffer,
		   gss_name_t *output_name)
{
    OM_uint32 major;
    krb5_error_code ret;
    krb5_storage *sp;
    uint32_t name_len = 0;
    uint16_t tok_id;
    gss_OID_desc oid_buf = { 0, NULL };
    uint8_t is_anonymous;

    sp = krb5_storage_from_readonly_mem(input_name_buffer->value,
					input_name_buffer->length);
    if (sp == NULL) {
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_BE);

    major = GSS_S_BAD_NAME;
    *minor = 0;

    ret = krb5_ret_uint16(sp, &tok_id);
    if (ret == 0 && tok_id != 0x0401)
	ret = EINVAL;
    if (ret == 0)
	ret = storage_ret_der_oid(sp, &oid_buf);
    if (ret == 0) {
	if (!gss_oid_equal(&oid_buf, GSS_SANON_X25519_MECHANISM))
	    ret = EINVAL;
	free(oid_buf.elements);
    }
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &name_len);
    if (ret == 0)
        ret = krb5_ret_uint8(sp, &is_anonymous);
    if (ret == 0) {
        if (name_len != 1)
            ret = EINVAL;
	if (is_anonymous == 1) {
	    *output_name = _gss_sanon_anonymous_identity;
	    major = GSS_S_COMPLETE;
	} else {
	    major = GSS_S_BAD_NAME;
	}
    }

    krb5_storage_free(sp);

    if (*minor == 0)
	*minor = ret;

    return major;
}

OM_uint32 GSSAPI_CALLCONV
_gss_sanon_import_name(OM_uint32 *minor,
		       const gss_buffer_t input_name_buffer,
		       const gss_OID input_name_type,
		       gss_name_t *output_name)
{
    if (gss_oid_equal(input_name_type, GSS_C_NT_EXPORT_NAME))
	return import_export_name(minor, input_name_buffer, output_name);

    *minor = 0;
    *output_name =
	is_anonymous_identity_p(input_name_buffer, input_name_type) ?
	    _gss_sanon_anonymous_identity : _gss_sanon_non_anonymous_identity;

    return GSS_S_COMPLETE;
}
