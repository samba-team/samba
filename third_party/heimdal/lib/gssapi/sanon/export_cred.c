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

OM_uint32 GSSAPI_CALLCONV
_gss_sanon_export_cred(OM_uint32 *minor,
		       gss_cred_id_t input_cred,
		       gss_buffer_t token)
{
    gss_buffer_desc buf;
    krb5_storage *sp;
    krb5_data data_out, data;
    OM_uint32 major, junk;

    token->value = NULL;
    token->length = 0;

    major = _gss_sanon_export_name(minor, (gss_name_t)input_cred, &buf);
    if (major)
	return major;

    sp = krb5_storage_emem();
    if (sp == NULL) {
	gss_release_buffer(&junk, &buf);
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }

    major = _gss_mg_store_oid(minor, sp, GSS_SANON_X25519_MECHANISM);
    if (major) {
	gss_release_buffer(&junk, &buf);
	krb5_storage_free(sp);
	return major;
    }
    data_out.length = 0;
    data_out.data = NULL;
    data.length = buf.length;
    data.data = buf.value;
    *minor = krb5_store_data(sp, data);
    if (*minor == 0)
	*minor = krb5_storage_to_data(sp, &data_out);
    if (*minor == 0) {
	token->value = data_out.data;
	token->length = data_out.length;
    }
    gss_release_buffer(&junk, &buf);
    krb5_storage_free(sp);
    return major;
}
