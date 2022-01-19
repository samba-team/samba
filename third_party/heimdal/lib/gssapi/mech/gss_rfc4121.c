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

#include "mech_locl.h"

/*
 * An internal API (for now) to return a mechglue context handle given
 * a session key that can provide RFC 4121 compatible message protection
 * and PRF services. Used by SAnon. The implementation of those services
 * is currently provided by the krb5 GSS mechanism but that is opaque to
 * the caller (minor status codes notwithstanding).
 */
OM_uint32
_gss_mg_import_rfc4121_context(OM_uint32 *minor,
			       uint8_t initiator_flag,
			       OM_uint32 gss_flags,
			       int32_t rfc3961_enctype,
			       gss_const_buffer_t session_key,
			       gss_ctx_id_t *rfc4121_context_handle)
{
    OM_uint32 major = GSS_S_FAILURE, tmpMinor;
    krb5_storage *sp;
    krb5_error_code ret;
    krb5_data d;
    gss_buffer_desc rfc4121_args = GSS_C_EMPTY_BUFFER;

    krb5_data_zero(&d);

    *minor = 0;
    *rfc4121_context_handle = GSS_C_NO_CONTEXT;

    sp = krb5_storage_emem();
    if (sp == NULL) {
	ret = ENOMEM;
	goto out;
    }

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_HOST);

    /*
     * The arguments GSS_KRB5_IMPORT_RFC4121_CONTEXT_X are the serialized
     * form of initiator_flag || flags || keytype || session_key. The session
     * key length is inferred from the keytype.
     */
    ret = krb5_store_uint8(sp, initiator_flag);
    if (ret != 0)
	goto out;

    ret = krb5_store_uint32(sp, gss_flags);
    if (ret != 0)
	goto out;

    ret = krb5_store_int32(sp, rfc3961_enctype);
    if (ret != 0)
	goto out;

    if (krb5_storage_write(sp, session_key->value, session_key->length)
	!= session_key->length) {
	ret = ENOMEM;
	goto out;
    }

    ret = krb5_storage_to_data(sp, &d);
    if (ret != 0)
	goto out;

    rfc4121_args.length = d.length;
    rfc4121_args.value = d.data;

    major = gss_set_sec_context_option(minor, rfc4121_context_handle,
				       GSS_KRB5_IMPORT_RFC4121_CONTEXT_X,
				       &rfc4121_args);

out:
    _gss_secure_release_buffer(&tmpMinor, &rfc4121_args);
    krb5_storage_free(sp);

    if (major == GSS_S_FAILURE && *minor == 0)
	*minor = ret;

    return major;
}

