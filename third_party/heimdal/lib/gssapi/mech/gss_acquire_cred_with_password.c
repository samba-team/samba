/*
 * Copyright (c) 2011, PADL Software Pty Ltd.
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

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_acquire_cred_with_password(OM_uint32 *minor_status,
			       gss_const_name_t desired_name,
			       const gss_buffer_t password,
			       OM_uint32 time_req,
			       const gss_OID_set desired_mechs,
			       gss_cred_usage_t cred_usage,
			       gss_cred_id_t *output_cred_handle,
			       gss_OID_set *actual_mechs,
			       OM_uint32 *time_rec)
{
    OM_uint32 major_status;
    gss_key_value_element_desc kv;
    gss_key_value_set_desc store;
    char *spassword = NULL;

    *output_cred_handle = GSS_C_NO_CREDENTIAL;

    if (password == GSS_C_NO_BUFFER || password->value == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ;

    spassword = malloc(password->length + 1);
    if (spassword == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    memcpy(spassword, password->value, password->length);
    spassword[password->length] = '\0';

    kv.key = "password";
    kv.value = spassword;

    store.count = 1;
    store.elements = &kv;

    major_status = gss_acquire_cred_from(minor_status,
					 desired_name,
					 time_req,
					 desired_mechs,
					 cred_usage,
					 &store,
					 output_cred_handle,
					 actual_mechs,
					 time_rec);
    if (spassword) {
	memset_s(spassword, password->length, 0, password->length);
	free(spassword);
    }

    return major_status;
}
