/*
 * Copyright (C) 2019 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <roken.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <krb5.h>
#include <der.h>
#include <gssapi_asn1.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_spnego.h>

struct test_context {
    int initiator;
    uint8_t hops;	       /* hops remaining; 0 means established */
};

OM_uint32 GSSAPI_CALLCONV
gss_init_sec_context(OM_uint32 *minor_status,
		     gss_const_cred_id_t claimant_cred_handle,
		     gss_ctx_id_t *context_handle, gss_const_name_t target_name,
		     const gss_OID mech_type, OM_uint32 req_flags,
		     OM_uint32 time_req,
		     const gss_channel_bindings_t input_chan_bindings,
		     const gss_buffer_t input_token, gss_OID *actual_mech,
		     gss_buffer_t output_token, OM_uint32 *ret_flags,
		     OM_uint32 *time_rec)
{
    struct test_context *ctx = (struct test_context *)*context_handle;
    OM_uint32 major;
    gss_buffer_desc tok;
    const char *envstr;
    uint8_t hops, mech_last_octet;

    if (actual_mech)
	*actual_mech = GSS_C_NO_OID;
    if (ret_flags)
	*ret_flags = 0;
    if (time_rec)
	*time_rec = 0;

    major = gss_duplicate_oid(minor_status, mech_type, actual_mech);
    if (major != GSS_S_COMPLETE)
	return major;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
	envstr = getenv("HOPS");
	hops = (envstr != NULL) ? atoi(envstr) : 1;
	assert(hops > 0);
    } else if (input_token->length == 4 &&
	       memcmp(input_token->value, "fail", 4) == 0) {
	*minor_status = 12345;
	return GSS_S_FAILURE;
    } else {
	hops = ((uint8_t *)input_token->value)[0];
    }

    mech_last_octet = ((uint8_t *)mech_type->elements)[mech_type->length - 1];
    envstr = getenv("INIT_FAIL");
    if (envstr != NULL && atoi(envstr) == mech_last_octet)
	return GSS_S_FAILURE;

    if (ctx == NULL) {
	ctx = malloc(sizeof(*ctx));
	assert(ctx != NULL);
	ctx->initiator = 1;
	ctx->hops = hops;
	*context_handle = (gss_ctx_id_t)ctx;
    } else if (ctx != NULL) {
	assert(ctx->initiator);
	ctx->hops--;
	assert(ctx->hops == hops);
    }

    if (ctx->hops > 0) {
	/* Generate a token containing the remaining hop count. */
	ctx->hops--;
	tok.value = &ctx->hops;
	tok.length = 1;
	major = gss_encapsulate_token(&tok, mech_type, output_token);
	assert(major == GSS_S_COMPLETE);
    }

    return (ctx->hops > 0) ? GSS_S_CONTINUE_NEEDED : GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_accept_sec_context(OM_uint32 *minor_status, gss_ctx_id_t *context_handle,
		       gss_const_cred_id_t verifier_cred_handle,
		       const gss_buffer_t input_token,
		       const gss_channel_bindings_t input_chan_bindings,
		       gss_name_t *src_name, gss_OID *mech_type,
		       gss_buffer_t output_token, OM_uint32 *ret_flags,
		       OM_uint32 *time_rec,
		       gss_cred_id_t *delegated_cred_handle)
{
    struct test_context *ctx = (struct test_context *)*context_handle;
    uint8_t hops, mech_last_octet;
    const char *envstr;
    unsigned char mechbuf[64];
    GSSAPIContextToken ct;
    gss_OID_desc oid;
    int ret;
    size_t mech_len;

    if (src_name)
	*src_name = GSS_C_NO_NAME;
    if (mech_type)
	*mech_type = GSS_C_NO_OID;
    if (ret_flags)
	*ret_flags = 0;
    if (time_rec)
	*time_rec = 0;
    if (delegated_cred_handle)
	*delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    ret = decode_GSSAPIContextToken(input_token->value, input_token->length,
				    &ct, NULL);
    if (ret == 0) {
	ret = der_put_oid ((unsigned char *)mechbuf + sizeof(mechbuf) - 1,
			   sizeof(mechbuf),
			   &ct.thisMech,
			   &mech_len);
	free_GSSAPIContextToken(&ct);
    }
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    oid.length   = (OM_uint32)mech_len;
    oid.elements = mechbuf + sizeof(mechbuf) - mech_len;

    if (mech_type)
	gss_duplicate_oid(minor_status, &oid, mech_type);

    /*
     * The unwrapped token sits at the end and is just one byte giving the
     * remaining number of hops.  The final octet of the mech encoding should
     * be just prior to it.
     */
    assert(input_token->length >= 2);
    hops = ((uint8_t *)input_token->value)[input_token->length - 1];
    mech_last_octet = ((uint8_t *)input_token->value)[input_token->length - 2];

    envstr = getenv("ACCEPT_FAIL");
    if (envstr != NULL && atoi(envstr) == mech_last_octet) {
	output_token->value = strdup("fail");
	assert(output_token->value != NULL);
	output_token->length = 4;
	return GSS_S_FAILURE;
    }

    if (*context_handle == GSS_C_NO_CONTEXT) {
	ctx = malloc(sizeof(*ctx));
	assert(ctx != NULL);
	ctx->initiator = 0;
	ctx->hops = hops;
	*context_handle = (gss_ctx_id_t)ctx;
    } else {
	assert(!ctx->initiator);
	ctx->hops--;
	assert(ctx->hops == hops);
    }

    if (ctx->hops > 0) {
	/* Generate a token containing the remaining hop count. */
	ctx->hops--;
	output_token->value = malloc(1);
	assert(output_token->value != NULL);
	memcpy(output_token->value, &ctx->hops, 1);
	output_token->length = 1;
    }

    return (ctx->hops > 0) ? GSS_S_CONTINUE_NEEDED : GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_delete_sec_context(OM_uint32 *minor_status, gss_ctx_id_t *context_handle,
		       gss_buffer_t output_token)
{
    free(*context_handle);
    *context_handle = GSS_C_NO_CONTEXT;
    return GSS_S_COMPLETE;
}

static int dummy_cred;

OM_uint32 GSSAPI_CALLCONV
gss_acquire_cred(OM_uint32 *minor_status, gss_const_name_t desired_name,
		 OM_uint32 time_req, const gss_OID_set desired_mechs,
		 gss_cred_usage_t cred_usage,
		 gss_cred_id_t *output_cred_handle, gss_OID_set *actual_mechs,
		 OM_uint32 *time_rec)
{
    *minor_status = 0;
    *output_cred_handle = (gss_cred_id_t)&dummy_cred;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_acquire_cred_with_password(OM_uint32 *minor_status,
			       gss_const_name_t desired_name,
			       const gss_buffer_t password, OM_uint32 time_req,
			       const gss_OID_set desired_mechs,
			       gss_cred_usage_t cred_usage,
			       gss_cred_id_t *output_cred_handle,
			       gss_OID_set *actual_mechs, OM_uint32 *time_rec)
{
    *minor_status = 0;
    *output_cred_handle = (gss_cred_id_t)&dummy_cred;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_release_cred(OM_uint32 *minor_status, gss_cred_id_t *cred_handle)
{
    return GSS_S_COMPLETE;
}

static int dummy_name;

OM_uint32 GSSAPI_CALLCONV
gss_import_name(OM_uint32 *minor_status, gss_buffer_t input_name_buffer,
		gss_OID input_name_type, gss_name_t *output_name)
{
    /*
     * We don't need to remember anything about names, but we do need to
     * distinguish them from GSS_C_NO_NAME (to determine the direction of
     * gss_query_meta_data() and gss_exchange_meta_data()), so assign an
     * arbitrary data pointer.
     */
    *output_name = (gss_name_t)&dummy_name;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_release_name(OM_uint32 *minor_status, gss_name_t *input_name)
{
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_display_status(OM_uint32 *minor_status, OM_uint32 status_value,
		   int status_type, gss_OID mech_type,
		   OM_uint32 *message_context, gss_buffer_t status_string)
{
    if (status_type == GSS_C_MECH_CODE && status_value == 12345) {
	status_string->value = strdup("failure from acceptor");
	assert(status_string->value != NULL);
	status_string->length = strlen(status_string->value);
	return GSS_S_COMPLETE;
    }
    return GSS_S_BAD_STATUS;
}

OM_uint32 GSSAPI_CALLCONV
gssspi_query_meta_data(OM_uint32 *minor_status, gss_const_OID mech_oid,
		       gss_cred_id_t cred_handle, gss_ctx_id_t *context_handle,
		       gss_const_name_t targ_name, OM_uint32 req_flags,
		       gss_buffer_t meta_data)
{
    const char *envstr;
    uint8_t mech_last_octet;
    int initiator = (targ_name != GSS_C_NO_NAME);

    mech_last_octet = ((uint8_t *)mech_oid->elements)[mech_oid->length - 1];
    envstr = getenv(initiator ? "INIT_QUERY_FAIL" : "ACCEPT_QUERY_FAIL");
    if (envstr != NULL && atoi(envstr) == mech_last_octet)
	return GSS_S_FAILURE;
    envstr = getenv(initiator ? "INIT_QUERY_NONE" : "ACCEPT_QUERY_NONE");
    if (envstr != NULL && atoi(envstr) == mech_last_octet)
	return GSS_S_COMPLETE;

    meta_data->value = strdup("X");
    meta_data->length = 1;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gssspi_exchange_meta_data(OM_uint32 *minor_status, gss_const_OID mech_oid,
			  gss_cred_id_t cred_handle,
			  gss_ctx_id_t *context_handle,
			  gss_const_name_t targ_name, OM_uint32 req_flags,
			  gss_const_buffer_t meta_data)
{
    const char *envstr;
    uint8_t mech_last_octet;
    int initiator = (targ_name != GSS_C_NO_NAME);

    mech_last_octet = ((uint8_t *)mech_oid->elements)[mech_oid->length - 1];
    envstr = getenv(initiator ? "INIT_EXCHANGE_FAIL" : "ACCEPT_EXCHANGE_FAIL");
    if (envstr != NULL && atoi(envstr) == mech_last_octet)
	return GSS_S_FAILURE;

    assert(meta_data->length == 1 && memcmp(meta_data->value, "X", 1) == 0);
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gssspi_query_mechanism_info(OM_uint32 *minor_status, gss_const_OID mech_oid,
			    unsigned char auth_scheme[16])
{
    /* Copy the mech OID encoding and right-pad it with zeros. */
    memset(auth_scheme, 0, 16);
    assert(mech_oid->length <= 16);
    memcpy(auth_scheme, mech_oid->elements, mech_oid->length);
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_inquire_sec_context_by_oid(OM_uint32 *minor_status,
			       gss_const_ctx_id_t context_handle,
			       const gss_OID desired_object,
			       gss_buffer_set_t *data_set)
{
    struct test_context *ctx = (struct test_context *)context_handle;
    OM_uint32 major;
    uint8_t keybytes[32] = { 0 };
    uint8_t typebytes[4];
    gss_buffer_desc key, type;
    const char *envstr;
    int ask_verify;

    if (gss_oid_equal(desired_object, GSS_C_INQ_NEGOEX_KEY))
	ask_verify = 0;
    else if (gss_oid_equal(desired_object, GSS_C_INQ_NEGOEX_VERIFY_KEY))
	ask_verify = 1;
    else
	return GSS_S_UNAVAILABLE;

    /*
     * By default, make a key available only if the context is established.
     * This can be overridden to "always", "init-always", "accept-always",
     * or "never".
     */
    envstr = getenv("KEY");
    if (envstr != NULL && strcmp(envstr, "never") == 0) {
	return GSS_S_UNAVAILABLE;
    } else if (ctx->hops > 0) {
	if (envstr == NULL)
	    return GSS_S_UNAVAILABLE;
	else if (strcmp(envstr, "init-always") == 0 && !ctx->initiator)
	    return GSS_S_UNAVAILABLE;
	else if (strcmp(envstr, "accept-always") == 0 && ctx->initiator)
	    return GSS_S_UNAVAILABLE;
    }

    /* Perturb the key so that each side's verifier key is equal to the other's
     * checksum key. */
    keybytes[0] = ask_verify ^ ctx->initiator;

    /* Supply an all-zeros aes256-sha1 negoex key. */
    if (gss_oid_equal(desired_object, GSS_C_INQ_NEGOEX_KEY) ||
	gss_oid_equal(desired_object, GSS_C_INQ_NEGOEX_VERIFY_KEY)) {
	OM_uint32 n = ENCTYPE_AES256_CTS_HMAC_SHA1_96;

	typebytes[0] = (n >> 0 ) & 0xFF;
	typebytes[1] = (n >> 8 ) & 0xFF;
	typebytes[2] = (n >> 16) & 0xFF;
	typebytes[3] = (n >> 24) & 0xFF;

	key.value = keybytes;
	key.length = sizeof(keybytes);
	type.value = typebytes;
	type.length = sizeof(typebytes);
	major = gss_add_buffer_set_member(minor_status, &key, data_set);
	if (major != GSS_S_COMPLETE)
	    return major;
	return gss_add_buffer_set_member(minor_status, &type, data_set);
    }

    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_process_context_token(OM_uint32 *minor_status,
    gss_const_ctx_id_t context_handle,
    const gss_buffer_t token_buffer)
{
    return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_context_time(OM_uint32 *minor_status,
    gss_const_ctx_id_t context_handle,
    OM_uint32 *time_rec)
{
    *time_rec = 0;
    return GSS_S_COMPLETE;
}

/*
 * We also need to supply a fake MIC in case SPNEGO test negotiates
 * as non-default mechanism
 */
#define FAKE_MIC	"negoex-fake-mic"
#define FAKE_MIC_LEN	(sizeof(FAKE_MIC) - 1)

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_get_mic(OM_uint32 *minor_status,
    gss_const_ctx_id_t context_handle,
    gss_qop_t qop_req,
    const gss_buffer_t message_buffer,
    gss_buffer_t message_token)
{
    message_token->value = strdup(FAKE_MIC);
    message_token->length = FAKE_MIC_LEN;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_verify_mic(OM_uint32 *minor_status,
    gss_const_ctx_id_t context_handle,
    const gss_buffer_t message_buffer,
    const gss_buffer_t token_buffer,
    gss_qop_t *qop_state)
{
    *minor_status = 0;
    if (token_buffer->length == FAKE_MIC_LEN &&
	memcmp(token_buffer->value, FAKE_MIC, FAKE_MIC_LEN) == 0)
	return GSS_S_COMPLETE;
    else
	return GSS_S_BAD_MIC;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_wrap(OM_uint32 *minor_status,
    gss_const_ctx_id_t context_handle,
    int conf_req_flag,
    gss_qop_t qop_req,
    const gss_buffer_t input_message_buffer,
    int *conf_state,
    gss_buffer_t output_message_buffer)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_unwrap(OM_uint32 *minor_status,
    gss_const_ctx_id_t context_handle,
    const gss_buffer_t input_message_buffer,
    gss_buffer_t output_message_buffer,
    int *conf_state,
    gss_qop_t *qop_state)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_compare_name(OM_uint32 *minor_status,
    gss_const_name_t name1_arg,
    gss_const_name_t name2_arg,
    int *name_equal)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_display_name(OM_uint32 *minor_status,
    gss_const_name_t input_name,
    gss_buffer_t output_name_buffer,
    gss_OID *output_name_type)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_export_name(OM_uint32 *minor_status,
    gss_const_name_t input_name,
    gss_buffer_t exported_name)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_inquire_context(OM_uint32 *minor_status,
    gss_const_ctx_id_t context_handle,
    gss_name_t *src_name,
    gss_name_t *targ_name,
    OM_uint32 *lifetime_rec,
    gss_OID *mech_type,
    OM_uint32 *ctx_flags,
    int *locally_initiated,
    int *xopen)
{
    *lifetime_rec = GSS_C_INDEFINITE;
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_wrap_size_limit(OM_uint32 *minor_status,
    gss_const_ctx_id_t context_handle,
    int conf_req_flag,
    gss_qop_t qop_req,
    OM_uint32 req_output_size,
    OM_uint32 *max_input_size)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_import_sec_context(OM_uint32 *minor_status,
    const gss_buffer_t interprocess_token,
    gss_ctx_id_t *context_handle)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_export_sec_context(OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_buffer_t interprocess_token)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_canonicalize_name(OM_uint32 *minor_status,
    gss_const_name_t input_name,
    const gss_OID mech_type,
    gss_name_t *output_name)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_duplicate_name(OM_uint32 *minor_status,
    gss_const_name_t src_name,
    gss_name_t *dest_name)
{
    return GSS_S_UNAVAILABLE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_inquire_cred(OM_uint32 *minor_status,
    gss_const_cred_id_t cred_handle,
    gss_name_t *name_ret,
    OM_uint32 *lifetime,
    gss_cred_usage_t *cred_usage,
    gss_OID_set *mechanisms)
{
    if (name_ret)
	*name_ret = (gss_name_t)&dummy_name;
    if (lifetime)
	*lifetime = GSS_C_INDEFINITE;
    if (cred_usage)
	*cred_usage = GSS_C_BOTH;
    if (mechanisms)
	*mechanisms = GSS_C_NO_OID_SET;
	
    return GSS_S_COMPLETE;
}

