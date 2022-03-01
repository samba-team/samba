/*
 * Copyright (C) 2011-2021 PADL Software Pty Ltd.
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

#include "spnego_locl.h"

/*
 * The initial context token emitted by the initiator is a INITIATOR_NEGO
 * message followed by zero or more INITIATOR_META_DATA tokens, and zero
 * or one AP_REQUEST tokens.
 *
 * Upon receiving this, the acceptor computes the list of mutually supported
 * authentication mechanisms and performs the metadata exchange. The output
 * token is ACCEPTOR_NEGO followed by zero or more ACCEPTOR_META_DATA tokens,
 * and zero or one CHALLENGE tokens.
 *
 * Once the metadata exchange is complete and a mechanism is selected, the
 * selected mechanism's context token exchange continues with AP_REQUEST and
 * CHALLENGE messages.
 *
 * Once the context token exchange is complete, VERIFY messages are sent to
 * authenticate the entire exchange.
 */

static OM_uint32
buffer_set_to_crypto(OM_uint32 *minor,
		     krb5_context context,
		     gss_buffer_set_t buffers,
		     krb5_crypto *crypto)
{
    krb5_error_code ret;
    krb5_keyblock keyblock;
    OM_uint32 tmp;

    /*
     * Returned keys must be in two buffers, with the key contents in
     * the first and the enctype as a 32-bit little-endian integer in
     * the second.
     */
    if (buffers->count != 2 ||
	buffers->elements[1].length != sizeof(tmp)) {
	*minor = (OM_uint32)NEGOEX_NO_VERIFY_KEY;
	return GSS_S_FAILURE;
    }

    if (*crypto != NULL) {
	krb5_crypto_destroy(context, *crypto);
	*crypto = NULL;
    }

    keyblock.keyvalue.data = buffers->elements[0].value;
    keyblock.keyvalue.length = buffers->elements[0].length;
    _gss_mg_decode_le_uint32(buffers->elements[1].value, &tmp);
    keyblock.keytype = tmp;

    ret = krb5_crypto_init(context, &keyblock, 0, crypto);
    if (ret) {
	*minor = ret;
	return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

#define NEGOEX_SIGN_KEY	    1
#define NEGOEX_VERIFY_KEY   2
#define NEGOEX_BOTH_KEYS    (NEGOEX_SIGN_KEY|NEGOEX_VERIFY_KEY)

static OM_uint32
get_session_keys(OM_uint32 *minor,
		 krb5_context context,
		 OM_uint32 flags,
		 struct negoex_auth_mech *mech)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_set_t buffers = GSS_C_NO_BUFFER_SET;

    if (flags & NEGOEX_SIGN_KEY) {
	major = gss_inquire_sec_context_by_oid(&tmpMinor, mech->mech_context,
					       GSS_C_INQ_NEGOEX_KEY, &buffers);
	if (major == GSS_S_COMPLETE) {
	    major = buffer_set_to_crypto(minor, context,
					 buffers, &mech->crypto);
	    _gss_secure_release_buffer_set(&tmpMinor, &buffers);
	    if (major != GSS_S_COMPLETE)
		return major;
	}
    }

    if (flags & NEGOEX_VERIFY_KEY) {
	major = gss_inquire_sec_context_by_oid(&tmpMinor, mech->mech_context,
					       GSS_C_INQ_NEGOEX_VERIFY_KEY,
					       &buffers);
	if (major == GSS_S_COMPLETE) {
	    major = buffer_set_to_crypto(minor, context,
					 buffers, &mech->verify_crypto);
	    _gss_secure_release_buffer_set(&tmpMinor, &buffers);
	    if (major != GSS_S_COMPLETE)
		return major;
	}
    }

    return GSS_S_COMPLETE;
}

static OM_uint32
emit_initiator_nego(OM_uint32 *minor, gssspnego_ctx ctx)
{
    uint8_t random[32];
    struct negoex_auth_mech *mech;
    size_t i = 0;

    krb5_generate_random_block(random, sizeof(random));

    HEIM_TAILQ_FOREACH(mech, &ctx->negoex_mechs, links)
	_gss_negoex_log_auth_scheme(ctx->flags.local, ++i, mech->scheme);

    return _gss_negoex_add_nego_message(minor, ctx, INITIATOR_NEGO, random);
}

static OM_uint32
process_initiator_nego(OM_uint32 *minor,
		       gssspnego_ctx ctx,
		       struct negoex_message *messages,
		       size_t nmessages)
{
    struct nego_message *msg;
    size_t i;

    heim_assert(!ctx->flags.local && ctx->negoex_step == 1,
		"NegoEx INITIATOR_NEGO token received after first leg");

    msg = _gss_negoex_locate_nego_message(messages, nmessages, INITIATOR_NEGO);
    if (msg == NULL) {
	*minor = (OM_uint32)NEGOEX_MISSING_NEGO_MESSAGE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    for (i = 0; i < msg->nschemes; i++)
	_gss_negoex_log_auth_scheme(ctx->flags.local, i + 1, &msg->schemes[i * GUID_LENGTH]);

    _gss_negoex_restrict_auth_schemes(ctx, msg->schemes, msg->nschemes);

    return GSS_S_COMPLETE;
}

static OM_uint32
emit_acceptor_nego(OM_uint32 *minor, gssspnego_ctx ctx)
{
    uint8_t random[32];

    krb5_generate_random_block(random, 32);

    return _gss_negoex_add_nego_message(minor, ctx, ACCEPTOR_NEGO, random);
}

static OM_uint32
process_acceptor_nego(OM_uint32 *minor,
		      gssspnego_ctx ctx,
		      struct negoex_message *messages,
		      size_t nmessages)
{
    struct nego_message *msg;

    msg = _gss_negoex_locate_nego_message(messages, nmessages, ACCEPTOR_NEGO);
    if (msg == NULL) {
	*minor = (OM_uint32)NEGOEX_MISSING_NEGO_MESSAGE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    /*
     * Reorder and prune our mech list to match the acceptor's list (or a
     * subset of it).
     */
    _gss_negoex_common_auth_schemes(ctx, msg->schemes, msg->nschemes);

    return GSS_S_COMPLETE;
}

static void
query_meta_data(gssspnego_ctx ctx,
		struct gssspnego_optimistic_ctx *opt,
		gss_cred_id_t cred,
		OM_uint32 req_flags)
{
    OM_uint32 major, minor;
    struct negoex_auth_mech *p, *next;

    /*
     * Note that if we received an optimistic context token from SPNEGO,
     * then we will call QMD after ISC, rather than before. Mechanisms
     * must be prepared to handle this and must not assume the context
     * will be NULL on entry.
     */
    HEIM_TAILQ_FOREACH_SAFE(p, &ctx->negoex_mechs, links, next) {
	if (opt != NULL && memcmp(opt->scheme, p->scheme, GUID_LENGTH) == 0)
	    p->mech_context = opt->gssctx;;

	major = gssspi_query_meta_data(&minor, p->oid, cred, &p->mech_context,
				       ctx->target_name, req_flags, &p->metadata);
	/* GSS_Query_meta_data failure removes mechanism from list. */
	if (major != GSS_S_COMPLETE)
	    _gss_negoex_delete_auth_mech(ctx, p);
    }
}

static void
exchange_meta_data(gssspnego_ctx ctx,
		   gss_cred_id_t cred,
		   OM_uint32 req_flags,
		   struct negoex_message *messages,
		   size_t nmessages)
{
    OM_uint32 major, minor;
    struct negoex_auth_mech *mech;
    enum message_type type;
    struct exchange_message *msg;
    uint32_t i;

    type = ctx->flags.local ? ACCEPTOR_META_DATA : INITIATOR_META_DATA;

    for (i = 0; i < nmessages; i++) {
	if (messages[i].type != type)
	    continue;
	msg = &messages[i].u.e;

	mech = _gss_negoex_locate_auth_scheme(ctx, msg->scheme);
	if (mech == NULL)
	    continue;

	major = gssspi_exchange_meta_data(&minor, mech->oid, cred,
					  &mech->mech_context,
					  ctx->target_name,
					  req_flags, &msg->token);
	/* GSS_Exchange_meta_data failure removes mechanism from list. */
	if (major != GSS_S_COMPLETE)
	    _gss_negoex_delete_auth_mech(ctx, mech);
    }
}

static void
release_mech_crypto(struct negoex_auth_mech *mech)
{
    krb5_context context = NULL;

    if (mech->crypto || mech->verify_crypto)
	context = _gss_mg_krb5_context();

    if (mech->crypto) {
	krb5_crypto_destroy(context, mech->crypto);
	mech->crypto = NULL;
    }

    if (mech->verify_crypto) {
	krb5_crypto_destroy(context, mech->verify_crypto);
	mech->verify_crypto = NULL;
    }

    mech->sent_checksum = FALSE;
}

/*
 * In the initiator, if we are processing the acceptor's first reply, discard
 * the optimistic context if the acceptor ignored the optimistic token. If the
 * acceptor continued the optimistic mech, discard all other mechs.
 */
static void
check_optimistic_result(gssspnego_ctx ctx,
			struct negoex_message *messages,
			size_t nmessages)
{
    struct negoex_auth_mech *mech;
    OM_uint32 tmpMinor;

    heim_assert(ctx->flags.local && ctx->negoex_step == 2,
		"NegoEx optimistic result should only be checked in second leg");

    /* Do nothing if we didn't make an optimistic context. */
    mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
    if (mech == NULL || mech->mech_context == GSS_C_NO_CONTEXT)
	return;

    /*
     * If the acceptor used the optimistic token, it will send an acceptor
     * token or a checksum (or both) in its first reply.
     */
    if (_gss_negoex_locate_exchange_message(messages, nmessages,
					    CHALLENGE) != NULL ||
	_gss_negoex_locate_verify_message(messages, nmessages) != NULL) {
	/*
	 * The acceptor continued the optimistic mech, and metadata exchange
	 * didn't remove it. Commit to this mechanism.
	 */
	_gss_negoex_select_auth_mech(ctx, mech);
    } else {
	/*
	 * The acceptor ignored the optimistic token. Restart the mech.
	 */
	gss_delete_sec_context(&tmpMinor, &mech->mech_context, GSS_C_NO_BUFFER);
	release_mech_crypto(mech);
	mech->complete = FALSE;
    }
}

/* Perform an initiator step of the underlying mechanism exchange. */
static OM_uint32
mech_init(OM_uint32 *minor,
	  struct gssspnego_optimistic_ctx *opt,
	  gssspnego_ctx ctx,
	  gss_cred_id_t cred,
	  OM_uint32 req_flags,
	  OM_uint32 time_req,
	  const gss_channel_bindings_t input_chan_bindings,
	  struct negoex_message *messages,
	  size_t nmessages,
	  gss_buffer_t output_token,
	  int *mech_error)
{
    OM_uint32 major, first_major = GSS_S_COMPLETE, first_minor = 0;
    struct negoex_auth_mech *mech = NULL;
    gss_buffer_t input_token = GSS_C_NO_BUFFER;
    struct exchange_message *msg;
    int first_mech;
    krb5_context context = _gss_mg_krb5_context();

    output_token->value = NULL;
    output_token->length = 0;

    *mech_error = FALSE;

    /* Allow disabling of optimistic token for testing. */
    if (ctx->negoex_step == 1 &&
	secure_getenv("NEGOEX_NO_OPTIMISTIC_TOKEN") != NULL)
	return GSS_S_COMPLETE;

    if (HEIM_TAILQ_EMPTY(&ctx->negoex_mechs)) {
	*minor = (OM_uint32)NEGOEX_NO_AVAILABLE_MECHS;
	return GSS_S_FAILURE;
    }

    /*
     * Get the input token. The challenge could be for the optimistic mech,
     * which we might have discarded in metadata exchange, so ignore the
     * challenge if it doesn't match the first auth mech.
     */
    mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
    msg = _gss_negoex_locate_exchange_message(messages, nmessages, CHALLENGE);
    if (msg != NULL && GUID_EQ(msg->scheme, mech->scheme))
	input_token = &msg->token;

    if (mech->complete)
	return GSS_S_COMPLETE;

    first_mech = TRUE;
    major = GSS_S_BAD_MECH;

    while (!HEIM_TAILQ_EMPTY(&ctx->negoex_mechs)) {
	mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);

	/*
	 * If SPNEGO generated an optimistic token when probing available
	 * mechanisms, we can reuse it here. This avoids a potentially
	 * expensive and redundant call to GSS_Init_sec_context();
	 */
	if (opt != NULL && memcmp(opt->scheme, mech->scheme, GUID_LENGTH) == 0) {
	    heim_assert(ctx->negoex_step == 1,
			"SPNEGO optimistic token only valid for NegoEx first leg");

	    major = _gss_copy_buffer(minor, &opt->optimistic_token, output_token);
	    if (GSS_ERROR(major))
		return major;

	    ctx->negotiated_mech_type = opt->negotiated_mech_type;
	    ctx->mech_flags = opt->optimistic_flags;
	    ctx->mech_time_rec = opt->optimistic_time_rec;

	    mech->mech_context = opt->gssctx;
	    opt->gssctx = NULL; /* steal it */

	    mech->complete = opt->complete;
	    major = GSS_S_COMPLETE;
	} else {
	    major = gss_init_sec_context(minor, cred, &mech->mech_context,
					 ctx->target_name, mech->oid,
					 req_flags, time_req,
					 input_chan_bindings, input_token,
					 &ctx->negotiated_mech_type, output_token,
					 &ctx->mech_flags, &ctx->mech_time_rec);
	    if (major == GSS_S_COMPLETE)
		mech->complete = 1;
	    else if (GSS_ERROR(major)) {
		gss_mg_collect_error(mech->oid, major, *minor);
		*mech_error = TRUE;
	    }
	}
	if (!GSS_ERROR(major))
	    return get_session_keys(minor, context, NEGOEX_BOTH_KEYS, mech);

	/* Remember the error we got from the first mech. */
	if (first_mech) {
	    first_major = major;
	    first_minor = *minor;
	}

	/* If we still have multiple mechs to try, move on to the next one. */
	_gss_negoex_delete_auth_mech(ctx, mech);
	first_mech = FALSE;
	input_token = GSS_C_NO_BUFFER;
    }

    if (HEIM_TAILQ_EMPTY(&ctx->negoex_mechs)) {
	major = first_major;
	*minor = first_minor;
    }

    return major;
}

/* Perform an acceptor step of the underlying mechanism exchange. */
static OM_uint32
mech_accept(OM_uint32 *minor,
	    gssspnego_ctx ctx,
	    gss_cred_id_t cred,
	    const gss_channel_bindings_t input_chan_bindings,
	    struct negoex_message *messages,
	    size_t nmessages,
	    gss_buffer_t output_token,
	    gss_cred_id_t *deleg_cred,
	    int *mech_error)
{
    OM_uint32 major, tmpMinor;
    struct negoex_auth_mech *mech;
    struct exchange_message *msg;
    krb5_context context = _gss_mg_krb5_context();

    heim_assert(!ctx->flags.local && !HEIM_TAILQ_EMPTY(&ctx->negoex_mechs),
		"Acceptor NegoEx function called in wrong sequence");

    *mech_error = FALSE;

    msg = _gss_negoex_locate_exchange_message(messages, nmessages, AP_REQUEST);
    if (msg == NULL) {
	/*
	 * No input token is okay on the first request or if the mech is
	 * complete.
	 */
	if (ctx->negoex_step == 1 ||
	    HEIM_TAILQ_FIRST(&ctx->negoex_mechs)->complete)
	    return GSS_S_COMPLETE;
	*minor = (OM_uint32)NEGOEX_MISSING_AP_REQUEST_MESSAGE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (ctx->negoex_step == 1) {
	/*
	 * Ignore the optimistic token if it isn't for our most preferred
	 * mech.
	 */
	mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
	if (!GUID_EQ(msg->scheme, mech->scheme)) {
	    _gss_mg_log(10, "negoex ignored optimistic token as not for preferred mech");
	    return GSS_S_COMPLETE;
	}
    } else {
	/* The initiator has selected a mech; discard other entries. */
	mech = _gss_negoex_locate_auth_scheme(ctx, msg->scheme);
	if (mech == NULL) {
	    *minor = (OM_uint32)NEGOEX_NO_AVAILABLE_MECHS;
	    return GSS_S_FAILURE;
	}
	_gss_negoex_select_auth_mech(ctx, mech);
    }

    if (mech->complete)
	return GSS_S_COMPLETE;

    if (ctx->mech_src_name != GSS_C_NO_NAME)
	gss_release_name(&tmpMinor, &ctx->mech_src_name);
    if (deleg_cred && *deleg_cred != GSS_C_NO_CREDENTIAL)
	gss_release_cred(&tmpMinor, deleg_cred);

    major = gss_accept_sec_context(minor, &mech->mech_context, cred,
				   &msg->token, input_chan_bindings,
				   &ctx->mech_src_name, &ctx->negotiated_mech_type,
				   output_token, &ctx->mech_flags,
				   &ctx->mech_time_rec, deleg_cred);
    if (major == GSS_S_COMPLETE)
	mech->complete = 1;

    if (!GSS_ERROR(major)) {
	if (major == GSS_S_COMPLETE &&
	    !gss_oid_equal(ctx->negotiated_mech_type, mech->oid))
	    _gss_mg_log(1, "negoex client didn't send the mech they said they would");

	major = get_session_keys(minor, context, NEGOEX_BOTH_KEYS, mech);
    } else if (ctx->negoex_step == 1) {
	gss_mg_collect_error(ctx->negotiated_mech_type, major, *minor);
	*mech_error = TRUE;

	/* This was an optimistic token; pretend this never happened. */
	major = GSS_S_COMPLETE;
	*minor = 0;
	gss_release_buffer(&tmpMinor, output_token);
	gss_delete_sec_context(&tmpMinor, &mech->mech_context, GSS_C_NO_BUFFER);
    }

    return major;
}

static krb5_keyusage
verify_keyusage(gssspnego_ctx ctx, int make_checksum)
{
    /* Of course, these are the wrong way around in the spec. */
    return (ctx->flags.local ^ !make_checksum) ?
	NEGOEX_KEYUSAGE_ACCEPTOR_CHECKSUM : NEGOEX_KEYUSAGE_INITIATOR_CHECKSUM;
}

static OM_uint32
verify_key_flags(gssspnego_ctx ctx, int make_checksum)
{
    return (ctx->flags.local ^ make_checksum) ?
	NEGOEX_SIGN_KEY : NEGOEX_VERIFY_KEY;
}

static OM_uint32
verify_checksum(OM_uint32 *minor,
		gssspnego_ctx ctx,
		struct negoex_message *messages,
		size_t nmessages,
		gss_const_buffer_t input_token,
		int *send_alert_out)
{
    krb5_error_code ret;
    struct negoex_auth_mech *mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
    struct verify_message *msg;
    krb5_context context = _gss_mg_krb5_context();
    krb5_crypto_iov iov[3];
    krb5_keyusage usage = verify_keyusage(ctx, FALSE);

    *send_alert_out = FALSE;
    heim_assert(mech != NULL, "Invalid null mech when verifying NegoEx checksum");

    /*
     * The other party may not be ready to send a verify token yet, or (in the
     * first initiator step) may send one for a mechanism we don't support.
     */
    msg = _gss_negoex_locate_verify_message(messages, nmessages);
    if (msg == NULL || !GUID_EQ(msg->scheme, mech->scheme))
	return GSS_S_COMPLETE;

    /*
     * Last chance attempt to obtain session key for imported exported partial
     * contexts (which do not carry the session key at the NegoEx layer).
     */
    if (mech->verify_crypto == NULL)
	get_session_keys(minor, context, verify_key_flags(ctx, FALSE), mech);

    /*
     * A recoverable error may cause us to be unable to verify a token from the
     * other party. In this case we should send an alert.
     */
    if (mech->verify_crypto == NULL) {
	*send_alert_out = TRUE;
	return GSS_S_COMPLETE;
    }

    if (!krb5_checksum_is_keyed(context, msg->cksum_type)) {
	*minor = (OM_uint32)NEGOEX_INVALID_CHECKSUM;
	return GSS_S_BAD_SIG;
    }

    /*
     * Verify the checksum over the existing transcript and the portion of the
     * input token leading up to the verify message.
     */
    iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
    ret = krb5_storage_to_data(ctx->negoex_transcript, &iov[0].data);
    if (ret) {
	*minor = ret;
	return GSS_S_FAILURE;
    }

    iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[1].data.data = input_token->value;
    iov[1].data.length = msg->offset_in_token;

    iov[2].flags = KRB5_CRYPTO_TYPE_CHECKSUM;
    iov[2].data.data = (uint8_t *)msg->cksum;
    iov[2].data.length = msg->cksum_len;

    ret = krb5_verify_checksum_iov(context, mech->verify_crypto, usage,
				   iov, sizeof(iov) / sizeof(iov[0]), NULL);
    if (ret == 0)
	mech->verified_checksum = TRUE;
    else
	*minor = ret;

    krb5_data_free(&iov[0].data);

    return (ret == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

static OM_uint32
make_checksum(OM_uint32 *minor, gssspnego_ctx ctx)
{
    krb5_error_code ret;
    krb5_context context = _gss_mg_krb5_context();
    krb5_data d;
    krb5_keyusage usage = verify_keyusage(ctx, TRUE);
    krb5_checksum cksum;
    struct negoex_auth_mech *mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
    OM_uint32 major;

    heim_assert(mech != NULL, "Invalid null mech when making NegoEx checksum");

    if (mech->crypto == NULL) {
	if (mech->complete) {
	    /*
	     * Last chance attempt to obtain session key for imported exported partial
	     * contexts (which do not carry the session key at the NegoEx layer).
	     */
	    get_session_keys(minor, context, verify_key_flags(ctx, TRUE), mech);
	    if (mech->crypto == NULL) {
		*minor = (OM_uint32)NEGOEX_NO_VERIFY_KEY;
		return GSS_S_UNAVAILABLE;
	    }
	} else {
	    return GSS_S_COMPLETE;
	}
    }

    ret = krb5_storage_to_data(ctx->negoex_transcript, &d);
    if (ret) {
	*minor = ret;
	return GSS_S_FAILURE;
    }

    ret = krb5_create_checksum(context, mech->crypto,
			       usage, 0, d.data, d.length, &cksum);
    krb5_data_free(&d);
    if (ret) {
	*minor = ret;
	return GSS_S_FAILURE;
    }

    major = _gss_negoex_add_verify_message(minor, ctx, mech->scheme,
					   cksum.cksumtype,
					   cksum.checksum.data,
					   cksum.checksum.length);
    free_Checksum(&cksum);

    if (major == GSS_S_COMPLETE)
	mech->sent_checksum = TRUE;

    return major;
}

/*
 * If the other side sent a VERIFY_NO_KEY pulse alert, clear the checksum state
 * on the mechanism so that we send another VERIFY message.
 */
static void
process_alerts(gssspnego_ctx ctx,
	       struct negoex_message *messages,
	       uint32_t nmessages)
{
    struct alert_message *msg;
    struct negoex_auth_mech *mech;

    msg = _gss_negoex_locate_alert_message(messages, nmessages);
    if (msg != NULL && msg->verify_no_key) {
	mech = _gss_negoex_locate_auth_scheme(ctx, msg->scheme);
	if (mech != NULL)
	    release_mech_crypto(mech);
    }
}

static OM_uint32
make_output_token(OM_uint32 *minor,
		  gssspnego_ctx ctx,
		  gss_buffer_t mech_output_token,
		  int send_alert,
		  gss_buffer_t output_token)
{
    OM_uint32 major, tmpMinor;
    struct negoex_auth_mech *mech;
    enum message_type type;
    off_t old_transcript_len;

    output_token->length = 0;
    output_token->value = NULL;

    old_transcript_len = krb5_storage_seek(ctx->negoex_transcript, 0, SEEK_CUR);

    /*
     * If the mech is complete and we previously sent a checksum, we just
     * processed the last leg and don't need to send another token.
     */
    if (mech_output_token->length == 0 &&
	HEIM_TAILQ_FIRST(&ctx->negoex_mechs)->sent_checksum)
	return GSS_S_COMPLETE;

    if (ctx->negoex_step == 1) {
	if (ctx->flags.local)
	    major = emit_initiator_nego(minor, ctx);
	else
	    major = emit_acceptor_nego(minor, ctx);
	if (major != GSS_S_COMPLETE)
	    return major;

	type = ctx->flags.local ? INITIATOR_META_DATA : ACCEPTOR_META_DATA;
	HEIM_TAILQ_FOREACH(mech, &ctx->negoex_mechs, links) {
	    if (mech->metadata.length > 0) {
		major = _gss_negoex_add_exchange_message(minor, ctx,
							 type, mech->scheme,
							 &mech->metadata);
		if (major != GSS_S_COMPLETE)
		    return major;
	    }
	}
    }

    mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);

    if (mech_output_token->length > 0) {
	type = ctx->flags.local ? AP_REQUEST : CHALLENGE;
	major = _gss_negoex_add_exchange_message(minor, ctx,
						 type, mech->scheme,
						 mech_output_token);
	if (major != GSS_S_COMPLETE)
	    return major;
    }

    if (send_alert) {
	major = _gss_negoex_add_verify_no_key_alert(minor, ctx, mech->scheme);
	if (major != GSS_S_COMPLETE)
	    return major;
    }

    /* Try to add a VERIFY message if we haven't already done so. */
    if (!mech->sent_checksum) {
	major = make_checksum(minor, ctx);
	if (major != GSS_S_COMPLETE)
	    return major;
    }

    heim_assert(ctx->negoex_transcript != NULL, "NegoEx context uninitialized");

    output_token->length =
	krb5_storage_seek(ctx->negoex_transcript, 0, SEEK_CUR) - old_transcript_len;
    output_token->value = malloc(output_token->length);
    if (output_token->value == NULL) {
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }

    krb5_storage_seek(ctx->negoex_transcript, old_transcript_len, SEEK_SET);

    if (krb5_storage_read(ctx->negoex_transcript,
			  output_token->value,
			  output_token->length) != output_token->length) {
	*minor = ERANGE;
	gss_release_buffer(&tmpMinor, output_token);
	return GSS_S_FAILURE;
    }

    krb5_storage_seek(ctx->negoex_transcript, 0, SEEK_END);

    return GSS_S_COMPLETE;
}

OM_uint32
_gss_negoex_init(OM_uint32 *minor,
		 struct gssspnego_optimistic_ctx *opt,
		 gssspnego_ctx ctx,
		 gss_cred_id_t cred,
		 OM_uint32 req_flags,
		 OM_uint32 time_req,
		 const gss_channel_bindings_t input_chan_bindings,
		 gss_const_buffer_t input_token,
		 gss_buffer_t output_token)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc mech_output_token = GSS_C_EMPTY_BUFFER;
    struct negoex_message *messages = NULL;
    struct negoex_auth_mech *mech;
    size_t nmessages = 0;
    int send_alert = FALSE, mech_error = FALSE;

    output_token->length = 0;
    output_token->value = NULL;

    if (ctx->negoex_step == 0 && input_token != GSS_C_NO_BUFFER &&
	input_token->length != 0)
	return GSS_S_DEFECTIVE_TOKEN;

    major = _gss_negoex_begin(minor, ctx);
    if (major != GSS_S_COMPLETE)
	goto cleanup;

    ctx->negoex_step++;

    if (input_token != GSS_C_NO_BUFFER && input_token->length > 0) {
	major = _gss_negoex_parse_token(minor, ctx, input_token,
					&messages, &nmessages);
	if (major != GSS_S_COMPLETE)
	    goto cleanup;
    }

    process_alerts(ctx, messages, nmessages);

    if (ctx->negoex_step == 1) {
	/* Choose a random conversation ID. */
	krb5_generate_random_block(ctx->negoex_conv_id, GUID_LENGTH);

	/* Query each mech for its metadata (this may prune the mech list). */
	query_meta_data(ctx, opt, cred, req_flags);
    } else if (ctx->negoex_step == 2) {
	/* See if the mech processed the optimistic token. */
	check_optimistic_result(ctx, messages, nmessages);

	/* Pass the acceptor metadata to each mech to prune the list. */
	exchange_meta_data(ctx, cred, req_flags, messages, nmessages);

	/* Process the ACCEPTOR_NEGO message. */
	major = process_acceptor_nego(minor, ctx, messages, nmessages);
	if (major != GSS_S_COMPLETE)
	    goto cleanup;
    }

    /*
     * Process the input token and/or produce an output token. This may prune
     * the mech list, but on success there will be at least one mech entry.
     */
    major = mech_init(minor, opt, ctx, cred, req_flags, time_req,
		      input_chan_bindings, messages, nmessages,
		      &mech_output_token, &mech_error);
    if (major != GSS_S_COMPLETE)
	goto cleanup;
    heim_assert(!HEIM_TAILQ_EMPTY(&ctx->negoex_mechs),
		"Invalid empty NegoEx mechanism list");

    /*
     * At this point in step 2 we have performed the metadata exchange and
     * chosen a mech we can use, so discard any fallback mech entries.
     */
    if (ctx->negoex_step == 2)
	_gss_negoex_select_auth_mech(ctx, HEIM_TAILQ_FIRST(&ctx->negoex_mechs));

    major = verify_checksum(minor, ctx, messages, nmessages, input_token,
			    &send_alert);
    if (major != GSS_S_COMPLETE)
	goto cleanup;

    if (input_token != GSS_C_NO_BUFFER) {
	if (krb5_storage_write(ctx->negoex_transcript,
			       input_token->value,
			       input_token->length) != input_token->length) {
	    major = GSS_S_FAILURE;
	    *minor = ENOMEM;
	    goto cleanup;
	}
    }

    major = make_output_token(minor, ctx, &mech_output_token, send_alert,
			      output_token);
    if (major != GSS_S_COMPLETE)
	goto cleanup;

    mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
    major = (mech->complete && mech->verified_checksum) ? GSS_S_COMPLETE :
	GSS_S_CONTINUE_NEEDED;

cleanup:
    free(messages);
    gss_release_buffer(&tmpMinor, &mech_output_token);
    _gss_negoex_end(ctx);

    if (GSS_ERROR(major)) {
	if (!mech_error) {
	    krb5_context context = _gss_mg_krb5_context();
	    const char *emsg = krb5_get_error_message(context, *minor);

	    gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				    major, *minor,
				    "NegoEx failed to initialize security context: %s",
				    emsg);
	    krb5_free_error_message(context, emsg);
	}

	_gss_negoex_release_context(ctx);
    }

    return major;
}

OM_uint32
_gss_negoex_accept(OM_uint32 *minor,
		   gssspnego_ctx ctx,
		   gss_cred_id_t cred,
		   gss_const_buffer_t input_token,
		   const gss_channel_bindings_t input_chan_bindings,
		   gss_buffer_t output_token,
		   gss_cred_id_t *deleg_cred)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc mech_output_token = GSS_C_EMPTY_BUFFER;
    struct negoex_message *messages = NULL;
    struct negoex_auth_mech *mech;
    size_t nmessages;
    int send_alert = FALSE, mech_error = FALSE;

    output_token->length = 0;
    output_token->value = NULL;
    if (deleg_cred)
	*deleg_cred = GSS_C_NO_CREDENTIAL;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
	major = GSS_S_DEFECTIVE_TOKEN;
	goto cleanup;
    }

    major = _gss_negoex_begin(minor, ctx);
    if (major != GSS_S_COMPLETE)
	goto cleanup;

    ctx->negoex_step++;

    major = _gss_negoex_parse_token(minor, ctx, input_token,
				    &messages, &nmessages);
    if (major != GSS_S_COMPLETE)
	goto cleanup;

    process_alerts(ctx, messages, nmessages);

    if (ctx->negoex_step == 1) {
	/*
	 * Read the INITIATOR_NEGO message to prune the candidate mech list.
	 */
	major = process_initiator_nego(minor, ctx, messages, nmessages);
	if (major != GSS_S_COMPLETE)
	    goto cleanup;

	/*
	 * Pass the initiator metadata to each mech to prune the list, and
	 * query each mech for its acceptor metadata (which may also prune the
	 * list).
	 */
	exchange_meta_data(ctx, cred, 0, messages, nmessages);
	query_meta_data(ctx, NULL, cred, 0);

	if (HEIM_TAILQ_EMPTY(&ctx->negoex_mechs)) {
	    *minor = (OM_uint32)NEGOEX_NO_AVAILABLE_MECHS;
	    major = GSS_S_FAILURE;
	    goto cleanup;
	}
    }

    /*
     * Process the input token and possibly produce an output token. This may
     * prune the list to a single mech. Continue on error if an output token
     * is generated, so that we send the token to the initiator.
     */
    major = mech_accept(minor, ctx, cred, input_chan_bindings,
			messages, nmessages, &mech_output_token,
			deleg_cred, &mech_error);
    if (major != GSS_S_COMPLETE && mech_output_token.length == 0)
	goto cleanup;

    if (major == GSS_S_COMPLETE) {
	major = verify_checksum(minor, ctx, messages, nmessages, input_token,
				&send_alert);
	if (major != GSS_S_COMPLETE)
	    goto cleanup;
    }

    if (krb5_storage_write(ctx->negoex_transcript,
			   input_token->value,
			   input_token->length) != input_token->length) {
	major = GSS_S_FAILURE;
	*minor = ENOMEM;
	goto cleanup;
    }

    major = make_output_token(minor, ctx, &mech_output_token, send_alert,
			      output_token);
    if (major != GSS_S_COMPLETE)
	goto cleanup;

    mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
    major = (mech->complete && mech->verified_checksum) ? GSS_S_COMPLETE :
	GSS_S_CONTINUE_NEEDED;

cleanup:
    free(messages);
    gss_release_buffer(&tmpMinor, &mech_output_token);
    _gss_negoex_end(ctx);

    if (GSS_ERROR(major)) {
	if (!mech_error) {
	    krb5_context context = _gss_mg_krb5_context();
	    const char *emsg = krb5_get_error_message(context, *minor);

	    gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				    major, *minor,
				    "NegoEx failed to accept security context: %s",
				    emsg);
	    krb5_free_error_message(context, emsg);
	}

	_gss_negoex_release_context(ctx);
    }

    return major;
}
