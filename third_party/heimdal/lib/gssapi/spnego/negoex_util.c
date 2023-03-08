/*
 * Copyright (C) 2011-2019 PADL Software Pty Ltd.
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
 * SPNEGO expects to find the active mech context in ctx->negotiated_ctx_id,
 * but the metadata exchange APIs force us to have one mech context per mech
 * entry. To address this mismatch, move the active mech context (if we have
 * one) to ctx->negotiated_ctx_id at the end of NegoEx processing.
 */
void
_gss_negoex_end(gssspnego_ctx ctx)
{
    struct negoex_auth_mech *mech;

    mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
    if (mech == NULL || mech->mech_context == GSS_C_NO_CONTEXT)
	return;

    heim_assert(ctx->negotiated_ctx_id == GSS_C_NO_CONTEXT,
		"SPNEGO/NegoEx context mismatch");
    ctx->negotiated_ctx_id = mech->mech_context;
    mech->mech_context = GSS_C_NO_CONTEXT;
}

OM_uint32
_gss_negoex_begin(OM_uint32 *minor, gssspnego_ctx ctx)
{
    struct negoex_auth_mech *mech;

    if (ctx->negoex_transcript != NULL) {
	/*
	 * The context is already initialized for NegoEx; undo what
	 * _gss_negoex_end() did, if applicable.
	 */
	if (ctx->negotiated_ctx_id != GSS_C_NO_CONTEXT) {
	    mech = HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
	    heim_assert(mech != NULL && mech->mech_context == GSS_C_NO_CONTEXT,
			"NegoEx/SPNEGO context mismatch");
	    mech->mech_context = ctx->negotiated_ctx_id;
	    ctx->negotiated_ctx_id = GSS_C_NO_CONTEXT;
	}
	return GSS_S_COMPLETE;
    }

    ctx->negoex_transcript = krb5_storage_emem();
    if (ctx->negoex_transcript == NULL) {
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }

    krb5_storage_set_byteorder(ctx->negoex_transcript,
			       KRB5_STORAGE_BYTEORDER_LE);

    return GSS_S_COMPLETE;
}

static void
release_all_mechs(gssspnego_ctx ctx, krb5_context context)
{
    struct negoex_auth_mech *mech, *next;
    struct negoex_auth_mech *prev = NULL;

    HEIM_TAILQ_FOREACH_SAFE(mech, &ctx->negoex_mechs, links, next) {
	if (prev)
	    _gss_negoex_release_auth_mech(context, prev);
	prev = mech;
    }
    if (prev)
	_gss_negoex_release_auth_mech(context, mech);

    HEIM_TAILQ_INIT(&ctx->negoex_mechs);
}

void
_gss_negoex_release_context(gssspnego_ctx ctx)
{
    krb5_context context = _gss_mg_krb5_context();

    if (ctx->negoex_transcript != NULL) {
	krb5_storage_free(ctx->negoex_transcript);
	ctx->negoex_transcript = NULL;
    }

    release_all_mechs(ctx, context);
}

static int
guid_to_string(const uint8_t guid[16], char *buffer, size_t bufsiz)
{
    uint32_t data1;
    uint16_t data2, data3;

    _gss_mg_decode_le_uint32(&guid[0], &data1);
    _gss_mg_decode_le_uint16(&guid[4], &data2);
    _gss_mg_decode_le_uint16(&guid[6], &data3);

    return snprintf(buffer, bufsiz,
		    "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		    data1, data2, data3, guid[8], guid[9], guid[10], guid[11],
		    guid[12], guid[13], guid[14], guid[15]);
}

void
_gss_negoex_log_auth_scheme(int initiator,
			    int index,
			    const auth_scheme scheme)
{
    char scheme_str[37];

    guid_to_string(scheme, scheme_str, sizeof(scheme_str));

    _gss_mg_log(NEGOEX_LOG_LEVEL,
		"negoex: %s authentication scheme %d %s",
		initiator ? "proposing" : "received", index, scheme_str);
}

void
_gss_negoex_log_message(int direction,
			enum message_type type,
			const conversation_id conv_id,
			unsigned int seqnum,
			unsigned int header_len,
			unsigned int msg_len)
{
    char conv_str[37];
    char *typestr;

    if (type == INITIATOR_NEGO)
	typestr = "INITIATOR_NEGO";
    else if (type == ACCEPTOR_NEGO)
	typestr = "ACCEPTOR_NEGO";
    else if (type == INITIATOR_META_DATA)
	typestr = "INITIATOR_META_DATA";
    else if (type == ACCEPTOR_META_DATA)
	typestr = "ACCEPTOR_META_DATA";
    else if (type == CHALLENGE)
	typestr = "CHALLENGE";
    else if (type == AP_REQUEST)
	typestr = "AP_REQUEST";
    else if (type == VERIFY)
	typestr = "VERIFY";
    else if (type == ALERT)
	typestr = "ALERT";
    else
	typestr = "UNKNOWN";

    guid_to_string(conv_id, conv_str, sizeof(conv_str));
    _gss_mg_log(NEGOEX_LOG_LEVEL,
		"negoex: %s (%d)%s conversation %s",
		direction ? "received" : "sending",
		seqnum, typestr, conv_str);
}

/*
 * Check that the described vector lies within the message, and return a
 * pointer to its first element.
 */
static inline const uint8_t *
vector_base(size_t offset, size_t count, size_t width,
	    const uint8_t *msg_base, size_t msg_len)
{
    if (offset > msg_len || count > (msg_len - offset) / width)
	return NULL;
    return msg_base + offset;
}

static OM_uint32
parse_nego_message(OM_uint32 *minor, krb5_storage *sp,
		   const uint8_t *msg_base, size_t msg_len,
		   struct nego_message *msg)
{
    krb5_error_code ret;
    const uint8_t *p;
    uint64_t protocol_version;
    uint32_t extension_type, offset;
    uint16_t count;
    size_t i;

    if (krb5_storage_read(sp, msg->random,
			  sizeof(msg->random)) != sizeof(msg->random)) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    ret = krb5_ret_uint64(sp, &protocol_version);
    if (ret) {
	*minor = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (protocol_version != 0) {
	*minor = (OM_uint32)NEGOEX_UNSUPPORTED_VERSION;
	return GSS_S_UNAVAILABLE;
    }

    ret = krb5_ret_uint32(sp, &offset);
    if (ret == 0)
	ret = krb5_ret_uint16(sp, &count);
    if (ret) {
	*minor = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    msg->schemes = vector_base(offset, count, GUID_LENGTH, msg_base, msg_len);
    msg->nschemes = count;
    if (msg->schemes == NULL) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    ret = krb5_ret_uint32(sp, &offset);
    if (ret == 0)
	ret = krb5_ret_uint16(sp, &count);
    if (ret) {
	*minor = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }
    p = vector_base(offset, count, EXTENSION_LENGTH, msg_base, msg_len);
    for (i = 0; i < count; i++) {
	_gss_mg_decode_le_uint32(p + i * EXTENSION_LENGTH, &extension_type);
	if (extension_type & EXTENSION_FLAG_CRITICAL) {
	    *minor = (OM_uint32)NEGOEX_UNSUPPORTED_CRITICAL_EXTENSION;
	    return GSS_S_UNAVAILABLE;
	}
    }

    return GSS_S_COMPLETE;
}

static OM_uint32
parse_exchange_message(OM_uint32 *minor, krb5_storage *sp,
		       const uint8_t *msg_base, size_t msg_len,
		       struct exchange_message *msg)
{
    krb5_error_code ret;
    const uint8_t *p;
    uint32_t offset;
    uint16_t len;

    if (krb5_storage_read(sp, msg->scheme, GUID_LENGTH) != GUID_LENGTH) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    ret = krb5_ret_uint32(sp, &offset);
    if (ret == 0)
	ret = krb5_ret_uint16(sp, &len);
    if (ret) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    p = vector_base(offset, len, 1, msg_base, msg_len);
    if (p == NULL) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }
    msg->token.value = (void *)p;
    msg->token.length = len;

    return GSS_S_COMPLETE;
}

static OM_uint32
parse_verify_message(OM_uint32 *minor, krb5_storage *sp,
		     const uint8_t *msg_base, size_t msg_len,
		     size_t token_offset, struct verify_message *msg)
{
    krb5_error_code ret;
    uint32_t hdrlen, cksum_scheme;
    uint32_t offset, len;

    if (krb5_storage_read(sp, msg->scheme, GUID_LENGTH) == GUID_LENGTH)
	ret = 0;
    else
	ret = NEGOEX_INVALID_MESSAGE_SIZE;
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &hdrlen);
    if (ret) {
	*minor = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (hdrlen != CHECKSUM_HEADER_LENGTH) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    ret = krb5_ret_uint32(sp, &cksum_scheme);
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &msg->cksum_type);
    if (ret) {
	*minor = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (cksum_scheme != CHECKSUM_SCHEME_RFC3961) {
	*minor = (OM_uint32)NEGOEX_UNKNOWN_CHECKSUM_SCHEME;
	return GSS_S_UNAVAILABLE;
    }

    ret = krb5_ret_uint32(sp, &offset);
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &len);
    if (ret) {
	*minor = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    msg->cksum = vector_base(offset, len, 1, msg_base, msg_len);
    msg->cksum_len = len;
    if (msg->cksum == NULL) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    msg->offset_in_token = token_offset;
    return GSS_S_COMPLETE;
}

static OM_uint32
storage_from_memory(OM_uint32 *minor,
		    const uint8_t *data,
		    size_t length,
		    krb5_storage **sp)
{
    *sp = krb5_storage_from_readonly_mem(data, length);
    if (*sp == NULL) {
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }

    krb5_storage_set_byteorder(*sp, KRB5_STORAGE_BYTEORDER_LE);
    krb5_storage_set_eof_code(*sp, NEGOEX_INVALID_MESSAGE_SIZE);

    return 0;
}

static OM_uint32
parse_alert_message(OM_uint32 *minor, krb5_storage *sp,
		    const uint8_t *msg_base, size_t msg_len,
		    struct alert_message *msg)
{
    OM_uint32 major;
    krb5_error_code ret;
    const uint8_t *p;
    uint32_t error_code, atype;
    uint32_t alerts_offset, nalerts, value_offset, value_len;
    size_t i;
    krb5_storage *alerts;

    if (krb5_storage_read(sp, msg->scheme, GUID_LENGTH) == GUID_LENGTH)
	ret = 0;
    else
	ret = NEGOEX_INVALID_MESSAGE_SIZE;
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &error_code);
    if (ret) {
	*minor = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    ret = krb5_ret_uint32(sp, &alerts_offset);
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &nalerts);
    if (ret) {
	*minor = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    p = vector_base(alerts_offset, nalerts, ALERT_LENGTH, msg_base, msg_len);
    if (p == NULL) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    /* Look for a VERIFY_NO_KEY pulse alert in the alerts vector. */
    msg->verify_no_key = FALSE;

    major = storage_from_memory(minor, p, nalerts * ALERT_LENGTH, &alerts);
    if (major != GSS_S_COMPLETE)
	return major;

    for (i = 0; i < nalerts; i++) {
	ret = krb5_ret_uint32(alerts, &atype);
	if (ret == 0)
	    ret = krb5_ret_uint32(alerts, &value_offset);
	if (ret == 0)
	    ret = krb5_ret_uint32(alerts, &value_len);
	if (ret) {
	    *minor = ret;
	    major = GSS_S_DEFECTIVE_TOKEN;
	    break;
	}

	p = vector_base(value_offset, value_len, 1, msg_base, msg_len);
	if (p == NULL) {
	    *minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	    major = GSS_S_DEFECTIVE_TOKEN;
	    break;
	}

	if (atype == ALERT_TYPE_PULSE && value_len >= ALERT_PULSE_LENGTH) {
	    krb5_storage *pulse;
	    uint32_t hdrlen, reason;

	    major = storage_from_memory(minor, p, value_len, &pulse);
	    if (major != GSS_S_COMPLETE)
		break;

	    ret = krb5_ret_uint32(pulse, &hdrlen);
	    if (ret == 0)
		ret = krb5_ret_uint32(pulse, &reason);
	    krb5_storage_free(pulse);
	    if (ret) {
		*minor = ret;
		major = GSS_S_DEFECTIVE_TOKEN;
		break;
	    }

	    if (reason == ALERT_VERIFY_NO_KEY)
		msg->verify_no_key = TRUE;
	}
    }

    krb5_storage_free(alerts);

    return major;
}

static OM_uint32
parse_message(OM_uint32 *minor,
	      gssspnego_ctx ctx,
	      gss_const_buffer_t token,
	      size_t *token_offset,
	      struct negoex_message *msg)
{
    OM_uint32 major;
    krb5_error_code ret;
    krb5_storage *sp;
    uint64_t signature;
    uint32_t header_len, msg_len;
    uint32_t type, seqnum;
    conversation_id conv_id;
    size_t token_remaining = token->length - *token_offset;
    const uint8_t *msg_base = (uint8_t *)token->value + *token_offset;

    major = storage_from_memory(minor, msg_base, token_remaining, &sp);
    if (major != GSS_S_COMPLETE)
	return major;

    major = GSS_S_DEFECTIVE_TOKEN;

    ret = krb5_ret_uint64(sp, &signature);
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &type);
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &seqnum);
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &header_len);
    if (ret == 0)
	ret = krb5_ret_uint32(sp, &msg_len);
    if (ret == 0) {
	if (krb5_storage_read(sp, conv_id, GUID_LENGTH) != GUID_LENGTH)
	    ret = NEGOEX_INVALID_MESSAGE_SIZE;
    }
    if (ret) {
	*minor = ret;
	goto cleanup;
    }

    if (msg_len > token_remaining || header_len > msg_len) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	goto cleanup;
    }
    if (signature != MESSAGE_SIGNATURE) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIGNATURE;
	goto cleanup;
    }
    if (seqnum != ctx->negoex_seqnum) {
	*minor = (OM_uint32)NEGOEX_MESSAGE_OUT_OF_SEQUENCE;
	goto cleanup;
    }
    if (seqnum == 0) {
	memcpy(ctx->negoex_conv_id, conv_id, GUID_LENGTH);
    } else if (!GUID_EQ(conv_id, ctx->negoex_conv_id)) {
	*minor = (OM_uint32)NEGOEX_INVALID_CONVERSATION_ID;
	goto cleanup;
    }

    krb5_storage_truncate(sp, msg_len);

    msg->type = type;
    if (type == INITIATOR_NEGO || type == ACCEPTOR_NEGO) {
	major = parse_nego_message(minor, sp, msg_base, msg_len, &msg->u.n);
    } else if (type == INITIATOR_META_DATA || type == ACCEPTOR_META_DATA ||
	       type == CHALLENGE || type == AP_REQUEST) {
	major = parse_exchange_message(minor, sp, msg_base, msg_len,
				       &msg->u.e);
    } else if (type == VERIFY) {
	major = parse_verify_message(minor, sp, msg_base, msg_len,
				     msg_base - (uint8_t *)token->value,
				     &msg->u.v);
    } else if (type == ALERT) {
	major = parse_alert_message(minor, sp, msg_base, msg_len, &msg->u.a);
    } else {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_TYPE;
	goto cleanup;
    }

cleanup:
    krb5_storage_free(sp);

    if (major == GSS_S_COMPLETE) {
	_gss_negoex_log_message(1, msg->type,
				ctx->negoex_conv_id, ctx->negoex_seqnum,
				header_len, msg_len);
	ctx->negoex_seqnum++;
	*token_offset += msg_len;
    }

    return major;
}

/*
 * Parse token into an array of negoex_message structures. All pointer fields
 * within the parsed messages are aliases into token, so the result can be
 * freed with free(). An unknown protocol version, a critical extension, or an
 * unknown checksum scheme will cause a parsing failure. Increment the
 * sequence number in ctx for each message, and record and check the
 * conversation ID in ctx as appropriate.
 */
OM_uint32
_gss_negoex_parse_token(OM_uint32 *minor,
			gssspnego_ctx ctx,
			gss_const_buffer_t token,
			struct negoex_message **messages_out,
			size_t *count_out)
{
    OM_uint32 major = GSS_S_DEFECTIVE_TOKEN;
    size_t count = 0;
    size_t token_offset = 0;
    struct negoex_message *messages = NULL, *newptr;

    *messages_out = NULL;
    *count_out = 0;
    heim_assert(token != GSS_C_NO_BUFFER, "Invalid null NegoEx input token");

    while (token_offset < token->length) {
	newptr = realloc(messages, (count + 1) * sizeof(*newptr));
	if (newptr == NULL) {
	    free(messages);
	    *minor = ENOMEM;
	    return GSS_S_FAILURE;
	}
	messages = newptr;

	major = parse_message(minor, ctx, token, &token_offset,
			      &messages[count]);
	if (major != GSS_S_COMPLETE)
	    break;

	count++;
    }

    if (token_offset != token->length) {
	*minor = (OM_uint32)NEGOEX_INVALID_MESSAGE_SIZE;
	major = GSS_S_DEFECTIVE_TOKEN;
    }
    if (major != GSS_S_COMPLETE) {
	free(messages);
	return major;
    }

    *messages_out = messages;
    *count_out = count;
    return GSS_S_COMPLETE;
}

static struct negoex_message *
locate_message(struct negoex_message *messages, size_t nmessages,
	       enum message_type type)
{
    uint32_t i;

    for (i = 0; i < nmessages; i++) {
	if (messages[i].type == type)
	    return &messages[i];
    }

    return NULL;
}

struct nego_message *
_gss_negoex_locate_nego_message(struct negoex_message *messages,
				size_t nmessages,
				enum message_type type)
{
    struct negoex_message *msg = locate_message(messages, nmessages, type);

    return (msg == NULL) ? NULL : &msg->u.n;
}

struct exchange_message *
_gss_negoex_locate_exchange_message(struct negoex_message *messages,
				    size_t nmessages,
				    enum message_type type)
{
    struct negoex_message *msg = locate_message(messages, nmessages, type);

    return (msg == NULL) ? NULL : &msg->u.e;
}

struct verify_message *
_gss_negoex_locate_verify_message(struct negoex_message *messages,
				  size_t nmessages)
{
    struct negoex_message *msg = locate_message(messages, nmessages, VERIFY);

    return (msg == NULL) ? NULL : &msg->u.v;
}

struct alert_message *
_gss_negoex_locate_alert_message(struct negoex_message *messages,
				 size_t nmessages)
{
    struct negoex_message *msg = locate_message(messages, nmessages, ALERT);

    return (msg == NULL) ? NULL : &msg->u.a;
}

/*
 * Add the encoding of a MESSAGE_HEADER structure to buf, given the number of
 * bytes of the payload following the full header. Increment the sequence
 * number in ctx. Set *payload_start_out to the position of the payload within
 * the message.
 */
static OM_uint32
put_message_header(OM_uint32 *minor, gssspnego_ctx ctx,
		   enum message_type type, uint32_t payload_len,
		   uint32_t *payload_start_out)
{
    krb5_error_code ret;
    size_t header_len = 0;

    if (type == INITIATOR_NEGO || type == ACCEPTOR_NEGO)
	header_len = NEGO_MESSAGE_HEADER_LENGTH;
    else if (type == INITIATOR_META_DATA || type == ACCEPTOR_META_DATA ||
	     type == CHALLENGE || type == AP_REQUEST)
	header_len = EXCHANGE_MESSAGE_HEADER_LENGTH;
    else if (type == VERIFY)
	header_len = VERIFY_MESSAGE_HEADER_LENGTH;
    else if (type == ALERT)
	header_len = ALERT_MESSAGE_HEADER_LENGTH;
    else
	heim_assert(0, "Invalid NegoEx message type");

    /* Signature */
    CHECK(ret, krb5_store_uint64(ctx->negoex_transcript, MESSAGE_SIGNATURE));
    /* MessageType */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, type));
    /* SequenceNum */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, ctx->negoex_seqnum));
    /* cbHeaderLength */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, header_len));
    /* cbMessageLength */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, header_len + payload_len));
    /* ConversationId */
    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, ctx->negoex_conv_id, GUID_LENGTH));

    _gss_negoex_log_message(0, type,
			    ctx->negoex_conv_id, ctx->negoex_seqnum,
			    header_len,
			    header_len + payload_len);

    ctx->negoex_seqnum++;

    *payload_start_out = header_len;
    return GSS_S_COMPLETE;

fail:
    *minor = ret;
    return GSS_S_FAILURE;
}

OM_uint32
_gss_negoex_add_nego_message(OM_uint32 *minor,
			     gssspnego_ctx ctx,
			     enum message_type type,
			     uint8_t random[32])
{
    OM_uint32 major;
    krb5_error_code ret;
    struct negoex_auth_mech *mech;
    uint32_t payload_start;
    uint16_t nschemes;

    nschemes = 0;
    HEIM_TAILQ_FOREACH(mech, &ctx->negoex_mechs, links)
	nschemes++;

    major = put_message_header(minor, ctx, type,
			       nschemes * GUID_LENGTH, &payload_start);
    if (major != GSS_S_COMPLETE)
	return major;

    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, random, 32));
    /* ProtocolVersion */
    CHECK(ret, krb5_store_uint64(ctx->negoex_transcript, 0));
    /* AuthSchemes vector */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, payload_start));
    CHECK(ret, krb5_store_uint16(ctx->negoex_transcript, nschemes));
    /* Extensions vector */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, payload_start));
    CHECK(ret, krb5_store_uint16(ctx->negoex_transcript, 0));
    /* Four bytes of padding to reach a multiple of 8 bytes. */
    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, "\0\0\0\0", 4));

    /* Payload (auth schemes) */
    HEIM_TAILQ_FOREACH(mech, &ctx->negoex_mechs, links) {
	CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, mech->scheme, GUID_LENGTH));
    }

    return GSS_S_COMPLETE;

fail:
    *minor = ret;
    return GSS_S_FAILURE;
}

OM_uint32
_gss_negoex_add_exchange_message(OM_uint32 *minor,
				 gssspnego_ctx ctx,
				 enum message_type type,
				 const auth_scheme scheme,
				 gss_buffer_t token)
{
    OM_uint32 major;
    krb5_error_code ret;
    uint32_t payload_start;

    major = put_message_header(minor, ctx, type, token->length, &payload_start);
    if (major != GSS_S_COMPLETE)
	return major;

    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, scheme, GUID_LENGTH));
    /* Exchange byte vector */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, payload_start));
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, token->length));
    /* Payload (token) */
    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, token->value, token->length));

    return GSS_S_COMPLETE;

fail:
    *minor = ret;
    return GSS_S_FAILURE;
}

OM_uint32
_gss_negoex_add_verify_message(OM_uint32 *minor,
			       gssspnego_ctx ctx,
			       const auth_scheme scheme,
			       uint32_t cksum_type,
			       const uint8_t *cksum,
			       uint32_t cksum_len)
{
    OM_uint32 major;
    krb5_error_code ret;
    uint32_t payload_start;

    major = put_message_header(minor, ctx, VERIFY, cksum_len, &payload_start);
    if (major != GSS_S_COMPLETE)
	return major;

    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, scheme, GUID_LENGTH));
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, CHECKSUM_HEADER_LENGTH));
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, CHECKSUM_SCHEME_RFC3961));
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, cksum_type));
    /* ChecksumValue vector */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, payload_start));
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, cksum_len));
    /* Four bytes of padding to reach a multiple of 8 bytes. */
    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, "\0\0\0\0", 4));
    /* Payload (checksum contents) */
    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, cksum, cksum_len));

    return GSS_S_COMPLETE;

fail:
    *minor = ret;
    return GSS_S_FAILURE;
}

/*
 * Add an ALERT_MESSAGE containing a single ALERT_TYPE_PULSE alert with the
 * reason ALERT_VERIFY_NO_KEY.
 */
OM_uint32
_gss_negoex_add_verify_no_key_alert(OM_uint32 *minor,
				    gssspnego_ctx ctx,
				    const auth_scheme scheme)
{
    OM_uint32 major;
    krb5_error_code ret;
    uint32_t payload_start;

    major = put_message_header(minor, ctx,
			       ALERT, ALERT_LENGTH + ALERT_PULSE_LENGTH,
			       &payload_start);
    if (major != GSS_S_COMPLETE)
	return major;

    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, scheme, GUID_LENGTH));
    /* ErrorCode */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, 0));
    /* Alerts vector */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, payload_start));
    CHECK(ret, krb5_store_uint16(ctx->negoex_transcript, 1));
    /* Six bytes of padding to reach a multiple of 8 bytes. */
    CHECK(ret, krb5_store_bytes(ctx->negoex_transcript, "\0\0\0\0\0\0", 6));
    /* Payload part 1: a single ALERT element */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, ALERT_TYPE_PULSE));
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript,
				 payload_start + ALERT_LENGTH));
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, ALERT_PULSE_LENGTH));
    /* Payload part 2: ALERT_PULSE */
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, ALERT_PULSE_LENGTH));
    CHECK(ret, krb5_store_uint32(ctx->negoex_transcript, ALERT_VERIFY_NO_KEY));

    return GSS_S_COMPLETE;

fail:
    *minor = ret;
    return GSS_S_FAILURE;
}


void
_gss_negoex_release_auth_mech(krb5_context context,
			      struct negoex_auth_mech *mech)
{
    OM_uint32 tmpmin;

    if (mech == NULL)
	return;

    gss_delete_sec_context(&tmpmin, &mech->mech_context, NULL);
    gss_release_oid(&tmpmin, &mech->oid);
    gss_release_buffer(&tmpmin, &mech->metadata);
    if (mech->crypto)
	krb5_crypto_destroy(context, mech->crypto);
    if (mech->verify_crypto)
	krb5_crypto_destroy(context, mech->verify_crypto);

    free(mech);
}

void
_gss_negoex_delete_auth_mech(gssspnego_ctx ctx,
			     struct negoex_auth_mech *mech)
{
    krb5_context context = _gss_mg_krb5_context();

    HEIM_TAILQ_REMOVE(&ctx->negoex_mechs, mech, links);
    _gss_negoex_release_auth_mech(context, mech);
}

/* Remove all auth mech entries except for mech from ctx->mechs. */
void
_gss_negoex_select_auth_mech(gssspnego_ctx ctx,
			     struct negoex_auth_mech *mech)
{
    krb5_context context = _gss_mg_krb5_context();

    heim_assert(mech != NULL, "Invalid null NegoEx mech");
    HEIM_TAILQ_REMOVE(&ctx->negoex_mechs, mech, links);
    release_all_mechs(ctx, context);
    HEIM_TAILQ_INSERT_HEAD(&ctx->negoex_mechs, mech, links);
}

OM_uint32
_gss_negoex_add_auth_mech(OM_uint32 *minor,
			  gssspnego_ctx ctx,
			  gss_const_OID oid,
			  auth_scheme scheme)
{
    OM_uint32 major;
    struct negoex_auth_mech *mech;

    mech = calloc(1, sizeof(*mech));
    if (mech == NULL) {
	*minor = ENOMEM;
	return GSS_S_FAILURE;
    }

    major = gss_duplicate_oid(minor, (gss_OID)oid, &mech->oid);
    if (major != GSS_S_COMPLETE) {
	free(mech);
	return major;
    }

    memcpy(mech->scheme, scheme, GUID_LENGTH);

    HEIM_TAILQ_INSERT_TAIL(&ctx->negoex_mechs, mech, links);

    *minor = 0;
    return GSS_S_COMPLETE;
}

struct negoex_auth_mech *
_gss_negoex_locate_auth_scheme(gssspnego_ctx ctx,
			       const auth_scheme scheme)
{
    struct negoex_auth_mech *mech;

    HEIM_TAILQ_FOREACH(mech, &ctx->negoex_mechs, links) {
	if (GUID_EQ(mech->scheme, scheme))
	    return mech;
    }

    return NULL;
}

/*
 * Prune ctx->mechs to the schemes present in schemes, and reorder them to
 * match its order.
 */
void
_gss_negoex_common_auth_schemes(gssspnego_ctx ctx,
				const uint8_t *schemes,
				uint16_t nschemes)
{
    struct negoex_mech_list list;
    struct negoex_auth_mech *mech;
    uint16_t i;
    krb5_context context = _gss_mg_krb5_context();

    /* Construct a new list in the order of schemes. */
    HEIM_TAILQ_INIT(&list);
    for (i = 0; i < nschemes; i++) {
	mech = _gss_negoex_locate_auth_scheme(ctx, schemes + i * GUID_LENGTH);
	if (mech == NULL)
	    continue;
	HEIM_TAILQ_REMOVE(&ctx->negoex_mechs, mech, links);
	HEIM_TAILQ_INSERT_TAIL(&list, mech, links);
    }

    /* Release any leftover entries and replace the context list. */
    release_all_mechs(ctx, context);
    HEIM_TAILQ_CONCAT(&ctx->negoex_mechs, &list, links);
}

/*
 * Prune ctx->mechs to the schemes present in schemes, but do not change
 * their order.
 */
void
_gss_negoex_restrict_auth_schemes(gssspnego_ctx ctx,
				  const uint8_t *schemes,
				  uint16_t nschemes)
{
    struct negoex_auth_mech *mech, *next;
    uint16_t i;
    int found;

    HEIM_TAILQ_FOREACH_SAFE(mech, &ctx->negoex_mechs, links, next) {
	found = FALSE;
	for (i = 0; i < nschemes && !found; i++) {
	    if (GUID_EQ(mech->scheme, schemes + i * GUID_LENGTH))
		found = TRUE;
	}

	if (!found)
	    _gss_negoex_delete_auth_mech(ctx, mech);
    }
}

/*
 * Return the OID of the current NegoEx mechanism.
 */
struct negoex_auth_mech *
_gss_negoex_negotiated_mech(gssspnego_ctx ctx)
{
    return HEIM_TAILQ_FIRST(&ctx->negoex_mechs);
}

/*
 * Returns TRUE if mechanism can be negotiated by both NegoEx and SPNEGO
 */

int
_gss_negoex_and_spnego_mech_p(gss_const_OID mech)
{
    OM_uint32 major, minor;
    gss_OID_set attrs = GSS_C_NO_OID_SET;
    int negoex_and_spnego = FALSE;

    major = gss_inquire_attrs_for_mech(&minor, mech, &attrs, NULL);
    if (major == GSS_S_COMPLETE) {
	gss_test_oid_set_member(&minor, GSS_C_MA_NEGOEX_AND_SPNEGO,
				attrs, &negoex_and_spnego);
	gss_release_oid_set(&minor, &attrs);
    }

    return negoex_and_spnego;
}

int
_gss_negoex_mech_p(gss_const_OID mech)
{
    OM_uint32 minor;
    auth_scheme scheme;

    return gssspi_query_mechanism_info(&minor, mech,
				       scheme) == GSS_S_COMPLETE;
}

