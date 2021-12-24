/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * Portions Copyright (c) 2004 PADL Software Pty Ltd.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "spnego_locl.h"

#define GSISC(name) \
static								   \
OM_uint32 name(OM_uint32 *, gss_const_cred_id_t, gssspnego_ctx,	   \
	       gss_const_name_t, gss_const_OID,			   \
	       OM_uint32, OM_uint32, const gss_channel_bindings_t, \
	       gss_const_buffer_t, gss_buffer_t,                   \
	       OM_uint32 *, OM_uint32 *)

GSISC(spnego_initial);
GSISC(spnego_reply);
GSISC(wait_server_mic);
GSISC(step_completed);


 /*
  * Is target_name an sane target for `mech´.
  */

static OM_uint32
initiator_approved(OM_uint32 *minor_status,
		   void *userptr,
		   gss_const_name_t target_name,
		   gss_const_cred_id_t cred,
		   gss_OID mech)
{
    OM_uint32 min_stat, maj_stat;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc out;
    struct gssspnego_optimistic_ctx *sel = userptr;
    gss_OID negotiated_mech_type = GSS_C_NO_OID;
    OM_uint32 flags = 0, time_rec = 0;
    auth_scheme scheme;
    int negoex = 0;

    maj_stat = gss_init_sec_context(&min_stat,
				    cred,
				    &ctx,
				    sel->target_name,
				    mech,
				    sel->req_flags,
				    sel->time_req,
				    sel->input_chan_bindings,
				    GSS_C_NO_BUFFER,
				    &negotiated_mech_type,
				    &out,
				    &flags,
				    &time_rec);
    if (GSS_ERROR(maj_stat)) {
	gss_mg_collect_error(mech, maj_stat, min_stat);
	*minor_status = min_stat;
	return maj_stat;
    }

    if (gssspi_query_mechanism_info(&min_stat, mech, scheme) == GSS_S_COMPLETE)
	negoex = 1;

    if (sel->preferred_mech_type == GSS_C_NO_OID) {
	sel->preferred_mech_type = mech;
	sel->negotiated_mech_type = negotiated_mech_type;
	sel->optimistic_token = out;
	sel->optimistic_flags = flags;
	sel->optimistic_time_rec = time_rec;
	sel->gssctx = ctx;
	if (maj_stat == GSS_S_COMPLETE)
	    sel->complete = 1;
	if (negoex)
	    memcpy(sel->scheme, scheme, GUID_LENGTH);
    } else {
	gss_release_buffer(&min_stat, &out);
	gss_delete_sec_context(&min_stat, &ctx, NULL);
    }

    maj_stat = GSS_S_COMPLETE;

    if (negoex) {
	maj_stat = _gss_negoex_add_auth_mech(minor_status, sel->spnegoctx,
					     mech, scheme);
    }

    return maj_stat;
}

/*
 * Send a reply. Note that we only need to send a reply if we
 * need to send a MIC or a mechanism token. Otherwise, we can
 * return an empty buffer.
 *
 * The return value of this will be returned to the API, so it
 * must return GSS_S_CONTINUE_NEEDED if a token was generated.
 */
static OM_uint32
make_reply(OM_uint32 *minor_status,
	   gssspnego_ctx ctx,
	   gss_buffer_t mech_token,
	   gss_buffer_t output_token)
{
    NegotiationToken nt;
    gss_buffer_desc mic_buf;
    OM_uint32 ret, minor;
    size_t size;
    NegStateEnum state;

    memset(&nt, 0, sizeof(nt));

    nt.element = choice_NegotiationToken_negTokenResp;

    nt.u.negTokenResp.negState = NULL;
    nt.u.negTokenResp.supportedMech = NULL;

    output_token->length = 0;
    output_token->value = NULL;

    /* figure out our status */

    if (ctx->flags.open) {
	if (ctx->flags.verified_mic == 1 || ctx->flags.require_mic == 0)
	    state = accept_completed;
	else
	    state = accept_incomplete;
    } else  {
	state = accept_incomplete;
    }

    if (mech_token->length == 0) {
	nt.u.negTokenResp.responseToken = NULL;
    } else {
	ALLOC(nt.u.negTokenResp.responseToken, 1);
	if (nt.u.negTokenResp.responseToken == NULL) {
	    free_NegotiationToken(&nt);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	nt.u.negTokenResp.responseToken->length = mech_token->length;
	nt.u.negTokenResp.responseToken->data   = mech_token->value;
	mech_token->length = 0;
	mech_token->value  = NULL;
    }

    /*
     * XXX should limit when we send the MIC ?
     */
    if (ctx->flags.open && ctx->flags.sent_mic == 0) {

	ctx->flags.sent_mic = 1;

	ret = gss_get_mic(minor_status,
			  ctx->negotiated_ctx_id,
			  0,
			  &ctx->NegTokenInit_mech_types,
			  &mic_buf);
	if (ret == GSS_S_COMPLETE) {
	    _gss_spnego_ntlm_reset_crypto(&minor, ctx, FALSE);

	    ALLOC(nt.u.negTokenResp.mechListMIC, 1);
	    if (nt.u.negTokenResp.mechListMIC == NULL) {
		gss_release_buffer(minor_status, &mic_buf);
		free_NegotiationToken(&nt);
		*minor_status = ENOMEM;
		return GSS_S_FAILURE;
	    }

	    nt.u.negTokenResp.mechListMIC->length = mic_buf.length;
	    nt.u.negTokenResp.mechListMIC->data   = mic_buf.value;
	    /* mic_buf free()d with nt */
	} else if (ret == GSS_S_UNAVAILABLE) {
	    /* lets hope that its ok to not send te mechListMIC for broken mechs */
	    nt.u.negTokenResp.mechListMIC = NULL;
	    ctx->flags.require_mic = 0;
	} else {
	    free_NegotiationToken(&nt);
	    *minor_status = ENOMEM;
	    return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
					   ret, *minor_status,
					   "SPNEGO failed to sign MIC");
	}
    } else {
	nt.u.negTokenResp.mechListMIC = NULL;
    }

    ALLOC(nt.u.negTokenResp.negState, 1);
    if (nt.u.negTokenResp.negState == NULL) {
	free_NegotiationToken(&nt);
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    *nt.u.negTokenResp.negState = state;

    ASN1_MALLOC_ENCODE(NegotiationToken,
		       output_token->value, output_token->length,
		       &nt, &size, ret);
    free_NegotiationToken(&nt);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    if (state != accept_completed)
	return GSS_S_CONTINUE_NEEDED;

    return GSS_S_COMPLETE;
}

static OM_uint32
spnego_initial(OM_uint32 * minor_status,
	       gss_const_cred_id_t cred,
	       gssspnego_ctx ctx,
	       gss_const_name_t target_name,
	       gss_const_OID mech_type,
	       OM_uint32 req_flags,
	       OM_uint32 time_req,
	       const gss_channel_bindings_t input_chan_bindings,
	       gss_const_buffer_t input_token,
	       gss_buffer_t output_token,
	       OM_uint32 * ret_flags,
	       OM_uint32 * time_rec)
{
    NegotiationToken nt;
    int ret;
    OM_uint32 sub, minor;
    gss_buffer_desc mech_token;
    size_t size = 0;
    gss_buffer_desc data;
    struct gssspnego_optimistic_ctx sel;

    *minor_status = 0;

    memset(&nt, 0, sizeof(nt));

    if (target_name == GSS_C_NO_NAME)
	return GSS_S_BAD_NAME;

    sub = gss_duplicate_name(&minor, target_name, &ctx->target_name);
    if (GSS_ERROR(sub)) {
	*minor_status = minor;
	return sub;
    }

    nt.element = choice_NegotiationToken_negTokenInit;

    ctx->flags.local = 1;

    memset(&sel, 0, sizeof(sel));

    sel.spnegoctx = ctx;
    sel.target_name = ctx->target_name;
    sel.preferred_mech_type = GSS_C_NO_OID;
    sel.req_flags = req_flags;
    sel.time_req = time_req;
    sel.input_chan_bindings = (gss_channel_bindings_t)input_chan_bindings;

    sub = _gss_spnego_indicate_mechtypelist(&minor,
					    ctx->target_name,
					    req_flags,
					    initiator_approved,
					    &sel,
					    0,
					    cred,
					    &nt.u.negTokenInit.mechTypes,
					    &ctx->preferred_mech_type);
    if (GSS_ERROR(sub)) {
	*minor_status = minor;
	return sub;
    }

    _gss_spnego_log_mechTypes(&nt.u.negTokenInit.mechTypes);

    nt.u.negTokenInit.reqFlags = NULL;

    if (gss_oid_equal(ctx->preferred_mech_type, GSS_NEGOEX_MECHANISM)) {
	struct negoex_auth_mech *mech;

	sub = _gss_negoex_init(&minor,
			       &sel,
			       ctx,
			       (gss_cred_id_t)cred,
			       req_flags,
			       time_req,
			       input_chan_bindings,
			       GSS_C_NO_BUFFER,
			       &mech_token);
	if (GSS_ERROR(sub)) {
	    free_NegotiationToken(&nt);
	    return gss_mg_set_error_string(GSS_C_NO_OID, sub, minor,
					   "NegoEx could not generate a context token");
	}
	mech = _gss_negoex_negotiated_mech(ctx);
	ctx->flags.maybe_open = mech && mech->complete;
	gss_release_buffer(&minor, &sel.optimistic_token);
    } else {
	/* optimistic token from selection context */
	mech_token = sel.optimistic_token;
	ctx->mech_flags = sel.optimistic_flags;
	ctx->mech_time_rec = sel.optimistic_time_rec;
	ctx->negotiated_mech_type = sel.negotiated_mech_type;
	ctx->negotiated_ctx_id = sel.gssctx;
	ctx->flags.maybe_open = sel.complete;
    }

    if (ctx->preferred_mech_type == GSS_C_NO_OID) {
	free_NegotiationToken(&nt);
	*minor_status = 0;
	return gss_mg_set_error_string(GSS_C_NO_OID, GSS_S_NO_CONTEXT, 0,
				       "SPNEGO could not find a preferred mechanism");
    }


    if (mech_token.length != 0) {
	ALLOC(nt.u.negTokenInit.mechToken, 1);
	if (nt.u.negTokenInit.mechToken == NULL) {
	    free_NegotiationToken(&nt);
	    gss_release_buffer(&minor, &mech_token);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	nt.u.negTokenInit.mechToken->length = mech_token.length;
	nt.u.negTokenInit.mechToken->data = malloc(mech_token.length);
	if (nt.u.negTokenInit.mechToken->data == NULL && mech_token.length != 0) {
	    free_NegotiationToken(&nt);
	    gss_release_buffer(&minor, &mech_token);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	memcpy(nt.u.negTokenInit.mechToken->data, mech_token.value, mech_token.length);
	gss_release_buffer(&minor, &mech_token);
    } else
	nt.u.negTokenInit.mechToken = NULL;

    nt.u.negTokenInit.mechListMIC = NULL;

    {
	MechTypeList mt;

	mt.len = nt.u.negTokenInit.mechTypes.len;
	mt.val = nt.u.negTokenInit.mechTypes.val;

	ASN1_MALLOC_ENCODE(MechTypeList,
			   ctx->NegTokenInit_mech_types.value,
			   ctx->NegTokenInit_mech_types.length,
			   &mt, &size, ret);
	if (ret) {
	    *minor_status = ret;
	    free_NegotiationToken(&nt);
	    return GSS_S_FAILURE;
	}
    }

    ASN1_MALLOC_ENCODE(NegotiationToken, data.value, data.length, &nt, &size, ret);
    free_NegotiationToken(&nt);
    if (ret) {
	return GSS_S_FAILURE;
    }
    if (data.length != size)
	abort();

    sub = gss_encapsulate_token(&data,
				GSS_SPNEGO_MECHANISM,
				output_token);
    free (data.value);

    if (sub) {
	return sub;
    }

    if (ret_flags)
	*ret_flags = ctx->mech_flags;
    if (time_rec)
	*time_rec = ctx->mech_time_rec;

    ctx->initiator_state = spnego_reply;

    return GSS_S_CONTINUE_NEEDED;
}

/*
 *
 */

static OM_uint32
spnego_reply(OM_uint32 * minor_status,
	     gss_const_cred_id_t cred,
	     gssspnego_ctx ctx,
	     gss_const_name_t target_name,
	     gss_const_OID mech_type,
	     OM_uint32 req_flags,
	     OM_uint32 time_req,
	     const gss_channel_bindings_t input_chan_bindings,
	     gss_const_buffer_t input_token,
	     gss_buffer_t output_token,
	     OM_uint32 * ret_flags,
	     OM_uint32 * time_rec)
{
    OM_uint32 ret, minor;
    NegotiationToken resp;
    gss_buffer_desc mech_output_token;
    NegStateEnum negState;

    *minor_status = 0;

    output_token->length = 0;
    output_token->value  = NULL;

    mech_output_token.length = 0;
    mech_output_token.value = NULL;

    ret = decode_NegotiationToken(input_token->value, input_token->length,
				  &resp, NULL);
    if (ret)
      return ret;

    /* The SPNEGO token must be a negTokenResp */
    if (resp.element != choice_NegotiationToken_negTokenResp) {
	free_NegotiationToken(&resp);
	*minor_status = 0;
	return GSS_S_BAD_MECH;
    }

    /*
     * When negState is absent, the actual state should be inferred from
     * the state of the negotiated mechanism context. (RFC 4178 4.2.2.)
     */
    if (resp.u.negTokenResp.negState != NULL)
	negState = *resp.u.negTokenResp.negState;
    else
	negState = accept_incomplete;

    /*
     * Pick up the mechanism that the acceptor selected, only pick up
     * the first selection.
     */

    if (ctx->selected_mech_type == GSS_C_NO_OID && resp.u.negTokenResp.supportedMech) {
	gss_OID_desc oid;
	size_t len;

	ctx->flags.seen_supported_mech = 1;

	oid.length = (OM_uint32)der_length_oid(resp.u.negTokenResp.supportedMech);
	oid.elements = malloc(oid.length);
	if (oid.elements == NULL) {
	    free_NegotiationToken(&resp);
	    return GSS_S_BAD_MECH;
	}
	ret = der_put_oid(((uint8_t *)oid.elements) + oid.length - 1,
			  oid.length,
			  resp.u.negTokenResp.supportedMech,
			  &len);
	if (ret || len != oid.length) {
	    free(oid.elements);
	    free_NegotiationToken(&resp);
	    return GSS_S_BAD_MECH;
	}

	if (gss_oid_equal(GSS_SPNEGO_MECHANISM, &oid)) {
	    free(oid.elements);
	    free_NegotiationToken(&resp);
	    return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
					   GSS_S_BAD_MECH, (*minor_status = EINVAL),
					   "SPNEGO acceptor picked SPNEGO??");
	}

	/* check if the acceptor took our optimistic token */
	if (gss_oid_equal(ctx->preferred_mech_type, &oid)) {
	    ctx->selected_mech_type = ctx->preferred_mech_type;
	} else if (gss_oid_equal(ctx->preferred_mech_type, GSS_KRB5_MECHANISM) &&
		   gss_oid_equal(&oid, &_gss_spnego_mskrb_mechanism_oid_desc)) {
	    /* mis-encoded asn1 type from msft servers */
	    ctx->selected_mech_type = ctx->preferred_mech_type;
	} else {
	    /* nope, lets start over */
	    gss_delete_sec_context(&minor, &ctx->negotiated_ctx_id,
				   GSS_C_NO_BUFFER);
	    ctx->negotiated_ctx_id = GSS_C_NO_CONTEXT;

	    if (gss_oid_equal(&oid, GSS_NEGOEX_MECHANISM))
		ctx->selected_mech_type = GSS_NEGOEX_MECHANISM;
	    else
		ctx->selected_mech_type = _gss_mg_support_mechanism(&oid);

	    /* XXX check that server pick a mechanism we proposed */
	    if (ctx->selected_mech_type == GSS_C_NO_OID) {
		free(oid.elements);
		free_NegotiationToken(&resp);
		return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
					       GSS_S_BAD_MECH, (*minor_status = EINVAL),
					       "SPNEGO acceptor sent unsupported supportedMech");
	    }
	}

	_gss_spnego_log_mech("initiator selected mechanism", ctx->selected_mech_type);

	free(oid.elements);

    } else if (ctx->selected_mech_type == NULL) {
	free_NegotiationToken(&resp);
	return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				       GSS_S_BAD_MECH, (*minor_status = EINVAL),
				       "SPNEGO acceptor didn't send supportedMech");
    }

    /* if a token (of non zero length) pass to underlaying mech */
    if ((resp.u.negTokenResp.responseToken != NULL && resp.u.negTokenResp.responseToken->length) ||
	ctx->negotiated_ctx_id == GSS_C_NO_CONTEXT) {
	gss_buffer_desc mech_input_token;

	if (resp.u.negTokenResp.responseToken) {
	    mech_input_token.length = resp.u.negTokenResp.responseToken->length;
	    mech_input_token.value  = resp.u.negTokenResp.responseToken->data;
	} else {
	    mech_input_token.length = 0;
	    mech_input_token.value = NULL;
	}

	/* Fall through as if the negotiated mechanism
	   was requested explicitly */
	if (gss_oid_equal(ctx->selected_mech_type, GSS_NEGOEX_MECHANISM)) {
	    ret = _gss_negoex_init(&minor,
				   NULL, /* no optimistic token */
				   ctx,
				   (gss_cred_id_t)cred,
				   req_flags,
				   time_req,
				   input_chan_bindings,
				   &mech_input_token,
				   &mech_output_token);
	} else {
	    ret = gss_init_sec_context(&minor,
				       cred,
				       &ctx->negotiated_ctx_id,
				       ctx->target_name,
				       ctx->selected_mech_type,
				       req_flags,
				       time_req,
				       input_chan_bindings,
				       &mech_input_token,
				       &ctx->negotiated_mech_type,
				       &mech_output_token,
				       &ctx->mech_flags,
				       &ctx->mech_time_rec);
	    if (GSS_ERROR(ret)) {
		gss_mg_collect_error(ctx->selected_mech_type, ret, minor);
	    }
	}
	/*
	 * If the acceptor rejected, we're out even if the inner context is
	 * now complete. Note that the rejection is not integrity-protected.
	 */
	if (negState == reject)
	    ret = GSS_S_BAD_MECH;
	if (GSS_ERROR(ret)) {
	    free_NegotiationToken(&resp);
	    *minor_status = minor;
	    return ret;
	}
	if (ret == GSS_S_COMPLETE) {
	    ctx->flags.open = 1;
	}
    } else if (negState == reject) {
	free_NegotiationToken(&resp);
	return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				       GSS_S_BAD_MECH, (*minor_status = EPERM),
				       "SPNEGO acceptor rejected initiator token");
    } else if (negState == accept_completed) {
	/*
	 * Note that the accept_completed isn't integrity-protected, but
	 * ctx->maybe_open can only be true if the inner context is fully
	 * established.
	 */
	if (ctx->flags.maybe_open)
	    ctx->flags.open = 1;

	if (!ctx->flags.open) {
	    free_NegotiationToken(&resp);
	    return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
					   GSS_S_BAD_MECH, (*minor_status = EINVAL),
					   "SPNEGO acceptor sent acceptor complete, "
					   "but we are not complete yet");
	}
    }

    if (negState == request_mic) {
	ctx->flags.peer_require_mic = 1;
    }

    if (ctx->flags.open && ctx->flags.verified_mic == 0) {

	ctx->flags.require_mic = 1; /* default is to require a MIC */
	ctx->flags.safe_omit = _gss_spnego_safe_omit_mechlist_mic(ctx);
	
	/*
	 * If the peer sent mechListMIC, require it to verify ...
	 */
	if (resp.u.negTokenResp.mechListMIC) {
	    heim_octet_string *m = resp.u.negTokenResp.mechListMIC;

	    /* ...unless its a windows 2000 server that sends the
	     * responseToken inside the mechListMIC too. We only
	     * accept this condition if would have been safe to omit
	     * anyway. */

	    if (ctx->flags.safe_omit
		&& resp.u.negTokenResp.responseToken
		&& der_heim_octet_string_cmp(m, resp.u.negTokenResp.responseToken) == 0)
	    {
		ctx->flags.require_mic = 0;
	    }
	}

    } else {
	ctx->flags.require_mic = 0;
    }

    /*
     * If we are supposed to check mic and have it, force checking now.
     */

    if (ctx->flags.require_mic && resp.u.negTokenResp.mechListMIC) {

	ret = _gss_spnego_verify_mechtypes_mic(minor_status, ctx,
					       resp.u.negTokenResp.mechListMIC);
	if (ret) {
	    free_NegotiationToken(&resp);
	    return ret;
	}
    }

    /*
     * Now that underlaying mech is open (conncted), we can figure out
     * what nexd step to go to.
     */

    if (ctx->flags.open) {

	if (negState == accept_completed && ctx->flags.safe_omit) {
	    ctx->initiator_state = step_completed;
	    ret = GSS_S_COMPLETE;
	} else if (ctx->flags.require_mic != 0 && ctx->flags.verified_mic == 0) {
	    ctx->initiator_state = wait_server_mic;
	    ret = GSS_S_CONTINUE_NEEDED;
	} else {
	    ctx->initiator_state = step_completed;
	    ret = GSS_S_COMPLETE;
	}
    }

    if (negState != accept_completed ||
	ctx->initiator_state != step_completed ||
	mech_output_token.length)
    {
	OM_uint32 ret2;
	ret2 = make_reply(minor_status, ctx,
			  &mech_output_token,
			  output_token);
	if (ret2)
	    ret = ret2;
    }

    free_NegotiationToken(&resp);

    gss_release_buffer(&minor, &mech_output_token);

    if (ret_flags)
	*ret_flags = ctx->mech_flags;
    if (time_rec)
	*time_rec = ctx->mech_time_rec;

    return ret;
}

static OM_uint32
wait_server_mic(OM_uint32 * minor_status,
		gss_const_cred_id_t cred,
		gssspnego_ctx ctx,
		gss_const_name_t target_name,
		gss_const_OID mech_type,
		OM_uint32 req_flags,
		OM_uint32 time_req,
		const gss_channel_bindings_t input_chan_bindings,
		gss_const_buffer_t input_token,
		gss_buffer_t output_token,
		OM_uint32 * ret_flags,
		OM_uint32 * time_rec)
{
    OM_uint32 major_status;
    NegotiationToken resp;
    int ret;

    ret = decode_NegotiationToken(input_token->value, input_token->length, &resp, NULL);
    if (ret)
	return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				       GSS_S_BAD_MECH, ret,
				       "Failed to decode NegotiationToken");

    if (resp.element != choice_NegotiationToken_negTokenResp
	|| resp.u.negTokenResp.negState == NULL
	|| *resp.u.negTokenResp.negState != accept_completed)
    {
	free_NegotiationToken(&resp);
	return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				       GSS_S_BAD_MECH, (*minor_status = EINVAL),
				       "NegToken not accept_completed");
    }

    if (resp.u.negTokenResp.mechListMIC) {
	major_status = _gss_spnego_verify_mechtypes_mic(minor_status, ctx,
							resp.u.negTokenResp.mechListMIC);
    } else if (ctx->flags.safe_omit == 0) {
	free_NegotiationToken(&resp);
	return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				       GSS_S_BAD_MECH, (*minor_status = EINVAL),
				       "Waiting for MIC, but its missing in server request");
    } else {
	major_status = GSS_S_COMPLETE;
    }

    free_NegotiationToken(&resp);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    ctx->flags.verified_mic = 1;
    ctx->initiator_state = step_completed;

    if (ret_flags)
	*ret_flags = ctx->mech_flags;
    if (time_rec)
	*time_rec = ctx->mech_time_rec;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
step_completed(OM_uint32 * minor_status,
	       gss_const_cred_id_t cred,
	       gssspnego_ctx ctx,
	       gss_const_name_t name,
	       gss_const_OID mech_type,
	       OM_uint32 req_flags,
	       OM_uint32 time_req,
	       const gss_channel_bindings_t input_chan_bindings,
	       gss_const_buffer_t input_token,
	       gss_buffer_t output_token,
	       OM_uint32 * ret_flags,
	       OM_uint32 * time_rec)
{
    return gss_mg_set_error_string(GSS_SPNEGO_MECHANISM,
				   GSS_S_BAD_STATUS, (*minor_status = EINVAL),
				   "SPNEGO called got ISC call one too many");
}

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_init_sec_context(OM_uint32 * minor_status,
			     gss_const_cred_id_t initiator_cred_handle,
			     gss_ctx_id_t * context_handle,
			     gss_const_name_t target_name,
			     const gss_OID mech_type,
			     OM_uint32 req_flags,
			     OM_uint32 time_req,
			     const gss_channel_bindings_t input_chan_bindings,
			     const gss_buffer_t input_token,
			     gss_OID * actual_mech_type,
			     gss_buffer_t output_token,
			     OM_uint32 * ret_flags,
			     OM_uint32 * time_rec)
{
    gssspnego_ctx ctx;
    OM_uint32 ret;

    if (*context_handle == GSS_C_NO_CONTEXT) {
	ret = _gss_spnego_alloc_sec_context(minor_status, context_handle);
	if (GSS_ERROR(ret))
	    return ret;

	ctx = (gssspnego_ctx)*context_handle;

	ctx->initiator_state = spnego_initial;
    } else {
	ctx = (gssspnego_ctx)*context_handle;
    }


    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);

    do {
	ret = ctx->initiator_state(minor_status, initiator_cred_handle, ctx, target_name,
				   mech_type, req_flags, time_req, input_chan_bindings, input_token,
				   output_token, ret_flags, time_rec);

    } while (ret == GSS_S_COMPLETE &&
	     ctx->initiator_state != step_completed &&
	     output_token->length == 0);

    /* destroy context in case of error */
    if (GSS_ERROR(ret)) {
	OM_uint32 junk;
	_gss_spnego_internal_delete_sec_context(&junk, context_handle, GSS_C_NO_BUFFER);
    } else {

	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);

	if (actual_mech_type)
	    *actual_mech_type = ctx->negotiated_mech_type;
    }

    return ret;
}

