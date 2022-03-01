/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
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

static OM_uint32
send_reject (OM_uint32 *minor_status,
	     gss_const_buffer_t mech_token,
	     gss_buffer_t output_token)
{
    NegotiationToken nt;
    size_t size;
    heim_octet_string responseToken;

    nt.element = choice_NegotiationToken_negTokenResp;

    ALLOC(nt.u.negTokenResp.negState, 1);
    if (nt.u.negTokenResp.negState == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    *(nt.u.negTokenResp.negState)  = reject;
    nt.u.negTokenResp.supportedMech = NULL;
    nt.u.negTokenResp.responseToken = NULL;

    if (mech_token != GSS_C_NO_BUFFER && mech_token->value != NULL) {
	responseToken.length = mech_token->length;
	responseToken.data   = mech_token->value;
	nt.u.negTokenResp.responseToken = &responseToken;
     } else
	nt.u.negTokenResp.responseToken = NULL;
    nt.u.negTokenResp.mechListMIC   = NULL;

    ASN1_MALLOC_ENCODE(NegotiationToken,
		       output_token->value, output_token->length, &nt,
		       &size, *minor_status);
    nt.u.negTokenResp.responseToken = NULL; /* allocated on stack */
    free_NegotiationToken(&nt);
    if (*minor_status != 0)
	return GSS_S_FAILURE;

    return GSS_S_BAD_MECH;
}

static OM_uint32
acceptor_approved(OM_uint32 *minor_status,
		  void *userptr,
		  gss_const_name_t target_name,
		  gss_const_cred_id_t cred_handle,
		  gss_OID mech)
{
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_OID_set oidset = GSS_C_NO_OID_SET;
    OM_uint32 junk, ret;

    if (target_name == GSS_C_NO_NAME)
	return GSS_S_COMPLETE;

    if (gss_oid_equal(mech, GSS_NEGOEX_MECHANISM)) {
	size_t i;

	ret = _gss_spnego_indicate_mechs(minor_status, &oidset);
	if (ret != GSS_S_COMPLETE)
	    return ret;

	/* before committing to NegoEx, check we can negotiate a mech */
	for (i = 0; i < oidset->count; i++) {
	    gss_OID inner_mech = &oidset->elements[i];

	    if (_gss_negoex_mech_p(inner_mech)) {
		ret = acceptor_approved(minor_status, userptr,
					target_name, cred_handle,
					inner_mech);
		if (ret == GSS_S_COMPLETE)
		    break;
	    }
	}
    } else if (cred_handle != GSS_C_NO_CREDENTIAL) {
	ret = gss_inquire_cred_by_mech(minor_status, cred_handle, mech,
				       NULL, NULL, NULL, NULL);
    } else {
	ret = gss_create_empty_oid_set(minor_status, &oidset);
	if (ret == GSS_S_COMPLETE)
	    ret = gss_add_oid_set_member(minor_status, mech, &oidset);
	if (ret == GSS_S_COMPLETE)
	    ret = gss_acquire_cred(minor_status, target_name,
				   GSS_C_INDEFINITE, oidset,
			       GSS_C_ACCEPT, &cred, NULL, NULL);
    }

    gss_release_oid_set(&junk, &oidset);
    gss_release_cred(&junk, &cred);

    return ret;
}

static OM_uint32
send_supported_mechs (OM_uint32 *minor_status,
		      gssspnego_ctx ctx,
		      gss_const_cred_id_t acceptor_cred,
		      gss_buffer_t output_token)
{
    NegotiationToken2 nt;
    size_t buf_len = 0;
    gss_buffer_desc data;
    OM_uint32 ret;

    memset(&nt, 0, sizeof(nt));

    nt.element = choice_NegotiationToken2_negTokenInit;
    nt.u.negTokenInit.reqFlags = NULL;
    nt.u.negTokenInit.mechToken = NULL;
    nt.u.negTokenInit.negHints = NULL;

    ret = _gss_spnego_indicate_mechtypelist(minor_status, GSS_C_NO_NAME, 0,
					    acceptor_approved, ctx, 1, acceptor_cred,
					    &nt.u.negTokenInit.mechTypes, NULL);
    if (ret != GSS_S_COMPLETE) {
	return ret;
    }

    ALLOC(nt.u.negTokenInit.negHints, 1);
    if (nt.u.negTokenInit.negHints == NULL) {
	*minor_status = ENOMEM;
	free_NegotiationToken2(&nt);
	return GSS_S_FAILURE;
    }

    ALLOC(nt.u.negTokenInit.negHints->hintName, 1);
    if (nt.u.negTokenInit.negHints->hintName == NULL) {
	*minor_status = ENOMEM;
	free_NegotiationToken2(&nt);
	return GSS_S_FAILURE;
    }

    *nt.u.negTokenInit.negHints->hintName = strdup("not_defined_in_RFC4178@please_ignore");
    nt.u.negTokenInit.negHints->hintAddress = NULL;

    ASN1_MALLOC_ENCODE(NegotiationToken2,
		       data.value, data.length, &nt, &buf_len, ret);
    free_NegotiationToken2(&nt);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
    if (data.length != buf_len) {
	abort();
        UNREACHABLE(return GSS_S_FAILURE);
    }

    ret = gss_encapsulate_token(&data, GSS_SPNEGO_MECHANISM, output_token);

    free (data.value);

    if (ret != GSS_S_COMPLETE)
	return ret;

    *minor_status = 0;

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
send_accept (OM_uint32 *minor_status,
	     gssspnego_ctx context_handle,
	     int optimistic_mech_ok,
	     gss_buffer_t mech_token,
	     gss_const_OID selected_mech, /* valid on initial response only */
	     gss_buffer_t mech_buf,
	     gss_buffer_t output_token)
{
    int initial_response = (selected_mech != GSS_C_NO_OID);
    NegotiationToken nt;
    OM_uint32 ret, minor;
    gss_buffer_desc mech_mic_buf;
    size_t size;

    memset(&nt, 0, sizeof(nt));

    nt.element = choice_NegotiationToken_negTokenResp;

    ALLOC(nt.u.negTokenResp.negState, 1);
    if (nt.u.negTokenResp.negState == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    if (context_handle->flags.open) {
	if (mech_token != GSS_C_NO_BUFFER
	    && mech_token->length != 0
	    && mech_buf != GSS_C_NO_BUFFER)
	    *(nt.u.negTokenResp.negState)  = accept_incomplete;
	else
	    *(nt.u.negTokenResp.negState)  = accept_completed;
    } else {
	if (initial_response && !optimistic_mech_ok)
	    *(nt.u.negTokenResp.negState)  = request_mic;
	else
	    *(nt.u.negTokenResp.negState)  = accept_incomplete;
    }

    if (initial_response) {
	ALLOC(nt.u.negTokenResp.supportedMech, 1);
	if (nt.u.negTokenResp.supportedMech == NULL) {
	    *minor_status = ENOMEM;
	    ret = GSS_S_FAILURE;
	    goto out;
	}

	ret = der_get_oid(selected_mech->elements,
			  selected_mech->length,
			  nt.u.negTokenResp.supportedMech,
			  NULL);
	if (ret) {
	    *minor_status = ENOMEM;
	    ret = GSS_S_FAILURE;
	    goto out;
	}

	_gss_spnego_log_mech("acceptor sending selected mech", selected_mech);
    } else {
	nt.u.negTokenResp.supportedMech = NULL;
    }

    if (mech_token != GSS_C_NO_BUFFER && mech_token->length != 0) {
	ALLOC(nt.u.negTokenResp.responseToken, 1);
	if (nt.u.negTokenResp.responseToken == NULL) {
	    *minor_status = ENOMEM;
	    ret = GSS_S_FAILURE;
	    goto out;
	}
	nt.u.negTokenResp.responseToken->length = mech_token->length;
	nt.u.negTokenResp.responseToken->data   = mech_token->value;
	mech_token->length = 0;
	mech_token->value  = NULL;
    } else {
	nt.u.negTokenResp.responseToken = NULL;
    }

    if (mech_buf != GSS_C_NO_BUFFER) {
	ret = gss_get_mic(minor_status,
			  context_handle->negotiated_ctx_id,
			  0,
			  mech_buf,
			  &mech_mic_buf);
	if (ret == GSS_S_COMPLETE) {
	    _gss_spnego_ntlm_reset_crypto(&minor, context_handle, FALSE);

	    ALLOC(nt.u.negTokenResp.mechListMIC, 1);
	    if (nt.u.negTokenResp.mechListMIC == NULL) {
		gss_release_buffer(minor_status, &mech_mic_buf);
		*minor_status = ENOMEM;
		ret = GSS_S_FAILURE;
		goto out;
	    }
	    nt.u.negTokenResp.mechListMIC->length = mech_mic_buf.length;
	    nt.u.negTokenResp.mechListMIC->data   = mech_mic_buf.value;
	} else if (ret == GSS_S_UNAVAILABLE) {
	    nt.u.negTokenResp.mechListMIC = NULL;
	} else {
	    goto out;
	}

    } else
	nt.u.negTokenResp.mechListMIC = NULL;

    ASN1_MALLOC_ENCODE(NegotiationToken,
		       output_token->value, output_token->length,
		       &nt, &size, ret);
    if (ret) {
	*minor_status = ENOMEM;
	ret = GSS_S_FAILURE;
	goto out;
    }

    /*
     * The response should not be encapsulated, because
     * it is a SubsequentContextToken (note though RFC 1964
     * specifies encapsulation for all _Kerberos_ tokens).
     */

    if (*(nt.u.negTokenResp.negState) == accept_completed)
	ret = GSS_S_COMPLETE;
    else
	ret = GSS_S_CONTINUE_NEEDED;

 out:
    free_NegotiationToken(&nt);
    return ret;
}

/*
 * Return the default acceptor identity based on the local hostname
 * or the GSSAPI_SPNEGO_NAME environment variable.
 */

static OM_uint32
default_acceptor_name(OM_uint32 *minor_status,
		      gss_name_t *namep)
{
    OM_uint32 major_status;
    gss_buffer_desc namebuf;
    char *str = NULL, *host, hostname[MAXHOSTNAMELEN];

    *namep = GSS_C_NO_NAME;

    host = secure_getenv("GSSAPI_SPNEGO_NAME");
    if (host == NULL) {
	int rv;

	if (gethostname(hostname, sizeof(hostname)) != 0) {
	    *minor_status = errno;
	    return GSS_S_FAILURE;
	}

	rv = asprintf(&str, "host@%s", hostname);
	if (rv < 0 || str == NULL) {
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	host = str;
    }

    namebuf.length = strlen(host);
    namebuf.value = host;

    major_status = gss_import_name(minor_status, &namebuf,
				   GSS_C_NT_HOSTBASED_SERVICE, namep);

    free(str);

    return major_status;
}

/*
 * Determine whether the mech in mechType can be negotiated. If the
 * mech is NegoEx, make NegoEx mechanisms available for negotiation.
 */

static OM_uint32
select_mech(OM_uint32 *minor_status,
	    gssspnego_ctx ctx,
	    gss_const_cred_id_t cred,
	    gss_const_OID_set supported_mechs,
	    MechType *mechType,
	    int verify_p, /* set on non-optimistic tokens */
	    gss_const_OID *advertised_mech_p)
{
    char mechbuf[64];
    size_t mech_len;
    gss_OID_desc oid;
    gss_OID selected_mech = GSS_C_NO_OID;
    OM_uint32 ret, junk;
    int negoex_proposed = FALSE, negoex_selected = FALSE;
    int includeMSCompatOID = FALSE;
    size_t i;

    *minor_status = 0;
    *advertised_mech_p = GSS_C_NO_OID; /* deals with broken MS OID */

    ctx->selected_mech_type = GSS_C_NO_OID;

    ret = der_put_oid ((unsigned char *)mechbuf + sizeof(mechbuf) - 1,
		       sizeof(mechbuf),
		       mechType,
		       &mech_len);
    if (ret)
	return GSS_S_DEFECTIVE_TOKEN;

    oid.length   = (OM_uint32)mech_len;
    oid.elements = mechbuf + sizeof(mechbuf) - mech_len;

    if (gss_oid_equal(&oid, GSS_NEGOEX_MECHANISM))
	negoex_proposed = TRUE;
    else if (gss_oid_equal(&oid, &_gss_spnego_mskrb_mechanism_oid_desc))
	includeMSCompatOID = TRUE;

    for (i = 0; i < supported_mechs->count; i++) {
	gss_OID iter = &supported_mechs->elements[i];
	auth_scheme scheme;
	int is_negoex_mech = /* mechanism is negotiable under NegoEx */
	    gssspi_query_mechanism_info(&junk, iter, scheme) == GSS_S_COMPLETE;

	if (is_negoex_mech && negoex_proposed) {
	    ret = _gss_negoex_add_auth_mech(minor_status, ctx, iter, scheme);
	    if (ret != GSS_S_COMPLETE)
		break;

	    negoex_selected = TRUE;
	}

	if (gss_oid_equal(includeMSCompatOID ? GSS_KRB5_MECHANISM : &oid, iter)) {
	    ret = _gss_intern_oid(minor_status, iter, &selected_mech);
	    if (ret != GSS_S_COMPLETE)
		return ret;

	    break;
	}
    }

    /* always prefer NegoEx if a mechanism supported both */
    if (negoex_selected)
	selected_mech = GSS_NEGOEX_MECHANISM;
    if (selected_mech == GSS_C_NO_OID)
	ret = GSS_S_BAD_MECH;
    if (ret != GSS_S_COMPLETE)
	return ret;

    heim_assert(!gss_oid_equal(selected_mech, GSS_SPNEGO_MECHANISM),
		"SPNEGO should not be able to negotiate itself");

    if (verify_p) {
	gss_name_t name = GSS_C_NO_NAME;

	/*
	 * If we do not have a credential, acquire a default name as a hint
	 * to acceptor_approved() so it can attempt to acquire a default
	 * credential.
	 */
	if (cred == GSS_C_NO_CREDENTIAL) {
	    ret = default_acceptor_name(minor_status, &name);
	    if (ret != GSS_S_COMPLETE)
		return ret;
	}

	ret = acceptor_approved(minor_status, ctx, name, cred, selected_mech);

	gss_release_name(&junk, &name);
    } else {
        /* Stash optimistic mech for use by _gss_spnego_require_mechlist_mic() */
	ret = gss_duplicate_oid(minor_status, &oid, &ctx->preferred_mech_type);
    }

    if (ret == GSS_S_COMPLETE) {
	*minor_status = 0;

	*advertised_mech_p = ctx->selected_mech_type = selected_mech;

	/* if the initiator used the broken MS OID, send that instead */
	if (includeMSCompatOID && gss_oid_equal(selected_mech, GSS_KRB5_MECHANISM))
	    *advertised_mech_p = &_gss_spnego_mskrb_mechanism_oid_desc;
    }

    return ret;
}


static OM_uint32
acceptor_complete(OM_uint32 * minor_status,
		  gssspnego_ctx ctx,
		  int *get_mic,
		  gss_buffer_t mech_input_token,
		  gss_buffer_t mech_output_token,
		  heim_octet_string *mic,
		  gss_buffer_t output_token)
{
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    OM_uint32 ret;
    int verify_mic;

    ctx->flags.require_mic = 1;
    ctx->flags.safe_omit = _gss_spnego_safe_omit_mechlist_mic(ctx);

    if (ctx->flags.open) {
	if (mech_input_token == GSS_C_NO_BUFFER) { /* Even/One */
	    verify_mic = 1;
	    *get_mic = 0;
	} else if (mech_output_token != GSS_C_NO_BUFFER &&
		   mech_output_token->length == 0) { /* Odd */
	    *get_mic = verify_mic = 1;
	} else { /* Even/One */
	    verify_mic = 0;
	    *get_mic = 1;
	}

	/*
	 * Change from previous versions: do not generate a MIC if not
	 * necessary. This conforms to RFC4178 s.5 ("if the accepted
	 * mechanism is the most preferred mechanism of both the initiator
	 * and acceptor, then the MIC token exchange... is OPTIONAL"),
	 * and is consistent with MIT and Windows behavior.
	 */
	if (ctx->flags.safe_omit)
	    *get_mic = 0;

	if (verify_mic && mic == NULL && ctx->flags.safe_omit) {
	    /*
	     * Peer is old and didn't send a mic while we expected
	     * one, but since it safe to omit, let do that
	     */
	} else if (verify_mic) {
	    ret = _gss_spnego_verify_mechtypes_mic(minor_status, ctx, mic);
	    if (ret) {
		if (*get_mic)
		    send_reject(minor_status, GSS_C_NO_BUFFER, output_token);
		if (buf.value)
		    free(buf.value);
		return ret;
	    }
	}
    } else
	*get_mic = 0;

    return GSS_S_COMPLETE;
}

/*
 * Call gss_accept_sec_context() via mechglue or NegoEx, depending on
 * whether mech_oid is NegoEx.
 */

static OM_uint32
mech_accept(OM_uint32 *minor_status,
	    gssspnego_ctx ctx,
	    gss_const_cred_id_t acceptor_cred_handle,
	    gss_const_buffer_t input_token_buffer,
	    const gss_channel_bindings_t input_chan_bindings,
	    gss_buffer_t output_token,
	    gss_cred_id_t *delegated_cred_handle)
{
    OM_uint32 ret, junk;

    heim_assert(ctx->selected_mech_type != GSS_C_NO_OID,
		"mech_accept called with no selected mech");

    if (gss_oid_equal(ctx->selected_mech_type, GSS_NEGOEX_MECHANISM)) {
	ret = _gss_negoex_accept(minor_status,
				 ctx,
				 (gss_cred_id_t)acceptor_cred_handle,
				 input_token_buffer,
				 input_chan_bindings,
				 output_token,
				 delegated_cred_handle);
    } else {
	if (ctx->mech_src_name != GSS_C_NO_NAME)
	    gss_release_name(&junk, &ctx->mech_src_name);

	ret = gss_accept_sec_context(minor_status,
				     &ctx->negotiated_ctx_id,
				     acceptor_cred_handle,
				     (gss_buffer_t)input_token_buffer,
				     input_chan_bindings,
				     &ctx->mech_src_name,
				     &ctx->negotiated_mech_type,
				     output_token,
				     &ctx->mech_flags,
				     &ctx->mech_time_rec,
				     delegated_cred_handle);
	if (GSS_ERROR(ret))
	    gss_mg_collect_error(ctx->negotiated_mech_type, ret, *minor_status);
	else if (ctx->negotiated_mech_type != GSS_C_NO_OID &&
	    !gss_oid_equal(ctx->negotiated_mech_type, ctx->selected_mech_type))
	    _gss_mg_log(1, "spnego client didn't send the mech they said they would");
    }

    return ret;
}

static OM_uint32 GSSAPI_CALLCONV
acceptor_start
	   (OM_uint32 * minor_status,
	    gss_ctx_id_t * context_handle,
	    gss_const_cred_id_t acceptor_cred_handle,
	    const gss_buffer_t input_token_buffer,
	    const gss_channel_bindings_t input_chan_bindings,
	    gss_name_t * src_name,
	    gss_OID * mech_type,
	    gss_buffer_t output_token,
	    OM_uint32 * ret_flags,
	    OM_uint32 * time_rec,
	    gss_cred_id_t *delegated_cred_handle
	   )
{
    OM_uint32 ret, junk;
    NegotiationToken nt;
    gss_OID_set supported_mechs = GSS_C_NO_OID_SET;
    size_t size;
    NegTokenInit *ni;
    gss_buffer_desc data;
    gss_buffer_t mech_input_token = GSS_C_NO_BUFFER;
    gss_buffer_desc mech_output_token;
    gssspnego_ctx ctx;
    int get_mic = 0, first_ok = 0, canonical_order;
    gss_const_OID advertised_mech = GSS_C_NO_OID;

    memset(&nt, 0, sizeof(nt));

    mech_output_token.value = NULL;
    mech_output_token.length = 0;

    if (input_token_buffer->length == 0)
	return send_supported_mechs (minor_status, NULL,
				     acceptor_cred_handle, output_token);

    ret = _gss_spnego_alloc_sec_context(minor_status, context_handle);
    if (ret != GSS_S_COMPLETE)
	return ret;

    ctx = (gssspnego_ctx)*context_handle;

    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);

    /*
     * The GSS-API encapsulation is only present on the initial
     * context token (negTokenInit).
     */
    ret = gss_decapsulate_token (input_token_buffer,
				 GSS_SPNEGO_MECHANISM,
				 &data);
    if (ret)
	goto out;

    ret = decode_NegotiationToken(data.value, data.length, &nt, &size);
    gss_release_buffer(minor_status, &data);
    if (ret) {
	*minor_status = ret;
	ret = GSS_S_DEFECTIVE_TOKEN;
	goto out;
    }
    if (nt.element != choice_NegotiationToken_negTokenInit) {
	*minor_status = 0;
	ret = GSS_S_DEFECTIVE_TOKEN;
	goto out;
    }
    ni = &nt.u.negTokenInit;

    if (ni->mechTypes.len < 1) {
	free_NegotiationToken(&nt);
	*minor_status = 0;
	ret = GSS_S_DEFECTIVE_TOKEN;
	goto out;
    }

    _gss_spnego_log_mechTypes(&ni->mechTypes);

    {
	MechTypeList mt;
	int kret;

	mt.len = ni->mechTypes.len;
	mt.val = ni->mechTypes.val;

	ASN1_MALLOC_ENCODE(MechTypeList,
			   ctx->NegTokenInit_mech_types.value,
			   ctx->NegTokenInit_mech_types.length,
			   &mt, &size, kret);
	if (kret) {
	    *minor_status = kret;
	    ret = GSS_S_FAILURE;
	    goto out;
	}
    }

    if (acceptor_cred_handle != GSS_C_NO_CREDENTIAL)
	ret = _gss_spnego_inquire_cred_mechs(minor_status,
					     acceptor_cred_handle,
					     &supported_mechs,
					     &canonical_order);
    else
	ret = _gss_spnego_indicate_mechs(minor_status, &supported_mechs);
    if (ret != GSS_S_COMPLETE)
	goto out;

    /*
     * First we try the opportunistic token if we have support for it,
     * don't try to verify we have credential for the token,
     * gss_accept_sec_context() will (hopefully) tell us that.
     * If that failes,
     */

    ret = select_mech(minor_status,
		      ctx,
		      acceptor_cred_handle,
		      supported_mechs,
		      &ni->mechTypes.val[0],
		      0, /* optimistic token */
		      &advertised_mech);

    if (ret == GSS_S_COMPLETE && ni->mechToken != NULL) {
	gss_buffer_desc ibuf;

	ibuf.length = ni->mechToken->length;
	ibuf.value = ni->mechToken->data;
	mech_input_token = &ibuf;

	_gss_spnego_log_mech("acceptor selected opportunistic mech", ctx->selected_mech_type);

	ret = mech_accept(&junk,
			  ctx,
			  acceptor_cred_handle,
			  mech_input_token,
			  input_chan_bindings,
			  &mech_output_token,
			  delegated_cred_handle);
	if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
	    first_ok = 1;
	} else {
	    ctx->selected_mech_type = GSS_C_NO_OID;
	}

	if (ret == GSS_S_COMPLETE) {
	    ret = acceptor_complete(minor_status,
				    ctx,
				    &get_mic,
				    mech_input_token,
				    &mech_output_token,
				    ni->mechListMIC,
				    output_token);
	    if (ret != GSS_S_COMPLETE)
		goto out;

	    ctx->flags.open = 1;
	}
    } else {
	*minor_status = 0;
	gss_release_oid_set(&junk, &supported_mechs);
	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
	return gss_mg_set_error_string(GSS_C_NO_OID, GSS_S_NO_CONTEXT,
				       *minor_status,
				       "SPNEGO acceptor didn't find a prefered mechanism");
    }

    /*
     * If opportunistic token failed, lets try the other mechs.
     */

    if (!first_ok) {
	size_t j;

	/* Call glue layer to find first mech we support */
	for (j = 1; j < ni->mechTypes.len; ++j) {
	    ret = select_mech(&junk,
			      ctx,
			      acceptor_cred_handle,
			      supported_mechs,
			      &ni->mechTypes.val[j],
			      1, /* not optimistic token */
			      &advertised_mech);
	    if (ret == GSS_S_COMPLETE) {
		_gss_spnego_log_mech("acceptor selected non-opportunistic mech",
                                     ctx->selected_mech_type);
		break;
	    }
	}
    }
    if (ctx->selected_mech_type == GSS_C_NO_OID) {
        heim_assert(ret != GSS_S_COMPLETE, "no oid and no error code?");
        *minor_status = junk;
        goto out;
    }

    /* The initial token always has a response */
    ret = send_accept(minor_status,
		      ctx,
		      first_ok,
		      &mech_output_token,
		      advertised_mech,
		      get_mic ? &ctx->NegTokenInit_mech_types : NULL,
		      output_token);
    if (ret)
	goto out;

out:
    gss_release_oid_set(&junk, &supported_mechs);
    if (mech_output_token.value != NULL)
	gss_release_buffer(&junk, &mech_output_token);
    free_NegotiationToken(&nt);


    if (ret == GSS_S_COMPLETE) {
	if (src_name != NULL && ctx->mech_src_name != GSS_C_NO_NAME)
	    ret = gss_duplicate_name(minor_status,
				     ctx->mech_src_name,
				     src_name);
    }

    if (mech_type != NULL)
	*mech_type = ctx->negotiated_mech_type;
    if (ret_flags != NULL)
	*ret_flags = ctx->mech_flags;
    if (time_rec != NULL)
	*time_rec = ctx->mech_time_rec;

    if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
 	return ret;
    }

    _gss_spnego_internal_delete_sec_context(&junk, context_handle,
					    GSS_C_NO_BUFFER);

    return ret;
}


static OM_uint32 GSSAPI_CALLCONV
acceptor_continue
	   (OM_uint32 * minor_status,
	    gss_ctx_id_t * context_handle,
	    gss_const_cred_id_t acceptor_cred_handle,
	    const gss_buffer_t input_token_buffer,
	    const gss_channel_bindings_t input_chan_bindings,
	    gss_name_t * src_name,
	    gss_OID * mech_type,
	    gss_buffer_t output_token,
	    OM_uint32 * ret_flags,
	    OM_uint32 * time_rec,
	    gss_cred_id_t *delegated_cred_handle
	   )
{
    OM_uint32 ret, ret2, minor, junk;
    NegotiationToken nt;
    size_t nt_len;
    NegTokenResp *na;
    unsigned int negState = accept_incomplete;
    gss_buffer_t mech_input_token = GSS_C_NO_BUFFER;
    gss_buffer_t mech_output_token = GSS_C_NO_BUFFER;
    gssspnego_ctx ctx;

    ctx = (gssspnego_ctx)*context_handle;

    /*
     * The GSS-API encapsulation is only present on the initial
     * context token (negTokenInit).
     */

    ret = decode_NegotiationToken(input_token_buffer->value,
				  input_token_buffer->length,
				  &nt, &nt_len);
    if (ret) {
	*minor_status = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }
    if (nt.element != choice_NegotiationToken_negTokenResp) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }
    na = &nt.u.negTokenResp;

    if (na->negState != NULL) {
	negState = *(na->negState);
    }

    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);

    {
	gss_buffer_desc ibuf, obuf;
	int get_mic = 0;
	int require_response;

	if (na->responseToken != NULL) {
	    ibuf.length = na->responseToken->length;
	    ibuf.value = na->responseToken->data;
	    mech_input_token = &ibuf;
	} else {
	    ibuf.value = NULL;
	    ibuf.length = 0;
	}

	if (mech_input_token != GSS_C_NO_BUFFER) {

	    ret = mech_accept(minor_status,
			      ctx,
			      acceptor_cred_handle,
			      mech_input_token,
			      input_chan_bindings,
			      &obuf,
			      delegated_cred_handle);
	    mech_output_token = &obuf;
	    if (ret != GSS_S_COMPLETE && ret != GSS_S_CONTINUE_NEEDED) {
		free_NegotiationToken(&nt);
		send_reject(&junk, mech_output_token, output_token);
		gss_release_buffer(&junk, mech_output_token);
		HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
		return ret;
	    }
	    if (ret == GSS_S_COMPLETE)
		ctx->flags.open = 1;
	} else
	    ret = GSS_S_COMPLETE;

	if (ret == GSS_S_COMPLETE)
	    ret = acceptor_complete(minor_status,
				    ctx,
				    &get_mic,
				    mech_input_token,
				    mech_output_token,
				    na->mechListMIC,
				    output_token);

	if (ctx->mech_flags & GSS_C_DCE_STYLE)
	    require_response = (negState != accept_completed);
	else
	    require_response = 0;

	/*
	 * Check whether we need to send a result: there should be only
	 * one accept_completed response sent in the entire negotiation
	 */
	if ((mech_output_token != GSS_C_NO_BUFFER &&
	     mech_output_token->length != 0)
	    || (ctx->flags.open && negState == accept_incomplete)
	    || require_response
	    || get_mic) {
	    ret2 = send_accept (minor_status,
				ctx,
				0, /* ignored on subsequent tokens */
				mech_output_token,
				GSS_C_NO_OID,
				get_mic ? &ctx->NegTokenInit_mech_types : NULL,
				output_token);
	    if (ret2)
		goto out;
	} else
	    ret2 = GSS_S_COMPLETE;

     out:
	if (ret2 != GSS_S_COMPLETE)
	    ret = ret2;
	if (mech_output_token != NULL)
	    gss_release_buffer(&minor, mech_output_token);
	free_NegotiationToken(&nt);
    }

    if (ret == GSS_S_COMPLETE) {
	if (src_name != NULL && ctx->mech_src_name != GSS_C_NO_NAME)
	    ret = gss_duplicate_name(minor_status,
				     ctx->mech_src_name,
				     src_name);
    }

    if (mech_type != NULL)
	*mech_type = ctx->negotiated_mech_type;
    if (ret_flags != NULL)
	*ret_flags = ctx->mech_flags;
    if (time_rec != NULL)
	*time_rec = ctx->mech_time_rec;

    if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
 	return ret;
    }

    _gss_spnego_internal_delete_sec_context(&minor, context_handle,
				   GSS_C_NO_BUFFER);

    return ret;
}

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_accept_sec_context
	   (OM_uint32 * minor_status,
	    gss_ctx_id_t * context_handle,
	    gss_const_cred_id_t acceptor_cred_handle,
	    const gss_buffer_t input_token_buffer,
	    const gss_channel_bindings_t input_chan_bindings,
	    gss_name_t * src_name,
	    gss_OID * mech_type,
	    gss_buffer_t output_token,
	    OM_uint32 * ret_flags,
	    OM_uint32 * time_rec,
	    gss_cred_id_t *delegated_cred_handle
	   )
{
    _gss_accept_sec_context_t *func;

    *minor_status = 0;

    output_token->length = 0;
    output_token->value  = NULL;

    if (src_name != NULL)
	*src_name = GSS_C_NO_NAME;
    if (mech_type != NULL)
	*mech_type = GSS_C_NO_OID;
    if (ret_flags != NULL)
	*ret_flags = 0;
    if (time_rec != NULL)
	*time_rec = 0;
    if (delegated_cred_handle != NULL)
	*delegated_cred_handle = GSS_C_NO_CREDENTIAL;


    if (*context_handle == GSS_C_NO_CONTEXT)
	func = acceptor_start;
    else
	func = acceptor_continue;


    return (*func)(minor_status, context_handle, acceptor_cred_handle,
		   input_token_buffer, input_chan_bindings,
		   src_name, mech_type, output_token, ret_flags,
		   time_rec, delegated_cred_handle);
}
