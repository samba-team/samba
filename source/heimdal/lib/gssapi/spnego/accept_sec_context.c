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

#include "spnego/spnego_locl.h"

RCSID("$Id: accept_sec_context.c,v 1.6 2006/10/07 22:26:57 lha Exp $");

OM_uint32
_gss_spnego_encode_response(OM_uint32 *minor_status,
			    const NegTokenResp *resp,
			    gss_buffer_t data,
			    u_char **ret_buf)
{
    OM_uint32 ret;
    u_char *buf;
    size_t buf_size, buf_len;

    buf_size = 1024;
    buf = malloc(buf_size);
    if (buf == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    do {
	ret = encode_NegTokenResp(buf + buf_size - 1,
				  buf_size,
				  resp, &buf_len);
	if (ret == 0) {
	    size_t tmp;

	    ret = der_put_length_and_tag(buf + buf_size - buf_len - 1,
					 buf_size - buf_len,
					 buf_len,
					 ASN1_C_CONTEXT,
					 CONS,
					 1,
					 &tmp);
	    if (ret == 0)
		buf_len += tmp;
	}
	if (ret) {
	    if (ret == ASN1_OVERFLOW) {
		u_char *tmp;

		buf_size *= 2;
		tmp = realloc (buf, buf_size);
		if (tmp == NULL) {
		    *minor_status = ENOMEM;
		    free(buf);
		    return GSS_S_FAILURE;
		}
		buf = tmp;
	    } else {
		*minor_status = ret;
		free(buf);
		return GSS_S_FAILURE;
	    }
	}
    } while (ret == ASN1_OVERFLOW);

    data->value  = buf + buf_size - buf_len;
    data->length = buf_len;
    *ret_buf     = buf;

    return GSS_S_COMPLETE;
}

static OM_uint32
send_reject (OM_uint32 *minor_status,
	     gss_buffer_t output_token)
{
    NegTokenResp resp;
    gss_buffer_desc data;
    u_char *buf;
    OM_uint32 ret;

    ALLOC(resp.negResult, 1);
    if (resp.negResult == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    *(resp.negResult)  = reject;
    resp.supportedMech = NULL;
    resp.responseToken = NULL;
    resp.mechListMIC   = NULL;
    
    ret = _gss_spnego_encode_response (minor_status, &resp, &data, &buf);
    free_NegTokenResp(&resp);
    if (ret != GSS_S_COMPLETE)
	return ret;

    output_token->value = malloc(data.length);
    if (output_token->value == NULL) {
	*minor_status = ENOMEM;
	ret = GSS_S_FAILURE;
    } else {
	output_token->length = data.length;
	memcpy(output_token->value, data.value, output_token->length);
    }
    free(buf);
    if (ret != GSS_S_COMPLETE)
	return ret;
    return GSS_S_BAD_MECH;
}

OM_uint32
_gss_spnego_indicate_mechtypelist (OM_uint32 *minor_status,
				   int includeMSCompatOID,
				   const gssspnego_cred cred_handle,
				   MechTypeList *mechtypelist,
				   gss_OID *preferred_mech)
{
    OM_uint32 ret;
    gss_OID_set supported_mechs = GSS_C_NO_OID_SET;
    int i, count;

    if (cred_handle != NULL) {
	ret = gss_inquire_cred(minor_status,
			       cred_handle->negotiated_cred_id,
			       NULL,
			       NULL,
			       NULL,
			       &supported_mechs);
    } else {
	ret = gss_indicate_mechs(minor_status, &supported_mechs);
    }

    if (ret != GSS_S_COMPLETE) {
	return ret;
    }

    if (supported_mechs->count == 0) {
	*minor_status = ENOENT;
	gss_release_oid_set(minor_status, &supported_mechs);
	return GSS_S_FAILURE;
    }

    count = supported_mechs->count;
    if (includeMSCompatOID)
	count++;

    mechtypelist->len = 0;
    mechtypelist->val = calloc(count, sizeof(MechType));
    if (mechtypelist->val == NULL) {
	*minor_status = ENOMEM;
	gss_release_oid_set(minor_status, &supported_mechs);
	return GSS_S_FAILURE;
    }

    for (i = 0; i < supported_mechs->count; i++) {
	ret = _gss_spnego_add_mech_type(&supported_mechs->elements[i],
					includeMSCompatOID,
					mechtypelist);
	if (ret != 0) {
	    *minor_status = ENOMEM;
	    ret = GSS_S_FAILURE;
	    break;
	}
    }

    if (ret == GSS_S_COMPLETE && preferred_mech != NULL) {
	ret = gss_duplicate_oid(minor_status,
				&supported_mechs->elements[0],
				preferred_mech);
    }

    if (ret != GSS_S_COMPLETE) {
	free_MechTypeList(mechtypelist);
	mechtypelist->len = 0;
	mechtypelist->val = NULL;
    }
    gss_release_oid_set(minor_status, &supported_mechs);

    return ret;
}

static OM_uint32
send_supported_mechs (OM_uint32 *minor_status,
		      gss_buffer_t output_token)
{
    NegTokenInit ni;
    char hostname[MAXHOSTNAMELEN], *p;
    gss_buffer_desc name_buf;
    gss_OID name_type;
    gss_name_t target_princ;
    gss_name_t canon_princ;
    OM_uint32 ret, minor;
    u_char *buf;
    size_t buf_size, buf_len;
    gss_buffer_desc data;

    memset(&ni, 0, sizeof(ni));

    ni.reqFlags = NULL;
    ni.mechToken = NULL;
    ni.negHints = NULL;
    ni.mechListMIC = NULL;

    ret = _gss_spnego_indicate_mechtypelist(minor_status, 1,
					    NULL,
					    &ni.mechTypes, NULL);
    if (ret != GSS_S_COMPLETE) {
	return ret;
    }

    memset(&target_princ, 0, sizeof(target_princ));
    if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
	*minor_status = errno;
	free_NegTokenInit(&ni);
	return GSS_S_FAILURE;
    }

    /* Send the constructed SAM name for this host */
    for (p = hostname; *p != '\0' && *p != '.'; p++) {
	*p = toupper((unsigned char)*p);
    }
    *p++ = '$';
    *p = '\0';

    name_buf.length = strlen(hostname);
    name_buf.value = hostname;

    ret = gss_import_name(minor_status, &name_buf,
			  GSS_C_NO_OID,
			  &target_princ);
    if (ret != GSS_S_COMPLETE) {
	return ret;
    }

    name_buf.length = 0;
    name_buf.value = NULL;

    /* Canonicalize the name using the preferred mechanism */
    ret = gss_canonicalize_name(minor_status,
				target_princ,
				GSS_C_NO_OID,
				&canon_princ);
    if (ret != GSS_S_COMPLETE) {
	gss_release_name(&minor, &target_princ);
	return ret;
    }

    ret = gss_display_name(minor_status, canon_princ,
			   &name_buf, &name_type);
    if (ret != GSS_S_COMPLETE) {
	gss_release_name(&minor, &canon_princ);
	gss_release_name(&minor, &target_princ);
	return ret;
    }

    gss_release_name(&minor, &canon_princ);
    gss_release_name(&minor, &target_princ);

    ALLOC(ni.negHints, 1);
    if (ni.negHints == NULL) {
	*minor_status = ENOMEM;
	gss_release_buffer(&minor, &name_buf);
	free_NegTokenInit(&ni);
	return GSS_S_FAILURE;
    }

    ALLOC(ni.negHints->hintName, 1);
    if (ni.negHints->hintName == NULL) {
	*minor_status = ENOMEM;
	gss_release_buffer(&minor, &name_buf);
	free_NegTokenInit(&ni);
	return GSS_S_FAILURE;
    }

    *(ni.negHints->hintName) = name_buf.value;
    name_buf.value = NULL;
    ni.negHints->hintAddress = NULL;

    buf_size = 1024;
    buf = malloc(buf_size);
    if (buf == NULL) {
	free_NegTokenInit(&ni);
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    do {
	ret = encode_NegTokenInit(buf + buf_size - 1,
				  buf_size,
				  &ni, &buf_len);
	if (ret == 0) {
	    size_t tmp;

	    ret = der_put_length_and_tag(buf + buf_size - buf_len - 1,
					 buf_size - buf_len,
					 buf_len,
					 ASN1_C_CONTEXT,
					 CONS,
					 0,
					 &tmp);
	    if (ret == 0)
		buf_len += tmp;
	}
	if (ret) {
	    if (ret == ASN1_OVERFLOW) {
		u_char *tmp;

		buf_size *= 2;
		tmp = realloc (buf, buf_size);
		if (tmp == NULL) {
		    *minor_status = ENOMEM;
		    free(buf);
		    free_NegTokenInit(&ni);
		    return GSS_S_FAILURE;
		}
		buf = tmp;
	    } else {
		*minor_status = ret;
		free(buf);
		free_NegTokenInit(&ni);
		return GSS_S_FAILURE;
	    }
	}
    } while (ret == ASN1_OVERFLOW);

    data.value  = buf + buf_size - buf_len;
    data.length = buf_len;

    ret = gss_encapsulate_token(&data,
				GSS_SPNEGO_MECHANISM,
				output_token);
    free (buf);
    free_NegTokenInit (&ni);

    if (ret != GSS_S_COMPLETE)
	return ret;

    *minor_status = 0;

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
send_accept (OM_uint32 *minor_status,
	     gssspnego_ctx context_handle,
	     gss_buffer_t mech_token,
	     int initial_response,
	     gss_buffer_t mech_buf,
	     gss_buffer_t output_token)
{
    NegTokenResp resp;
    gss_buffer_desc data;
    u_char *buf;
    OM_uint32 ret;
    gss_buffer_desc mech_mic_buf;

    memset(&resp, 0, sizeof(resp));

    ALLOC(resp.negResult, 1);
    if (resp.negResult == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    if (context_handle->open) {
	if (mech_token != GSS_C_NO_BUFFER
	    && mech_token->length != 0
	    && mech_buf != GSS_C_NO_BUFFER)
	    *(resp.negResult) = accept_incomplete;
	else
	    *(resp.negResult) = accept_completed;
    } else {
	if (initial_response && context_handle->require_mic)
	    *(resp.negResult) = request_mic;
	else
	    *(resp.negResult) = accept_incomplete;
    }

    if (initial_response) {
	ALLOC(resp.supportedMech, 1);
	if (resp.supportedMech == NULL) {
	    free_NegTokenResp(&resp);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}

	ret = der_get_oid(context_handle->preferred_mech_type->elements,
			  context_handle->preferred_mech_type->length,
			  resp.supportedMech,
			  NULL);
	if (ret) {
	    free_NegTokenResp(&resp);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
    } else {
	resp.supportedMech = NULL;
    }

    if (mech_token != GSS_C_NO_BUFFER && mech_token->length != 0) {
	ALLOC(resp.responseToken, 1);
	if (resp.responseToken == NULL) {
	    free_NegTokenResp(&resp);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	resp.responseToken->length = mech_token->length;
	resp.responseToken->data   = mech_token->value;
	mech_token->length = 0;
	mech_token->value  = NULL;
    } else {
	resp.responseToken = NULL;
    }

    if (mech_buf != GSS_C_NO_BUFFER) {
	ALLOC(resp.mechListMIC, 1);
	if (resp.mechListMIC == NULL) {
	    free_NegTokenResp(&resp);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}

	ret = gss_get_mic(minor_status,
			  context_handle->negotiated_ctx_id,
			  0,
			  mech_buf,
			  &mech_mic_buf);
	if (ret != GSS_S_COMPLETE) {
	    free_NegTokenResp(&resp);
	    return ret;
	}

	resp.mechListMIC->length = mech_mic_buf.length;
	resp.mechListMIC->data   = mech_mic_buf.value;
    } else
	resp.mechListMIC = NULL;
 
    ret = _gss_spnego_encode_response (minor_status, &resp, &data, &buf);
    if (ret != GSS_S_COMPLETE) {
	free_NegTokenResp(&resp);
	return ret;
    }

    /*
     * The response should not be encapsulated, because
     * it is a SubsequentContextToken (note though RFC 1964
     * specifies encapsulation for all _Kerberos_ tokens).
     */
    output_token->value = malloc(data.length);
    if (output_token->value == NULL) {
	*minor_status = ENOMEM;
	ret = GSS_S_FAILURE;
    } else {
	output_token->length = data.length;
	memcpy(output_token->value, data.value, output_token->length);
    }
    free(buf);
    if (ret != GSS_S_COMPLETE) {
	free_NegTokenResp(&resp);
	return ret;
    }

    ret = (*(resp.negResult) == accept_completed) ? GSS_S_COMPLETE :
						    GSS_S_CONTINUE_NEEDED;
    free_NegTokenResp(&resp);
    return ret;
}


static OM_uint32
verify_mechlist_mic
	   (OM_uint32 *minor_status,
	    gssspnego_ctx context_handle,
	    gss_buffer_t mech_buf,
	    heim_octet_string *mechListMIC
	   )
{
    OM_uint32 ret;
    gss_buffer_desc mic_buf;

    if (context_handle->verified_mic) {
	/* This doesn't make sense, we've already verified it? */
	*minor_status = 0;
	return GSS_S_DUPLICATE_TOKEN;
    }

    if (mechListMIC == NULL) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    mic_buf.length = mechListMIC->length;
    mic_buf.value  = mechListMIC->data;

    ret = gss_verify_mic(minor_status,
			 context_handle->negotiated_ctx_id,
			 mech_buf,
			 &mic_buf,
			 NULL);

    if (ret != GSS_S_COMPLETE)
	ret = GSS_S_DEFECTIVE_TOKEN;

    return ret;
}

OM_uint32
_gss_spnego_accept_sec_context
	   (OM_uint32 * minor_status,
	    gss_ctx_id_t * context_handle,
	    const gss_cred_id_t acceptor_cred_handle,
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
    OM_uint32 ret, ret2, minor;
    NegTokenInit ni;
    NegTokenResp na;
    size_t ni_len, na_len;
    int i;
    gss_buffer_desc data;
    size_t len, taglen;
    int initialToken;
    unsigned int negResult = accept_incomplete;
    gss_buffer_t mech_input_token = GSS_C_NO_BUFFER;
    gss_buffer_t mech_output_token = GSS_C_NO_BUFFER;
    gss_buffer_desc mech_buf;
    gss_OID preferred_mech_type = GSS_C_NO_OID;
    gssspnego_ctx ctx;
    gssspnego_cred acceptor_cred = (gssspnego_cred)acceptor_cred_handle;

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

    mech_buf.value = NULL;

    if (*context_handle == GSS_C_NO_CONTEXT) {
	ret = _gss_spnego_alloc_sec_context(minor_status,
					    context_handle);
	if (ret != GSS_S_COMPLETE)
	    return ret;

	if (input_token_buffer->length == 0) {
	    return send_supported_mechs (minor_status,
					 output_token);
	}
    }

    ctx = (gssspnego_ctx)*context_handle;

    /*
     * The GSS-API encapsulation is only present on the initial
     * context token (negTokenInit).
     */
    ret = gss_decapsulate_token (input_token_buffer,
				 GSS_SPNEGO_MECHANISM,
				 &data);
    initialToken = (ret == GSS_S_COMPLETE);

    if (!initialToken) {
	data.value  = input_token_buffer->value;
	data.length = input_token_buffer->length;
    }

    ret = der_match_tag_and_length(data.value, data.length,
				   ASN1_C_CONTEXT, CONS,
				   initialToken ? 0 : 1,
				   &len, &taglen);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    if (len > data.length - taglen) {
	*minor_status = ASN1_OVERRUN;
	return GSS_S_FAILURE;
    }

    if (initialToken) {
	ret = decode_NegTokenInit((const unsigned char *)data.value + taglen, 
				  len, &ni, &ni_len);
    } else {
	ret = decode_NegTokenResp((const unsigned char *)data.value + taglen, 
				  len, &na, &na_len);
    }
    if (ret) {
	*minor_status = ret;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (!initialToken && na.negResult != NULL) {
	negResult = *(na.negResult);
    }

    if (negResult == reject || negResult == request_mic) {
	/* request_mic should only be sent by acceptor */
	free_NegTokenResp(&na);
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (initialToken) {
	for (i = 0; i < ni.mechTypes.len; ++i) {
	    /* Call glue layer to find first mech we support */
	    ret = _gss_spnego_select_mech(minor_status, &ni.mechTypes.val[i],
					  &preferred_mech_type);
	    if (ret == 0)
		break;
	}
	if (preferred_mech_type == GSS_C_NO_OID) {
	    free_NegTokenInit(&ni);
	    return GSS_S_BAD_MECH;
	}
    }

    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);

    if (initialToken) {
	ctx->preferred_mech_type = preferred_mech_type;
	ctx->initiator_mech_types.len = ni.mechTypes.len;
	ctx->initiator_mech_types.val = ni.mechTypes.val;
	ni.mechTypes.len = 0;
	ni.mechTypes.val = NULL;
    }

    {
	gss_buffer_desc ibuf, obuf;
	int require_mic, verify_mic, get_mic;
	int require_response;
	heim_octet_string *mic;

	if (initialToken) {
	    if (ni.mechToken != NULL) {
		ibuf.length = ni.mechToken->length;
		ibuf.value = ni.mechToken->data;
		mech_input_token = &ibuf;
	    }
	} else {
	    if (na.responseToken != NULL) {
		ibuf.length = na.responseToken->length;
		ibuf.value = na.responseToken->data;
		mech_input_token = &ibuf;
	    }
	}

	if (mech_input_token != GSS_C_NO_BUFFER) {
	    gss_cred_id_t mech_cred;
	    gss_cred_id_t mech_delegated_cred;
	    gss_cred_id_t *mech_delegated_cred_p;

	    if (acceptor_cred != NULL)
		mech_cred = acceptor_cred->negotiated_cred_id;
	    else
		mech_cred = GSS_C_NO_CREDENTIAL;

	    if (delegated_cred_handle != NULL) {
		mech_delegated_cred = GSS_C_NO_CREDENTIAL;
		mech_delegated_cred_p = &mech_delegated_cred;
	    } else {
		mech_delegated_cred_p = NULL;
	    }

	    if (ctx->mech_src_name != GSS_C_NO_NAME)
		gss_release_name(&minor, &ctx->mech_src_name);

	    if (ctx->delegated_cred_id != GSS_C_NO_CREDENTIAL)
		_gss_spnego_release_cred(&minor, &ctx->delegated_cred_id);

	    ret = gss_accept_sec_context(&minor,
					 &ctx->negotiated_ctx_id,
					 mech_cred,
					 mech_input_token,
					 input_chan_bindings,
					 &ctx->mech_src_name,
					 &ctx->negotiated_mech_type,
					 &obuf,
					 &ctx->mech_flags,
					 &ctx->mech_time_rec,
					 mech_delegated_cred_p);
	    if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
		if (mech_delegated_cred_p != NULL &&
		    mech_delegated_cred != GSS_C_NO_CREDENTIAL) {
		    ret2 = _gss_spnego_alloc_cred(minor_status,
						  mech_delegated_cred,
						  &ctx->delegated_cred_id);
		    if (ret2 != GSS_S_COMPLETE)
			ret = ret2;
		}
		mech_output_token = &obuf;
	    }
	    if (ret != GSS_S_COMPLETE && ret != GSS_S_CONTINUE_NEEDED) {
		if (initialToken)
		    free_NegTokenInit(&ni);
		else
		    free_NegTokenResp(&na);
		send_reject (minor_status, output_token);
		HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
		return ret;
	    }
	    if (ret == GSS_S_COMPLETE)
		ctx->open = 1;
	} else
	    ret = GSS_S_COMPLETE;

	ret2 = _gss_spnego_require_mechlist_mic(minor_status, 
						ctx,
						&require_mic);
	if (ret2)
	    goto out;

	ctx->require_mic = require_mic;

	mic = initialToken ? ni.mechListMIC : na.mechListMIC;
	if (mic != NULL)
	    require_mic = 1;

	if (ctx->open && require_mic) {
	    if (mech_input_token == GSS_C_NO_BUFFER) { /* Even/One */
		verify_mic = 1;
		get_mic = 0;
	    } else if (mech_output_token != GSS_C_NO_BUFFER &&
		       mech_output_token->length == 0) { /* Odd */
		get_mic = verify_mic = 1;
	    } else { /* Even/One */
		verify_mic = 0;
		get_mic = 1;
	    }

	    if (verify_mic || get_mic) {
		int eret;
		size_t buf_len;

    		ASN1_MALLOC_ENCODE(MechTypeList, 
				   mech_buf.value, mech_buf.length,
				   &ctx->initiator_mech_types, &buf_len, eret);
		if (eret) {
		    ret2 = GSS_S_FAILURE;
		    *minor_status = eret;
		    goto out;
		}
		if (mech_buf.length != buf_len)
		    abort();
	    }

	    if (verify_mic) {
		ret2 = verify_mechlist_mic(minor_status, ctx, &mech_buf, mic);
		if (ret2) {
		    if (get_mic)
			send_reject (minor_status, output_token);
		    goto out;
		}

		ctx->verified_mic = 1;
	    }
	} else
	    verify_mic = get_mic = 0;

	if (ctx->mech_flags & GSS_C_DCE_STYLE)
	    require_response = (negResult != accept_completed);
	else
	    require_response = 0;

	/*
	 * Check whether we need to send a result: there should be only
	 * one accept_completed response sent in the entire negotiation
	 */
	if ((mech_output_token != GSS_C_NO_BUFFER &&
	     mech_output_token->length != 0)
	    || require_response
	    || get_mic) {
	    ret2 = send_accept (minor_status,
				ctx,
				mech_output_token,
				initialToken,
				get_mic ? &mech_buf : NULL,
				output_token);
	    if (ret2)
		goto out;
	}

     out:
	if (ret2 != GSS_S_COMPLETE)
	    ret = ret2;
	if (mech_output_token != NULL)
	    gss_release_buffer(&minor, mech_output_token);
	if (mech_buf.value != NULL)
	    free(mech_buf.value);
	if (initialToken)
	    free_NegTokenInit(&ni);
	else
	    free_NegTokenResp(&na);
    }

    if (ret == GSS_S_COMPLETE) {
	if (src_name != NULL) {
	    ret2 = gss_duplicate_name(minor_status,
				      ctx->mech_src_name,
				      src_name);
	    if (ret2 != GSS_S_COMPLETE)
		ret = ret2;
	}
        if (delegated_cred_handle != NULL) {
	    *delegated_cred_handle = ctx->delegated_cred_id;
	    ctx->delegated_cred_id = GSS_C_NO_CREDENTIAL;
	}
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

