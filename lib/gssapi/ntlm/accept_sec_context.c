/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
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

#include "ntlm/ntlm.h"

RCSID("$Id$");

/*
 *
 */

static OM_uint32
handle_type2(OM_uint32 *minor_status,
	     ntlm_ctx ctx,
	     uint32_t flags,
	     const char *hostname,
	     const char *domain,
	     gss_buffer_t output_token)
{
    krb5_error_code ret;
    struct ntlm_type2 type2;
    krb5_data challange;
    struct ntlm_buf data;
    krb5_data ti;
    
    memset(&type2, 0, sizeof(type2));
    
    /*
     * Request data for type 2 packet from the KDC.
     */
    ret = krb5_ntlm_init_request(ctx->context, 
				 ctx->ntlm,
				 NULL,
				 ctx->id,
				 flags,
				 hostname,
				 domain);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    /*
     *
     */

    ret = krb5_ntlm_init_get_opaque(ctx->context, ctx->ntlm, &ctx->opaque);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    /*
     *
     */

    ret = krb5_ntlm_init_get_flags(ctx->context, ctx->ntlm, &type2.flags);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
    ctx->flags = type2.flags;

    ret = krb5_ntlm_init_get_challange(ctx->context, ctx->ntlm, &challange);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    if (challange.length != sizeof(type2.challange)) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }
    memcpy(type2.challange, challange.data, sizeof(type2.challange));
    krb5_data_free(&challange);

    ret = krb5_ntlm_init_get_targetname(ctx->context, ctx->ntlm,
					&type2.targetname);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    ret = krb5_ntlm_init_get_targetinfo(ctx->context, ctx->ntlm, &ti);
    if (ret) {
	free(type2.targetname);
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    type2.targetinfo.data = ti.data;
    type2.targetinfo.length = ti.length;
	
    ret = heim_ntlm_encode_type2(&type2, &data);
    free(type2.targetname);
    krb5_data_free(&ti);
    if (ret) {
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
	
    output_token->value = data.data;
    output_token->length = data.length;

    return GSS_S_COMPLETE;
}

static OM_uint32
handle_type3(OM_uint32 *minor_status,
	     ntlm_ctx ctx,
	     struct ntlm_type3 *type3)
{
    krb5_error_code ret;
    
    if (type3->username == NULL || type3->targetname == NULL ||
	type3->ntlm.length == 0)
    {
	ret = EINVAL;
	goto out;
    }

    ret = krb5_ntlm_req_set_flags(ctx->context, ctx->ntlm, type3->flags);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_username(ctx->context, ctx->ntlm, type3->username);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_targetname(ctx->context, ctx->ntlm, 
				       type3->targetname);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_lm(ctx->context, ctx->ntlm, 
			       type3->lm.data, type3->lm.length);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_ntlm(ctx->context, ctx->ntlm, 
				 type3->ntlm.data, type3->ntlm.length);
    if (ret) goto out;
    ret = krb5_ntlm_req_set_opaque(ctx->context, ctx->ntlm, &ctx->opaque);
    if (ret) goto out;
    if (type3->sessionkey.length) {
	ret = krb5_ntlm_req_set_session(ctx->context, ctx->ntlm,
					type3->sessionkey.data,
					type3->sessionkey.length);
	if (ret) goto out;
    }

    /*
     * Verify with the KDC the type3 packet is ok
     */
    ret = krb5_ntlm_request(ctx->context, 
			    ctx->ntlm,
			    NULL,
			    ctx->id);
    if (ret)
	goto out;

    if (krb5_ntlm_rep_get_status(ctx->context, ctx->ntlm) != TRUE) {
	ret = EINVAL;
	goto out;
    }

    ret = krb5_ntlm_rep_get_sessionkey(ctx->context, 
				       ctx->ntlm,
				       &ctx->sessionkey);
    if (ret == 0) {
	if (ctx->sessionkey.length != 16) {
	    ret = EINVAL;
	    goto out;
	}

	ctx->status |= STATUS_SESSIONKEY; 

	if (ctx->flags & NTLM_NEG_NTLM2_SESSION) {
	    ctx->u.v2.send.seq = 0;
	    RC4_set_key(&ctx->u.v2.send.sealkey, 
			ctx->sessionkey.length,
			ctx->sessionkey.data);
	    memcpy(ctx->u.v2.send.signkey, ctx->sessionkey.data, 16);

	    ctx->u.v2.recv.seq = 0;
	    RC4_set_key(&ctx->u.v2.recv.sealkey, 
			ctx->sessionkey.length,
			ctx->sessionkey.data);
	    memcpy(ctx->u.v2.recv.signkey, ctx->sessionkey.data, 16);
	} else {
	    RC4_set_key(&ctx->u.v1.crypto_send.key, 
			ctx->sessionkey.length,
			ctx->sessionkey.data);
	    RC4_set_key(&ctx->u.v1.crypto_recv.key, 
			ctx->sessionkey.length,
			ctx->sessionkey.data);
	}
    }

    return GSS_S_COMPLETE;
out:
    *minor_status = ret;
    return GSS_S_FAILURE;
}

/*
 * Get credential cache that the ntlm code can use to talk to the KDC
 * using the digest API.
 */

static krb5_error_code
get_ccache(krb5_context context, krb5_ccache *id)
{
    krb5_principal principal = NULL;
    krb5_error_code ret;
    krb5_keytab kt;

    *id = NULL;
    
    if (!issuid()) {
	const char *cache;

	cache = getenv("NTLM_ACCEPTOR_CCACHE");
	if (cache) {
	    ret = krb5_cc_resolve(context, cache, id);
	    if (ret)
		goto out;
	    return 0;
	}
    }

    ret = krb5_sname_to_principal(context, NULL, "host", 
				  KRB5_NT_SRV_HST, &principal);
    if (ret)
	goto out;
    
    ret = krb5_cc_cache_match(context, principal, NULL, id);
    if (ret == 0)
	goto out;
    
    /* did not find in default credcache, lets try default keytab */
    ret = krb5_kt_default(context, &kt);
    if (ret)
	goto out;

    /* XXX check in keytab */
#if 0
    {
	krb5_creds cred = NULL;

	ret = krb5_get_init_creds_keytab (context,
					  &cred,
					  principal,
					  kt,
					  NULL,
					  NULL,
					  NULL);
	if (ret)
	    goto out;
	ret = krb5_cc_initialize (context, ccache, cred.client);
	ret = krb5_cc_store_cred (context, ccache, &cred);
	krb5_free_cred_contents (context, &cred);
    }
#endif
    krb5_kt_close(context, kt);
    
out:
    if (principal)
	krb5_free_principal(context, principal);
    return ret;
}

OM_uint32
_gss_ntlm_allocate_ctx(OM_uint32 *minor_status, ntlm_ctx *ctx)
{
    krb5_error_code ret;

    *ctx = calloc(1, sizeof(**ctx));

    ret = krb5_init_context(&(*ctx)->context);
    if (ret) {
	gss_ctx_id_t context = (gss_ctx_id_t)*ctx;
	_gss_ntlm_delete_sec_context(minor_status, &context, NULL);
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    ret = get_ccache((*ctx)->context, &(*ctx)->id);
    if (ret) {
	gss_ctx_id_t context = (gss_ctx_id_t)*ctx;
	_gss_ntlm_delete_sec_context(minor_status, &context, NULL);
	*minor_status = ret;
	return GSS_S_FAILURE;
    }

    ret = krb5_ntlm_alloc((*ctx)->context, &(*ctx)->ntlm);
    if (ret) {
	gss_ctx_id_t context = (gss_ctx_id_t)*ctx;
	_gss_ntlm_delete_sec_context(minor_status, &context, NULL);
	*minor_status = ret;
	return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

/*
 *
 */

OM_uint32
_gss_ntlm_accept_sec_context
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
 gss_cred_id_t * delegated_cred_handle
    )
{
    krb5_error_code ret;
    struct ntlm_buf data;
    ntlm_ctx ctx;

    output_token->value = NULL;
    output_token->length = 0;

    *minor_status = 0;

    if (context_handle == NULL)
	return GSS_S_FAILURE;
	
    if (input_token_buffer == GSS_C_NO_BUFFER)
	return GSS_S_FAILURE;

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

    if (*context_handle == GSS_C_NO_CONTEXT) {
	struct ntlm_type1 type1;
	OM_uint32 major_status;

	major_status = _gss_ntlm_allocate_ctx(minor_status, &ctx);
	if (major_status)
	    return major_status;
	*context_handle = (gss_ctx_id_t)ctx;
	
	data.data = input_token_buffer->value;
	data.length = input_token_buffer->length;
	
	ret = heim_ntlm_decode_type1(&data, &type1);
	if (ret) {
	    _gss_ntlm_delete_sec_context(minor_status, context_handle, NULL);
	    *minor_status = ret;
	    return GSS_S_FAILURE;
	}

	if ((type1.flags & NTLM_NEG_UNICODE) == 0) {
	    _gss_ntlm_delete_sec_context(minor_status, context_handle, NULL);
	    *minor_status = EINVAL;
	    return GSS_S_FAILURE;
	}

	if (type1.flags & NTLM_NEG_SIGN)
	    ctx->flags |= GSS_C_CONF_FLAG;
	if (type1.flags & NTLM_NEG_SIGN)
	    ctx->flags |= GSS_C_INTEG_FLAG;

	major_status = handle_type2(minor_status,
				    ctx,
				    type1.flags,
				    type1.hostname,
				    type1.domain,
				    output_token);
	heim_ntlm_free_type1(&type1);
	if (major_status != GSS_S_COMPLETE) {
	    _gss_ntlm_delete_sec_context(minor_status, 
					 context_handle, NULL);
	    return major_status;
	}

	return GSS_S_CONTINUE_NEEDED;
    } else {
	OM_uint32 maj_stat;
	struct ntlm_type3 type3;

	ctx = (ntlm_ctx)*context_handle;

	data.data = input_token_buffer->value;
	data.length = input_token_buffer->length;

	ret = heim_ntlm_decode_type3(&data, 1, &type3);
	if (ret) {
	    _gss_ntlm_delete_sec_context(minor_status, 
					 context_handle, NULL);
	    *minor_status = ret;
	    return GSS_S_FAILURE;
	}

	maj_stat = handle_type3(minor_status, ctx, &type3);
	if (maj_stat != GSS_S_COMPLETE) {
	    OM_uint32 junk;
	    _gss_ntlm_delete_sec_context(&junk, context_handle, NULL);
	    return maj_stat;
	}

	heim_ntlm_free_type3(&type3);

	if (mech_type)
	    *mech_type = GSS_NTLM_MECHANISM;
	if (time_rec)
	    *time_rec = GSS_C_INDEFINITE;

	ctx->status |= STATUS_OPEN;

	return GSS_S_COMPLETE;
    }
}
