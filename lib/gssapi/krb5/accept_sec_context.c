/*
 * Copyright (c) 1997 - 2006 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

RCSID("$Id$");

HEIMDAL_MUTEX gssapi_keytab_mutex = HEIMDAL_MUTEX_INITIALIZER;
krb5_keytab _gsskrb5_keytab;

#if 0
OM_uint32
gsskrb5_register_acceptor_identity (const char *identity)
{
    krb5_error_code ret;

    ret = _gsskrb5_init();
    if(ret)
	return GSS_S_FAILURE;
    
    HEIMDAL_MUTEX_lock(&gssapi_keytab_mutex);

    if(_gsskrb5_keytab != NULL) {
	krb5_kt_close(_gsskrb5_context, gssapi_krb5_keytab);
	_gsskrb5_keytab = NULL;
    }
    if (identity == NULL) {
	ret = krb5_kt_default(_gsskrb5_context, &gssapi_krb5_keytab);
    } else {
	char *p;

	asprintf(&p, "FILE:%s", identity);
	if(p == NULL) {
	    HEIMDAL_MUTEX_unlock(&gssapi_keytab_mutex);
	    return GSS_S_FAILURE;
	}
	ret = krb5_kt_resolve(_gsskrb5_context, p, &gssapi_krb5_keytab);
	free(p);
    }
    HEIMDAL_MUTEX_unlock(&gssapi_keytab_mutex);
    if(ret)
	return GSS_S_FAILURE;
    return GSS_S_COMPLETE;
}
#endif

void
_gsskrb5i_is_cfx(gsskrb5_ctx ctx, int *is_cfx)
{
    krb5_keyblock *key;
    int acceptor = (ctx->more_flags & LOCAL) == 0;

    *is_cfx = 0;

    if (acceptor) {
	if (ctx->auth_context->local_subkey)
	    key = ctx->auth_context->local_subkey;
	else
	    key = ctx->auth_context->remote_subkey;
    } else {
	if (ctx->auth_context->remote_subkey)
	    key = ctx->auth_context->remote_subkey;
	else
	    key = ctx->auth_context->local_subkey;
    }
    if (key == NULL)
	key = ctx->auth_context->keyblock;

    if (key == NULL)
	return;
	    
    switch (key->keytype) {
    case ETYPE_DES_CBC_CRC:
    case ETYPE_DES_CBC_MD4:
    case ETYPE_DES_CBC_MD5:
    case ETYPE_DES3_CBC_MD5:
    case ETYPE_DES3_CBC_SHA1:
    case ETYPE_ARCFOUR_HMAC_MD5:
    case ETYPE_ARCFOUR_HMAC_MD5_56:
	break;
    default :
	*is_cfx = 1;
	if ((acceptor && ctx->auth_context->local_subkey) ||
	    (!acceptor && ctx->auth_context->remote_subkey))
	    ctx->more_flags |= ACCEPTOR_SUBKEY;
	break;
    }
}


static OM_uint32
gsskrb5_accept_delegated_token
(OM_uint32 * minor_status,
 gsskrb5_ctx ctx,
 krb5_data *fwd_data,
 OM_uint32 *flags,
 krb5_principal principal,
 gss_cred_id_t * delegated_cred_handle
    )
{
    krb5_ccache ccache = NULL;
    krb5_error_code kret;
    int32_t ac_flags, ret = GSS_S_COMPLETE;
      
    *minor_status = 0;

    *delegated_cred_handle = NULL;

    /* XXX Create a new delegated_cred_handle? */
    if (delegated_cred_handle == NULL)
	kret = krb5_cc_default (_gsskrb5_context, &ccache);
    else
	kret = krb5_cc_gen_new (_gsskrb5_context, &krb5_mcc_ops, &ccache);
    if (kret) {
	*flags &= ~GSS_C_DELEG_FLAG;
	goto out;
    }

    kret = krb5_cc_initialize(_gsskrb5_context, ccache, principal);
    if (kret) {
	*flags &= ~GSS_C_DELEG_FLAG;
	goto out;
    }
      
    krb5_auth_con_removeflags(_gsskrb5_context,
			      ctx->auth_context,
			      KRB5_AUTH_CONTEXT_DO_TIME,
			      &ac_flags);
    kret = krb5_rd_cred2(_gsskrb5_context,
			 ctx->auth_context,
			 ccache,
			 fwd_data);
    if (kret)
	_gsskrb5_set_error_string();
    krb5_auth_con_setflags(_gsskrb5_context,
			   ctx->auth_context,
			   ac_flags);
    if (kret) {
	*flags &= ~GSS_C_DELEG_FLAG;
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	goto out;
    }

    if (delegated_cred_handle) {
	gsskrb5_cred handle;

	ret = _gsskrb5_import_cred(minor_status,
				   ccache,
				   NULL,
				   NULL,
				   delegated_cred_handle);
	if (ret != GSS_S_COMPLETE)
	    goto out;

	handle = (gsskrb5_cred) *delegated_cred_handle;
    
	handle->cred_flags |= GSS_CF_DESTROY_CRED_ON_RELEASE;
	ccache = NULL;
    }

out:
    if (ccache) {
	if (delegated_cred_handle == NULL)
	    krb5_cc_close(_gsskrb5_context, ccache);
	else
	    krb5_cc_destroy(_gsskrb5_context, ccache);
    }
    return ret;
}


OM_uint32
_gsskrb5_accept_sec_context
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
    krb5_error_code kret;
    OM_uint32 ret = GSS_S_COMPLETE;
    krb5_data indata;
    krb5_flags ap_options;
    OM_uint32 flags;
    krb5_ticket *ticket = NULL;
    krb5_keytab keytab = NULL;
    krb5_data fwd_data;
    OM_uint32 minor;
    int is_cfx = 0;
    gsskrb5_ctx ctx = NULL;
    gsskrb5_cred cred = (gsskrb5_cred)acceptor_cred_handle;

    GSSAPI_KRB5_INIT();

    krb5_data_zero (&fwd_data);
    output_token->length = 0;
    output_token->value = NULL;
    *minor_status = 0;

    if (src_name != NULL)
	*src_name = NULL;
    if (mech_type)
	*mech_type = GSS_KRB5_MECHANISM;

    if (*context_handle != GSS_C_NO_CONTEXT) {
	*minor_status = 0;
	return GSS_S_BAD_MECH;
    }

    ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    HEIMDAL_MUTEX_init(&ctx->ctx_id_mutex);
    ctx->auth_context =  NULL;
    ctx->source = NULL;
    ctx->target = NULL;
    ctx->flags = 0;
    ctx->more_flags = 0;
    ctx->ticket = NULL;
    ctx->lifetime = GSS_C_INDEFINITE;
    ctx->order = NULL;

    kret = krb5_auth_con_init (_gsskrb5_context,
			       &ctx->auth_context);
    if (kret) {
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	_gsskrb5_set_error_string ();
	goto failure;
    }

    if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS
	&& input_chan_bindings->application_data.length ==
	2 * sizeof(ctx->auth_context->local_port)
	) {
     
	/* Port numbers are expected to be in application_data.value,
	 * initator's port first */
     
	krb5_address initiator_addr, acceptor_addr;
     
	memset(&initiator_addr, 0, sizeof(initiator_addr));
	memset(&acceptor_addr, 0, sizeof(acceptor_addr));

	ctx->auth_context->remote_port = 
	    *(int16_t *) input_chan_bindings->application_data.value; 
     
	ctx->auth_context->local_port =
	    *((int16_t *) input_chan_bindings->application_data.value + 1);

     
	kret = _gsskrb5i_address_to_krb5addr(input_chan_bindings->acceptor_addrtype,
					     &input_chan_bindings->acceptor_address,
					     ctx->auth_context->local_port,
					     &acceptor_addr); 
	if (kret) {
	    _gsskrb5_set_error_string ();
	    ret = GSS_S_BAD_BINDINGS;
	    *minor_status = kret;
	    goto failure;
	}
                             
	kret = _gsskrb5i_address_to_krb5addr(input_chan_bindings->initiator_addrtype,
					     &input_chan_bindings->initiator_address, 
					     ctx->auth_context->remote_port,
					     &initiator_addr); 
	if (kret) {
	    krb5_free_address (_gsskrb5_context, &acceptor_addr);
	    _gsskrb5_set_error_string ();
	    ret = GSS_S_BAD_BINDINGS;
	    *minor_status = kret;
	    goto failure;
	}
     
	kret = krb5_auth_con_setaddrs(_gsskrb5_context,
				      ctx->auth_context,
				      &acceptor_addr,    /* local address */
				      &initiator_addr);  /* remote address */
     
	krb5_free_address (_gsskrb5_context, &initiator_addr);
	krb5_free_address (_gsskrb5_context, &acceptor_addr);
     
#if 0
	free(input_chan_bindings->application_data.value);
	input_chan_bindings->application_data.value = NULL;
	input_chan_bindings->application_data.length = 0;
#endif
     
	if (kret) {
	    _gsskrb5_set_error_string ();
	    ret = GSS_S_BAD_BINDINGS;
	    *minor_status = kret;
	    goto failure;
	}
    }
  
    krb5_auth_con_addflags(_gsskrb5_context,
			   ctx->auth_context,
			   KRB5_AUTH_CONTEXT_DO_SEQUENCE,
			   NULL);

    ret = _gsskrb5_decapsulate (minor_status,
				   input_token_buffer,
				   &indata,
				   "\x01\x00",
				   GSS_KRB5_MECHANISM);
    if (ret)
	goto failure;

    HEIMDAL_MUTEX_lock(&gssapi_keytab_mutex);

    if (cred == NULL) {
	if (_gsskrb5_keytab != NULL) {
	    keytab = _gsskrb5_keytab;
	}
    } else if (cred->keytab != NULL) {
	keytab = cred->keytab;
    }

    kret = krb5_rd_req (_gsskrb5_context,
			&ctx->auth_context,
			&indata,
			(cred == NULL) ? NULL : cred->principal,
			keytab,
			&ap_options,
			&ticket);

    HEIMDAL_MUTEX_unlock(&gssapi_keytab_mutex);

    if (kret) {
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	_gsskrb5_set_error_string ();
	goto failure;
    }

    kret = krb5_copy_principal (_gsskrb5_context,
				ticket->client,
				&ctx->source);
    if (kret) {
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	_gsskrb5_set_error_string ();
	goto failure;
    }

    kret = krb5_copy_principal (_gsskrb5_context,
				ticket->server,
				&ctx->target);
    if (kret) {
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	_gsskrb5_set_error_string ();
	goto failure;
    }

    ret = _gss_DES3_get_mic_compat(minor_status, ctx);
    if (ret)
	goto failure;

    if (src_name != NULL) {
	krb5_principal name;

	kret = krb5_copy_principal (_gsskrb5_context,
				    ticket->client,
				    &name);
	if (kret) {
	    ret = GSS_S_FAILURE;
	    *minor_status = kret;
	    _gsskrb5_set_error_string ();
	    goto failure;
	}
	*src_name = (gss_name_t)name;
    }

    {
	krb5_authenticator authenticator;
      
	kret = krb5_auth_con_getauthenticator(_gsskrb5_context,
					      ctx->auth_context,
					      &authenticator);
	if(kret) {
	    ret = GSS_S_FAILURE;
	    *minor_status = kret;
	    _gsskrb5_set_error_string ();
	    goto failure;
	}

	ret = _gsskrb5_verify_8003_checksum(minor_status,
					    input_chan_bindings,
					    authenticator->cksum,
					    &flags,
					    &fwd_data);
	krb5_free_authenticator(_gsskrb5_context, &authenticator);
	if (ret)
	    goto failure;
    }

    flags |= GSS_C_TRANS_FLAG;

    if (ret_flags)
	*ret_flags = flags;
    ctx->lifetime = ticket->ticket.endtime;
    ctx->flags = flags;
    ctx->more_flags |= OPEN;

    if (mech_type)
	*mech_type = GSS_KRB5_MECHANISM;

    if (time_rec) {
	ret = _gsskrb5_lifetime_left(minor_status,
				   ctx->lifetime,
				   time_rec);
	if (ret)
	    goto failure;
    }

    _gsskrb5i_is_cfx(ctx, &is_cfx);

    if(flags & GSS_C_MUTUAL_FLAG) {
	krb5_data outbuf;

	if (is_cfx != 0
	    || (ap_options & AP_OPTS_USE_SUBKEY)) {
	    kret = krb5_auth_con_addflags(_gsskrb5_context,
					  ctx->auth_context,
					  KRB5_AUTH_CONTEXT_USE_SUBKEY,
					  NULL);
	    ctx->more_flags |= ACCEPTOR_SUBKEY;
	}

	kret = krb5_mk_rep (_gsskrb5_context,
			    ctx->auth_context,
			    &outbuf);
	if (kret) {
	    ret = GSS_S_FAILURE;
	    *minor_status = kret;
	    _gsskrb5_set_error_string ();
	    goto failure;
	}
	ret = _gsskrb5_encapsulate (minor_status,
				       &outbuf,
				       output_token,
				       (u_char *)"\x02\x00",
				       GSS_KRB5_MECHANISM);
	krb5_data_free (&outbuf);
	if (ret)
	    goto failure;
    }

    ctx->ticket = ticket;

    {
	int32_t seq_number;
	
	krb5_auth_getremoteseqnumber (_gsskrb5_context,
				      ctx->auth_context,
				      &seq_number);
	ret = _gssapi_msg_order_create(minor_status,
				       &ctx->order,
				       _gssapi_msg_order_f(flags),
				       seq_number, 0, is_cfx);
	if (ret)
	    goto failure;
	
	if ((flags & GSS_C_MUTUAL_FLAG) == 0 && _gssapi_msg_order_f(flags)) {
	    krb5_auth_con_setlocalseqnumber (_gsskrb5_context,
					     ctx->auth_context,
					     seq_number);
	}
    }

    if (fwd_data.length > 0) {

	if (flags & GSS_C_DELEG_FLAG) {
	    ret = gsskrb5_accept_delegated_token(minor_status,
						 ctx,
						 &fwd_data,
						 &flags,
						 ticket->client,
						 delegated_cred_handle);
	    if (ret)
		goto failure;
	}
	free(fwd_data.data);
	krb5_data_zero(&fwd_data);
    }

    *context_handle = (gss_ctx_id_t)ctx;

    *minor_status = 0;
    return GSS_S_COMPLETE;

failure:
    if (fwd_data.length > 0)
	free(fwd_data.data);
    if (ticket != NULL)
	krb5_free_ticket (_gsskrb5_context, ticket);
    krb5_auth_con_free (_gsskrb5_context,
			ctx->auth_context);
    if(ctx->source)
	krb5_free_principal (_gsskrb5_context,
			     ctx->source);
    if(ctx->target)
	krb5_free_principal (_gsskrb5_context,
			     ctx->target);
    if(ctx->order)
	_gssapi_msg_order_destroy(&ctx->order);
    HEIMDAL_MUTEX_destroy(&ctx->ctx_id_mutex);
    free(ctx);
    if (src_name != NULL) {
	_gsskrb5_release_name (&minor, src_name);
	*src_name = NULL;
    }
    *context_handle = GSS_C_NO_CONTEXT;
    return ret;
}
