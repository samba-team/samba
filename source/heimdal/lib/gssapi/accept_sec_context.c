/*
 * Copyright (c) 1997 - 2003 Kungliga Tekniska Högskolan
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

#include "gssapi_locl.h"

RCSID("$Id: accept_sec_context.c,v 1.55 2005/11/25 15:57:35 lha Exp $");

HEIMDAL_MUTEX gssapi_keytab_mutex = HEIMDAL_MUTEX_INITIALIZER;
krb5_keytab gssapi_krb5_keytab;

OM_uint32
gsskrb5_register_acceptor_identity (const char *identity)
{
    krb5_error_code ret;

    ret = gssapi_krb5_init();
    if(ret)
	return GSS_S_FAILURE;
    
    HEIMDAL_MUTEX_lock(&gssapi_keytab_mutex);

    if(gssapi_krb5_keytab != NULL) {
	krb5_kt_close(gssapi_krb5_context, gssapi_krb5_keytab);
	gssapi_krb5_keytab = NULL;
    }
    if (identity == NULL) {
	ret = krb5_kt_default(gssapi_krb5_context, &gssapi_krb5_keytab);
    } else {
	char *p;

	asprintf(&p, "FILE:%s", identity);
	if(p == NULL) {
	    HEIMDAL_MUTEX_unlock(&gssapi_keytab_mutex);
	    return GSS_S_FAILURE;
	}
	ret = krb5_kt_resolve(gssapi_krb5_context, p, &gssapi_krb5_keytab);
	free(p);
    }
    HEIMDAL_MUTEX_unlock(&gssapi_keytab_mutex);
    if(ret)
	return GSS_S_FAILURE;
    return GSS_S_COMPLETE;
}

void
gsskrb5_is_cfx(gss_ctx_id_t context_handle, int *is_cfx)
{
    krb5_keyblock *key;
    int acceptor = (context_handle->more_flags & LOCAL) == 0;
    *is_cfx = 0;

    if (acceptor) {
	if (context_handle->auth_context->local_subkey)
	    key = context_handle->auth_context->local_subkey;
	else
	    key = context_handle->auth_context->remote_subkey;
    } else {
	if (context_handle->auth_context->remote_subkey)
	    key = context_handle->auth_context->remote_subkey;
	else
	    key = context_handle->auth_context->local_subkey;
    }
    if (key == NULL)
	key = context_handle->auth_context->keyblock;

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
	if ((acceptor && context_handle->auth_context->local_subkey) ||
	    (!acceptor && context_handle->auth_context->remote_subkey))
	    context_handle->more_flags |= ACCEPTOR_SUBKEY;
	break;
    }
}


static OM_uint32
gsskrb5_accept_delegated_token
           (OM_uint32 * minor_status,
            gss_ctx_id_t * context_handle,
            gss_cred_id_t * delegated_cred_handle)
{
    krb5_data *fwd_data = &(*context_handle)->fwd_data;
    OM_uint32 *flags = &(*context_handle)->flags;
    krb5_principal principal = (*context_handle)->source;
    krb5_ccache ccache = NULL;
    krb5_error_code kret;
    int32_t ac_flags, ret = GSS_S_COMPLETE;
      
    *minor_status = 0;

    /* XXX Create a new delegated_cred_handle? */
    if (delegated_cred_handle == NULL)
	kret = krb5_cc_default (gssapi_krb5_context, &ccache);
    else
	kret = krb5_cc_gen_new (gssapi_krb5_context, &krb5_mcc_ops, &ccache);
    if (kret) {
	*flags &= ~GSS_C_DELEG_FLAG;
	goto out;
    }

    kret = krb5_cc_initialize(gssapi_krb5_context, ccache, principal);
    if (kret) {
	*flags &= ~GSS_C_DELEG_FLAG;
	goto out;
    }
      
    krb5_auth_con_removeflags(gssapi_krb5_context,
			      (*context_handle)->auth_context,
			      KRB5_AUTH_CONTEXT_DO_TIME,
			      &ac_flags);
    kret = krb5_rd_cred2(gssapi_krb5_context,
			 (*context_handle)->auth_context,
			 ccache,
			 fwd_data);
    if (kret)
	gssapi_krb5_set_error_string();
    krb5_auth_con_setflags(gssapi_krb5_context,
			   (*context_handle)->auth_context,
			   ac_flags);
    if (kret) {
	*flags &= ~GSS_C_DELEG_FLAG;
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	goto out;
    }

    if (delegated_cred_handle) {
	ret = gss_krb5_import_cred(minor_status,
				   ccache,
				   NULL,
				   NULL,
				   delegated_cred_handle);
	if (ret != GSS_S_COMPLETE)
	    goto out;

	(*delegated_cred_handle)->cred_flags |= GSS_CF_DESTROY_CRED_ON_RELEASE;
	ccache = NULL;
    }

out:
    if (ccache) {
	if (delegated_cred_handle == NULL)
	    krb5_cc_close(gssapi_krb5_context, ccache);
	else
	    krb5_cc_destroy(gssapi_krb5_context, ccache);
    }
    return ret;
}

static OM_uint32
gsskrb5_acceptor_ready(
	OM_uint32 * minor_status,
	gss_ctx_id_t * context_handle,
	gss_cred_id_t * delegated_cred_handle)
{
	OM_uint32 ret;
	int32_t seq_number;
	int is_cfx = 0;
	u_int32_t *flags = &(*context_handle)->flags;

	krb5_auth_getremoteseqnumber (gssapi_krb5_context,
				      (*context_handle)->auth_context,
				      &seq_number);

	gsskrb5_is_cfx(*context_handle, &is_cfx);

	ret = _gssapi_msg_order_create(minor_status,
				       &(*context_handle)->order,
				       _gssapi_msg_order_f(*flags),
				       seq_number, 0, is_cfx);
	if (ret) return ret;

	if (!(*flags & GSS_C_MUTUAL_FLAG) && _gssapi_msg_order_f(*flags)) {
		krb5_auth_con_setlocalseqnumber(gssapi_krb5_context,
						(*context_handle)->auth_context,
						seq_number);
	}

	/*
	 * We should handle the delegation ticket, in case it's there
	 */
	if ((*context_handle)->fwd_data.length > 0 && (*flags & GSS_C_DELEG_FLAG)) {
		ret = gsskrb5_accept_delegated_token(minor_status,
						     context_handle,
						     delegated_cred_handle);
		if (ret) return ret;
	} else {
		/* Well, looks like it wasn't there after all */
		*flags &= ~GSS_C_DELEG_FLAG;
	}

	(*context_handle)->state	= ACCEPTOR_READY;
	(*context_handle)->more_flags	|= OPEN;

	return GSS_S_COMPLETE;
}
static OM_uint32
gsskrb5_acceptor_start
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
    krb5_keyblock *keyblock = NULL;
    int is_cfx = 0;

    krb5_data_zero (&(*context_handle)->fwd_data);

    /*
     * We may, or may not, have an escapsulation.
     */
    ret = gssapi_krb5_decapsulate (minor_status,
				   input_token_buffer,
				   &indata,
				   "\x01\x00",
				   GSS_KRB5_MECHANISM);

    if (ret) {
	/* No OID wrapping apparently available. */
	indata.length	= input_token_buffer->length;
	indata.data	= input_token_buffer->value;
    }

    /*
     * We need to get our keytab
     */
    if (acceptor_cred_handle == GSS_C_NO_CREDENTIAL) {
	if (gssapi_krb5_keytab != NULL) {
	    keytab = gssapi_krb5_keytab;
	}
    } else if (acceptor_cred_handle->keytab != NULL) {
	keytab = acceptor_cred_handle->keytab;
    }
    
    /*
     * We need to check the ticket and create the AP-REP packet
     */
    kret = krb5_rd_req_return_keyblock(gssapi_krb5_context,
				       &(*context_handle)->auth_context,
				       &indata,
				       (acceptor_cred_handle == GSS_C_NO_CREDENTIAL) ? NULL : acceptor_cred_handle->principal,
				       keytab,
				       &ap_options,
				       &ticket,
				       &keyblock);
    if (kret) {
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	gssapi_krb5_set_error_string ();
	return ret;
    }
    
    /*
     * We need to remember some data on the context_handle
     */
    (*context_handle)->ticket = ticket;
    (*context_handle)->service_keyblock = keyblock;
    (*context_handle)->lifetime = ticket->ticket.endtime;
    
    /*
     * We need to copy the principal names to the context and the calling layer
     */
    kret = krb5_copy_principal(gssapi_krb5_context,
			       ticket->client,
			       &(*context_handle)->source);
    if (kret) {
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	gssapi_krb5_set_error_string ();
    }

    kret = krb5_copy_principal (gssapi_krb5_context,
				ticket->server,
				&(*context_handle)->target);
    if (kret) {
	ret = GSS_S_FAILURE;
	*minor_status = kret;
	gssapi_krb5_set_error_string ();
	return ret;
    }
    
    /*
     * We need to setup some compat stuff, this assumes that context_handle->target is already set
     */
    ret = _gss_DES3_get_mic_compat(minor_status, *context_handle);
    if (ret) {
	return ret;
    }

    if (src_name != NULL) {
	kret = krb5_copy_principal (gssapi_krb5_context,
				    ticket->client,
				    src_name);
	if (kret) {
	    ret = GSS_S_FAILURE;
	    *minor_status = kret;
	    gssapi_krb5_set_error_string ();
	    return ret;
	}
    }

    /*
     * We need to get the flags out of the 8003 checksum
     */
    {
	krb5_authenticator authenticator;
      
	kret = krb5_auth_con_getauthenticator(gssapi_krb5_context,
					      (*context_handle)->auth_context,
					      &authenticator);
	if(kret) {
	    ret = GSS_S_FAILURE;
	    *minor_status = kret;
	    gssapi_krb5_set_error_string ();
	    return ret;
	}

	ret = gssapi_krb5_verify_8003_checksum(minor_status,
					       input_chan_bindings,
					       authenticator->cksum,
					       &flags,
					       &(*context_handle)->fwd_data);
	krb5_free_authenticator(gssapi_krb5_context, &authenticator);
	if (ret) {
	    return ret;
	}
    }
    
    if(flags & GSS_C_MUTUAL_FLAG) {
	    krb5_data outbuf;
	    
	    gsskrb5_is_cfx(*context_handle, &is_cfx);
	    
	    if (is_cfx != 0 
		|| (ap_options & AP_OPTS_USE_SUBKEY)) {
		    kret = krb5_auth_con_addflags(gssapi_krb5_context,
						  (*context_handle)->auth_context,
						  KRB5_AUTH_CONTEXT_USE_SUBKEY,
						  NULL);
		    (*context_handle)->more_flags |= ACCEPTOR_SUBKEY;
	    }
	    
	    kret = krb5_mk_rep(gssapi_krb5_context,
			       (*context_handle)->auth_context,
			       &outbuf);
	    if (kret) {
		    *minor_status = kret;
		    gssapi_krb5_set_error_string ();
		    return GSS_S_FAILURE;
	    }
	    
	    if (!(flags & GSS_C_DCE_STYLE)) {
		    ret = gssapi_krb5_encapsulate(minor_status,
						  &outbuf,
						  output_token,
						  "\x02\x00",
						  GSS_KRB5_MECHANISM);
		    krb5_data_free (&outbuf);
		    if (ret) {
			    return ret;
		    }
	    } else {
		    output_token->length	= outbuf.length;
		    output_token->value	= outbuf.data;
	    }
    }
    
    flags |= GSS_C_TRANS_FLAG;

    /* Remember the flags */
    
    (*context_handle)->lifetime = ticket->ticket.endtime;
    (*context_handle)->flags = flags;
    (*context_handle)->more_flags |= OPEN;
    
    if (mech_type)
	*mech_type = GSS_KRB5_MECHANISM;
    
    if (time_rec) {
	ret = gssapi_lifetime_left(minor_status,
				   (*context_handle)->lifetime,
				   time_rec);
	if (ret) {
	    return ret;
	}
    }

    /*
     * When GSS_C_DCE_STYLE is in use, we need ask for a AP-REP from the client
     */
    if (flags & GSS_C_DCE_STYLE) {
	    if (ret_flags) {
		    /* Return flags to caller, but we haven't processed delgations yet */
		    *ret_flags = flags & ~GSS_C_DELEG_FLAG;
	    }
    
	    (*context_handle)->state = ACCEPTOR_WAIT_FOR_DCESTYLE;
	    return GSS_S_CONTINUE_NEEDED;
    }

    ret = gsskrb5_acceptor_ready(minor_status, context_handle, delegated_cred_handle);

    /*
     * We need to send the flags back to the caller
     */
    
    *ret_flags = (*context_handle)->flags;
    return ret;
}

static OM_uint32
gsskrb5_acceptor_wait_for_dcestyle(
	OM_uint32 * minor_status,
	gss_ctx_id_t * context_handle,
	const gss_cred_id_t acceptor_cred_handle,
	const gss_buffer_t input_token_buffer,
	const gss_channel_bindings_t input_chan_bindings,
	gss_name_t * src_name,
	gss_OID * mech_type,
	gss_buffer_t output_token,
	OM_uint32 * ret_flags,
	OM_uint32 * time_rec,
	gss_cred_id_t * delegated_cred_handle)
{
	OM_uint32 ret;
	krb5_error_code kret;
	krb5_data inbuf;
	OM_uint32 r_seq_number;
	OM_uint32 l_seq_number;
	
	/* We know it's GSS_C_DCE_STYLE so we don't need to decapsulate the AP_REP */
	inbuf.length	= input_token_buffer->length;
	inbuf.data	= input_token_buffer->value;

	/* 
	 * We need to remeber the old remote seq_number, then check if the client has replied with our local seq_number,
	 * and then reset the remote seq_number to the old value 
	 */
	{
		kret = krb5_auth_con_getlocalseqnumber(gssapi_krb5_context,
						    (*context_handle)->auth_context,
						    &l_seq_number);
		if (kret) {
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}

		kret = krb5_auth_getremoteseqnumber(gssapi_krb5_context,
						    (*context_handle)->auth_context,
						    &r_seq_number);
		if (kret) {
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}

		kret = krb5_auth_con_setremoteseqnumber(gssapi_krb5_context,
						    (*context_handle)->auth_context,
						    l_seq_number);
		if (kret) {
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}
	}

	/* We need to verify the AP_REP, but we need to flag that this
	   is DCE_STYLE, so don't check the timestamps this time 
	*/ 
	{
		krb5_ap_rep_enc_part *repl;
		int32_t auth_flags;
		
		kret = krb5_auth_con_removeflags(gssapi_krb5_context,
						 (*context_handle)->auth_context,
						 KRB5_AUTH_CONTEXT_DO_TIME, &auth_flags);
		if (kret) { /* Can't happen */
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}

		kret = krb5_rd_rep(gssapi_krb5_context,
				   (*context_handle)->auth_context,
				   &inbuf,
				   &repl);
		if (kret) {
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}
		
		/* Because the inbuf above is a final leg from client
		 * to server, we don't have a use for a 'reply'
		 * here */
		krb5_free_ap_rep_enc_part(gssapi_krb5_context, repl);

		/* Do no harm, put the flags back */
		kret = krb5_auth_con_setflags(gssapi_krb5_context,
					      (*context_handle)->auth_context,
					      auth_flags);
		if (kret) { /* Can't happen */
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}
	}

	/* We need to check the liftime */
	{
		OM_uint32 lifetime_rec;

		ret = gssapi_lifetime_left(minor_status,
					   (*context_handle)->lifetime,
					   &lifetime_rec);
		if (ret) {
			return ret;
		}
		if (lifetime_rec == 0) {
			return GSS_S_CONTEXT_EXPIRED;
		}
	
		if (time_rec) *time_rec = lifetime_rec;
	}

	/* We need to give the caller the flags which are in use */
	if (ret_flags) *ret_flags = (*context_handle)->flags;

	if (src_name) {
		kret = krb5_copy_principal(gssapi_krb5_context,
					   (*context_handle)->source,
					   src_name);
		if (kret) {
			*minor_status = kret;
			gssapi_krb5_set_error_string ();
			return GSS_S_FAILURE;
		}
	}

	/*
	 * After the krb5_rd_rep() the remote and local seq_number should be the same,
	 * because the client just replies the seq_number from our AP-REP in its AP-REP,
	 * but then the client uses the seq_number from its AP-REQ for GSS_wrap()
	 */
	{
		OM_uint32 tmp_r_seq_number;
		OM_uint32 tmp_l_seq_number;

		kret = krb5_auth_getremoteseqnumber(gssapi_krb5_context,
						    (*context_handle)->auth_context,
						    &tmp_r_seq_number);
		if (kret) {
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}

		kret = krb5_auth_con_getlocalseqnumber(gssapi_krb5_context,
						    (*context_handle)->auth_context,
						    &tmp_l_seq_number);
		if (kret) {
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}

		/*
		 * Here we check if the client has responsed with our local seq_number,
		 */
		if (tmp_r_seq_number != tmp_l_seq_number) {
			return GSS_S_UNSEQ_TOKEN;
		}
	}

	/*
	 * We need to reset the remote seq_number, because the client will use,
	 * the old one for the GSS_wrap() calls
	 */
	{
		kret = krb5_auth_con_setremoteseqnumber(gssapi_krb5_context,
						       (*context_handle)->auth_context,
						       r_seq_number);	
		if (kret) {
			gssapi_krb5_set_error_string ();
			*minor_status = kret;
			return GSS_S_FAILURE;
		}
	}

	return gsskrb5_acceptor_ready(minor_status, context_handle, delegated_cred_handle);
}

static OM_uint32
gsskrb5_accept_sec_context
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
    OM_uint32 ret = GSS_S_COMPLETE;
    krb5_data fwd_data;
    gss_ctx_id_t local_context;

    GSSAPI_KRB5_INIT();

    krb5_data_zero (&fwd_data);
    output_token->length = 0;
    output_token->value = NULL;

    if (src_name != NULL)
	*src_name = NULL;
    if (mech_type)
	*mech_type = GSS_KRB5_MECHANISM;

    if (*context_handle == GSS_C_NO_CONTEXT) {
	ret = _gsskrb5_create_ctx(minor_status,
				  &local_context,
				  input_chan_bindings,
				  ACCEPTOR_START);
	if (ret) return ret;
    } else {
	local_context = *context_handle;
    }
    
    /*
     * TODO: check the channel_bindings 
     * (above just sets them to krb5 layer)
     */

    HEIMDAL_MUTEX_lock(&(local_context)->ctx_id_mutex);
    
    switch ((local_context)->state) {
    case ACCEPTOR_START:
	ret = gsskrb5_acceptor_start(minor_status,
				     &local_context,
				     acceptor_cred_handle,
				     input_token_buffer,
				     input_chan_bindings,
				     src_name,
				     mech_type,
				     output_token,
				     ret_flags,
				     time_rec,
				     delegated_cred_handle);
	break;
    case ACCEPTOR_WAIT_FOR_DCESTYLE:
	ret = gsskrb5_acceptor_wait_for_dcestyle(minor_status,
						 &local_context,
						 acceptor_cred_handle,
						 input_token_buffer,
						 input_chan_bindings,
						 src_name,
						 mech_type,
						 output_token,
						 ret_flags,
						 time_rec,
						 delegated_cred_handle);
	break;
    case ACCEPTOR_READY:
	/* this function should not be called after it has returned GSS_S_COMPLETE */
	ret =  GSS_S_BAD_STATUS;
	break;
    default:
	/* TODO: is this correct here? --metze */
	ret =  GSS_S_BAD_STATUS;
	break;
    }
    
    HEIMDAL_MUTEX_unlock(&(local_context)->ctx_id_mutex);
    
    if (*context_handle == GSS_C_NO_CONTEXT) {
	if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
	    *context_handle = local_context;
	} else {
	    gss_delete_sec_context(minor_status, 
				   &local_context, 
				   NULL);
	}
    }

    return ret;
}

static OM_uint32
code_NegTokenArg(OM_uint32 *minor_status,
		 const NegTokenTarg *targ,
		 krb5_data *data,
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
	ret = encode_NegTokenTarg(buf + buf_size - 1,
				  buf_size,
				  targ, &buf_len);
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

    data->data   = buf + buf_size - buf_len;
    data->length = buf_len;
    *ret_buf     = buf;
    return GSS_S_COMPLETE;
}

static OM_uint32
send_reject (OM_uint32 *minor_status,
	     gss_buffer_t output_token)
{
    NegTokenTarg targ;
    krb5_data data;
    u_char *buf;
    OM_uint32 ret;

    ALLOC(targ.negResult, 1);
    if (targ.negResult == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    *(targ.negResult) = reject;
    targ.supportedMech = NULL;
    targ.responseToken = NULL;
    targ.mechListMIC   = NULL;
    
    ret = code_NegTokenArg (minor_status, &targ, &data, &buf);
    free_NegTokenTarg(&targ);
    if (ret)
	return ret;

#if 0
    ret = _gssapi_encapsulate(minor_status,
			      &data,
			      output_token,
			      GSS_SPNEGO_MECHANISM);
#else
    output_token->value = malloc(data.length);
    if (output_token->value == NULL) {
	*minor_status = ENOMEM;
	ret = GSS_S_FAILURE;
    } else {
	output_token->length = data.length;
	memcpy(output_token->value, data.data, output_token->length);
    }
#endif
    free(buf);
    if (ret)
	return ret;
    return GSS_S_BAD_MECH;
}

static OM_uint32
send_accept (OM_uint32 *minor_status,
	     OM_uint32 major_status,
	     gss_buffer_t output_token,
	     gss_buffer_t mech_token,
	     gss_ctx_id_t context_handle,
	     const MechTypeList *mechtypelist)
{
    NegTokenTarg targ;
    krb5_data data;
    u_char *buf;
    OM_uint32 ret;
    gss_buffer_desc mech_buf, mech_mic_buf;
    krb5_boolean require_mic;

    memset(&targ, 0, sizeof(targ));
    ALLOC(targ.negResult, 1);
    if (targ.negResult == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }
    *(targ.negResult) = accept_completed;

    ALLOC(targ.supportedMech, 1);
    if (targ.supportedMech == NULL) {
	free_NegTokenTarg(&targ);
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    ret = der_get_oid(GSS_KRB5_MECHANISM->elements,
		      GSS_KRB5_MECHANISM->length,
		      targ.supportedMech,
		      NULL);
    if (ret) {
	free_NegTokenTarg(&targ);
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    if (mech_token != NULL && mech_token->length != 0) {
	ALLOC(targ.responseToken, 1);
	if (targ.responseToken == NULL) {
	    free_NegTokenTarg(&targ);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	targ.responseToken->length = mech_token->length;
	targ.responseToken->data   = mech_token->value;
	mech_token->length = 0;
	mech_token->value  = NULL;
    } else {
	targ.responseToken = NULL;
    }

    ret = _gss_spnego_require_mechlist_mic(minor_status, context_handle,
					   &require_mic);
    if (ret) {
	free_NegTokenTarg(&targ);
	return ret;
    }

    if (major_status == GSS_S_COMPLETE && require_mic) {
	size_t buf_len;

	ALLOC(targ.mechListMIC, 1);
	if (targ.mechListMIC == NULL) {
	    free_NegTokenTarg(&targ);
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	
	ASN1_MALLOC_ENCODE(MechTypeList, mech_buf.value, mech_buf.length,
			   mechtypelist, &buf_len, ret);
	if (ret) {
	    free_NegTokenTarg(&targ);
	    return ret;
	}
	if (mech_buf.length != buf_len)
	    abort();

	ret = gss_get_mic(minor_status, context_handle, 0, &mech_buf,
			  &mech_mic_buf);
	free (mech_buf.value);
	if (ret) {
	    free_NegTokenTarg(&targ);
	    return ret;
	}

	targ.mechListMIC->length = mech_mic_buf.length;
	targ.mechListMIC->data   = mech_mic_buf.value;
    } else
	targ.mechListMIC = NULL;

    ret = code_NegTokenArg (minor_status, &targ, &data, &buf);
    free_NegTokenTarg(&targ);
    if (ret)
	return ret;

#if 0
    ret = _gssapi_encapsulate(minor_status,
			      &data,
			      output_token,
			      GSS_SPNEGO_MECHANISM);
#else
    output_token->value = malloc(data.length);
    if (output_token->value == NULL) {
	*minor_status = ENOMEM;
	ret = GSS_S_FAILURE;
    } else {
	output_token->length = data.length;
	memcpy(output_token->value, data.data, output_token->length);
    }
#endif
    free(buf);
    if (ret)
	return ret;
    return GSS_S_COMPLETE;
}

static OM_uint32
spnego_accept_sec_context
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
    OM_uint32 ret, ret2;
    NegTokenInit ni;
    size_t ni_len;
    int i;
    int found = 0;
    krb5_data data;
    size_t len, taglen;

    output_token->length = 0;
    output_token->value  = NULL;

    ret = _gssapi_decapsulate (minor_status,
			       input_token_buffer,
			       &data,
			       GSS_SPNEGO_MECHANISM);
    if (ret)
	return ret;

    ret = der_match_tag_and_length(data.data, data.length,
				   ASN1_C_CONTEXT, CONS, 0, &len, &taglen);
    if (ret)
	return ret;

    if(len > data.length - taglen)
	return ASN1_OVERRUN;

    ret = decode_NegTokenInit((const unsigned char *)data.data + taglen, len,
			      &ni, &ni_len);
    if (ret)
	return GSS_S_DEFECTIVE_TOKEN;

    if (ni.mechTypes == NULL) {
	free_NegTokenInit(&ni);
	return send_reject (minor_status, output_token);
    }

    for (i = 0; !found && i < ni.mechTypes->len; ++i) {
	unsigned char mechbuf[17];
	size_t mech_len;

	ret = der_put_oid (mechbuf + sizeof(mechbuf) - 1,
			   sizeof(mechbuf),
			   &ni.mechTypes->val[i],
			   &mech_len);
	if (ret) {
	    free_NegTokenInit(&ni);
	    return GSS_S_DEFECTIVE_TOKEN;
	}
	if (mech_len == GSS_KRB5_MECHANISM->length
	    && memcmp(GSS_KRB5_MECHANISM->elements,
		      mechbuf + sizeof(mechbuf) - mech_len,
		      mech_len) == 0)
	    found = 1;
    }
    if (found) {
	gss_buffer_desc ibuf, obuf;
	gss_buffer_t ot = NULL;
	OM_uint32 minor;

	if (ni.mechToken != NULL) {
	    ibuf.length = ni.mechToken->length;
	    ibuf.value  = ni.mechToken->data;

	    ret = gsskrb5_accept_sec_context(&minor,
					     context_handle,
					     acceptor_cred_handle,
					     &ibuf,
					     input_chan_bindings,
					     src_name,
					     mech_type,
					     &obuf,
					     ret_flags,
					     time_rec,
					     delegated_cred_handle);
	    if (ret == GSS_S_COMPLETE || ret == GSS_S_CONTINUE_NEEDED) {
		ot = &obuf;
	    } else {
		free_NegTokenInit(&ni);
		send_reject (minor_status, output_token);
		return ret;
	    }
	}
	ret2 = send_accept (minor_status, ret, output_token, ot,
			   *context_handle, ni.mechTypes);
	if (ret2 != GSS_S_COMPLETE)
	    ret = ret2;
	if (ot != NULL)
	    gss_release_buffer(&minor, ot);
	free_NegTokenInit(&ni);
	return ret;
    } else {
	free_NegTokenInit(&ni);
	return send_reject (minor_status, output_token);
    }
}

OM_uint32
gss_accept_sec_context
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
    OM_uint32 ret;
    ssize_t mech_len;
    const u_char *p;

    *minor_status = 0;

    mech_len = gssapi_krb5_get_mech (input_token_buffer->value,
				     input_token_buffer->length,
				     &p);

    /* This could be 'dce style' kerberos, where the OID is missing :-( */
    if ((mech_len < 0) || ((mech_len == GSS_KRB5_MECHANISM->length)
			   && memcmp(p, GSS_KRB5_MECHANISM->elements, mech_len) == 0))
	ret = gsskrb5_accept_sec_context(minor_status,
					 context_handle,
					 acceptor_cred_handle,
					 input_token_buffer,
					 input_chan_bindings,
					 src_name,
					 mech_type,
					 output_token,
					 ret_flags,
					 time_rec,
					 delegated_cred_handle);
    else if (mech_len == GSS_SPNEGO_MECHANISM->length
	     && memcmp(p, GSS_SPNEGO_MECHANISM->elements, mech_len) == 0)
	ret = spnego_accept_sec_context(minor_status,
					context_handle,
					acceptor_cred_handle,
					input_token_buffer,
					input_chan_bindings,
					src_name,
					mech_type,
					output_token,
					ret_flags,
					time_rec,
					delegated_cred_handle);
    else
	return GSS_S_BAD_MECH;

    return ret;
}
