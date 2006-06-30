/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
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

/*
 * copy the addresses from `input_chan_bindings' (if any) to
 * the auth context `ac'
 */

static OM_uint32
set_addresses (krb5_auth_context ac,
	       const gss_channel_bindings_t input_chan_bindings)	       
{
    /* Port numbers are expected to be in application_data.value, 
     * initator's port first */ 

    krb5_address initiator_addr, acceptor_addr;
    krb5_error_code kret;
       
    if (input_chan_bindings == GSS_C_NO_CHANNEL_BINDINGS
	|| input_chan_bindings->application_data.length !=
	2 * sizeof(ac->local_port))
	return 0;

    memset(&initiator_addr, 0, sizeof(initiator_addr));
    memset(&acceptor_addr, 0, sizeof(acceptor_addr));
       
    ac->local_port =
	*(int16_t *) input_chan_bindings->application_data.value;
       
    ac->remote_port =
	*((int16_t *) input_chan_bindings->application_data.value + 1);
       
    kret = _gsskrb5i_address_to_krb5addr(input_chan_bindings->acceptor_addrtype,
					 &input_chan_bindings->acceptor_address,
					 ac->remote_port,
					 &acceptor_addr);
    if (kret)
	return kret;
           
    kret = _gsskrb5i_address_to_krb5addr(input_chan_bindings->initiator_addrtype,
					 &input_chan_bindings->initiator_address,
					 ac->local_port,
					 &initiator_addr);
    if (kret) {
	krb5_free_address (_gsskrb5_context, &acceptor_addr);
	return kret;
    }
       
    kret = krb5_auth_con_setaddrs(_gsskrb5_context,
				  ac,
				  &initiator_addr,  /* local address */
				  &acceptor_addr);  /* remote address */
       
    krb5_free_address (_gsskrb5_context, &initiator_addr);
    krb5_free_address (_gsskrb5_context, &acceptor_addr);
       
#if 0
    free(input_chan_bindings->application_data.value);
    input_chan_bindings->application_data.value = NULL;
    input_chan_bindings->application_data.length = 0;
#endif

    return kret;
}

/*
 * handle delegated creds in init-sec-context
 */

static void
do_delegation (krb5_auth_context ac,
	       krb5_ccache ccache,
	       krb5_creds *cred,
	       krb5_const_principal name,
	       krb5_data *fwd_data,
	       uint32_t *flags)
{
    krb5_creds creds;
    krb5_kdc_flags fwd_flags;
    krb5_error_code kret;
       
    memset (&creds, 0, sizeof(creds));
    krb5_data_zero (fwd_data);
       
    kret = krb5_cc_get_principal(_gsskrb5_context, ccache, &creds.client);
    if (kret) 
	goto out;
       
    kret = krb5_build_principal(_gsskrb5_context,
				&creds.server,
				strlen(creds.client->realm),
				creds.client->realm,
				KRB5_TGS_NAME,
				creds.client->realm,
				NULL);
    if (kret)
	goto out; 
       
    creds.times.endtime = 0;
       
    fwd_flags.i = 0;
    fwd_flags.b.forwarded = 1;
    fwd_flags.b.forwardable = 1;
       
    if ( /*target_name->name.name_type != KRB5_NT_SRV_HST ||*/
	name->name.name_string.len < 2) 
	goto out;
       
    kret = krb5_get_forwarded_creds(_gsskrb5_context,
				    ac,
				    ccache,
				    KDCOptions2int(fwd_flags),
				    name->name.name_string.val[1],
				    &creds,
				    fwd_data);
       
 out:
    if (kret)
	*flags &= ~GSS_C_DELEG_FLAG;
    else
	*flags |= GSS_C_DELEG_FLAG;
       
    if (creds.client)
	krb5_free_principal(_gsskrb5_context, creds.client);
    if (creds.server)
	krb5_free_principal(_gsskrb5_context, creds.server);
}

/*
 * first stage of init-sec-context
 */

static OM_uint32
init_auth
(OM_uint32 * minor_status,
 gsskrb5_cred initiator_cred_handle,
 gss_ctx_id_t * context_handle,
 krb5_const_principal name,
 const gss_OID mech_type,
 OM_uint32 req_flags,
 OM_uint32 time_req,
 const gss_channel_bindings_t input_chan_bindings,
 const gss_buffer_t input_token,
 gss_OID * actual_mech_type,
 gss_buffer_t output_token,
 OM_uint32 * ret_flags,
 OM_uint32 * time_rec
    )
{
    OM_uint32 ret = GSS_S_FAILURE;
    krb5_error_code kret;
    krb5_flags ap_options;
    krb5_creds this_cred, *cred = NULL;
    krb5_data outbuf;
    krb5_ccache ccache = NULL;
    uint32_t flags;
    krb5_data authenticator;
    Checksum cksum;
    krb5_enctype enctype;
    krb5_data fwd_data;
    OM_uint32 lifetime_rec;
    gsskrb5_ctx ctx;

    krb5_data_zero(&outbuf);
    krb5_data_zero(&fwd_data);

    *minor_status = 0;

    ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    ctx->auth_context = NULL;
    ctx->source       = NULL;
    ctx->target       = NULL;
    ctx->flags        = 0;
    ctx->more_flags   = 0;
    ctx->ticket       = NULL;
    ctx->lifetime     = GSS_C_INDEFINITE;
    ctx->order	    = NULL;
    HEIMDAL_MUTEX_init(&ctx->ctx_id_mutex);

    kret = krb5_auth_con_init (_gsskrb5_context,
			       &ctx->auth_context);
    if (kret) {
	_gsskrb5_set_error_string ();
	*minor_status = kret;
	ret = GSS_S_FAILURE;
	goto failure;
    }

    kret = set_addresses (ctx->auth_context,
			  input_chan_bindings);
    if (kret) {
	*minor_status = kret;
	ret = GSS_S_BAD_BINDINGS;
	goto failure;
    }

    krb5_auth_con_addflags(_gsskrb5_context,
			   ctx->auth_context,
			   KRB5_AUTH_CONTEXT_DO_SEQUENCE |
			   KRB5_AUTH_CONTEXT_CLEAR_FORWARDED_CRED,
			   NULL);

    if (actual_mech_type)
	*actual_mech_type = GSS_KRB5_MECHANISM;

    if (initiator_cred_handle == NULL) {
	kret = krb5_cc_default (_gsskrb5_context, &ccache);
	if (kret) {
	    _gsskrb5_set_error_string ();
	    *minor_status = kret;
	    ret = GSS_S_FAILURE;
	    goto failure;
	}
    } else
	ccache = initiator_cred_handle->ccache;

    kret = krb5_cc_get_principal (_gsskrb5_context,
				  ccache,
				  &ctx->source);
    if (kret) {
	_gsskrb5_set_error_string ();
	*minor_status = kret;
	ret = GSS_S_FAILURE;
	goto failure;
    }

    kret = krb5_copy_principal (_gsskrb5_context, name, &ctx->target);
    if (kret) {
	_gsskrb5_set_error_string ();
	*minor_status = kret;
	ret = GSS_S_FAILURE;
	goto failure;
    }

    ret = _gss_DES3_get_mic_compat(minor_status, ctx);
    if (ret)
	goto failure;


    memset(&this_cred, 0, sizeof(this_cred));
    this_cred.client          = ctx->source;
    this_cred.server          = ctx->target;
    if (time_req && time_req != GSS_C_INDEFINITE) {
	krb5_timestamp ts;

	krb5_timeofday (_gsskrb5_context, &ts);
	this_cred.times.endtime = ts + time_req;
    } else
	this_cred.times.endtime   = 0;
    this_cred.session.keytype = KEYTYPE_NULL;

    kret = krb5_get_credentials (_gsskrb5_context,
				 0,
				 ccache,
				 &this_cred,
				 &cred);

    if (kret) {
	_gsskrb5_set_error_string ();
	*minor_status = kret;
	ret = GSS_S_FAILURE;
	goto failure;
    }

    ctx->lifetime = cred->times.endtime;

    ret = _gsskrb5_lifetime_left(minor_status,
			       ctx->lifetime,
			       &lifetime_rec);
    if (ret) {
	goto failure;
    }

    if (lifetime_rec == 0) {
	*minor_status = 0;
	ret = GSS_S_CONTEXT_EXPIRED;
	goto failure;
    }

    krb5_auth_con_setkey(_gsskrb5_context, 
			 ctx->auth_context, 
			 &cred->session);

    kret = krb5_auth_con_generatelocalsubkey(_gsskrb5_context, 
					     ctx->auth_context,
					     &cred->session);
    if(kret) {
	_gsskrb5_set_error_string ();
	*minor_status = kret;
	ret = GSS_S_FAILURE;
	goto failure;
    }
    
    /* 
     * If the credential doesn't have ok-as-delegate, check what local
     * policy say about ok-as-delegate, default is FALSE that makes
     * code ignore the KDC setting and follow what the application
     * requested. If its TRUE, strip of the GSS_C_DELEG_FLAG if the
     * KDC doesn't set ok-as-delegate.
     */
    if (!cred->flags.b.ok_as_delegate) {
	krb5_boolean delegate;
    
	krb5_appdefault_boolean(_gsskrb5_context,
				"gssapi", name->realm,
				"ok-as-delegate", FALSE, &delegate);
	if (delegate)
	    req_flags &= ~GSS_C_DELEG_FLAG;
    }

    flags = 0;
    ap_options = 0;
    if (req_flags & GSS_C_DELEG_FLAG)
	do_delegation (ctx->auth_context,
		       ccache, cred, name, &fwd_data, &flags);
    
    if (req_flags & GSS_C_MUTUAL_FLAG) {
	flags |= GSS_C_MUTUAL_FLAG;
	ap_options |= AP_OPTS_MUTUAL_REQUIRED;
    }
    
    if (req_flags & GSS_C_REPLAY_FLAG)
	flags |= GSS_C_REPLAY_FLAG;
    if (req_flags & GSS_C_SEQUENCE_FLAG)
	flags |= GSS_C_SEQUENCE_FLAG;
    if (req_flags & GSS_C_ANON_FLAG)
	;                               /* XXX */
    flags |= GSS_C_CONF_FLAG;
    flags |= GSS_C_INTEG_FLAG;
    flags |= GSS_C_TRANS_FLAG;
    
    if (ret_flags)
	*ret_flags = flags;
    ctx->flags = flags;
    ctx->more_flags |= LOCAL;
    
    ret = _gsskrb5_create_8003_checksum (minor_status,
					 input_chan_bindings,
					 flags,
					 &fwd_data,
					 &cksum);
    krb5_data_free (&fwd_data);
    if (ret)
	goto failure;

    enctype = ctx->auth_context->keyblock->keytype;

    kret = krb5_build_authenticator (_gsskrb5_context,
				     ctx->auth_context,
				     enctype,
				     cred,
				     &cksum,
				     NULL,
				     &authenticator,
				     KRB5_KU_AP_REQ_AUTH);

    if (kret) {
	_gsskrb5_set_error_string ();
	*minor_status = kret;
	ret = GSS_S_FAILURE;
	goto failure;
    }

    kret = krb5_build_ap_req (_gsskrb5_context,
			      enctype,
			      cred,
			      ap_options,
			      authenticator,
			      &outbuf);

    if (kret) {
	_gsskrb5_set_error_string ();
	*minor_status = kret;
	ret = GSS_S_FAILURE;
	goto failure;
    }

    ret = _gsskrb5_encapsulate (minor_status, &outbuf, output_token,
				   (u_char *)"\x01\x00", GSS_KRB5_MECHANISM);
    if (ret)
	goto failure;

    krb5_data_free (&outbuf);
    krb5_free_creds(_gsskrb5_context, cred);
    free_Checksum(&cksum);
    if (initiator_cred_handle == NULL)
	krb5_cc_close(_gsskrb5_context, ccache);

    if (flags & GSS_C_MUTUAL_FLAG) {
	*context_handle = (gss_ctx_id_t)ctx;
	return GSS_S_CONTINUE_NEEDED;
    } else {
	int32_t seq_number;
	int is_cfx = 0;
	
	krb5_auth_getremoteseqnumber (_gsskrb5_context,
				      ctx->auth_context,
				      &seq_number);

	_gsskrb5i_is_cfx(ctx, &is_cfx);

	ret = _gssapi_msg_order_create(minor_status,
				       &ctx->order,
				       _gssapi_msg_order_f(flags),
				       seq_number, 0, is_cfx);
	if (ret)
	    goto failure;

	if (time_rec)
	    *time_rec = lifetime_rec;

	ctx->more_flags |= OPEN;
	*context_handle = (gss_ctx_id_t)ctx;
	return GSS_S_COMPLETE;
    }

failure:
    krb5_auth_con_free (_gsskrb5_context,
			ctx->auth_context);
    krb5_data_free (&outbuf);
    if(cred)
	krb5_free_creds(_gsskrb5_context, cred);
    if (ccache && initiator_cred_handle == NULL)
	krb5_cc_close(_gsskrb5_context, ccache);
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
    *context_handle = GSS_C_NO_CONTEXT;
    return ret;
}

static OM_uint32
repl_mutual
           (OM_uint32 * minor_status,
	    const gsskrb5_cred initiator_cred_handle,
            gss_ctx_id_t * context_handle,
            const gss_OID mech_type,
            OM_uint32 req_flags,
            OM_uint32 time_req,
            const gss_channel_bindings_t input_chan_bindings,
            const gss_buffer_t input_token,
            gss_OID * actual_mech_type,
            gss_buffer_t output_token,
            OM_uint32 * ret_flags,
            OM_uint32 * time_rec
           )
{
    OM_uint32 ret;
    int32_t seq_number;
    krb5_error_code kret;
    krb5_data indata;
    krb5_ap_rep_enc_part *repl;
    int is_cfx = 0;
    gsskrb5_ctx ctx = (gsskrb5_ctx) *context_handle;

    output_token->length = 0;
    output_token->value = NULL;

    HEIMDAL_MUTEX_lock(&ctx->ctx_id_mutex);

    if (actual_mech_type)
	*actual_mech_type = GSS_KRB5_MECHANISM;

    ret = _gsskrb5_decapsulate (minor_status, input_token, &indata,
				   "\x02\x00", GSS_KRB5_MECHANISM);
    if (ret) {
	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
	/* XXX - Handle AP_ERROR */
	return ret;
    }
    
    kret = krb5_rd_rep (_gsskrb5_context,
			ctx->auth_context,
			&indata,
			&repl);
    if (kret) {
	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
	_gsskrb5_set_error_string ();
	*minor_status = kret;
	return GSS_S_FAILURE;
    }
    krb5_free_ap_rep_enc_part (_gsskrb5_context,
			       repl);
    
    krb5_auth_getremoteseqnumber (_gsskrb5_context,
				  ctx->auth_context,
				  &seq_number);

    _gsskrb5i_is_cfx(ctx, &is_cfx);

    ret = _gssapi_msg_order_create(minor_status,
				   &ctx->order,
				   _gssapi_msg_order_f(ctx->flags),
				   seq_number, 0, is_cfx);
    if (ret) {
	HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
	return ret;
    }
	
    ctx->more_flags |= OPEN;

    *minor_status = 0;
    if (time_rec) {
	ret = _gsskrb5_lifetime_left(minor_status,
				   ctx->lifetime,
				   time_rec);
    } else {
	ret = GSS_S_COMPLETE;
    }
    if (ret_flags)
	*ret_flags = ctx->flags;
    HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);

    return ret;
}

/*
 * gss_init_sec_context
 */

OM_uint32 _gsskrb5_init_sec_context
(OM_uint32 * minor_status,
 const gss_cred_id_t initiator_cred_handle,
 gss_ctx_id_t * context_handle,
 const gss_name_t target_name,
 const gss_OID mech_type,
 OM_uint32 req_flags,
 OM_uint32 time_req,
 const gss_channel_bindings_t input_chan_bindings,
 const gss_buffer_t input_token,
 gss_OID * actual_mech_type,
 gss_buffer_t output_token,
 OM_uint32 * ret_flags,
 OM_uint32 * time_rec
    )
{
    gsskrb5_cred cred = (gsskrb5_cred)initiator_cred_handle;
    krb5_const_principal name = (krb5_const_principal)target_name;

    GSSAPI_KRB5_INIT ();

    output_token->length = 0;
    output_token->value  = NULL;

    if (ret_flags)
	*ret_flags = 0;
    if (time_rec)
	*time_rec = 0;

    if (target_name == GSS_C_NO_NAME) {
	if (actual_mech_type)
	    *actual_mech_type = GSS_C_NO_OID;
	*minor_status = 0;
	return GSS_S_BAD_NAME;
    }

    if (mech_type != GSS_C_NO_OID && 
	!gss_oid_equal(mech_type, GSS_KRB5_MECHANISM))
	return GSS_S_BAD_MECH;


    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0)
	return init_auth (minor_status,
			  cred,
			  context_handle,
			  name,
			  mech_type,
			  req_flags,
			  time_req,
			  input_chan_bindings,
			  input_token,
			  actual_mech_type,
			  output_token,
			  ret_flags,
			  time_rec);
    else
	return repl_mutual(minor_status,
			   cred,
			   context_handle,
			   mech_type,
			   req_flags,
			   time_req,
			   input_chan_bindings,
			   input_token,
			   actual_mech_type,
			   output_token,
			   ret_flags,
			   time_rec);
}
