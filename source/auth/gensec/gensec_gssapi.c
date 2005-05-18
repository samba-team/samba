/* 
   Unix SMB/CIFS implementation.

   Kerberos backend for GENSEC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/kerberos.h"
#include "system/network.h"
#include "auth/kerberos/kerberos.h"
#include "librpc/gen_ndr/ndr_krb5pac.h"
#include "auth/auth.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

struct gensec_gssapi_state {
	gss_ctx_id_t gssapi_context;
	struct gss_channel_bindings_struct *input_chan_bindings;
	gss_name_t server_name;
	gss_name_t client_name;
	OM_uint32 want_flags, got_flags;
	const gss_OID_desc *gss_oid;

	DATA_BLOB session_key;
	DATA_BLOB pac;

	krb5_context krb5_context;
	krb5_ccache ccache;
	const char *ccache_name;

	gss_cred_id_t cred;
};

static char *gssapi_error_string(TALLOC_CTX *mem_ctx, 
				 OM_uint32 maj_stat, OM_uint32 min_stat)
{
	OM_uint32 disp_min_stat, disp_maj_stat;
	gss_buffer_desc maj_error_message;
	gss_buffer_desc min_error_message;
	OM_uint32 msg_ctx = 0;

	char *ret;

	maj_error_message.value = NULL;
	min_error_message.value = NULL;
	
	disp_maj_stat = gss_display_status(&disp_min_stat, maj_stat, GSS_C_GSS_CODE,
			   GSS_C_NULL_OID, &msg_ctx, &maj_error_message);
	disp_maj_stat = gss_display_status(&disp_min_stat, min_stat, GSS_C_MECH_CODE,
			   GSS_C_NULL_OID, &msg_ctx, &min_error_message);
	ret = talloc_asprintf(mem_ctx, "%s: %s", (char *)maj_error_message.value, (char *)min_error_message.value);

	gss_release_buffer(&disp_min_stat, &maj_error_message);
	gss_release_buffer(&disp_min_stat, &min_error_message);

	return ret;
}


static int gensec_gssapi_destory(void *ptr) 
{
	struct gensec_gssapi_state *gensec_gssapi_state = ptr;
	OM_uint32 maj_stat, min_stat;
	
	if (gensec_gssapi_state->cred != GSS_C_NO_CREDENTIAL) {
		maj_stat = gss_release_cred(&min_stat, 
					    &gensec_gssapi_state->cred);
	}

	if (gensec_gssapi_state->gssapi_context != GSS_C_NO_CONTEXT) {
		maj_stat = gss_delete_sec_context (&min_stat,
						   &gensec_gssapi_state->gssapi_context,
						   GSS_C_NO_BUFFER);
	}

	if (gensec_gssapi_state->server_name != GSS_C_NO_NAME) {
		maj_stat = gss_release_name(&min_stat, &gensec_gssapi_state->server_name);
	}
	if (gensec_gssapi_state->client_name != GSS_C_NO_NAME) {
		maj_stat = gss_release_name(&min_stat, &gensec_gssapi_state->client_name);
	}
	if (gensec_gssapi_state->krb5_context) {
		krb5_free_context(gensec_gssapi_state->krb5_context);
	}
	return 0;
}

static NTSTATUS gensec_gssapi_start(struct gensec_security *gensec_security)
{
	struct gensec_gssapi_state *gensec_gssapi_state;
	krb5_error_code ret;
	
	gensec_gssapi_state = talloc(gensec_security, struct gensec_gssapi_state);
	if (!gensec_gssapi_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_security->private_data = gensec_gssapi_state;

	gensec_gssapi_state->gssapi_context = GSS_C_NO_CONTEXT;
	gensec_gssapi_state->server_name = GSS_C_NO_NAME;
	gensec_gssapi_state->client_name = GSS_C_NO_NAME;

	/* TODO: Fill in channel bindings */
	gensec_gssapi_state->input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;
	
	gensec_gssapi_state->want_flags = 0;
	gensec_gssapi_state->got_flags = 0;

	gensec_gssapi_state->session_key = data_blob(NULL, 0);
	gensec_gssapi_state->pac = data_blob(NULL, 0);

	gensec_gssapi_state->krb5_context = NULL;

	gensec_gssapi_state->cred = GSS_C_NO_CREDENTIAL;

	talloc_set_destructor(gensec_gssapi_state, gensec_gssapi_destory); 

	if (gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
#ifndef HAVE_GSSKRB5_GET_INITIATOR_SUBKEY
		/* GSSAPI won't give us the session keys, without the
		 * right hooks.  This is critical when requested, so
		 * fail outright. */
		return NT_STATUS_INVALID_PARAMETER;
#endif
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		gensec_gssapi_state->want_flags |= GSS_C_INTEG_FLAG;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		gensec_gssapi_state->want_flags |= GSS_C_CONF_FLAG;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_DCE_STYLE) {
#ifndef GSS_C_DCE_STYLE
		/* GSSAPI DCE_STYLE is critical when requested, so
		 * fail outright */
		return NT_STATUS_INVALID_PARAMETER;
#else
		gensec_gssapi_state->want_flags |= GSS_C_DCE_STYLE;
#endif
	}

	gensec_gssapi_state->gss_oid = gss_mech_krb5;
	
	ret = krb5_init_context(&gensec_gssapi_state->krb5_context);
	if (ret) {
		DEBUG(1,("gensec_krb5_start: krb5_init_context failed (%s)\n", 					
			 smb_get_krb5_error_message(gensec_gssapi_state->krb5_context, 
						    ret, gensec_gssapi_state)));
		return NT_STATUS_INTERNAL_ERROR;
	}
	
	if (lp_realm() && *lp_realm()) {
		char *upper_realm = strupper_talloc(gensec_gssapi_state, lp_realm());
		if (!upper_realm) {
			DEBUG(1,("gensec_krb5_start: could not uppercase realm: %s\n", lp_realm()));
			return NT_STATUS_NO_MEMORY;
		}
		ret = krb5_set_default_realm(gensec_gssapi_state->krb5_context, upper_realm);
		if (ret) {
			DEBUG(1,("gensec_krb5_start: krb5_set_default_realm failed (%s)\n", 
				 smb_get_krb5_error_message(gensec_gssapi_state->krb5_context, 
							    ret, gensec_gssapi_state)));
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_server_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	struct gensec_gssapi_state *gensec_gssapi_state;

	nt_status = gensec_gssapi_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_gssapi_state = gensec_security->private_data;

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_client_start(struct gensec_security *gensec_security)
{
	struct gensec_gssapi_state *gensec_gssapi_state;
	NTSTATUS nt_status;
	gss_buffer_desc name_token;
	OM_uint32 maj_stat, min_stat;
	const char *ccache_name;

	nt_status = gensec_gssapi_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_gssapi_state = gensec_security->private_data;

	name_token.value = talloc_asprintf(gensec_gssapi_state, "%s@%s", gensec_get_target_service(gensec_security), 
					   gensec_get_target_hostname(gensec_security));
	name_token.length = strlen(name_token.value);

	maj_stat = gss_import_name (&min_stat,
				    &name_token,
				    GSS_C_NT_HOSTBASED_SERVICE,
				    &gensec_gssapi_state->server_name);
	if (maj_stat) {
		DEBUG(1, ("GSS Import name of %s failed: %s\n",
			  (char *)name_token.value,
			  gssapi_error_string(gensec_gssapi_state, maj_stat, min_stat)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	name_token.value = cli_credentials_get_principal(gensec_get_credentials(gensec_security), gensec_gssapi_state),
	name_token.length = strlen(name_token.value);

	maj_stat = gss_import_name (&min_stat,
				    &name_token,
				    GSS_C_NT_USER_NAME,
				    &gensec_gssapi_state->client_name);
	if (maj_stat) {
		DEBUG(1, ("GSS Import name of %s failed: %s\n",
			  (char *)name_token.value,
			  gssapi_error_string(gensec_gssapi_state, maj_stat, min_stat)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	initialize_krb5_error_table();
	
	nt_status = kinit_to_ccache(gensec_gssapi_state, 
				    gensec_get_credentials(gensec_security),
				    gensec_gssapi_state->krb5_context, 
				    &gensec_gssapi_state->ccache, &gensec_gssapi_state->ccache_name);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

#ifdef HAVE_GSS_KRB5_CCACHE_NAME /* FIXME, we need an alternate function */
	maj_stat = gss_krb5_ccache_name(&min_stat, 
					gensec_gssapi_state->ccache_name, 
					NULL);
	if (maj_stat) {
		DEBUG(1, ("GSS krb5 ccache set %s failed: %s\n",
			  ccache_name,
			  gssapi_error_string(gensec_gssapi_state, maj_stat, min_stat)));
		return NT_STATUS_UNSUCCESSFUL;
	}
#endif

	maj_stat = gss_acquire_cred(&min_stat, 
				    gensec_gssapi_state->client_name,
				    GSS_C_INDEFINITE,
				    GSS_C_NULL_OID_SET,
				    GSS_C_INITIATE,
				    &gensec_gssapi_state->cred,
				    NULL, 
				    NULL);
	if (maj_stat) {
		DEBUG(1, ("Aquiring initiator credentails failed: %s\n", 
			  gssapi_error_string(gensec_gssapi_state, maj_stat, min_stat)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}



/**
 * Next state function for the GSSAPI GENSEC mechanism
 * 
 * @param gensec_gssapi_state GSSAPI State
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent, 
 *                or NT_STATUS_OK if the user is authenticated. 
 */

static NTSTATUS gensec_gssapi_update(struct gensec_security *gensec_security, 
				   TALLOC_CTX *out_mem_ctx, 
				   const DATA_BLOB in, DATA_BLOB *out) 
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	OM_uint32 maj_stat, min_stat;
	OM_uint32 min_stat2;
	gss_buffer_desc input_token, output_token;
	gss_OID gss_oid_p;
	input_token.length = in.length;
	input_token.value = in.data;

	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
	{
		maj_stat = gss_init_sec_context(&min_stat, 
						GSS_C_NO_CREDENTIAL, 
						&gensec_gssapi_state->gssapi_context, 
						gensec_gssapi_state->server_name, 
						discard_const_p(gss_OID_desc, gensec_gssapi_state->gss_oid),
						gensec_gssapi_state->want_flags, 
						0, 
						gensec_gssapi_state->input_chan_bindings,
						&input_token, 
						NULL, 
						&output_token, 
						&gensec_gssapi_state->got_flags, /* ret flags */
						NULL);
		break;
	}
	case GENSEC_SERVER:
	{
		maj_stat = gss_accept_sec_context(&min_stat, 
						  &gensec_gssapi_state->gssapi_context, 
						  GSS_C_NO_CREDENTIAL, 
						  &input_token, 
						  gensec_gssapi_state->input_chan_bindings,
						  &gensec_gssapi_state->client_name, 
						  &gss_oid_p,
						  &output_token, 
						  &gensec_gssapi_state->got_flags, 
						  NULL, 
						  NULL);
		gensec_gssapi_state->gss_oid = gss_oid_p;
		break;
	}
	default:
		return NT_STATUS_INVALID_PARAMETER;
		
	}

	*out = data_blob_talloc(out_mem_ctx, output_token.value, output_token.length);
	gss_release_buffer(&min_stat2, &output_token);

	if (maj_stat == GSS_S_COMPLETE) {
		return NT_STATUS_OK;
	} else if (maj_stat == GSS_S_CONTINUE_NEEDED) {
		return NT_STATUS_MORE_PROCESSING_REQUIRED;
	} else {
		if (maj_stat == GSS_S_FAILURE
		    && (min_stat == KRB5KRB_AP_ERR_BADVERSION || min_stat == KRB5KRB_AP_ERR_MSG_TYPE)) {
			/* garbage input, possibly from the auto-mech detection */
			return NT_STATUS_INVALID_PARAMETER;
		}
		DEBUG(1, ("GSS Update failed: %s\n", 
			  gssapi_error_string(out_mem_ctx, maj_stat, min_stat)));
		return nt_status;
	}
}

static NTSTATUS gensec_gssapi_wrap(struct gensec_security *gensec_security, 
				   TALLOC_CTX *mem_ctx, 
				   const DATA_BLOB *in, 
				   DATA_BLOB *out)
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	input_token.length = in->length;
	input_token.value = in->data;
	
	maj_stat = gss_wrap(&min_stat, 
			    gensec_gssapi_state->gssapi_context, 
			    gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL),
			    GSS_C_QOP_DEFAULT,
			    &input_token,
			    &conf_state,
			    &output_token);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("GSS Wrap failed: %s\n", 
			  gssapi_error_string(mem_ctx, maj_stat, min_stat)));
		return NT_STATUS_ACCESS_DENIED;
	}
	*out = data_blob_talloc(mem_ctx, output_token.value, output_token.length);

	gss_release_buffer(&min_stat, &output_token);

	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)
	    && !conf_state) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_unwrap(struct gensec_security *gensec_security, 
				     TALLOC_CTX *mem_ctx, 
				     const DATA_BLOB *in, 
				     DATA_BLOB *out)
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	gss_qop_t qop_state;
	input_token.length = in->length;
	input_token.value = in->data;
	
	maj_stat = gss_unwrap(&min_stat, 
			      gensec_gssapi_state->gssapi_context, 
			      &input_token,
			      &output_token, 
			      &conf_state,
			      &qop_state);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("GSS UnWrap failed: %s\n", 
			  gssapi_error_string(mem_ctx, maj_stat, min_stat)));
		return NT_STATUS_ACCESS_DENIED;
	}
	*out = data_blob_talloc(mem_ctx, output_token.value, output_token.length);

	gss_release_buffer(&min_stat, &output_token);
	
	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)
	    && !conf_state) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static size_t gensec_gssapi_sig_size(struct gensec_security *gensec_security) 
{
	/* not const but work for DCERPC packets and arcfour */
	return 45;
}

static NTSTATUS gensec_gssapi_seal_packet(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx, 
					  uint8_t *data, size_t length, 
					  const uint8_t *whole_pdu, size_t pdu_length, 
					  DATA_BLOB *sig)
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	ssize_t sig_length = 0;

	input_token.length = length;
	input_token.value = data;
	
	maj_stat = gss_wrap(&min_stat, 
			    gensec_gssapi_state->gssapi_context,
			    gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL),
			    GSS_C_QOP_DEFAULT,
			    &input_token,
			    &conf_state,
			    &output_token);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("GSS Wrap failed: %s\n", 
			  gssapi_error_string(mem_ctx, maj_stat, min_stat)));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (output_token.length < length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	sig_length = 45;

	memcpy(data, ((uint8_t *)output_token.value) + sig_length, length);
	*sig = data_blob_talloc(mem_ctx, (uint8_t *)output_token.value, sig_length);

	dump_data_pw("gensec_gssapi_seal_packet: sig\n", sig->data, sig->length);
	dump_data_pw("gensec_gssapi_seal_packet: clear\n", data, length);
	dump_data_pw("gensec_gssapi_seal_packet: sealed\n", ((uint8_t *)output_token.value) + sig_length, output_token.length - sig_length);

	gss_release_buffer(&min_stat, &output_token);

	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)
	    && !conf_state) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_unseal_packet(struct gensec_security *gensec_security, 
					    TALLOC_CTX *mem_ctx, 
					    uint8_t *data, size_t length, 
					    const uint8_t *whole_pdu, size_t pdu_length,
					    const DATA_BLOB *sig)
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	gss_qop_t qop_state;
	DATA_BLOB in;

	dump_data_pw("gensec_gssapi_seal_packet: sig\n", sig->data, sig->length);

	in = data_blob_talloc(mem_ctx, NULL, sig->length + length);

	memcpy(in.data, sig->data, sig->length);
	memcpy(in.data + sig->length, data, length);

	input_token.length = in.length;
	input_token.value = in.data;
	
	maj_stat = gss_unwrap(&min_stat, 
			      gensec_gssapi_state->gssapi_context, 
			      &input_token,
			      &output_token, 
			      &conf_state,
			      &qop_state);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("GSS UnWrap failed: %s\n", 
			  gssapi_error_string(mem_ctx, maj_stat, min_stat)));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (output_token.length != length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	memcpy(data, output_token.value, length);

	gss_release_buffer(&min_stat, &output_token);
	
	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)
	    && !conf_state) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_sign_packet(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx, 
					  const uint8_t *data, size_t length, 
					  const uint8_t *whole_pdu, size_t pdu_length, 
					  DATA_BLOB *sig)
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	ssize_t sig_length = 0;

	input_token.length = length;
	input_token.value = discard_const_p(uint8_t *, data);

	maj_stat = gss_wrap(&min_stat, 
			    gensec_gssapi_state->gssapi_context,
			    0,
			    GSS_C_QOP_DEFAULT,
			    &input_token,
			    &conf_state,
			    &output_token);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("GSS Wrap failed: %s\n", 
			  gssapi_error_string(mem_ctx, maj_stat, min_stat)));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (output_token.length < length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	sig_length = 45;

	/*memcpy(data, ((uint8_t *)output_token.value) + sig_length, length);*/
	*sig = data_blob_talloc(mem_ctx, (uint8_t *)output_token.value, sig_length);

	dump_data_pw("gensec_gssapi_seal_packet: sig\n", sig->data, sig->length);

	gss_release_buffer(&min_stat, &output_token);

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gssapi_check_packet(struct gensec_security *gensec_security, 
					   TALLOC_CTX *mem_ctx, 
					   const uint8_t *data, size_t length, 
					   const uint8_t *whole_pdu, size_t pdu_length, 
					   const DATA_BLOB *sig)
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	gss_qop_t qop_state;
	DATA_BLOB in;

	dump_data_pw("gensec_gssapi_seal_packet: sig\n", sig->data, sig->length);

	in = data_blob_talloc(mem_ctx, NULL, sig->length + length);

	memcpy(in.data, sig->data, sig->length);
	memcpy(in.data + sig->length, data, length);

	input_token.length = in.length;
	input_token.value = in.data;
	
	maj_stat = gss_unwrap(&min_stat, 
			      gensec_gssapi_state->gssapi_context, 
			      &input_token,
			      &output_token, 
			      &conf_state,
			      &qop_state);
	if (GSS_ERROR(maj_stat)) {
		DEBUG(1, ("GSS UnWrap failed: %s\n", 
			  gssapi_error_string(mem_ctx, maj_stat, min_stat)));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (output_token.length != length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	gss_release_buffer(&min_stat, &output_token);

	return NT_STATUS_OK;
}

static BOOL gensec_gssapi_have_feature(struct gensec_security *gensec_security, 
				       uint32_t feature) 
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	if (feature & GENSEC_FEATURE_SIGN) {
		return gensec_gssapi_state->got_flags & GSS_C_INTEG_FLAG;
	}
	if (feature & GENSEC_FEATURE_SEAL) {
		return gensec_gssapi_state->got_flags & GSS_C_CONF_FLAG;
	}
	if (feature & GENSEC_FEATURE_SESSION_KEY) {
#ifdef HAVE_GSSKRB5_GET_INITIATOR_SUBKEY
		if ((gensec_gssapi_state->gss_oid->length == gss_mech_krb5->length)
		    && (memcmp(gensec_gssapi_state->gss_oid->elements, gss_mech_krb5->elements, gensec_gssapi_state->gss_oid->length) == 0)) {
			return True;
		}
#endif 
	}
	return False;
}

static NTSTATUS gensec_gssapi_session_key(struct gensec_security *gensec_security, 
					  DATA_BLOB *session_key) 
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	
	if (gensec_gssapi_state->session_key.data) {
		*session_key = gensec_gssapi_state->session_key;
		return NT_STATUS_OK;
	}

#ifdef HAVE_GSSKRB5_GET_INITIATOR_SUBKEY
	/* Ensure we only call this for GSSAPI/krb5, otherwise things could get very ugly */
	if ((gensec_gssapi_state->gss_oid->length == gss_mech_krb5->length)
	    && (memcmp(gensec_gssapi_state->gss_oid->elements, gss_mech_krb5->elements, 
		       gensec_gssapi_state->gss_oid->length) == 0)) {
		OM_uint32 maj_stat, min_stat;
		gss_buffer_desc skey;
		
		maj_stat = gsskrb5_get_initiator_subkey(&min_stat, 
							gensec_gssapi_state->gssapi_context, 
							&skey);
		
		if (maj_stat == 0) {
			DEBUG(10, ("Got KRB5 session key of length %d\n",  skey.length));
			gensec_gssapi_state->session_key = data_blob_talloc(gensec_gssapi_state, 
									    skey.value, skey.length);
			*session_key = gensec_gssapi_state->session_key;
			dump_data_pw("KRB5 Session Key:\n", session_key->data, session_key->length);
			
			gss_release_buffer(&min_stat, &skey);
			return NT_STATUS_OK;
		}
		return NT_STATUS_NO_USER_SESSION_KEY;
	}
#endif
	
	DEBUG(1, ("NO session key for this mech\n"));
	return NT_STATUS_NO_USER_SESSION_KEY;
}

static NTSTATUS gensec_gssapi_session_info(struct gensec_security *gensec_security,
					 struct auth_session_info **_session_info) 
{
	NTSTATUS nt_status;
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	struct auth_serversupplied_info *server_info = NULL;
	struct auth_session_info *session_info = NULL;
	char *p;
	char *principal;
	const char *account_name;
	const char *realm;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc name_token;
	
	maj_stat = gss_display_name (&min_stat,
				     gensec_gssapi_state->client_name,
				     &name_token,
				     NULL);
	if (maj_stat) {
		return NT_STATUS_FOOBAR;
	}

	principal = talloc_strndup(gensec_gssapi_state, name_token.value, name_token.length);

	gss_release_buffer(&min_stat, &name_token);

	NT_STATUS_HAVE_NO_MEMORY(principal);

	p = strchr(principal, '@');
	if (p) {
		*p = '\0';
		p++;
		realm = p;
	} else {
		realm = lp_realm();
	}
	account_name = principal;

	/* IF we have the PAC - otherwise we need to get this
	 * data from elsewere - local ldb, or (TODO) lookup of some
	 * kind... 
	 *
	 * when heimdal can generate the PAC, we should fail if there's
	 * no PAC present
	 */

	{
		DATA_BLOB user_sess_key = data_blob(NULL, 0);
		DATA_BLOB lm_sess_key = data_blob(NULL, 0);
		/* TODO: should we pass the krb5 session key in here? */
		nt_status = sam_get_server_info(gensec_gssapi_state, account_name, realm,
						user_sess_key, lm_sess_key,
						&server_info);
		talloc_free(principal);
		NT_STATUS_NOT_OK_RETURN(nt_status);
	}

	/* references the server_info into the session_info */
	nt_status = auth_generate_session_info(gensec_gssapi_state, server_info, &session_info);
	talloc_free(server_info);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	nt_status = gensec_gssapi_session_key(gensec_security, &session_info->session_key);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	*_session_info = session_info;

	return NT_STATUS_OK;
}

static const char *gensec_krb5_oids[] = { 
	GENSEC_OID_KERBEROS5,
	GENSEC_OID_KERBEROS5_OLD,
	NULL 
};

/* As a server, this could in theory accept any GSSAPI mech */
static const struct gensec_security_ops gensec_gssapi_krb5_security_ops = {
	.name		= "gssapi_krb5",
	.oid            = gensec_krb5_oids,
	.client_start   = gensec_gssapi_client_start,
	.server_start   = gensec_gssapi_server_start,
	.update 	= gensec_gssapi_update,
	.session_key	= gensec_gssapi_session_key,
	.session_info	= gensec_gssapi_session_info,
	.sig_size	= gensec_gssapi_sig_size,
	.sign_packet	= gensec_gssapi_sign_packet,
	.check_packet	= gensec_gssapi_check_packet,
	.seal_packet	= gensec_gssapi_seal_packet,
	.unseal_packet	= gensec_gssapi_unseal_packet,
	.wrap           = gensec_gssapi_wrap,
	.unwrap         = gensec_gssapi_unwrap,
	.have_feature   = gensec_gssapi_have_feature,
	.enabled        = False
};

NTSTATUS gensec_gssapi_init(void)
{
	NTSTATUS ret;

	ret = gensec_register(&gensec_gssapi_krb5_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_gssapi_krb5_security_ops.name));
		return ret;
	}

	return ret;
}
