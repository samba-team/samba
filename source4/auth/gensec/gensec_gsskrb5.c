/* 
   Unix SMB/CIFS implementation.

   GSSAPI KRB5 backend for GENSEC
   
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
#include "system/time.h"
#include "auth/kerberos/kerberos.h"
#include "auth/auth.h"

static const gss_OID_desc gensec_gss_krb5_mechanism_oid_desc =
			{9, (void *)discard_const_p(char, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")};

enum GENSEC_GSSKRB5_STATE {
	GENSEC_GSSKRB5_CLIENT_START,
	GENSEC_GSSKRB5_CLIENT_MUTUAL_AUTH,
	GENSEC_GSSKRB5_CLIENT_DCE_STYLE,
	GENSEC_GSSKRB5_DONE
};

struct gensec_gsskrb5_state {
	enum GENSEC_GSSKRB5_STATE state_position;
	gss_ctx_id_t gssapi_context;
	struct gss_channel_bindings_struct *input_chan_bindings;
	gss_name_t server_name;
	gss_name_t client_name;
	OM_uint32 want_flags, got_flags;
};

static int gensec_gsskrb5_destory(void *ptr) 
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = ptr;
	OM_uint32 maj_stat, min_stat;

	if (gensec_gsskrb5_state->gssapi_context != GSS_C_NO_CONTEXT) {
		maj_stat = gss_delete_sec_context (&min_stat,
						   &gensec_gsskrb5_state->gssapi_context,
						   GSS_C_NO_BUFFER);
	}

	if (gensec_gsskrb5_state->server_name != GSS_C_NO_NAME) {
		maj_stat = gss_release_name(&min_stat, &gensec_gsskrb5_state->server_name);
	}
	if (gensec_gsskrb5_state->client_name != GSS_C_NO_NAME) {
		maj_stat = gss_release_name(&min_stat, &gensec_gsskrb5_state->client_name);
	}
	return 0;
}

static NTSTATUS gensec_gsskrb5_start(struct gensec_security *gensec_security)
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state;

	gensec_gsskrb5_state = talloc(gensec_security, struct gensec_gsskrb5_state);
	if (!gensec_gsskrb5_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_security->private_data = gensec_gsskrb5_state;

	gensec_gsskrb5_state->gssapi_context = GSS_C_NO_CONTEXT;
	gensec_gsskrb5_state->server_name = GSS_C_NO_NAME;
	gensec_gsskrb5_state->client_name = GSS_C_NO_NAME;

	talloc_set_destructor(gensec_gsskrb5_state, gensec_gsskrb5_destory); 

	/* TODO: Fill in channel bindings */
	gensec_gsskrb5_state->input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;
	
	gensec_gsskrb5_state->want_flags = GSS_C_MUTUAL_FLAG;
	gensec_gsskrb5_state->got_flags = 0;

	if (gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		/* GSSAPI won't give us the session keys */
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		gensec_gsskrb5_state->want_flags |= GSS_C_INTEG_FLAG;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		gensec_gsskrb5_state->want_flags |= GSS_C_CONF_FLAG;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_DCE_STYLE) {
		gensec_gsskrb5_state->want_flags |= GSS_C_DCE_STYLE;
	}

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gsskrb5_client_start(struct gensec_security *gensec_security)
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state;
	NTSTATUS nt_status;
	gss_buffer_desc name_token;
	OM_uint32 maj_stat, min_stat;

	gss_OID_desc hostbased = {10, 
				  (void *)discard_const_p(char, "\x2a\x86\x48\x86\xf7\x12"
							  "\x01\x02\x01\x04")};

	nt_status = gensec_gsskrb5_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_gsskrb5_state = gensec_security->private_data;

	gensec_gsskrb5_state->state_position = GENSEC_GSSKRB5_CLIENT_START;

	name_token.value = talloc_asprintf(gensec_gsskrb5_state, "%s@%s", gensec_get_target_service(gensec_security), 
					   gensec_get_target_hostname(gensec_security));
	DEBUG(0, ("name: %s\n", (char *)name_token.value));
	name_token.length = strlen(name_token.value);

	maj_stat = gss_import_name (&min_stat,
				    &name_token,
				    &hostbased,
				    &gensec_gsskrb5_state->server_name);
	if (maj_stat) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

/**
 * Next state function for the GSSKRB5 GENSEC mechanism
 * 
 * @param gensec_gsskrb5_state GSSAPI State
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent, 
 *                or NT_STATUS_OK if the user is authenticated. 
 */

static NTSTATUS gensec_gsskrb5_update(struct gensec_security *gensec_security, 
				   TALLOC_CTX *out_mem_ctx, 
				   const DATA_BLOB in, DATA_BLOB *out) 
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = gensec_security->private_data;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	OM_uint32 maj_stat, min_stat;
	OM_uint32 min_stat2;
	gss_buffer_desc input_token, output_token;

	*out = data_blob(NULL, 0);

	input_token.length = in.length;
	input_token.value = in.data;

	switch (gensec_gsskrb5_state->state_position) {
	case GENSEC_GSSKRB5_CLIENT_START:
	{
		maj_stat = gss_init_sec_context(&min_stat, 
						GSS_C_NO_CREDENTIAL, 
						&gensec_gsskrb5_state->gssapi_context, 
						gensec_gsskrb5_state->server_name, 
						discard_const_p(gss_OID_desc, &gensec_gss_krb5_mechanism_oid_desc),
						gensec_gsskrb5_state->want_flags, 
						0, 
						gensec_gsskrb5_state->input_chan_bindings,
						&input_token, 
						NULL, 
						&output_token, 
						&gensec_gsskrb5_state->got_flags, /* ret flags */
						NULL);
		*out = data_blob_talloc(out_mem_ctx, output_token.value, output_token.length);
		if (out->length != output_token.length) {
			gss_release_buffer(&min_stat2, &output_token);
			return NT_STATUS_NO_MEMORY;
		}
		gss_release_buffer(&min_stat2, &output_token);

		if (maj_stat == GSS_S_COMPLETE) {
			gensec_gsskrb5_state->state_position = GENSEC_GSSKRB5_DONE;
			return NT_STATUS_OK;
		} else if (maj_stat == GSS_S_CONTINUE_NEEDED) {
			gensec_gsskrb5_state->state_position = GENSEC_GSSKRB5_CLIENT_MUTUAL_AUTH;
			return NT_STATUS_MORE_PROCESSING_REQUIRED;
		} else {
			gss_buffer_desc msg1, msg2;
			OM_uint32 msg_ctx = 0;

			msg1.value = NULL;
			msg2.value = NULL;
			gss_display_status(&min_stat2, maj_stat, GSS_C_GSS_CODE,
					   GSS_C_NULL_OID, &msg_ctx, &msg1);
			gss_display_status(&min_stat2, min_stat, GSS_C_MECH_CODE,
					   GSS_C_NULL_OID, &msg_ctx, &msg2);
			DEBUG(1, ("gensec_gsskrb5_update: %s : %s\n", (char *)msg1.value, (char *)msg2.value));
			gss_release_buffer(&min_stat2, &msg1);
			gss_release_buffer(&min_stat2, &msg2);

			return nt_status;
		}
		break;
	}
	case GENSEC_GSSKRB5_CLIENT_MUTUAL_AUTH:
	{
		maj_stat = gss_init_sec_context(&min_stat, 
						GSS_C_NO_CREDENTIAL, 
						&gensec_gsskrb5_state->gssapi_context, 
						gensec_gsskrb5_state->server_name, 
						discard_const_p(gss_OID_desc, &gensec_gss_krb5_mechanism_oid_desc),
						gensec_gsskrb5_state->want_flags, 
						0, 
						gensec_gsskrb5_state->input_chan_bindings,
						&input_token, 
						NULL, 
						&output_token, 
						&gensec_gsskrb5_state->got_flags, /* ret flags */
						NULL);
		*out = data_blob_talloc(out_mem_ctx, output_token.value, output_token.length);
		if (out->length != output_token.length) {
			gss_release_buffer(&min_stat2, &output_token);
			return NT_STATUS_NO_MEMORY;
		}
		gss_release_buffer(&min_stat2, &output_token);

		if (maj_stat == GSS_S_COMPLETE) {
			if (gensec_gsskrb5_state->got_flags & GSS_C_DCE_STYLE) {
				gensec_gsskrb5_state->state_position = GENSEC_GSSKRB5_CLIENT_DCE_STYLE;
				return NT_STATUS_MORE_PROCESSING_REQUIRED;	
			}
			gensec_gsskrb5_state->state_position = GENSEC_GSSKRB5_DONE;
			return NT_STATUS_OK;
		} else if (maj_stat == GSS_S_CONTINUE_NEEDED) {
			gensec_gsskrb5_state->state_position = GENSEC_GSSKRB5_CLIENT_DCE_STYLE;
			return NT_STATUS_MORE_PROCESSING_REQUIRED;
		} else {
			gss_buffer_desc msg1, msg2;
			OM_uint32 msg_ctx = 0;

			msg1.value = NULL;
			msg2.value = NULL;
			gss_display_status(&min_stat2, maj_stat, GSS_C_GSS_CODE,
					   GSS_C_NULL_OID, &msg_ctx, &msg1);
			gss_display_status(&min_stat2, min_stat, GSS_C_MECH_CODE,
					   GSS_C_NULL_OID, &msg_ctx, &msg2);
			DEBUG(1, ("gensec_gsskrb5_update: %s : %s\n", (char *)msg1.value, (char *)msg2.value));
			gss_release_buffer(&min_stat2, &msg1);
			gss_release_buffer(&min_stat2, &msg2);

			return nt_status;
		}
		break;
	}
	case GENSEC_GSSKRB5_CLIENT_DCE_STYLE:
	{
		gensec_gsskrb5_state->state_position = GENSEC_GSSKRB5_DONE;
		return NT_STATUS_OK;
	}
	case GENSEC_GSSKRB5_DONE:
	{
		return NT_STATUS_OK;
	}
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_INVALID_PARAMETER;
}

static NTSTATUS gensec_gsskrb5_wrap(struct gensec_security *gensec_security, 
				   TALLOC_CTX *mem_ctx, 
				   const DATA_BLOB *in, 
				   DATA_BLOB *out)
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	input_token.length = in->length;
	input_token.value = in->data;

	maj_stat = gss_wrap(&min_stat, 
			    gensec_gsskrb5_state->gssapi_context, 
			    gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL),
			    GSS_C_QOP_DEFAULT,
			    &input_token,
			    &conf_state,
			    &output_token);
	if (GSS_ERROR(maj_stat)) {
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

static NTSTATUS gensec_gsskrb5_unwrap(struct gensec_security *gensec_security, 
				     TALLOC_CTX *mem_ctx, 
				     const DATA_BLOB *in, 
				     DATA_BLOB *out)
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	gss_qop_t qop_state;
	input_token.length = in->length;
	input_token.value = in->data;
	
	maj_stat = gss_unwrap(&min_stat, 
			      gensec_gsskrb5_state->gssapi_context, 
			      &input_token,
			      &output_token, 
			      &conf_state,
			      &qop_state);
	if (GSS_ERROR(maj_stat)) {
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

static size_t gensec_gsskrb5_sig_size(struct gensec_security *gensec_security) 
{
	/* not const but work for DCERPC packets and arcfour */
	return 45;
}

static NTSTATUS gensec_gsskrb5_seal_packet(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx, 
					  uint8_t *data, size_t length, 
					  const uint8_t *whole_pdu, size_t pdu_length, 
					  DATA_BLOB *sig)
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	ssize_t sig_length = 0;

	input_token.length = length;
	input_token.value = data;
	
	maj_stat = gss_wrap(&min_stat, 
			    gensec_gsskrb5_state->gssapi_context,
			    gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL),
			    GSS_C_QOP_DEFAULT,
			    &input_token,
			    &conf_state,
			    &output_token);
	if (GSS_ERROR(maj_stat)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (output_token.length < length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	sig_length = 45;

	memcpy(data, ((uint8_t *)output_token.value) + sig_length, length);
	*sig = data_blob_talloc(mem_ctx, (uint8_t *)output_token.value, sig_length);

DEBUG(0,("gensec_gsskrb5_seal_packet: siglen: %d inlen: %d, wrap_len: %d\n", sig->length, length, output_token.length - sig_length));
dump_data(0,sig->data, sig->length);
dump_data(0,data, length);
dump_data(0,((uint8_t *)output_token.value) + sig_length, output_token.length - sig_length);

	gss_release_buffer(&min_stat, &output_token);

	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)
	    && !conf_state) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static NTSTATUS gensec_gsskrb5_unseal_packet(struct gensec_security *gensec_security, 
					    TALLOC_CTX *mem_ctx, 
					    uint8_t *data, size_t length, 
					    const uint8_t *whole_pdu, size_t pdu_length,
					    DATA_BLOB *sig)
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	gss_qop_t qop_state;
	DATA_BLOB in;

DEBUG(0,("gensec_gsskrb5_unseal_packet: siglen: %d\n", sig->length));
dump_data(0,sig->data, sig->length);

	in = data_blob_talloc(mem_ctx, NULL, sig->length + length);

	memcpy(in.data, sig->data, sig->length);
	memcpy(in.data + sig->length, data, length);

	input_token.length = in.length;
	input_token.value = in.data;
	
	maj_stat = gss_unwrap(&min_stat, 
			      gensec_gsskrb5_state->gssapi_context, 
			      &input_token,
			      &output_token, 
			      &conf_state,
			      &qop_state);
	if (GSS_ERROR(maj_stat)) {
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

static NTSTATUS gensec_gsskrb5_sign_packet(struct gensec_security *gensec_security, 
					  TALLOC_CTX *mem_ctx, 
					  const uint8_t *data, size_t length, 
					  const uint8_t *whole_pdu, size_t pdu_length, 
					  DATA_BLOB *sig)
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	ssize_t sig_length = 0;

	input_token.length = length;
	input_token.value = data;

	maj_stat = gss_wrap(&min_stat, 
			    gensec_gsskrb5_state->gssapi_context,
			    0,
			    GSS_C_QOP_DEFAULT,
			    &input_token,
			    &conf_state,
			    &output_token);
	if (GSS_ERROR(maj_stat)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (output_token.length < length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	sig_length = 45;

	/*memcpy(data, ((uint8_t *)output_token.value) + sig_length, length);*/
	*sig = data_blob_talloc(mem_ctx, (uint8_t *)output_token.value, sig_length);

DEBUG(0,("gensec_gsskrb5_sign_packet: siglen: %d\n", sig->length));
dump_data(0,sig->data, sig->length);

	gss_release_buffer(&min_stat, &output_token);

	return NT_STATUS_OK;
}

static NTSTATUS gensec_gsskrb5_check_packet(struct gensec_security *gensec_security, 
					   TALLOC_CTX *mem_ctx, 
					   const uint8_t *data, size_t length, 
					   const uint8_t *whole_pdu, size_t pdu_length, 
					   const DATA_BLOB *sig)
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = gensec_security->private_data;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;
	int conf_state;
	gss_qop_t qop_state;
	DATA_BLOB in;

DEBUG(0,("gensec_gsskrb5_check_packet: siglen: %d\n", sig->length));
dump_data(0,sig->data, sig->length);

	in = data_blob_talloc(mem_ctx, NULL, sig->length + length);

	memcpy(in.data, sig->data, sig->length);
	memcpy(in.data + sig->length, data, length);

	input_token.length = in.length;
	input_token.value = in.data;
	
	maj_stat = gss_unwrap(&min_stat, 
			      gensec_gsskrb5_state->gssapi_context, 
			      &input_token,
			      &output_token, 
			      &conf_state,
			      &qop_state);
	if (GSS_ERROR(maj_stat)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (output_token.length != length) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*memcpy(data, output_token.value, length);*/

	gss_release_buffer(&min_stat, &output_token);

	return NT_STATUS_OK;
}

static BOOL gensec_gsskrb5_have_feature(struct gensec_security *gensec_security, 
				       uint32_t feature) 
{
	struct gensec_gsskrb5_state *gensec_gsskrb5_state = gensec_security->private_data;
	if (feature & GENSEC_FEATURE_SIGN) {
		return gensec_gsskrb5_state->got_flags & GSS_C_INTEG_FLAG;
	}
	if (feature & GENSEC_FEATURE_SEAL) {
		return gensec_gsskrb5_state->got_flags & GSS_C_CONF_FLAG;
	}
	return False;
}

static const struct gensec_security_ops gensec_gsskrb5_security_ops = {
	.name		= "gsskrb5",
	.auth_type	= DCERPC_AUTH_TYPE_KRB5,
	.oid            = GENSEC_OID_KERBEROS5,
	.client_start   = gensec_gsskrb5_client_start,
	.update 	= gensec_gsskrb5_update,
	.sig_size	= gensec_gsskrb5_sig_size,
	.sign_packet	= gensec_gsskrb5_sign_packet,
	.check_packet	= gensec_gsskrb5_check_packet,
	.seal_packet	= gensec_gsskrb5_seal_packet,
	.unseal_packet	= gensec_gsskrb5_unseal_packet,
	.wrap           = gensec_gsskrb5_wrap,
	.unwrap         = gensec_gsskrb5_unwrap,
	.have_feature   = gensec_gsskrb5_have_feature,
	.enabled        = False
};

NTSTATUS gensec_gsskrb5_init(void)
{
	NTSTATUS ret;

	ret = gensec_register(&gensec_gsskrb5_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_gsskrb5_security_ops.name));
		return ret;
	}

	return ret;
}
