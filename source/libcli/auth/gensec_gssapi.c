/* 
   Unix SMB/CIFS implementation.

   Kerberos backend for GENSEC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004

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
#include "libcli/auth/kerberos.h"
#include "auth/auth.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

struct gensec_gssapi_state {
	gss_ctx_id_t gssapi_context;
	struct gss_channel_bindings_struct *input_chan_bindings;
	gss_name_t server_name;
	gss_name_t client_name;
	int want_flags, got_flags;
	const gss_OID_desc *gss_oid;
};
static int gensec_gssapi_destory(void *ptr) 
{
	struct gensec_gssapi_state *gensec_gssapi_state = ptr;
	OM_uint32 maj_stat, min_stat;

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
	return 0;
}

static NTSTATUS gensec_gssapi_start(struct gensec_security *gensec_security)
{
	struct gensec_gssapi_state *gensec_gssapi_state;

	gensec_gssapi_state = talloc_p(gensec_security, struct gensec_gssapi_state);
	if (!gensec_gssapi_state) {
		return NT_STATUS_NO_MEMORY;
	}

	gensec_security->private_data = gensec_gssapi_state;

	gensec_gssapi_state->gssapi_context = GSS_C_NO_CONTEXT;
	gensec_gssapi_state->server_name = GSS_C_NO_NAME;
	gensec_gssapi_state->client_name = GSS_C_NO_NAME;

	talloc_set_destructor(gensec_gssapi_state, gensec_gssapi_destory); 

	/* TODO: Fill in channel bindings */
	gensec_gssapi_state->input_chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;
	
	gensec_gssapi_state->want_flags = 0;
	gensec_gssapi_state->got_flags = 0;

	if (gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		/* GSSAPI won't give us the session keys */
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		gensec_gssapi_state->want_flags |= GSS_C_INTEG_FLAG;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		gensec_gssapi_state->want_flags |= GSS_C_CONF_FLAG;
	}

	if (strcmp(gensec_security->ops->oid, GENSEC_OID_KERBEROS5) == 0) {
		static const gss_OID_desc gensec_gss_krb5_mechanism_oid_desc =
			{9, (void *)discard_const_p(char, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")};

		gensec_gssapi_state->gss_oid = &gensec_gss_krb5_mechanism_oid_desc;
	} else if (strcmp(gensec_security->ops->oid, GENSEC_OID_SPNEGO) == 0) {
		static const gss_OID_desc gensec_gss_spnego_mechanism_oid_desc =
			{6, (void *)discard_const_p(char, "\x2b\x06\x01\x05\x05\x02")};
		gensec_gssapi_state->gss_oid = &gensec_gss_spnego_mechanism_oid_desc;
	} else {
		return NT_STATUS_INVALID_PARAMETER;
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

	nt_status = gensec_gssapi_start(gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	gensec_gssapi_state = gensec_security->private_data;

	name_token.value = talloc_asprintf(gensec_gssapi_state, "%s@%s", gensec_get_target_service(gensec_security), 
					   gensec_get_target_hostname(gensec_security));
	DEBUG(0, ("name: %s\n", (char *)name_token.value));
	name_token.length = strlen(name_token.value);

	maj_stat = gss_import_name (&min_stat,
				    &name_token,
				    GSS_C_NT_HOSTBASED_SERVICE,
				    &gensec_gssapi_state->server_name);


	if (maj_stat) {
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
						  gensec_gssapi_state->gssapi_context, 
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
		gss_buffer_desc msg1, msg2;
		OM_uint32 msg_ctx = 0;
		
		msg1.value = NULL;
		msg2.value = NULL;
		gss_display_status(&min_stat2, maj_stat, GSS_C_GSS_CODE,
				   GSS_C_NULL_OID, &msg_ctx, &msg1);
		gss_display_status(&min_stat2, min_stat, GSS_C_MECH_CODE,
				   GSS_C_NULL_OID, &msg_ctx, &msg2);
		DEBUG(1, ("gensec_gssapi_update: %s : %s\n", (char *)msg1.value, (char *)msg2.value));
		gss_release_buffer(&min_stat2, &msg1);
		gss_release_buffer(&min_stat2, &msg2);

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

static BOOL gensec_gssapi_have_feature(struct gensec_security *gensec_security, 
				       uint32 feature) 
{
	struct gensec_gssapi_state *gensec_gssapi_state = gensec_security->private_data;
	if (feature & GENSEC_FEATURE_SIGN) {
		return gensec_gssapi_state->got_flags & GSS_C_INTEG_FLAG;
	}
	if (feature & GENSEC_FEATURE_SEAL) {
		return gensec_gssapi_state->got_flags & GSS_C_CONF_FLAG;
	}
	return False;
}

/* As a server, this could in theory accept any GSSAPI mech */
static const struct gensec_security_ops gensec_gssapi_krb5_security_ops = {
	.name		= "gssapi_krb5",
	.sasl_name	= "GSSAPI",
	.oid            = GENSEC_OID_KERBEROS5,
	.client_start   = gensec_gssapi_client_start,
	.server_start   = gensec_gssapi_server_start,
	.update 	= gensec_gssapi_update,
	.wrap           = gensec_gssapi_wrap,
	.unwrap         = gensec_gssapi_unwrap,
	.have_feature   = gensec_gssapi_have_feature

};

static const struct gensec_security_ops gensec_gssapi_spnego_security_ops = {
	.name		= "gssapi_spnego",
	.sasl_name	= "GSS-SPNEGO",
	.oid            = GENSEC_OID_SPNEGO,
	.client_start   = gensec_gssapi_client_start,
	.server_start   = gensec_gssapi_server_start,
	.update 	= gensec_gssapi_update,
	.wrap           = gensec_gssapi_wrap,
	.unwrap         = gensec_gssapi_unwrap,
	.have_feature   = gensec_gssapi_have_feature

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

	ret = gensec_register(&gensec_gssapi_spnego_security_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			gensec_gssapi_spnego_security_ops.name));
		return ret;
	}

	return ret;
}
