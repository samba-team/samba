/*
   NLTMSSP wrappers

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2003,2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "ntlmssp_wrap.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/param/param.h"

NTSTATUS auth_ntlmssp_sign_packet(struct auth_ntlmssp_state *ans,
				  TALLOC_CTX *sig_mem_ctx,
				  const uint8_t *data,
				  size_t length,
				  const uint8_t *whole_pdu,
				  size_t pdu_length,
				  DATA_BLOB *sig)
{
	return gensec_sign_packet(ans->gensec_security,
				  sig_mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

NTSTATUS auth_ntlmssp_check_packet(struct auth_ntlmssp_state *ans,
				   const uint8_t *data,
				   size_t length,
				   const uint8_t *whole_pdu,
				   size_t pdu_length,
				   const DATA_BLOB *sig)
{
	return gensec_check_packet(ans->gensec_security,
				   data, length, whole_pdu, pdu_length, sig);
}

NTSTATUS auth_ntlmssp_seal_packet(struct auth_ntlmssp_state *ans,
				  TALLOC_CTX *sig_mem_ctx,
				  uint8_t *data,
				  size_t length,
				  const uint8_t *whole_pdu,
				  size_t pdu_length,
				  DATA_BLOB *sig)
{
	return gensec_seal_packet(ans->gensec_security,
				  sig_mem_ctx, data, length, whole_pdu, pdu_length, sig);
}

NTSTATUS auth_ntlmssp_unseal_packet(struct auth_ntlmssp_state *ans,
				    uint8_t *data,
				    size_t length,
				    const uint8_t *whole_pdu,
				    size_t pdu_length,
				    const DATA_BLOB *sig)
{
	return gensec_unseal_packet(ans->gensec_security,
				    data, length, whole_pdu, pdu_length, sig);
}

NTSTATUS auth_ntlmssp_set_username(struct auth_ntlmssp_state *ans,
				   const char *user)
{
	cli_credentials_set_username(ans->credentials, user, CRED_SPECIFIED);
	return NT_STATUS_OK;
}

NTSTATUS auth_ntlmssp_set_domain(struct auth_ntlmssp_state *ans,
				 const char *domain)
{
	cli_credentials_set_domain(ans->credentials, domain, CRED_SPECIFIED);
	return NT_STATUS_OK;
}

NTSTATUS auth_ntlmssp_set_password(struct auth_ntlmssp_state *ans,
				   const char *password)
{
	cli_credentials_set_password(ans->credentials, password, CRED_SPECIFIED);
	return NT_STATUS_OK;
}

void auth_ntlmssp_want_feature(struct auth_ntlmssp_state *ans, uint32_t feature)
{
	if (feature & NTLMSSP_FEATURE_SESSION_KEY) {
		gensec_want_feature(ans->gensec_security, GENSEC_FEATURE_SESSION_KEY);
	}
	if (feature & NTLMSSP_FEATURE_SIGN) {
		gensec_want_feature(ans->gensec_security, GENSEC_FEATURE_SIGN);
	}
	if (feature & NTLMSSP_FEATURE_SEAL) {
		gensec_want_feature(ans->gensec_security, GENSEC_FEATURE_SEAL);
	}
}

DATA_BLOB auth_ntlmssp_get_session_key(struct auth_ntlmssp_state *ans, TALLOC_CTX *mem_ctx)
{
	DATA_BLOB session_key;
	NTSTATUS status = gensec_session_key(ans->gensec_security, mem_ctx, &session_key);
	if (NT_STATUS_IS_OK(status)) {
		return session_key;
	} else {
		return data_blob_null;
	}
}

static NTSTATUS gensec_ntlmssp3_client_update(struct gensec_security *gensec_security,
					      TALLOC_CTX *out_mem_ctx,
					      struct tevent_context *ev,
					      const DATA_BLOB request,
					      DATA_BLOB *reply)
{
	NTSTATUS status;
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);

	status = ntlmssp_update(gensec_ntlmssp->ntlmssp_state, request, reply);
	if (NT_STATUS_IS_OK(status) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		talloc_steal(out_mem_ctx, reply->data);
	}

	return status;
}

static NTSTATUS gensec_ntlmssp3_client_start(struct gensec_security *gensec_security)
{
	NTSTATUS nt_status;
	struct gensec_ntlmssp_context *gensec_ntlmssp;
	const char *user, *domain;
	const char *password;

	nt_status = gensec_ntlmssp_start(gensec_security);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);

	nt_status = ntlmssp_client_start(gensec_ntlmssp,
					 lp_netbios_name(), lp_workgroup(),
					 lp_client_ntlmv2_auth(), &gensec_ntlmssp->ntlmssp_state);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	cli_credentials_get_ntlm_username_domain(gensec_security->credentials, gensec_ntlmssp, &user, &domain);
	if (!user || !domain) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = ntlmssp_set_username(gensec_ntlmssp->ntlmssp_state, user);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = ntlmssp_set_domain(gensec_ntlmssp->ntlmssp_state, domain);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	password = cli_credentials_get_password(gensec_security->credentials);
	if (!password) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = ntlmssp_set_password(gensec_ntlmssp->ntlmssp_state, password);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (gensec_ntlmssp->gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_ntlmssp->gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_ntlmssp->gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

	return NT_STATUS_OK;
}

static const char *gensec_ntlmssp3_client_oids[] = {
	GENSEC_OID_NTLMSSP,
	NULL
};

static const struct gensec_security_ops gensec_ntlmssp3_client_ops = {
	.name		= "ntlmssp3_client",
	.sasl_name	= GENSEC_SASL_NAME_NTLMSSP, /* "NTLM" */
	.auth_type	= DCERPC_AUTH_TYPE_NTLMSSP,
	.oid            = gensec_ntlmssp3_client_oids,
	.client_start   = gensec_ntlmssp3_client_start,
	.magic 	        = gensec_ntlmssp_magic,
	.update 	= gensec_ntlmssp3_client_update,
	.sig_size	= gensec_ntlmssp_sig_size,
	.sign_packet	= gensec_ntlmssp_sign_packet,
	.check_packet	= gensec_ntlmssp_check_packet,
	.seal_packet	= gensec_ntlmssp_seal_packet,
	.unseal_packet	= gensec_ntlmssp_unseal_packet,
	.wrap           = gensec_ntlmssp_wrap,
	.unwrap         = gensec_ntlmssp_unwrap,
	.session_key	= gensec_ntlmssp_session_key,
	.have_feature   = gensec_ntlmssp_have_feature,
	.enabled        = true,
	.priority       = GENSEC_NTLMSSP
};

NTSTATUS auth_ntlmssp_client_prepare(TALLOC_CTX *mem_ctx, struct auth_ntlmssp_state **auth_ntlmssp_state)
{
	struct auth_ntlmssp_state *ans;
	NTSTATUS nt_status;

	struct gensec_settings *gensec_settings;
	struct loadparm_context *lp_ctx;

	ans = talloc_zero(mem_ctx, struct auth_ntlmssp_state);
	if (!ans) {
		DEBUG(0,("auth_ntlmssp_start: talloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	lp_ctx = loadparm_init_s3(ans, loadparm_s3_context());
	if (lp_ctx == NULL) {
		DEBUG(10, ("loadparm_init_s3 failed\n"));
		TALLOC_FREE(ans);
		return NT_STATUS_INVALID_SERVER_STATE;
	}
	
	gensec_settings = lpcfg_gensec_settings(ans, lp_ctx);
	if (lp_ctx == NULL) {
		DEBUG(10, ("lpcfg_gensec_settings failed\n"));
		TALLOC_FREE(ans);
		return NT_STATUS_NO_MEMORY;
	}
	
	nt_status = gensec_client_start(ans, &ans->gensec_security, gensec_settings);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(ans);
		return nt_status;
	}

	ans->credentials = cli_credentials_init(ans);
	if (!ans->credentials) {
		TALLOC_FREE(ans);
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_guess(ans->credentials, lp_ctx);

	talloc_unlink(ans, lp_ctx);
	talloc_unlink(ans, gensec_settings);

	*auth_ntlmssp_state = ans;
	return NT_STATUS_OK;
}

NTSTATUS auth_ntlmssp_client_start(struct auth_ntlmssp_state *ans)
{
	NTSTATUS status;

	/* Transfer the credentials to gensec */
	status = gensec_set_credentials(ans->gensec_security, ans->credentials);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set GENSEC credentials: %s\n", 
			  nt_errstr(status)));
		return status;
	}
	talloc_unlink(ans, ans->credentials);
	ans->credentials = NULL;

	status = gensec_start_mech_by_ops(ans->gensec_security,
					  &gensec_ntlmssp3_client_ops);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}
