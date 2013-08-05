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
#include "auth/ntlmssp/ntlmssp_private.h"
#include "auth_generic.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/credentials/credentials.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/param/param.h"

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

	if (gensec_security->want_features & GENSEC_FEATURE_SESSION_KEY) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	}
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL) {
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
		gensec_ntlmssp->ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
	}

	return NT_STATUS_OK;
}

static const char *gensec_ntlmssp3_client_oids[] = {
	GENSEC_OID_NTLMSSP,
	NULL
};

const struct gensec_security_ops gensec_ntlmssp3_client_ops = {
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
