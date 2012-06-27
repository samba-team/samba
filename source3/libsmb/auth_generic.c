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
#include "auth_generic.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/param/param.h"
#include "librpc/crypto/gse.h"

NTSTATUS auth_generic_set_username(struct auth_generic_state *ans,
				   const char *user)
{
	cli_credentials_set_username(ans->credentials, user, CRED_SPECIFIED);
	return NT_STATUS_OK;
}

NTSTATUS auth_generic_set_domain(struct auth_generic_state *ans,
				 const char *domain)
{
	cli_credentials_set_domain(ans->credentials, domain, CRED_SPECIFIED);
	return NT_STATUS_OK;
}

NTSTATUS auth_generic_set_password(struct auth_generic_state *ans,
				   const char *password)
{
	cli_credentials_set_password(ans->credentials, password, CRED_SPECIFIED);
	return NT_STATUS_OK;
}

NTSTATUS auth_generic_client_prepare(TALLOC_CTX *mem_ctx, struct auth_generic_state **auth_generic_state)
{
	struct auth_generic_state *ans;
	NTSTATUS nt_status;
	size_t idx = 0;
	struct gensec_settings *gensec_settings;
	struct loadparm_context *lp_ctx;

	ans = talloc_zero(mem_ctx, struct auth_generic_state);
	if (!ans) {
		DEBUG(0,("auth_generic_start: talloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	lp_ctx = loadparm_init_s3(ans, loadparm_s3_helpers());
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

	gensec_settings->backends = talloc_zero_array(gensec_settings,
					struct gensec_security_ops *, 4);
	if (gensec_settings->backends == NULL) {
		TALLOC_FREE(ans);
		return NT_STATUS_NO_MEMORY;
	}

	gensec_init();

	/* These need to be in priority order, krb5 before NTLMSSP */
#if defined(HAVE_KRB5)
	gensec_settings->backends[idx++] = &gensec_gse_krb5_security_ops;
#endif

	gensec_settings->backends[idx++] = &gensec_ntlmssp3_client_ops;

	gensec_settings->backends[idx++] = gensec_security_by_oid(NULL,
						GENSEC_OID_SPNEGO);

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

	*auth_generic_state = ans;
	return NT_STATUS_OK;
}

NTSTATUS auth_generic_client_start(struct auth_generic_state *ans, const char *oid)
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

	status = gensec_start_mech_by_oid(ans->gensec_security,
					  oid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS auth_generic_client_start_by_authtype(struct auth_generic_state *ans,
					       uint8_t auth_type,
					       uint8_t auth_level)
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

	status = gensec_start_mech_by_authtype(ans->gensec_security,
					       auth_type, auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}
