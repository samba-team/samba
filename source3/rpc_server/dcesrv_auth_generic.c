/*
 *  NTLMSSP Acceptor
 *  DCERPC Server functions
 *  Copyright (C) Simo Sorce 2010.
 *  Copyright (C) Andrew Bartlett 2011.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "rpc_server/dcesrv_auth_generic.h"
#include "auth.h"
#include "auth/gensec/gensec.h"

static NTSTATUS auth_generic_server_authtype_start_as_root(TALLOC_CTX *mem_ctx,
							   uint8_t auth_type, uint8_t auth_level,
							   DATA_BLOB *token_in,
							   DATA_BLOB *token_out,
							   const struct tsocket_address *remote_address,
							   struct gensec_security **ctx)
{
	struct gensec_security *gensec_security = NULL;
	NTSTATUS status;

	status = auth_generic_prepare(talloc_tos(), remote_address, &gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, (__location__ ": auth_generic_prepare failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	status = gensec_start_mech_by_authtype(gensec_security, auth_type, auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, (__location__ ": auth_generic_start failed: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(gensec_security);
		return status;
	}

	status = gensec_update(gensec_security, mem_ctx, *token_in, token_out);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(2, (__location__ ": gensec_update failed: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(gensec_security);
		return status;
	}

	/* steal gensec context to the caller */
	*ctx = talloc_move(mem_ctx, &gensec_security);
	return status;
}

NTSTATUS auth_generic_server_authtype_start(TALLOC_CTX *mem_ctx,
					    uint8_t auth_type, uint8_t auth_level,
					    DATA_BLOB *token_in,
					    DATA_BLOB *token_out,
					    const struct tsocket_address *remote_address,
					    struct gensec_security **ctx)
{
	NTSTATUS status;
	become_root();

	/* this has to be done as root in order to create the messaging socket */
	status = auth_generic_server_authtype_start_as_root(mem_ctx,
							    auth_type, auth_level,
							    token_in,
							    token_out,
							    remote_address,
							    ctx);
	unbecome_root();
	return status;
}

NTSTATUS auth_generic_server_step(struct gensec_security *gensec_security,
			     TALLOC_CTX *mem_ctx,
			     DATA_BLOB *token_in,
			     DATA_BLOB *token_out)
{
	NTSTATUS status;

	if (gensec_security == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* this has to be done as root in order to verify the password */
	become_root();
	status = gensec_update(gensec_security, mem_ctx, *token_in, token_out);
	unbecome_root();

	return status;
}

NTSTATUS auth_generic_server_check_flags(struct gensec_security *gensec_security,
				    bool do_sign, bool do_seal)
{
	if (do_sign && !gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		DEBUG(1, (__location__ "Integrity was requested but client "
			  "failed to negotiate signing.\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (do_seal && !gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
		DEBUG(1, (__location__ "Privacy was requested but client "
			  "failed to negotiate sealing.\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

NTSTATUS auth_generic_server_get_user_info(struct gensec_security *gensec_security,
				      TALLOC_CTX *mem_ctx,
				      struct auth_session_info **session_info)
{
	NTSTATUS status;

	/* this has to be done as root in order to get to the
	 * messaging sockets for IDMAP and privilege.ldb in the AD
	 * DC */
	become_root();
	status = gensec_session_info(gensec_security, mem_ctx, session_info);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, (__location__ ": Failed to get authenticated user "
			  "info: %s\n", nt_errstr(status)));
		return status;
	}

	DEBUG(5, (__location__ "OK: user: %s domain: %s\n",
		  (*session_info)->info->account_name,
		  (*session_info)->info->domain_name));

	return NT_STATUS_OK;
}
