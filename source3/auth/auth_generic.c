/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, server side

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
#include "auth.h"
#include "../auth/ntlmssp/ntlmssp.h"
#include "ntlmssp_wrap.h"
#include "../librpc/gen_ndr/netlogon.h"
#include "../librpc/gen_ndr/dcerpc.h"
#include "../lib/tsocket/tsocket.h"
#include "auth/gensec/gensec.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/param/param.h"

NTSTATUS auth_generic_prepare(TALLOC_CTX *mem_ctx,
			      const struct tsocket_address *remote_address,
			      struct auth_generic_state **auth_ntlmssp_state)
{
	struct auth_context *auth_context;
	struct auth_generic_state *ans;
	NTSTATUS nt_status;

	ans = talloc_zero(mem_ctx, struct auth_generic_state);
	if (!ans) {
		DEBUG(0,("auth_ntlmssp_start: talloc failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = make_auth_context_subsystem(talloc_tos(), &auth_context);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(ans);
		return nt_status;
	}

	ans->auth_context = talloc_steal(ans, auth_context);

	if (auth_context->prepare_gensec) {
		nt_status = auth_context->prepare_gensec(ans,
							 &ans->gensec_security);
		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(ans);
			return nt_status;
		}
	} else {
		struct gensec_settings *gensec_settings;
		struct loadparm_context *lp_ctx;

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

		gensec_settings->backends = talloc_zero_array(gensec_settings, struct gensec_security_ops *, 2);
		if (gensec_settings->backends == NULL) {
			TALLOC_FREE(ans);
			return NT_STATUS_NO_MEMORY;
		}

		gensec_settings->backends[0] = &gensec_ntlmssp3_server_ops;

		nt_status = gensec_server_start(ans, gensec_settings,
						NULL, &ans->gensec_security);

		if (!NT_STATUS_IS_OK(nt_status)) {
			TALLOC_FREE(ans);
			return nt_status;
		}
		talloc_unlink(ans, lp_ctx);
		talloc_unlink(ans, gensec_settings);
	}

	nt_status = gensec_set_remote_address(ans->gensec_security,
					      remote_address);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(ans);
		return nt_status;
	}

	*auth_ntlmssp_state = ans;
	return NT_STATUS_OK;
}

NTSTATUS auth_generic_start(struct auth_generic_state *auth_ntlmssp_state, const char *oid)
{
	return gensec_start_mech_by_oid(auth_ntlmssp_state->gensec_security, oid);
}

NTSTATUS auth_generic_authtype_start(struct auth_generic_state *auth_ntlmssp_state,
				     uint8_t auth_type, uint8_t auth_level)
{
	return gensec_start_mech_by_authtype(auth_ntlmssp_state->gensec_security,
					     auth_type, auth_level);
}
