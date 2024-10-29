/*
   Unix SMB/CIFS implementation.

   netlogon schannel utility functions

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2008
   Copyright (C) Stefan Metzmacher <metze@samba.org>  2005
   Copyright (C) Matthias Dieter Wallnöfer            2009-2010

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
#include "schannel_util.h"
#include "param/param.h"
#include "libcli/security/dom_sid.h"
#include "libcli/auth/schannel.h"
#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "lib/util/util_str_escape.h"

struct dcesrv_netr_check_schannel_state {
	struct dom_sid account_sid;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	bool schannel_global_required;
	bool schannel_required;
	bool schannel_explicitly_set;

	bool seal_global_required;
	bool seal_required;
	bool seal_explicitly_set;

	NTSTATUS result;
};

static NTSTATUS dcesrv_netr_check_schannel_get_state(struct dcesrv_call_state *dce_call,
						     const struct netlogon_creds_CredentialState *creds,
						     enum dcerpc_AuthType auth_type,
						     enum dcerpc_AuthLevel auth_level,
						     struct dcesrv_netr_check_schannel_state **_s)
{
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	int schannel = lpcfg_server_schannel(lp_ctx);
	bool schannel_global_required = (schannel == true);
	bool schannel_required = schannel_global_required;
	const char *explicit_opt = NULL;
	bool global_require_seal = lpcfg_server_schannel_require_seal(lp_ctx);
	bool require_seal = global_require_seal;
	const char *explicit_seal_opt = NULL;
#define DCESRV_NETR_CHECK_SCHANNEL_STATE_MAGIC (NETLOGON_SERVER_PIPE_STATE_MAGIC+1)
	struct dcesrv_netr_check_schannel_state *s = NULL;
	NTSTATUS status;

	*_s = NULL;

	s = dcesrv_iface_state_find_conn(dce_call,
			DCESRV_NETR_CHECK_SCHANNEL_STATE_MAGIC,
			struct dcesrv_netr_check_schannel_state);
	if (s != NULL) {
		if (!dom_sid_equal(&s->account_sid, &creds->ex->client_sid)) {
			goto new_state;
		}
		if (s->auth_type != auth_type) {
			goto new_state;
		}
		if (s->auth_level != auth_level) {
			goto new_state;
		}

		*_s = s;
		return NT_STATUS_OK;
	}

new_state:
	TALLOC_FREE(s);
	s = talloc_zero(dce_call,
			struct dcesrv_netr_check_schannel_state);
	if (s == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	s->account_sid = creds->ex->client_sid;
	s->auth_type = auth_type;
	s->auth_level = auth_level;
	s->result = NT_STATUS_MORE_PROCESSING_REQUIRED;

	/*
	 * We don't use lpcfg_parm_bool(), as we
	 * need the explicit_opt pointer in order to
	 * adjust the debug messages.
	 */
	explicit_seal_opt = lpcfg_get_parametric(lp_ctx,
						 NULL,
						 "server schannel require seal",
						 creds->account_name);
	if (explicit_seal_opt != NULL) {
		require_seal = lp_bool(explicit_seal_opt);
	}

	/*
	 * We don't use lpcfg_parm_bool(), as we
	 * need the explicit_opt pointer in order to
	 * adjust the debug messages.
	 */
	explicit_opt = lpcfg_get_parametric(lp_ctx,
					    NULL,
					    "server require schannel",
					    creds->account_name);
	if (explicit_opt != NULL) {
		schannel_required = lp_bool(explicit_opt);
	}

	s->schannel_global_required = schannel_global_required;
	s->schannel_required = schannel_required;
	s->schannel_explicitly_set = explicit_opt != NULL;

	s->seal_global_required = global_require_seal;
	s->seal_required = require_seal;
	s->seal_explicitly_set = explicit_seal_opt != NULL;

	status = dcesrv_iface_state_store_conn(dce_call,
			DCESRV_NETR_CHECK_SCHANNEL_STATE_MAGIC,
			s);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_s = s;
	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_netr_check_schannel_once(struct dcesrv_call_state *dce_call,
						struct dcesrv_netr_check_schannel_state *s,
						const struct netlogon_creds_CredentialState *creds,
						uint16_t opnum)
{
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	int CVE_2020_1472_warn_level = lpcfg_parm_int(lp_ctx, NULL,
		"CVE_2020_1472", "warn_about_unused_debug_level", DBGLVL_ERR);
	int CVE_2020_1472_error_level = lpcfg_parm_int(lp_ctx, NULL,
		"CVE_2020_1472", "error_debug_level", DBGLVL_ERR);
	int CVE_2022_38023_warn_level = lpcfg_parm_int(lp_ctx, NULL,
		"CVE_2022_38023", "warn_about_unused_debug_level", DBGLVL_ERR);
	int CVE_2022_38023_error_level = lpcfg_parm_int(lp_ctx, NULL,
		"CVE_2022_38023", "error_debug_level", DBGLVL_ERR);
	TALLOC_CTX *frame = talloc_stackframe();
	unsigned int dbg_lvl = DBGLVL_DEBUG;
	const char *opname = "<unknown>";
	const char *reason = "<unknown>";

	if (opnum < ndr_table_netlogon.num_calls) {
		opname = ndr_table_netlogon.calls[opnum].name;
	}

	if (s->auth_type == DCERPC_AUTH_TYPE_SCHANNEL) {
		if (s->auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
			reason = "WITH SEALED";
		} else if (s->auth_level == DCERPC_AUTH_LEVEL_INTEGRITY) {
			reason = "WITH SIGNED";
		} else {
			reason = "WITH INVALID";
			dbg_lvl = DBGLVL_ERR;
			s->result = NT_STATUS_INTERNAL_ERROR;
		}
	} else {
		reason = "WITHOUT";
	}

	if (!NT_STATUS_EQUAL(s->result, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		if (!NT_STATUS_IS_OK(s->result)) {
			dbg_lvl = MIN(dbg_lvl, DBGLVL_INFO);
		}

		DEBUG(dbg_lvl, (
		      "CVE-2020-1472(ZeroLogon)/CVE-2022-38023: "
		      "%s request (opnum[%u]) %s schannel from "
		      "client_account[%s] client_computer_name[%s] %s\n",
		      opname, opnum, reason,
		      log_escape(frame, creds->account_name),
		      log_escape(frame, creds->computer_name),
		      nt_errstr(s->result)));
		TALLOC_FREE(frame);
		return s->result;
	}

	if (s->auth_type == DCERPC_AUTH_TYPE_SCHANNEL &&
	    s->auth_level == DCERPC_AUTH_LEVEL_PRIVACY)
	{
		s->result = NT_STATUS_OK;

		if (s->schannel_explicitly_set && !s->schannel_required) {
			dbg_lvl = MIN(dbg_lvl, CVE_2020_1472_warn_level);
		} else if (!s->schannel_required) {
			dbg_lvl = MIN(dbg_lvl, DBGLVL_INFO);
		}
		if (s->seal_explicitly_set && !s->seal_required) {
			dbg_lvl = MIN(dbg_lvl, CVE_2022_38023_warn_level);
		} else if (!s->seal_required) {
			dbg_lvl = MIN(dbg_lvl, DBGLVL_INFO);
		}

		DEBUG(dbg_lvl, (
		      "CVE-2020-1472(ZeroLogon)/CVE-2022-38023: "
		      "%s request (opnum[%u]) %s schannel from "
		      "client_account[%s] client_computer_name[%s] %s\n",
		      opname, opnum, reason,
		      log_escape(frame, creds->account_name),
		      log_escape(frame, creds->computer_name),
		      nt_errstr(s->result)));

		if (s->schannel_explicitly_set && !s->schannel_required) {
			DEBUG(CVE_2020_1472_warn_level, (
			      "CVE-2020-1472(ZeroLogon): "
			      "Option 'server require schannel:%s = no' not needed for '%s'!\n",
			      log_escape(frame, creds->account_name),
			      log_escape(frame, creds->computer_name)));
		}

		if (s->seal_explicitly_set && !s->seal_required) {
			DEBUG(CVE_2022_38023_warn_level, (
			      "CVE-2022-38023: "
			      "Option 'server schannel require seal:%s = no' not needed for '%s'!\n",
			      log_escape(frame, creds->account_name),
			      log_escape(frame, creds->computer_name)));
		}

		TALLOC_FREE(frame);
		return s->result;
	}

	if (s->auth_type == DCERPC_AUTH_TYPE_SCHANNEL) {
		if (s->seal_required) {
			s->result = NT_STATUS_ACCESS_DENIED;

			if (s->seal_explicitly_set) {
				dbg_lvl = DBGLVL_NOTICE;
			} else {
				dbg_lvl = MIN(dbg_lvl, CVE_2022_38023_error_level);
			}
			if (s->schannel_explicitly_set && !s->schannel_required) {
				dbg_lvl = MIN(dbg_lvl, CVE_2022_38023_warn_level);
			}

			DEBUG(dbg_lvl, (
			      "CVE-2022-38023: "
			      "%s request (opnum[%u]) %s schannel from "
			      "from client_account[%s] client_computer_name[%s] %s\n",
			      opname, opnum, reason,
			      log_escape(frame, creds->account_name),
			      log_escape(frame, creds->computer_name),
			      nt_errstr(s->result)));
			if (s->seal_explicitly_set) {
				D_NOTICE("CVE-2022-38023: Option "
					 "'server schannel require seal:%s = yes' "
					 "rejects access for client.\n",
					 log_escape(frame, creds->account_name));
			} else {
				DEBUG(CVE_2020_1472_error_level, (
				      "CVE-2022-38023: Check if option "
				      "'server schannel require seal:%s = no' "
				      "might be needed for a legacy client.\n",
				      log_escape(frame, creds->account_name)));
			}
			if (s->schannel_explicitly_set && !s->schannel_required) {
				DEBUG(CVE_2020_1472_warn_level, (
				      "CVE-2020-1472(ZeroLogon): Option "
				      "'server require schannel:%s = no' "
				      "not needed for '%s'!\n",
				      log_escape(frame, creds->account_name),
				      log_escape(frame, creds->computer_name)));
			}
			TALLOC_FREE(frame);
			return s->result;
		}

		s->result = NT_STATUS_OK;

		if (s->schannel_explicitly_set && !s->schannel_required) {
			dbg_lvl = MIN(dbg_lvl, CVE_2020_1472_warn_level);
		} else if (!s->schannel_required) {
			dbg_lvl = MIN(dbg_lvl, DBGLVL_INFO);
		}
		if (s->seal_explicitly_set && !s->seal_required) {
			dbg_lvl = MIN(dbg_lvl, DBGLVL_INFO);
		} else if (!s->seal_required) {
			dbg_lvl = MIN(dbg_lvl, CVE_2022_38023_error_level);
		}

		DEBUG(dbg_lvl, (
		      "CVE-2020-1472(ZeroLogon): "
		      "%s request (opnum[%u]) %s schannel from "
		      "client_account[%s] client_computer_name[%s] %s\n",
		      opname, opnum, reason,
		      log_escape(frame, creds->account_name),
		      log_escape(frame, creds->computer_name),
		      nt_errstr(s->result)));
		if (s->schannel_explicitly_set && !s->schannel_required) {
			DEBUG(CVE_2020_1472_warn_level, (
			      "CVE-2020-1472(ZeroLogon): "
			      "Option 'server require schannel:%s = no' not needed for '%s'!\n",
			      log_escape(frame, creds->account_name),
			      log_escape(frame, creds->computer_name)));
		}
		if (s->seal_explicitly_set && !s->seal_required) {
			D_INFO("CVE-2022-38023: "
			       "Option 'server schannel require seal:%s = no' still needed for '%s'!\n",
			       log_escape(frame, creds->account_name),
			       log_escape(frame, creds->computer_name));
		} else if (!s->seal_required) {
			/*
			 * admins should set
			 * server schannel require seal:COMPUTER$ = no
			 * in order to avoid the level 0 messages.
			 * Over time they can switch the global value
			 * to be strict.
			 */
			DEBUG(CVE_2022_38023_error_level, (
			      "CVE-2022-38023: "
			      "Please use 'server schannel require seal:%s = no' "
			      "for '%s' to avoid this warning!\n",
			      log_escape(frame, creds->account_name),
			      log_escape(frame, creds->computer_name)));
		}

		TALLOC_FREE(frame);
		return s->result;
	}

	if (s->seal_required) {
		s->result = NT_STATUS_ACCESS_DENIED;

		if (s->seal_explicitly_set) {
			dbg_lvl = MIN(dbg_lvl, DBGLVL_NOTICE);
		} else {
			dbg_lvl = MIN(dbg_lvl, CVE_2022_38023_error_level);
		}
		if (!s->schannel_explicitly_set) {
			dbg_lvl = MIN(dbg_lvl, CVE_2020_1472_error_level);
		} else if (s->schannel_required) {
			dbg_lvl = MIN(dbg_lvl, DBGLVL_NOTICE);
		}

		DEBUG(dbg_lvl, (
		      "CVE-2020-1472(ZeroLogon)/CVE-2022-38023: "
		      "%s request (opnum[%u]) %s schannel from "
		      "from client_account[%s] client_computer_name[%s] %s\n",
		      opname, opnum, reason,
		      log_escape(frame, creds->account_name),
		      log_escape(frame, creds->computer_name),
		      nt_errstr(s->result)));
		if (s->seal_explicitly_set) {
			D_NOTICE("CVE-2022-38023: Option "
			         "'server schannel require seal:%s = yes' "
			         "rejects access for client.\n",
			         log_escape(frame, creds->account_name));
		} else {
			DEBUG(CVE_2022_38023_error_level, (
			      "CVE-2022-38023: Check if option "
			      "'server schannel require seal:%s = no' "
			      "might be needed for a legacy client.\n",
			      log_escape(frame, creds->account_name)));
		}
		if (!s->schannel_explicitly_set) {
			DEBUG(CVE_2020_1472_error_level, (
			      "CVE-2020-1472(ZeroLogon): Check if option "
			      "'server require schannel:%s = no' "
			      "might be needed for a legacy client.\n",
			      log_escape(frame, creds->account_name)));
		} else if (s->schannel_required) {
			D_NOTICE("CVE-2022-38023: Option "
			         "'server require schannel:%s = yes' "
			         "also rejects access for client.\n",
			         log_escape(frame, creds->account_name));
		}
		TALLOC_FREE(frame);
		return s->result;
	}

	if (s->schannel_required) {
		s->result = NT_STATUS_ACCESS_DENIED;

		if (s->schannel_explicitly_set) {
			dbg_lvl = MIN(dbg_lvl, DBGLVL_NOTICE);
		} else {
			dbg_lvl = MIN(dbg_lvl, CVE_2020_1472_error_level);
		}
		if (!s->seal_explicitly_set) {
			dbg_lvl = MIN(dbg_lvl, CVE_2022_38023_error_level);
		}

		DEBUG(dbg_lvl, (
		      "CVE-2020-1472(ZeroLogon)/CVE-2022-38023: "
		      "%s request (opnum[%u]) %s schannel from "
		      "client_account[%s] client_computer_name[%s] %s\n",
		      opname, opnum, reason,
		      log_escape(frame, creds->account_name),
		      log_escape(frame, creds->computer_name),
		      nt_errstr(s->result)));
		if (s->schannel_explicitly_set) {
			D_NOTICE("CVE-2020-1472(ZeroLogon): Option "
				"'server require schannel:%s = yes' "
				"rejects access for client.\n",
				log_escape(frame, creds->account_name));
		} else {
			DEBUG(CVE_2020_1472_error_level, (
			      "CVE-2020-1472(ZeroLogon): Check if option "
			      "'server require schannel:%s = no' "
			      "might be needed for a legacy client.\n",
			      log_escape(frame, creds->account_name)));
		}
		if (!s->seal_explicitly_set) {
			DEBUG(CVE_2022_38023_error_level, (
			      "CVE-2022-38023: Check if option "
			      "'server schannel require seal:%s = no' "
			      "might be needed for a legacy client.\n",
			      log_escape(frame, creds->account_name)));
		}
		TALLOC_FREE(frame);
		return s->result;
	}

	s->result = NT_STATUS_OK;

	if (s->seal_explicitly_set) {
		dbg_lvl = MIN(dbg_lvl, DBGLVL_INFO);
	} else {
		dbg_lvl = MIN(dbg_lvl, CVE_2022_38023_error_level);
	}

	if (s->schannel_explicitly_set) {
		dbg_lvl = MIN(dbg_lvl, DBGLVL_INFO);
	} else {
		dbg_lvl = MIN(dbg_lvl, CVE_2020_1472_error_level);
	}

	DEBUG(dbg_lvl, (
	      "CVE-2020-1472(ZeroLogon)/CVE-2022-38023: "
	      "%s request (opnum[%u]) %s schannel from "
	      "client_account[%s] client_computer_name[%s] %s\n",
	      opname, opnum, reason,
	      log_escape(frame, creds->account_name),
	      log_escape(frame, creds->computer_name),
	      nt_errstr(s->result)));

	if (s->seal_explicitly_set) {
		D_INFO("CVE-2022-38023: Option "
		       "'server schannel require seal:%s = no' "
		       "still needed for '%s'!\n",
		       log_escape(frame, creds->account_name),
		       log_escape(frame, creds->computer_name));
	} else {
		/*
		 * admins should set
		 * server schannel require seal:COMPUTER$ = no
		 * in order to avoid the level 0 messages.
		 * Over time they can switch the global value
		 * to be strict.
		 */
		DEBUG(CVE_2022_38023_error_level, (
		      "CVE-2022-38023: Please use "
		       "'server schannel require seal:%s = no' "
		      "for '%s' to avoid this warning!\n",
		      log_escape(frame, creds->account_name),
		      log_escape(frame, creds->computer_name)));
	}

	if (s->schannel_explicitly_set) {
		D_INFO("CVE-2020-1472(ZeroLogon): Option "
		       "'server require schannel:%s = no' "
		       "still needed for '%s'!\n",
		       log_escape(frame, creds->account_name),
		       log_escape(frame, creds->computer_name));
	} else {
		/*
		 * admins should set
		 * server require schannel:COMPUTER$ = no
		 * in order to avoid the level 0 messages.
		 * Over time they can switch the global value
		 * to be strict.
		 */
		DEBUG(CVE_2020_1472_error_level, (
		      "CVE-2020-1472(ZeroLogon): "
		      "Please use 'server require schannel:%s = no' "
		      "for '%s' to avoid this warning!\n",
		      log_escape(frame, creds->account_name),
		      log_escape(frame, creds->computer_name)));
	}

	TALLOC_FREE(frame);
	return s->result;
}

NTSTATUS dcesrv_netr_check_schannel(struct dcesrv_call_state *dce_call,
				    const struct netlogon_creds_CredentialState *creds,
				    enum dcerpc_AuthType auth_type,
				    enum dcerpc_AuthLevel auth_level,
				    uint16_t opnum)
{
	struct dcesrv_netr_check_schannel_state *s = NULL;
	NTSTATUS status;

	status = dcesrv_netr_check_schannel_get_state(dce_call,
						      creds,
						      auth_type,
						      auth_level,
						      &s);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = dcesrv_netr_check_schannel_once(dce_call, s, creds, opnum);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS dcesrv_netr_creds_server_step_check(struct dcesrv_call_state *dce_call,
						    TALLOC_CTX *mem_ctx,
						    const char *computer_name,
						    struct netr_Authenticator *received_authenticator,
						    struct netr_Authenticator *return_authenticator,
						    struct netlogon_creds_CredentialState **creds_out)
{
	NTSTATUS nt_status;
	struct netlogon_creds_CredentialState *creds = NULL;
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	enum dcerpc_AuthLevel auth_level = DCERPC_AUTH_LEVEL_NONE;

	dcesrv_call_auth_info(dce_call, &auth_type, &auth_level);

	nt_status = schannel_check_creds_state(mem_ctx,
					       dce_call->conn->dce_ctx->lp_ctx,
					       computer_name,
					       received_authenticator,
					       return_authenticator,
					       auth_type,
					       auth_level,
					       &creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ZERO_STRUCTP(return_authenticator);
		return nt_status;
	}

	nt_status = dcesrv_netr_check_schannel(dce_call,
					       creds,
					       auth_type,
					       auth_level,
					       dce_call->pkt.u.request.opnum);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(creds);
		ZERO_STRUCTP(return_authenticator);
		return nt_status;
	}

	*creds_out = creds;
	return NT_STATUS_OK;
}
