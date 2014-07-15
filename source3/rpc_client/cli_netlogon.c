/*
   Unix SMB/CIFS implementation.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Jeremy Allison                    1998.
   Largely re-written by Jeremy Allison (C)	   2005.
   Copyright (C) Guenther Deschner                 2008.

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
#include "system/filesys.h"
#include "libsmb/libsmb.h"
#include "rpc_client/rpc_client.h"
#include "rpc_client/cli_pipe.h"
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/auth/netlogon_creds_cli.h"
#include "../librpc/gen_ndr/ndr_netlogon_c.h"
#include "../librpc/gen_ndr/schannel.h"
#include "rpc_client/cli_netlogon.h"
#include "rpc_client/init_netlogon.h"
#include "rpc_client/util_netlogon.h"
#include "../libcli/security/security.h"
#include "lib/param/param.h"
#include "libcli/smb/smbXcli_base.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "util_tdb.h"


NTSTATUS rpccli_pre_open_netlogon_creds(void)
{
	static bool already_open = false;
	TALLOC_CTX *frame;
	struct loadparm_context *lp_ctx;
	char *fname;
	struct db_context *global_db;
	NTSTATUS status;

	if (already_open) {
		return NT_STATUS_OK;
	}

	frame = talloc_stackframe();

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	fname = lpcfg_private_db_path(frame, lp_ctx, "netlogon_creds_cli");
	if (fname == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	global_db = db_open(talloc_autofree_context(), fname,
			    0, TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
			    O_RDWR|O_CREAT, 0600, DBWRAP_LOCK_ORDER_2,
			    DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS);
	if (global_db == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = netlogon_creds_cli_set_global_db(&global_db);
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	already_open = true;
	return NT_STATUS_OK;
}

NTSTATUS rpccli_create_netlogon_creds(const char *server_computer,
				      const char *server_netbios_domain,
				      const char *client_account,
				      enum netr_SchannelType sec_chan_type,
				      struct messaging_context *msg_ctx,
				      TALLOC_CTX *mem_ctx,
				      struct netlogon_creds_cli_context **netlogon_creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct loadparm_context *lp_ctx;
	NTSTATUS status;

	status = rpccli_pre_open_netlogon_creds();
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	status = netlogon_creds_cli_context_global(lp_ctx,
						   msg_ctx,
						   client_account,
						   sec_chan_type,
						   server_computer,
						   server_netbios_domain,
						   mem_ctx, netlogon_creds);
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS rpccli_setup_netlogon_creds(struct cli_state *cli,
				     struct netlogon_creds_cli_context *netlogon_creds,
				     bool force_reauth,
				     struct samr_Password current_nt_hash,
				     const struct samr_Password *previous_nt_hash)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_CredentialState *creds = NULL;
	NTSTATUS status;

	status = netlogon_creds_cli_get(netlogon_creds,
					frame, &creds);
	if (NT_STATUS_IS_OK(status)) {
		const char *action = "using";

		if (force_reauth) {
			action = "overwrite";
		}

		DEBUG(5,("%s: %s cached netlogon_creds cli[%s/%s] to %s\n",
			 __FUNCTION__, action,
			 creds->account_name, creds->computer_name,
			 smbXcli_conn_remote_name(cli->conn)));
		if (!force_reauth) {
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}
		TALLOC_FREE(creds);
	}

	status = cli_rpc_pipe_open_noauth(cli,
					  &ndr_table_netlogon,
					  &netlogon_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("%s: failed to open noauth netlogon connection to %s - %s\n",
			 __FUNCTION__,
			 smbXcli_conn_remote_name(cli->conn),
			 nt_errstr(status)));
		TALLOC_FREE(frame);
		return status;
	}
	talloc_steal(frame, netlogon_pipe);

	status = netlogon_creds_cli_auth(netlogon_creds,
					 netlogon_pipe->binding_handle,
					 current_nt_hash,
					 previous_nt_hash);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(netlogon_creds,
					frame, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	DEBUG(5,("%s: using new netlogon_creds cli[%s/%s] to %s\n",
		 __FUNCTION__,
		 creds->account_name, creds->computer_name,
		 smbXcli_conn_remote_name(cli->conn)));

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS map_validation_to_info3(TALLOC_CTX *mem_ctx,
					uint16_t validation_level,
					union netr_Validation *validation,
					struct netr_SamInfo3 **info3_p)
{
	struct netr_SamInfo3 *info3;
	NTSTATUS status;

	if (validation == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (validation_level) {
	case 3:
		if (validation->sam3 == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		info3 = talloc_move(mem_ctx, &validation->sam3);
		break;
	case 6:
		if (validation->sam6 == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		info3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
		if (info3 == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		status = copy_netr_SamBaseInfo(info3, &validation->sam6->base, &info3->base);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(info3);
			return status;
		}

		info3->sidcount = validation->sam6->sidcount;
		info3->sids = talloc_move(info3, &validation->sam6->sids);
		break;
	default:
		return NT_STATUS_BAD_VALIDATION_CLASS;
	}

	*info3_p = info3;

	return NT_STATUS_OK;
}

/* Logon domain user */

NTSTATUS rpccli_netlogon_password_logon(struct netlogon_creds_cli_context *creds,
					struct dcerpc_binding_handle *binding_handle,
					TALLOC_CTX *mem_ctx,
					uint32_t logon_parameters,
					const char *domain,
					const char *username,
					const char *password,
					const char *workstation,
					enum netr_LogonInfoClass logon_type,
					struct netr_SamInfo3 **info3)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	union netr_LogonLevel *logon;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	uint8_t authoritative = 0;
	uint32_t flags = 0;
	char *workstation_slash = NULL;

	logon = talloc_zero(frame, union netr_LogonLevel);
	if (logon == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (workstation == NULL) {
		workstation = lp_netbios_name();
	}

	workstation_slash = talloc_asprintf(frame, "\\\\%s", workstation);
	if (workstation_slash == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* Initialise input parameters */

	switch (logon_type) {
	case NetlogonInteractiveInformation: {

		struct netr_PasswordInfo *password_info;

		struct samr_Password lmpassword;
		struct samr_Password ntpassword;

		password_info = talloc_zero(frame, struct netr_PasswordInfo);
		if (password_info == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		nt_lm_owf_gen(password, ntpassword.hash, lmpassword.hash);

		password_info->identity_info.domain_name.string		= domain;
		password_info->identity_info.parameter_control		= logon_parameters;
		password_info->identity_info.logon_id_low		= 0xdead;
		password_info->identity_info.logon_id_high		= 0xbeef;
		password_info->identity_info.account_name.string	= username;
		password_info->identity_info.workstation.string		= workstation_slash;

		password_info->lmpassword = lmpassword;
		password_info->ntpassword = ntpassword;

		logon->password = password_info;

		break;
	}
	case NetlogonNetworkInformation: {
		struct netr_NetworkInfo *network_info;
		uint8 chal[8];
		unsigned char local_lm_response[24];
		unsigned char local_nt_response[24];
		struct netr_ChallengeResponse lm;
		struct netr_ChallengeResponse nt;

		ZERO_STRUCT(lm);
		ZERO_STRUCT(nt);

		network_info = talloc_zero(frame, struct netr_NetworkInfo);
		if (network_info == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		generate_random_buffer(chal, 8);

		SMBencrypt(password, chal, local_lm_response);
		SMBNTencrypt(password, chal, local_nt_response);

		lm.length = 24;
		lm.data = local_lm_response;

		nt.length = 24;
		nt.data = local_nt_response;

		network_info->identity_info.domain_name.string		= domain;
		network_info->identity_info.parameter_control		= logon_parameters;
		network_info->identity_info.logon_id_low		= 0xdead;
		network_info->identity_info.logon_id_high		= 0xbeef;
		network_info->identity_info.account_name.string		= username;
		network_info->identity_info.workstation.string		= workstation_slash;

		memcpy(network_info->challenge, chal, 8);
		network_info->nt = nt;
		network_info->lm = lm;

		logon->network = network_info;

		break;
	}
	default:
		DEBUG(0, ("switch value %d not supported\n",
			logon_type));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	status = netlogon_creds_cli_LogonSamLogon(creds,
						  binding_handle,
						  logon_type,
						  logon,
						  frame,
						  &validation_level,
						  &validation,
						  &authoritative,
						  &flags);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = map_validation_to_info3(mem_ctx,
					 validation_level, validation,
					 info3);
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}


	return NT_STATUS_OK;
}

/**
 * Logon domain user with an 'network' SAM logon
 *
 * @param info3 Pointer to a NET_USER_INFO_3 already allocated by the caller.
 **/


NTSTATUS rpccli_netlogon_network_logon(struct netlogon_creds_cli_context *creds,
				       struct dcerpc_binding_handle *binding_handle,
				       TALLOC_CTX *mem_ctx,
				       uint32_t logon_parameters,
				       const char *username,
				       const char *domain,
				       const char *workstation,
				       const uint8 chal[8],
				       DATA_BLOB lm_response,
				       DATA_BLOB nt_response,
				       uint8_t *authoritative,
				       uint32_t *flags,
				       struct netr_SamInfo3 **info3)
{
	NTSTATUS status;
	const char *workstation_name_slash;
	union netr_LogonLevel *logon = NULL;
	struct netr_NetworkInfo *network_info;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	uint8_t _authoritative = 0;
	uint32_t _flags = 0;
	struct netr_ChallengeResponse lm;
	struct netr_ChallengeResponse nt;

	*info3 = NULL;

	if (authoritative == NULL) {
		authoritative = &_authoritative;
	}
	if (flags == NULL) {
		flags = &_flags;
	}

	ZERO_STRUCT(lm);
	ZERO_STRUCT(nt);

	logon = talloc_zero(mem_ctx, union netr_LogonLevel);
	if (!logon) {
		return NT_STATUS_NO_MEMORY;
	}

	network_info = talloc_zero(mem_ctx, struct netr_NetworkInfo);
	if (!network_info) {
		return NT_STATUS_NO_MEMORY;
	}

	if (workstation[0] != '\\' && workstation[1] != '\\') {
		workstation_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", workstation);
	} else {
		workstation_name_slash = workstation;
	}

	if (!workstation_name_slash) {
		DEBUG(0, ("talloc_asprintf failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Initialise input parameters */

	lm.data = lm_response.data;
	lm.length = lm_response.length;
	nt.data = nt_response.data;
	nt.length = nt_response.length;

	network_info->identity_info.domain_name.string		= domain;
	network_info->identity_info.parameter_control		= logon_parameters;
	network_info->identity_info.logon_id_low		= 0xdead;
	network_info->identity_info.logon_id_high		= 0xbeef;
	network_info->identity_info.account_name.string		= username;
	network_info->identity_info.workstation.string		= workstation_name_slash;

	memcpy(network_info->challenge, chal, 8);
	network_info->nt = nt;
	network_info->lm = lm;

	logon->network = network_info;

	/* Marshall data and send request */

	status = netlogon_creds_cli_LogonSamLogon(creds,
						  binding_handle,
						  NetlogonNetworkInformation,
						  logon,
						  mem_ctx,
						  &validation_level,
						  &validation,
						  authoritative,
						  flags);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = map_validation_to_info3(mem_ctx,
					 validation_level, validation,
					 info3);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}
