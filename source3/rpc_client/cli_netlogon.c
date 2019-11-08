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
#include "rpc_client/util_netlogon.h"
#include "../libcli/security/security.h"
#include "lib/param/param.h"
#include "libcli/smb/smbXcli_base.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "util_tdb.h"
#include "lib/crypto/gnutls_helpers.h"


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

	global_db = db_open(frame, fname,
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

static NTSTATUS rpccli_create_netlogon_creds(
	const char *server_computer,
	const char *server_netbios_domain,
	const char *server_dns_domain,
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
						   server_dns_domain,
						   mem_ctx, netlogon_creds);
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS rpccli_create_netlogon_creds_ctx(
	struct cli_credentials *creds,
	const char *server_computer,
	struct messaging_context *msg_ctx,
	TALLOC_CTX *mem_ctx,
	struct netlogon_creds_cli_context **creds_ctx)
{
	enum netr_SchannelType sec_chan_type;
	const char *server_netbios_domain;
	const char *server_dns_domain;
	const char *client_account;

	sec_chan_type = cli_credentials_get_secure_channel_type(creds);
	client_account = cli_credentials_get_username(creds);
	server_netbios_domain = cli_credentials_get_domain(creds);
	server_dns_domain = cli_credentials_get_realm(creds);

	return rpccli_create_netlogon_creds(server_computer,
					    server_netbios_domain,
					    server_dns_domain,
					    client_account,
					    sec_chan_type,
					    msg_ctx, mem_ctx,
					    creds_ctx);
}

NTSTATUS rpccli_setup_netlogon_creds_locked(
	struct cli_state *cli,
	enum dcerpc_transport_t transport,
	struct netlogon_creds_cli_context *creds_ctx,
	bool force_reauth,
	struct cli_credentials *cli_creds,
	uint32_t *negotiate_flags)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_CredentialState *creds = NULL;
	uint8_t num_nt_hashes = 0;
	const struct samr_Password *nt_hashes[2] = { NULL, NULL };
	uint8_t idx_nt_hashes = 0;
	NTSTATUS status;

	status = netlogon_creds_cli_get(creds_ctx, frame, &creds);
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
			goto done;
		}
		TALLOC_FREE(creds);
	}

	nt_hashes[0] = cli_credentials_get_nt_hash(cli_creds, talloc_tos());
	if (nt_hashes[0] == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	num_nt_hashes = 1;

	nt_hashes[1] = cli_credentials_get_old_nt_hash(cli_creds,
						       talloc_tos());
	if (nt_hashes[1] != NULL) {
		num_nt_hashes = 2;
	}

	status = cli_rpc_pipe_open_noauth_transport(cli,
						    transport,
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

	status = netlogon_creds_cli_auth(creds_ctx,
					 netlogon_pipe->binding_handle,
					 num_nt_hashes,
					 nt_hashes,
					 &idx_nt_hashes);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(creds_ctx, frame, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	DEBUG(5,("%s: using new netlogon_creds cli[%s/%s] to %s\n",
		 __FUNCTION__,
		 creds->account_name, creds->computer_name,
		 smbXcli_conn_remote_name(cli->conn)));

done:
	if (negotiate_flags != NULL) {
		*negotiate_flags = creds->negotiate_flags;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS rpccli_setup_netlogon_creds(
	struct cli_state *cli,
	enum dcerpc_transport_t transport,
	struct netlogon_creds_cli_context *creds_ctx,
	bool force_reauth,
	struct cli_credentials *cli_creds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct netlogon_creds_cli_lck *lck;
	NTSTATUS status;

	status = netlogon_creds_cli_lck(
		creds_ctx, NETLOGON_CREDS_CLI_LCK_EXCLUSIVE,
		frame, &lck);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("netlogon_creds_cli_lck failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return status;
	}

	status = rpccli_setup_netlogon_creds_locked(
		cli, transport, creds_ctx, force_reauth, cli_creds, NULL);

	TALLOC_FREE(frame);

	return status;
}

NTSTATUS rpccli_connect_netlogon(
	struct cli_state *cli,
	enum dcerpc_transport_t transport,
	struct netlogon_creds_cli_context *creds_ctx,
	bool force_reauth,
	struct cli_credentials *trust_creds,
	struct rpc_pipe_client **_rpccli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct netlogon_creds_CredentialState *creds = NULL;
	enum netlogon_creds_cli_lck_type lck_type;
	enum netr_SchannelType sec_chan_type;
	struct netlogon_creds_cli_lck *lck = NULL;
	uint32_t negotiate_flags;
	uint8_t found_session_key[16] = {0};
	bool found_existing_creds = false;
	bool do_serverauth;
	struct rpc_pipe_client *rpccli;
	NTSTATUS status;
	bool retry = false;

	sec_chan_type = cli_credentials_get_secure_channel_type(trust_creds);
	if (sec_chan_type == SEC_CHAN_NULL) {
		DBG_ERR("secure_channel_type gave SEC_CHAN_NULL\n");
		status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto fail;
	}

again:

	/*
	 * See whether we can use existing netlogon_creds or
	 * whether we have to serverauthenticate.
	 */
	status = netlogon_creds_cli_get(creds_ctx, frame, &creds);

	if (NT_STATUS_IS_OK(status)) {
		int cmp = memcmp(found_session_key,
				 creds->session_key,
				 sizeof(found_session_key));
		found_existing_creds = (cmp != 0);

		memcpy(found_session_key,
		       creds->session_key,
		       sizeof(found_session_key));

		TALLOC_FREE(creds);
	}

	lck_type = (force_reauth || !found_existing_creds) ?
		NETLOGON_CREDS_CLI_LCK_EXCLUSIVE :
		NETLOGON_CREDS_CLI_LCK_SHARED;

	status = netlogon_creds_cli_lck(creds_ctx, lck_type, frame, &lck);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("netlogon_creds_cli_lck failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	if (!found_existing_creds) {
		/*
		 * Try to find creds under the lock again. Someone
		 * else might have done it for us.
		 */
		status = netlogon_creds_cli_get(creds_ctx, frame, &creds);

		if (NT_STATUS_IS_OK(status)) {
			int cmp = memcmp(found_session_key,
					 creds->session_key,
					 sizeof(found_session_key));
			found_existing_creds = (cmp != 0);

			memcpy(found_session_key, creds->session_key,
			       sizeof(found_session_key));

			TALLOC_FREE(creds);
		}
	}

	do_serverauth = force_reauth || !found_existing_creds;

	if (!do_serverauth) {
		/*
		 * Do the quick schannel bind without a reauth
		 */
		status = cli_rpc_pipe_open_bind_schannel(
			cli, &ndr_table_netlogon, transport, creds_ctx,
			&rpccli);
		if (!retry && NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED)) {
			DBG_DEBUG("Retrying with serverauthenticate\n");
			TALLOC_FREE(lck);
			retry = true;
			goto again;
		}
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("cli_rpc_pipe_open_bind_schannel "
				  "failed: %s\n", nt_errstr(status));
			goto fail;
		}
		goto done;
	}

	if (cli_credentials_is_anonymous(trust_creds)) {
		DBG_WARNING("get_trust_credential for %s only gave anonymous,"
			    "unable to negotiate NETLOGON credentials\n",
			    netlogon_creds_cli_debug_string(
				    creds_ctx, frame));
		status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		goto fail;
	}

	status = rpccli_setup_netlogon_creds_locked(
		cli, transport, creds_ctx, true, trust_creds,
		&negotiate_flags);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpccli_setup_netlogon_creds failed for %s, "
			  "unable to setup NETLOGON credentials: %s\n",
			  netlogon_creds_cli_debug_string(
				  creds_ctx, frame),
			  nt_errstr(status));
		goto fail;
	}

	if (!(negotiate_flags & NETLOGON_NEG_AUTHENTICATED_RPC)) {
		if (lp_winbind_sealed_pipes() || lp_require_strong_key()) {
			status = NT_STATUS_DOWNGRADE_DETECTED;
			DBG_WARNING("Unwilling to make connection to %s"
				    "without connection level security, "
				    "must set 'winbind sealed pipes = false'"
				    " and 'require strong key = false' "
				    "to proceed: %s\n",
				    netlogon_creds_cli_debug_string(
					    creds_ctx, frame),
				    nt_errstr(status));
			goto fail;
		}

		status = cli_rpc_pipe_open_noauth_transport(
			cli, transport, &ndr_table_netlogon, &rpccli);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("cli_rpc_pipe_open_noauth_transport "
				  "failed: %s\n", nt_errstr(status));
			goto fail;
		}
		goto done;
	}

	status = cli_rpc_pipe_open_bind_schannel(
		cli, &ndr_table_netlogon, transport, creds_ctx, &rpccli);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("cli_rpc_pipe_open_bind_schannel "
			  "failed: %s\n", nt_errstr(status));
		goto fail;
	}

	status = netlogon_creds_cli_check(creds_ctx, rpccli->binding_handle,
					  NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("netlogon_creds_cli_check failed: %s\n",
			    nt_errstr(status));
		goto fail;
	}

done:
	*_rpccli = rpccli;
	status = NT_STATUS_OK;
fail:
	ZERO_STRUCT(found_session_key);
	TALLOC_FREE(lck);
	TALLOC_FREE(frame);
	return status;
}

/* Logon domain user */

NTSTATUS rpccli_netlogon_password_logon(
	struct netlogon_creds_cli_context *creds_ctx,
	struct dcerpc_binding_handle *binding_handle,
	TALLOC_CTX *mem_ctx,
	uint32_t logon_parameters,
	const char *domain,
	const char *username,
	const char *password,
	const char *workstation,
	const uint64_t logon_id,
	enum netr_LogonInfoClass logon_type,
	uint8_t *authoritative,
	uint32_t *flags,
	uint16_t *_validation_level,
	union netr_Validation **_validation)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	union netr_LogonLevel *logon;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	char *workstation_slash = NULL;

	unsigned char local_nt_response[24];
	unsigned char local_lm_response[24];
	struct samr_Password lmpassword = {.hash = {0}};
	struct samr_Password ntpassword = {.hash = {0}};
	struct netr_ChallengeResponse lm = {0};
	struct netr_ChallengeResponse nt = {0};

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
	case NetlogonInteractiveInformation:
	case NetlogonInteractiveTransitiveInformation: {

		struct netr_PasswordInfo *password_info;


		password_info = talloc_zero(frame, struct netr_PasswordInfo);
		if (password_info == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		nt_lm_owf_gen(password, ntpassword.hash, lmpassword.hash);

		password_info->identity_info.domain_name.string		= domain;
		password_info->identity_info.parameter_control		= logon_parameters;
		password_info->identity_info.logon_id			= logon_id;
		password_info->identity_info.account_name.string	= username;
		password_info->identity_info.workstation.string		= workstation_slash;

		password_info->lmpassword = lmpassword;
		password_info->ntpassword = ntpassword;

		logon->password = password_info;

		break;
	}
	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation: {
		struct netr_NetworkInfo *network_info;
		uint8_t chal[8];
		int rc;

		ZERO_STRUCT(lm);
		ZERO_STRUCT(nt);

		network_info = talloc_zero(frame, struct netr_NetworkInfo);
		if (network_info == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		generate_random_buffer(chal, 8);

		SMBencrypt(password, chal, local_lm_response);
		rc = SMBNTencrypt(password, chal, local_nt_response);
		if (rc != 0) {
			TALLOC_FREE(frame);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		}

		lm.length = 24;
		lm.data = local_lm_response;

		nt.length = 24;
		nt.data = local_nt_response;

		network_info->identity_info.domain_name.string		= domain;
		network_info->identity_info.parameter_control		= logon_parameters;
		network_info->identity_info.logon_id			= logon_id;
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

	status = netlogon_creds_cli_LogonSamLogon(creds_ctx,
						  binding_handle,
						  logon_type,
						  logon,
						  mem_ctx,
						  &validation_level,
						  &validation,
						  authoritative,
						  flags);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);
	*_validation_level = validation_level;
	*_validation = validation;

	return NT_STATUS_OK;
}

/**
 * Logon domain user with an 'network' SAM logon
 *
 * @param info3 Pointer to a NET_USER_INFO_3 already allocated by the caller.
 **/


NTSTATUS rpccli_netlogon_network_logon(
	struct netlogon_creds_cli_context *creds_ctx,
	struct dcerpc_binding_handle *binding_handle,
	TALLOC_CTX *mem_ctx,
	uint32_t logon_parameters,
	const char *username,
	const char *domain,
	const char *workstation,
	const uint64_t logon_id,
	const uint8_t chal[8],
	DATA_BLOB lm_response,
	DATA_BLOB nt_response,
	enum netr_LogonInfoClass logon_type,
	uint8_t *authoritative,
	uint32_t *flags,
	uint16_t *_validation_level,
	union netr_Validation **_validation)
{
	NTSTATUS status;
	const char *workstation_name_slash;
	union netr_LogonLevel *logon = NULL;
	struct netr_NetworkInfo *network_info;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	struct netr_ChallengeResponse lm;
	struct netr_ChallengeResponse nt;

	*_validation = NULL;

	ZERO_STRUCT(lm);
	ZERO_STRUCT(nt);

	switch (logon_type) {
	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		break;
	default:
		DEBUG(0, ("switch value %d not supported\n",
			logon_type));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

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
	network_info->identity_info.logon_id			= logon_id;
	network_info->identity_info.account_name.string		= username;
	network_info->identity_info.workstation.string		= workstation_name_slash;

	memcpy(network_info->challenge, chal, 8);
	network_info->nt = nt;
	network_info->lm = lm;

	logon->network = network_info;

	/* Marshall data and send request */

	status = netlogon_creds_cli_LogonSamLogon(creds_ctx,
						  binding_handle,
						  logon_type,
						  logon,
						  mem_ctx,
						  &validation_level,
						  &validation,
						  authoritative,
						  flags);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_validation_level = validation_level;
	*_validation = validation;

	return NT_STATUS_OK;
}

NTSTATUS rpccli_netlogon_interactive_logon(
	struct netlogon_creds_cli_context *creds_ctx,
	struct dcerpc_binding_handle *binding_handle,
	TALLOC_CTX *mem_ctx,
	uint32_t logon_parameters,
	const char *username,
	const char *domain,
	const char *workstation,
	const uint64_t logon_id,
	DATA_BLOB lm_hash,
	DATA_BLOB nt_hash,
	enum netr_LogonInfoClass logon_type,
	uint8_t *authoritative,
	uint32_t *flags,
	uint16_t *_validation_level,
	union netr_Validation **_validation)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	const char *workstation_name_slash;
	union netr_LogonLevel *logon = NULL;
	struct netr_PasswordInfo *password_info = NULL;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	struct netr_ChallengeResponse lm;
	struct netr_ChallengeResponse nt;

	*_validation = NULL;

	ZERO_STRUCT(lm);
	ZERO_STRUCT(nt);

	switch (logon_type) {
	case NetlogonInteractiveInformation:
	case NetlogonInteractiveTransitiveInformation:
		break;
	default:
		DEBUG(0, ("switch value %d not supported\n",
			logon_type));
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	logon = talloc_zero(mem_ctx, union netr_LogonLevel);
	if (logon == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	password_info = talloc_zero(logon, struct netr_PasswordInfo);
	if (password_info == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (workstation[0] != '\\' && workstation[1] != '\\') {
		workstation_name_slash = talloc_asprintf(frame, "\\\\%s", workstation);
	} else {
		workstation_name_slash = workstation;
	}

	if (workstation_name_slash == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* Initialise input parameters */

	password_info->identity_info.domain_name.string		= domain;
	password_info->identity_info.parameter_control		= logon_parameters;
	password_info->identity_info.logon_id			= logon_id;
	password_info->identity_info.account_name.string	= username;
	password_info->identity_info.workstation.string		= workstation_name_slash;

	if (nt_hash.length != sizeof(password_info->ntpassword.hash)) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}
	memcpy(password_info->ntpassword.hash, nt_hash.data, nt_hash.length);
	if (lm_hash.length != 0) {
		if (lm_hash.length != sizeof(password_info->lmpassword.hash)) {
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_PARAMETER;
		}
		memcpy(password_info->lmpassword.hash, lm_hash.data, lm_hash.length);
	}

	logon->password = password_info;

	/* Marshall data and send request */

	status = netlogon_creds_cli_LogonSamLogon(creds_ctx,
						  binding_handle,
						  logon_type,
						  logon,
						  mem_ctx,
						  &validation_level,
						  &validation,
						  authoritative,
						  flags);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	*_validation_level = validation_level;
	*_validation = validation;

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
