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
#include "rpc_client/rpc_client.h"
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/auth/netlogon_creds_cli.h"
#include "../librpc/gen_ndr/ndr_netlogon_c.h"
#include "rpc_client/cli_netlogon.h"
#include "rpc_client/init_netlogon.h"
#include "rpc_client/util_netlogon.h"
#include "../libcli/security/security.h"
#include "lib/param/param.h"

/****************************************************************************
 Wrapper function that uses the auth and auth2 calls to set up a NETLOGON
 credentials chain. Stores the credentials in the struct dcinfo in the
 netlogon pipe struct.
****************************************************************************/

NTSTATUS rpccli_netlogon_setup_creds(struct rpc_pipe_client *cli,
				     const char *server_name,
				     const char *domain,
				     const char *clnt_name,
				     const char *machine_account,
				     const unsigned char machine_pwd[16],
				     enum netr_SchannelType sec_chan_type,
				     uint32_t *neg_flags_inout)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct loadparm_context *lp_ctx;
	NTSTATUS status;
	struct samr_Password password;
	fstring mach_acct;
	struct dcerpc_binding_handle *b = cli->binding_handle;
	struct netlogon_creds_CredentialState *creds = NULL;

	if (!ndr_syntax_id_equal(&cli->abstract_syntax,
				 &ndr_table_netlogon.syntax_id)) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!strequal(lp_netbios_name(), clnt_name)) {
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	TALLOC_FREE(cli->netlogon_creds);

	fstr_sprintf( mach_acct, "%s$", machine_account);

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	status = netlogon_creds_cli_context_global(lp_ctx,
						   NULL, /* msg_ctx */
						   mach_acct,
						   sec_chan_type,
						   server_name,
						   domain,
						   cli, &cli->netlogon_creds);
	talloc_unlink(frame, lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(cli->netlogon_creds,
					frame, &creds);
	if (NT_STATUS_IS_OK(status)) {
		DEBUG(5,("rpccli_netlogon_setup_creds: server %s using "
			 "cached credential\n",
			 cli->desthost));
		*neg_flags_inout = creds->negotiate_flags;
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	/* Store the machine account password we're going to use. */
	memcpy(password.hash, machine_pwd, 16);

	DEBUG(5,("rpccli_netlogon_setup_creds: server %s credential "
		"chain established.\n",
		cli->desthost ));

	status = netlogon_creds_cli_auth(cli->netlogon_creds, b,
					 password, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(cli->netlogon_creds,
					frame, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	*neg_flags_inout = creds->negotiate_flags;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/* Logon domain user */

NTSTATUS rpccli_netlogon_sam_logon(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   uint32 logon_parameters,
				   const char *domain,
				   const char *username,
				   const char *password,
				   const char *workstation,
				   uint16_t _ignored_validation_level,
				   int logon_type)
{
	NTSTATUS status;
	union netr_LogonLevel *logon;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	uint8_t authoritative = 0;
	uint32_t flags = 0;
	fstring clnt_name_slash;

	logon = talloc_zero(mem_ctx, union netr_LogonLevel);
	if (!logon) {
		return NT_STATUS_NO_MEMORY;
	}

	if (workstation) {
		fstr_sprintf( clnt_name_slash, "\\\\%s", workstation );
	} else {
		fstr_sprintf( clnt_name_slash, "\\\\%s", lp_netbios_name() );
	}

	/* Initialise input parameters */

	switch (logon_type) {
	case NetlogonInteractiveInformation: {

		struct netr_PasswordInfo *password_info;

		struct samr_Password lmpassword;
		struct samr_Password ntpassword;

		password_info = talloc_zero(mem_ctx, struct netr_PasswordInfo);
		if (!password_info) {
			return NT_STATUS_NO_MEMORY;
		}

		nt_lm_owf_gen(password, ntpassword.hash, lmpassword.hash);

		password_info->identity_info.domain_name.string		= domain;
		password_info->identity_info.parameter_control		= logon_parameters;
		password_info->identity_info.logon_id_low		= 0xdead;
		password_info->identity_info.logon_id_high		= 0xbeef;
		password_info->identity_info.account_name.string	= username;
		password_info->identity_info.workstation.string		= clnt_name_slash;

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

		network_info = talloc_zero(mem_ctx, struct netr_NetworkInfo);
		if (!network_info) {
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
		network_info->identity_info.workstation.string		= clnt_name_slash;

		memcpy(network_info->challenge, chal, 8);
		network_info->nt = nt;
		network_info->lm = lm;

		logon->network = network_info;

		break;
	}
	default:
		DEBUG(0, ("switch value %d not supported\n",
			logon_type));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	status = netlogon_creds_cli_LogonSamLogon(cli->netlogon_creds,
						  cli->binding_handle,
						  logon_type,
						  logon,
						  mem_ctx,
						  &validation_level,
						  &validation,
						  &authoritative,
						  &flags);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

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

/**
 * Logon domain user with an 'network' SAM logon
 *
 * @param info3 Pointer to a NET_USER_INFO_3 already allocated by the caller.
 **/

NTSTATUS rpccli_netlogon_sam_network_logon(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   uint32 logon_parameters,
					   const char *server,
					   const char *username,
					   const char *domain,
					   const char *workstation,
					   const uint8 chal[8],
					   uint16_t _ignored_validation_level,
					   DATA_BLOB lm_response,
					   DATA_BLOB nt_response,
					   struct netr_SamInfo3 **info3)
{
	NTSTATUS status;
	const char *workstation_name_slash;
	union netr_LogonLevel *logon = NULL;
	struct netr_NetworkInfo *network_info;
	uint16_t validation_level = 0;
	union netr_Validation *validation = NULL;
	uint8_t authoritative = 0;
	uint32_t flags = 0;
	struct netr_ChallengeResponse lm;
	struct netr_ChallengeResponse nt;

	*info3 = NULL;

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

	status = netlogon_creds_cli_LogonSamLogon(cli->netlogon_creds,
						  cli->binding_handle,
						  NetlogonNetworkInformation,
						  logon,
						  mem_ctx,
						  &validation_level,
						  &validation,
						  &authoritative,
						  &flags);
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

NTSTATUS rpccli_netlogon_sam_network_logon_ex(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      uint32 logon_parameters,
					      const char *server,
					      const char *username,
					      const char *domain,
					      const char *workstation,
					      const uint8 chal[8],
					      uint16_t validation_level,
					      DATA_BLOB lm_response,
					      DATA_BLOB nt_response,
					      struct netr_SamInfo3 **info3)
{
	return rpccli_netlogon_sam_network_logon(cli,
						 mem_ctx,
						 logon_parameters,
						 server,
						 username,
						 domain,
						 workstation,
						 chal,
						 validation_level,
						 lm_response,
						 nt_response,
						 info3);
}

/*********************************************************
 Change the domain password on the PDC.

 Just changes the password betwen the two values specified.

 Caller must have the cli connected to the netlogon pipe
 already.
**********************************************************/

NTSTATUS rpccli_netlogon_set_trust_password(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    const char *account_name,
					    const unsigned char orig_trust_passwd_hash[16],
					    const char *new_trust_pwd_cleartext,
					    const unsigned char new_trust_passwd_hash[16],
					    enum netr_SchannelType sec_channel_type)
{
	NTSTATUS result;

	if (cli->netlogon_creds == NULL) {
		uint32_t neg_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS |
					NETLOGON_NEG_SUPPORTS_AES;
		result = rpccli_netlogon_setup_creds(cli,
						     cli->desthost, /* server name */
						     lp_workgroup(), /* domain */
						     lp_netbios_name(), /* client name */
						     account_name, /* machine account name */
						     orig_trust_passwd_hash,
						     sec_channel_type,
						     &neg_flags);
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3,("rpccli_netlogon_set_trust_password: unable to setup creds (%s)!\n",
				 nt_errstr(result)));
			return result;
		}
	}

	result = netlogon_creds_cli_ServerPasswordSet(cli->netlogon_creds,
						      cli->binding_handle,
						      new_trust_pwd_cleartext,
						      NULL); /* new_version */
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("netlogon_creds_cli_ServerPasswordSet failed: %s\n",
			nt_errstr(result)));
		return result;
	}

	return NT_STATUS_OK;
}

