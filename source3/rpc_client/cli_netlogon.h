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

#ifndef _RPC_CLIENT_CLI_NETLOGON_H_
#define _RPC_CLIENT_CLI_NETLOGON_H_

struct cli_state;
struct messaging_context;
struct netlogon_creds_cli_context;
struct dcerpc_binding_handle;

/* The following definitions come from rpc_client/cli_netlogon.c  */

NTSTATUS rpccli_pre_open_netlogon_creds(void);
NTSTATUS rpccli_create_netlogon_creds(const char *server_computer,
				      const char *server_netbios_domain,
				      const char *client_account,
				      enum netr_SchannelType sec_chan_type,
				      struct messaging_context *msg_ctx,
				      TALLOC_CTX *mem_ctx,
				      struct netlogon_creds_cli_context **netlogon_creds);
NTSTATUS rpccli_setup_netlogon_creds(struct cli_state *cli,
				     struct netlogon_creds_cli_context *netlogon_creds,
				     bool force_reauth,
				     struct samr_Password current_nt_hash,
				     const struct samr_Password *previous_nt_hash);
NTSTATUS rpccli_netlogon_password_logon(struct netlogon_creds_cli_context *creds,
					struct dcerpc_binding_handle *binding_handle,
					TALLOC_CTX *mem_ctx,
					uint32_t logon_parameters,
					const char *domain,
					const char *username,
					const char *password,
					const char *workstation,
					enum netr_LogonInfoClass logon_type,
					struct netr_SamInfo3 **info3);
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
				       struct netr_SamInfo3 **info3);

#endif /* _RPC_CLIENT_CLI_NETLOGON_H_ */
