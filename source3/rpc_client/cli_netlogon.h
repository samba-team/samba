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
struct cli_credentials;
struct netlogon_creds_cli_context;
struct dcerpc_binding_handle;
#include "librpc/rpc/rpc_common.h"

/* The following definitions come from rpc_client/cli_netlogon.c  */

NTSTATUS rpccli_pre_open_netlogon_creds(void);
NTSTATUS rpccli_create_netlogon_creds_ctx(
	struct cli_credentials *creds,
	const char *server_computer,
	struct messaging_context *msg_ctx,
	TALLOC_CTX *mem_ctx,
	struct netlogon_creds_cli_context **creds_ctx);
NTSTATUS rpccli_setup_netlogon_creds_locked(
	struct cli_state *cli,
	enum dcerpc_transport_t transport,
	struct netlogon_creds_cli_context *creds_ctx,
	bool force_reauth,
	struct cli_credentials *cli_creds,
	uint32_t *negotiate_flags);
NTSTATUS rpccli_setup_netlogon_creds(
	struct cli_state *cli,
	enum dcerpc_transport_t transport,
	struct netlogon_creds_cli_context *creds_ctx,
	bool force_reauth,
	struct cli_credentials *cli_creds);
NTSTATUS rpccli_connect_netlogon(
	struct cli_state *cli,
	enum dcerpc_transport_t transport,
	struct netlogon_creds_cli_context *creds_ctx,
	bool force_reauth,
	struct cli_credentials *trust_creds,
	struct rpc_pipe_client **_rpccli);
NTSTATUS rpccli_netlogon_password_logon(
	struct netlogon_creds_cli_context *creds,
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
	union netr_Validation **_validation);
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
	union netr_Validation **_validation);
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
	union netr_Validation **_validation);

#endif /* _RPC_CLIENT_CLI_NETLOGON_H_ */
