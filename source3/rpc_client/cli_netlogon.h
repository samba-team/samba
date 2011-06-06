#ifndef __RPC_CLIENT_CLI_NETLOGON_H__
#define __RPC_CLIENT_CLI_NETLOGON_H__

/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

/* The following definitions come from rpc_client/cli_netlogon.c  */

NTSTATUS rpccli_netlogon_setup_creds(struct rpc_pipe_client *cli,
				     const char *server_name,
				     const char *domain,
				     const char *clnt_name,
				     const char *machine_account,
				     const unsigned char machine_pwd[16],
				     enum netr_SchannelType sec_chan_type,
				     uint32_t *neg_flags_inout);
NTSTATUS rpccli_netlogon_sam_logon(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   uint32 logon_parameters,
				   const char *domain,
				   const char *username,
				   const char *password,
				   const char *workstation,
				   uint16_t validation_level,
				   int logon_type);
NTSTATUS rpccli_netlogon_sam_network_logon(struct rpc_pipe_client *cli,
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
					   struct netr_SamInfo3 **info3);
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
					      struct netr_SamInfo3 **info3);
NTSTATUS rpccli_netlogon_set_trust_password(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    const char *account_name,
					    const unsigned char orig_trust_passwd_hash[16],
					    const char *new_trust_pwd_cleartext,
					    const unsigned char new_trust_passwd_hash[16],
					    enum netr_SchannelType sec_channel_type);
#endif
