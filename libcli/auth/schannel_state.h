/*
   Unix SMB/CIFS implementation.

   module to store/fetch session keys for the schannel server

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2008

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

#ifndef _LIBCLI_AUTH_SCHANNEL_STATE_H__
#define _LIBCLI_AUTH_SCHANNEL_STATE_H__

NTSTATUS schannel_get_creds_state(TALLOC_CTX *mem_ctx,
				  struct loadparm_context *lp_ctx,
				  const char *computer_name,
				  struct netlogon_creds_CredentialState **creds);

NTSTATUS schannel_save_creds_state(TALLOC_CTX *mem_ctx,
				   struct loadparm_context *lp_ctx,
				   struct netlogon_creds_CredentialState *creds);

NTSTATUS schannel_check_creds_state(TALLOC_CTX *mem_ctx,
				    struct loadparm_context *lp_ctx,
				    const char *computer_name,
				    struct netr_Authenticator *received_authenticator,
				    struct netr_Authenticator *return_authenticator,
				    struct netlogon_creds_CredentialState **creds_out);

NTSTATUS schannel_get_challenge(struct loadparm_context *lp_ctx,
				struct netr_Credential *client_challenge,
				struct netr_Credential *server_challenge,
				const char *computer_name);

NTSTATUS schannel_save_challenge(struct loadparm_context *lp_ctx,
				 const struct netr_Credential *client_challenge,
				 const struct netr_Credential *server_challenge,
				 const char *computer_name);

NTSTATUS schannel_delete_challenge(struct loadparm_context *lp_ctx,
				   const char *computer_name);
#endif
