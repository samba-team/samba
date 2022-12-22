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

#ifndef __LIBRPC_RPC_SERVER_NETLOGON_SCHANNEL_UTIL_H__
#define __LIBRPC_RPC_SERVER_NETLOGON_SCHANNEL_UTIL_H__

#include "replace.h"
#include <talloc.h>
#include "libcli/util/ntstatus.h"

#define NETLOGON_SERVER_PIPE_STATE_MAGIC 0x4f555358

struct dcesrv_call_state;
struct netlogon_creds_CredentialState;
struct netr_Authenticator;
enum dcerpc_AuthType;
enum dcerpc_AuthLevel;

NTSTATUS dcesrv_netr_check_schannel(
		struct dcesrv_call_state *dce_call,
		const struct netlogon_creds_CredentialState *creds,
		enum dcerpc_AuthType auth_type,
		enum dcerpc_AuthLevel auth_level,
		uint16_t opnum);

NTSTATUS dcesrv_netr_creds_server_step_check(
		struct dcesrv_call_state *dce_call,
		TALLOC_CTX *mem_ctx,
		const char *computer_name,
		struct netr_Authenticator *received_authenticator,
		struct netr_Authenticator *return_authenticator,
		struct netlogon_creds_CredentialState **creds_out);

#endif /* __LIBRPC_RPC_SERVER_NETLOGON_SCHANNEL_UTIL_H__ */
