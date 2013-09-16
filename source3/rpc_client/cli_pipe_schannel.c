/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Largely rewritten by Jeremy Allison		    2005.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../librpc/gen_ndr/ndr_schannel.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../libcli/auth/schannel.h"
#include "rpc_client/cli_netlogon.h"
#include "rpc_client/cli_pipe.h"
#include "librpc/rpc/dcerpc.h"
#include "passdb.h"
#include "libsmb/libsmb.h"
#include "../libcli/smb/smbXcli_base.h"
#include "libcli/auth/netlogon_creds_cli.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_CLI

/****************************************************************************
 Open a named pipe to an SMB server and bind using schannel (bind type 68).
 Fetch the session key ourselves using a temporary netlogon pipe.
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_schannel(struct cli_state *cli,
				    struct messaging_context *msg_ctx,
				    const struct ndr_interface_table *table,
				    enum dcerpc_transport_t transport,
				    enum dcerpc_AuthLevel auth_level,
				    const char *domain,
				    struct rpc_pipe_client **presult,
				    TALLOC_CTX *mem_ctx,
				    struct netlogon_creds_cli_context **pcreds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *dc_name = smbXcli_conn_remote_name(cli->conn);
	struct rpc_pipe_client *result = NULL;
	NTSTATUS status;
	struct netlogon_creds_cli_context *netlogon_creds = NULL;
	struct netlogon_creds_CredentialState *creds = NULL;
	uint32_t netlogon_flags = 0;
	enum netr_SchannelType sec_chan_type = 0;
	const char *_account_name = NULL;
	const char *account_name = NULL;
	struct samr_Password current_nt_hash;
	struct samr_Password *previous_nt_hash = NULL;
	bool ok;

	ok = get_trust_pw_hash(domain,
			       current_nt_hash.hash,
			       &_account_name,
			       &sec_chan_type);
	if (!ok) {
		TALLOC_FREE(frame);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	account_name = talloc_asprintf(frame, "%s$", _account_name);
	if (account_name == NULL) {
		SAFE_FREE(previous_nt_hash);
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = rpccli_create_netlogon_creds(dc_name,
					      domain,
					      account_name,
					      sec_chan_type,
					      msg_ctx,
					      frame,
					      &netlogon_creds);
	if (!NT_STATUS_IS_OK(status)) {
		SAFE_FREE(previous_nt_hash);
		TALLOC_FREE(frame);
		return status;
	}

	status = rpccli_setup_netlogon_creds(cli,
					     netlogon_creds,
					     false, /* force_reauth */
					     current_nt_hash,
					     previous_nt_hash);
	SAFE_FREE(previous_nt_hash);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(netlogon_creds,
					frame,
					&creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}
	netlogon_flags = creds->negotiate_flags;
	TALLOC_FREE(creds);

	if (!(netlogon_flags & NETLOGON_NEG_AUTHENTICATED_RPC)) {
		TALLOC_FREE(frame);
		return NT_STATUS_DOWNGRADE_DETECTED;
	}

	status = cli_rpc_pipe_open_schannel_with_key(
		cli, table, transport, domain,
		netlogon_creds,
		&result);

	if (NT_STATUS_IS_OK(status)) {
		*presult = result;
		if (pcreds != NULL) {
			*pcreds = talloc_move(mem_ctx, &netlogon_creds);
		}
	}

	TALLOC_FREE(frame);
	return status;
}
