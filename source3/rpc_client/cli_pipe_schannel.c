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
				    const char *domain,
				    struct rpc_pipe_client **presult,
				    TALLOC_CTX *mem_ctx,
				    struct netlogon_creds_cli_context **pcreds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *dc_name = smbXcli_conn_remote_name(cli->conn);
	struct rpc_pipe_client *result = NULL;
	NTSTATUS status;
	struct cli_credentials *cli_creds = NULL;
	struct netlogon_creds_cli_context *netlogon_creds = NULL;
	struct netlogon_creds_CredentialState *creds = NULL;
	uint32_t netlogon_flags;

	status = pdb_get_trust_credentials(domain, NULL,
					   frame, &cli_creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = rpccli_create_netlogon_creds_ctx(cli_creds,
						  dc_name,
						  msg_ctx,
						  frame,
						  &netlogon_creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = rpccli_setup_netlogon_creds(cli, transport,
					     netlogon_creds,
					     false, /* force_reauth */
					     cli_creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = netlogon_creds_cli_get(netlogon_creds, frame, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	netlogon_flags = creds->negotiate_flags;
	TALLOC_FREE(creds);

	if (netlogon_flags & NETLOGON_NEG_AUTHENTICATED_RPC) {
		status = cli_rpc_pipe_open_schannel_with_creds(cli, table,
							       transport,
							       netlogon_creds,
							       &result);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	} else {
		status = cli_rpc_pipe_open_noauth(cli, table, &result);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	}

	*presult = result;
	if (pcreds != NULL) {
		*pcreds = talloc_move(mem_ctx, &netlogon_creds);
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
