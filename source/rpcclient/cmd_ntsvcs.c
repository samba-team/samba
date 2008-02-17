/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Günther Deschner 2008

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
#include "rpcclient.h"

static WERROR cmd_ntsvcs_get_version(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     int argc,
				     const char **argv)
{
	NTSTATUS status;
	WERROR werr;
	uint16_t version;

	status = rpccli_PNP_GetVersion(cli, mem_ctx,
				       &version, &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (W_ERROR_IS_OK(werr)) {
		printf("version: %d\n", version);
	}

	return werr;
}

struct cmd_set ntsvcs_commands[] = {

	{ "NTSVCS" },
	{ "ntsvcs_getversion", RPC_RTYPE_WERROR, NULL, cmd_ntsvcs_get_version, PI_NTSVCS, NULL, "Query NTSVCS version", "" },
	{ NULL }
};
