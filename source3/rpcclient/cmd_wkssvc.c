/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Günther Deschner 2007

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

static WERROR cmd_wkssvc_wkstagetinfo(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx,
				      int argc,
				      const char **argv)
{
	NTSTATUS status;
	WERROR werr;
	uint32_t level = 100;
	union wkssvc_NetWkstaInfo info;
	const char *server_name;

	if (argc > 2) {
		printf("usage: %s <level>\n", argv[0]);
		return WERR_OK;
	}

	if (argc > 1) {
		level = atoi(argv[1]);
	}

	server_name = cli->cli->desthost;

	status = rpccli_wkssvc_NetWkstaGetInfo(cli, mem_ctx,
					       server_name,
					       level,
					       &info,
					       &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	return werr;
}

struct cmd_set wkssvc_commands[] = {

	{ "WKSSVC" },
	{ "wkstagetinfo", RPC_RTYPE_WERROR, NULL, cmd_wkssvc_wkstagetinfo, PI_WKSSVC, NULL, "Query WKSSVC Workstation Information", "" },
	{ NULL }
};
