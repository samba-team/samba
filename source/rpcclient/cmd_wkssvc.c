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

static WERROR cmd_wkssvc_getjoininformation(struct rpc_pipe_client *cli,
					    TALLOC_CTX *mem_ctx,
					    int argc,
					    const char **argv)
{
	const char *server_name;
	const char *name_buffer;
	enum wkssvc_NetJoinStatus name_type;
	NTSTATUS status;
	WERROR werr;

	server_name = cli->cli->desthost;
	name_buffer = "";

	status = rpccli_wkssvc_NetrGetJoinInformation(cli, mem_ctx,
						      server_name,
						      &name_buffer,
						      &name_type,
						      &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (W_ERROR_IS_OK(werr)) {
		printf("%s (%d)\n", name_buffer, name_type);
	}

	return werr;
}

static WERROR cmd_wkssvc_messagebuffersend(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   int argc,
					   const char **argv)
{
	const char *server_name = cli->cli->desthost;
	const char *message_name = cli->cli->desthost;
	const char *message_sender_name = cli->cli->desthost;
	smb_ucs2_t *message_buffer = NULL;
	size_t message_size = 0;
	const char *message = "my message";
	NTSTATUS status;
	WERROR werr;

	if (argc > 1) {
		message = argv[1];
	}

	message_size = push_ucs2_talloc(mem_ctx,
					&message_buffer,
					message);
	if (message_size == -1) {
		return WERR_NOMEM;
	}

	status = rpccli_wkssvc_NetrMessageBufferSend(cli, mem_ctx,
						     server_name,
						     message_name,
						     message_sender_name,
						     (uint8_t *)message_buffer,
						     message_size,
						     &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	return werr;
}

static WERROR cmd_wkssvc_enumeratecomputernames(struct rpc_pipe_client *cli,
						TALLOC_CTX *mem_ctx,
						int argc,
						const char **argv)
{
	const char *server_name;
	enum wkssvc_ComputerNameType name_type = NetAllComputerNames;
	NTSTATUS status;
	struct wkssvc_ComputerNamesCtr *ctr = NULL;
	WERROR werr;

	server_name = cli->cli->desthost;

	if (argc >= 2) {
		name_type = atoi(argv[1]);
	}

	status = rpccli_wkssvc_NetrEnumerateComputerNames(cli, mem_ctx,
							  server_name,
							  name_type, 0,
							  &ctr,
							  &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	if (W_ERROR_IS_OK(werr)) {
		int i=0;
		for (i = 0; i < ctr->count; i++) {
			printf("name: %d %s\n", i, ctr->computer_name->string);
		}
	}

	return werr;
}

struct cmd_set wkssvc_commands[] = {

	{ "WKSSVC" },
	{ "wkssvc_wkstagetinfo", RPC_RTYPE_WERROR, NULL, cmd_wkssvc_wkstagetinfo, PI_WKSSVC, NULL, "Query WKSSVC Workstation Information", "" },
	{ "wkssvc_getjoininformation", RPC_RTYPE_WERROR, NULL, cmd_wkssvc_getjoininformation, PI_WKSSVC, NULL, "Query WKSSVC Join Information", "" },
	{ "wkssvc_messagebuffersend", RPC_RTYPE_WERROR, NULL, cmd_wkssvc_messagebuffersend, PI_WKSSVC, NULL, "Send WKSSVC message", "" },
	{ "wkssvc_enumeratecomputernames", RPC_RTYPE_WERROR, NULL, cmd_wkssvc_enumeratecomputernames, PI_WKSSVC, NULL, "Enumerate WKSSVC computer names", "" },
	{ NULL }
};
