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
#include "../librpc/gen_ndr/ndr_wkssvc_c.h"

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
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc > 2) {
		printf("usage: %s <level>\n", argv[0]);
		return WERR_OK;
	}

	if (argc > 1) {
		level = atoi(argv[1]);
	}

	server_name = cli->desthost;

	status = dcerpc_wkssvc_NetWkstaGetInfo(b, mem_ctx,
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
	struct dcerpc_binding_handle *b = cli->binding_handle;

	server_name = cli->desthost;
	name_buffer = "";

	status = dcerpc_wkssvc_NetrGetJoinInformation(b, mem_ctx,
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
	const char *server_name = cli->desthost;
	const char *message_name = cli->desthost;
	const char *message_sender_name = cli->desthost;
	smb_ucs2_t *message_buffer = NULL;
	size_t message_size = 0;
	const char *message = "my message";
	NTSTATUS status;
	WERROR werr;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc > 1) {
		message = argv[1];
	}

	if (!push_ucs2_talloc(mem_ctx, &message_buffer, message,
			      &message_size))
	{
		return WERR_NOT_ENOUGH_MEMORY;
	}

	status = dcerpc_wkssvc_NetrMessageBufferSend(b, mem_ctx,
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
	struct dcerpc_binding_handle *b = cli->binding_handle;

	server_name = cli->desthost;

	if (argc >= 2) {
		name_type = atoi(argv[1]);
	}

	status = dcerpc_wkssvc_NetrEnumerateComputerNames(b, mem_ctx,
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

static WERROR cmd_wkssvc_enumerateusers(struct rpc_pipe_client *cli,
					TALLOC_CTX *mem_ctx,
					int argc,
					const char **argv)
{
	const char *server_name;
	NTSTATUS status;
	struct wkssvc_NetWkstaEnumUsersInfo info;
	WERROR werr;
	uint32_t i, num_entries, resume_handle;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	server_name = cli->desthost;

	ZERO_STRUCT(info);

	if (argc >= 2) {
		info.level = atoi(argv[1]);
	}

	status = dcerpc_wkssvc_NetWkstaEnumUsers(b, mem_ctx, server_name,
						 &info, 1000, &num_entries,
						 &resume_handle, &werr);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	for (i=0; i<num_entries; i++) {
		const char *user = NULL;
		switch (info.level) {
		case 0:
			user = info.ctr.user0->user0[i].user_name;
			break;
		case 1:
			user = talloc_asprintf(
				talloc_tos(), "%s\\%s",
				info.ctr.user1->user1[i].logon_domain,
				info.ctr.user1->user1[i].user_name);
			break;
		}
		printf("%s\n", user ? user : "(null)");
	}

	return werr;
}

struct cmd_set wkssvc_commands[] = {

	{
		.name = "WKSSVC",
	},
	{
		.name               = "wkssvc_wkstagetinfo",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_wkssvc_wkstagetinfo,
		.table              = &ndr_table_wkssvc,
		.rpc_pipe           = NULL,
		.description        = "Query WKSSVC Workstation Information",
		.usage              = "",
	},
	{
		.name               = "wkssvc_getjoininformation",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_wkssvc_getjoininformation,
		.table              = &ndr_table_wkssvc,
		.rpc_pipe           = NULL,
		.description        = "Query WKSSVC Join Information",
		.usage              = "",
	},
	{
		.name               = "wkssvc_messagebuffersend",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_wkssvc_messagebuffersend,
		.table              = &ndr_table_wkssvc,
		.rpc_pipe           = NULL,
		.description        = "Send WKSSVC message",
		.usage              = "",
	},
	{
		.name               = "wkssvc_enumeratecomputernames",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_wkssvc_enumeratecomputernames,
		.table              = &ndr_table_wkssvc,
		.rpc_pipe           = NULL,
		.description        = "Enumerate WKSSVC computer names",
		.usage              = "",
	},
	{
		.name               = "wkssvc_enumerateusers",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = cmd_wkssvc_enumerateusers,
		.table              = &ndr_table_wkssvc,
		.rpc_pipe           = NULL,
		.description        = "Enumerate WKSSVC users",
		.usage              = "",
	},
	{
		.name =NULL,
	},
};
