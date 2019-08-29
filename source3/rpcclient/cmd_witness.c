/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Gregor Beck 2013-2014

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
#include "librpc/gen_ndr/ndr_witness_c.h"
#include <popt.h>

/*
 * We have to use the same connection for each subcommand
 * for the context handles to be meaningful.
 */
static void use_only_one_rpc_pipe_hack(struct rpc_pipe_client *cli);

static WERROR cmd_witness_GetInterfaceList(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx, int argc,
					   const char **argv)
{
	NTSTATUS status;
	WERROR result;
	TALLOC_CTX *frame = talloc_stackframe();
	struct witness_interfaceList *interface_list = NULL;
	uint32_t num_interfaces, n;
	struct witness_interfaceInfo *interfaces;

	use_only_one_rpc_pipe_hack(cli);

	status = dcerpc_witness_GetInterfaceList(cli->binding_handle, frame,
						 &interface_list, &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_witness_GetInterfaceList failed, status: %s\n", nt_errstr(status)));
		result = ntstatus_to_werror(status);
		goto done;
	}
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("dcerpc_witness_GetInterfaceList failed, error: %s\n", win_errstr(result)));
		goto done;
	}

	SMB_ASSERT(interface_list);
	interfaces = interface_list->interfaces;
	num_interfaces = interface_list->num_interfaces;

	for (n=0; n < num_interfaces; n++) {
		char wif = (interfaces[n].flags & WITNESS_INFO_WITNESS_IF) ? '*' : ' ';
		char state = 'X';

		if (interfaces[n].state == WITNESS_STATE_AVAILABLE) {
			state = '+';
		} else if (interfaces[n].state == WITNESS_STATE_UNAVAILABLE) {
			state = '-';
		} else if (interfaces[n].state == WITNESS_STATE_UNKNOWN) {
			state = '?';
		}

		d_printf("%c%c %s", wif, state, interfaces[n].group_name);

		if (interfaces[n].flags & WITNESS_INFO_IPv4_VALID) {
			d_printf(" %s", interfaces[n].ipv4);
		}

		if (interfaces[n].flags & WITNESS_INFO_IPv6_VALID) {
			d_printf(" %s", interfaces[n].ipv6);
		}

		switch (interfaces[n].version) {
		case WITNESS_V1:
			d_printf(" V1");
			break;
		case WITNESS_V2:
			d_printf(" V2");
			break;
		default:
			d_printf(" Unsupported Version (0x%08x)", interfaces[n].version);
		}

		d_printf("\n");
	}

done:
	talloc_free(frame);
	return result;
}

static WERROR cmd_witness_Register(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx, int argc,
				   const char **argv)
{
	static char hostname[MAXHOSTNAMELEN] = {'\0'};
	NTSTATUS status;
	WERROR result = WERR_OK;
	TALLOC_CTX *frame = talloc_stackframe();
	struct policy_handle hnd;
	const char *net_name = NULL;
	const char *ip_addr = NULL;
	const char *client_name = hostname;
	long version = WITNESS_V1;
	int c;
	poptContext optCon;
	struct poptOption optionsTable[] = {
		{
			.longName   = "version",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_LONG|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &version,
			.val        = WITNESS_V2,
			.descrip    = "witness version",
			.argDescrip = "version"
		},
		{
			.longName   = "V1",
			.shortName  = '1',
			.argInfo    = POPT_ARG_LONG|POPT_ARG_VAL,
			.arg        = &version,
			.val        = WITNESS_V1,
			.descrip    = "witness version 1",
			.argDescrip = NULL
		},
		{
			.longName   = "V2",
			.shortName  = '2',
			.argInfo    = POPT_ARG_LONG|POPT_ARG_VAL,
			.arg        = &version,
			.val        = WITNESS_V2,
			.descrip    = "witness version 2",
			.argDescrip = NULL
		},
		{
			.longName   = "net",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &net_name,
			.val        = 0,
			.descrip    = "net name",
			.argDescrip = NULL
		},
		{
			.longName   = "ip",
			.shortName  =  'i',
			.argInfo    = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &ip_addr,
			.val        = 0,
			.descrip    = "ip address",
			.argDescrip = NULL
		},
		{
			.longName   = "client",
			.shortName  = 'c',
			.argInfo    = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT|POPT_ARGFLAG_OPTIONAL,
			.arg        = &client_name,
			.val        = 0,
			.descrip    = "client name",
			.argDescrip = NULL
		},
		POPT_TABLEEND
	};

	use_only_one_rpc_pipe_hack(cli);

	if (hostname[0] == '\0') {
		gethostname (hostname, sizeof(hostname));
	}

	optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);

	while ((c = poptGetNextOpt(optCon)) >= 0) { }

	if (c < -1) {
             /* an error occurred during option processing */
		d_fprintf(stderr, "%s: %s\n",
			  poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			  poptStrerror(c));
             goto done;
	}

	if (argc < 2 || poptPeekArg(optCon) != NULL) {
		poptPrintHelp(optCon, stderr, 0);
		goto done;
	}

	status = dcerpc_witness_Register(cli->binding_handle, frame,
					 &hnd,
					 version,
					 net_name, ip_addr, client_name,
					 &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_witness_Register failed, status: %s\n", nt_errstr(status)));
		result = ntstatus_to_werror(status);
		goto done;
	}
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("dcerpc_witness_Register failed, error: %s\n", win_errstr(result)));
		goto done;
	}

	d_printf("%x:%s\n", hnd.handle_type, GUID_string(frame, &hnd.uuid));

done:
	poptFreeContext(optCon);
	talloc_free(frame);
	return result;
}

static WERROR cmd_witness_RegisterEx(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx, int argc,
				     const char **argv)
{
	static char hostname[MAXHOSTNAMELEN] = {'\0'};
	NTSTATUS status;
	WERROR result = WERR_OK;
	TALLOC_CTX *frame = talloc_stackframe();
	struct policy_handle hnd;
	const char *net_name = NULL;
	const char *ip_addr = NULL;
	const char *share_name = NULL;
	const char *client_name = hostname;
	long version = WITNESS_V2;
	long flags = 0;
	long timeout = 0;
	int c;
	poptContext optCon;
	struct poptOption optionsTable[] = {
		{
			.longName   = "version",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_LONG|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &version,
			.val        = WITNESS_V2,
			.descrip    = "witness version",
			.argDescrip = "version"
		},
		{
			.longName   = "V1",
			.shortName  = '1',
			.argInfo    = POPT_ARG_LONG|POPT_ARG_VAL,
			.arg        = &version,
			.val        = WITNESS_V1,
			.descrip    = "witness version 1",
		},
		{
			.longName   = "V2",
			.shortName  = '2',
			.argInfo    = POPT_ARG_LONG|POPT_ARG_VAL,
			.arg        = &version,
			.val        = WITNESS_V2,
			.descrip    = "witness version 2",
		},
		{
			.longName   = "net",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &net_name,
			.val        = 0,
			.descrip    = "net name",
		},
		{
			.longName   = "ip",
			.shortName  = 'i',
			.argInfo    = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &ip_addr,
			.val        = 0,
			.descrip    = "ip address",
		},
		{
			.longName   = "share",
			.shortName  = 's',
			.argInfo    = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &share_name,
			.val        = 0,
			.descrip    = "share name",
		},
		{
			.longName   = "client",
			.shortName  = 'c',
			.argInfo    = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT|POPT_ARGFLAG_OPTIONAL,
			.arg        = &client_name,
			.val        = 0,
			.descrip    = "client name",
		},
		{
			.longName   = "flags",
			.shortName  = 'f',
			.argInfo    = POPT_ARG_LONG|POPT_ARGFLAG_OR|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &flags,
			.val        = 0,
			.descrip    = "flags",
		},
		{
			.longName   = "timeout",
			.shortName  = 't',
			.argInfo    = POPT_ARG_LONG|POPT_ARGFLAG_SHOW_DEFAULT,
			.arg        = &timeout,
			.val        = 0,
			.descrip    = "timeout",
		},
		POPT_TABLEEND
	};

	use_only_one_rpc_pipe_hack(cli);

	if (hostname[0] == '\0') {
		gethostname (hostname, sizeof(hostname));
	}

	optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);

	while ((c = poptGetNextOpt(optCon)) >= 0) { }

	if (c < -1) {
             /* an error occurred during option processing */
		d_fprintf(stderr, "%s: %s\n",
			  poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			  poptStrerror(c));
             goto done;
	}

	if (argc < 2 || poptPeekArg(optCon) != NULL) {
		poptPrintHelp(optCon, stderr, 0);
		goto done;
	}

	status = dcerpc_witness_RegisterEx(cli->binding_handle, frame,
					   &hnd,
					   version,
					   net_name, share_name, ip_addr, client_name,
					   flags, timeout,
					   &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_witness_RegisterEx failed, status: %s\n", nt_errstr(status)));
		result = ntstatus_to_werror(status);
		goto done;
	}
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("dcerpc_witness_RegisterEx failed, error: %s\n", win_errstr(result)));
		goto done;
	}

	d_printf("%x:%s\n", hnd.handle_type, GUID_string(frame, &hnd.uuid));

done:
	poptFreeContext(optCon);
	talloc_free(frame);
	return result;
}

static bool
read_context_handle(const char *str, struct policy_handle *hnd)
{
	NTSTATUS status;
	long type;
	char *pos;
	struct GUID guid;

	type = strtol(str, &pos, 16);
	if (*pos != ':') {
		DEBUG(0, ("read_context_handle: failed to parse type\n"));
		return false;
	}
	status = GUID_from_string(pos+1, &guid);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("read_context_handle: failed to parse guid %s\n", nt_errstr(status)));
		return false;
	}

	hnd->handle_type = type;
	hnd->uuid = guid;
	return true;
}

static WERROR cmd_witness_UnRegister(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx, int argc,
				     const char **argv)
{
	NTSTATUS status;
	WERROR result = WERR_OK;
	TALLOC_CTX *frame = talloc_stackframe();
	struct policy_handle hnd;

	use_only_one_rpc_pipe_hack(cli);

	if (argc != 2) {
		d_printf("%s <context_handle>\n", argv[0]);
		goto done;
	}

	if (!read_context_handle(argv[1], &hnd)) {
		result = WERR_INVALID_PARAMETER;
		goto done;
	}

	status = dcerpc_witness_UnRegister(cli->binding_handle, frame,
					   hnd, &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_witness_UnRegister failed, status: %s\n", nt_errstr(status)));
		result = ntstatus_to_werror(status);
		goto done;
	}
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("dcerpc_witness_UnRegister failed, error: %s\n", win_errstr(result)));
		goto done;
	}

done:
	talloc_free(frame);
	return result;
}

static void print_notify_response_resource_change(struct witness_ResourceChange *r)
{
	const char *type_str;

	if (r->type == WITNESS_RESOURCE_STATE_UNKNOWN) {
		type_str = "Unknown";
	} else if (r->type == WITNESS_RESOURCE_STATE_AVAILABLE) {
		type_str = "Available\n";
	} else if (r->type == WITNESS_RESOURCE_STATE_UNAVAILABLE) {
		type_str = "Unavailable";
	} else {
		type_str = talloc_asprintf(r, "Invalid (%u)", r->type);
	}
	d_printf("%s -> %s\n", r->name, type_str);
}

static void print_notify_response_ip_addr_info_list(struct witness_IPaddrInfoList *r)
{
	int i;

	for (i=0; i < r->num; i++) {
		uint32_t flags = r->addr[i].flags;
		const char *str4 = r->addr[i].ipv4;
		const char *str6 = r->addr[i].ipv6;

		d_printf("Flags 0x%08x", flags);
		if (flags & WITNESS_IPADDR_V4) {
			d_printf(" %s", str4);
		}
		if (flags & WITNESS_IPADDR_V6) {
			d_printf(" %s", str6);
		}
		if (flags & WITNESS_IPADDR_ONLINE) {
			d_printf(" Online");
		}
		if (flags & WITNESS_IPADDR_ONLINE) {
			d_printf(" Offline");
		}
		d_printf("\n");
	}
}

static void print_notify_response(union witness_notifyResponse_message *r,
				  uint32_t type)
{
	switch (type) {
	case WITNESS_NOTIFY_RESOURCE_CHANGE:
		print_notify_response_resource_change(&r->resource_change);
		break;
	case WITNESS_NOTIFY_CLIENT_MOVE:
	case WITNESS_NOTIFY_SHARE_MOVE:
	case WITNESS_NOTIFY_IP_CHANGE:
		print_notify_response_ip_addr_info_list(&r->client_move);
		break;
	default:
		break;
	}
}

static WERROR cmd_witness_AsyncNotify(struct rpc_pipe_client *cli,
				      TALLOC_CTX *mem_ctx, int argc,
				      const char **argv)
{
	NTSTATUS status;
	WERROR result = WERR_OK;
	TALLOC_CTX *frame = talloc_stackframe();
	struct policy_handle hnd;
	struct witness_notifyResponse *response = NULL;
	uint32_t timeout;
	int i;

	use_only_one_rpc_pipe_hack(cli);

	if (argc != 2) {
		d_printf("%s <context_handle>\n", argv[0]);
		goto done;
	}

	if (!read_context_handle(argv[1], &hnd)) {
		result = WERR_INVALID_PARAMETER;
		goto done;
	}

	timeout = dcerpc_binding_handle_set_timeout(cli->binding_handle, UINT32_MAX);
	status = dcerpc_witness_AsyncNotify(cli->binding_handle, frame, hnd,
					    &response, &result);
	dcerpc_binding_handle_set_timeout(cli->binding_handle, timeout);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_witness_AsyncNotify failed, status: %s\n", nt_errstr(status)));
		result = ntstatus_to_werror(status);
		goto done;
	}
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("dcerpc_witness_AsyncNotify failed, error: %s\n", win_errstr(result)));
		goto done;
	}

	if (response == NULL) {
		d_printf("Got an empty response\n");
		goto done;
	}

	switch(response->type) {
	case WITNESS_NOTIFY_RESOURCE_CHANGE:
		d_printf("Resource change");
		break;
	case WITNESS_NOTIFY_CLIENT_MOVE:
		d_printf("Client move");
		break;
	case WITNESS_NOTIFY_SHARE_MOVE:
		d_printf("Share move");
		break;
	case WITNESS_NOTIFY_IP_CHANGE:
		d_printf("IP change");
		break;
	default:
		d_printf("Unknown (0x%x)", (int)response->type);
	}
	d_printf(" with %d messages\n", response->num);

	for (i=0; i < response->num; i++) {
		print_notify_response(&response->messages[i], response->type);
	}
done:
	talloc_free(frame);
	return result;
}

struct cmd_set witness_commands[] = {
	{
		.name = "WITNESS",
	},
	{
		.name               = "GetInterfaceList",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = &cmd_witness_GetInterfaceList,
		.table              = &ndr_table_witness,
		.rpc_pipe           = NULL,
		.description        = "",
		.usage              = "",
	},
	{
		.name               = "Register",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = &cmd_witness_Register,
		.table              = &ndr_table_witness,
		.rpc_pipe           = NULL,
		.description        = "",
		.usage              = "",
	},
	{
		.name               = "UnRegister",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = &cmd_witness_UnRegister,
		.table              = &ndr_table_witness,
		.rpc_pipe           = NULL,
		.description        = "",
		.usage              = "",
	},
	{
		.name               = "AsyncNotify",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = &cmd_witness_AsyncNotify,
		.table              = &ndr_table_witness,
		.rpc_pipe           = NULL,
		.description        = "",
		.usage              = "",
	},
	{
		.name               = "RegisterEx",
		.returntype         = RPC_RTYPE_WERROR,
		.ntfn               = NULL,
		.wfn                = &cmd_witness_RegisterEx,
		.table              = &ndr_table_witness,
		.rpc_pipe           = NULL,
		.description        = "",
		.usage              = "",
	},
	{
		.name = NULL,
	}
};

/*
 * We have to use the same connection for each subcommand
 * for the context handles to be meaningful.
 */
static void use_only_one_rpc_pipe_hack(struct rpc_pipe_client *cli)
{
	struct cmd_set *ptr;

	for (ptr = &witness_commands[0]; ptr->name; ptr++) {
		ptr->rpc_pipe = cli;
	}
}
