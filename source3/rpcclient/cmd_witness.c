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
			d_printf(" Unsuported Version (0x%08x)", interfaces[n].version);
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
		{"version", 'v', POPT_ARG_LONG|POPT_ARGFLAG_SHOW_DEFAULT, &version, WITNESS_V2, "witness version", "version"},
		{"V1", '1', POPT_ARG_LONG|POPT_ARG_VAL, &version, WITNESS_V1, "witness version 1", NULL},
		{"V2", '2', POPT_ARG_LONG|POPT_ARG_VAL, &version, WITNESS_V2, "witness version 2", NULL},
		{"net", 'n', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT, &net_name, 0, "net name", NULL},
		{"ip",  'i', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT, &ip_addr, 0, "ip address", NULL},
		{"client", 'c', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT|POPT_ARGFLAG_OPTIONAL, &client_name, 0, "client name", NULL},
		{ NULL, 0, 0, NULL, 0 }
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
		{"version", 'v', POPT_ARG_LONG|POPT_ARGFLAG_SHOW_DEFAULT, &version, WITNESS_V2, "witness version", "version"},
		{"V1", '1', POPT_ARG_LONG|POPT_ARG_VAL, &version, WITNESS_V1, "witness version 1", NULL},
		{"V2", '2', POPT_ARG_LONG|POPT_ARG_VAL, &version, WITNESS_V2, "witness version 2", NULL},
		{"net", 'n', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT, &net_name, 0, "net name", NULL},
		{"ip",  'i', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT, &ip_addr, 0, "ip address", NULL},
		{"share", 's', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT, &share_name, 0, "share name", NULL},
		{"client", 'c', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT|POPT_ARGFLAG_OPTIONAL, &client_name, 0, "client name", NULL},
		{"flags", 'f', POPT_ARG_LONG|POPT_ARGFLAG_OR|POPT_ARGFLAG_SHOW_DEFAULT, &flags, 0, "flags", NULL},
		{"timeout", 't', POPT_ARG_LONG|POPT_ARGFLAG_SHOW_DEFAULT, &timeout, 0, "timeout", NULL},
		{ NULL, 0, 0, NULL, 0 }
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
		result = WERR_INVALID_PARAM;
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

enum {
	RESOURCE_STATE_UNKNOWN     = 0x00,
	RESOURCE_STATE_AVAILABLE   = 0x01,
	RESOURCE_STATE_UNAVAILABLE = 0xff
};

static bool AsyncNotify_Change(TALLOC_CTX *mem_ctx, const uint8_t **ptr)
{
	const uint8_t *pos = *ptr;
	uint32_t length = IVAL(pos,0);
	uint32_t type   = IVAL(pos,4);
	char *name = NULL;
	const char *type_str;
	bool ok;
	ok = convert_string_talloc(mem_ctx, CH_UTF16LE, CH_UNIX, pos + 8,
				   length - 8, &name, NULL);
	if (!ok) {
		return false;
	}

	if (type == RESOURCE_STATE_UNKNOWN) {
		type_str = "Unknown";
	} else if(type == RESOURCE_STATE_AVAILABLE) {
		type_str = "Available\n";
	} else if(type == RESOURCE_STATE_UNAVAILABLE) {
		type_str = "Unavailable";
	} else {
		type_str = talloc_asprintf(name, "Invalid (%u)", type);
	}
	d_printf("%s -> %s\n", name, type_str);

	TALLOC_FREE(name);
	*ptr += length;
	return true;
}

enum {
	IPADDR_V4      = 0x01,
	IPADDR_V6      = 0x02,
	IPADDR_ONLINE  = 0x08,
	IPADDR_OFFLINE = 0x10,
};

/* IPADDR_INFO_LIST */
static bool AsyncNotify_Move(TALLOC_CTX *mem_ctx, const uint8_t **ptr)
{
	const uint8_t *pos = *ptr;
	uint32_t length   = IVAL(pos,0);
	/* uint32_t reserved = IVAL(pos,4); */
	uint32_t num      = IVAL(pos,8);
	uint32_t n;

	pos += 12;

	for (n=0; n<num; n++) {
		uint32_t flags = IVAL(pos,0);
		struct in_addr ipv4;
		struct sockaddr_storage sas4;
		char *str4, *str6;
		pos += 4;

		ipv4.s_addr = *((const in_addr_t*)pos);
		in_addr_to_sockaddr_storage(&sas4, ipv4);
		str4 = print_canonical_sockaddr(mem_ctx, &sas4);
		pos += 4;

		{
#ifdef HAVE_IPV6
			struct in6_addr ipv6;
			struct sockaddr_storage sas6;

			memcpy(&ipv6.s6_addr, pos, 16);
			in6_addr_to_sockaddr_storage(&sas6, ipv6);
			str6 = print_canonical_sockaddr(mem_ctx, &sas6);
#else
			DATA_BLOB ipv6 = data_blob(pos, 16);
			str6 = data_blob_hex_string_upper(mem_ctx, &ipv6);
#endif
		}
		pos += 16;

		d_printf("Flags 0x%08x", flags);
		if (flags & IPADDR_V4) {
			d_printf(" %s", str4);
		}
		if (flags & IPADDR_V6) {
			d_printf(" %s", str6);
		}
		if (flags & IPADDR_ONLINE) {
			d_printf(" Online");
		}
		if (flags & IPADDR_ONLINE) {
			d_printf(" Offline");
		}
		d_printf("\n");
		TALLOC_FREE(str4);
		TALLOC_FREE(str6);
	}

	if (pos - *ptr == length) {
		*ptr = pos;
		return true;
	}
	return false;
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
	bool (*read_response)(TALLOC_CTX*, const uint8_t**) = NULL;

	use_only_one_rpc_pipe_hack(cli);

	if (argc != 2) {
		d_printf("%s <context_handle>\n", argv[0]);
		goto done;
	}

	if (!read_context_handle(argv[1], &hnd)) {
		result = WERR_INVALID_PARAM;
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

	switch(response->message_type) {
	case WITNESS_NOTIFY_RESOURCE_CHANGE:
		d_printf("Resource change");
		read_response = AsyncNotify_Change;
		break;
	case WITNESS_NOTIFY_CLIENT_MOVE:
		d_printf("Client move");
		read_response = AsyncNotify_Move;
		break;
	case WITNESS_NOTIFY_SHARE_MOVE:
		d_printf("Share move");
		read_response = AsyncNotify_Move;
		break;
	case WITNESS_NOTIFY_IP_CHANGE:
		d_printf("IP change");
		read_response = AsyncNotify_Move;
		break;
	default:
		d_printf("Unknown (0x%x)", (int)response->message_type);
	}
	d_printf(" with %d messages\n", response->num_messages);

	if (read_response) {
		unsigned n;
		const uint8_t *pos = response->message_buffer;

		for (n=0; n<response->num_messages; n++) {
			read_response(frame, &pos);
		}
	}

done:
	talloc_free(frame);
	return result;
}

struct cmd_set witness_commands[] = {
	{"WITNESS"},
	{"GetInterfaceList", RPC_RTYPE_WERROR, NULL, &cmd_witness_GetInterfaceList, &ndr_table_witness, NULL, "", ""},
	{"Register", RPC_RTYPE_WERROR, NULL, &cmd_witness_Register, &ndr_table_witness, NULL, "", ""},
	{"UnRegister", RPC_RTYPE_WERROR, NULL, &cmd_witness_UnRegister, &ndr_table_witness, NULL, "", ""},
	{"AsyncNotify", RPC_RTYPE_WERROR, NULL, &cmd_witness_AsyncNotify, &ndr_table_witness, NULL, "", ""},
	{"RegisterEx", RPC_RTYPE_WERROR, NULL, &cmd_witness_RegisterEx, &ndr_table_witness, NULL, "", ""},
	{NULL}
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
