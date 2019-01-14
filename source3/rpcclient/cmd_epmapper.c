/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Volker Lendecke 2009

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
#include "../librpc/gen_ndr/ndr_epmapper_c.h"
#include "librpc/ndr/ndr_table.h"

static NTSTATUS cmd_epmapper_map(struct rpc_pipe_client *p,
				 TALLOC_CTX *mem_ctx,
				 int argc, const char **argv)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct dcerpc_binding *map_binding;
	struct epm_twr_t map_tower;
	struct epm_twr_p_t towers[500];
	struct policy_handle entry_handle;
	struct ndr_syntax_id abstract_syntax;
	uint32_t num_towers;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	NTSTATUS status;
	uint32_t result;
	uint32_t i;
	const struct ndr_interface_list *l;
	const char *interface_name = "lsarpc";
	enum dcerpc_transport_t transport = NCACN_NP;
	bool ok = false;
	struct GUID object_uuid = GUID_zero();

	if (argc > 4) {
		d_fprintf(stderr,
			  "Usage: %s [interface_name] [transport] "
			  "[object_uuid]\n",
			  argv[0]);
		return NT_STATUS_OK;
	}

	if (argc >= 2) {
		interface_name = argv[1];
	}

	for (l = ndr_table_list(); l != NULL; l = l->next) {

		ok = strequal(interface_name, l->table->name);
		if (ok) {
			abstract_syntax = l->table->syntax_id;
			break;
		}
	}

	if (!ok) {
		d_fprintf(stderr, "unknown interface: %s\n",
			interface_name);
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (argc >= 3) {
		transport = dcerpc_transport_by_name(argv[2]);
		if (transport == NCA_UNKNOWN) {
			d_fprintf(stderr, "unknown transport: %s\n",
				argv[2]);
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	}

	if (argc >= 4) {
		status = GUID_from_string(argv[3], &object_uuid);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	/* 127.0.0.1[0] => correct? needed? */
	status = dcerpc_parse_binding(tmp_ctx, "ncacn_np:127.0.0.1[0]",
				      &map_binding);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "dcerpc_parse_binding returned %s\n",
			  nt_errstr(status));
		goto done;
	}

	status = dcerpc_binding_set_transport(map_binding, transport);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "dcerpc_binding_set_transport returned %s\n",
			  nt_errstr(status));
		goto done;
	}

	status = dcerpc_binding_set_abstract_syntax(map_binding,
						    &abstract_syntax);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "dcerpc_binding_set_abstract_syntax returned %s\n",
			  nt_errstr(status));
		goto done;
	}

	status = dcerpc_binding_build_tower(tmp_ctx, map_binding,
					    &map_tower.tower);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "dcerpc_binding_build_tower returned %s\n",
			  nt_errstr(status));
		goto done;
	}

	ZERO_STRUCT(towers);
	ZERO_STRUCT(entry_handle);

	status = dcerpc_epm_Map(
		b, tmp_ctx, &object_uuid,
		&map_tower, &entry_handle, ARRAY_SIZE(towers),
		&num_towers, towers, &result);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "dcerpc_epm_Map returned %s\n",
			  nt_errstr(status));
		goto done;
	}

	if (result != EPMAPPER_STATUS_OK) {
		d_fprintf(stderr, "epm_Map returned %u (0x%08X)\n",
			  result, result);
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	d_printf("num_tower[%u]\n", num_towers);

	for (i=0; i < num_towers; i++) {
		struct dcerpc_binding *binding;

		if (towers[i].twr == NULL) {
			d_fprintf(stderr, "tower[%u] NULL\n", i);
			break;
		}

		status = dcerpc_binding_from_tower(tmp_ctx, &towers[i].twr->tower,
						   &binding);
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}

		d_printf("tower[%u] %s\n", i, dcerpc_binding_string(tmp_ctx, binding));
	}
done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

static NTSTATUS cmd_epmapper_lookup(struct rpc_pipe_client *p,
				    TALLOC_CTX *mem_ctx,
				    int argc, const char **argv)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	struct policy_handle entry_handle;

	ZERO_STRUCT(entry_handle);

	while (true) {
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		uint32_t num_entries;
		struct epm_entry_t entry;
		NTSTATUS status;
		char *guid_string;
		struct dcerpc_binding *binding;
		uint32_t result;

		status = dcerpc_epm_Lookup(b, tmp_ctx,
				   0, /* rpc_c_ep_all */
				   NULL,
				   NULL,
				   0, /* rpc_c_vers_all */
				   &entry_handle,
				   1, /* max_ents */
				   &num_entries, &entry,
				   &result);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "dcerpc_epm_Lookup returned %s\n",
				  nt_errstr(status));
			break;
		}

		if (result == EPMAPPER_STATUS_NO_MORE_ENTRIES) {
			d_fprintf(stderr, "epm_Lookup no more entries\n");
			break;
		}

		if (result != EPMAPPER_STATUS_OK) {
			d_fprintf(stderr, "epm_Lookup returned %u (0x%08X)\n",
				  result, result);
			break;
		}

		if (num_entries != 1) {
			d_fprintf(stderr, "epm_Lookup returned %d "
				  "entries, expected one\n", (int)num_entries);
			break;
		}

		guid_string = GUID_string(tmp_ctx, &entry.object);
		if (guid_string == NULL) {
			break;
		}

		status = dcerpc_binding_from_tower(tmp_ctx, &entry.tower->tower,
						   &binding);
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}

		d_printf("%s %s: %s\n", guid_string,
			 dcerpc_binding_string(tmp_ctx, binding),
			 entry.annotation);

		TALLOC_FREE(tmp_ctx);
	}

	return NT_STATUS_OK;
}


/* List of commands exported by this module */

struct cmd_set epmapper_commands[] = {

	{
		.name = "EPMAPPER",
	},

	{
		.name               = "epmmap",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_epmapper_map,
		.wfn                = NULL,
		.table              = &ndr_table_epmapper,
		.rpc_pipe           = NULL,
		.description        = "Map a binding",
		.usage              = "",
	},
	{
		.name               = "epmlookup",
		.returntype         = RPC_RTYPE_NTSTATUS,
		.ntfn               = cmd_epmapper_lookup,
		.wfn                = NULL,
		.table              = &ndr_table_epmapper,
		.rpc_pipe           = NULL,
		.description        = "Lookup bindings",
		.usage              = "",
	},
	{
		.name = NULL,
	},
};
