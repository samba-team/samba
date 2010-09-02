/*
 *  Endpoint Mapper Functions
 *  DCERPC local endpoint mapper client routines
 *  Copyright (c) 2010      Andreas Schneider.
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
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_ep.h"
#include "librpc/gen_ndr/cli_epmapper.h"

#define EPM_MAX_ANNOTATION_SIZE 64

static NTSTATUS ep_register(const struct ndr_interface_table *iface,
			    const struct dcerpc_binding_vector *bind_vec,
			    const struct GUID *object_guid,
			    const char *annotation,
			    uint32_t replace)
{
	struct dcerpc_binding_handle *h = NULL;
	static struct client_address client_id;
	struct epm_entry_t *entries;
	uint32_t num_ents, i;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS result = NT_STATUS_OK;
	NTSTATUS status;

	if (iface == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (bind_vec == NULL || bind_vec->count == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

#if 0
	/* NOTE: Samba3 doesn't have a ncalrpc server component yet. As soon as
	 * this is supported, we should talk to the endpoint mapper over the
	 * local transport.
	 */

	/* Connect to the endpoint mapper locally */
	ncalrpc_sock = talloc_asprintf(tmp_ctx,
				      "%s/%s",
				      get_dyn_NCALRPCDIR(),
				      "epmapper");
	if (ncalrpc_sock == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = rpc_pipe_open_ncalrpc(tmp_ctx,
				       ncalrpc_sock,
				       &ndr_table_epmapper.syntax_id,
				       &cli);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
#endif

	strlcpy(client_id.addr, "localhost", sizeof(client_id.addr));
	client_id.name = "localhost";

	status = rpcint_binding_handle(tmp_ctx,
				       &ndr_table_epmapper,
				       &client_id,
				       get_server_info_system(),
				       server_messaging_context(),
				       &h);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_ep_register: Could not connect to epmapper (%s)",
			  nt_errstr(status)));
		goto done;
	}

	num_ents = bind_vec->count;
	entries = talloc_array(tmp_ctx, struct epm_entry_t, num_ents);

	for (i = 0; i < num_ents; i++) {
		struct dcerpc_binding *map_binding = &bind_vec->bindings[i];
		struct epm_twr_t *map_tower;

		map_tower = talloc_zero(entries, struct epm_twr_t);
		if (map_tower == NULL) {
			goto done;
		}

		status = dcerpc_binding_build_tower(entries,
						    map_binding,
						    &map_tower->tower);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		entries[i].tower = map_tower;
		entries[i].annotation = talloc_strndup(entries, annotation,
						       EPM_MAX_ANNOTATION_SIZE);
		if (entries[i].annotation == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		if (object_guid != NULL) {
			entries[i].object = *object_guid;
		} else {
			entries[i].object = map_binding->object.uuid;
		}
	}

	status = dcerpc_epm_Insert(h,
				   tmp_ctx,
				   num_ents,
				   entries,
				   replace,
				   &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_ep_register: Could not insert tower (%s)\n",
			  nt_errstr(status)));
		goto done;
	}
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("dcerpc_ep_register: Could not insert tower (%s)\n",
			  nt_errstr(result)));
		status = result;
		goto done;
	}

done:
	talloc_free(tmp_ctx);

	return status;
}

NTSTATUS dcerpc_ep_register(const struct ndr_interface_table *iface,
			    const struct dcerpc_binding_vector *bind_vec,
			    const struct GUID *object_guid,
			    const char *annotation)
{
	return ep_register(iface, bind_vec, object_guid, annotation, 1);
}

NTSTATUS dcerpc_ep_register_noreplace(const struct ndr_interface_table *iface,
				      const struct dcerpc_binding_vector *bind_vec,
				      const struct GUID *object_guid,
				      const char *annotation)
{
	return ep_register(iface, bind_vec, object_guid, annotation, 0);
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
