/*
 *  Endpoint Mapper Functions
 *  DCERPC local endpoint mapper client routines
 *  Copyright (c) 2010-2011 Andreas Schneider.
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
#include "../librpc/gen_ndr/ndr_epmapper_c.h"
#include "rpc_client/cli_pipe.h"
#include "auth.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "../lib/tsocket/tsocket.h"

#include "librpc/rpc/dcesrv_core.h"
#include "rpc_server/rpc_config.h"

#define EPM_MAX_ANNOTATION_SIZE 64

static NTSTATUS ep_register(TALLOC_CTX *mem_ctx,
			    struct messaging_context *msg_ctx,
			    struct dcesrv_context *dce_ctx,
			    const struct dcesrv_interface *iface,
			    const struct GUID *object_guid,
			    const char *annotation,
			    uint32_t replace,
			    uint32_t unregister,
			    struct dcerpc_binding_handle **pbh)
{
	struct rpc_pipe_client *cli = NULL;
	struct dcerpc_binding_handle *h;
	struct pipe_auth_data *auth;
	const char *ncalrpc_sock;
	enum rpc_service_mode_e epmd_mode;
	struct epm_entry_t *entries = NULL;
	uint32_t i = 0;
	TALLOC_CTX *tmp_ctx;
	uint32_t result = EPMAPPER_STATUS_OK;
	NTSTATUS status;
	struct dcesrv_endpoint *ep;
	bool found = false;

	if (iface == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (dce_ctx == NULL || iface == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Check if interface is registered */
	for (ep = dce_ctx->endpoint_list; ep; ep = ep->next) {
		struct dcesrv_if_list *ifl;
		for (ifl = ep->interface_list; ifl; ifl = ifl->next) {
			if (ndr_syntax_id_equal(&ifl->iface->syntax_id,
						&iface->syntax_id)) {
				found = true;
				break;
			}
		}
		if (found) {
			break;
		}
	}
	if (!found) {
		DBG_ERR("Failed to register interface '%s' in the endpoint "
			"mapper as it is not registered in any endpoint\n",
			iface->name);
		return NT_STATUS_INVALID_PARAMETER;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	epmd_mode = rpc_epmapper_mode();

	if (epmd_mode == RPC_SERVICE_MODE_EMBEDDED) {
		struct tsocket_address *local;
		int rc;

		rc = tsocket_address_inet_from_strings(tmp_ctx,
						       "ip",
						       "127.0.0.1",
						       0,
						       &local);
		if (rc < 0) {
			return NT_STATUS_NO_MEMORY;
		}

		status = rpcint_binding_handle(tmp_ctx,
					       &ndr_table_epmapper,
					       local,
					       NULL,
					       get_session_info_system(),
					       msg_ctx,
					       &h);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("dcerpc_ep_register: Could not connect to "
				  "epmapper (%s)", nt_errstr(status)));
			goto done;
		}
	} else if (epmd_mode == RPC_SERVICE_MODE_EXTERNAL) {
		/* Connect to the endpoint mapper locally */
		ncalrpc_sock = talloc_asprintf(tmp_ctx,
					      "%s/%s",
					      lp_ncalrpc_dir(),
					      "EPMAPPER");
		if (ncalrpc_sock == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		status = rpc_pipe_open_ncalrpc(tmp_ctx,
					       ncalrpc_sock,
					       &ndr_table_epmapper,
					       &cli);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		status = rpccli_ncalrpc_bind_data(cli, &auth);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to initialize anonymous bind.\n"));
			goto done;
		}

		status = rpc_pipe_bind(cli, auth);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("Failed to bind ncalrpc socket.\n"));
			goto done;
		}

		h = cli->binding_handle;
	} else {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	for (i = 0, ep = dce_ctx->endpoint_list; ep; i++, ep = ep->next) {
		struct dcerpc_binding *map_binding;
		struct epm_twr_t *map_tower;
		struct dcesrv_if_list *ifl;

		for (ifl = ep->interface_list; ifl; ifl = ifl->next) {
			if (!ndr_syntax_id_equal(&ifl->iface->syntax_id,
						 &iface->syntax_id)) {
				continue;
			}
		}

		/* The interface is registered in this endpoint, add it */
		entries = talloc_realloc(tmp_ctx, entries, struct epm_entry_t,
					 i + 1);
		if (entries == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		map_binding = dcerpc_binding_dup(entries, ep->ep_description);
		if (map_binding == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		status = dcerpc_binding_set_abstract_syntax(map_binding,
							    &iface->syntax_id);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		map_tower = talloc_zero(entries, struct epm_twr_t);
		if (map_tower == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		status = dcerpc_binding_build_tower(entries,
						    map_binding,
						    &map_tower->tower);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		TALLOC_FREE(map_binding);

		entries[i].tower = map_tower;
		if (annotation == NULL) {
			entries[i].annotation = talloc_strdup(entries, "");
		} else {
			entries[i].annotation = talloc_strndup(entries,
							       annotation,
							       EPM_MAX_ANNOTATION_SIZE);
		}
		if (entries[i].annotation == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		if (object_guid != NULL) {
			entries[i].object = *object_guid;
		} else {
			ZERO_STRUCT(entries[i].object);
		}
	}

	if (unregister) {
		status = dcerpc_epm_Delete(h,
					   tmp_ctx,
					   i,
					   entries,
					   &result);
	} else {
		status = dcerpc_epm_Insert(h,
					   tmp_ctx,
					   i,
					   entries,
					   replace,
					   &result);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_ep_register: Could not insert tower (%s)\n",
			  nt_errstr(status)));
		goto done;
	}
	if (result != EPMAPPER_STATUS_OK) {
		DEBUG(0, ("dcerpc_ep_register: Could not insert tower (0x%.8x)\n",
			  result));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (pbh != NULL) {
		*pbh = talloc_move(mem_ctx, &h);
		talloc_steal(*pbh, cli);
	}

done:
	talloc_free(tmp_ctx);

	return status;
}

NTSTATUS dcerpc_ep_register(TALLOC_CTX *mem_ctx,
			    struct messaging_context *msg_ctx,
			    struct dcesrv_context *dce_ctx,
			    const struct dcesrv_interface *iface,
			    const struct GUID *object_guid,
			    const char *annotation,
			    struct dcerpc_binding_handle **ph)
{
	return ep_register(mem_ctx,
			   msg_ctx,
			   dce_ctx,
			   iface,
			   object_guid,
			   annotation,
			   1,
			   0,
			   ph);
}

NTSTATUS dcerpc_ep_register_noreplace(TALLOC_CTX *mem_ctx,
				      struct messaging_context *msg_ctx,
				      struct dcesrv_context *dce_ctx,
				      const struct dcesrv_interface *iface,
				      const struct GUID *object_guid,
				      const char *annotation,
				      struct dcerpc_binding_handle **ph)
{
	return ep_register(mem_ctx,
			   msg_ctx,
			   dce_ctx,
			   iface,
			   object_guid,
			   annotation,
			   0,
			   0,
			   ph);
}

NTSTATUS dcerpc_ep_unregister(struct messaging_context *msg_ctx,
			      struct dcesrv_context *dce_ctx,
			      const struct dcesrv_interface *iface,
			      const struct GUID *object_guid)
{
	return ep_register(NULL,
			   msg_ctx,
			   dce_ctx,
			   iface,
			   object_guid,
			   NULL,
			   0,
			   1,
			   NULL);
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
