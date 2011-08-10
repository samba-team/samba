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
#include "rpc_server/rpc_config.h"

#define EPM_MAX_ANNOTATION_SIZE 64

static bool binding_vector_realloc(struct dcerpc_binding_vector *bvec)
{
	if (bvec->count >= bvec->allocated) {
		struct dcerpc_binding *tmp;

		tmp = talloc_realloc(bvec,
				     bvec->bindings,
				     struct dcerpc_binding,
				     bvec->allocated * 2);
		if (tmp == NULL) {
			return false;
		}
		bvec->bindings = tmp;
		bvec->allocated = bvec->allocated * 2;
	}

	return true;
}

NTSTATUS dcerpc_binding_vector_new(TALLOC_CTX *mem_ctx,
				   struct dcerpc_binding_vector **pbvec)
{
	struct dcerpc_binding_vector *bvec;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	bvec = talloc_zero(tmp_ctx, struct dcerpc_binding_vector);
	if (bvec == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	bvec->bindings = talloc_zero_array(bvec,
					   struct dcerpc_binding,
					   4);
	if (bvec->bindings == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	bvec->allocated = 4;
	bvec->count = 0;

	*pbvec = talloc_move(mem_ctx, &bvec);

	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return status;
}

NTSTATUS dcerpc_binding_vector_add_np_default(const struct ndr_interface_table *iface,
					      struct dcerpc_binding_vector *bvec)
{
	uint32_t ep_count = iface->endpoints->count;
	uint32_t i;
	NTSTATUS status;
	bool ok;

	for (i = 0; i < ep_count; i++) {
		struct dcerpc_binding *b;

		b = talloc_zero(bvec->bindings, struct dcerpc_binding);
		if (b == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = dcerpc_parse_binding(b, iface->endpoints->names[i], &b);
		if (!NT_STATUS_IS_OK(status)) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		/* Only add the named pipes defined in the iface endpoints */
		if (b->transport != NCACN_NP) {
			talloc_free(b);
			continue;
		}

		b->object = iface->syntax_id;

		b->host = talloc_asprintf(b, "\\\\%s", lp_netbios_name());
		if (b->host == NULL) {
			talloc_free(b);
			return NT_STATUS_NO_MEMORY;
		}

		ok = binding_vector_realloc(bvec);
		if (!ok) {
			talloc_free(b);
			return NT_STATUS_NO_MEMORY;
		}

		bvec->bindings[bvec->count] = *b;
		bvec->count++;
	}

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_binding_vector_add_port(const struct ndr_interface_table *iface,
					struct dcerpc_binding_vector *bvec,
					const char *host,
					uint16_t port)
{
	uint32_t ep_count = iface->endpoints->count;
	uint32_t i;
	NTSTATUS status;
	bool ok;

	for (i = 0; i < ep_count; i++) {
		struct dcerpc_binding *b;

		b = talloc_zero(bvec->bindings, struct dcerpc_binding);
		if (b == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = dcerpc_parse_binding(b, iface->endpoints->names[i], &b);
		if (!NT_STATUS_IS_OK(status)) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		if (b->transport != NCACN_IP_TCP) {
			talloc_free(b);
			continue;
		}

		b->object = iface->syntax_id;

		b->host = talloc_strdup(b, host);
		if (b->host == NULL) {
			talloc_free(b);
			return NT_STATUS_NO_MEMORY;
		}

		b->endpoint = talloc_asprintf(b, "%u", port);
		if (b->endpoint == NULL) {
			talloc_free(b);
			return NT_STATUS_NO_MEMORY;
		}

		ok = binding_vector_realloc(bvec);
		if (!ok) {
			talloc_free(b);
			return NT_STATUS_NO_MEMORY;
		}

		bvec->bindings[bvec->count] = *b;
		bvec->count++;

		break;
	}

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_binding_vector_add_unix(const struct ndr_interface_table *iface,
					struct dcerpc_binding_vector *bvec,
					const char *name)
{
	uint32_t ep_count = iface->endpoints->count;
	uint32_t i;
	NTSTATUS status;
	bool ok;

	for (i = 0; i < ep_count; i++) {
		struct dcerpc_binding *b;

		b = talloc_zero(bvec->bindings, struct dcerpc_binding);
		if (b == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = dcerpc_parse_binding(b, iface->endpoints->names[i], &b);
		if (!NT_STATUS_IS_OK(status)) {
			return NT_STATUS_UNSUCCESSFUL;
		}

		if (b->transport != NCALRPC) {
			talloc_free(b);
			continue;
		}

		b->object = iface->syntax_id;

		b->endpoint = talloc_asprintf(b,
					      "%s/%s",
					      lp_ncalrpc_dir(),
					      name);
		if (b->endpoint == NULL) {
			talloc_free(b);
			return NT_STATUS_NO_MEMORY;
		}

		ok = binding_vector_realloc(bvec);
		if (!ok) {
			talloc_free(b);
			return NT_STATUS_NO_MEMORY;
		}

		bvec->bindings[bvec->count] = *b;
		bvec->count++;

		break;
	}

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_binding_vector_replace_iface(const struct ndr_interface_table *iface,
					     struct dcerpc_binding_vector *v)
{
	uint32_t i;

	for (i = 0; i < v->count; i++) {
		struct dcerpc_binding *b;

		b = &(v->bindings[i]);
		b->object = iface->syntax_id;
	}

	return NT_STATUS_OK;
}

struct dcerpc_binding_vector *dcerpc_binding_vector_dup(TALLOC_CTX *mem_ctx,
							const struct dcerpc_binding_vector *bvec)
{
	struct dcerpc_binding_vector *v;
	uint32_t i;

	v = talloc(mem_ctx, struct dcerpc_binding_vector);
	if (v == NULL) {
		return NULL;
	}

	v->bindings = talloc_array(v, struct dcerpc_binding, bvec->allocated);
	if (v->bindings == NULL) {
		talloc_free(v);
		return NULL;
	}
	v->allocated = bvec->allocated;

	for (i = 0; i < bvec->count; i++) {
		struct dcerpc_binding *b;

		b = dcerpc_binding_dup(v->bindings, &bvec->bindings[i]);
		if (b == NULL) {
			talloc_free(v);
			return NULL;
		}
		v->bindings[i] = *b;
	}
	v->count = bvec->count;

	return v;
}

static NTSTATUS ep_register(TALLOC_CTX *mem_ctx,
			    struct messaging_context *msg_ctx,
			    const struct ndr_interface_table *iface,
			    const struct dcerpc_binding_vector *bind_vec,
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
	struct epm_entry_t *entries;
	uint32_t num_ents, i;
	TALLOC_CTX *tmp_ctx;
	uint32_t result = EPMAPPER_STATUS_OK;
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
					       &ndr_table_epmapper.syntax_id,
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

	num_ents = bind_vec->count;
	entries = talloc_array(tmp_ctx, struct epm_entry_t, num_ents);

	for (i = 0; i < num_ents; i++) {
		struct dcerpc_binding *map_binding = &bind_vec->bindings[i];
		struct epm_twr_t *map_tower;

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
			entries[i].object = map_binding->object.uuid;
		}
	}

	if (unregister) {
		status = dcerpc_epm_Delete(h,
					   tmp_ctx,
					   num_ents,
					   entries,
					   &result);
	} else {
		status = dcerpc_epm_Insert(h,
					   tmp_ctx,
					   num_ents,
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
			    const struct ndr_interface_table *iface,
			    const struct dcerpc_binding_vector *bind_vec,
			    const struct GUID *object_guid,
			    const char *annotation,
			    struct dcerpc_binding_handle **ph)
{
	return ep_register(mem_ctx,
			   msg_ctx,
			   iface,
			   bind_vec,
			   object_guid,
			   annotation,
			   1,
			   0,
			   ph);
}

NTSTATUS dcerpc_ep_register_noreplace(TALLOC_CTX *mem_ctx,
				      struct messaging_context *msg_ctx,
				      const struct ndr_interface_table *iface,
				      const struct dcerpc_binding_vector *bind_vec,
				      const struct GUID *object_guid,
				      const char *annotation,
				      struct dcerpc_binding_handle **ph)
{
	return ep_register(mem_ctx,
			   msg_ctx,
			   iface,
			   bind_vec,
			   object_guid,
			   annotation,
			   0,
			   0,
			   ph);
}

NTSTATUS dcerpc_ep_unregister(struct messaging_context *msg_ctx,
			      const struct ndr_interface_table *iface,
			      const struct dcerpc_binding_vector *bind_vec,
			      const struct GUID *object_guid)
{
	return ep_register(NULL,
			   msg_ctx,
			   iface,
			   bind_vec,
			   object_guid,
			   NULL,
			   0,
			   1,
			   NULL);
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
