/*
   Unix SMB/CIFS implementation.

   Endpoint server for the epmapper pipe

   Copyright (C) 2010-2011 Andreas Schneider <asn@samba.org>

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
#include "ntdomain.h"
#include "../libcli/security/security.h"
#include "../lib/tsocket/tsocket.h"
#include "auth.h"

#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_epmapper_scompat.h"
#include "rpc_server/rpc_server.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/util_tdb.h"
#include "lib/util/strv.h"

static struct tdb_wrap *epmdb = NULL;

/* handle types for this module */
enum handle_types {HTYPE_LOOKUP};

typedef uint32_t error_status_t;

/* An endpoint combined with an interface description */
struct dcesrv_ep_iface {
	const char *name;
	struct ndr_syntax_id syntax_id;
	struct epm_tower ep;
};

/* A rpc service interface like samr, lsarpc or netlogon */
struct dcesrv_iface {
	const char *name;
	struct ndr_syntax_id syntax_id;
};

struct dcesrv_iface_list {
	struct dcesrv_iface_list *next, *prev;
	struct dcesrv_iface *iface;
};

/*
 * An endpoint can serve multiple rpc services interfaces.
 * For example \\pipe\netlogon can be used by lsarpc and netlogon.
 */
struct dcesrv_epm_endpoint {
	struct dcesrv_epm_endpoint *next, *prev;

	/* The type and the location of the endpoint */
	struct dcerpc_binding *ep_description;

	/* A list of rpc services able to connect to the endpoint */
	struct dcesrv_iface_list *iface_list;
};

struct rpc_eps {
	struct dcesrv_ep_iface *e;
	uint32_t count;
};

struct build_ep_list_state {
	const struct GUID *uuid;
	const char *srv_addr;
	TALLOC_CTX *mem_ctx;
	struct dcesrv_ep_iface *ifaces;
};

static bool build_ep_list_fill_iface(
	TALLOC_CTX *mem_ctx,
	const struct ndr_syntax_id *syntax_id,
	const char *endpoint,
	const char *name,
	const char *srv_addr,
	struct dcesrv_ep_iface *dst)
{
	struct dcesrv_ep_iface iface = {
		.syntax_id = *syntax_id,
	};
	struct dcerpc_binding *binding = NULL;
	enum dcerpc_transport_t transport;
	char *name_dup = NULL;
	const char *host_addr = NULL;
	NTSTATUS status;

	/* copy without const for error path TALLOC_FREE */
	name_dup = talloc_strdup(mem_ctx, name);
	if (name_dup == NULL) {
		goto fail;
	}
	iface.name = name_dup;

	status = dcerpc_parse_binding(mem_ctx, endpoint, &binding);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_parse_binding failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	status = dcerpc_binding_set_abstract_syntax(binding, syntax_id);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_binding_set_abstract_syntax failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	transport = dcerpc_binding_get_transport(binding);
	if (transport == NCACN_IP_TCP) {
		const char *host = NULL;

		host = dcerpc_binding_get_string_option(binding, "host");
		if (host == NULL) {
			host_addr = srv_addr;
		} else if (!is_ipaddress_v4(host)) {
			host_addr = srv_addr;
		} else if (strcmp(host, "0.0.0.0") == 0) {
			host_addr = srv_addr;
		}
	}

	if (host_addr != NULL) {
		status = dcerpc_binding_set_string_option(
			binding, "host", host_addr);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dcerpc_binding_set_string_option "
				  "failed: %s\n",
				  nt_errstr(status));
			goto fail;
		}
	}

	status = dcerpc_binding_build_tower(mem_ctx, binding, &iface.ep);
	TALLOC_FREE(binding);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_binding_build_tower failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	*dst = iface;
	return true;

fail:
	TALLOC_FREE(binding);
	TALLOC_FREE(name_dup);
	TALLOC_FREE(iface.ep.floors);
	return false;
}

static int build_ep_list_fn(
	struct tdb_context *tdb,
	TDB_DATA key,
	TDB_DATA value,
	void *private_data)
{
	struct build_ep_list_state *state = private_data;
	struct ndr_syntax_id syntax_id = { .if_version = 0 };
	const char *name = NULL;
	char *endpoints = NULL;
	const char *endpoint = NULL;
	bool ok;

	if ((key.dsize == 0) || (key.dptr[key.dsize-1] != '\0') ||
	    (value.dsize == 0) || (value.dptr[value.dsize-1] != '\0')) {
		DBG_DEBUG("Invalid record\n");
		return 0;
	}

	ok = ndr_syntax_id_from_string((char *)key.dptr, &syntax_id);
	if (!ok) {
		DBG_DEBUG("Invalid interface: %s\n", (char *)key.dptr);
		return 0;
	}

	endpoints = (char *)value.dptr;
	endpoint = endpoints;
	name = endpoints;

	while ((endpoint = strv_len_next(endpoints, value.dsize, endpoint))) {
		size_t num_ifaces = talloc_array_length(state->ifaces);
		struct dcesrv_ep_iface *tmp = NULL;

		if (num_ifaces+1 < num_ifaces) {
			return 1;
		}

		tmp = talloc_realloc(
			state->mem_ctx,
			state->ifaces,
			struct dcesrv_ep_iface,
			num_ifaces+1);
		if (tmp == NULL) {
			return 1;
		}
		state->ifaces = tmp;

		ok = build_ep_list_fill_iface(
			state->ifaces,
			&syntax_id,
			endpoint,
			name,
			state->srv_addr,
			&state->ifaces[num_ifaces]);
		if (!ok) {
			state->ifaces = talloc_realloc(
				state->mem_ctx,
				state->ifaces,
				struct dcesrv_ep_iface,
				num_ifaces);
		}
	}

	return 0;
}

/*
 * Build a list of all interfaces handled by all endpoint servers.
 */
static uint32_t build_ep_list(TALLOC_CTX *mem_ctx,
			      const struct GUID *uuid,
			      const char *srv_addr,
			      struct dcesrv_ep_iface **peps)
{
	struct build_ep_list_state state = {
		.mem_ctx = mem_ctx, .uuid = uuid, .srv_addr = srv_addr,
	};
	int ret;

	ret = tdb_traverse_read(epmdb->tdb, build_ep_list_fn, &state);
	if (ret == -1) {
		DBG_DEBUG("tdb_traverse_read failed\n");
		return 0;
	}

	*peps = state.ifaces;
	return talloc_array_length(*peps);
}

/*
 * epm_Insert
 *
 * Add the specified entries to an endpoint map.
 */
error_status_t _epm_Insert(struct pipes_struct *p,
			   struct epm_Insert *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}

/*
 * epm_Delete
 *
 * Delete the specified entries from an endpoint map.
 */
error_status_t _epm_Delete(struct pipes_struct *p,
			   struct epm_Delete *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}

/*
 * epm_Lookup
 *
 * Lookup entries in an endpoint map.
 */
error_status_t _epm_Lookup(struct pipes_struct *p,
			   struct epm_Lookup *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct dcesrv_connection *dcesrv_conn = dce_call->conn;
	struct policy_handle *entry_handle;
	struct rpc_eps *eps;
	TALLOC_CTX *tmp_ctx;
	error_status_t rc;
	uint32_t count = 0;
	uint32_t num_ents = 0;
	uint32_t i;
	bool match = false;
	bool ok;
	NTSTATUS status;

	*r->out.num_ents = 0;
	r->out.entries = NULL;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return EPMAPPER_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("_epm_Lookup: Trying to lookup max. %u entries.\n",
		  r->in.max_ents));

	if (r->in.entry_handle == NULL ||
	    ndr_policy_handle_empty(r->in.entry_handle)) {
		const struct tsocket_address *local_address =
			dcesrv_connection_get_local_address(dcesrv_conn);
		char *srv_addr = NULL;

		DEBUG(7, ("_epm_Lookup: No entry_handle found, creating it.\n"));

		eps = talloc_zero(tmp_ctx, struct rpc_eps);
		if (eps == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		if (local_address != NULL &&
		    tsocket_address_is_inet(local_address, "ipv4"))
		{
			srv_addr = tsocket_address_inet_addr_string(
				local_address, tmp_ctx);
		}

		switch (r->in.inquiry_type) {
		case RPC_C_EP_ALL_ELTS:
			/*
			 * Return all elements from the endpoint map. The
			 * interface_id, vers_option, and object parameters MUST
			 * be ignored.
			 */
			eps->count = build_ep_list(eps,
						   NULL,
						   srv_addr,
						   &eps->e);
			break;
		case RPC_C_EP_MATCH_BY_IF:
			/*
			 * Return endpoint map elements that contain the
			 * interface identifier specified by the interface_id
			 * and vers_option values.
			 *
			 * RPC_C_EP_MATCH_BY_IF and RPC_C_EP_MATCH_BY_BOTH
			 * need both the same endpoint list. There is a second
			 * check for the inquiry_type below which differentiates
			 * between them.
			 */
		case RPC_C_EP_MATCH_BY_BOTH:
			/*
			 * Return endpoint map elements that contain the
			 * interface identifier and object UUID specified by
			 * interface_id, vers_option, and object.
			 */
			eps->count = build_ep_list(eps,
						   &r->in.interface_id->uuid,
						   srv_addr,
						   &eps->e);
			break;
		case RPC_C_EP_MATCH_BY_OBJ:
			/*
			 * Return endpoint map elements that contain the object
			 * UUID specified by object.
			 */
			eps->count = build_ep_list(eps,
						   r->in.object,
						   srv_addr,
						   &eps->e);
			break;
		default:
			rc = EPMAPPER_STATUS_CANT_PERFORM_OP;
			goto done;
		}

		if (eps->count == 0) {
			rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
			goto done;
		}

		ok = create_policy_hnd(p, r->out.entry_handle, HTYPE_LOOKUP, eps);
		if (!ok) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		eps = find_policy_by_hnd(p,
					 r->out.entry_handle,
					 HTYPE_LOOKUP,
					 struct rpc_eps,
					 &status);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		entry_handle = r->out.entry_handle;
	} else {
		DEBUG(7, ("_epm_Lookup: Trying to find entry_handle.\n"));

		eps = find_policy_by_hnd(p,
					 r->in.entry_handle,
					 HTYPE_LOOKUP,
					 struct rpc_eps,
					 &status);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		entry_handle = r->in.entry_handle;
	}

	if (eps == NULL || eps->e == NULL) {
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	/* return the next N elements */
	count = r->in.max_ents;
	if (count > eps->count) {
		count = eps->count;
	}

	DEBUG(5, ("_epm_Lookup: Find %u entries\n", count));

	if (count == 0) {
		close_policy_hnd(p, entry_handle);
		ZERO_STRUCTP(r->out.entry_handle);

		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	r->out.entries = talloc_array(p->mem_ctx, struct epm_entry_t, count);
	if (r->out.entries == NULL) {
		rc = EPMAPPER_STATUS_NO_MEMORY;
		goto done;
	}

	for (i = 0; i < count; i++) {
		match = false;

		switch (r->in.inquiry_type) {
		case RPC_C_EP_ALL_ELTS:
			/*
			 * Return all elements from the endpoint map. The
			 * interface_id, vers_option, and object parameters MUST
			 * be ignored.
			 */
			match = true;
			break;
		case RPC_C_EP_MATCH_BY_IF:
			/*
			 * Return endpoint map elements that contain the
			 * interface identifier specified by the interface_id
			 * and vers_option values.
			 */
			if (GUID_equal(&r->in.interface_id->uuid,
				       &eps->e[i].syntax_id.uuid)) {
				match = true;
			}
			break;
		case RPC_C_EP_MATCH_BY_OBJ:
			/*
			 * Return endpoint map elements that contain the object
			 * UUID specified by object.
			 */
			if (GUID_equal(r->in.object,
				       &eps->e[i].syntax_id.uuid)) {
				match = true;
			}
			break;
		case RPC_C_EP_MATCH_BY_BOTH:
			/*
			 * Return endpoint map elements that contain the
			 * interface identifier and object UUID specified by
			 * interface_id, vers_option, and object.
			 */
			if (GUID_equal(&r->in.interface_id->uuid,
				       &eps->e[i].syntax_id.uuid) &&
			    GUID_equal(r->in.object, &eps->e[i].syntax_id.uuid)) {
				match = true;
			}
			break;
		default:
			return EPMAPPER_STATUS_CANT_PERFORM_OP;
		}

		if (match) {
			if (r->in.inquiry_type == RPC_C_EP_MATCH_BY_IF ||
			    r->in.inquiry_type == RPC_C_EP_MATCH_BY_OBJ) {
				/* Check interface version */

				match = false;
				switch (r->in.vers_option) {
				case RPC_C_VERS_ALL:
					/*
					 * Return endpoint map elements that
					 * contain the specified interface UUID,
					 * regardless of the version numbers.
					 */
					match = true;
					break;
				case RPC_C_VERS_COMPATIBLE:
					/*
					 * Return the endpoint map elements that
					 * contain the same major versions of
					 * the specified interface UUID and a
					 * minor version greater than or equal
					 * to the minor version of the specified
					 * UUID.
					 */
					if (r->in.interface_id->vers_major ==
					    (eps->e[i].syntax_id.if_version >> 16) &&
					    r->in.interface_id->vers_minor <=
					    (eps->e[i].syntax_id.if_version & 0xFFFF)) {
						match = true;
					}
					break;
				case RPC_C_VERS_EXACT:
					/*
					 * Return endpoint map elements that
					 * contain the specified version of the
					 * specified interface UUID.
					 */
					if (r->in.interface_id->vers_major ==
					    (eps->e[i].syntax_id.if_version >> 16) &&
					    r->in.interface_id->vers_minor ==
					    (eps->e[i].syntax_id.if_version & 0xFFFF)) {
						match = true;
					}
					match = true;
					break;
				case RPC_C_VERS_MAJOR_ONLY:
					/*
					 * Return endpoint map elements that
					 * contain the same version of the
					 * specified interface UUID and ignore
					 * the minor version.
					 */
					if (r->in.interface_id->vers_major ==
					    (eps->e[i].syntax_id.if_version >> 16)) {
						match = true;
					}
					match = true;
					break;
				case RPC_C_VERS_UPTO:
					/*
					 * Return endpoint map elements that
					 * contain a version of the specified
					 * interface UUID less than or equal to
					 * the specified major and minor
					 * version.
					 */
					if (r->in.interface_id->vers_major >
					    eps->e[i].syntax_id.if_version >> 16) {
						match = true;
					} else {
						if (r->in.interface_id->vers_major ==
						    (eps->e[i].syntax_id.if_version >> 16) &&
						    r->in.interface_id->vers_minor >=
						    (eps->e[i].syntax_id.if_version & 0xFFFF)) {
							match = true;
						}
					}
					break;
				default:
					return EPMAPPER_STATUS_CANT_PERFORM_OP;
				}
			}
		}

		if (match) {
			ZERO_STRUCT(r->out.entries[num_ents].object);

			DEBUG(10, ("_epm_Lookup: Adding tower for '%s'\n",
				   eps->e[i].name));
			r->out.entries[num_ents].annotation = talloc_strdup(r->out.entries,
									    eps->e[i].name);
			r->out.entries[num_ents].tower = talloc(r->out.entries,
								struct epm_twr_t);
			if (r->out.entries[num_ents].tower == NULL) {
				rc = EPMAPPER_STATUS_NO_MEMORY;
				goto done;
			}
			r->out.entries[num_ents].tower->tower.floors = talloc_move(r->out.entries[num_ents].tower, &eps->e[i].ep.floors);
			r->out.entries[num_ents].tower->tower.num_floors = eps->e[i].ep.num_floors;
			r->out.entries[num_ents].tower->tower_length = 0;

			num_ents++;
		}
	} /* end for loop */

	*r->out.num_ents = num_ents;

	eps->count -= count;
	eps->e += count;
	if (eps->count == 0) {
		close_policy_hnd(p, entry_handle);
		ZERO_STRUCTP(r->out.entry_handle);
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	rc = EPMAPPER_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return rc;
}

static struct rpc_eps *epm_map_get_towers(
	TALLOC_CTX *mem_ctx,
	const struct ndr_syntax_id *iface,
	enum dcerpc_transport_t transport,
	const char *local_address)
{
	struct ndr_syntax_id_buf idbuf;
	char *iface_string = ndr_syntax_id_buf_string(iface, &idbuf);
	struct rpc_eps *eps = NULL;
	uint8_t *buf = NULL;
	size_t buflen;
	char *bindings = NULL;
	char *binding = NULL;
	char *name = NULL;
	NTSTATUS status;
	int ret;

	DBG_DEBUG("Mapping interface %s\n", iface_string);

	eps = talloc_zero(mem_ctx, struct rpc_eps);
	if (eps == NULL) {
		goto fail;
	}

	ret = tdb_fetch_talloc(
		epmdb->tdb, string_term_tdb_data(iface_string), eps, &buf);
	if (ret != 0) {
		DBG_DEBUG("Could not find epm entry for %s: %s\n",
			  iface_string,
			  strerror(ret));
		goto fail;
	}
	buflen = talloc_array_length(buf);

	if ((buflen < 1) || (buf[buflen-1] != '\0')) {
		DBG_DEBUG("epm entry for %s invalid\n", iface_string);
		goto fail;
	}
	bindings = (char *)buf;

	name = bindings;	/* name comes first */
	binding = name;		/* strv_next will skip name */

	while ((binding = strv_next(bindings, binding)) != NULL) {
		struct dcerpc_binding *b = NULL;
		enum dcerpc_transport_t found_transport;
		struct dcesrv_ep_iface *tmp = NULL, *new_ep = NULL;

		DBG_DEBUG("Found %s for %s\n", binding, name);

		status = dcerpc_parse_binding(mem_ctx, binding, &b);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dcerpc_parse_binding() for %s failed: %s\n",
				  binding,
				  nt_errstr(status));
			goto fail;
		}

		found_transport = dcerpc_binding_get_transport(b);
		if (found_transport != transport) {
			DBG_DEBUG("Transport %d does not match %d\n",
				  (int)found_transport,
				  (int)transport);
			TALLOC_FREE(b);
			continue;
		}

		if (found_transport == NCACN_IP_TCP) {
			status = dcerpc_binding_set_string_option(
				b, "host", local_address);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("Could not set host: %s\n",
					  nt_errstr(status));
				goto fail;
			}
		}

		status = dcerpc_binding_set_abstract_syntax(b, iface);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Could not set abstract syntax: %s\n",
				  nt_errstr(status));
			goto fail;
		}

		tmp = talloc_realloc(
			eps,
			eps->e,
			struct dcesrv_ep_iface,
			eps->count+1);
		if (tmp == NULL) {
			goto fail;
		}
		eps->e = tmp;

		new_ep = &eps->e[eps->count];

		new_ep->name = talloc_strdup(eps->e, name);
		if (new_ep->name == NULL) {
			goto fail;
		}
		new_ep->syntax_id = *iface;

		status = dcerpc_binding_build_tower(eps->e, b, &new_ep->ep);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dcerpc_binding_build_tower failed: %s\n",
				  nt_errstr(status));
			goto fail;
		}

		eps->count += 1;

		TALLOC_FREE(b);
	}
	return eps;

fail:
	TALLOC_FREE(eps);
	return NULL;
}

/*
 * epm_Map
 *
 * Apply some algorithm (using the fields in the map_tower) to an endpoint map
 * to produce a list of protocol towers.
 */
error_status_t _epm_Map(struct pipes_struct *p,
			struct epm_Map *r)
{
	struct dcesrv_call_state *dce_call = p->dce_call;
	struct dcesrv_connection *dcesrv_conn = dce_call->conn;
	struct policy_handle *entry_handle;
	enum dcerpc_transport_t transport;
	struct ndr_syntax_id ifid;
	struct epm_floor *floors;
	struct rpc_eps *eps;
	TALLOC_CTX *tmp_ctx;
	error_status_t rc;
	uint32_t count = 0;
	uint32_t num_towers = 0;
	uint32_t i;
	bool ok;
	NTSTATUS status;

	*r->out.num_towers = 0;
	r->out.towers = NULL;

	if (r->in.map_tower == NULL || r->in.max_towers == 0 ||
	    r->in.map_tower->tower.num_floors < 3) {
		return EPMAPPER_STATUS_NO_MORE_ENTRIES;
	}

	tmp_ctx = talloc_stackframe();

	ZERO_STRUCTP(r->out.entry_handle);

	DEBUG(5, ("_epm_Map: Trying to map max. %u towers.\n",
		  r->in.max_towers));

	/*
	 * A tower has normally up to 6 floors
	 *
	 * +-----------------------------------------------------------------+
	 * | Floor 1 | Provides the RPC interface identifier. (e.g. UUID for |
	 * |         | netlogon)                                             |
	 * +---------+-------------------------------------------------------+
	 * | Floor 2 | Transfer syntax (NDR encoded)                        |
	 * +---------+-------------------------------------------------------+
	 * | Floor 3 | RPC protocol identifier (ncacn_tcp_ip, ncacn_np, ...) |
	 * +---------+-------------------------------------------------------+
	 * | Floor 4 | Port address (e.g. TCP Port: 49156)                   |
	 * +---------+-------------------------------------------------------+
	 * | Floor 5 | Transport (e.g. IP:192.168.51.10)                     |
	 * +---------+-------------------------------------------------------+
	 * | Floor 6 | Routing                                               |
	 * +---------+-------------------------------------------------------+
	 */
	floors = r->in.map_tower->tower.floors;

	/* We accept NDR as the transfer syntax */
	status = dcerpc_floor_get_lhs_data(&floors[1], &ifid);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_floor_get_lhs_data() failed: %s\n",
			  nt_errstr(status));
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	if (floors[1].lhs.protocol != EPM_PROTOCOL_UUID ||
	    !ndr_syntax_id_equal(&ifid, &ndr_transfer_syntax_ndr)) {
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	/* We only talk to sane transports */
	transport = dcerpc_transport_by_tower(&r->in.map_tower->tower);
	if (transport == NCA_UNKNOWN) {
		DEBUG(2, ("epm_Map: Client requested unknown transport with "
			  "levels: "));
		for (i = 2; i < r->in.map_tower->tower.num_floors; i++) {
			DEBUG(2, ("%d, ", r->in.map_tower->tower.floors[i].lhs.protocol));
		}
		DEBUG(2, ("\n"));
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	if (r->in.entry_handle == NULL ||
	    ndr_policy_handle_empty(r->in.entry_handle)) {
		const struct tsocket_address *local_addr =
			dcesrv_connection_get_local_address(dcesrv_conn);
		char *local_address = NULL;
		struct ndr_syntax_id_buf buf;
		char *if_string = NULL;

		DEBUG(7, ("_epm_Map: No entry_handle found, creating it.\n"));

		status = dcerpc_floor_get_lhs_data(&floors[0], &ifid);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dcerpc_floor_get_lhs_data() failed: %s\n",
				  nt_errstr(status));
			rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
			goto done;
		}

		if_string = ndr_syntax_id_buf_string(&ifid, &buf);

		DBG_INFO("Mapping interface %s\n", if_string);

		if ((transport == NCACN_IP_TCP) &&
		    tsocket_address_is_inet(local_addr, "ip")) {
			/*
			 * We don't have the host ip in the epm
			 * database. For NCACN_IP_TCP, add the IP that
			 * the client connected to.
			 */
			local_address = tsocket_address_inet_addr_string(
				local_addr, tmp_ctx);
		}

		eps = epm_map_get_towers(
			tmp_ctx, &ifid, transport, local_address);
		if (eps == NULL) {
			DBG_DEBUG("No bindings found\n");
			rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
			goto done;
		}

		ok = create_policy_hnd(p, r->out.entry_handle, HTYPE_LOOKUP, eps);
		if (!ok) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		eps = find_policy_by_hnd(p,
					 r->out.entry_handle,
					 HTYPE_LOOKUP,
					 struct rpc_eps,
					 &status);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		entry_handle = r->out.entry_handle;
	} else {
		DEBUG(7, ("_epm_Map: Trying to find entry_handle.\n"));

		eps = find_policy_by_hnd(p,
					 r->in.entry_handle,
					 HTYPE_LOOKUP,
					 struct rpc_eps,
					 &status);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		entry_handle = r->in.entry_handle;
	}

	if (eps == NULL || eps->e == NULL) {
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	/* return the next N elements */
	count = r->in.max_towers;
	if (count > eps->count) {
		count = eps->count;
	}

	if (count == 0) {
		close_policy_hnd(p, entry_handle);
		ZERO_STRUCTP(r->out.entry_handle);

		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	r->out.towers = talloc_array(p->mem_ctx, struct epm_twr_p_t, count);
	if (r->out.towers == NULL) {
		rc = EPMAPPER_STATUS_NO_MEMORY;
		goto done;
	}

	for (i = 0; i < count; i++) {
		DEBUG(7, ("_epm_Map: Map tower for '%s'\n",
			   eps->e[i].name));

		r->out.towers[num_towers].twr = talloc(r->out.towers,
						       struct epm_twr_t);
		if (r->out.towers[num_towers].twr == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		r->out.towers[num_towers].twr->tower.floors = talloc_move(r->out.towers[num_towers].twr, &eps->e[i].ep.floors);
		r->out.towers[num_towers].twr->tower.num_floors = eps->e[i].ep.num_floors;
		r->out.towers[num_towers].twr->tower_length = 0;

		num_towers++;
	}

	*r->out.num_towers = num_towers;

	eps->count -= count;
	eps->e += count;
	if (eps->count == 0) {
		close_policy_hnd(p, entry_handle);
		ZERO_STRUCTP(r->out.entry_handle);
	}

	rc = EPMAPPER_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return rc;
}

/*
 * epm_LookupHandleFree
 */
error_status_t _epm_LookupHandleFree(struct pipes_struct *p,
				     struct epm_LookupHandleFree *r)
{
	if (r->in.entry_handle == NULL) {
		return EPMAPPER_STATUS_OK;
	}

	if (is_valid_policy_hnd(r->in.entry_handle)) {
		close_policy_hnd(p, r->in.entry_handle);
	}

	r->out.entry_handle = r->in.entry_handle;

	return EPMAPPER_STATUS_OK;
}


/*
 * epm_InqObject
 *
 * A client implementation SHOULD NOT call this method. These extensions do not
 * provide an alternative method.
 */
error_status_t _epm_InqObject(struct pipes_struct *p,
		      struct epm_InqObject *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
 * epm_MgmtDelete
 *
 * A client implementation SHOULD NOT call this method. These extensions do not
 * provide an alternative method.
*/
error_status_t _epm_MgmtDelete(struct pipes_struct *p,
		       struct epm_MgmtDelete *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_MapAuth
*/
error_status_t _epm_MapAuth(struct pipes_struct *p,
		    struct epm_MapAuth *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}

static NTSTATUS epmapper__op_shutdown_server(struct dcesrv_context *dce_ctx,
			const struct dcesrv_endpoint_server *ep_server);

#define DCESRV_INTERFACE_EPMAPPER_SHUTDOWN_SERVER \
       epmapper_shutdown_server

static NTSTATUS epmapper_shutdown_server(struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server)
{
	return epmapper__op_shutdown_server(dce_ctx, ep_server);
}

static NTSTATUS epmapper__op_init_server(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server *ep_server);

static NTSTATUS epmapper_init_server(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server *ep_server)
{
	char *epmdb_path = NULL;
	NTSTATUS status;

	epmdb_path = lock_path(dce_ctx, "epmdb.tdb");
	if (epmdb_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	epmdb = tdb_wrap_open(
		dce_ctx,
		epmdb_path,
		0,
		TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
		O_RDONLY,
		0644);
	if (epmdb == NULL) {
		DBG_DEBUG("Could not open epmdb.tdb: %s\n", strerror(errno));
		return map_nt_error_from_unix(errno);
	}
	TALLOC_FREE(epmdb_path);

	status = epmapper__op_init_server(dce_ctx, ep_server);
	return status;
}

#define DCESRV_INTERFACE_EPMAPPER_INIT_SERVER epmapper_init_server

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_epmapper_scompat.c"

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
