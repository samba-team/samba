/* 
   Unix SMB/CIFS implementation.

   endpoint server for the epmapper pipe

   Copyright (C) Andrew Tridgell 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"


/* handle types for this module */
enum handle_types {HTYPE_LOOKUP};


/*
  simple routine to compare a GUID string to a GUID structure
*/
static int guid_cmp(TALLOC_CTX *mem_ctx, const GUID *guid, const char *uuid_str)
{
	const char *s = GUID_string(mem_ctx, guid);
	if (!s || strcasecmp(s, uuid_str)) {
		return -1;
	}
	return 0;
}

/*
  fill a protocol tower
*/
static BOOL fill_protocol_tower(TALLOC_CTX *mem_ctx, struct epm_towers *twr, 
				struct dcesrv_ep_iface *e)
{
	twr->num_floors = 5;
	twr->floors = talloc_array_p(mem_ctx, struct epm_floor, 5);
	if (!twr->floors) {
		return False;
	}
	
	twr->floors[0].lhs.protocol = EPM_PROTOCOL_UUID;
	GUID_from_string(e->uuid, &twr->floors[0].lhs.info.uuid.uuid);
	twr->floors[0].lhs.info.uuid.version = e->if_version;
	twr->floors[0].rhs.rhs_data = data_blob_talloc_zero(mem_ctx, 2);
	
	/* encoded with NDR ... */
	twr->floors[1].lhs.protocol = EPM_PROTOCOL_UUID;
	GUID_from_string(NDR_GUID, &twr->floors[1].lhs.info.uuid.uuid);
	twr->floors[1].lhs.info.uuid.version = NDR_GUID_VERSION;
	twr->floors[1].rhs.rhs_data = data_blob_talloc_zero(mem_ctx, 2);
	
	/* on an RPC connection ... */
	twr->floors[2].lhs.protocol = EPM_PROTOCOL_RPC_C;
	twr->floors[2].lhs.info.lhs_data = data_blob(NULL, 0);
	twr->floors[2].rhs.rhs_data = data_blob_talloc_zero(mem_ctx, 2);
	
	/* on a SMB pipe ... */
	twr->floors[3].lhs.protocol = EPM_PROTOCOL_SMB;
	twr->floors[3].lhs.info.lhs_data = data_blob(NULL, 0);
	twr->floors[3].rhs.rhs_data.data = talloc_asprintf(mem_ctx, "\\PIPE\\%s", 
							   e->endpoint.info.smb_pipe);
	twr->floors[3].rhs.rhs_data.length = strlen(twr->floors[3].rhs.rhs_data.data)+1;
	
	/* on an NetBIOS link ... */
	twr->floors[4].lhs.protocol = EPM_PROTOCOL_NETBIOS;
	twr->floors[4].lhs.info.lhs_data = data_blob(NULL, 0);
	twr->floors[4].rhs.rhs_data.data = talloc_asprintf(mem_ctx, "\\\\%s", 
							   lp_netbios_name());
	twr->floors[4].rhs.rhs_data.length = strlen(twr->floors[4].rhs.rhs_data.data)+1;

	return True;
}


/*
  build a list of all interfaces handled by all endpoint servers
*/
static uint32 build_ep_list(TALLOC_CTX *mem_ctx,
			    struct dce_endpoint *endpoint_list,
			    struct dcesrv_ep_iface **eps)
{
	struct dce_endpoint *d;
	uint32 total = 0;

	(*eps) = NULL;
	
	for (d=endpoint_list; d; d=d->next) {
		struct dcesrv_ep_iface *e;
		int count = d->endpoint_ops->lookup_endpoints(mem_ctx, &e);
		if (count > 0) {
			(*eps) = talloc_realloc_p(mem_ctx, *eps, 
						  struct dcesrv_ep_iface,
						  total + count);
			if (!*eps) {
				return 0;
			}
			memcpy((*eps) + total, e, sizeof(*e) * count);
			total += count;
		}
	}

	return total;
}


static NTSTATUS epm_Insert(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			   struct epm_Insert *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS epm_Delete(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			   struct epm_Delete *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  implement epm_Lookup. This call is used to enumerate the interfaces
  available on a rpc server
*/
static NTSTATUS epm_Lookup(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			   struct epm_Lookup *r)
{
	struct dcesrv_handle *h;
	struct rpc_eps {
		uint32 count;
		struct dcesrv_ep_iface *e;
	} *eps;
	uint32 num_ents;
	int i;

	h = dcesrv_handle_fetch(dce, r->in.entry_handle, HTYPE_LOOKUP);
	if (!h) {
		return NT_STATUS_INVALID_HANDLE;
	}

	eps = h->data;

	if (!eps) {
		/* this is the first call - fill the list. Subsequent calls 
		   will feed from this list, stored in the handle */
		eps = talloc_p(h->mem_ctx, struct rpc_eps);
		if (!eps) {
			return NT_STATUS_NO_MEMORY;
		}
		h->data = eps;

		eps->count = build_ep_list(h->mem_ctx, dce->smb->dcesrv.endpoint_list, &eps->e);
	}

	/* return the next N elements */
	num_ents = r->in.max_ents;
	if (num_ents > eps->count) {
		num_ents = eps->count;
	}

	*r->out.entry_handle = h->wire_handle;
	r->out.num_ents = num_ents;
	r->out.status = 0;

	if (num_ents == 0) {
		r->out.entries = NULL;
		r->out.status  = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		ZERO_STRUCTP(r->out.entry_handle);
		dcesrv_handle_destroy(dce, h);
		return NT_STATUS_OK;
	}

	r->out.entries = talloc_array_p(mem_ctx, struct epm_entry_t, num_ents);
	if (!r->out.entries) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<num_ents;i++) {
		ZERO_STRUCT(r->out.entries[i].object);
		r->out.entries[i].annotation = eps->e[i].name;
		r->out.entries[i].tower = talloc_p(mem_ctx, struct epm_twr_t);
		if (!r->out.entries[i].tower) {
			return NT_STATUS_NO_MEMORY;
		}

		if (!fill_protocol_tower(mem_ctx, &r->out.entries[i].tower->towers, &eps->e[i])) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	eps->count -= num_ents;
	eps->e += num_ents;

	return NT_STATUS_OK;
}


/*
  implement epm_Map. This is used to find the specific endpoint to talk to given
  a generic protocol tower
*/
static NTSTATUS epm_Map(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			struct epm_Map *r)
{
	uint32 count;
	int i;
	struct dcesrv_ep_iface *eps;
	struct epm_floor *floors;

	count = build_ep_list(mem_ctx, dce->smb->dcesrv.endpoint_list, &eps);

	ZERO_STRUCTP(r->out.entry_handle);
	r->out.num_towers = 1;
	r->out.status = 0;
	r->out.towers = talloc_p(mem_ctx, struct epm_twr_p_t);
	if (!r->out.towers) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.towers->twr = talloc_p(mem_ctx, struct epm_twr_t);
	if (!r->out.towers->twr) {
		return NT_STATUS_NO_MEMORY;
	}
	
	if (!r->in.map_tower || r->in.max_towers == 0 ||
	    r->in.map_tower->towers.num_floors != 5) {
		goto failed;
	}

	floors = r->in.map_tower->towers.floors;

	if (floors[0].lhs.protocol != EPM_PROTOCOL_UUID ||
	    floors[1].lhs.protocol != EPM_PROTOCOL_UUID ||
	    guid_cmp(mem_ctx, &floors[1].lhs.info.uuid.uuid, NDR_GUID) != 0 ||
	    floors[1].lhs.info.uuid.version != NDR_GUID_VERSION ||
	    floors[2].lhs.protocol != EPM_PROTOCOL_RPC_C) {
		goto failed;
	}
	
	for (i=0;i<count;i++) {
		if (guid_cmp(mem_ctx, &floors[0].lhs.info.uuid.uuid, eps[i].uuid) != 0 ||
		    floors[0].lhs.info.uuid.version != eps[i].if_version) {
			continue;
		}
		switch (eps[i].endpoint.type) {
		case ENDPOINT_SMB:
			if (floors[3].lhs.protocol != EPM_PROTOCOL_SMB ||
			    floors[4].lhs.protocol != EPM_PROTOCOL_NETBIOS) {
				continue;
			}
			break;
		case ENDPOINT_TCP:
			if (floors[3].lhs.protocol != EPM_PROTOCOL_TCP ||
			    floors[4].lhs.protocol != EPM_PROTOCOL_IP) {
				continue;
			}
			break;
		}
		fill_protocol_tower(mem_ctx, &r->out.towers->twr->towers, &eps[i]);
		return NT_STATUS_OK;
	}


failed:
	r->out.num_towers = 0;
	r->out.status = EPMAPPER_STATUS_NO_MORE_ENTRIES;
	r->out.towers->twr = NULL;

	return NT_STATUS_OK;
}

static NTSTATUS epm_LookupHandleFree(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
				     struct epm_LookupHandleFree *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS epm_InqObject(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			      struct epm_InqObject *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS epm_MgmtDelete(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			       struct epm_MgmtDelete *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/**************************************************************************
  all the code below this point is boilerplate that will be auto-generated
***************************************************************************/

static const dcesrv_dispatch_fn_t dispatch_table[] = {
	(dcesrv_dispatch_fn_t)epm_Insert,
	(dcesrv_dispatch_fn_t)epm_Delete,
	(dcesrv_dispatch_fn_t)epm_Lookup,
	(dcesrv_dispatch_fn_t)epm_Map,
	(dcesrv_dispatch_fn_t)epm_LookupHandleFree,
	(dcesrv_dispatch_fn_t)epm_InqObject,
	(dcesrv_dispatch_fn_t)epm_MgmtDelete
};


/*
  return True if we want to handle the given endpoint
*/
static BOOL op_query_endpoint(const struct dcesrv_endpoint *ep)
{
	return dcesrv_table_query(&dcerpc_table_epmapper, ep);
}

/*
  setup for a particular rpc interface
*/
static BOOL op_set_interface(struct dcesrv_state *dce, const char *uuid, uint32 if_version)
{
	if (strcasecmp(uuid, dcerpc_table_epmapper.uuid) != 0 ||
	    if_version != dcerpc_table_epmapper.if_version) {
		DEBUG(2,("Attempt to use unknown interface %s/%d\n", uuid, if_version));
		return False;
	}

	dce->ndr = &dcerpc_table_epmapper;
	dce->dispatch = dispatch_table;

	return True;
}


/* op_connect is called when a connection is made to an endpoint */
static NTSTATUS op_connect(struct dcesrv_state *dce)
{
	return NT_STATUS_OK;
}

static void op_disconnect(struct dcesrv_state *dce)
{
	/* nothing to do */
}


static int op_lookup_endpoints(TALLOC_CTX *mem_ctx, struct dcesrv_ep_iface **e)
{
	return dcesrv_lookup_endpoints(&dcerpc_table_epmapper, mem_ctx, e);
}


static const struct dcesrv_endpoint_ops rpc_epmapper_ops = {
	op_query_endpoint,
	op_set_interface,
	op_connect,
	op_disconnect,
	op_lookup_endpoints
};

/*
  register with the dcerpc server
*/
void rpc_epmapper_init(struct server_context *smb)
{
	if (!dcesrv_endpoint_register(smb, &rpc_epmapper_ops)) {
		DEBUG(1,("Failed to register epmapper endpoint\n"));
	}
}
