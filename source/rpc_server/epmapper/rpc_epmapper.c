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

static NTSTATUS epm_Insert(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			   struct epm_Lookup *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS epm_Delete(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			   struct epm_Lookup *r)
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
		struct dce_endpoint *d;
		struct dcesrv_ep_iface *e;

		eps = talloc_p(h->mem_ctx, struct rpc_eps);
		if (!eps) {
			return NT_STATUS_NO_MEMORY;
		}
		eps->count = 0;
		eps->e = NULL;
		h->data = eps;
		
		for (d=dce->smb->dcesrv.endpoint_list; d; d=d->next) {
			int count = d->endpoint_ops->lookup_endpoints(h->mem_ctx, &e);
			if (count > 0) {
				eps->e = talloc_realloc_p(h->mem_ctx,
							  eps->e,
							  struct dcesrv_ep_iface,
							  eps->count + count);
				if (!eps->e) {
					return NT_STATUS_NO_MEMORY;
				}
				memcpy(eps->e + eps->count, e, sizeof(*e) * count);
				eps->count += count;
			}
		}
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
		return NT_STATUS_OK;
	}

	r->out.entries = talloc_array_p(mem_ctx, struct epm_entry_t, num_ents);
	if (!r->out.entries) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<num_ents;i++) {
		struct epm_twr_t *t;
		struct epm_towers *twr;

		ZERO_STRUCT(r->out.entries[i].object);
		r->out.entries[i].annotation = "";
		t = talloc_p(mem_ctx, struct epm_twr_t);
		if (!twr) {
			return NT_STATUS_NO_MEMORY;
		}
		r->out.entries[i].tower = t;
		twr = &t->towers;
		twr->num_floors = 5;
		twr->floors = talloc_array_p(mem_ctx, struct epm_floor, 5);
		if (!twr->floors) {
			return NT_STATUS_NO_MEMORY;
		}

		twr->floors[0].lhs.protocol = EPM_PROTOCOL_UUID;
		GUID_from_string(eps->e[i].uuid, &twr->floors[0].lhs.info.uuid.uuid);
		twr->floors[0].lhs.info.uuid.version = eps->e[i].if_version;
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
								   eps->e[i].endpoint.info.smb_pipe);
		twr->floors[3].rhs.rhs_data.length = strlen(twr->floors[3].rhs.rhs_data.data);

		/* on an NetBIOS link ... */
		twr->floors[4].lhs.protocol = EPM_PROTOCOL_NETBIOS;
		twr->floors[4].lhs.info.lhs_data = data_blob(NULL, 0);
		twr->floors[4].rhs.rhs_data.data = talloc_asprintf(mem_ctx, "\\\\%s", 
								   lp_netbios_name());
		twr->floors[4].rhs.rhs_data.length = strlen(twr->floors[4].rhs.rhs_data.data);
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
			   struct epm_Lookup *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS epm_LookupHandleFree(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			   struct epm_Lookup *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS epm_InqObject(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			   struct epm_Lookup *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS epm_MgmtDelete(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, 
			   struct epm_Lookup *r)
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
