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

/* a endpoint combined with an interface description */
struct dcesrv_ep_iface {
	const char *name;
	struct dcesrv_ep_description ep_description;
	const char *uuid;
	uint32_t if_version;
};

/*
  simple routine to compare a GUID string to a GUID structure
*/
static int guid_cmp(TALLOC_CTX *mem_ctx, const struct GUID *guid, const char *uuid_str)
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
	twr->floors[2].lhs.protocol = EPM_PROTOCOL_NCACN_RPC_C;
	twr->floors[2].lhs.info.lhs_data = data_blob(NULL, 0);
	twr->floors[2].rhs.rhs_data = data_blob_talloc_zero(mem_ctx, 2);

	switch (e->ep_description.type) {
	case ENDPOINT_SMB:
		/* on a SMB pipe ... */
		twr->floors[3].lhs.protocol = EPM_PROTOCOL_NCACN_SMB;
		twr->floors[3].lhs.info.lhs_data = data_blob(NULL, 0);
		twr->floors[3].rhs.rhs_data.data = talloc_asprintf(mem_ctx, "\\PIPE\\%s", 
								   e->ep_description.info.smb_pipe);
		twr->floors[3].rhs.rhs_data.length = strlen(twr->floors[3].rhs.rhs_data.data)+1;
		
		/* on an NetBIOS link ... */
		twr->floors[4].lhs.protocol = EPM_PROTOCOL_NCACN_NETBIOS;
		twr->floors[4].lhs.info.lhs_data = data_blob(NULL, 0);
		twr->floors[4].rhs.rhs_data.data = talloc_asprintf(mem_ctx, "\\\\%s", 
								   lp_netbios_name());
		twr->floors[4].rhs.rhs_data.length = strlen(twr->floors[4].rhs.rhs_data.data)+1;
		break;

	case ENDPOINT_TCP:
		/* on a TCP connection ... */
		twr->floors[3].lhs.protocol = EPM_PROTOCOL_NCACN_TCP;
		twr->floors[3].lhs.info.lhs_data = data_blob(NULL, 0);
		twr->floors[3].rhs.rhs_data = data_blob_talloc(mem_ctx, NULL, 2);
		RSSVAL(twr->floors[3].rhs.rhs_data.data, 0, e->ep_description.info.tcp_port);
		
		/* on an IP link ... */
		twr->floors[4].lhs.protocol = EPM_PROTOCOL_NCACN_IP;
		twr->floors[4].lhs.info.lhs_data = data_blob(NULL, 0);
		twr->floors[4].rhs.rhs_data = data_blob_talloc_zero(mem_ctx, 4);
		/* TODO: we should fill in our IP address here as a hint to the 
		   client */
		break;
	}

	return True;
}


/*
  build a list of all interfaces handled by all endpoint servers
*/
static uint32_t build_ep_list(TALLOC_CTX *mem_ctx,
			    struct dcesrv_endpoint *endpoint_list,
			    struct dcesrv_ep_iface **eps)
{
	struct dcesrv_endpoint *d;
	uint32_t total = 0;

	(*eps) = NULL;
	
	for (d=endpoint_list; d; d=d->next) {
		struct dcesrv_if_list *iface;

		for (iface=d->interface_list;iface;iface=iface->next) {
			(*eps) = talloc_realloc_p(mem_ctx, *eps, 
						  struct dcesrv_ep_iface,
						  total + 1);
			if (!*eps) {
				return 0;
			}
			(*eps)[total].name = iface->iface.ndr->name;
			(*eps)[total].uuid = iface->iface.ndr->uuid;
			(*eps)[total].if_version = iface->iface.ndr->if_version;
			(*eps)[total].ep_description = d->ep_description;
			total++;
		}
	}

	return total;
}


static NTSTATUS epm_Insert(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, 
			   struct epm_Insert *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

static NTSTATUS epm_Delete(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, 
			   struct epm_Delete *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  implement epm_Lookup. This call is used to enumerate the interfaces
  available on a rpc server
*/
static NTSTATUS epm_Lookup(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, 
			   struct epm_Lookup *r)
{
	struct dcesrv_handle *h;
	struct rpc_eps {
		uint32_t count;
		struct dcesrv_ep_iface *e;
	} *eps;
	uint32_t num_ents;
	int i;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.entry_handle, HTYPE_LOOKUP);
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

		eps->count = build_ep_list(h->mem_ctx, dce_call->conn->dce_ctx->endpoint_list, &eps->e);
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
		dcesrv_handle_destroy(dce_call->conn, h);
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
static NTSTATUS epm_Map(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, 
			struct epm_Map *r)
{
	uint32_t count;
	int i;
	struct dcesrv_ep_iface *eps;
	struct epm_floor *floors;

	count = build_ep_list(mem_ctx, dce_call->conn->dce_ctx->endpoint_list, &eps);

	ZERO_STRUCT(*r->out.entry_handle);
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
	    floors[2].lhs.protocol != EPM_PROTOCOL_NCACN_RPC_C) {
		goto failed;
	}
	
	for (i=0;i<count;i++) {
		if (guid_cmp(mem_ctx, &floors[0].lhs.info.uuid.uuid, eps[i].uuid) != 0 ||
		    floors[0].lhs.info.uuid.version != eps[i].if_version) {
			continue;
		}
		switch (eps[i].ep_description.type) {
		case ENDPOINT_SMB:
			if (floors[3].lhs.protocol != EPM_PROTOCOL_NCACN_SMB ||
			    floors[4].lhs.protocol != EPM_PROTOCOL_NCACN_NETBIOS) {
				continue;
			}
			break;
		case ENDPOINT_TCP:
			if (floors[3].lhs.protocol != EPM_PROTOCOL_NCACN_TCP ||
			    floors[4].lhs.protocol != EPM_PROTOCOL_NCACN_IP) {
				continue;
			}
			break;
		}
		fill_protocol_tower(mem_ctx, &r->out.towers->twr->towers, &eps[i]);
		r->out.towers->twr->tower_length = 0;
		return NT_STATUS_OK;
	}


failed:
	r->out.num_towers = 0;
	r->out.status = EPMAPPER_STATUS_NO_MORE_ENTRIES;
	r->out.towers->twr = NULL;

	return NT_STATUS_OK;
}

static NTSTATUS epm_LookupHandleFree(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, 
				     struct epm_LookupHandleFree *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

static NTSTATUS epm_InqObject(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, 
			      struct epm_InqObject *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

static NTSTATUS epm_MgmtDelete(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, 
			       struct epm_MgmtDelete *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

static NTSTATUS epm_MapAuth(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			    struct epm_MapAuth *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_epmapper_s.c"
