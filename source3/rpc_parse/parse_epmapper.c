/* 
   Unix SMB/CIFS implementation.
   Samba end point mapper functions
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)     2003.
   
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

static uint32 internal_referent_id = 0;


/*******************************************************************
 Reads or writes a handle.
********************************************************************/
BOOL epm_io_handle(const char *desc, EPM_HANDLE *handle, prs_struct *ps,
		   int depth)
{
	if (!prs_align(ps))
		return False;

	if (!prs_uint8s(False, "data", ps, depth, handle->data, 
			sizeof(handle->data)))
		return False;

	return True;
}

/*******************************************************************
 inits an EPM_FLOOR structure.
********************************************************************/
NTSTATUS init_epm_floor(EPM_FLOOR *floor, uint8 protocol)
{
	/* handle lhs */
	floor->lhs.protocol = protocol;
	floor->lhs.length = sizeof(floor->lhs.protocol);

	switch(floor->lhs.protocol) {
	case EPM_FLOOR_UUID:
		floor->lhs.length += sizeof(floor->lhs.uuid.uuid);
		floor->lhs.length += sizeof(floor->lhs.uuid.version);
		break;
	default:
		break;
	}

	/* handle rhs */
	switch(floor->lhs.protocol) {
	case EPM_FLOOR_RPC:
	case EPM_FLOOR_UUID:
		floor->rhs.length = sizeof(floor->rhs.unknown);
		break;
	case EPM_FLOOR_TCP:
		floor->rhs.length = sizeof(floor->rhs.tcp.port);
		break;
	case EPM_FLOOR_IP:
		floor->rhs.length = sizeof(floor->rhs.ip.addr);
		break;
	case EPM_FLOOR_NMPIPES:
	case EPM_FLOOR_LRPC:
	case EPM_FLOOR_NETBIOS:
		floor->rhs.length = strlen(floor->rhs.string) + 1;
		break;
	default:
		break;
	}

	return NT_STATUS_OK;
}
	
/*******************************************************************
 inits an EPM_FLOOR structure with a UUID
********************************************************************/
NTSTATUS init_epm_floor_uuid(EPM_FLOOR *floor,
			     const RPC_UUID *uuid, uint16 version)
{
	memcpy(&floor->lhs.uuid.uuid, uuid, sizeof(*uuid));
	floor->lhs.uuid.version = version;
	floor->rhs.unknown = 0;
	return init_epm_floor(floor, EPM_FLOOR_UUID);
}

/*******************************************************************
 inits an EPM_FLOOR structure for RPC
********************************************************************/
NTSTATUS init_epm_floor_rpc(EPM_FLOOR *floor)
{
	floor->rhs.unknown = 0;
	return init_epm_floor(floor, EPM_FLOOR_RPC);
}

/*******************************************************************
 inits an EPM_FLOOR structure for TCP
********************************************************************/
NTSTATUS init_epm_floor_tcp(EPM_FLOOR *floor, uint16 port)
{
	floor->rhs.tcp.port = htons(port);
	return init_epm_floor(floor, EPM_FLOOR_TCP);
}

/*******************************************************************
 inits an EPM_FLOOR structure for IP
********************************************************************/
NTSTATUS init_epm_floor_ip(EPM_FLOOR *floor, uint8 addr[4])
{
	memcpy(&floor->rhs.ip.addr, addr, sizeof(addr));
	return init_epm_floor(floor, EPM_FLOOR_IP);
}

/*******************************************************************
 inits an EPM_FLOOR structure for named pipe
********************************************************************/
NTSTATUS init_epm_floor_np(EPM_FLOOR *floor, const char *pipe_name)
{
	safe_strcpy(floor->rhs.string, pipe_name, sizeof(floor->rhs.string)-1);
	return init_epm_floor(floor, EPM_FLOOR_NMPIPES);
}

/*******************************************************************
 inits an EPM_FLOOR structure for named pipe
********************************************************************/
NTSTATUS init_epm_floor_lrpc(EPM_FLOOR *floor, const char *pipe_name)
{
	safe_strcpy(floor->rhs.string, pipe_name, sizeof(floor->rhs.string)-1);
	return init_epm_floor(floor, EPM_FLOOR_LRPC);
}

/*******************************************************************
 inits an EPM_FLOOR structure for named pipe
********************************************************************/
NTSTATUS init_epm_floor_nb(EPM_FLOOR *floor, char *host_name)
{
	safe_strcpy(floor->rhs.string, host_name, sizeof(floor->rhs.string)-1);
	return init_epm_floor(floor, EPM_FLOOR_NETBIOS);
}

/*******************************************************************
 reads and writes EPM_FLOOR.
********************************************************************/
BOOL epm_io_floor(const char *desc, EPM_FLOOR *floor,
		  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "epm_io_floor");
	depth++;

	if (!prs_uint16("lhs_length", ps, depth, &floor->lhs.length))
		return False;
	if (!prs_uint8("protocol", ps, depth, &floor->lhs.protocol))
		return False;

	switch (floor->lhs.protocol) {
	case EPM_FLOOR_UUID:
		if (!smb_io_rpc_uuid("uuid", &floor->lhs.uuid.uuid, ps, depth))
			return False;
		if (!prs_uint16("version", ps, depth, 
				&floor->lhs.uuid.version))
			return False;
		break;
	}

	if (!prs_uint16("rhs_length", ps, depth, &floor->rhs.length))
		return False;

	switch (floor->lhs.protocol) {
	case EPM_FLOOR_UUID:
	case EPM_FLOOR_RPC:
		if (!prs_uint16("unknown", ps, depth, &floor->rhs.unknown))
			return False;
		break;
	case EPM_FLOOR_TCP:
		if (!prs_uint16("tcp_port", ps, depth, &floor->rhs.tcp.port))
			return False;
		break;
	case EPM_FLOOR_IP:
		if (!prs_uint8s(False, "ip_addr", ps, depth, 
				floor->rhs.ip.addr,
				sizeof(floor->rhs.ip.addr)))
			return False;
		break;
	case EPM_FLOOR_NMPIPES:
	case EPM_FLOOR_LRPC:
	case EPM_FLOOR_NETBIOS:
		if (!prs_uint8s(False, "string", ps, depth,
				floor->rhs.string,
				floor->rhs.length))
			return False;
		break;
	default:
		break;
	}

	return True;
}

/*******************************************************************
 Inits a EPM_TOWER structure.
********************************************************************/
NTSTATUS init_epm_tower(TALLOC_CTX *ctx, EPM_TOWER *tower, 
			const EPM_FLOOR *floors, int num_floors)
{
	int size = 0;
	int i;

	DEBUG(5, ("init_epm_tower\n"));

	size += sizeof(uint16); /* number of floors is in tower length */
	for (i = 0; i < num_floors; i++) {
		size += (sizeof(uint16) * 2);
		size += floors[i].lhs.length;
		size += floors[i].rhs.length;
	}

	tower->max_length = tower->length = size;
	tower->num_floors = num_floors;
	tower->floors = talloc(ctx, sizeof(EPM_FLOOR) * num_floors);
	if (!tower->floors) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(tower->floors, floors, sizeof(EPM_FLOOR) * num_floors);
	tower->unknown = 0x7e;

	return NT_STATUS_OK;
}

/*******************************************************************
 Reads or writes an EPM_TOWER structure.
********************************************************************/
BOOL epm_io_tower(const char *desc, EPM_TOWER *tower,
		  prs_struct *ps, int depth)
{
	int i;

	prs_debug(ps, depth, desc, "epm_io_tower");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("max_length", ps, depth, &tower->max_length))
		return False;
	if (!prs_uint32("length", ps, depth, &tower->length))
		return False;
	if (!prs_uint16("num_floors", ps, depth, &tower->num_floors))
		return False;

	if (UNMARSHALLING(ps)) {
		tower->floors = talloc(ps->mem_ctx,
				       sizeof(EPM_FLOOR) * tower->num_floors);
		if (!tower->floors)
			return False;
	}

	for (i = 0; i < tower->num_floors; i++) {
		if (!epm_io_floor("floor", tower->floors + i, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
 Initialize an EPM_TOWER_ARRAY structure
********************************************************************/
NTSTATUS init_epm_tower_array(TALLOC_CTX *ctx, EPM_TOWER_ARRAY *array,
			      const EPM_TOWER *towers, int num_towers)
{
	int i;

	array->max_count = num_towers;
	array->offset = 0;
	array->count = num_towers;
	array->tower_ref_ids = talloc(ctx, sizeof(uint32) * num_towers);
	if (!array->tower_ref_ids) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<num_towers;i++)
		array->tower_ref_ids[i] = ++internal_referent_id;

	array->towers = talloc(ctx, sizeof(EPM_TOWER) * num_towers);
	if (!array->towers) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(array->towers, towers, sizeof(EPM_TOWER) * num_towers);

	return NT_STATUS_OK;
}

/*******************************************************************
 Reads or writes an EPM_TOWER_ARRAY structure.
********************************************************************/
BOOL epm_io_tower_array(const char *desc, EPM_TOWER_ARRAY *array,
			prs_struct *ps, int depth)
{
	int i;

	prs_debug(ps, depth, desc, "epm_io_tower_array");
	depth++;

	if (!prs_uint32("max_count", ps, depth, &array->max_count))
		return False;
	if (!prs_uint32("offset", ps, depth, &array->offset))
		return False;
	if (!prs_uint32("count", ps, depth, &array->count))
		return False;


	if (UNMARSHALLING(ps)) {
		array->tower_ref_ids = talloc(ps->mem_ctx,
					      sizeof(uint32) * array->count);
		if (!array->tower_ref_ids) {
			return False;
		}
	}
	for (i=0; i < array->count; i++)
		if (!prs_uint32("ref_id", ps, depth, &array->tower_ref_ids[i]))
			return False;

	if (!prs_set_offset(ps, prs_offset(ps) + array->offset))
		return False;

	if (UNMARSHALLING(ps)) {
		array->towers = talloc(ps->mem_ctx,
				       sizeof(EPM_TOWER) * array->count);
		if (!array->towers) {
			return False;
		}
	}

	for (i = 0; i < array->count; i++) {
		if (!epm_io_tower("tower", &array->towers[i], ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
  Initialize EPM_R_MAP structure
******************************************************************/
NTSTATUS init_epm_r_map(TALLOC_CTX *ctx, EPM_R_MAP *r_map, 
			const EPM_HANDLE *handle, const EPM_TOWER_ARRAY *array,
			int num_elements, uint32 status)
{
	memcpy(&r_map->handle, handle, sizeof(*handle));
	r_map->num_results = num_elements;
	r_map->results = talloc(ctx, sizeof(EPM_TOWER_ARRAY) * num_elements);
	if (!r_map->results) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(r_map->results, array, sizeof(EPM_TOWER_ARRAY) * num_elements);
	r_map->status = status;
	return NT_STATUS_OK;
}

/*************************************************************************
 Inits a EPM_Q_MAP structure.
**************************************************************************
* We attempt to hide the ugliness of the wire format by taking a EPM_TOWER
* array with a defined size 
**************************************************************************/
NTSTATUS init_epm_q_map(TALLOC_CTX *ctx, EPM_Q_MAP *q_map,
			const EPM_TOWER *towers, int num_towers)
{
	static uint32 handle = 1;

	ZERO_STRUCTP(q_map);

	DEBUG(5, ("init_epm_q_map\n"));
	q_map->handle.data[0] = (handle >>  0) & 0xFF;
	q_map->handle.data[1] = (handle >>  8) & 0xFF;
	q_map->handle.data[2] = (handle >> 16) & 0xFF;
	q_map->handle.data[3] = (handle >> 24) & 0xFF;

	q_map->tower = talloc(ctx, sizeof(EPM_TOWER) * (num_towers + 1));
	if (!q_map->tower) {
		return NT_STATUS_NO_MEMORY;
	}

	memcpy(q_map->tower, towers, sizeof(EPM_TOWER) * num_towers);

	ZERO_STRUCT(q_map->tower[num_towers]);

	/* For now let's not take more than 4 towers per result */
	q_map->max_towers = num_towers * 4;

	q_map->tower_ref_id = ++internal_referent_id;

	handle++;

	return NT_STATUS_OK;
}

/*****************************************************************
  epm_io_q_map - read or write EPM_Q_MAP structure
******************************************************************/
BOOL epm_io_q_map(const char *desc, EPM_Q_MAP *io_map, prs_struct *ps, 
		  int depth)
{
	prs_debug(ps, depth, desc, "epm_io_q_map");
	depth++;
	
	if (!epm_io_handle("handle", &io_map->handle, ps, depth))
		return False;

	if (!prs_uint32("max_towers", ps, 0, &io_map->tower_ref_id))
		return False;

	/* HACK: We need a more elegant way of doing this */
	if (UNMARSHALLING(ps)) {
		io_map->tower = talloc(ps->mem_ctx, sizeof(EPM_TOWER));
		if (!io_map->tower)
			return False;
	}		
	if (!epm_io_tower("tower", io_map->tower, ps, depth))
		return False;
	if (!epm_io_handle("term_handle", &io_map->term_handle, ps, depth))
		return False;

	if (!prs_uint32("max_towers", ps, 0, &io_map->max_towers))
		return False;

	return True;
}

/*******************************************************************
  epm_io_r_map - Read/Write EPM_R_MAP structure
******************************************************************/
BOOL epm_io_r_map(const char *desc, EPM_R_MAP *io_map,
		  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "epm_io_r_map");
	depth++;

	if (!epm_io_handle("handle", &io_map->handle, ps, depth))
		return False;
	if (!prs_uint32("num_results", ps, depth, &io_map->num_results))
		return False;

	if (UNMARSHALLING(ps)) {
		io_map->results = talloc(ps->mem_ctx,
					 sizeof(EPM_TOWER_ARRAY) * 
					 io_map->num_results);
		if (!io_map->results)
			return False;
	}
	if (!epm_io_tower_array("results", io_map->results, ps, depth))
			return False;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("status", ps, depth, &io_map->status))
		return False;

	return True;
}
