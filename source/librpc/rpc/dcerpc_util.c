/* 
   Unix SMB/CIFS implementation.

   dcerpc utility functions

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

/*
  this ndr_size_* stuff should really be auto-generated ....
*/

static size_t ndr_size_epm_floor(struct epm_floor *fl)
{
	size_t ret = 5;
	if (fl->lhs.protocol == EPM_PROTOCOL_UUID) {
		ret += 18;
	} else {
		ret += fl->lhs.info.lhs_data.length;
	}
	ret += fl->rhs.rhs_data.length;
	return ret;
}

size_t ndr_size_epm_towers(struct epm_towers *towers)
{
	size_t ret = 2;
	int i;
	for (i=0;i<towers->num_floors;i++) {
		ret += ndr_size_epm_floor(&towers->floors[i]);
	}
	return ret;
}

/*
  work out what TCP port to use for a given interface on a given host
*/
NTSTATUS dcerpc_epm_map_tcp_port(const char *server, 
				 const char *uuid, unsigned version,
				 uint32 *port)
{
	struct dcerpc_pipe *p;
	NTSTATUS status;
	struct epm_Map r;
	struct policy_handle handle;
	GUID guid;
	struct epm_twr_t twr, *twr_r;

	if (strcasecmp(uuid, DCERPC_EPMAPPER_UUID) == 0 ||
	    strcasecmp(uuid, DCERPC_MGMT_UUID) == 0) {
		/* don't lookup epmapper via epmapper! */
		*port = EPMAPPER_PORT;
		return NT_STATUS_OK;
	}

	status = dcerpc_pipe_open_tcp(&p, server, EPMAPPER_PORT);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* we can use the pipes memory context here as we will have a short
	   lived connection */
	status = dcerpc_bind_byuuid(p, p->mem_ctx, 
				    DCERPC_EPMAPPER_UUID,
				    DCERPC_EPMAPPER_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_pipe_close(p);
		return status;
	}

	ZERO_STRUCT(handle);
	ZERO_STRUCT(guid);

	twr.towers.num_floors = 5;
	twr.towers.floors = talloc(p->mem_ctx, sizeof(twr.towers.floors[0]) * 5);

	/* what I'd like for christmas ... */

	/* an RPC interface ... */
	twr.towers.floors[0].lhs.protocol = EPM_PROTOCOL_UUID;
	GUID_from_string(uuid, &twr.towers.floors[0].lhs.info.uuid.uuid);
	twr.towers.floors[0].lhs.info.uuid.version = version;
	twr.towers.floors[0].rhs.rhs_data = data_blob_talloc(p->mem_ctx, NULL, 2);

	/* encoded with NDR ... */
	twr.towers.floors[1].lhs.protocol = EPM_PROTOCOL_UUID;
	GUID_from_string(NDR_GUID, &twr.towers.floors[1].lhs.info.uuid.uuid);
	twr.towers.floors[1].lhs.info.uuid.version = NDR_GUID_VERSION;
	twr.towers.floors[1].rhs.rhs_data = data_blob_talloc(p->mem_ctx, NULL, 2);

	/* on an RPC connection ... */
	twr.towers.floors[2].lhs.protocol = EPM_PROTOCOL_RPC_C;
	twr.towers.floors[2].lhs.info.lhs_data = data_blob(NULL, 0);
	twr.towers.floors[2].rhs.rhs_data = data_blob_talloc(p->mem_ctx, NULL, 2);

	/* on a TCP port ... */
	twr.towers.floors[3].lhs.protocol = EPM_PROTOCOL_TCP;
	twr.towers.floors[3].lhs.info.lhs_data = data_blob(NULL, 0);
	twr.towers.floors[3].rhs.rhs_data = data_blob_talloc(p->mem_ctx, NULL, 2);

	/* on an IP link ... */
	twr.towers.floors[4].lhs.protocol = EPM_PROTOCOL_IP;
	twr.towers.floors[4].lhs.info.lhs_data = data_blob(NULL, 0);
	twr.towers.floors[4].rhs.rhs_data = data_blob_talloc(p->mem_ctx, NULL, 4);

	/* with some nice pretty paper around it of course */
	r.in.object = &guid;
	r.in.map_tower = &twr;
	r.in.entry_handle = &handle;
	r.in.max_towers = 1;
	r.out.entry_handle = &handle;

	status = dcerpc_epm_Map(p, p->mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_pipe_close(p);
		return status;
	}
	if (r.out.status != 0 || r.out.num_towers != 1) {
		dcerpc_pipe_close(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	twr_r = r.out.towers[0].twr;
	if (!twr_r) {
		dcerpc_pipe_close(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	if (twr_r->towers.num_floors != 5 ||
	    twr_r->towers.floors[3].lhs.protocol != twr.towers.floors[3].lhs.protocol ||
	    twr_r->towers.floors[3].rhs.rhs_data.length != 2) {
		dcerpc_pipe_close(p);
		return NT_STATUS_PORT_UNREACHABLE;
	}

	*port = RSVAL(twr_r->towers.floors[3].rhs.rhs_data.data, 0);

	dcerpc_pipe_close(p);

	return NT_STATUS_OK;
}


/*
  find the pipe name for a local IDL interface
*/
const char *idl_pipe_name(const char *uuid, uint32 if_version)
{
	int i;
	for (i=0;dcerpc_pipes[i];i++) {
		if (strcasecmp(dcerpc_pipes[i]->uuid, uuid) == 0 &&
		    dcerpc_pipes[i]->if_version == if_version) {
			return dcerpc_pipes[i]->name;
		}
	}
	return "UNKNOWN";
}

/*
  find the number of calls defined by local IDL
*/
int idl_num_calls(const char *uuid, uint32 if_version)
{
	int i;
	for (i=0;dcerpc_pipes[i];i++) {
		if (strcasecmp(dcerpc_pipes[i]->uuid, uuid) == 0 &&
		    dcerpc_pipes[i]->if_version == if_version) {
			return dcerpc_pipes[i]->num_calls;
		}
	}
	return -1;
}

