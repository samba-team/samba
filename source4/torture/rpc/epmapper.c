/* 
   Unix SMB/CIFS implementation.
   test suite for epmapper rpc operations

   Copyright (C) Andrew Tridgell 2003
   
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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "librpc/rpc/dcerpc_table.h"
#include "torture/rpc/rpc.h"


/*
  display any protocol tower
 */
static void display_tower(TALLOC_CTX *mem_ctx, struct epm_tower *twr)
{
	int i;

	for (i=0;i<twr->num_floors;i++) {
		printf(" %s", epm_floor_string(mem_ctx, &twr->floors[i]));
	}
	printf("\n");
}


static BOOL test_Map(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		     struct epm_twr_t *twr)
{
	NTSTATUS status;
	struct epm_Map r;
	struct GUID uuid;
	struct policy_handle handle;
	int i;
	struct ndr_syntax_id syntax;
	uint32_t num_towers;

	ZERO_STRUCT(uuid);
	ZERO_STRUCT(handle);

	r.in.object = &uuid;
	r.in.map_tower = twr;
	r.in.entry_handle = &handle;	
	r.out.entry_handle = &handle;
	r.in.max_towers = 100;
	r.out.num_towers = &num_towers;

	dcerpc_floor_get_lhs_data(&twr->tower.floors[0], &syntax);

	printf("epm_Map results for '%s':\n", 
	       idl_pipe_name(&syntax.uuid, syntax.if_version));

	twr->tower.floors[2].lhs.protocol = EPM_PROTOCOL_NCACN;
	twr->tower.floors[2].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[2].rhs.ncacn.minor_version = 0;

	twr->tower.floors[3].lhs.protocol = EPM_PROTOCOL_TCP;
	twr->tower.floors[3].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[3].rhs.tcp.port = 0;

	twr->tower.floors[4].lhs.protocol = EPM_PROTOCOL_IP;
	twr->tower.floors[4].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[4].rhs.ip.ipaddr = "0.0.0.0";

	status = dcerpc_epm_Map(p, mem_ctx, &r);
	if (NT_STATUS_IS_OK(status) && r.out.result == 0) {
		for (i=0;i<*r.out.num_towers;i++) {
			if (r.out.towers[i].twr) {
				display_tower(mem_ctx, &r.out.towers[i].twr->tower);
			}
		}
	}

	twr->tower.floors[3].lhs.protocol = EPM_PROTOCOL_HTTP;
	twr->tower.floors[3].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[3].rhs.http.port = 0;

	status = dcerpc_epm_Map(p, mem_ctx, &r);
	if (NT_STATUS_IS_OK(status) && r.out.result == 0) {
		for (i=0;i<*r.out.num_towers;i++) {
			if (r.out.towers[i].twr) {
				display_tower(mem_ctx, &r.out.towers[i].twr->tower);
			}
		}
	}

	twr->tower.floors[3].lhs.protocol = EPM_PROTOCOL_UDP;
	twr->tower.floors[3].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[3].rhs.http.port = 0;

	status = dcerpc_epm_Map(p, mem_ctx, &r);
	if (NT_STATUS_IS_OK(status) && r.out.result == 0) {
		for (i=0;i<*r.out.num_towers;i++) {
			if (r.out.towers[i].twr) {
				display_tower(mem_ctx, &r.out.towers[i].twr->tower);
			}
		}
	}

	twr->tower.floors[3].lhs.protocol = EPM_PROTOCOL_SMB;
	twr->tower.floors[3].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[3].rhs.smb.unc = "";

	twr->tower.floors[4].lhs.protocol = EPM_PROTOCOL_NETBIOS;
	twr->tower.floors[4].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[4].rhs.netbios.name = "";

	status = dcerpc_epm_Map(p, mem_ctx, &r);
	if (NT_STATUS_IS_OK(status) && r.out.result == 0) {
		for (i=0;i<*r.out.num_towers;i++) {
			if (r.out.towers[i].twr) {
				display_tower(mem_ctx, &r.out.towers[i].twr->tower);
			}
		}
	}

	/* FIXME: Extend to do other protocols as well (ncacn_unix_stream, ncalrpc) */
	
	return True;
}

static BOOL test_Lookup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct epm_Lookup r;
	struct GUID uuid;
	struct rpc_if_id_t iface;
	struct policy_handle handle;
	uint32_t num_ents;

	ZERO_STRUCT(handle);

	r.in.inquiry_type = 0;
	r.in.object = &uuid;
	r.in.interface_id = &iface;
	r.in.vers_option = 0;
	r.in.entry_handle = &handle;
	r.out.entry_handle = &handle;
	r.in.max_ents = 10;
	r.out.num_ents = &num_ents;

	do {
		int i;

		ZERO_STRUCT(uuid);
		ZERO_STRUCT(iface);

		status = dcerpc_epm_Lookup(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status) || r.out.result != 0) {
			break;
		}

		printf("epm_Lookup returned %d events GUID %s\n", 
		       *r.out.num_ents, GUID_string(mem_ctx, &handle.uuid));

		for (i=0;i<*r.out.num_ents;i++) {
			printf("\nFound '%s'\n", r.out.entries[i].annotation);
			display_tower(mem_ctx, &r.out.entries[i].tower->tower);
			if (r.out.entries[i].tower->tower.num_floors == 5) {
				test_Map(p, mem_ctx, r.out.entries[i].tower);
			}
		}
	} while (NT_STATUS_IS_OK(status) && 
		 r.out.result == 0 && 
		 *r.out.num_ents == r.in.max_ents &&
		 !policy_handle_empty(&handle));

	if (!NT_STATUS_IS_OK(status)) {
		printf("Lookup failed - %s\n", nt_errstr(status));
		return False;
	}


	return True;
}

static BOOL test_Delete(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct epm_entry_t *entries)
{
	NTSTATUS status;
	struct epm_Delete r;

	r.in.num_ents = 1;
	r.in.entries = entries;
	
	status = dcerpc_epm_Delete(p, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		printf("Delete failed - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.result != 0) {
		printf("Delete failed - %d\n", r.out.result);
		return False;
	}

	return True;
}

static BOOL test_Insert(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct epm_Insert r;
	struct dcerpc_binding *bd;

	r.in.num_ents = 1;

	r.in.entries = talloc_array(mem_ctx, struct epm_entry_t, 1);
	ZERO_STRUCT(r.in.entries[0].object);
	r.in.entries[0].annotation = "smbtorture endpoint";
	status = dcerpc_parse_binding(mem_ctx, "ncalrpc:[SMBTORTURE]", &bd);
	if (NT_STATUS_IS_ERR(status)) {
		printf("Unable to generate dcerpc_binding struct\n");
		return False;
	}

	r.in.entries[0].tower = talloc(mem_ctx, struct epm_twr_t);

	status = dcerpc_binding_build_tower(mem_ctx, bd, &r.in.entries[0].tower->tower);
	if (NT_STATUS_IS_ERR(status)) {
		printf("Unable to build tower from binding struct\n");
		return False;
	}
	
	r.in.replace = 0;

	status = dcerpc_epm_Insert(p, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		printf("Insert failed - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.result != 0) {
		printf("Insert failed - %d\n", r.out.result);
		printf("NOT CONSIDERING AS A FAILURE\n");
		return True;
	}

	if (!test_Delete(p, mem_ctx, r.in.entries)) {
		return False; 
	}

	return True;
}

static BOOL test_InqObject(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct epm_InqObject r;

	r.in.epm_object = talloc(mem_ctx, struct GUID);
	*r.in.epm_object = ndr_table_epmapper.syntax_id.uuid;

	status = dcerpc_epm_InqObject(p, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		printf("InqObject failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

BOOL torture_rpc_epmapper(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_epmapper");

	status = torture_rpc_connection(mem_ctx, &p, &ndr_table_epmapper);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!test_Lookup(p, mem_ctx)) {
		ret = False;
	}

	if (!test_Insert(p, mem_ctx)) {
		ret = False;
	}

	if (!test_InqObject(p, mem_ctx)) {
		ret = False;
	}

	talloc_free(mem_ctx);

	return ret;
}
