/* 
   Unix SMB/CIFS implementation.
   test suite for epmapper rpc operations

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
  display any protocol tower
 */
static void display_tower(TALLOC_CTX *mem_ctx, struct epm_towers *twr)
{
	int i;
	const char *uuid;

	for (i=0;i<twr->num_floors;i++) {
		struct epm_lhs *lhs = &twr->floors[i].lhs;
		struct epm_rhs *rhs = &twr->floors[i].rhs;
		switch (lhs->protocol) {
		case 0xd:
			uuid = GUID_string(mem_ctx, &lhs->info.uuid.uuid);
			if (strcasecmp(uuid, NDR_GUID) == 0) {
				printf(" NDR");
			} else {
				printf(" uuid %s/0x%02x", uuid, lhs->info.uuid.version);
			}
			break;
		case 0xb:
			printf(" RPC-C");
			break;

		case 0x9:
			printf(" IP:");
			if (rhs->rhs_data.length == 4) {
				struct in_addr in;
				in.s_addr = RIVAL(rhs->rhs_data.data, 0);
				printf("%s", inet_ntoa(in));
			}
			break;

		case 0x10:
			printf(" PIPE:%.*s", rhs->rhs_data.length, rhs->rhs_data.data);
			break;

		case 0x0f:
			printf(" SMB:%.*s", rhs->rhs_data.length, rhs->rhs_data.data);
			break;

		case 0x11:
			printf(" NetBIOS:%.*s", rhs->rhs_data.length, rhs->rhs_data.data);
			break;

		case 0x01:
			printf(" UNK(1):%.*s", rhs->rhs_data.length, rhs->rhs_data.data);
			break;

		case 0x1f:
			printf(" TCP:");
			if (rhs->rhs_data.length == 2) {
				printf("%d", SVAL(rhs->rhs_data.data, 0));
			}
			break;

		default:
			printf(" UNK(%02x):", lhs->protocol);
			if (rhs->rhs_data.length == 2) {
				printf("%d", SVAL(rhs->rhs_data.data, 0));
			}
			break;
		}
	}
	printf("\n");
}


static BOOL test_Map(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		     struct epm_twr_t *twr)
{
	NTSTATUS status;
	struct epm_Map r;
	GUID uuid;
	struct policy_handle handle;
	int i;

	ZERO_STRUCT(uuid);
	ZERO_STRUCT(handle);

	r.in.object = &uuid;
	r.in.map_tower = twr;
	r.in.entry_handle = &handle;	
	r.out.entry_handle = &handle;
	r.in.max_towers = 100;

	status = dcerpc_epm_Map(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || r.out.status != 0) {
		printf("epm_Map failed - %s/0x%x\n", 
		       nt_errstr(status), r.out.status);
		return False;
	}

	printf("epm_Map results:\n");

	for (i=0;i<r.out.num_towers;i++) {
		if (r.out.towers[i].twr) {
			display_tower(mem_ctx, &r.out.towers[i].twr->towers);
		}
	}
	
	return True;
}

static BOOL test_Lookup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct epm_Lookup r;
	struct GUID uuid;
	struct rpc_if_id_t iface;
	struct policy_handle handle;

	ZERO_STRUCT(uuid);
	ZERO_STRUCT(iface);
	ZERO_STRUCT(handle);

	r.in.inquiry_type = 0;
	r.in.object = &uuid;
	r.in.interface_id = &iface;
	r.in.vers_option = 0;
	r.in.entry_handle = &handle;
	r.out.entry_handle = &handle;
	r.in.max_ents = 10;

	do {
		int i;
		status = dcerpc_epm_Lookup(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status) || r.out.status != 0) {
			break;
		}
		for (i=0;i<r.out.num_ents;i++) {
			printf("\nFound '%s'\n", r.out.entries[i].annotation);
			display_tower(mem_ctx, &r.out.entries[i].tower->towers);
			test_Map(p, mem_ctx, r.out.entries[i].tower);
		}
	} while (NT_STATUS_IS_OK(status) && 
		 r.out.status == 0 && 
		 r.out.num_ents == r.in.max_ents);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Lookup failed - %s\n", nt_errstr(status));
		return False;
	}


	return True;
}

BOOL torture_rpc_epmapper(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_epmapper");

	status = torture_rpc_tcp(&p, 
				 DCERPC_EPMAPPER_NAME,
				 DCERPC_EPMAPPER_UUID,
				 DCERPC_EPMAPPER_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

	if (!test_Lookup(p, mem_ctx)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
