/* 
   Unix SMB/CIFS implementation.
   test suite for mgmt rpc operations

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


static BOOL test_inq_if_ids(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct mgmt_inq_if_ids r;
	int i;

	status = dcerpc_mgmt_inq_if_ids(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("inq_if_ids failed - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.status != 0) {
		printf("inq_if_ids gave error code 0x%x\n", r.out.status);
		return False;
	}

	if (!r.out.if_id_vector) {
		printf("inq_if_ids gave NULL if_id_vector\n");
		return False;
	}

	for (i=0;i<r.out.if_id_vector->count;i++) {
		struct dcerpc_syntax_id *id = r.out.if_id_vector->if_id[i].id;
		if (!id) continue;
		printf("\tuuid %s  version 0x%04x:0x%04x\n",
		       GUID_string(mem_ctx, &id->uuid),
		       id->major_version, id->minor_version);
	}

	return True;
}

BOOL torture_rpc_mgmt(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	int i;

	mem_ctx = talloc_init("torture_rpc_mgmt");

	for (i=0;dcerpc_pipes[i];i++) {
		
		/* some interfaces are not mappable */
		if (dcerpc_pipes[i]->num_calls == 0 ||
		    strcmp(dcerpc_pipes[i]->name, "mgmt") == 0) {
			continue;
		}

		printf("\nTesting pipe '%s'\n", dcerpc_pipes[i]->name);

		status = torture_rpc_connection(&p, 
						dcerpc_pipes[i]->name,
						DCERPC_MGMT_UUID,
						DCERPC_MGMT_VERSION);
		if (!NT_STATUS_IS_OK(status)) {
			ret = False;
			continue;
		}
	
		p->flags |= DCERPC_DEBUG_PRINT_BOTH;

		if (!test_inq_if_ids(p, mem_ctx)) {
			ret = False;
		}

		torture_rpc_close(p);
	}

	return ret;
}
