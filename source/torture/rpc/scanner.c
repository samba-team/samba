/* 
   Unix SMB/CIFS implementation.

   scanner for rpc calls

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
  work out how many calls there are for an interface
 */
static BOOL test_num_calls(const struct dcerpc_interface_table *iface,
			   TALLOC_CTX *mem_ctx,
			   struct dcerpc_syntax_id *id)
{
	struct dcerpc_pipe *p;
	NTSTATUS status;
	const char *uuid;
	int i;
	DATA_BLOB stub_in, stub_out;
	int idl_calls;

	uuid = GUID_string(mem_ctx, &id->uuid);

	status = torture_rpc_connection(&p, iface->name,
					uuid, id->major_version);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to connect to '%s' on '%s' - %s\n", 
		       uuid, iface->name, nt_errstr(status));
		return False;
	}

	/* make null calls */
	stub_in = data_blob(NULL, 0);

	status = dcerpc_request(p, 10000, mem_ctx, &stub_in, &stub_out);
	if (NT_STATUS_IS_OK(status) ||
	    p->last_fault_code != DCERPC_FAULT_OP_RNG_ERROR) {
		printf("\tunable to determine call count - %s %08x\n",
		       nt_errstr(status), p->last_fault_code);
		goto done;
	}

	for (i=128;i>=0;i--) {
		status = dcerpc_request(p, i, mem_ctx, &stub_in, &stub_out);
		if (NT_STATUS_IS_OK(status) ||
		    p->last_fault_code != DCERPC_FAULT_OP_RNG_ERROR) break;
	}

	printf("\t%d calls available\n", i+1);
	idl_calls = idl_num_calls(uuid, id->major_version);
	if (idl_calls == -1) {
		printf("\tinterface not known in local IDL\n");
	} else if (i+1 != idl_calls) {
		printf("\tWARNING: local IDL defines %u calls\n", idl_calls);
	} else {
		printf("\tOK: matches num_calls in local IDL\n");
	}

done:
	torture_rpc_close(p);
	return True;
}

/*
  ask the server what interface IDs are available on this endpoint
*/
static BOOL test_inq_if_ids(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx,
			    const struct dcerpc_interface_table *iface)
{
	NTSTATUS status;
	struct mgmt_inq_if_ids r;
	int i;
	
	status = dcerpc_mgmt_inq_if_ids(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("inq_if_ids failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("inq_if_ids gave error code %s\n", win_errstr(r.out.result));
		return False;
	}

	if (!r.out.if_id_vector) {
		printf("inq_if_ids gave NULL if_id_vector\n");
		return False;
	}

	for (i=0;i<r.out.if_id_vector->count;i++) {
		const char *uuid;
		struct dcerpc_syntax_id *id = r.out.if_id_vector->if_id[i].id;
		if (!id) continue;

		uuid = GUID_string(mem_ctx, &id->uuid),

		printf("\n\tuuid %s  version 0x%04x:0x%04x  '%s'\n",
		       uuid,
		       id->major_version, id->minor_version,
		       idl_pipe_name(uuid, id->major_version));
		test_num_calls(iface, mem_ctx, id);
	}

	return True;
}


BOOL torture_rpc_scanner(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	int i;
	char *host = lp_parm_string(-1, "torture", "host");
	uint32 port;

	mem_ctx = talloc_init("torture_rpc_scanner");

	for (i=0;dcerpc_pipes[i];i++) {		
		char *transport = lp_parm_string(-1, "torture", "transport");

		/* some interfaces are not mappable */
		if (dcerpc_pipes[i]->num_calls == 0 ||
		    strcmp(dcerpc_pipes[i]->name, "mgmt") == 0) {
			continue;
		}

		printf("\nTesting pipe '%s'\n", dcerpc_pipes[i]->name);

		/* on TCP we need to find the right endpoint */
		if (strcasecmp(transport, "ncacn_ip_tcp") == 0) {
			status = dcerpc_epm_map_tcp_port(host, 
							 dcerpc_pipes[i]->uuid, 
							 dcerpc_pipes[i]->if_version, 
							 &port);
			if (!NT_STATUS_IS_OK(status)) {
				ret = False;
				continue;
			}

			lp_set_cmdline("torture:share", 
				       talloc_asprintf(mem_ctx, "%u", port));
		}

		status = torture_rpc_connection(&p, 
						dcerpc_pipes[i]->name,
						DCERPC_MGMT_UUID,
						DCERPC_MGMT_VERSION);
		if (!NT_STATUS_IS_OK(status)) {
			ret = False;
			continue;
		}
	
		if (!test_inq_if_ids(p, mem_ctx, dcerpc_pipes[i])) {
			ret = False;
		}

		torture_rpc_close(p);
	}

	return ret;
}
