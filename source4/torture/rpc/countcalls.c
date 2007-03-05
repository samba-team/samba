/* 
   Unix SMB/CIFS implementation.

   count number of calls on an interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007
   
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
#include "torture/torture.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_table.h"
#include "torture/rpc/rpc.h"


	
BOOL count_calls(TALLOC_CTX *mem_ctx,
		 const struct dcerpc_interface_table *iface,
	BOOL all) 
{
	struct dcerpc_pipe *p;
	DATA_BLOB stub_in, stub_out;
	int i;
	NTSTATUS status = torture_rpc_connection(mem_ctx, &p, iface);
	if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_NOT_FOUND, status)
	    || NT_STATUS_EQUAL(NT_STATUS_NET_WRITE_FAULT, status)
	    || NT_STATUS_EQUAL(NT_STATUS_PORT_UNREACHABLE, status)
	    || NT_STATUS_EQUAL(NT_STATUS_ACCESS_DENIED, status)) {
		if (all) {
			/* Not fatal if looking for all pipes */
			return True;
		} else {
			printf("Failed to open '%s' to count calls - %s\n", iface->name, nt_errstr(status));
			return False;
		}
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open '%s' to count calls - %s\n", iface->name, nt_errstr(status));
		return False;
	}

	stub_in = data_blob_talloc(p, mem_ctx, 0);

	printf("\nScanning pipe '%s'\n", iface->name);

	for (i=0;i<500;i++) {
		status = dcerpc_request(p, NULL, i, False, p, &stub_in, &stub_out);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT) &&
		    p->last_fault_code == DCERPC_FAULT_OP_RNG_ERROR) {
			i--;
			break;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT) &&
		    p->last_fault_code == DCERPC_FAULT_OP_RNG_ERROR) {
			i--;
			break;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_DISCONNECTED)) {
			i--;
			break;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_PIPE_DISCONNECTED)) {
			i--;
			break;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			i--;
			break;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_LOGON_FAILURE)) {
			i--;
			break;
		}
	}
	
	if (i==500) {
		talloc_free(p);
		printf("no limit on calls: %s!?\n", nt_errstr(status));
		return False;
	}

	printf("Found %d calls\n", i);

	talloc_free(p);
	
	return True;

}

BOOL torture_rpc_countcalls(struct torture_context *torture)
{
	const struct dcerpc_interface_table *iface;
	const char *iface_name;
	BOOL ret = True;
	const struct dcerpc_interface_list *l;
	TALLOC_CTX *mem_ctx = talloc_named(torture, 0, "torture_rpc_countcalls context");
	if (!mem_ctx) {
		return False;
	}
	iface_name = lp_parm_string(-1, "countcalls", "interface");
	if (iface_name != NULL) {
		iface = idl_iface_by_name(iface_name);
		if (!iface) {
			printf("Unknown interface '%s'\n", iface_name);
			return False;
		}
		return count_calls(mem_ctx, iface, False);
	}

	for (l=librpc_dcerpc_pipes();l;l=l->next) {		
		TALLOC_CTX *loop_ctx;
		loop_ctx = talloc_named(mem_ctx, 0, "torture_rpc_councalls loop context");
		ret &= count_calls(loop_ctx, l->table, True);
		talloc_free(loop_ctx);
	}
	return ret;
}
