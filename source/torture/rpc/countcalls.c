/* 
   Unix SMB/CIFS implementation.

   count number of calls on an interface

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


BOOL torture_rpc_countcalls(void)
{
	const struct dcerpc_interface_table *iface;
	NTSTATUS status;
	struct dcerpc_pipe *p;
	int i;
	const char *iface_name;
	DATA_BLOB stub_in, stub_out;
	
	iface_name = lp_parm_string(-1, "countcalls", "interface");
	if (iface_name == NULL) {
		printf("You must specify an interface name with countcalls:interface\n");
		return False;
	}

	iface = idl_iface_by_name(iface_name);
	if (!iface) {
		printf("Unknown interface '%s'\n", iface_name);
		return False;
	}

	status = torture_rpc_connection(&p, iface->endpoints->names[0], 
					iface->uuid, iface->if_version);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open '%s' - %s\n", iface->name, nt_errstr(status));
		return False;
	}

	stub_in = data_blob_talloc(p, NULL, 0);

	printf("\nScanning pipe '%s'\n", iface->name);

	for (i=0;i<5000;i++) {
		status = dcerpc_request(p, NULL, i, p, &stub_in, &stub_out);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT) &&
		    p->last_fault_code == DCERPC_FAULT_OP_RNG_ERROR) break;
	}
	
	if (i==5000) {
		printf("no limit on calls!?\n");
		return False;
	}

	printf("Found %d calls\n", i);

	torture_rpc_close(p);

	return True;
}
