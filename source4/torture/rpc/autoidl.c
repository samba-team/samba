/* 
   Unix SMB/CIFS implementation.

   auto-idl scanner

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


static void reopen(struct dcerpc_pipe **p, const struct dcerpc_interface_table *iface)
{
	NTSTATUS status;

	if (*p) {
		dcerpc_pipe_close(*p);
	}

	status = torture_rpc_connection(p, iface->endpoints->names[0], iface->uuid, iface->if_version);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to reopen '%s' - %s\n", iface->name, nt_errstr(status));
		exit(1);
	}
}


static void test_ptr_scan(TALLOC_CTX *mem_ctx, const struct dcerpc_interface_table *iface, 
			  int opnum, int min_in)
{
	DATA_BLOB stub_in, stub_out;
	int ofs;
	NTSTATUS status;
	struct dcerpc_pipe *p = NULL;

	reopen(&p, iface);

	stub_in = data_blob(NULL, min_in);
	data_blob_clear(&stub_in);

	/* work out the minimum amount of input data */
	for (ofs=0;ofs<min_in;ofs+=4) {
		SIVAL(stub_in.data, ofs, 1);
		status = dcerpc_request(p, opnum, mem_ctx, &stub_in, &stub_out);
		SIVAL(stub_in.data, ofs, 0);

		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			printf("opnum %d ofs %d size %d fault 0x%08x\n", 
			       opnum, ofs, min_in, p->last_fault_code);
			if (p->last_fault_code == 5) {
				reopen(&p, iface);
			}
			continue;
		}
		printf("opnum %d  ofs %d error %s\n", opnum, ofs, nt_errstr(status));
	}

	dcerpc_pipe_close(p);	
}
	

static void test_scan_call(TALLOC_CTX *mem_ctx, const struct dcerpc_interface_table *iface, int opnum)
{
	DATA_BLOB stub_in, stub_out;
	int i;
	NTSTATUS status;
	struct dcerpc_pipe *p = NULL;

	reopen(&p, iface);

	/* work out the minimum amount of input data */
	for (i=0;i<100;i++) {
		stub_in = data_blob(NULL, i);
		data_blob_clear(&stub_in);

		status = dcerpc_request(p, opnum, mem_ctx, &stub_in, &stub_out);

		if (NT_STATUS_IS_OK(status)) {
			printf("opnum %d   min_input %d - output %d\n", 
			       opnum, stub_in.length, stub_out.length);
			dcerpc_pipe_close(p);
			test_ptr_scan(mem_ctx, iface, opnum, stub_in.length);
			return;
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			printf("opnum %d  size %d fault 0x%08x\n", opnum, i, p->last_fault_code);
			if (p->last_fault_code == 5) {
				reopen(&p, iface);
			}
			continue;
		}

		printf("opnum %d  size %d error %s\n", opnum, i, nt_errstr(status));
	}

	printf("opnum %d minimum not found!?\n", opnum);
	dcerpc_pipe_close(p);
}


static void test_auto_scan(TALLOC_CTX *mem_ctx, const struct dcerpc_interface_table *iface)
{
	int i;
	for (i=0;i<100;i++) {
		test_scan_call(mem_ctx, iface, i);
	}
}

BOOL torture_rpc_autoidl(int dummy)
{
        NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	const struct dcerpc_interface_table *iface;
	char *host = lp_parm_string(-1, "torture", "host");
	char *transport = lp_parm_string(-1, "torture", "transport");
		
	iface = idl_iface_by_name("browser");
	if (!iface) {
		printf("Unknown interface!\n");
		return False;
	}

	mem_ctx = talloc_init("torture_rpc_autoidl");

	printf("\nProbing pipe '%s'\n", iface->name);

	/* on TCP we need to find the right endpoint */
	if (strcasecmp(transport, "ncacn_ip_tcp") == 0) {
		uint32 port;
		status = dcerpc_epm_map_tcp_port(host, iface->uuid, iface->if_version, &port);
		if (!NT_STATUS_IS_OK(status)) {
			return False;
		}
		lp_set_cmdline("torture:share", talloc_asprintf(mem_ctx, "%u", port));
	}

	test_auto_scan(mem_ctx, iface);

	return True;
}
