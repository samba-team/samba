/* 
   Unix SMB/CIFS implementation.

   DRSUapi tests

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004
   
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

static const char *machine_password;

#define TEST_MACHINE_NAME "torturetest"

#if 0
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

static void print_depth(int depth)
{
	int i;
	for (i=0;i<depth;i++) {
		printf("    ");
	}
}

static void test_ptr_scan(TALLOC_CTX *mem_ctx, const struct dcerpc_interface_table *iface, 
			  int opnum, DATA_BLOB *base_in, int min_ofs, int max_ofs, int depth);

static void try_expand(TALLOC_CTX *mem_ctx, const struct dcerpc_interface_table *iface, 
		       int opnum, DATA_BLOB *base_in, int insert_ofs, int depth)
{
	DATA_BLOB stub_in, stub_out;
	int n;
	NTSTATUS status;
	struct dcerpc_pipe *p = NULL;

	reopen(&p, iface);

	/* work out how much to expand to get a non fault */
	for (n=0;n<2000;n++) {
		stub_in = data_blob(NULL, base_in->length + n);
		data_blob_clear(&stub_in);
		memcpy(stub_in.data, base_in->data, insert_ofs);
		memcpy(stub_in.data+insert_ofs+n, base_in->data+insert_ofs, base_in->length-insert_ofs);

		status = dcerpc_request(p, opnum, mem_ctx, &stub_in, &stub_out);

		if (!NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			print_depth(depth);
			printf("expand by %d gives %s\n", n, nt_errstr(status));
			if (n >= 4) {
				test_ptr_scan(mem_ctx, iface, opnum, &stub_in, 
					      insert_ofs, insert_ofs+n, depth+1);
			}
			return;
		} else {
#if 0
			print_depth(depth);
			printf("expand by %d gives fault 0x%x\n", n, p->last_fault_code);
#endif
		}
		if (p->last_fault_code == 5) {
			reopen(&p, iface);
		}
	}

	dcerpc_pipe_close(p);	
}


static void test_ptr_scan(TALLOC_CTX *mem_ctx, const struct dcerpc_interface_table *iface, 
			  int opnum, DATA_BLOB *base_in, int min_ofs, int max_ofs, int depth)
{
	DATA_BLOB stub_in, stub_out;
	int ofs;
	NTSTATUS status;
	struct dcerpc_pipe *p = NULL;

	reopen(&p, iface);

	stub_in = data_blob(NULL, base_in->length);
	memcpy(stub_in.data, base_in->data, base_in->length);

	/* work out which elements are pointers */
	for (ofs=min_ofs;ofs<=max_ofs-4;ofs+=4) {
		SIVAL(stub_in.data, ofs, 1);
		status = dcerpc_request(p, opnum, mem_ctx, &stub_in, &stub_out);

		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			print_depth(depth);
			printf("possible ptr at ofs %d - fault 0x%08x\n", 
			       ofs-min_ofs, p->last_fault_code);
			if (p->last_fault_code == 5) {
				reopen(&p, iface);
			}
			if (depth == 0) {
				try_expand(mem_ctx, iface, opnum, &stub_in, ofs+4, depth+1);
			} else {
				try_expand(mem_ctx, iface, opnum, &stub_in, max_ofs, depth+1);
			}
			SIVAL(stub_in.data, ofs, 0);
			continue;
		}
		SIVAL(stub_in.data, ofs, 0);
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
	for (i=0;i<2000;i++) {
		stub_in = data_blob(NULL, i);
		data_blob_clear(&stub_in);


		status = dcerpc_request(p, opnum, mem_ctx, &stub_in, &stub_out);

		if (NT_STATUS_IS_OK(status)) {
			printf("opnum %d   min_input %d - output %d\n", 
			       opnum, stub_in.length, stub_out.length);
			dump_data(0, stub_out.data, stub_out.length);
			dcerpc_pipe_close(p);
			test_ptr_scan(mem_ctx, iface, opnum, &stub_in, 0, stub_in.length, 0);
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


static BOOL test_scan(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	test_scan_call(mem_ctx, &dcerpc_table_drsuapi, 0x0);
	return True;
}
#endif

static BOOL test_DRSBind(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct DRSUAPI_BIND r;
	BOOL ret = True;

	ZERO_STRUCT(r.in.blob);

	status = dcerpc_DRSUAPI_BIND(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(p->last_fault_code);
		}
		printf("DRSUAPI_BIND level failed - %s\n", errstr);
		ret = False;
	}

	return ret;
}

BOOL torture_rpc_drsuapi(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	void *join_ctx;
	const char *binding = lp_parm_string(-1, "torture", "binding");

	if (!binding) {
		printf("You must specify a ncacn binding string\n");
		return False;
	}

	lp_set_cmdline("netbios name", TEST_MACHINE_NAME);

	join_ctx = torture_join_domain(TEST_MACHINE_NAME, lp_workgroup(), ACB_SVRTRUST, 
				       &machine_password);
	if (!join_ctx) {
		printf("Failed to join as BDC\n");
		return False;
	}

	status = dcerpc_pipe_connect(&p, binding,
				     	DCERPC_DRSUAPI_UUID,
					DCERPC_DRSUAPI_VERSION,
					lp_workgroup(), 
					TEST_MACHINE_NAME"$",
					machine_password);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	mem_ctx = talloc_init("torture_rpc_drsuapi");

	if (!test_DRSBind(p, mem_ctx)) {
		ret = False;
	}

#if 0
	if (!test_scan(p, mem_ctx)) {
		ret = False;
	}
#endif
	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	torture_leave_domain(join_ctx);

	return ret;
}
