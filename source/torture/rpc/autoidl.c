/* 
   Unix SMB/CIFS implementation.

   auto-idl scanner

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
#include "librpc/gen_ndr/ndr_drsuapi_c.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/rpc/dcerpc_table.h"
#include "torture/rpc/rpc.h"


#if 1
/*
  get a DRSUAPI policy handle
*/
static BOOL get_policy_handle(struct dcerpc_pipe *p,
			      TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct drsuapi_DsBind r;

	ZERO_STRUCT(r);
	r.out.bind_handle = handle;

	status = dcerpc_drsuapi_DsBind(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("drsuapi_DsBind failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}
#else
/*
  get a SAMR handle
*/
static BOOL get_policy_handle(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct samr_Connect r;

	r.in.system_name = 0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.connect_handle = handle;

	status = dcerpc_samr_Connect(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("samr_Connect failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}
#endif

static void fill_blob_handle(DATA_BLOB *blob, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle)
{
	DATA_BLOB b2;

	if (blob->length < 20) {
		return;
	}

	ndr_push_struct_blob(&b2, mem_ctx, handle, (ndr_push_flags_fn_t)ndr_push_policy_handle);

	memcpy(blob->data, b2.data, 20);
}

static void reopen(TALLOC_CTX *mem_ctx, 
		   struct dcerpc_pipe **p, 
		   const struct ndr_interface_table *iface)
{
	NTSTATUS status;

	talloc_free(*p);

	status = torture_rpc_connection(mem_ctx, 
					p, iface);
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

static void test_ptr_scan(TALLOC_CTX *mem_ctx, const struct ndr_interface_table *iface, 
			  int opnum, DATA_BLOB *base_in, int min_ofs, int max_ofs, int depth);

static void try_expand(TALLOC_CTX *mem_ctx, const struct ndr_interface_table *iface, 
		       int opnum, DATA_BLOB *base_in, int insert_ofs, int depth)
{
	DATA_BLOB stub_in, stub_out;
	int n;
	NTSTATUS status;
	struct dcerpc_pipe *p = NULL;

	reopen(mem_ctx, &p, iface);

	/* work out how much to expand to get a non fault */
	for (n=0;n<2000;n++) {
		stub_in = data_blob(NULL, base_in->length + n);
		data_blob_clear(&stub_in);
		memcpy(stub_in.data, base_in->data, insert_ofs);
		memcpy(stub_in.data+insert_ofs+n, base_in->data+insert_ofs, base_in->length-insert_ofs);

		status = dcerpc_request(p, NULL, opnum, False, mem_ctx, &stub_in, &stub_out);

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
			printf("expand by %d gives fault %s\n", n, dcerpc_errstr(mem_ctx, p->last_fault_code));
#endif
		}
		if (p->last_fault_code == 5) {
			reopen(mem_ctx, &p, iface);
		}
	}

	talloc_free(p);	
}


static void test_ptr_scan(TALLOC_CTX *mem_ctx, const struct ndr_interface_table *iface, 
			  int opnum, DATA_BLOB *base_in, int min_ofs, int max_ofs, int depth)
{
	DATA_BLOB stub_in, stub_out;
	int ofs;
	NTSTATUS status;
	struct dcerpc_pipe *p = NULL;

	reopen(mem_ctx, &p, iface);

	stub_in = data_blob(NULL, base_in->length);
	memcpy(stub_in.data, base_in->data, base_in->length);

	/* work out which elements are pointers */
	for (ofs=min_ofs;ofs<=max_ofs-4;ofs+=4) {
		SIVAL(stub_in.data, ofs, 1);
		status = dcerpc_request(p, NULL, opnum, False, mem_ctx, &stub_in, &stub_out);

		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			print_depth(depth);
			printf("possible ptr at ofs %d - fault %s\n", 
			       ofs-min_ofs, dcerpc_errstr(mem_ctx, p->last_fault_code));
			if (p->last_fault_code == 5) {
				reopen(mem_ctx, &p, iface);
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

	talloc_free(p);	
}
	

static void test_scan_call(TALLOC_CTX *mem_ctx, const struct ndr_interface_table *iface, int opnum)
{
	DATA_BLOB stub_in, stub_out;
	int i;
	NTSTATUS status;
	struct dcerpc_pipe *p = NULL;
	struct policy_handle handle;

	reopen(mem_ctx, &p, iface);

	get_policy_handle(p, mem_ctx, &handle);

	/* work out the minimum amount of input data */
	for (i=0;i<2000;i++) {
		stub_in = data_blob(NULL, i);
		data_blob_clear(&stub_in);


		status = dcerpc_request(p, NULL, opnum, False, mem_ctx, &stub_in, &stub_out);

		if (NT_STATUS_IS_OK(status)) {
			printf("opnum %d   min_input %d - output %d\n", 
			       opnum, (int)stub_in.length, (int)stub_out.length);
			dump_data(0, stub_out.data, stub_out.length);
			talloc_free(p);
			test_ptr_scan(mem_ctx, iface, opnum, &stub_in, 0, stub_in.length, 0);
			return;
		}

		fill_blob_handle(&stub_in, mem_ctx, &handle);

		status = dcerpc_request(p, NULL, opnum, False, mem_ctx, &stub_in, &stub_out);

		if (NT_STATUS_IS_OK(status)) {
			printf("opnum %d   min_input %d - output %d (with handle)\n", 
			       opnum, (int)stub_in.length, (int)stub_out.length);
			dump_data(0, stub_out.data, stub_out.length);
			talloc_free(p);
			test_ptr_scan(mem_ctx, iface, opnum, &stub_in, 0, stub_in.length, 0);
			return;
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			printf("opnum %d  size %d fault %s\n", opnum, i, dcerpc_errstr(mem_ctx, p->last_fault_code));
			if (p->last_fault_code == 5) {
				reopen(mem_ctx, &p, iface);
			}
			continue;
		}

		printf("opnum %d  size %d error %s\n", opnum, i, nt_errstr(status));
	}

	printf("opnum %d minimum not found!?\n", opnum);
	talloc_free(p);
}


static void test_auto_scan(TALLOC_CTX *mem_ctx, const struct ndr_interface_table *iface)
{
	test_scan_call(mem_ctx, iface, 2);
}

BOOL torture_rpc_autoidl(struct torture_context *torture)
{
	TALLOC_CTX *mem_ctx;
	const struct ndr_interface_table *iface;
		
	iface = idl_iface_by_name("drsuapi");
	if (!iface) {
		printf("Unknown interface!\n");
		return False;
	}

	mem_ctx = talloc_init("torture_rpc_autoidl");

	printf("\nProbing pipe '%s'\n", iface->name);

	test_auto_scan(mem_ctx, iface);

	talloc_free(mem_ctx);
	return True;
}
