/* 
   Unix SMB/CIFS implementation.

   test suite for dcerpc alter_context operations

   Copyright (C) Andrew Tridgell 2005
   
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
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_dssetup.h"
#include "librpc/rpc/dcerpc.h"
#include "torture/rpc/rpc.h"

BOOL torture_rpc_alter_context(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p, *p2;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle *handle;
	struct dcerpc_interface_table tmptbl;
	struct ndr_syntax_id syntax;
	struct ndr_syntax_id transfer_syntax;

	mem_ctx = talloc_init("torture_rpc_alter_context");

	printf("opening LSA connection\n");
	status = torture_rpc_connection(mem_ctx, &p, &dcerpc_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!test_lsa_OpenPolicy2(p, mem_ctx, &handle)) {
		ret = False;
	}

	printf("Opening secondary DSSETUP context\n");
	status = dcerpc_secondary_context(p, &p2, &dcerpc_table_dssetup);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		printf("dcerpc_alter_context failed - %s\n", nt_errstr(status));
		return False;
	}

	tmptbl = dcerpc_table_dssetup;
	tmptbl.syntax_id.if_version += 100;
	printf("Opening bad secondary connection\n");
	status = dcerpc_secondary_context(p, &p2, &tmptbl);
	if (NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		printf("dcerpc_alter_context with wrong version should fail\n");
		return False;
	}

	printf("testing DSSETUP pipe operations\n");
	ret &= test_DsRoleGetPrimaryDomainInformation(p2, mem_ctx);

	if (handle) {
		if (!test_lsa_Close(p, mem_ctx, handle)) {
			ret = False;
		}
	}

	syntax = p->syntax;
	transfer_syntax = p->transfer_syntax;

	printf("Testing change of primary context\n");
	status = dcerpc_alter_context(p, mem_ctx, &p2->syntax, &p2->transfer_syntax);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		printf("dcerpc_alter_context failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("testing DSSETUP pipe operations - should fault\n");
	if (test_DsRoleGetPrimaryDomainInformation(p, mem_ctx)) {
		ret = False;
	}

	if (!test_lsa_OpenPolicy2(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (handle) {
		if (!test_lsa_Close(p, mem_ctx, handle)) {
			ret = False;
		}
	}

	printf("testing DSSETUP pipe operations\n");
	ret &= test_DsRoleGetPrimaryDomainInformation(p2, mem_ctx);

	talloc_free(mem_ctx);

	return ret;
}
