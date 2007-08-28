/* 
   Unix SMB/CIFS implementation.

   test suite for dssetup rpc operations

   Copyright (C) Andrew Tridgell 2004
   
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
#include "librpc/gen_ndr/ndr_dssetup_c.h"
#include "torture/rpc/rpc.h"


BOOL test_DsRoleGetPrimaryDomainInformation(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct dssetup_DsRoleGetPrimaryDomainInformation r;
	NTSTATUS status;
	BOOL ret = True;
	int i;

	printf("\ntesting DsRoleGetPrimaryDomainInformation\n");

	for (i=DS_ROLE_BASIC_INFORMATION; i <= DS_ROLE_OP_STATUS; i++) {
		r.in.level = i;

		status = dcerpc_dssetup_DsRoleGetPrimaryDomainInformation(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			const char *errstr = nt_errstr(status);
			if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
				errstr = dcerpc_errstr(mem_ctx, p->last_fault_code);
			}
			printf("dcerpc_dssetup_DsRoleGetPrimaryDomainInformation level %d failed - %s\n",
				i, errstr);
			ret = False;
		} else if (!W_ERROR_IS_OK(r.out.result)) {
			printf("DsRoleGetPrimaryDomainInformation level %d failed - %s\n",
				i, win_errstr(r.out.result));
			ret = False;
		}
	}

	return ret;
}

BOOL torture_rpc_dssetup(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_dssetup");

	status = torture_rpc_connection(torture, &p, &ndr_table_dssetup);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);

		return False;
	}

	ret &= test_DsRoleGetPrimaryDomainInformation(p, mem_ctx);

	talloc_free(mem_ctx);

	return ret;
}
