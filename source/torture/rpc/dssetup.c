/* 
   Unix SMB/CIFS implementation.

   test suite for dssetup rpc operations

   Copyright (C) Andrew Tridgell 2004
   
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
#include "librpc/gen_ndr/ndr_dssetup.h"


static BOOL test_RolerGetPrimaryDomainInformation(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct ds_RolerGetPrimaryDomainInformation r;
	NTSTATUS status;
	BOOL ret = True;
	int i;

	printf("\ntesting RolerGetPrimaryDomainInformation\n");

	for (i=DS_BASIC_INFORMATION;i<=DS_ROLE_OP_STATUS;i++) {
		r.in.level = i;

		status = dcerpc_ds_RolerGetPrimaryDomainInformation(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("RolerGetPrimaryDomainInformation level %d failed - %s\n",
			       i, nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}

BOOL torture_rpc_dssetup(void)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_dssetup");

	status = torture_rpc_connection(&p, 
					DCERPC_DSSETUP_NAME, 
					DCERPC_DSSETUP_UUID, 
					DCERPC_DSSETUP_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	ret &= test_RolerGetPrimaryDomainInformation(p, mem_ctx);

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
