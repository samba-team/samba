/* 
   Unix SMB/CIFS implementation.
   test suite for unixinfo rpc operations

   Copyright (C) Volker Lendecke 2005
   
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
#include "librpc/gen_ndr/ndr_unixinfo.h"


/*
  test the UidToSid interface
*/
static BOOL test_uidtosid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct unixinfo_UidToSid r;

	r.in.uid = 1000;

	status = dcerpc_unixinfo_UidToSid(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("UidToSid failed == %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_getpwuid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	uint64_t uids[512];
	const int num_uids = sizeof(uids)/sizeof(uids[0]);
	int i;
	struct unixinfo_GetPWUid r;
	NTSTATUS result;

	for (i=0; i<num_uids; i++) {
		uids[i] = i;
	}
	
	r.in.count = num_uids;
	r.in.uids = uids;

	result = dcerpc_unixinfo_GetPWUid(p, mem_ctx, &r);

	return NT_STATUS_IS_OK(result);
}

BOOL torture_rpc_unixinfo(void)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_unixinfo");

	status = torture_rpc_connection(mem_ctx, &p, &dcerpc_table_unixinfo);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	ret &= test_uidtosid(p, mem_ctx);
	ret &= test_getpwuid(p, mem_ctx);

	printf("\n");
	
	talloc_free(mem_ctx);

	return ret;
}
