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
#include "torture/torture.h"
#include "torture/rpc/rpc.h"
#include "librpc/gen_ndr/ndr_unixinfo_c.h"
#include "libcli/security/security.h"


/*
  test the SidToUid interface
*/
static BOOL test_sidtouid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct unixinfo_SidToUid r;
	struct dom_sid *sid;
	
	sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1234-5432");
	r.in.sid = *sid;

	status = dcerpc_unixinfo_SidToUid(p, mem_ctx, &r);
	if (NT_STATUS_EQUAL(NT_STATUS_NONE_MAPPED, status)) {
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("UidToSid failed == %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

/*
  test the UidToSid interface
*/
static BOOL test_uidtosid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct unixinfo_UidToSid r;

	r.in.uid = 1000;

	status = dcerpc_unixinfo_UidToSid(p, mem_ctx, &r);
	if (NT_STATUS_EQUAL(NT_STATUS_NO_SUCH_USER, status)) {
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("UidToSid failed == %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_getpwuid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	uint64_t uids[512];
	uint32_t num_uids = ARRAY_SIZE(uids);
	uint32_t i;
	struct unixinfo_GetPWUid r;
	NTSTATUS result;

	for (i=0; i<num_uids; i++) {
		uids[i] = i;
	}
	
	r.in.count = &num_uids;
	r.in.uids = uids;
	r.out.count = &num_uids;
	r.out.infos = talloc_array(mem_ctx, struct unixinfo_GetPWUidInfo, num_uids);

	result = dcerpc_unixinfo_GetPWUid(p, mem_ctx, &r);

	return NT_STATUS_IS_OK(result);
}

/*
  test the SidToGid interface
*/
static BOOL test_sidtogid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct unixinfo_SidToGid r;
	struct dom_sid *sid;
	
	sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-1234-5432");
	r.in.sid = *sid;

	status = dcerpc_unixinfo_SidToGid(p, mem_ctx, &r);
	if (NT_STATUS_EQUAL(NT_STATUS_NONE_MAPPED, status)) {
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("SidToGid failed == %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

/*
  test the GidToSid interface
*/
static BOOL test_gidtosid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct unixinfo_GidToSid r;

	r.in.gid = 1000;

	status = dcerpc_unixinfo_GidToSid(p, mem_ctx, &r);
	if (NT_STATUS_EQUAL(NT_STATUS_NO_SUCH_GROUP, status)) {
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("GidToSid failed == %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

BOOL torture_rpc_unixinfo(struct torture_context *torture)
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
	ret &= test_gidtosid(p, mem_ctx);

	printf("\n");
	
	talloc_free(mem_ctx);

	return ret;
}
