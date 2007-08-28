/* 
   Unix SMB/CIFS implementation.
   Test suite for libnet calls.

   Copyright (C) Rafal Szczesniak  2007
   
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
#include "lib/cmdline/popt_common.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "torture/torture.h"
#include "torture/rpc/rpc.h"


#define TEST_GROUPNAME  "libnetgrouptest"


static BOOL test_cleanup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *domain_handle, const char *groupname)
{
	NTSTATUS status;
	struct samr_LookupNames r1;
	struct samr_OpenGroup r2;
	struct samr_DeleteDomainGroup r3;
	struct lsa_String names[2];
	uint32_t rid;
	struct policy_handle group_handle;

	names[0].string = groupname;

	r1.in.domain_handle  = domain_handle;
	r1.in.num_names      = 1;
	r1.in.names          = names;
	
	printf("group account lookup '%s'\n", groupname);

	status = dcerpc_samr_LookupNames(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return False;
	}

	rid = r1.out.rids.ids[0];
	
	r2.in.domain_handle  = domain_handle;
	r2.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r2.in.rid            = rid;
	r2.out.group_handle  = &group_handle;

	printf("opening group account\n");

	status = dcerpc_samr_OpenGroup(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenGroup failed - %s\n", nt_errstr(status));
		return False;
	}

	r3.in.group_handle  = &group_handle;
	r3.out.group_handle = &group_handle;

	printf("deleting group account\n");
	
	status = dcerpc_samr_DeleteDomainGroup(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteGroup failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_creategroup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			     struct policy_handle *handle, const char *name)
{
	NTSTATUS status;
	struct lsa_String groupname;
	struct samr_CreateDomainGroup r;
	struct policy_handle group_handle;
	uint32_t group_rid;
	
	groupname.string = name;
	
	r.in.domain_handle  = handle;
	r.in.name           = &groupname;
	r.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.group_handle  = &group_handle;
	r.out.rid           = &group_rid;

	printf("creating group account %s\n", name);

	status = dcerpc_samr_CreateDomainGroup(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateGroup failed - %s\n", nt_errstr(status));

		if (NT_STATUS_EQUAL(status, NT_STATUS_GROUP_EXISTS)) {
			printf("Group (%s) already exists - attempting to delete and recreate group again\n", name);
			if (!test_cleanup(p, mem_ctx, handle, TEST_GROUPNAME)) {
				return False;
			}

			printf("creating group account\n");
			
			status = dcerpc_samr_CreateDomainGroup(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status)) {
				printf("CreateGroup failed - %s\n", nt_errstr(status));
				return False;
			}
			return True;
		}
		return False;
	}

	return True;
}


static BOOL test_opendomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *handle, struct lsa_String *domname)
{
	NTSTATUS status;
	struct policy_handle h, domain_handle;
	struct samr_Connect r1;
	struct samr_LookupDomain r2;
	struct samr_OpenDomain r3;
	
	printf("connecting\n");
	
	r1.in.system_name = 0;
	r1.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r1.out.connect_handle = &h;
	
	status = dcerpc_samr_Connect(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect failed - %s\n", nt_errstr(status));
		return False;
	}
	
	r2.in.connect_handle = &h;
	r2.in.domain_name = domname;

	printf("domain lookup on %s\n", domname->string);

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	r3.in.connect_handle = &h;
	r3.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r3.in.sid = r2.out.sid;
	r3.out.domain_handle = &domain_handle;

	printf("opening domain\n");

	status = dcerpc_samr_OpenDomain(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenDomain failed - %s\n", nt_errstr(status));
		return False;
	} else {
		*handle = domain_handle;
	}

	return True;
}


static BOOL test_samr_close(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *domain_handle)
{
	NTSTATUS status;
	struct samr_Close r;
  
	r.in.handle = domain_handle;
	r.out.handle = domain_handle;

	status = dcerpc_samr_Close(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close samr domain failed - %s\n", nt_errstr(status));
		return False;
	}
	
	return True;
}


BOOL torture_groupinfo_api(struct torture_context *torture)
{
	const char *name = TEST_GROUPNAME;
	const char *binding;
	BOOL ret = True;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL, *prep_mem_ctx;
	struct libnet_context *ctx;
	struct dcerpc_pipe *p;
	struct policy_handle h;
	struct lsa_String domain_name;
	struct libnet_GroupInfo req;

	prep_mem_ctx = talloc_init("prepare torture group info");
	binding = torture_setting_string(torture, "binding", NULL);

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	status = torture_rpc_connection(torture,
					&p,
					&ndr_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	domain_name.string = lp_workgroup();
	if (!test_opendomain(p, prep_mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_creategroup(p, prep_mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	mem_ctx = talloc_init("torture group info");

	ZERO_STRUCT(req);
	
	req.in.domain_name = domain_name.string;
	req.in.group_name   = name;

	status = libnet_GroupInfo(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_GroupInfo call failed: %s\n", nt_errstr(status));
		ret = False;
		talloc_free(mem_ctx);
		goto done;
	}

	if (!test_cleanup(ctx->samr.pipe, mem_ctx, &ctx->samr.handle, TEST_GROUPNAME)) {
		printf("cleanup failed\n");
		ret = False;
		goto done;
	}

	if (!test_samr_close(ctx->samr.pipe, mem_ctx, &ctx->samr.handle)) {
		printf("domain close failed\n");
		ret = False;
	}

	talloc_free(ctx);

done:
	talloc_free(mem_ctx);
	return ret;
}
