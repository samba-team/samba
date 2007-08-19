/* 
   Unix SMB/CIFS implementation.
   Test suite for libnet calls.

   Copyright (C) Rafal Szczesniak 2007
   
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
#include "torture/rpc/rpc.h"
#include "libnet/libnet.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_samr_c.h"

#define TEST_GROUPNAME  "libnetgroupinfotest"


static BOOL test_opendomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *handle, struct lsa_String *domname,
			    struct dom_sid2 *sid)
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

	*sid = *r2.out.sid;
	return True;
}


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
		printf("OpenUser failed - %s\n", nt_errstr(status));
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


static BOOL test_create(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			struct policy_handle *handle, const char *name, uint32_t *rid)
{
	NTSTATUS status;
	struct lsa_String groupname;
	struct samr_CreateDomainGroup r;
	struct policy_handle group_handle;
	
	groupname.string = name;
	
	r.in.domain_handle  = handle;
	r.in.name           = &groupname;
	r.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.group_handle  = &group_handle;
	r.out.rid           = rid;

	printf("creating group account %s\n", name);

	status = dcerpc_samr_CreateDomainGroup(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateGroup failed - %s\n", nt_errstr(status));

		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			printf("Group (%s) already exists - attempting to delete and recreate account again\n", name);
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


static BOOL test_groupinfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			   struct policy_handle *domain_handle,
			   struct dom_sid2 *domain_sid, const char* group_name,
			   uint32_t *rid)
{
	const uint16_t level = 5;
	NTSTATUS status;
	struct libnet_rpc_groupinfo group;
	struct dom_sid *group_sid;
	
	group_sid = dom_sid_add_rid(mem_ctx, domain_sid, *rid);
	
	group.in.domain_handle = *domain_handle;
	group.in.sid           = dom_sid_string(mem_ctx, group_sid);
	group.in.level         = level;       /* this should be extended */

	printf("Testing sync libnet_rpc_groupinfo (SID argument)\n");
	status = libnet_rpc_groupinfo(p, mem_ctx, &group);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync libnet_rpc_userinfo - %s\n", nt_errstr(status));
		return False;
	}

	ZERO_STRUCT(group);

	group.in.domain_handle  = *domain_handle;
	group.in.sid            = NULL;
	group.in.groupname      = TEST_GROUPNAME;
	group.in.level          = level;

	printf("Testing sync libnet_rpc_groupinfo (groupname argument)\n");
	status = libnet_rpc_groupinfo(p, mem_ctx, &group);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync libnet_rpc_groupinfo - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


BOOL torture_groupinfo(struct torture_context *torture)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle h;
	struct lsa_String name;
	struct dom_sid2 sid;
	uint32_t rid;

	mem_ctx = talloc_init("test_userinfo");
	binding = torture_setting_string(torture, "binding", NULL);

	status = torture_rpc_connection(mem_ctx, 
					&p,
					&dcerpc_table_samr);
	
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	name.string = lp_workgroup();

	/*
	 * Testing synchronous version
	 */
	if (!test_opendomain(p, mem_ctx, &h, &name, &sid)) {
		ret = False;
		goto done;
	}

	if (!test_create(p, mem_ctx, &h, TEST_GROUPNAME, &rid)) {
		ret = False;
		goto done;
	}

	if (!test_groupinfo(p, mem_ctx, &h, &sid, TEST_GROUPNAME, &rid)) {
		ret = False;
		goto done;
	}

	if (!test_cleanup(p, mem_ctx, &h, TEST_GROUPNAME)) {
		ret = False;
		goto done;
	}

done:
	talloc_free(mem_ctx);

	return ret;
}
