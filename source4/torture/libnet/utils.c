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

/*
 * These are more general use functions shared among the tests.
 */

#include "includes.h"
#include "torture/rpc/torture_rpc.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "torture/libnet/utils.h"

bool test_opendomain(struct torture_context *tctx,
		     struct dcerpc_binding_handle *b, TALLOC_CTX *mem_ctx,
		     struct policy_handle *handle, struct lsa_String *domname,
		     struct dom_sid2 *sid_p)
{
	struct policy_handle h, domain_handle;
	struct samr_Connect r1;
	struct samr_LookupDomain r2;
	struct dom_sid2 *sid = NULL;
	struct samr_OpenDomain r3;

	torture_comment(tctx, "connecting\n");

	r1.in.system_name = 0;
	r1.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r1.out.connect_handle = &h;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_Connect_r(b, mem_ctx, &r1),
		"Connect failed");
	torture_assert_ntstatus_ok(tctx, r1.out.result,
		"Connect failed");

	r2.in.connect_handle = &h;
	r2.in.domain_name = domname;
	r2.out.sid = &sid;

	torture_comment(tctx, "domain lookup on %s\n", domname->string);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_LookupDomain_r(b, mem_ctx, &r2),
		"LookupDomain failed");
	torture_assert_ntstatus_ok(tctx, r2.out.result,
		"LookupDomain failed");

	r3.in.connect_handle = &h;
	r3.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r3.in.sid = *r2.out.sid;
	r3.out.domain_handle = &domain_handle;

	torture_comment(tctx, "opening domain\n");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_OpenDomain_r(b, mem_ctx, &r3),
		"OpenDomain failed");
	torture_assert_ntstatus_ok(tctx, r3.out.result,
		"OpenDomain failed");
	*handle = domain_handle;

	*sid_p = **r2.out.sid;
	return true;
}


bool test_user_cleanup(struct torture_context *tctx,
		       struct dcerpc_binding_handle *b,
		       TALLOC_CTX *mem_ctx, struct policy_handle *domain_handle,
		       const char *name)
{
	struct samr_LookupNames r1;
	struct samr_OpenUser r2;
	struct samr_DeleteUser r3;
	struct lsa_String names[2];
	uint32_t rid;
	struct policy_handle user_handle;
	struct samr_Ids rids, types;

	names[0].string = name;

	r1.in.domain_handle  = domain_handle;
	r1.in.num_names      = 1;
	r1.in.names          = names;
	r1.out.rids          = &rids;
	r1.out.types         = &types;

	torture_comment(tctx, "user account lookup '%s'\n", name);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_LookupNames_r(b, mem_ctx, &r1),
		"LookupNames failed");
	torture_assert_ntstatus_ok(tctx, r1.out.result,
		"LookupNames failed");

	rid = r1.out.rids->ids[0];

	r2.in.domain_handle  = domain_handle;
	r2.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r2.in.rid            = rid;
	r2.out.user_handle   = &user_handle;

	torture_comment(tctx, "opening user account\n");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_OpenUser_r(b, mem_ctx, &r2),
		"OpenUser failed");
	torture_assert_ntstatus_ok(tctx, r2.out.result,
		"OpenUser failed");

	r3.in.user_handle  = &user_handle;
	r3.out.user_handle = &user_handle;

	torture_comment(tctx, "deleting user account\n");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_DeleteUser_r(b, mem_ctx, &r3),
		"DeleteUser failed");
	torture_assert_ntstatus_ok(tctx, r3.out.result,
		"DeleteUser failed");

	return true;
}


bool test_user_create(struct torture_context *tctx,
		      struct dcerpc_binding_handle *b,
		      TALLOC_CTX *mem_ctx,
		      struct policy_handle *handle, const char *name,
		      uint32_t *rid)
{
	struct lsa_String username;
	struct samr_CreateUser r;
	struct policy_handle user_handle;

	username.string = name;

	r.in.domain_handle = handle;
	r.in.account_name  = &username;
	r.in.access_mask   = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.user_handle  = &user_handle;
	r.out.rid          = rid;

	torture_comment(tctx, "creating user account %s\n", name);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_CreateUser_r(b, mem_ctx, &r),
		"CreateUser failed");
	if (!NT_STATUS_IS_OK(r.out.result)) {
		printf("CreateUser failed - %s\n", nt_errstr(r.out.result));
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_USER_EXISTS)) {
			torture_comment(tctx, "User (%s) already exists - attempting to delete and recreate account again\n", name);
			if (!test_user_cleanup(tctx, b, mem_ctx, handle, name)) {
				return false;
			}

			torture_comment(tctx, "creating user account\n");

			torture_assert_ntstatus_ok(tctx,
				dcerpc_samr_CreateUser_r(b, mem_ctx, &r),
				"CreateUser failed");
			torture_assert_ntstatus_ok(tctx, r.out.result,
				"CreateUser failed");

			return true;
		}
		return false;
	}

	return true;
}


bool test_group_cleanup(struct torture_context *tctx,
			struct dcerpc_binding_handle *b, TALLOC_CTX *mem_ctx,
			struct policy_handle *domain_handle,
			const char *name)
{
	struct samr_LookupNames r1;
	struct samr_OpenGroup r2;
	struct samr_DeleteDomainGroup r3;
	struct lsa_String names[2];
	uint32_t rid;
	struct policy_handle group_handle;
	struct samr_Ids rids, types;

	names[0].string = name;

	r1.in.domain_handle  = domain_handle;
	r1.in.num_names      = 1;
	r1.in.names          = names;
	r1.out.rids          = &rids;
	r1.out.types         = &types;

	torture_comment(tctx, "group account lookup '%s'\n", name);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_LookupNames_r(b, mem_ctx, &r1),
		"LookupNames failed");
	torture_assert_ntstatus_ok(tctx, r1.out.result,
		"LookupNames failed");

	rid = r1.out.rids->ids[0];

	r2.in.domain_handle  = domain_handle;
	r2.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r2.in.rid            = rid;
	r2.out.group_handle  = &group_handle;

	torture_comment(tctx, "opening group account\n");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_OpenGroup_r(b, mem_ctx, &r2),
		"OpenGroup failed");
	torture_assert_ntstatus_ok(tctx, r2.out.result,
		"OpenGroup failed");

	r3.in.group_handle  = &group_handle;
	r3.out.group_handle = &group_handle;

	torture_comment(tctx, "deleting group account\n");

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_DeleteDomainGroup_r(b, mem_ctx, &r3),
		"DeleteGroup failed");
	torture_assert_ntstatus_ok(tctx, r3.out.result,
		"DeleteGroup failed");

	return true;
}


bool test_group_create(struct torture_context *tctx,
		       struct dcerpc_binding_handle *b, TALLOC_CTX *mem_ctx,
		       struct policy_handle *handle, const char *name,
		       uint32_t *rid)
{
	struct lsa_String groupname;
	struct samr_CreateDomainGroup r;
	struct policy_handle group_handle;

	groupname.string = name;

	r.in.domain_handle  = handle;
	r.in.name           = &groupname;
	r.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.group_handle  = &group_handle;
	r.out.rid           = rid;

	torture_comment(tctx, "creating group account %s\n", name);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_samr_CreateDomainGroup_r(b, mem_ctx, &r),
		"CreateGroup failed");
	if (!NT_STATUS_IS_OK(r.out.result)) {
		torture_comment(tctx, "CreateGroup failed - %s\n", nt_errstr(r.out.result));

		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_USER_EXISTS)) {
			torture_comment(tctx, "Group (%s) already exists - attempting to delete and recreate account again\n", name);
			if (!test_group_cleanup(tctx, b, mem_ctx, handle, name)) {
				return false;
			}

			torture_comment(tctx, "creating group account\n");

			torture_assert_ntstatus_ok(tctx,
				dcerpc_samr_CreateDomainGroup_r(b, mem_ctx, &r),
				"CreateGroup failed");
			torture_assert_ntstatus_ok(tctx, r.out.result,
				"CreateGroup failed");

			return true;
		}
		return false;
	}

	return true;
}

/**
 * Closes SAMR handle obtained from Connect, Open User/Domain, etc
 */
bool test_samr_close_handle(struct torture_context *tctx,
			    struct dcerpc_binding_handle *b,
			    TALLOC_CTX *mem_ctx,
			    struct policy_handle *samr_handle)
{
	struct samr_Close r;

	r.in.handle = samr_handle;
	r.out.handle = samr_handle;

	torture_assert_ntstatus_ok(tctx,
				   dcerpc_samr_Close_r(b, mem_ctx, &r),
				   "Close SAMR handle RPC call failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
				   "Close SAMR handle failed");

	return true;
}


void msg_handler(struct monitor_msg *m)
{
	struct msg_rpc_open_user *msg_open;
	struct msg_rpc_query_user *msg_query;
	struct msg_rpc_close_user *msg_close;
	struct msg_rpc_create_user *msg_create;

	switch (m->type) {
	case mon_SamrOpenUser:
		msg_open = (struct msg_rpc_open_user*)m->data;
		printf("monitor_msg: user opened (rid=%d, access_mask=0x%08x)\n",
		       msg_open->rid, msg_open->access_mask);
		break;
	case mon_SamrQueryUser:
		msg_query = (struct msg_rpc_query_user*)m->data;
		printf("monitor_msg: user queried (level=%d)\n", msg_query->level);
		break;
	case mon_SamrCloseUser:
		msg_close = (struct msg_rpc_close_user*)m->data;
		printf("monitor_msg: user closed (rid=%d)\n", msg_close->rid);
		break;
	case mon_SamrCreateUser:
		msg_create = (struct msg_rpc_create_user*)m->data;
		printf("monitor_msg: user created (rid=%d)\n", msg_create->rid);
		break;
	}
}
