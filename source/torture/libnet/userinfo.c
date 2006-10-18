/* 
   Unix SMB/CIFS implementation.
   Test suite for libnet calls.

   Copyright (C) Rafal Szczesniak 2005
   
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
#include "torture/rpc/rpc.h"
#include "libnet/libnet.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_samr_c.h"

#define TEST_USERNAME  "libnetuserinfotest"

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
			 struct policy_handle *domain_handle, const char *username)
{
	NTSTATUS status;
	struct samr_LookupNames r1;
	struct samr_OpenUser r2;
	struct samr_DeleteUser r3;
	struct lsa_String names[2];
	uint32_t rid;
	struct policy_handle user_handle;

	names[0].string = username;

	r1.in.domain_handle  = domain_handle;
	r1.in.num_names      = 1;
	r1.in.names          = names;
	
	printf("user account lookup '%s'\n", username);

	status = dcerpc_samr_LookupNames(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return False;
	}

	rid = r1.out.rids.ids[0];
	
	r2.in.domain_handle  = domain_handle;
	r2.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r2.in.rid            = rid;
	r2.out.user_handle   = &user_handle;

	printf("opening user account\n");

	status = dcerpc_samr_OpenUser(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenUser failed - %s\n", nt_errstr(status));
		return False;
	}

	r3.in.user_handle  = &user_handle;
	r3.out.user_handle = &user_handle;

	printf("deleting user account\n");
	
	status = dcerpc_samr_DeleteUser(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteUser failed - %s\n", nt_errstr(status));
		return False;
	}
	
	return True;
}


static BOOL test_create(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			struct policy_handle *handle, const char *name, uint32_t *rid)
{
	NTSTATUS status;
	struct lsa_String username;
	struct samr_CreateUser r;
	struct policy_handle user_handle;
	
	username.string = name;
	
	r.in.domain_handle = handle;
	r.in.account_name  = &username;
	r.in.access_mask   = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.user_handle  = &user_handle;
	r.out.rid          = rid;

	printf("creating user account %s\n", name);

	status = dcerpc_samr_CreateUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateUser failed - %s\n", nt_errstr(status));

		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			printf("User (%s) already exists - attempting to delete and recreate account again\n", name);
			if (!test_cleanup(p, mem_ctx, handle, TEST_USERNAME)) {
				return False;
			}

			printf("creating user account\n");
			
			status = dcerpc_samr_CreateUser(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status)) {
				printf("CreateUser failed - %s\n", nt_errstr(status));
				return False;
			}
			return True;
		}
		return False;
	}

	return True;
}


static BOOL test_userinfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct policy_handle *domain_handle,
			  struct dom_sid2 *domain_sid, const char* user_name,
			  uint32_t *rid)
{
	const uint16_t level = 5;
	NTSTATUS status;
	struct libnet_rpc_userinfo user;
	struct dom_sid *user_sid;
	
	user_sid = dom_sid_add_rid(mem_ctx, domain_sid, *rid);
	
	user.in.domain_handle = *domain_handle;
	user.in.sid           = dom_sid_string(mem_ctx, user_sid);
	user.in.level         = level;       /* this should be extended */

	printf("Testing sync libnet_rpc_userinfo (SID argument)\n");
	status = libnet_rpc_userinfo(p, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync libnet_rpc_userinfo - %s\n", nt_errstr(status));
		return False;
	}

	ZERO_STRUCT(user);

	user.in.domain_handle = *domain_handle;
	user.in.sid           = NULL;
	user.in.username      = TEST_USERNAME;
	user.in.level         = level;

	printf("Testing sync libnet_rpc_userinfo (username argument)\n");
	status = libnet_rpc_userinfo(p, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync libnet_rpc_userinfo - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static void msg_handler(struct monitor_msg *m)
{
	struct msg_rpc_open_user *msg_open;
	struct msg_rpc_query_user *msg_query;
	struct msg_rpc_close_user *msg_close;

	switch (m->type) {
	case rpc_open_user:
		msg_open = (struct msg_rpc_open_user*)m->data;
		printf("monitor_msg: user opened (rid=%d, access_mask=0x%08x)\n",
		       msg_open->rid, msg_open->access_mask);
		break;
	case rpc_query_user:
		msg_query = (struct msg_rpc_query_user*)m->data;
		printf("monitor_msg: user queried (level=%d)\n", msg_query->level);
		break;
	case rpc_close_user:
		msg_close = (struct msg_rpc_close_user*)m->data;
		printf("monitor_msg: user closed (rid=%d)\n", msg_close->rid);
		break;
	}
}


static BOOL test_userinfo_async(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				struct policy_handle *domain_handle,
				struct dom_sid2 *domain_sid, const char* user_name,
				uint32_t *rid)
{
	const uint16_t level = 10;
	NTSTATUS status;
	struct composite_context *c;
	struct libnet_rpc_userinfo user;
	struct dom_sid *user_sid;

	user_sid = dom_sid_add_rid(mem_ctx, domain_sid, *rid);

	user.in.domain_handle = *domain_handle;
	user.in.sid           = dom_sid_string(mem_ctx, user_sid);
	user.in.level         = level;       /* this should be extended */

	printf("Testing async libnet_rpc_userinfo (SID argument)\n");

	c = libnet_rpc_userinfo_send(p, &user, msg_handler);
	if (!c) {
		printf("Failed to call sync libnet_rpc_userinfo_send\n");
		return False;
	}

	status = libnet_rpc_userinfo_recv(c, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Calling async libnet_rpc_userinfo failed - %s\n", nt_errstr(status));
		return False;
	}

	ZERO_STRUCT(user);

	user.in.domain_handle = *domain_handle;
	user.in.sid           = NULL;
	user.in.username      = TEST_USERNAME;
	user.in.level         = level;

	printf("Testing async libnet_rpc_userinfo (username argument)\n");

	c = libnet_rpc_userinfo_send(p, &user, msg_handler);
	if (!c) {
		printf("Failed to call sync libnet_rpc_userinfo_send\n");
		return False;
	}

	status = libnet_rpc_userinfo_recv(c, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Calling async libnet_rpc_userinfo failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


BOOL torture_userinfo(struct torture_context *torture)
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

	if (!test_create(p, mem_ctx, &h, TEST_USERNAME, &rid)) {
		ret = False;
		goto done;
	}

	if (!test_userinfo(p, mem_ctx, &h, &sid, TEST_USERNAME, &rid)) {
		ret = False;
		goto done;
	}

	if (!test_cleanup(p, mem_ctx, &h, TEST_USERNAME)) {
		ret = False;
		goto done;
	}

	/*
	 * Testing asynchronous version and monitor messages
	 */
	if (!test_opendomain(p, mem_ctx, &h, &name, &sid)) {
		ret = False;
		goto done;
	}

	if (!test_create(p, mem_ctx, &h, TEST_USERNAME, &rid)) {
		ret = False;
		goto done;
	}

	if (!test_userinfo_async(p, mem_ctx, &h, &sid, TEST_USERNAME, &rid)) {
		ret = False;
		goto done;
	}

	if (!test_cleanup(p, mem_ctx, &h, TEST_USERNAME)) {
		ret = False;
		goto done;
	}

done:
	talloc_free(mem_ctx);

	return ret;
}
