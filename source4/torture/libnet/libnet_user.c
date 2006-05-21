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
#include "lib/cmdline/popt_common.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "torture/torture.h"
#include "torture/rpc/rpc.h"


#define TEST_USERNAME  "libnetusertest"


static BOOL test_cleanup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *domain_handle, const char *username)
{
	NTSTATUS status;
	struct samr_LookupNames r1;
	struct samr_OpenUser r2;
	struct samr_DeleteUser r3;
	struct samr_Close r4;
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

	r4.in.handle = domain_handle;
	r4.out.handle = domain_handle;

	status = dcerpc_samr_Close(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close failed - %s\n", nt_errstr(status));
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


static BOOL test_createuser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
 			    struct policy_handle *handle, const char* user)
{
	NTSTATUS status;
	struct policy_handle user_handle;
	struct lsa_String username;
	struct samr_CreateUser r1;
	struct samr_Close r2;
	uint32_t user_rid;

	username.string = user;
	
	r1.in.domain_handle = handle;
	r1.in.account_name = &username;
	r1.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r1.out.user_handle = &user_handle;
	r1.out.rid = &user_rid;

	printf("creating user '%s'\n", username.string);
	
	status = dcerpc_samr_CreateUser(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateUser failed - %s\n", nt_errstr(status));

		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			printf("User (%s) already exists - attempting to delete and recreate account again\n", user);
			if (!test_cleanup(p, mem_ctx, handle, TEST_USERNAME)) {
				return False;
			}

			printf("creating user account\n");
			
			status = dcerpc_samr_CreateUser(p, mem_ctx, &r1);
			if (!NT_STATUS_IS_OK(status)) {
				printf("CreateUser failed - %s\n", nt_errstr(status));
				return False;
			}
			return True;
		}		
		return False;
	}

	r2.in.handle = &user_handle;
	r2.out.handle = &user_handle;
	
	printf("closing user '%s'\n", username.string);

	status = dcerpc_samr_Close(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


BOOL torture_createuser(struct torture_context *torture)
{
	NTSTATUS status;
	const char *binding;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	struct libnet_CreateUser req;

	mem_ctx = talloc_init("test_createuser");
	binding = lp_parm_string(-1, "torture", "binding");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	req.in.user_name = TEST_USERNAME;
	req.in.domain_name = lp_workgroup();
	req.out.error_string = NULL;

	status = libnet_CreateUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_CreateUser call failed: %s\n", nt_errstr(status));
		return False;
	}

	if (!test_cleanup(ctx->samr_pipe, mem_ctx, &ctx->domain.handle, TEST_USERNAME)) {
		printf("cleanup failed\n");
		return False;
	}

	return True;
}


BOOL torture_deleteuser(struct torture_context *torture)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_pipe *p;
	TALLOC_CTX *prep_mem_ctx, *mem_ctx;
	struct policy_handle h;
	struct lsa_String domain_name;
	const char *name = TEST_USERNAME;
	struct libnet_context *ctx;
	struct libnet_DeleteUser req;
	BOOL ret = True;

	prep_mem_ctx = talloc_init("prepare test_deleteuser");
	binding = lp_parm_string(-1, "torture", "binding");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	req.in.user_name = TEST_USERNAME;
	req.in.domain_name = lp_workgroup();

	status = torture_rpc_connection(prep_mem_ctx,
					&p,
					&dcerpc_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	domain_name.string = lp_workgroup();
	if (!test_opendomain(p, prep_mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_createuser(p, prep_mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	mem_ctx = talloc_init("test_deleteuser");

	status = libnet_DeleteUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_DeleteUser call failed: %s\n", nt_errstr(status));
		return False;
	}

done:
	talloc_free(prep_mem_ctx);
	talloc_free(mem_ctx);
	return ret;
}
