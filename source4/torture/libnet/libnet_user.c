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


BOOL torture_createuser(void)
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

	status = libnet_CreateUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_CreateUser call failed: %s\n", nt_errstr(status));
		return False;
	}

	if (!test_cleanup(ctx->pipe, mem_ctx, &ctx->domain_handle, TEST_USERNAME)) {
		printf("cleanup failed\n");
		return False;
	}

	return True;
}
