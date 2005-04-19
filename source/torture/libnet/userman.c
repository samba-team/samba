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
#include "librpc/gen_ndr/ndr_samr.h"
#include "libnet/composite.h"

#define TEST_USERNAME  "libnetuserinfotest"


static BOOL test_opendomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *handle, struct samr_String *domname)
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


static BOOL test_useradd(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *domain_handle,
			 const char *name)
{
	NTSTATUS status;
	BOOL ret = True;
	struct rpc_composite_useradd user;
	
	user.in.domain_handle = *domain_handle;
	user.in.username      = name;

	status = rpc_composite_useradd(p, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync rpc_composite_userinfo - %s\n", nt_errstr(status));
		return False;
	}
	
	return ret;
}


BOOL torture_useradd(void)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_pipe *p;
	struct dcerpc_binding *b;
	struct policy_handle h;
	struct samr_String domain_name;
	char* name = TEST_USERNAME;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("test_useradd");
	binding = lp_parm_string(-1, "torture", "binding");

	status = torture_rpc_connection(mem_ctx, 
					&p,
					DCERPC_SAMR_NAME,
					DCERPC_SAMR_UUID,
					DCERPC_SAMR_VERSION);
	
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("failed to parse dcerpc binding '%s'\n", binding);
		talloc_free(mem_ctx);
		ret = False;
		goto done;
	}

	domain_name.string = lp_workgroup();
	if (!test_opendomain(p, mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_useradd(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

done:
	talloc_free(mem_ctx);
	return ret;
}
