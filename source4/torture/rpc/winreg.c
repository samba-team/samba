/* 
   Unix SMB/CIFS implementation.
   test suite for winreg rpc operations

   Copyright (C) Tim Potter 2003
   
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

static BOOL test_GetVersion(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_GetVersion r;

	printf("\ntesting GetVersion\n");

	r.in.handle = handle;

	status = dcerpc_winreg_GetVersion(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetVersion failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_CloseKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_CloseKey r;

	printf("\ntesting CloseKey\n");

	r.in.handle = r.out.handle = handle;

	status = dcerpc_winreg_CloseKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("CloseKey failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_OpenHKLM(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct winreg_OpenHKLM r;
	struct winreg_OpenHKLMUnknown unknown;
	struct policy_handle handle;
	BOOL ret = True;

	printf("\ntesting OpenHKLM\n");

	unknown.unknown0 = 0x84e0;
	unknown.unknown1 = 0x0000;
	r.in.unknown = &unknown;
	r.in.access_required = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = &handle;

	status = dcerpc_winreg_OpenHKLM(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenHKLM failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_GetVersion(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_CloseKey(p, mem_ctx, &handle)) {
		ret = False;
	}

	return ret;
}

BOOL torture_rpc_winreg(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_winreg");

	status = torture_rpc_connection(&p, 
					DCERPC_WINREG_NAME, 
					DCERPC_WINREG_UUID, 
					DCERPC_WINREG_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

	if (!test_OpenHKLM(p, mem_ctx)) {
		ret = False;
	}

        torture_rpc_close(p);

	return ret;
}
