/* 
   Unix SMB/CIFS implementation.
   test suite for eventlog rpc operations

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

BOOL test_CloseEventLog(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			struct policy_handle *handle)
{
	NTSTATUS status;
	struct eventlog_CloseEventLog r;

	r.in.handle = r.out.handle = handle;

	printf("Testing CloseEventLog\n");

	status = dcerpc_eventlog_CloseEventLog(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CloseEventLog failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_OpenEventLog(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct eventlog_OpenEventLog r;
	struct policy_handle handle;

	printf("\ntesting OpenEventLog\n");

	r.in.servername = dcerpc_server_name(p);
	r.out.handle = &handle;

	status = dcerpc_eventlog_OpenEventLog(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenEventLog failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_CloseEventLog(p, mem_ctx, &handle))
		return False;

	return True;
}

BOOL torture_rpc_eventlog(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_atsvc");

	status = torture_rpc_connection(&p, 
					DCERPC_ATSVC_NAME, 
					DCERPC_ATSVC_UUID, 
					DCERPC_ATSVC_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

	if (!test_OpenEventLog(p, mem_ctx)) {
		return False;
	}

        torture_rpc_close(p);

	return ret;
}
