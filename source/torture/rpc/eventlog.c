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

static void init_eventlog_String(struct eventlog_String *name, const char *s)
{
	name->name = s;
	name->name_len = 2*strlen_m(s);
	name->name_size = name->name_len;
}

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
	struct eventlog_OpenUnknown0 unknown0;
	struct policy_handle handle;

	printf("\ntesting OpenEventLog\n");

	unknown0.unknown0 = 0x005c;
	unknown0.unknown1 = 0x0001;

	r.in.unknown0 = &unknown0;
	init_eventlog_String(&r.in.source, "system");
	init_eventlog_String(&r.in.unknown1, NULL);
	r.in.unknown2 = 0x00000001;
	r.in.unknown3 = 0x00000001;

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
					DCERPC_EVENTLOG_NAME, 
					DCERPC_EVENTLOG_UUID, 
					DCERPC_EVENTLOG_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

	if (!test_OpenEventLog(p, mem_ctx)) {
		return False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
