/* 
   Unix SMB/CIFS implementation.
   test suite for eventlog rpc operations

   Copyright (C) Tim Potter 2003,2005
   Copyright (C) Jelmer Vernooij 2004
   
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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_eventlog.h"
#include "librpc/gen_ndr/ndr_eventlog_c.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "torture/rpc/rpc.h"

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
	name->length = 2*strlen_m(s);
	name->size = name->length;
}

static BOOL test_GetNumRecords(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct eventlog_GetNumRecords r;

	printf("\ntesting GetNumRecords\n");

	r.in.handle = handle;

	status = dcerpc_eventlog_GetNumRecords(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetNumRecords failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("%d records\n", r.out.number);

	return True;
}

static BOOL test_ReadEventLog(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct eventlog_ReadEventLogW r;

	printf("\ntesting ReadEventLog\n");

	r.in.offset = 0;
	r.in.handle = handle;
	r.in.flags = EVENTLOG_BACKWARDS_READ|EVENTLOG_SEQUENTIAL_READ;

	while (1) {
		DATA_BLOB blob;
		struct eventlog_Record rec;
		struct ndr_pull *ndr;

		/* Read first for number of bytes in record */

		r.in.number_of_bytes = 0;
		r.out.data = NULL;

		status = dcerpc_eventlog_ReadEventLogW(p, mem_ctx, &r);

		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_END_OF_FILE)) {
			break;
		}

		if (!NT_STATUS_EQUAL(r.out.result, NT_STATUS_BUFFER_TOO_SMALL)) {
			printf("ReadEventLog failed - %s\n", nt_errstr(r.out.result));
			return False;
		}
		
		/* Now read the actual record */

		r.in.number_of_bytes = r.out.real_size;
		r.out.data = talloc_size(mem_ctx, r.in.number_of_bytes);

		status = dcerpc_eventlog_ReadEventLogW(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status)) {
			printf("ReadEventLog failed - %s\n", nt_errstr(status));
			return False;
		}
		
		/* Decode a user-marshalled record */

		blob.length = r.out.sent_size;
		blob.data = talloc_steal(mem_ctx, r.out.data);

		ndr = ndr_pull_init_blob(&blob, mem_ctx);

		status = ndr_pull_eventlog_Record(
			ndr, NDR_SCALARS|NDR_BUFFERS, &rec);

		NDR_PRINT_DEBUG(eventlog_Record, &rec);

		if (!NT_STATUS_IS_OK(status)) {
			printf("ReadEventLog failed parsing event log record "
			       "- %s\n", nt_errstr(status));
			return False;
		}

		r.in.offset++;
	}

	return True;
}

static BOOL test_CloseEventLog(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
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

static BOOL test_FlushEventLog(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct eventlog_FlushEventLog r;

	r.in.handle = handle;

	printf("Testing FlushEventLog\n");

	status = dcerpc_eventlog_FlushEventLog(p, mem_ctx, &r);

	/* Huh?  Does this RPC always return access denied? */

	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		printf("FlushEventLog failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_ClearEventLog(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct eventlog_ClearEventLogW r;

	r.in.handle = handle;
	r.in.unknown = NULL;

	printf("Testing ClearEventLog\n");

	status = dcerpc_eventlog_ClearEventLogW(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("ClearEventLog failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_OpenEventLog(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct eventlog_OpenEventLogW r;
	struct eventlog_OpenUnknown0 unknown0;

	printf("\ntesting OpenEventLog\n");

	unknown0.unknown0 = 0x005c;
	unknown0.unknown1 = 0x0001;

	r.in.unknown0 = &unknown0;
	init_lsa_String(&r.in.logname, "dns server");
	init_lsa_String(&r.in.servername, NULL);
	r.in.unknown2 = 0x00000001;
	r.in.unknown3 = 0x00000001;
	r.out.handle = handle;

	status = dcerpc_eventlog_OpenEventLogW(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenEventLog failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!NT_STATUS_IS_OK(r.out.result)) {
		printf("OpenEventLog failed - %s\n", nt_errstr(r.out.result));
		return False;
	}

	return True;
}

BOOL torture_rpc_eventlog(void)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	struct policy_handle handle;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_atsvc");

	status = torture_rpc_connection(mem_ctx, &p, &dcerpc_table_eventlog);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!test_OpenEventLog(p, mem_ctx, &handle)) {
		talloc_free(mem_ctx);
		return False;
	}

#if 0
	ret &= test_ClearEventLog(p, mem_ctx, &handle); /* Destructive test */
#endif
	
	ret &= test_GetNumRecords(p, mem_ctx, &handle);

	ret &= test_ReadEventLog(p, mem_ctx, &handle);

	ret &= test_FlushEventLog(p, mem_ctx, &handle);

	ret &= test_CloseEventLog(p, mem_ctx, &handle);

	talloc_free(mem_ctx);

	return ret;
}
