/* 
   Unix SMB/CIFS implementation.
   test suite for initshutdown operations

   Copyright (C) Tim Potter 2003
   Copyright (C) Jelmer Vernooij 2004-2005
   
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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_initshutdown_c.h"
#include "torture/rpc/rpc.h"

static void init_initshutdown_String(TALLOC_CTX *mem_ctx, struct initshutdown_String *name, const char *s)
{
	name->name = talloc(mem_ctx, struct initshutdown_String_sub);
	name->name->name = s;
}

static BOOL test_Init(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			const char *msg, uint32_t timeout)
{
	struct initshutdown_Init r;
	NTSTATUS status;
	uint16_t hostname = 0x0;
	
	r.in.hostname = &hostname;
	r.in.message = talloc(mem_ctx, struct initshutdown_String);
	init_initshutdown_String(mem_ctx, r.in.message, msg);
	r.in.force_apps = 1;
	r.in.timeout = timeout;
	r.in.reboot = 1;

	status = dcerpc_initshutdown_Init(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("initshutdown_Init failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("initshutdown_Init failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_InitEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			const char *msg, uint32_t timeout)
{
	struct initshutdown_InitEx r;
	NTSTATUS status;
	uint16_t hostname = 0x0;
	
	r.in.hostname = &hostname;
	r.in.message = talloc(mem_ctx, struct initshutdown_String);
	init_initshutdown_String(mem_ctx, r.in.message, msg);
	r.in.force_apps = 1;
	r.in.timeout = timeout;
	r.in.reboot = 1;
	r.in.reason = 0;

	status = dcerpc_initshutdown_InitEx(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("initshutdown_InitEx failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("initshutdown_InitEx failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_Abort(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct initshutdown_Abort r;
	NTSTATUS status;
	uint16_t server = 0x0;

	r.in.server = &server;
	
	status = dcerpc_initshutdown_Abort(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("initshutdown_Abort failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("initshutdown_Abort failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

BOOL torture_rpc_initshutdown(struct torture_context *torture)
{
    NTSTATUS status;
    struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_initshutdown");

	status = torture_rpc_connection(torture, &p, &ndr_table_initshutdown);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!torture_setting_bool(torture, "dangerous", False)) {
		printf("initshutdown tests disabled - enable dangerous tests to use\n");
	} else {
		ret &= test_Init(p, mem_ctx, "spottyfood", 30);
		ret &= test_Abort(p, mem_ctx);
		ret &= test_InitEx(p, mem_ctx, "spottyfood", 30);
		ret &= test_Abort(p, mem_ctx);
	}

	talloc_free(mem_ctx);

	return ret;
}
