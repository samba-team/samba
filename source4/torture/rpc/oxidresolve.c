/* 
   Unix SMB/CIFS implementation.
   test suite for oxidresolve operations

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

static int test_SimplePing(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct SimplePing r;
	NTSTATUS status;
	HYPER_T h = 10;

	r.in.SetId = &h;

	status = dcerpc_SimplePing(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "SimplePing: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "SimplePing: %s\n", win_errstr(r.out.result));
		return 0;
	}

	return 1;
}

static int test_ServerAlive(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct ServerAlive r;
	NTSTATUS status;

	status = dcerpc_ServerAlive(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "ServerAlive: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "ServerAlive: %s\n", win_errstr(r.out.result));
		return 0;
	}

	return 1;
}


static int test_ServerAlive2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct ServerAlive2 r;
	NTSTATUS status;

	status = dcerpc_ServerAlive2(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "ServerAlive2: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "ServerAlive2: %s\n", win_errstr(r.out.result));
		return 0;
	}

	return 1;
}

BOOL torture_rpc_oxidresolve(int dummy)
{
        NTSTATUS status;
       struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_oxidresolve");

	status = torture_rpc_connection(&p, 
					DCERPC_IOXIDRESOLVER_NAME, 
					DCERPC_IOXIDRESOLVER_UUID, 
					DCERPC_IOXIDRESOLVER_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if(!test_SimplePing(p, mem_ctx))
		ret = False;

	if(!test_ServerAlive(p, mem_ctx))
		ret = False;

	if(!test_ServerAlive2(p, mem_ctx))
		ret = False;

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
