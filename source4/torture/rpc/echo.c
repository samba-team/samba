/* 
   Unix SMB/CIFS implementation.
   test suite for echo rpc operations

   Copyright (C) Andrew Tridgell 2003
   
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


/*
  test the AddOne interface
*/
static BOOL test_addone(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	int i;
	NTSTATUS status;

	printf("\nTesting AddOne\n");

	for (i=0;i<10;i++) {
		int n;
		status = dcerpc_rpcecho_addone(p, i, &n);
		if (!NT_STATUS_IS_OK(status)) {
			printf("AddOne(%d) failed - %s\n", i, nt_errstr(status));
			return False;
		}
		printf("%d + 1 = %d\n", i, n);
	}

	return True;
}

/*
  test the EchoData interface
*/
static BOOL test_echodata(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	int i;
	NTSTATUS status;
	char *data_in, *data_out;
	int len = 10;
	int len_out;

	printf("\nTesting EchoData\n");

	data_in = talloc(mem_ctx, len);
	for (i=0;i<len;i++) {
		data_in[i] = i+1;
	}

	status = dcerpc_rpcecho_echodata(p, mem_ctx,
					 len,
					 data_in,
					 &len_out,
					 &data_out);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EchoData(%d) failed\n", len);
		return False;
	}
	printf("EchoData(%d) returned %d bytes\n", len, len_out);

	if (memcmp(data_in, data_out, len) != 0) {
		printf("Bad data returned!\n");
		return False;
	}


	return True;
}

BOOL torture_rpc_echo(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_echo");

	status = torture_rpc_connection(&p, "rpcecho");
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if (!test_addone(p, mem_ctx)) {
		ret = False;
	}

	if (!test_echodata(p, mem_ctx)) {
		ret = False;
	}

	printf("\n");
	
        torture_rpc_close(p);
	return ret;
}
