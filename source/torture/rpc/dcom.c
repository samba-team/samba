/* 
   Unix SMB/CIFS implementation.
   test suite for dcom operations

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

BOOL torture_rpc_dcom(int dummy)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_dcom");

	status = torture_rpc_connection(&p, 
									DCERPC_IOXIDRESOLVER_NAME,
									DCERPC_IOXIDRESOLVER_UUID,
									DCERPC_IOXIDRESOLVER_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	printf("\n");

	talloc_destroy(mem_ctx);

	torture_rpc_close(p);
	return ret;
}
