/* 
   Unix SMB/CIFS implementation.
   test suite for dcom operations

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "torture/rpc/rpc.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"

BOOL torture_rpc_dcom(void)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_dcom");

	status = torture_rpc_connection(mem_ctx, &p, &ndr_table_IOXIDResolver);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}

	printf("\n");

	talloc_free(mem_ctx);
	return ret;
}
