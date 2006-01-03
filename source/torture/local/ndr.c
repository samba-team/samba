/* 
   Unix SMB/CIFS implementation.
   test suite for basic ndr functions

   Copyright (C) Jelmer Vernooij 2005
   
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

BOOL test_check_string_terminator(TALLOC_CTX *mem_ctx)
{
	struct ndr_pull *ndr;
	DATA_BLOB blob;

	/* Simple test */
	blob = strhex_to_data_blob("0000");
	
	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	if (NT_STATUS_IS_ERR(ndr_check_string_terminator(ndr, 1, 2))) {
		DEBUG(0, ("simple check_string_terminator test failed\n"));
		return False;
	}

	if (ndr->offset != 0) {
		DEBUG(0, ("check_string_terminator did not reset offset\n"));
		return False;
	}

	if (NT_STATUS_IS_OK(ndr_check_string_terminator(ndr, 1, 3))) {
		DEBUG(0, ("check_string_terminator checked beyond string boundaries\n"));
		return False;
	}

	if (ndr->offset != 0) {
		DEBUG(0, ("check_string_terminator did not reset offset\n"));
		return False;
	}

	talloc_free(ndr);

	blob = strhex_to_data_blob("11220000");
	ndr = ndr_pull_init_blob(&blob, mem_ctx);

	if (NT_STATUS_IS_ERR(ndr_check_string_terminator(ndr, 4, 1))) {
		DEBUG(0, ("check_string_terminator failed to recognize terminator\n"));
		return False;
	}

	if (NT_STATUS_IS_ERR(ndr_check_string_terminator(ndr, 3, 1))) {
		DEBUG(0, ("check_string_terminator failed to recognize terminator\n"));
		return False;
	}

	if (NT_STATUS_IS_OK(ndr_check_string_terminator(ndr, 2, 1))) {
		DEBUG(0, ("check_string_terminator erroneously reported terminator\n"));
		return False;
	}

	if (ndr->offset != 0) {
		DEBUG(0, ("check_string_terminator did not reset offset\n"));
		return False;
	}

	talloc_free(ndr);

	return True;
}

BOOL torture_local_ndr(void)
{
    NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_local_ndr");

	ret &= test_check_string_terminator(mem_ctx);

	talloc_free(mem_ctx);

	return ret;
}
