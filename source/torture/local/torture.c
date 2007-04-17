/* 
   Unix SMB/CIFS implementation.

   local testing of torture

   Copyright (C) Jelmer Vernooij 2006
   
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
#include "system/wait.h"
#include "lib/events/events.h"
#include "libcli/raw/libcliraw.h"
#include "torture/util.h"

static bool test_tempdir(struct torture_context *tctx)
{
	char *location = NULL;
	TALLOC_CTX *mem_ctx = tctx;
	
	torture_assert_ntstatus_ok(tctx, torture_temp_dir(mem_ctx, "tempdir", &location), 
								"torture_temp_dir should return NT_STATUS_OK" );

	torture_assert(tctx, directory_exist(location), 
				   "created dir doesn't exist");
	return true;
}

struct torture_suite *torture_local_torture(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, 
													   "TORTURE");

	torture_suite_add_simple_test(suite, "tempdir", test_tempdir);

	return suite;
}
