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

static bool test_setup_server(struct torture_context *tctx)
{
	pid_t pid;
	TALLOC_CTX *mem_ctx = tctx;

	torture_assert_ntstatus_ok(tctx, torture_setup_server(mem_ctx, 
									"setupserver-success",
									"./script/tests/mktestsetup.sh",
									"./bin/smbd", &pid),
							   "starting smbd failed");

	torture_assert(tctx, pid > 0, "Pid invalid");

	torture_comment(tctx, "Created smbd with pid %d\n", pid);

	kill(pid, SIGINT);

	waitpid(pid, NULL, 0);

	torture_assert_ntstatus_equal(tctx, torture_setup_server(mem_ctx, 
									"setupserver-fail",
									"./invalid-script",
									"./bin/smbd", &pid), 
								  NT_STATUS_UNSUCCESSFUL,
							   "invalid script specified");

	torture_assert(tctx, pid == -1, "Pid not -1 after failure");
	return true;
}


struct torture_suite *torture_local_torture(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, 
													   "TORTURE");

	torture_suite_add_simple_test(suite, "tempdir", test_tempdir);
	torture_suite_add_simple_test(suite, "setup server", test_setup_server);

	return suite;
}
