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

static BOOL test_tempdir(struct torture_context *torture, 
							   const void *_data)
{
	char *location = NULL;
	
	torture_assert_ntstatus_ok(torture, torture_temp_dir(torture, "tempdir", &location), 
								"torture_temp_dir should return NT_STATUS_OK" );

	torture_assert(torture, directory_exist(location), 
				   "created dir doesn't exist");

	return True;
}

static BOOL test_setup_server(struct torture_context *torture, 
							   const void *_data)
{
	pid_t pid;

	torture_assert_ntstatus_ok(torture, torture_setup_server(torture, 
									"setupserver-success",
									"./script/tests/mktestsetup.sh",
									"./bin/smbd", &pid),
							   "starting smbd failed");

	torture_assert(torture, pid > 0, "Pid invalid");

	torture_comment(torture, "Created smbd with pid %d", pid);

	kill(pid, SIGINT);

	waitpid(pid, NULL, 0);

	torture_assert_ntstatus_equal(torture, torture_setup_server(torture, 
									"setupserver-fail",
									"./invalid-script",
									"./bin/smbd", &pid), 
								  NT_STATUS_UNSUCCESSFUL,
							   "invalid script specified");

	torture_assert(torture, pid == -1, "Pid not -1 after failure");

	return True;
}

struct torture_suite *torture_local_torture(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, 
													   "LOCAL-TORTURE");

	torture_suite_add_simple_tcase(suite, "tempdir", test_tempdir, NULL);
	torture_suite_add_simple_tcase(suite, "setup server", test_setup_server, NULL);

	return suite;
}
