/* 
   Unix SMB/CIFS implementation.

   local test for async resolve code

   Copyright (C) Andrew Tridgell 2004
   
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
#include "lib/events/events.h"
#include "libcli/resolve/resolve.h"
#include "torture/torture.h"
#include "torture/ui.h"

static BOOL test_async_resolve(struct torture_context *test, const void *_data)
{
	struct nbt_name n;
	struct event_context *ev;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	const char *host = lp_parm_string(-1, "torture", "host");
	int count = 0;
	struct timeval tv = timeval_current();

	ev = event_context_init(test);

	ZERO_STRUCT(n);
	n.name = host;

	torture_comment(test, "Testing async resolve of localhost for %d seconds",
					timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		const char *s;
		struct composite_context *c = resolve_name_host_send(&n, ev);
		torture_assert(test, c, "resolve_name_host_send");
		torture_assert_ntstatus_ok(test, resolve_name_host_recv(c, test, &s),
								   "async resolve failed");
		count++;
	}

	torture_comment(test, "async rate of %.1f resolves/sec", 
					count/timeval_elapsed(&tv));

	return True;
}

/*
  test resolution using sync method
*/
static BOOL test_sync_resolve(struct torture_context *test, const void *_data)
{
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	struct timeval tv = timeval_current();
	int count = 0;
	const char *host = lp_parm_string(-1, "torture", "host");

	torture_comment(test, "Testing sync resolve of localhost for %d seconds", 
				 timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		sys_inet_ntoa(interpret_addr2(host));
		count++;
	}
	
	torture_comment(test, "sync rate of %.1f resolves/sec", 
				 count/timeval_elapsed(&tv));

	return True;
}


BOOL torture_local_resolve(struct torture_context *torture) 
{
	struct torture_suite *suite = torture_suite_create(torture, 
													   "LOCAL-RESOLVE");

	torture_suite_add_simple_tcase(suite, "async", test_async_resolve, NULL);
	torture_suite_add_simple_tcase(suite, "sync", test_sync_resolve, NULL);

	return torture_run_suite(torture, suite);
}
