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

static BOOL test_async_resolve(TALLOC_CTX *mem_ctx)
{
	struct nbt_name n;
	struct event_context *ev = event_context_find(mem_ctx);
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	const char *host = lp_parm_string(-1, "torture", "host");
	int count = 0;
	struct timeval tv = timeval_current();

	ZERO_STRUCT(n);
	n.name = host;

	printf("Testing async resolve of localhost for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		const char *s;
		struct composite_context *c = resolve_name_host_send(&n, ev);
		NTSTATUS status = resolve_name_host_recv(c, mem_ctx, &s);
		if (!NT_STATUS_IS_OK(status)) {
			printf("async resolve failed - %s\n", nt_errstr(status));
			return False;
		}
		count++;
	}

	printf("async rate of %.1f resolves/sec\n", count/timeval_elapsed(&tv));
	return True;
}

/*
  test resolution using sync method
*/
static BOOL test_sync_resolve(TALLOC_CTX *mem_ctx)
{
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	struct timeval tv = timeval_current();
	int count = 0;
	const char *host = lp_parm_string(-1, "torture", "host");

	printf("Testing sync resolve of localhost for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		sys_inet_ntoa(interpret_addr2(host));
		count++;
	}
	
	printf("sync rate of %.1f resolves/sec\n", count/timeval_elapsed(&tv));
	return True;
}


BOOL torture_local_resolve(void) 
{
	TALLOC_CTX *mem_ctx = talloc_init("torture_local_irpc");
	BOOL ret = True;

	ret &= test_sync_resolve(mem_ctx);
	ret &= test_async_resolve(mem_ctx);

	talloc_free(mem_ctx);

	return ret;
}
