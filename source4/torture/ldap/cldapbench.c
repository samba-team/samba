/* 
   Unix SMB/CIFS implementation.

   CLDAP benchmark test

   Copyright (C) Andrew Tridgell 2005
   
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
#include "lib/events/events.h"
#include "libcli/cldap/cldap.h"
#include "libcli/resolve/resolve.h"
#include "torture/torture.h"

struct bench_state {
	int pass_count, fail_count;
};

static void request_handler(struct cldap_request *req)
{
	struct cldap_netlogon io;
	struct bench_state *state = talloc_get_type(req->async.private, struct bench_state);
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	io.in.version = 6;
	status = cldap_netlogon_recv(req, tmp_ctx, &io);
	if (NT_STATUS_IS_OK(status)) {
		state->pass_count++;
	} else {
		state->fail_count++;
	}
	talloc_free(tmp_ctx);
}

/*
  benchmark cldap calls
*/
static BOOL bench_cldap(TALLOC_CTX *mem_ctx, const char *address)
{
	struct cldap_socket *cldap = cldap_socket_init(mem_ctx, NULL);
	int num_sent=0;
	struct timeval tv = timeval_current();
	BOOL ret = True;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	struct cldap_netlogon search;
	struct bench_state *state;

	state = talloc_zero(mem_ctx, struct bench_state);

	ZERO_STRUCT(search);
	search.in.dest_address = address;
	search.in.acct_control = -1;
	search.in.version = 6;

	printf("Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		while (num_sent - (state->pass_count+state->fail_count) < 10) {
			struct cldap_request *req;
			req = cldap_netlogon_send(cldap, &search);

			req->async.private = state;
			req->async.fn = request_handler;
			num_sent++;
			if (num_sent % 50 == 0) {
				if (lp_parm_bool(-1, "torture", "progress", true)) {
					printf("%.1f queries per second (%d failures)  \r", 
					       state->pass_count / timeval_elapsed(&tv),
					       state->fail_count);
					fflush(stdout);
				}
			}
		}

		event_loop_once(cldap->event_ctx);
	}

	while (num_sent != (state->pass_count + state->fail_count)) {
		event_loop_once(cldap->event_ctx);
	}

	printf("%.1f queries per second (%d failures)  \n", 
	       state->pass_count / timeval_elapsed(&tv),
	       state->fail_count);

	talloc_free(cldap);
	return ret;
}


/*
  benchmark how fast a CLDAP server can respond to a series of parallel
  requests 
*/
BOOL torture_bench_cldap(struct torture_context *torture)
{
	const char *address;
	struct nbt_name name;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	NTSTATUS status;
	BOOL ret = True;
	
	make_nbt_name_server(&name, torture_setting_string(torture, "host", NULL));

	/* do an initial name resolution to find its IP */
	status = resolve_name(&name, mem_ctx, &address, event_context_find(mem_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to resolve %s - %s\n",
		       name.name, nt_errstr(status));
		talloc_free(mem_ctx);
		return False;
	}

	ret &= bench_cldap(mem_ctx, address);

	talloc_free(mem_ctx);

	return ret;
}
