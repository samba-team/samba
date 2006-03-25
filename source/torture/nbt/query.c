/* 
   Unix SMB/CIFS implementation.

   NBT name query testing

   Copyright (C) Andrew Tridgell 2005
   
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

struct result_struct {
	int num_pass;
	int num_fail;
};

static void increment_handler(struct nbt_name_request *req)
{
	struct result_struct *v = talloc_get_type(req->async.private, struct result_struct);
	if (req->state != NBT_REQUEST_DONE) {
		v->num_fail++;
	} else {
		v->num_pass++;
	}
	talloc_free(req);
}

/*
  benchmark simple name queries
*/
static BOOL bench_namequery(TALLOC_CTX *mem_ctx, struct nbt_name *name, const char *address)
{
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(mem_ctx, NULL);
	int num_sent=0;
	struct result_struct *result;
	struct nbt_name_query io;
	struct timeval tv = timeval_current();
	BOOL ret = True;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);

	io.in.name = *name;
	io.in.dest_addr = address;
	io.in.broadcast = False;
	io.in.wins_lookup = False;
	io.in.timeout = 1;

	result = talloc_zero(mem_ctx, struct result_struct);

	printf("Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		while (num_sent - (result->num_pass+result->num_fail) < 10) {
			struct nbt_name_request *req;
			req = nbt_name_query_send(nbtsock, &io);
			if (req == NULL) {
				printf("Failed to setup request!\n");
				ret = False;
				goto failed;
			}
			req->async.fn = increment_handler;
			req->async.private = result;
			num_sent++;
			if (num_sent % 1000 == 0) {
				printf("%.1f queries per second (%d failures)  \r", 
				       result->num_pass / timeval_elapsed(&tv),
				       result->num_fail);
			}
		}

		event_loop_once(nbtsock->event_ctx);
	}

	while (num_sent != (result->num_pass + result->num_fail)) {
		event_loop_once(nbtsock->event_ctx);
	}

	printf("%.1f queries per second (%d failures)  \n", 
	       result->num_pass / timeval_elapsed(&tv),
	       result->num_fail);

failed:
	talloc_free(nbtsock);
	return ret;
}


/*
  benchmark how fast a server can respond to name queries
*/
BOOL torture_bench_nbt(struct torture_context *torture)
{
	const char *address;
	struct nbt_name name;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	NTSTATUS status;
	BOOL ret = True;
	
	make_nbt_name_server(&name, lp_parm_string(-1, "torture", "host"));

	/* do an initial name resolution to find its IP */
	status = resolve_name(&name, mem_ctx, &address, event_context_find(mem_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to resolve %s - %s\n",
		       name.name, nt_errstr(status));
		talloc_free(mem_ctx);
		return False;
	}

	ret &= bench_namequery(mem_ctx, &name, address);

	talloc_free(mem_ctx);

	return ret;
}
