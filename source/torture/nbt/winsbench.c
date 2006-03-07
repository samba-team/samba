/* 
   Unix SMB/CIFS implementation.

   WINS benchmark test

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
#include "lib/socket/socket.h"
#include "libcli/resolve/resolve.h"
#include "system/network.h"
#include "netif/netif.h"

struct wins_state {
	int num_names;
	BOOL *registered;
	int pass_count;
	int fail_count;
	const char *wins_server;
	const char *my_ip;
	uint32_t ttl;
};

struct idx_state {
	int idx;
	struct wins_state *state;
};

struct nbt_name generate_name(TALLOC_CTX *mem_ctx, int idx)
{
	struct nbt_name name;
	name.name       = talloc_asprintf(mem_ctx, "WINSBench%6u", idx);
	name.type       = 0x4;
	name.scope      = NULL;
	return name;
}

static void register_handler(struct nbt_name_request *req)
{
	struct idx_state *istate = talloc_get_type(req->async.private, struct idx_state);
	struct wins_state *state = istate->state;
	struct nbt_name_register io;
	NTSTATUS status;

	status = nbt_name_register_recv(req, istate, &io);
	if (!NT_STATUS_IS_OK(status) || io.out.rcode != NBT_RCODE_OK) {
		state->fail_count++;
	} else {
		state->pass_count++;
		state->registered[istate->idx] = True;
	}
	talloc_free(istate);	
}

/*
  generate a registration
*/
static void generate_register(struct nbt_name_socket *nbtsock, struct wins_state *state, int idx)
{
	struct nbt_name_register io;
	TALLOC_CTX *tmp_ctx = talloc_new(state);
	struct nbt_name_request *req;
	struct idx_state *istate;

	istate = talloc(nbtsock, struct idx_state);
	istate->idx = idx;
	istate->state = state;

	io.in.name            = generate_name(tmp_ctx, idx);
	io.in.dest_addr       = state->wins_server;
	io.in.address         = state->my_ip;
	io.in.nb_flags        = NBT_NODE_H;
	io.in.register_demand = False;
	io.in.broadcast       = False;
	io.in.multi_homed     = False;
	io.in.ttl             = state->ttl;
	io.in.timeout         = 2;
	io.in.retries         = 1;

	req = nbt_name_register_send(nbtsock, &io);

	req->async.fn = register_handler;
	req->async.private = istate;

	talloc_free(tmp_ctx);
}


static void release_handler(struct nbt_name_request *req)
{
	struct idx_state *istate = talloc_get_type(req->async.private, struct idx_state);
	struct wins_state *state = istate->state;
	struct nbt_name_release io;
	NTSTATUS status;

	status = nbt_name_release_recv(req, istate, &io);
	if (state->registered[istate->idx] && 
	    (!NT_STATUS_IS_OK(status) || io.out.rcode != NBT_RCODE_OK)) {
		state->fail_count++;
	} else {
		state->pass_count++;
		state->registered[istate->idx] = False;
	}
	talloc_free(istate);	
}

/*
  generate a name release
*/
static void generate_release(struct nbt_name_socket *nbtsock, struct wins_state *state, int idx)
{
	struct nbt_name_release io;
	TALLOC_CTX *tmp_ctx = talloc_new(state);
	struct nbt_name_request *req;
	struct idx_state *istate;

	istate = talloc(nbtsock, struct idx_state);
	istate->idx = idx;
	istate->state = state;

	io.in.name            = generate_name(tmp_ctx, idx);
	io.in.dest_addr       = state->wins_server;
	io.in.address         = state->my_ip;
	io.in.nb_flags        = NBT_NODE_H;
	io.in.broadcast       = False;
	io.in.timeout         = 2;
	io.in.retries         = 1;

	req = nbt_name_release_send(nbtsock, &io);

	req->async.fn = release_handler;
	req->async.private = istate;

	talloc_free(tmp_ctx);
}


static void query_handler(struct nbt_name_request *req)
{
	struct idx_state *istate = talloc_get_type(req->async.private, struct idx_state);
	struct wins_state *state = istate->state;
	struct nbt_name_query io;
	NTSTATUS status;

	status = nbt_name_query_recv(req, istate, &io);
	if (!NT_STATUS_IS_OK(status) && state->registered[istate->idx]) {
		state->fail_count++;
	} else {
		state->pass_count++;
	}
	talloc_free(istate);	
}

/*
  generate a name query
*/
static void generate_query(struct nbt_name_socket *nbtsock, struct wins_state *state, int idx)
{
	struct nbt_name_query io;
	TALLOC_CTX *tmp_ctx = talloc_new(state);
	struct nbt_name_request *req;
	struct idx_state *istate;

	istate = talloc(nbtsock, struct idx_state);
	istate->idx = idx;
	istate->state = state;

	io.in.name            = generate_name(tmp_ctx, idx);
	io.in.dest_addr       = state->wins_server;
	io.in.broadcast       = False;
	io.in.wins_lookup     = True;
	io.in.timeout         = 2;
	io.in.retries         = 1;

	req = nbt_name_query_send(nbtsock, &io);

	req->async.fn = query_handler;
	req->async.private = istate;

	talloc_free(tmp_ctx);
}

/*
  generate one WINS request
*/
static void generate_request(struct nbt_name_socket *nbtsock, struct wins_state *state, int idx)
{
	if (random() % 5 == 0) {
		generate_register(nbtsock, state, idx);
		return;
	}

	if (random() % 20 == 0) {
		generate_release(nbtsock, state, idx);
		return;
	}

	generate_query(nbtsock, state, idx);
}

/*
  benchmark simple name queries
*/
static BOOL bench_wins(TALLOC_CTX *mem_ctx, struct nbt_name *name, const char *address)
{
	struct nbt_name_socket *nbtsock = nbt_name_socket_init(mem_ctx, NULL);
	int num_sent=0;
	struct timeval tv = timeval_current();
	BOOL ret = True;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	struct wins_state *state;
	extern int torture_entries;
	struct socket_address *my_ip;

	state = talloc_zero(nbtsock, struct wins_state);

	state->num_names = torture_entries;
	state->registered = talloc_zero_array(state, BOOL, state->num_names);
	state->wins_server = address;
	state->my_ip = talloc_strdup(mem_ctx, iface_best_ip(address));
	state->ttl = timelimit;

	my_ip = socket_address_from_strings(nbtsock, nbtsock->sock->backend_name, 
					    state->my_ip, 0);

	socket_listen(nbtsock->sock, my_ip, 0, 0);

	printf("Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		while (num_sent - (state->pass_count+state->fail_count) < 10) {
			generate_request(nbtsock, state, num_sent % state->num_names);
			num_sent++;
			if (num_sent % 50 == 0) {
				printf("%.1f queries per second (%d failures)  \r", 
				       state->pass_count / timeval_elapsed(&tv),
				       state->fail_count);
			}
		}

		event_loop_once(nbtsock->event_ctx);
	}

	while (num_sent != (state->pass_count + state->fail_count)) {
		event_loop_once(nbtsock->event_ctx);
	}

	printf("%.1f queries per second (%d failures)  \n", 
	       state->pass_count / timeval_elapsed(&tv),
	       state->fail_count);

	talloc_free(nbtsock);
	return ret;
}


/*
  benchmark how fast a WINS server can respond to a mixture of
  registration/refresh/release and name query requests
*/
BOOL torture_bench_wins(void)
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

	ret &= bench_wins(mem_ctx, &name, address);

	talloc_free(mem_ctx);

	return ret;
}
