/*
   CTDB tunnel test

   Copyright (C) Amitay Isaacs  2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/tevent_unix.h"

#include "protocol/protocol_private.h"
#include "client/client.h"

#define TUNNEL_ID	(CTDB_TUNNEL_TEST | 0xf0f0f0f0)

struct listen_state {
	TALLOC_CTX *mem_ctx;
	bool done;
};

static void listen_callback(struct ctdb_tunnel_context *tctx,
			    uint32_t srcnode, uint32_t reqid,
			    uint8_t *buf, size_t buflen,
			    void *private_data)
{
	struct listen_state *state = (struct listen_state *)private_data;
	const char *msg;
	size_t np;
	int ret;

	ret = ctdb_stringn_pull(buf, buflen, state->mem_ctx, &msg, &np);
	if (ret != 0) {
		fprintf(stderr, "Invalid tunnel message, ret=%d\n", ret);
		return;
	}

	fprintf(stderr, "%u: %s\n", srcnode, msg);

	if (strcmp(msg, "quit") == 0) {
		state->done = true;
	}

	talloc_free(discard_const(msg));
}

static int cmd_listen(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client)
{
	struct ctdb_tunnel_context *tunnel;
	struct listen_state state;
	int ret;

	state.mem_ctx = mem_ctx;
	state.done = false;

	ret = ctdb_tunnel_setup(mem_ctx, ev, client, TUNNEL_ID,
				listen_callback, &state, &tunnel);
	if (ret != 0) {
		return ret;
	}

	ctdb_client_wait(ev, &state.done);

	ret = ctdb_tunnel_destroy(ev, tunnel);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static void send_callback(struct ctdb_tunnel_context *tctx,
			  uint32_t srcnode, uint32_t reqid,
			  uint8_t *buf, size_t buflen, void *private_data)
{
	fprintf(stderr, "send received a message - %u: %zu\n", srcnode, buflen);
}

static int cmd_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		    struct ctdb_client_context *client,
		    uint32_t destnode, const char *msg)
{
	struct ctdb_tunnel_context *tunnel;
	uint8_t *buf;
	size_t buflen, np;
	int ret;

	ret = ctdb_tunnel_setup(mem_ctx, ev, client, TUNNEL_ID,
				send_callback, NULL, &tunnel);
	if (ret != 0) {
		return ret;
	}

	buflen = ctdb_stringn_len(&msg);
	buf = talloc_size(mem_ctx, buflen);
	if (buf == NULL) {
		return ENOMEM;
	}
	ctdb_stringn_push(&msg, buf, &np);

	ret = ctdb_tunnel_request(mem_ctx, ev, tunnel, destnode,
				  tevent_timeval_zero(), buf, buflen, false);
	if (ret != 0) {
		return ret;
	}

	ret = ctdb_tunnel_destroy(ev, tunnel);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static void usage(const char *cmd)
{
	fprintf(stderr, "usage: %s <ctdb-socket> listen\n", cmd);
	fprintf(stderr, "usage: %s <ctdb-socket> send <pnn> <msg>\n", cmd);
}

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	const char *socket = NULL, *msg = NULL;
	uint32_t pnn = CTDB_UNKNOWN_PNN;
	int ret;
	bool do_listen = false;
	bool do_send = false;

	if (argc != 3 && argc != 5) {
		usage(argv[0]);
		exit(1);
	}

	socket = argv[1];

	if (strcmp(argv[2], "listen") == 0) {
		do_listen = true;
	} else if (strcmp(argv[2], "send") == 0) {
		if (argc != 5) {
			usage(argv[0]);
			exit(1);
		}

		pnn = atol(argv[3]);
		msg = argv[4];
		do_send = true;
	} else {
		usage(argv[0]);
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		exit(1);
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		talloc_free(mem_ctx);
		exit(1);
	}

	ret = ctdb_client_init(mem_ctx, ev, socket, &client);
	if (ret != 0) {
		talloc_free(mem_ctx);
		exit(1);
	}

	if (do_listen) {
		ret = cmd_listen(mem_ctx, ev, client);
	}
	if (do_send) {
		ret = cmd_send(mem_ctx, ev, client, pnn, msg);
	}

	talloc_free(mem_ctx);

	return ret;
}
