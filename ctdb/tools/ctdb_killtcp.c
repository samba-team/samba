/*
   CTDB TCP connection killing utility

   Copyright (C) Martin Schwenke <martin@meltin.net> 2016

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

#include "lib/util/debug.h"

#include "protocol/protocol.h"

#include "common/system.h"
#include "common/logging.h"

#include "server/killtcp.h"

static const char *prog;

static int ctdb_killtcp_destructor(struct ctdb_kill_tcp *killtcp)
{
	bool *done = killtcp->destructor_data;
	*done = true;

	return 0;
}

static void usage(void)
{
	printf("usage: %s <interface> [ <srcip:port> <dstip:port> ]\n", prog);
	exit(1);
}

int main(int argc, char **argv)
{
	struct ctdb_connection conn;
	struct ctdb_kill_tcp *killtcp = NULL;
	struct tevent_context *ev = NULL;
	struct TALLOC_CONTEXT *mem_ctx = NULL;
	struct ctdb_connection *conns = NULL;
	bool done;
	int num = 0;
	int i, ret;

	prog = argv[0];

	if (argc != 2 && argc != 4) {
		usage();
	}

	if (argc == 4) {
		if (!parse_ip_port(argv[2], &conn.src)) {
			DEBUG(DEBUG_ERR, ("Bad IP:port '%s'\n", argv[2]));
			goto fail;
		}

		if (!parse_ip_port(argv[3], &conn.dst)) {
			DEBUG(DEBUG_ERR, ("Bad IP:port '%s'\n", argv[3]));
			goto fail;
		}

		conns = &conn;
		num = 1;
	} else {
		ret = ctdb_parse_connections(stdin, mem_ctx, &num, &conns);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,
			      ("Unable to parse connections [%s]\n",
			       strerror(ret)));
			goto fail;
		}
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		goto fail;
	}

        ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to initialise tevent\n"));
		goto fail;
	}

	if (num == 0) {
		/* No connections, done! */
		talloc_free(mem_ctx);
		return 0;
	}

	for (i = 0; i < num; i++) {
		ret = ctdb_killtcp(ev, mem_ctx, argv[1],
				   &conns[i].src, &conns[i].dst,
				   &killtcp);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to killtcp\n"));
			goto fail;
		}
	}

	done = false;
	killtcp->destructor_data = &done;
	talloc_set_destructor(killtcp, ctdb_killtcp_destructor);

	while (!done) {
		tevent_loop_once(ev);
	}

	talloc_free(mem_ctx);

	return 0;

fail:
	TALLOC_FREE(mem_ctx);
	return -1;
}
