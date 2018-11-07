/*
   Dummy CTDB client for testing

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

#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "common/logging.h"
#include "common/path.h"

#include "client/client.h"

static struct {
	const char *sockpath;
	const char *debuglevel;
	int num_connections;
	int timelimit;
	const char *srvidstr;
} options;

static struct poptOption cmdline_options[] = {
	POPT_AUTOHELP
	{ "socket", 's', POPT_ARG_STRING, &options.sockpath, 0,
		"Unix domain socket path", "filename" },
	{ "debug", 'd', POPT_ARG_STRING, &options.debuglevel, 0,
		"debug level", "ERR|WARNING|NOTICE|INFO|DEBUG" } ,
	{ "nconn", 'n', POPT_ARG_INT, &options.num_connections, 0,
		"number of connections", "" },
	{ "timelimit", 't', POPT_ARG_INT, &options.timelimit, 0,
		"time limit", "seconds" },
	{ "srvid", 'S', POPT_ARG_STRING, &options.srvidstr, 0,
		"srvid to register", "srvid" },
	POPT_TABLEEND
};

static void dummy_handler(uint64_t srvid, TDB_DATA data, void *private_data)
{
	bool *done = (bool *)private_data;

	*done = true;
}

int main(int argc, const char *argv[])
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct ctdb_client_context **client;
	struct ctdb_client_context *last_client;
	poptContext pc;
	int opt, ret, i;
	int log_level;
	bool status, done;

	/* Set default options */
	options.sockpath = NULL;
	options.debuglevel = "ERR";
	options.num_connections = 1;
	options.timelimit = 60;
	options.srvidstr = NULL;

	pc = poptGetContext(argv[0], argc, argv, cmdline_options,
			    POPT_CONTEXT_KEEP_FIRST);
	while ((opt = poptGetNextOpt(pc)) != -1) {
		fprintf(stderr, "Invalid option %s\n", poptBadOption(pc, 0));
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	status = debug_level_parse(options.debuglevel, &log_level);
	if (! status) {
		fprintf(stderr, "Invalid debug level\n");
		poptPrintHelp(pc, stdout, 0);
		exit(1);
	}

	setup_logging("dummy_client", DEBUG_STDERR);
	debuglevel_set(log_level);

	if (options.sockpath == NULL) {
		options.sockpath = path_socket(mem_ctx, "ctdbd");
		if (options.sockpath == NULL) {
			D_ERR("Memory allocation error\n");
			exit(1);
		}
	}

	client = talloc_array(mem_ctx, struct ctdb_client_context *,
			      options.num_connections);
	if (client == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	for (i=0; i<options.num_connections; i++) {
		ret = ctdb_client_init(client, ev, options.sockpath,
				       &client[i]);
		if (ret != 0) {
			D_ERR("Failed to initialize client %d, ret=%d\n",
			      i, ret);
			exit(1);
		}
	}

	last_client = client[options.num_connections-1];

	done = false;
	if (options.srvidstr != NULL) {
		uint64_t srvid;

		srvid = strtoull(options.srvidstr, NULL, 0);

		ret = ctdb_client_set_message_handler(ev, last_client, srvid,
						      dummy_handler, &done);
		if (ret != 0) {
			D_ERR("Failed to register srvid, ret=%d\n", ret);
			talloc_free(client);
			exit(1);
		}

		D_INFO("Registered SRVID 0x%"PRIx64"\n", srvid);
	}

	ret = ctdb_client_wait_timeout(ev, &done,
			tevent_timeval_current_ofs(options.timelimit, 0));
	if (ret != 0 && ret == ETIMEDOUT) {
		D_ERR("client_wait_timeout() failed, ret=%d\n", ret);
		talloc_free(client);
		exit(1);
	}

	talloc_free(mem_ctx);
	exit(0);
}
