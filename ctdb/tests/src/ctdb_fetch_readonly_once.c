/* 
   simple ctdb test tool
   This test just fetch_locks a record and releases it once.

   Copyright (C) Ronnie Sahlberg 2009

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

#include "includes.h"
#include "system/filesys.h"
#include "popt.h"
#include <poll.h>
#include "ctdb.h"

const char *TESTKEY = "testkey";

static void rorl_cb(struct ctdb_db *ctdb_db,
		   struct ctdb_lock *lock, TDB_DATA outdata, void *private)
{
	int *finished = private;

	printf("Record fetchlocked.\n");
	printf("Press enter to release the record ...\n");
	(void)getchar();

	*finished = 1;
}

/*
	Just try locking/unlocking a single record once
*/
static void fetch_readonly_once(struct ctdb_connection *ctdb, struct ctdb_db *ctdb_db, TDB_DATA key)
{
	int finished;

	printf("Trying to fetch lock the record ...\n");

	finished = 0;
	if (!ctdb_readonlyrecordlock_async(ctdb_db, key,
				       rorl_cb, &finished)) {
		printf("Failed to send READONLYRECORDLOCK\n");
		exit(10);
	}

	while (!finished) {
		struct pollfd pfd;

		pfd.fd = ctdb_get_fd(ctdb);
		pfd.events = ctdb_which_events(ctdb);
		if (poll(&pfd, 1, -1) < 0) {
			fprintf(stderr, "Poll failed");
			exit(10);
		}
		if (ctdb_service(ctdb, pfd.revents) < 0) {
			fprintf(stderr, "Failed to service");
			exit(10);
		}
	}

	printf("Record released.\n");
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_connection *ctdb;
	struct ctdb_db *ctdb_db;
	const char *socket_name;

	TDB_DATA key;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "record",      'r', POPT_ARG_STRING, &TESTKEY, 0, "record", "string" },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			exit(1);
		}
	}

	/* setup the remaining options for the main program to use */
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		while (extra_argv[extra_argc]) extra_argc++;
	}

	socket_name = getenv("CTDB_SOCKET");
	if (socket_name == NULL) {
		socket_name = "/tmp/ctdb.socket";
	}
	ctdb = ctdb_connect(socket_name, ctdb_log_file, stderr);

	if (!ctdb) {
		fprintf(stderr, "Connecting to /tmp/ctdb.socket");
		exit(10);
	}

	key.dptr  = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);

	/* attach to a specific database */
	ctdb_db = ctdb_attachdb(ctdb, "test.tdb", false, 0);
	if (!ctdb_db) {
		fprintf(stderr, "ctdb_attachdb failed\n");
		exit(10);
	}

	printf("Waiting for cluster\n");
	while (1) {
		uint32_t recmode=1;
		ctdb_getrecmode(ctdb, CTDB_CURRENT_NODE, &recmode);
		if (recmode == 0) break;
		sleep(1);
	}

	fetch_readonly_once(ctdb, ctdb_db, key);

	return 0;
}
