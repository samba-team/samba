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

#define TESTKEY "testkey"

static void rrl_cb(struct ctdb_db *ctdb_db,
		   struct ctdb_lock *lock, TDB_DATA outdata, void *private)
{
	bool *rrl_cb_called = private;

	printf("Record fetchlocked.\n");
	printf("Press enter to release the record ...\n");
	(void)getchar();
	printf("Record released.\n");

	*rrl_cb_called = true;
	return;
}

/*
	Just try locking/unlocking a single record once
*/
static void fetch_lock_once(struct ctdb_connection *ctdb, struct ctdb_db *ctdb_db)
{
	TDB_DATA key;
	bool rrl_cb_finished = false;

	key.dptr = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);

	printf("Trying to fetch lock the record ...\n");

	/* In the non-contended case the callback might be invoked
	 * immediately, before ctdb_readrecordlock_async() returns.
	 * In the contended case the callback will be invoked later.
	 *
	 * Normally an application would not care whether the callback
	 * has already been invoked here or not, but if the application
	 * needs to know, it can use the *private_data pointer
	 * to pass data through to the callback and back.
	 */
	if (!ctdb_readrecordlock_async(ctdb_db, key,
				       rrl_cb, &rrl_cb_finished)) {
		printf("Failed to send READRECORDLOCK\n");
		exit(10);
	}
	while (!rrl_cb_finished) {
		struct pollfd pfd;

		pfd.fd = ctdb_get_fd(ctdb);
		pfd.events = ctdb_which_events(ctdb);
		if (poll(&pfd, 1, -1) < 0) {
			printf("Poll failed");
			exit(10);
		}
		if (ctdb_service(ctdb, pfd.revents) < 0) {
			printf("Failed to service\n");
			exit(10);
		}
	}
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_connection *ctdb;
	struct ctdb_db *ctdb_db;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
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

	ctdb = ctdb_connect("/tmp/ctdb.socket",
				       ctdb_log_file, stderr);
	if (!ctdb) {
		printf("Connecting to /tmp/ctdb.socket\n");
		exit(1);
	}

	/* attach to a specific database */
	ctdb_db = ctdb_attachdb(ctdb, "test.tdb", false, 0);
	if (!ctdb_db) {
		printf("ctdb_attachdb failed\n");
		exit(1);
	}

	printf("Waiting for cluster\n");
	while (1) {
		uint32_t recmode=1;
		ctdb_getrecmode(ctdb, CTDB_CURRENT_NODE, &recmode);
		if (recmode == 0) break;
		sleep(1);
	}

	fetch_lock_once(ctdb, ctdb_db);

	return 0;
}
