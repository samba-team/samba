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

const char *TESTKEY = "testkey";

/*
	Just try locking/unlocking a single record once
*/
static void fetch_readonly_once(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	TDB_DATA data;
	struct ctdb_record_handle *h;

	printf("Trying to readonly fetch lock the record ...\n");

	h = ctdb_fetch_readonly_lock(ctdb_db, ctdb, key, &data, 1);
	if (h == NULL) {
		fprintf(stderr, "Failed to get readonly lock\n");
		exit(1);
	}

	talloc_free(h);
	printf("Record released.\n");
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct event_context *ev;

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

	ev = event_context_init(NULL);

	ctdb = ctdb_cmdline_client(ev, timeval_current_ofs(3, 0));
	if (ctdb == NULL) {
		printf("failed to connect to ctdb daemon.\n");
		exit(1);
	}

	key.dptr  = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, timeval_current_ofs(3, 0), "test.tdb",
			      false, 0);
	if (!ctdb_db) {
		fprintf(stderr, "ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(10);
	}

	printf("Waiting for cluster\n");
	while (1) {
		uint32_t recmode=1;
		ctdb_ctrl_getrecmode(ctdb, ctdb, timeval_zero(), CTDB_CURRENT_NODE, &recmode);
		if (recmode == 0) break;
		event_loop_once(ev);
	}

	fetch_readonly_once(ctdb, ctdb_db, key);

	return 0;
}
