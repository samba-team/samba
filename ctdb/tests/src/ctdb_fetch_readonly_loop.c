/* 
   simple ctdb test tool
   This test just fetch_locks a record and releases it in a loop.

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
#include "system/time.h"
#include "popt.h"
#include "cmdline.h"
#include "ctdb_private.h"

static struct ctdb_db_context *ctdb_db;

const char *TESTKEY = "testkey";
static int count;

/*
	Just try locking/unlocking a single record once
*/
static void fetch_lock_once(struct ctdb_context *ctdb, struct event_context *ev)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA key, data;
	struct ctdb_record_handle *h;
	static time_t t = 0, t2;

	key.dptr = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);

//	printf("Trying to fetch lock the record ...\n");

	h = ctdb_fetch_readonly_lock(ctdb_db, tmp_ctx, key, &data, 1);
	if (h == NULL) {
		printf("Failed to fetch record '%s' on node %d\n", 
	       		(const char *)key.dptr, ctdb_get_pnn(ctdb));
		talloc_free(tmp_ctx);
		exit(10);
	}

	count++;
	t2 = time(NULL);
	if (t != 0 && t != t2) {
		static int last_count = 0;

		printf("count : %d\n", count - last_count);
		last_count = count;
	}
	t = t2;

	talloc_free(tmp_ctx);
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	TDB_DATA key;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "record",      'r', POPT_ARG_STRING, &TESTKEY, 0, "record", "string" },
		POPT_TABLEEND
	};
	int opt, ret;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;
	struct event_context *ev;

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

	ctdb = ctdb_cmdline_client(ev, timeval_current_ofs(5, 0));
	if (ctdb == NULL) {
		exit(1);
	}

	key.dptr  = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);

	ret = ctdb_ctrl_getvnnmap(ctdb, timeval_zero(), CTDB_CURRENT_NODE, ctdb, &ctdb->vnn_map);
	if (ret != 0) {
		printf("failed to get vnnmap\n");
		exit(10);
	}
	printf("Record:%s\n", TESTKEY);
	printf("Lmaster : %d\n", ctdb_lmaster(ctdb, &key)); 

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, timeval_current_ofs(5, 0), "test.tdb", false, 0);
	if (!ctdb_db) {
		printf("ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	printf("Waiting for cluster\n");
	while (1) {
		uint32_t recmode=1;
		ctdb_ctrl_getrecmode(ctdb, ctdb, timeval_zero(), CTDB_CURRENT_NODE, &recmode);
		if (recmode == 0) break;
		event_loop_once(ev);
	}

	while (1) {
		fetch_lock_once(ctdb, ev);
	}

	return 0;
}
