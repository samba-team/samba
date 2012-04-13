/* 
   simple ctdb benchmark
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
#include "popt.h"
#include "cmdline.h"

#include <sys/time.h>
#include <time.h>

static int timelimit = 10;
static int lock_count = 0;

static struct ctdb_db_context *ctdb_db;

#define TESTKEY "testkey"


static void alarm_handler(int sig)
{
	printf("Locks:%d\n", lock_count);
	lock_count=0;

	timelimit--;
	if (timelimit <= 0) {
		exit(0);
	}
	alarm(1);
}

/*
	Just try locking/unlocking the same record over and over
*/
static void bench_fetch_one_loop(struct ctdb_context *ctdb, struct event_context *ev)
{
	TDB_DATA key, data;

	key.dptr = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);


	while (1) {
		TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
		struct ctdb_record_handle *h;

		h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
		if (h == NULL) {
			printf("Failed to fetch record '%s' on node %d\n", 
		       		(const char *)key.dptr, ctdb_get_pnn(ctdb));
			talloc_free(tmp_ctx);
			continue;
		}

		talloc_free(tmp_ctx);
		lock_count++;
	}
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "timelimit", 't', POPT_ARG_INT, &timelimit, 0, "timelimit", "integer" },
		POPT_TABLEEND
	};
	int opt;
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

	ctdb = ctdb_cmdline_client(ev, timeval_current_ofs(3, 0));

	if (ctdb == NULL) {
		printf("failed to connect to ctdb daemon.\n");
		exit(1);
	}

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, timeval_current_ofs(2, 0), "test.tdb",
			      false, 0);
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

	signal(SIGALRM, alarm_handler);
	alarm(1);

	bench_fetch_one_loop(ctdb, ev);

	return 0;
}
