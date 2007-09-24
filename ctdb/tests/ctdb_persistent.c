/* 
   simple tool to test persistent databases

   Copyright (C) Andrew Tridgell  2006-2007
   Copyright (c) Ronnie sahlberg  2007

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
#include "lib/events/events.h"
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"

#include <sys/time.h>
#include <time.h>

static void test_store_records(struct ctdb_context *ctdb, struct event_context *ev)
{
	TDB_DATA key, data;
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int ret, i;
	struct ctdb_record_handle *h;
	unsigned node=0, count=0;
	
	ctdb_db = ctdb_db_handle(ctdb, "persistent.tdb");

	key.dptr = discard_const("testkey");
	key.dsize = strlen((const char *)key.dptr)+1;

	for (i=0;i<10;i++) {
		h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
		if (h == NULL) {
			printf("Failed to fetch record '%s' on node %d\n", 
			       (const char *)key.dptr, ctdb_get_pnn(ctdb));
			talloc_free(tmp_ctx);
			return;
		}
		
		printf("Current value: %*.*s\n", (int)data.dsize, (int)data.dsize, data.dptr);
		
		if (data.dsize != 0) {
			if (sscanf((char *)data.dptr, "Node %u Count %u", &node, &count) != 2) {
				printf("Badly formatted node data!\n");
				exit(1);
			}
		}
		
		node = ctdb_get_pnn(ctdb);
		count++;
		
		data.dptr = (uint8_t *)talloc_asprintf(h, "Node %u Count %u", node, count);
		data.dsize = strlen((char *)data.dptr)+1;
		
		ret = ctdb_record_store(h, data);
		if (ret != 0) {
			DEBUG(0,("Failed to store record\n"));
			exit(1);
		}
		talloc_free(h);
	}

	talloc_free(tmp_ctx);
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
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

	ctdb = ctdb_cmdline_client(ev);

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, "persistent.tdb", true);
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

	printf("Starting test\n");
	test_store_records(ctdb, ev);

	return 0;
}
