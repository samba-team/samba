/* 
   simple tool to create a lot of records on a tdb and to read them out

   Copyright (C) Andrew Tridgell  2006
	Ronnie sahlberg 2007

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

static int num_records = 10;
static int base_rec;

static void store_records(struct ctdb_context *ctdb, struct event_context *ev)
{
	TDB_DATA key, data;
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int ret;
	struct ctdb_record_handle *h;
	uint32_t i;
	
	ctdb_db = ctdb_db_handle(ctdb, "test.tdb");

	printf("creating %d records\n", num_records);
	for (i=0;i<num_records;i++) {
		int r = base_rec + i;
		key.dptr = (uint8_t *)&r;
		key.dsize = sizeof(uint32_t); 

		h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
		if (h == NULL) {
			printf("Failed to fetch record '%s' on node %d\n", 
			       (const char *)key.dptr, ctdb_get_pnn(ctdb));
			talloc_free(tmp_ctx);
			return;
		}

		data.dptr = (uint8_t *)&i;
		data.dsize = sizeof(uint32_t);

		ret = ctdb_record_store(h, data);
		talloc_free(h);
		if (ret != 0) {
			printf("Failed to store record\n");
		}
		if (i % 1000 == 0) {
			printf("%u\r", i);
			fflush(stdout);
		}
	}

	printf("fetching all %d records\n", num_records);
	while (1) {
		for (i=0;i<num_records;i++) {
			int r = base_rec + i;
			key.dptr = (uint8_t *)&r;
			key.dsize = sizeof(uint32_t); 

			h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
			if (h == NULL) {
				printf("Failed to fetch record '%s' on node %d\n", 
				       (const char *)key.dptr, ctdb_get_pnn(ctdb));
				talloc_free(tmp_ctx);
				return;
			}
			talloc_free(h);
		}
		sleep(1);
		printf(".");
		fflush(stdout);
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
		{ "num-records", 'r', POPT_ARG_INT, &num_records, 0, "num_records", "integer" },
		{ "base-rec", 'b', POPT_ARG_INT, &base_rec, 0, "base_rec", "integer" },
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

	/* talloc_enable_leak_report_full(); */

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
	ctdb_db = ctdb_attach(ctdb, timeval_current_ofs(2, 0), "test.tdb", false, 0);
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

	store_records(ctdb, ev);

	return 0;
}
