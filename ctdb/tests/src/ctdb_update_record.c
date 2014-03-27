/* 
   simple ctdb test tool
   This test just fetch_locks a record bumps the RSN and then writes new content

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
#include "ctdb_private.h"

static struct ctdb_db_context *ctdb_db;

#define TESTKEY "testkey"


/*
	Just try locking/unlocking a single record once
*/
static void fetch_lock_once(struct ctdb_context *ctdb, struct event_context *ev, uint32_t generation)
{
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA key, data;
	struct ctdb_record_handle *h;
	struct ctdb_ltdb_header *header;
	int ret;

	key.dptr = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);

	printf("Trying to fetch lock the record ...\n");

	h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
	if (h == NULL) {
		printf("Failed to fetch record '%s' on node %d\n", 
	       		(const char *)key.dptr, ctdb_get_pnn(ctdb));
		talloc_free(tmp_ctx);
		exit(10);
	}

	printf("Record fetchlocked.\n");
	header = talloc_memdup(tmp_ctx, ctdb_header_from_record_handle(h), sizeof(*header));
       	printf("RSN:%d\n", (int)header->rsn);
	talloc_free(h);
	printf("Record released.\n");

	printf("Write new record with RSN+10\n");
	header->rsn += 10;
	data.dptr = (void *)talloc_asprintf(tmp_ctx, "%d", (int)header->rsn);
	data.dsize = strlen((char *)data.dptr);

	ret = ctdb_ctrl_updaterecord(ctdb, ctdb, timeval_zero(), CTDB_CURRENT_NODE, ctdb_db, key, header, data);
	if (ret != 0) {
		printf("Failed to writerecord,  ret==%d\n", ret);	
		exit(1);
	}

	printf("re-fetch the record\n");
	h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
	if (h == NULL) {
		printf("Failed to fetch record '%s' on node %d\n", 
	       		(const char *)key.dptr, ctdb_get_pnn(ctdb));
		talloc_free(tmp_ctx);
		exit(10);
	}

	printf("Record fetchlocked.\n");
	header = talloc_memdup(tmp_ctx, ctdb_header_from_record_handle(h), sizeof(*header));
       	printf("RSN:%d\n", (int)header->rsn);
	talloc_free(h);
	printf("Record released.\n");

	talloc_free(tmp_ctx);
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
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;
	struct event_context *ev;
	struct ctdb_vnn_map *vnnmap=NULL;

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


	if (ctdb_ctrl_getvnnmap(ctdb, timeval_zero(), CTDB_CURRENT_NODE, ctdb, &vnnmap) != 0) {
		printf("Unable to get vnnmap from local node\n");
		exit(1);
	}
	printf("Current Generation %d\n", (int)vnnmap->generation);

	fetch_lock_once(ctdb, ev, vnnmap->generation);

	return 0;
}
