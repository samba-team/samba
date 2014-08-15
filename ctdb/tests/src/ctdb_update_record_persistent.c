/* 
   simple ctdb test tool
   This test just creates/updates a record in a persistent database

   Copyright (C) Ronnie Sahlberg 2012

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
#include "lib/tdb_wrap/tdb_wrap.h"
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"
#include "ctdb_private.h"


static void update_once(struct ctdb_context *ctdb, struct event_context *ev, struct ctdb_db_context *ctdb_db, char *record, char *value)
{
	TDB_DATA key, data, olddata;
	struct ctdb_ltdb_header header;

	memset(&header, 0, sizeof(header));

	key.dptr  = (uint8_t *)record;
	key.dsize = strlen(record);

	data.dptr  = (uint8_t *)value;
	data.dsize = strlen(value);

	olddata = tdb_fetch(ctdb_db->ltdb->tdb, key);
	if (olddata.dsize != 0) {
		memcpy(&header, olddata.dptr, sizeof(header));
	} 
	header.rsn++;

	if (ctdb_ctrl_updaterecord(ctdb, ctdb, timeval_zero(), CTDB_CURRENT_NODE, ctdb_db, key, &header, data) != 0) {
		printf("Failed to update record\n");
		exit(1);
	}
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	char *test_db = NULL;
	char *record = NULL;
	char *value = NULL;
	struct ctdb_db_context *ctdb_db;
	struct event_context *ev;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "database",      'D', POPT_ARG_STRING, &test_db, 0, "database", "string" },
		{ "record",      'R', POPT_ARG_STRING, &record, 0, "record", "string" },
		{ "value",      'V', POPT_ARG_STRING, &value, 0, "value", "string" },
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

	ctdb = ctdb_cmdline_client(ev, timeval_current_ofs(5, 0));
	if (ctdb == NULL) {
		exit(1);
	}

	if (test_db == NULL) {
		fprintf(stderr, "You must specify the database\n");
		exit(10);
	}

	if (record == NULL) {
		fprintf(stderr, "You must specify the record\n");
		exit(10);
	}

	if (value == NULL) {
		fprintf(stderr, "You must specify the value\n");
		exit(10);
	}

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, timeval_current_ofs(5, 0), test_db, true, 0);
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

	update_once(ctdb, ev, ctdb_db, record, value);

	return 0;
}
