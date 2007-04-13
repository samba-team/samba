/* 
   simple ctdb fetch test

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "popt.h"


static void message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
			    TDB_DATA data, void *private)
{
printf("received a message\n");
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	const char *nlist = NULL;
	const char *transport = "tcp";
	const char *myaddress = NULL;
	int self_connect=0;
	int daemon_mode=0;
	TDB_DATA key, data, data2, store_data;
	struct ctdb_record_handle *rh;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "nlist", 0, POPT_ARG_STRING, &nlist, 0, "node list file", "filename" },
		{ "listen", 0, POPT_ARG_STRING, &myaddress, 0, "address to listen on", "address" },
		{ "transport", 0, POPT_ARG_STRING, &transport, 0, "protocol transport", NULL },
		{ "self-connect", 0, POPT_ARG_NONE, &self_connect, 0, "enable self connect", "boolean" },
		{ "daemon", 0, POPT_ARG_NONE, &daemon_mode, 0, "spawn a ctdb daemon", "boolean" },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int ret;
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

	if (nlist == NULL || myaddress == NULL) {
		printf("You must provide a node list with --nlist and an address with --listen\n");
		exit(1);
	}

	ev = event_context_init(NULL);

	/* initialise ctdb */
	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	if (self_connect) {
		ctdb_set_flags(ctdb, CTDB_FLAG_SELF_CONNECT);
	}
	if (daemon_mode) {
		ctdb_set_flags(ctdb, CTDB_FLAG_DAEMON_MODE);
	}

	ret = ctdb_set_transport(ctdb, transport);
	if (ret == -1) {
		printf("ctdb_set_transport failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* tell ctdb what address to listen on */
	ret = ctdb_set_address(ctdb, myaddress);
	if (ret == -1) {
		printf("ctdb_set_address failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* tell ctdb what nodes are available */
	ret = ctdb_set_nlist(ctdb, nlist);
	if (ret == -1) {
		printf("ctdb_set_nlist failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, "test.tdb", TDB_DEFAULT, O_RDWR|O_CREAT|O_TRUNC, 0666);
	if (!ctdb_db) {
		printf("ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* start the protocol running */
	ret = ctdb_start(ctdb);

	ctdb_set_message_handler(ctdb, 0, message_handler, NULL);

	/* wait until all nodes are connected (should not be needed
	   outside of test code) */
	ctdb_connect_wait(ctdb);

	key.dptr  = "Record";
	key.dsize = strlen(key.dptr)+1;
	rh = ctdb_fetch_lock(ctdb_db, ctdb_db, key, &data);

	store_data.dptr  = "data to store";
	store_data.dsize = strlen(store_data.dptr)+1;
	ret = ctdb_store_unlock(rh, store_data);

	rh = ctdb_fetch_lock(ctdb_db, ctdb_db, key, &data2);
	/* hopefully   data2 will now contain the record written above */
	if (!strcmp("data to store", data2.dptr)) {
		printf("woohoo we read back the data we stored\n");
	} else {
		printf("ERROR: we read back different data than we stored\n");
	}
	
	/* just write it back to unlock it */
	ret = ctdb_store_unlock(rh, store_data);

#if 0
	while (1) {
		event_loop_once(ev);
	}
#endif

	/* shut it down */
	talloc_free(ctdb);
	return 0;
}
