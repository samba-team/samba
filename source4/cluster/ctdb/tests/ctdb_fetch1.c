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
#include "ctdb.h"
#include "ctdb_private.h"

#define PARENT_SRVID	0
#define CHILD1_SRVID	1
#define CHILD2_SRVID	2

int num_msg=0;

static void message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
			    TDB_DATA data, void *private_data)
{
	num_msg++;
}
static void child_handler(struct ctdb_context *ctdb, uint32_t srvid, 
			    TDB_DATA data, void *private_data)
{
	num_msg++;
}

void test1(struct ctdb_db_context *ctdb_db)
{
	struct ctdb_record_handle *rh;
	TDB_DATA key, data, data2, store_data;
	int ret;
 
	/* 
	   test 1 : write data and read it back.   should all be the same
	 */
	printf("Test1: write and verify we can read it back: ");
	key.dptr  = discard_const("Record");
	key.dsize = strlen((const char *)key.dptr)+1;
	rh = ctdb_fetch_lock(ctdb_db, ctdb_db, key, &data);

	store_data.dptr  = discard_const("data to store");
	store_data.dsize = strlen((const char *)store_data.dptr)+1;
	ret = ctdb_store_unlock(rh, store_data);

	rh = ctdb_fetch_lock(ctdb_db, ctdb_db, key, &data2);
	/* hopefully   data2 will now contain the record written above */
	if (!strcmp("data to store", (const char *)data2.dptr)) {
		printf("SUCCESS\n");
	} else {
		printf("FAILURE\n");
		exit(10);
	}
	
	/* just write it back to unlock it */
	ret = ctdb_store_unlock(rh, store_data);
}

void child(int srvid, struct event_context *ev, struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db)
{
	TDB_DATA data;
	struct ctdb_record_handle *rh;
	TDB_DATA key, data2;

	data.dptr=discard_const("dummy message");
	data.dsize=strlen((const char *)data.dptr)+1;

	ctdb_set_message_handler(ctdb, srvid, child_handler, NULL);

	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), PARENT_SRVID, data);
	while (num_msg==0) {
		event_loop_once(ev);
	}


	/* fetch and lock the record */
	key.dptr  = discard_const("Record");
	key.dsize = strlen((const char *)key.dptr)+1;
	rh = ctdb_fetch_lock(ctdb_db, ctdb_db, key, &data2);
	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), PARENT_SRVID, data);


	while (1) {
		event_loop_once(ev);
	}
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
	TDB_DATA data;

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

#if 0
	/* wait until all nodes are connected (should not be needed
	   outside of test code) */
	ctdb_connect_wait(ctdb);
#endif

	/*
	   start two child processes
	 */
	if(fork()){
		/* 
		   set up a message handler so our child processes can talk to us
		 */
		ctdb_set_message_handler(ctdb, PARENT_SRVID, message_handler, NULL);
	} else {
		sleep(3);
		if(!fork()){
			child(CHILD1_SRVID, ev, ctdb, ctdb_db);
		} else {
			child(CHILD2_SRVID, ev, ctdb, ctdb_db);
		}
	}

	/* 
	   test 1 : write data and read it back.
	 */
	test1(ctdb_db); 

	/* 
	   wait until both children have sent us a message they have started
	 */
	printf("Wait for both child processes to start: ");
	while (num_msg!=2) {
		event_loop_once(ev);
	}
	printf("STARTED\n");


	/*
	   send message to child 1 to make it to fetch and lock the record 
	 */
	data.dptr=discard_const("dummy message");
	data.dsize=strlen((const char *)data.dptr)+1;
	printf("Send message to child 1 to fetch_lock the record\n");
	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), CHILD1_SRVID, data);

	/* wait for child 1 to complete fetching and locking the record */
	while (num_msg!=3) {
		event_loop_once(ev);
	}
	printf("Child 1 has fetched and locked the record\n");

	/* now tell child 2 to fetch and lock the same record */
	printf("Send message to child 2 to fetch_lock the record\n");
	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), CHILD2_SRVID, data);

	/* wait for child 2 to complete fetching and locking the record */
	while (num_msg!=4) {
		event_loop_once(ev);
	}
	printf("Child 2 has fetched and locked the record\n");


	while (1) {
		event_loop_once(ev);
	}

	/* shut it down */
	talloc_free(ctdb);
	return 0;
}
