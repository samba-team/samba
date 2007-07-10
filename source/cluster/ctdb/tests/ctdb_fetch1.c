/* 
   simple ctdb fetch test

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "popt.h"
#include "ctdb.h"
#include "ctdb_private.h"
#include "cmdline.h"
#include <sys/time.h>

#define PARENT_SRVID	0
#define CHILD1_SRVID	1
#define CHILD2_SRVID	2

int num_msg=0;

static struct timeval tp1,tp2;

static void start_timer(void)
{
	gettimeofday(&tp1,NULL);
}

static double end_timer(void)
{
	gettimeofday(&tp2,NULL);
	return (tp2.tv_sec + (tp2.tv_usec*1.0e-6)) - 
		(tp1.tv_sec + (tp1.tv_usec*1.0e-6));
}

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
	TDB_DATA key, data, data2, store_data;
	int ret;
	struct ctdb_record_handle *h;
 
	/* 
	   test 1 : write data and read it back.   should all be the same
	 */
	printf("Test1: write and verify we can read it back: ");
	key.dptr  = discard_const("Record");
	key.dsize = strlen((const char *)key.dptr)+1;
	h = ctdb_fetch_lock(ctdb_db, ctdb_db, key, &data);
	if (h == NULL) {
		printf("test1: ctdb_fetch_lock() failed\n");
		exit(1);
	}

	store_data.dptr  = discard_const("data to store");
	store_data.dsize = strlen((const char *)store_data.dptr)+1;
	ret = ctdb_record_store(h, store_data);
	talloc_free(h);
	if (ret!=0) {
		printf("test1: ctdb_record_store() failed\n");
		exit(1);
	}

	h = ctdb_fetch_lock(ctdb_db, ctdb_db, key, &data2);
	if (h == NULL) {
		printf("test1: ctdb_fetch_lock() failed\n");
		exit(1);
	}

	/* hopefully   data2 will now contain the record written above */
	if (!strcmp("data to store", (const char *)data2.dptr)) {
		printf("SUCCESS\n");
	} else {
		printf("FAILURE\n");
		exit(10);
	}
	
	/* just write it back to unlock it */
	ret = ctdb_record_store(h, store_data);
	talloc_free(h);
	if (ret!=0) {
		printf("test1: ctdb_record_store() failed\n");
		exit(1);
	}
}

void child(int srvid, struct event_context *ev, struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db)
{
	TDB_DATA data;
	TDB_DATA key, data2;
	struct ctdb_record_handle *h;

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
	printf("client:%d fetching the record\n",srvid);
	h = ctdb_fetch_lock(ctdb_db, ctdb_db, key, &data2);
	printf("client:%d the record is fetched and locked\n",srvid);
	if (h == NULL) {
		printf("client: ctdb_fetch_lock() failed\n");
		exit(1);
	}
	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), PARENT_SRVID, data);

	/* wait until parent tells us to release the lock */
	while (num_msg==1) {
		event_loop_once(ev);
	}

	printf("child %d terminating\n",srvid);
	exit(10);
	   
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	TDB_DATA data;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
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

	ev = event_context_init(NULL);

	/* initialise ctdb */
	ctdb = ctdb_cmdline_init(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
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
	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), CHILD1_SRVID, data);

	/* wait for child 1 to complete fetching and locking the record */
	while (num_msg!=3) {
		event_loop_once(ev);
	}

	/* now tell child 2 to fetch and lock the same record */
	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), CHILD2_SRVID, data);

	/* wait a while for child 2 to complete fetching and locking the 
	   record, this should fail since the record is already locked
	   by the first child */
	start_timer();
	while ( (end_timer() < 1.0) && (num_msg!=4) ) {
		event_loop_once(ev);
	}
	if (num_msg!=4) {
		printf("Child 2 did not get the lock since it is held by client 1:SUCCESS\n");
	} else {
		printf("Child 2 did get the lock:FAILURE\n");
		exit(10);
	}

	/* send message to child 1 to terminate, which should let child 2
	   get the lock.
	 */
	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), CHILD1_SRVID, data);


	/* wait for a final message from child 2 it has received the lock
	   which indicates success */
	while (num_msg!=4) {
		event_loop_once(ev);
	}
	printf("child 2 aquired the lock after child 1 terminated:SUCCESS\n");

	/* send a message to child 2 to tell it to terminate too */
	ctdb_send_message(ctdb, ctdb_get_vnn(ctdb), CHILD2_SRVID, data);


	printf("Test was SUCCESSFUL\n");

	/* shut it down */
	talloc_free(ctdb);
	return 0;
}
