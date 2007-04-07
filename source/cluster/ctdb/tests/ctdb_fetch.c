/* 
   simple ctdb benchmark

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

#include <sys/time.h>
#include <time.h>

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


static int timelimit = 10;
static int num_records = 10;
static int num_msgs = 1;

static int msg_count;

#define TESTKEY "testkey"

/*
  fetch a record
  store a expanded record
  send a message to next node to tell it to do the same
*/
static void bench_fetch_1node(struct ctdb_context *ctdb)
{
	TDB_DATA key, data, nulldata;
	struct ctdb_record_handle *rec;
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int dest, ret;

	key.dptr = discard_const("testkey");
	key.dsize = strlen((const char *)key.dptr);

	ctdb_db = ctdb_db_handle(ctdb, "test.tdb");

	rec = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
	if (rec == NULL) {
		printf("Failed to fetch record '%s' on node %d\n", 
		       (const char *)key.dptr, ctdb_get_vnn(ctdb));
		talloc_free(tmp_ctx);
		return;
	}

	if (data.dsize > 1000) {
		data.dsize = 0;
	}

	if (data.dsize == 0) {
		data.dptr = (uint8_t *)talloc_asprintf(tmp_ctx, "Test data\n");
	}
	data.dptr = (uint8_t *)talloc_asprintf_append((char *)data.dptr, 
						      "msg_count=%d on node %d\n",
						      msg_count, ctdb_get_vnn(ctdb));
	data.dsize = strlen((const char *)data.dptr)+1;

	ret = ctdb_record_store(rec, data);
	if (ret != 0) {
		printf("Failed to store record\n");
	}

	talloc_free(tmp_ctx);

	/* tell the next node to do the same */
	nulldata.dptr = NULL;
	nulldata.dsize = 0;

	dest = (ctdb_get_vnn(ctdb) + 1) % ctdb_get_num_nodes(ctdb);
	ctdb_send_message(ctdb, dest, 0, nulldata);
}

/*
  handler for messages in bench_ring()
*/
static void message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
			    TDB_DATA data, void *private)
{
	msg_count++;
	bench_fetch_1node(ctdb);
}


/*
  benchmark the following:

  fetch a record
  store a expanded record
  send a message to next node to tell it to do the same

*/
static void bench_fetch(struct ctdb_context *ctdb, struct event_context *ev)
{
	int vnn=ctdb_get_vnn(ctdb);

	if (vnn == ctdb_get_num_nodes(ctdb)-1) {
		bench_fetch_1node(ctdb);
	}
	
	start_timer();

	while (end_timer() < timelimit) {
		if (vnn == 0 && msg_count % 100 == 0) {
			printf("Fetch: %.2f msgs/sec\r", msg_count/end_timer());
			fflush(stdout);
		}
		if (event_loop_once(ev) != 0) {
			printf("Event loop failed!\n");
			break;
		}
	}

	printf("Fetch: %.2f msgs/sec\n", msg_count/end_timer());
}

enum my_functions {FUNC_FETCH=1};

/*
  ctdb call function to fetch a record
*/
static int fetch_func(struct ctdb_call_info *call)
{
	call->reply_data = &call->record_data;
	return 0;
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

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "nlist", 0, POPT_ARG_STRING, &nlist, 0, "node list file", "filename" },
		{ "listen", 0, POPT_ARG_STRING, &myaddress, 0, "address to listen on", "address" },
		{ "transport", 0, POPT_ARG_STRING, &transport, 0, "protocol transport", NULL },
		{ "self-connect", 0, POPT_ARG_NONE, &self_connect, 0, "enable self connect", "boolean" },
		{ "timelimit", 't', POPT_ARG_INT, &timelimit, 0, "timelimit", "integer" },
		{ "num-records", 'r', POPT_ARG_INT, &num_records, 0, "num_records", "integer" },
		{ "num-msgs", 'n', POPT_ARG_INT, &num_msgs, 0, "num_msgs", "integer" },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int ret;
	poptContext pc;
	struct event_context *ev;
	struct ctdb_call call;

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

	ret = ctdb_set_call(ctdb_db, fetch_func, FUNC_FETCH);

	ctdb_set_message_handler(ctdb, message_handler, &msg_count);

	/* start the protocol running */
	ret = ctdb_start(ctdb);

	/* wait until all nodes are connected (should not be needed
	   outside of test code) */
	ctdb_connect_wait(ctdb);

	bench_fetch(ctdb, ev);

	ZERO_STRUCT(call);
	call.key.dptr = discard_const(TESTKEY);
	call.key.dsize = strlen(TESTKEY);

	/* fetch the record */
	call.call_id = FUNC_FETCH;
	call.call_data.dptr = NULL;
	call.call_data.dsize = 0;

	ret = ctdb_call(ctdb_db, &call);
	if (ret == -1) {
		printf("ctdb_call FUNC_FETCH failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	printf("DATA:\n%s\n", (char *)call.reply_data.dptr);

	/* shut it down */
	talloc_free(ctdb);
	return 0;
}
