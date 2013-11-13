/* 
   simple ctdb benchmark

   Copyright (C) Andrew Tridgell  2006

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
static int num_nodes;
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
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int dest, ret;
	struct ctdb_record_handle *h;

	key.dptr = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);

	ctdb_db = ctdb_db_handle(ctdb, "test.tdb");

	h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
	if (h == NULL) {
		printf("Failed to fetch record '%s' on node %d\n", 
		       (const char *)key.dptr, ctdb_get_pnn(ctdb));
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
						      msg_count, ctdb_get_pnn(ctdb));
	if (data.dptr == NULL) {
		printf("Failed to create record\n");
		talloc_free(tmp_ctx);
		return;
	}
	data.dsize = strlen((const char *)data.dptr)+1;

	ret = ctdb_record_store(h, data);
	talloc_free(h);
	if (ret != 0) {
		printf("Failed to store record\n");
	}

	talloc_free(tmp_ctx);

	/* tell the next node to do the same */
	nulldata.dptr = NULL;
	nulldata.dsize = 0;

	dest = (ctdb_get_pnn(ctdb) + 1) % num_nodes;
	ctdb_client_send_message(ctdb, dest, 0, nulldata);
}

/*
  handler for messages in bench_ring()
*/
static void message_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			    TDB_DATA data, void *private_data)
{
	msg_count++;
	bench_fetch_1node(ctdb);
}


/*
 * timeout handler - noop
 */
static void timeout_handler(struct event_context *ev, struct timed_event *timer,
			    struct timeval curtime, void *private_data)
{
	return;
}

/*
  benchmark the following:

  fetch a record
  store a expanded record
  send a message to next node to tell it to do the same

*/
static void bench_fetch(struct ctdb_context *ctdb, struct event_context *ev)
{
	int pnn=ctdb_get_pnn(ctdb);

	if (pnn == num_nodes - 1) {
		bench_fetch_1node(ctdb);
	}
	
	start_timer();
	event_add_timed(ev, ctdb, timeval_current_ofs(timelimit,0), timeout_handler, NULL);

	while (end_timer() < timelimit) {
		if (pnn == 0 && msg_count % 100 == 0 && end_timer() > 0) {
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

/*
  handler for reconfigure message
*/
static void reconfigure_handler(struct ctdb_context *ctdb, uint64_t srvid, 
				TDB_DATA data, void *private_data)
{
	int *ready = (int *)private_data;
	*ready = 1;
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
		{ "timelimit", 't', POPT_ARG_INT, &timelimit, 0, "timelimit", "integer" },
		{ "num-records", 'r', POPT_ARG_INT, &num_records, 0, "num_records", "integer" },
		{ NULL, 'n', POPT_ARG_INT, &num_nodes, 0, "num_nodes", "integer" },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;
	struct event_context *ev;
	TDB_DATA key, data;
	struct ctdb_record_handle *h;
	int cluster_ready=0;

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

	if (num_nodes == 0) {
		printf("You must specify the number of nodes\n");
		exit(1);
	}

	ev = event_context_init(NULL);
	tevent_loop_allow_nesting(ev);

	ctdb = ctdb_cmdline_client(ev, timeval_current_ofs(3, 0));

	if (ctdb == NULL) {
		printf("failed to connect to ctdb daemon.\n");
		exit(1);
	}

	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_RECONFIGURE, reconfigure_handler, 
				 &cluster_ready);

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, timeval_current_ofs(2, 0), "test.tdb",
			      false, 0);
	if (!ctdb_db) {
		printf("ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	ctdb_client_set_message_handler(ctdb, 0, message_handler, &msg_count);

	printf("Waiting for cluster\n");
	while (1) {
		uint32_t recmode=1;
		ctdb_ctrl_getrecmode(ctdb, ctdb, timeval_zero(), CTDB_CURRENT_NODE, &recmode);
		if (recmode == 0) break;
		event_loop_once(ev);
	}

	/* This test has a race condition. If CTDB receives the message from previous
	 * node, before this node has registered for that message, this node will never
	 * receive that message and will block on receive. Sleeping for some time will
	 * hopefully ensure that the test program on all the nodes register for messages.
	 */
	printf("Sleeping for %d seconds\n", num_nodes);
	sleep(num_nodes);
	bench_fetch(ctdb, ev);

	key.dptr = discard_const(TESTKEY);
	key.dsize = strlen(TESTKEY);

	printf("Fetching final record\n");

	h = ctdb_fetch_lock(ctdb_db, ctdb, key, &data);

	if (h == NULL) {
		printf("Failed to fetch record '%s' on node %d\n", 
		       (const char *)key.dptr, ctdb_get_pnn(ctdb));
		exit(1);
	}

	printf("DATA:\n%s\n", (char *)data.dptr);

	return 0;
}
