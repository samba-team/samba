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

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/time.h"
#include "lib/util/debug.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/cmdline.h"
#include "common/common.h"
#include "common/logging.h"

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

enum my_functions {FUNC_INCR=1, FUNC_FETCH=2};

/*
  ctdb call function to increment an integer
*/
static int incr_func(struct ctdb_call_info *call)
{
	if (call->record_data.dsize == 0) {
		call->new_data = talloc(call, TDB_DATA);
		if (call->new_data == NULL) {
			return ENOMEM;
		}
		call->new_data->dptr = talloc_size(call, 4);
		call->new_data->dsize = 4;
		*(uint32_t *)call->new_data->dptr = 0;
	} else {
		call->new_data = &call->record_data;
	}
	(*(uint32_t *)call->new_data->dptr)++;
	return 0;
}

/*
  ctdb call function to fetch a record
*/
static int fetch_func(struct ctdb_call_info *call)
{
	call->reply_data = &call->record_data;
	return 0;
}


struct bench_data {
	struct ctdb_context *ctdb;
	struct tevent_context *ev;
	int msg_count;
	int msg_plus, msg_minus;
};

/*
  handler for messages in bench_ring()
*/
static void ring_message_handler(uint64_t srvid, TDB_DATA data,
				 void *private_data)
{
	struct bench_data *bdata = talloc_get_type_abort(
		private_data, struct bench_data);
	int incr = *(int *)data.dptr;
	int dest;

	bdata->msg_count++;
	dest = (ctdb_get_pnn(bdata->ctdb) + num_nodes + incr) % num_nodes;
	ctdb_client_send_message(bdata->ctdb, dest, srvid, data);
	if (incr == 1) {
		bdata->msg_plus++;
	} else {
		bdata->msg_minus++;
	}
}


static void send_start_messages(struct ctdb_context *ctdb, int incr)
{
	/* two messages are injected into the ring, moving
	   in opposite directions */
	int dest;
	TDB_DATA data;
		
	data.dptr = (uint8_t *)&incr;
	data.dsize = sizeof(incr);

	dest = (ctdb_get_pnn(ctdb) + num_nodes + incr) % num_nodes;
	ctdb_client_send_message(ctdb, dest, 0, data);
}

static void each_second(struct tevent_context *ev, struct tevent_timer *te,
			struct timeval t, void *private_data)
{
	struct bench_data *bdata = talloc_get_type_abort(
		private_data, struct bench_data);

	/* we kickstart the ring into action by inserting messages from node
	   with pnn 0.
	   it may happen that some other node does not yet have ctdb_bench
	   running in which case the ring is broken and the messages are lost.
	   if so, once every second try again to restart the ring
	*/
	if (bdata->msg_plus == 0) {
//		printf("no messages recevied, try again to kickstart the ring in forward direction...\n");
		send_start_messages(bdata->ctdb, 1);
	}
	if (bdata->msg_minus == 0) {
//		printf("no messages recevied, try again to kickstart the ring in reverse direction...\n");
		send_start_messages(bdata->ctdb, -1);
	}
	tevent_add_timer(bdata->ev, bdata, timeval_current_ofs(1, 0),
			 each_second, bdata);
}

static void dummy_event(struct tevent_context *ev, struct tevent_timer *te,
			struct timeval t, void *private_data)
{
	struct bench_data *bdata = talloc_get_type_abort(
		private_data, struct bench_data);

	tevent_add_timer(bdata->ev, bdata, timeval_current_ofs(1, 0),
			 dummy_event, bdata);
}

/*
  benchmark sending messages in a ring around the nodes
*/
static void bench_ring(struct bench_data *bdata)
{
	int pnn = ctdb_get_pnn(bdata->ctdb);

	if (pnn == 0) {
		tevent_add_timer(bdata->ev, bdata, timeval_current_ofs(1, 0),
				 each_second, bdata);
	} else {
		tevent_add_timer(bdata->ev, bdata, timeval_current_ofs(1, 0),
				 dummy_event, bdata);
	}

	start_timer();
	while (end_timer() < timelimit) {
		if (pnn == 0 && bdata->msg_count % 10000 == 0 && end_timer() > 0) {
			printf("Ring: %.2f msgs/sec (+ve=%d -ve=%d)\r",
			       bdata->msg_count/end_timer(),
			       bdata->msg_plus, bdata->msg_minus);
			fflush(stdout);
		}
		tevent_loop_once(bdata->ev);
	}

	printf("Ring: %.2f msgs/sec (+ve=%d -ve=%d)\n",
	       bdata->msg_count/end_timer(),
	       bdata->msg_plus, bdata->msg_minus);
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
	int ret;
	poptContext pc;
	struct tevent_context *ev;
	struct bench_data *bdata;

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

	if (num_nodes == 0) {
		printf("You must specify the number of nodes\n");
		exit(1);
	}

	ev = tevent_context_init(NULL);

	/* initialise ctdb */
	ctdb = ctdb_cmdline_client(ev, timeval_current_ofs(3, 0));
	if (ctdb == NULL) {
		exit(1);
	}

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, timeval_current_ofs(2, 0), "test.tdb",
			      false, 0);
	if (!ctdb_db) {
		printf("ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* setup a ctdb call function */
	ret = ctdb_set_call(ctdb_db, incr_func,  FUNC_INCR);
	if (ret != 0) {
		DEBUG(DEBUG_DEBUG,("ctdb_set_call() failed, ignoring return code %d\n", ret));
	}
	ret = ctdb_set_call(ctdb_db, fetch_func, FUNC_FETCH);
	if (ret != 0) {
		DEBUG(DEBUG_DEBUG,("ctdb_set_call() failed, ignoring return code %d\n", ret));
	}

	bdata = talloc_zero(ctdb, struct bench_data);
	if (bdata == NULL) {
		goto error;
	}
	bdata->ctdb = ctdb;
	bdata->ev = ev;

	if (ctdb_client_set_message_handler(ctdb, 0, ring_message_handler, bdata))
		goto error;

	printf("Waiting for cluster\n");
	while (1) {
		uint32_t recmode=1;
		ctdb_ctrl_getrecmode(ctdb, ctdb, timeval_zero(), CTDB_CURRENT_NODE, &recmode);
		if (recmode == 0) break;
		tevent_loop_once(ev);
	}

	bench_ring(bdata);

error:
	return 0;
}
