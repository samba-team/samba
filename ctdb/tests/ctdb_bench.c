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
static int num_msgs = 1;

enum my_functions {FUNC_INCR=1, FUNC_FETCH=2};

/*
  ctdb call function to increment an integer
*/
static int incr_func(struct ctdb_call_info *call)
{
	if (call->record_data.dsize == 0) {
		call->new_data = talloc(call, TDB_DATA);
		if (call->new_data == NULL) {
			return CTDB_ERR_NOMEM;
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


static int msg_count;
static int msg_plus, msg_minus;

/*
  handler for messages in bench_ring()
*/
static void ring_message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
				 TDB_DATA data, void *private_data)
{
	int incr = *(int *)data.dptr;
	int *count = (int *)private_data;
	int dest;
	(*count)++;
	dest = (ctdb_get_vnn(ctdb) + incr) % ctdb_get_num_nodes(ctdb);
	ctdb_send_message(ctdb, dest, srvid, data);
	if (incr == 1) {
		msg_plus++;
	} else {
		msg_minus++;
	}
}

/*
  benchmark sending messages in a ring around the nodes
*/
static void bench_ring(struct ctdb_context *ctdb, struct event_context *ev)
{
	int vnn=ctdb_get_vnn(ctdb);

	if (vnn == 0) {
		int i;
		/* two messages are injected into the ring, moving
		   in opposite directions */
		int dest, incr;
		TDB_DATA data;
		
		data.dptr = (uint8_t *)&incr;
		data.dsize = sizeof(incr);

		for (i=0;i<num_msgs;i++) {
			incr = 1;
			dest = (ctdb_get_vnn(ctdb) + incr) % ctdb_get_num_nodes(ctdb);
			ctdb_send_message(ctdb, dest, 0, data);

			incr = -1;
			dest = (ctdb_get_vnn(ctdb) + incr) % ctdb_get_num_nodes(ctdb);
			ctdb_send_message(ctdb, dest, 0, data);
		}
	}
	
	start_timer();

	while (end_timer() < timelimit) {
		if (vnn == 0 && msg_count % 10000 == 0) {
			printf("Ring: %.2f msgs/sec (+ve=%d -ve=%d)\r", 
			       msg_count/end_timer(), msg_plus, msg_minus);
			fflush(stdout);
		}
		event_loop_once(ev);
	}

	printf("Ring: %.2f msgs/sec (+ve=%d -ve=%d)\n", 
	       msg_count/end_timer(), msg_plus, msg_minus);
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
		{ "num-msgs", 'n', POPT_ARG_INT, &num_msgs, 0, "num_msgs", "integer" },
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

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, "test.tdb", TDB_DEFAULT, O_RDWR|O_CREAT|O_TRUNC, 0666);
	if (!ctdb_db) {
		printf("ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* setup a ctdb call function */
	ret = ctdb_set_call(ctdb_db, incr_func,  FUNC_INCR);
	ret = ctdb_set_call(ctdb_db, fetch_func, FUNC_FETCH);

	/* start the protocol running */
	ret = ctdb_start(ctdb);

	ctdb_set_message_handler(ctdb, 0, ring_message_handler,&msg_count);

	/* wait until all nodes are connected (should not be needed
	   outside of test code) */
	ctdb_connect_wait(ctdb);

	bench_ring(ctdb, ev);
       
	/* shut it down */
	ctdb_shutdown(ctdb);

	return 0;
}
