/* 
   test of messaging

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
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"

static int timelimit = 10;
static int num_records = 10;
static int num_msgs = 1;
static int num_clients = 2;


/*
  handler for messages in bench_ring()
*/
static void message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
				 TDB_DATA data, void *private_data)
{
	printf("client vnn:%d received a message to srvid:%d [%s]\n",ctdb_get_vnn(ctdb),srvid,data.dptr);
	fflush(stdout);
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	char buf[256];

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "timelimit", 't', POPT_ARG_INT, &timelimit, 0, "timelimit", "integer" },
		{ "num-records", 'r', POPT_ARG_INT, &num_records, 0, "num_records", "integer" },
		{ "num-msgs", 'n', POPT_ARG_INT, &num_msgs, 0, "num_msgs", "integer" },
		{ "num-clients", 0, POPT_ARG_INT, &num_clients, 0, "num_clients", "integer" },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int ret, i, j;
	poptContext pc;
	struct event_context *ev;
	pid_t pid;
	int srvid;
	TDB_DATA data;

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

	srvid = -1;
	for (i=0;i<num_clients-1;i++) {
		pid=fork();
		if (pid) {
			srvid = i;
			break;
		}
	}
	if (srvid == -1) {
		srvid = num_clients-1;
	}

	ctdb_set_message_handler(ctdb, srvid, message_handler, NULL);

	/* wait until all nodes are connected (should not be needed
	   outside of test code) */
	ctdb_connect_wait(ctdb);

	sleep(3);

	printf("sending message from vnn:%d to vnn:%d/srvid:%d\n",ctdb_get_vnn(ctdb),ctdb_get_vnn(ctdb), 1-srvid);
	for (i=0;i<ctdb_get_num_nodes(ctdb);i++) {
		for (j=0;j<num_clients;j++) {
			printf("sending message to %d:%d\n", i, j);
			sprintf(buf,"Message from %d to vnn:%d srvid:%d",ctdb_get_vnn(ctdb),i,j);
			data.dptr = (unsigned char *)buf;
			data.dsize=strlen(buf)+1;
			ctdb_send_message(ctdb, i, j, data);
		}
	}

	while (1) {
		event_loop_once(ev);
	}
       
	/* shut it down */
	ctdb_shutdown(ctdb);

	return 0;
}
