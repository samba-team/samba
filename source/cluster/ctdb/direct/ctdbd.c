/* 
   standalone ctdb daemon

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
#include "system/wait.h"

static void block_signal(int signum)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, signum);
	sigaction(signum, &act, NULL);
}


/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	const char *nlist = NULL;
	const char *transport = "tcp";
	const char *myaddress = NULL;
	int self_connect=0;
	int daemon_mode=0;
	const char *db_list = "test.tdb";
	char *s, *tok;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "nlist", 0, POPT_ARG_STRING, &nlist, 0, "node list file", "filename" },
		{ "listen", 0, POPT_ARG_STRING, &myaddress, 0, "address to listen on", "address" },
		{ "transport", 0, POPT_ARG_STRING, &transport, 0, "protocol transport", NULL },
		{ "self-connect", 0, POPT_ARG_NONE, &self_connect, 0, "enable self connect", "boolean" },
		{ "daemon", 0, POPT_ARG_NONE, &daemon_mode, 0, "spawn a ctdb daemon", "boolean" },
		{ "dblist", 0, POPT_ARG_STRING, &db_list, 0, "list of databases", NULL },
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

	block_signal(SIGPIPE);

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

	/* attach to the list of databases */
	s = talloc_strdup(ctdb, db_list);
	for (tok=strtok(s, ", "); tok; tok=strtok(NULL, ", ")) {
		struct ctdb_db_context *ctdb_db;
		ctdb_db = ctdb_attach(ctdb, tok, TDB_DEFAULT, 
				      O_RDWR|O_CREAT|O_TRUNC, 0666);
		if (!ctdb_db) {
			printf("ctdb_attach to '%s'failed - %s\n", tok, 
			       ctdb_errstr(ctdb));
			exit(1);
		}
		printf("Attached to database '%s'\n", tok);
	}

	/* start the protocol running */
	ret = ctdb_start(ctdb);

/*	event_loop_wait(ev);*/
	while (1) {
		event_loop_once(ev);
	}

	/* shut it down */
	talloc_free(ev);
	return 0;
}
