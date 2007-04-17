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
#include "cmdline.h"

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
	const char *db_list = "test.tdb";
	char *s, *tok;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
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

	block_signal(SIGPIPE);

	ev = event_context_init(NULL);

	ctdb = ctdb_cmdline_init(ev);

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
