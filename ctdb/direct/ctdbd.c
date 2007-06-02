/* 
   standalone ctdb daemon

   Copyright (C) Andrew Tridgell  2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "popt.h"
#include "system/wait.h"
#include "cmdline.h"
#include "../include/ctdb_private.h"

static void block_signal(int signum)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, signum);
	sigaction(signum, &act, NULL);
}

static struct {
	const char *nlist;
	const char *transport;
	const char *myaddress;
	const char *public_address_list;
	const char *public_interface;
	const char *event_script;
	const char *logfile;
	const char *recovery_lock_file;
	const char *db_dir;
	int self_connect;
} options = {
	.nlist = ETCDIR "/ctdb/nodes",
	.transport = "tcp",
	.event_script = ETCDIR "/ctdb/events",
	.logfile = VARDIR "/log/log.ctdb",
	.db_dir = VARDIR "/ctdb",
	.self_connect = 0,
};



/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	int interactive = 0;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "interactive", 'i', POPT_ARG_NONE, &interactive, 0, "don't fork", NULL },
		{ "public-addresses", 0, POPT_ARG_STRING, &options.public_address_list, 0, "public address list file", "filename" },
		{ "public-interface", 0, POPT_ARG_STRING, &options.public_interface, 0, "public interface", "interface"},
		{ "event-script", 0, POPT_ARG_STRING, &options.event_script, 0, "event script", "filename" },
		{ "logfile", 0, POPT_ARG_STRING, &options.logfile, 0, "log file location", "filename" },
		{ "nlist", 0, POPT_ARG_STRING, &options.nlist, 0, "node list file", "filename" },
		{ "listen", 0, POPT_ARG_STRING, &options.myaddress, 0, "address to listen on", "address" },
		{ "transport", 0, POPT_ARG_STRING, &options.transport, 0, "protocol transport", NULL },
		{ "self-connect", 0, POPT_ARG_NONE, &options.self_connect, 0, "enable self connect", "boolean" },
		{ "dbdir", 0, POPT_ARG_STRING, &options.db_dir, 0, "directory for the tdb files", NULL },
		POPT_TABLEEND
	};
	int opt, ret;
	const char **extra_argv;
	int extra_argc = 0;
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

	if (options.self_connect) {
		ctdb_set_flags(ctdb, CTDB_FLAG_SELF_CONNECT);
	}

	ret = ctdb_set_transport(ctdb, options.transport);
	if (ret == -1) {
		printf("ctdb_set_transport failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* tell ctdb what address to listen on */
	if (options.myaddress) {
		ret = ctdb_set_address(ctdb, options.myaddress);
		if (ret == -1) {
			printf("ctdb_set_address failed - %s\n", ctdb_errstr(ctdb));
			exit(1);
		}
	}

	/* tell ctdb what nodes are available */
	ret = ctdb_set_nlist(ctdb, options.nlist);
	if (ret == -1) {
		printf("ctdb_set_nlist failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	if (options.db_dir) {
		ret = ctdb_set_tdb_dir(ctdb, options.db_dir);
		if (ret == -1) {
			printf("ctdb_set_tdb_dir failed - %s\n", ctdb_errstr(ctdb));
			exit(1);
		}
	}

	ret = ctdb_set_logfile(ctdb, options.logfile);
	if (ret == -1) {
		printf("ctdb_set_logfile to %s failed - %s\n", options.logfile, ctdb_errstr(ctdb));
		exit(1);
	}

	if (options.public_interface) {
		ctdb->takeover.interface = talloc_strdup(ctdb, options.public_interface);
		CTDB_NO_MEMORY(ctdb, ctdb->takeover.interface);
	}

	if (options.public_address_list) {
		ret = ctdb_set_public_addresses(ctdb, options.public_address_list);
		if (ret == -1) {
			printf("Unable to setup public address list\n");
			exit(1);
		}
		ctdb->takeover.enabled = true;
	}

	ret = ctdb_set_event_script(ctdb, options.event_script);
	if (ret == -1) {
		printf("Unable to setup event script\n");
		exit(1);
	}

	/* useful default logfile */
	if (ctdb->logfile == NULL) {
		char *name = talloc_asprintf(ctdb, "%s/log.ctdb.vnn%u", 
					     VARDIR, ctdb->vnn);
		ctdb_set_logfile(ctdb, name);
		talloc_free(name);
	}

	/* start the protocol running (as a child) */
	return ctdb_start_daemon(ctdb, interactive?False:True);
}
