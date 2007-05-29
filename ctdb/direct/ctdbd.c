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
	const char *public_address_list;
	const char *public_interface;
	const char *event_script;
} options = {
	.event_script = "/etc/ctdb/events"
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
