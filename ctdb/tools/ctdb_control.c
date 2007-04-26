/* 
   ctdb control tool

   Copyright (C) Andrew Tridgell  2007

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
#include "../include/ctdb_private.h"


/*
  show usage message
 */
static void usage(void)
{
	printf("Usage: ctdb_control [options] <control>\n");
	exit(1);
}

static int control_process_exists(struct ctdb_context *ctdb, int argc, const char **argv)
{
	uint32_t srvid;
	pid_t pid;
	int ret;
	if (argc < 2) {
		usage();
	}

	srvid = strtoul(argv[0], NULL, 0);
	pid   = strtoul(argv[1], NULL, 0);

	ret = ctdb_process_exists(ctdb, srvid, pid);
	if (ret == 0) {
		printf("%u:%u exists\n", srvid, pid);
	} else {
		printf("%u:%u does not exist\n", srvid, pid);
	}
	return ret;
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
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
	const char *control;

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

	if (extra_argc < 1) {
		usage();
	}

	control = extra_argv[0];

	ev = event_context_init(NULL);

	/* initialise ctdb */
	ctdb = ctdb_cmdline_client(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	if (strcmp(control, "process-exists") == 0) {
		ret = control_process_exists(ctdb, extra_argc-1, extra_argv+1);
	} else {
		printf("Unknown control '%s'\n", control);
		exit(1);
	}

	return ret;
}
