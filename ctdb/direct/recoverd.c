/* 
   ctdb recovery daemon

   Copyright (C) Ronnie Sahlberg  2007

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
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"

static int timed_out = 0;

/*
  show usage message
 */
static void usage(void)
{
	printf(
		"Usage: recoverd\n"
		);
	exit(1);
}

void timeout_func(struct event_context *ev, struct timed_event *te, 
	struct timeval t, void *private_data)
{
	timed_out = 1;
}


void recoverd(struct ctdb_context *ctdb, struct event_context *ev)
{
	uint32_t vnn;
	TALLOC_CTX *mem_ctx=NULL;
	struct ctdb_node_map *nodemap=NULL;
	int ret;
	
again:
	if (mem_ctx) {
		talloc_free(mem_ctx);
		mem_ctx = NULL;
	}
	mem_ctx = talloc_new(ctdb);
	if (!mem_ctx) {
		DEBUG(0,("Failed to create temporary context\n"));
		exit(-1);
	}


	/* we only check for recovery once every second */
	timed_out = 0;
	event_add_timed(ctdb->ev, mem_ctx, timeval_current_ofs(1, 0), timeout_func, ctdb);
	while (!timed_out) {
		event_loop_once(ev);
	}


	/* get our vnn number */
	vnn = ctdb_get_vnn(ctdb);  
printf("our node number is :%d\n",vnn);

	/* get number of nodes */
	ret = ctdb_ctrl_getnodemap(ctdb, timeval_current_ofs(1, 0), vnn, mem_ctx, &nodemap);
	if (ret != 0) {
		printf("Unable to get nodemap from node %u\n", vnn);
		goto again;
	}

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

#if 0
	if (extra_argc < 1) {
		usage();
	}
#endif

	ev = event_context_init(NULL);

	/* initialise ctdb */
	ctdb = ctdb_cmdline_client(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}


	recoverd(ctdb, ev);

	return ret;
}
