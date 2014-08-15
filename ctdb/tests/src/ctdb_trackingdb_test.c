/* 
   simple trackingdb test tool

   This program is used to test the funcitons to manipulate and enumerate
   the trackingdb records :
	ctdb_trackingdb_add_pnn()
	ctdb_trackingdb_traverse()

   Copyright (C) Ronnie Sahlberg 2009

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
#include "system/time.h"
#include "popt.h"
#include "cmdline.h"
#include "ctdb_private.h"
#include "lib/tdb_wrap/tdb_wrap.h"

#define MAXINDEX 64
char indices[MAXINDEX];

static void vn_cb(struct ctdb_context *ctdb, uint32_t pnn, void *private_data)
{
	char *ind = private_data;

	printf("Callback for node %d\n", pnn);
	if (ind[pnn] == 0) {
		printf("ERROR, node %d from callback was never added\n", pnn);
		exit(10);
	}
	ind[pnn] = 0;
}

static void verify_nodes(struct ctdb_context *ctdb, TDB_DATA data)
{
	int i;

	printf("Verify the nodes\n");
	ctdb_trackingdb_traverse(ctdb, data, vn_cb, indices);
	for(i = 0; i < MAXINDEX; i++) {
		if (indices[i] != 0) {
			printf("Callback for %d was never invoked\n", i);
			exit(0);
		}
	}
}

	
	
static void add_node(struct ctdb_context *ctdb, TDB_DATA *data, int pnn)
{
	printf("Add node %d\n", pnn);
	if (ctdb_trackingdb_add_pnn(ctdb, data, pnn)) {
		printf("Failed to add tracking db data\n");
		exit(10);
	}
	indices[pnn] = 1;
}

static void trackdb_test(struct ctdb_context *ctdb)
{
	TDB_DATA data = {NULL,0};
	int i;

	printf("Add 10 nodes\n");
	srandom(time(NULL));
	for(i=0; i<10; i++) {
		add_node(ctdb, &data, random()%MAXINDEX);
	}

	verify_nodes(ctdb, data);
	printf("OK all seems well\n");
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

	ctdb = ctdb_cmdline_client(ev, timeval_current_ofs(5, 0));
	if (ctdb == NULL) {
		exit(1);
	}

	trackdb_test(ctdb);

	return 0;
}
