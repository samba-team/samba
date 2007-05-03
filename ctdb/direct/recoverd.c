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

void do_recovery(struct ctdb_context *ctdb, struct event_context *ev)
{
	printf("we need to do recovery !!!\n");
}

void recoverd(struct ctdb_context *ctdb, struct event_context *ev)
{
	uint32_t vnn, num_active;
	TALLOC_CTX *mem_ctx=NULL;
	struct ctdb_node_map *nodemap=NULL;
	struct ctdb_node_map *remote_nodemap=NULL;
	struct ctdb_vnn_map *vnnmap=NULL;
	struct ctdb_vnn_map *remote_vnnmap=NULL;
	int i, j, ret;
	
again:
	printf("check if we need to do recovery\n");
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

	/* get number of nodes */
	ret = ctdb_ctrl_getnodemap(ctdb, timeval_current_ofs(1, 0), vnn, mem_ctx, &nodemap);
	if (ret != 0) {
		printf("Unable to get nodemap from node %u\n", vnn);
		goto again;
	}

	/* count how many active nodes there are */
	num_active = 0;
	for (i=0; i<nodemap->num; i++) {
		if (nodemap->nodes[i].flags&NODE_FLAGS_CONNECTED) {
			num_active++;
		}
	}


	/* get the nodemap for all active remote nodes and verify
	   they are the same as for this node
	 */
	for (j=0; j<nodemap->num; j++) {
		if (!(nodemap->nodes[j].flags&NODE_FLAGS_CONNECTED)) {
			continue;
		}
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}

		ret = ctdb_ctrl_getnodemap(ctdb, timeval_current_ofs(1, 0), nodemap->nodes[j].vnn, mem_ctx, &remote_nodemap);
		if (ret != 0) {
			printf("Unable to get nodemap from remote node %u\n", nodemap->nodes[j].vnn);
			goto again;
		}

		/* if the nodes disagree on how many nodes there are
		   then this is a good reason to try recovery
		 */
		if (remote_nodemap->num != nodemap->num) {
			printf("Remote node:%d has different node count. %d vs %d of the local node\n", nodemap->nodes[j].vnn, remote_nodemap->num, nodemap->num);
			do_recovery(ctdb, ev);
			goto again;
		}

		/* if the nodes disagree on which nodes exist and are
		   active, then that is also a good reason to do recovery
		 */
		for (i=0;i<nodemap->num;i++) {
			if ((remote_nodemap->nodes[i].vnn != nodemap->nodes[i].vnn)
			||  (remote_nodemap->nodes[i].flags != nodemap->nodes[i].flags)) {
				printf("Remote node:%d has different nodemap.\n", nodemap->nodes[j].vnn);
				do_recovery(ctdb, ev);
				goto again;
			}
		}

	}

	/* get the vnnmap */
	ret = ctdb_ctrl_getvnnmap(ctdb, timeval_current_ofs(1, 0), vnn, mem_ctx, &vnnmap);
	if (ret != 0) {
		printf("Unable to get vnnmap from node %u\n", vnn);
		goto again;
	}

	/* there better be the same number of lmasters in the vnn map
	   as there are active nodes or well have to do a recovery
	 */
	if (vnnmap->size != num_active) {
		printf("The vnnmap count is different from the number of active nodes. %d vs %d\n", vnnmap->size, num_active);
		do_recovery(ctdb, ev);
		goto again;
	}

	/* verify that all active nodes in the nodemap also exist in 
	   the vnnmap.
	 */
	for (j=0; j<nodemap->num; j++) {
		if (!(nodemap->nodes[j].flags&NODE_FLAGS_CONNECTED)) {
			continue;
		}
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}

		for (i=0; i<vnnmap->size; i++) {
			if (vnnmap->map[i] == nodemap->nodes[j].vnn) {
				break;
			}
		}
		if (i==vnnmap->size) {
			printf("Node %d is active in the nodemap but did not exist in the vnnmap\n", nodemap->nodes[j].vnn);
			do_recovery(ctdb, ev);
			goto again;
		}
	}

	
	/* verify that all other nodes have the same vnnmap */
	for (j=0; j<nodemap->num; j++) {
		if (!(nodemap->nodes[j].flags&NODE_FLAGS_CONNECTED)) {
			continue;
		}
		if (nodemap->nodes[j].vnn == vnn) {
			continue;
		}

		ret = ctdb_ctrl_getvnnmap(ctdb, timeval_current_ofs(1, 0), nodemap->nodes[j].vnn, mem_ctx, &remote_vnnmap);
		if (ret != 0) {
			printf("Unable to get vnnmap from remote node %u\n", nodemap->nodes[j].vnn);
			goto again;
		}

		/* verify the vnnmap size is the same */
		if (vnnmap->size != remote_vnnmap->size) {
			printf("Remote node %d has different size of vnnmap. %d vs %d (ours)\n", nodemap->nodes[j].vnn, remote_vnnmap->size, vnnmap->size);
			do_recovery(ctdb, ev);
			goto again;
		}

		/* verify the vnnmap is the same */
		for (i=0;i<vnnmap->size;i++) {
			if (remote_vnnmap->map[i] != vnnmap->map[i]) {
				printf("Remote node %d has different vnnmap.\n", nodemap->nodes[j].vnn);
				do_recovery(ctdb, ev);
				goto again;
			}
		}
	}

	printf("no we did not need to do recovery\n");
	goto again;

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
