/* 
   common commandline code to ctdb test tools

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
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"

/* Handle common command line options for ctdb test progs
 */

static struct {
	const char *nlist;
	const char *transport;
	const char *myaddress;
	const char *socketname;
	int self_connect;
	const char *db_dir;
	int torture;
	const char *logfile;
	const char *events;
	int recovery_daemon;
} ctdb_cmdline = {
	.nlist = NULL,
	.transport = "tcp",
	.myaddress = NULL,
	.socketname = CTDB_PATH,
	.self_connect = 0,
	.db_dir = NULL,
	.torture = 0,
	.logfile = NULL,
	.recovery_daemon = 0,
};

enum {OPT_EVENTSYSTEM=1};

static void ctdb_cmdline_callback(poptContext con, 
				  enum poptCallbackReason reason,
				  const struct poptOption *opt,
				  const char *arg, const void *data)
{
	switch (opt->val) {
	case OPT_EVENTSYSTEM:
		event_set_default_backend(arg);
		break;
	}
}


struct poptOption popt_ctdb_cmdline[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, (void *)ctdb_cmdline_callback },	
	{ "nlist", 0, POPT_ARG_STRING, &ctdb_cmdline.nlist, 0, "node list file", "filename" },
	{ "listen", 0, POPT_ARG_STRING, &ctdb_cmdline.myaddress, 0, "address to listen on", "address" },
	{ "socket", 0, POPT_ARG_STRING, &ctdb_cmdline.socketname, 0, "local socket name", "filename" },
	{ "transport", 0, POPT_ARG_STRING, &ctdb_cmdline.transport, 0, "protocol transport", NULL },
	{ "self-connect", 0, POPT_ARG_NONE, &ctdb_cmdline.self_connect, 0, "enable self connect", "boolean" },
	{ "recovery-daemon", 0, POPT_ARG_NONE, &ctdb_cmdline.recovery_daemon, 0, "enable recovery daemon", "boolean" },
	{ "debug", 'd', POPT_ARG_INT, &LogLevel, 0, "debug level"},
	{ "dbdir", 0, POPT_ARG_STRING, &ctdb_cmdline.db_dir, 0, "directory for the tdb files", NULL },
	{ "torture", 0, POPT_ARG_NONE, &ctdb_cmdline.torture, 0, "enable nastiness in library", NULL },
	{ "logfile", 0, POPT_ARG_STRING, &ctdb_cmdline.logfile, 0, "log file location", "filename" },
	{ "events", 0, POPT_ARG_STRING, NULL, OPT_EVENTSYSTEM, "event system", NULL },
	{ NULL }
};


/*
  startup daemon side of ctdb according to command line options
 */
struct ctdb_context *ctdb_cmdline_init(struct event_context *ev)
{
	struct ctdb_context *ctdb;
	int i, ret;

	if (ctdb_cmdline.nlist == NULL) {
		printf("You must provide a node list with --nlist\n");
		exit(1);
	}

	/* initialise ctdb */
	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	ret = ctdb_set_logfile(ctdb, ctdb_cmdline.logfile);
	if (ret == -1) {
		printf("ctdb_set_logfile failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	if (ctdb_cmdline.self_connect) {
		ctdb_set_flags(ctdb, CTDB_FLAG_SELF_CONNECT);
	}
	if (ctdb_cmdline.torture) {
		ctdb_set_flags(ctdb, CTDB_FLAG_TORTURE);
	}
	if (ctdb_cmdline.recovery_daemon) {
		ctdb_set_flags(ctdb, CTDB_FLAG_RECOVERY);
	}

	ret = ctdb_set_transport(ctdb, ctdb_cmdline.transport);
	if (ret == -1) {
		printf("ctdb_set_transport failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* tell ctdb what address to listen on */
	if (ctdb_cmdline.myaddress) {
		ret = ctdb_set_address(ctdb, ctdb_cmdline.myaddress);
		if (ret == -1) {
			printf("ctdb_set_address failed - %s\n", ctdb_errstr(ctdb));
			exit(1);
		}
	}

	/* tell ctdb the socket address */
	ret = ctdb_set_socketname(ctdb, ctdb_cmdline.socketname);
	if (ret == -1) {
		printf("ctdb_set_socketname failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* tell ctdb what nodes are available */
	ret = ctdb_set_nlist(ctdb, ctdb_cmdline.nlist);
	if (ret == -1) {
		printf("ctdb_set_nlist failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	if (ctdb_cmdline.db_dir) {
		ret = ctdb_set_tdb_dir(ctdb, ctdb_cmdline.db_dir);
		if (ret == -1) {
			printf("ctdb_set_tdb_dir failed - %s\n", ctdb_errstr(ctdb));
			exit(1);
		}
	}

	/* initialize the vnn mapping table */
/*
XXX we currently initialize it to the maximum number of nodes to 
XXX make it behave the same way as previously.  
XXX Once we have recovery working we should initialize this always to 
XXX generation==0 (==invalid) and let the recovery tool populate this 
XXX table for the daemons. 
*/
	ctdb->vnn_map = talloc_zero_size(ctdb, offsetof(struct ctdb_vnn_map, map) + 4*ctdb->num_nodes);
	if (ctdb->vnn_map == NULL) {
		DEBUG(0,(__location__ " Unable to allocate vnn_map structure\n"));
		exit(1);
	}
	ctdb->vnn_map->generation = 1;
	ctdb->vnn_map->size = ctdb->num_nodes;
	for(i=0;i<ctdb->vnn_map->size;i++){
		ctdb->vnn_map->map[i] = i%ctdb->num_nodes;
	}


	return ctdb;
}


/*
  startup a client only ctdb context
 */
struct ctdb_context *ctdb_cmdline_client(struct event_context *ev)
{
	struct ctdb_context *ctdb;
	int ret;

	/* initialise ctdb */
	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	/* tell ctdb the socket address */
	ret = ctdb_set_socketname(ctdb, ctdb_cmdline.socketname);
	if (ret == -1) {
		printf("ctdb_set_socketname failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	ret = ctdb_socket_connect(ctdb);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to connect to daemon\n"));
		talloc_free(ctdb);
		return NULL;
	}

	/* get our config */
	ret = ctdb_ctrl_get_config(ctdb);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to get ctdb config\n"));
		talloc_free(ctdb);
		return NULL;
	}

	return ctdb;
}
