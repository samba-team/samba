/* 
   common commandline code to ctdb test tools

   Copyright (C) Andrew Tridgell  2007

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
#include "popt.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"
#include <ctype.h>

#include "internal/cmdline.h"

/* Handle common command line options for ctdb test progs
 */

static struct {
	const char *socketname;
	const char *debuglevel;
	int torture;
	const char *events;
} ctdb_cmdline = {
	.torture = 0,
	.debuglevel = "ERR",
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
	{ "socket", 0, POPT_ARG_STRING, &ctdb_cmdline.socketname, 0, "local socket name", "filename" },
	{ "debug", 'd', POPT_ARG_STRING, &ctdb_cmdline.debuglevel, 0, "debug level"},
	{ "torture", 0, POPT_ARG_NONE, &ctdb_cmdline.torture, 0, "enable nastiness in library", NULL },
	{ "events", 0, POPT_ARG_STRING, NULL, OPT_EVENTSYSTEM, "event system", NULL },
	{ NULL }
};


/*
  startup daemon side of ctdb according to command line options
 */
struct ctdb_context *ctdb_cmdline_init(struct event_context *ev)
{
	struct ctdb_context *ctdb;
	int ret;

	/* initialise ctdb */
	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	if (ctdb_cmdline.torture) {
		ctdb_set_flags(ctdb, CTDB_FLAG_TORTURE);
	}

	/* command line specified a socket name */
	if (ctdb_cmdline.socketname != NULL) {
		setenv("CTDB_SOCKET", ctdb_cmdline.socketname, 1);
		ret = ctdb_set_socketname(ctdb, ctdb_cmdline.socketname);
		if (ret == -1) {
			printf("ctdb_set_socketname failed - %s\n",
						    ctdb_errstr(ctdb));
			exit(1);
		}
	}

	/* Set the debug level */
	if (isalpha(ctdb_cmdline.debuglevel[0]) || ctdb_cmdline.debuglevel[0] == '-') { 
		DEBUGLEVEL = get_debug_by_desc(ctdb_cmdline.debuglevel);
	} else {
		DEBUGLEVEL = strtol(ctdb_cmdline.debuglevel, NULL, 0);
	}

	/* set up the tree to store server ids */
	ctdb->server_ids = trbt_create(ctdb, 0);

	return ctdb;
}


/*
  startup a client only ctdb context
 */
struct ctdb_context *ctdb_cmdline_client(struct tevent_context *ev,
					 struct timeval req_timeout)
{
	struct ctdb_context *ctdb;
	char *socket_name;
	int ret;

	/* initialise ctdb */
	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		fprintf(stderr, "Failed to init ctdb\n");
		exit(1);
	}

	/* tell ctdb the socket address */
	socket_name = getenv("CTDB_SOCKET");
	if (socket_name != NULL) {
		ret = ctdb_set_socketname(ctdb, socket_name);
		if (ret == -1) {
			printf("ctdb_set_socketname failed - %s\n",
						    ctdb_errstr(ctdb));
			exit(1);
		}
	}

	if (ctdb_cmdline.socketname != NULL) {
		ret = ctdb_set_socketname(ctdb, ctdb_cmdline.socketname);
		if (ret == -1) {
			fprintf(stderr, "ctdb_set_socketname failed - %s\n",
					ctdb_errstr(ctdb));
			exit(1);
		}
	}

	/* Set the debug level */
	if (isalpha(ctdb_cmdline.debuglevel[0]) || ctdb_cmdline.debuglevel[0] == '-') { 
		DEBUGLEVEL = get_debug_by_desc(ctdb_cmdline.debuglevel);
	} else {
		DEBUGLEVEL = strtol(ctdb_cmdline.debuglevel, NULL, 0);
	}

	ret = ctdb_socket_connect(ctdb);
	if (ret != 0) {
		fprintf(stderr, __location__ " Failed to connect to daemon\n");
		talloc_free(ctdb);
		return NULL;
	}

	/* get our pnn */
	ctdb->pnn = ctdb_ctrl_getpnn(ctdb, req_timeout, CTDB_CURRENT_NODE);
	if (ctdb->pnn == (uint32_t)-1) {
		DEBUG(DEBUG_CRIT,(__location__ " Failed to get ctdb pnn\n"));
		talloc_free(ctdb);
		return NULL;
	}

	return ctdb;
}
