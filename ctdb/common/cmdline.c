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
	int self_connect;
	const char *db_dir;
	int torture;
} ctdb_cmdline = {
	.nlist = NULL,
	.transport = "tcp",
	.myaddress = NULL,
	.self_connect = 0,
	.db_dir = NULL,
	.torture = 0
};


struct poptOption popt_ctdb_cmdline[] = {
	{ "nlist", 0, POPT_ARG_STRING, &ctdb_cmdline.nlist, 0, "node list file", "filename" },
	{ "listen", 0, POPT_ARG_STRING, &ctdb_cmdline.myaddress, 0, "address to listen on", "address" },
	{ "transport", 0, POPT_ARG_STRING, &ctdb_cmdline.transport, 0, "protocol transport", NULL },
	{ "self-connect", 0, POPT_ARG_NONE, &ctdb_cmdline.self_connect, 0, "enable self connect", "boolean" },
	{ "debug", 'd', POPT_ARG_INT, &LogLevel, 0, "debug level"},
	{ "dbdir", 0, POPT_ARG_STRING, &ctdb_cmdline.db_dir, 0, "directory for the tdb files", NULL },
	{ "torture", 0, POPT_ARG_NONE, &ctdb_cmdline.torture, 0, "enable nastiness in library", NULL },
	{ NULL }
};


/*
  startup daemon side of ctdb according to command line options
 */
struct ctdb_context *ctdb_cmdline_init(struct event_context *ev)
{
	struct ctdb_context *ctdb;
	int ret;

	if (ctdb_cmdline.nlist == NULL || ctdb_cmdline.myaddress == NULL) {
		printf("You must provide a node list with --nlist and an address with --listen\n");
		exit(1);
	}

	/* initialise ctdb */
	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	if (ctdb_cmdline.self_connect) {
		ctdb_set_flags(ctdb, CTDB_FLAG_SELF_CONNECT);
	}
	if (ctdb_cmdline.torture) {
		ctdb_set_flags(ctdb, CTDB_FLAG_TORTURE);
	}

	ret = ctdb_set_transport(ctdb, ctdb_cmdline.transport);
	if (ret == -1) {
		printf("ctdb_set_transport failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* tell ctdb what address to listen on */
	ret = ctdb_set_address(ctdb, ctdb_cmdline.myaddress);
	if (ret == -1) {
		printf("ctdb_set_address failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* tell ctdb what nodes are available */
	ret = ctdb_set_nlist(ctdb, ctdb_cmdline.nlist);
	if (ret == -1) {
		printf("ctdb_set_nlist failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	ret = ctdb_set_tdb_dir(ctdb, ctdb_cmdline.db_dir);
	if (ret == -1) {
		printf("ctdb_set_tdb_dir failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	return ctdb;
}


/*
  startup a client only ctdb context
 */
struct ctdb_context *ctdb_cmdline_client(struct event_context *ev, const char *ctdb_socket)
{
	struct ctdb_context *ctdb;
	int ret;

	/* initialise ctdb */
	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	ctdb->daemon.name = talloc_strdup(ctdb, ctdb_socket);

	ret = ctdb_socket_connect(ctdb);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to connect to daemon\n"));
		talloc_free(ctdb);
		return NULL;
	}

	return ctdb;
}
