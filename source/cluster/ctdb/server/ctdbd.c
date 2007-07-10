/* 
   standalone ctdb daemon

   Copyright (C) Andrew Tridgell  2006

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
} options = {
	.nlist = ETCDIR "/ctdb/nodes",
	.transport = "tcp",
	.event_script = ETCDIR "/ctdb/events",
	.logfile = VARDIR "/log/log.ctdb",
	.db_dir = VARDIR "/ctdb",
};


/*
  called by the transport layer when a packet comes in
*/
static void ctdb_recv_pkt(struct ctdb_context *ctdb, uint8_t *data, uint32_t length)
{
	struct ctdb_req_header *hdr = (struct ctdb_req_header *)data;

	ctdb->statistics.node_packets_recv++;

	/* up the counter for this source node, so we know its alive */
	if (ctdb_validate_vnn(ctdb, hdr->srcnode)) {
		/* as a special case, redirected calls don't increment the rx_cnt */
		if (hdr->operation != CTDB_REQ_CALL ||
		    ((struct ctdb_req_call *)hdr)->hopcount == 0) {
			ctdb->nodes[hdr->srcnode]->rx_cnt++;
		}
	}

	ctdb_input_pkt(ctdb, hdr);
}



static const struct ctdb_upcalls ctdb_upcalls = {
	.recv_pkt       = ctdb_recv_pkt,
	.node_dead      = ctdb_node_dead,
	.node_connected = ctdb_node_connected
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
		{ "dbdir", 0, POPT_ARG_STRING, &options.db_dir, 0, "directory for the tdb files", NULL },
		{ "reclock", 0, POPT_ARG_STRING, &options.recovery_lock_file, 0, "location of recovery lock file", "filename" },
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

	if (!options.recovery_lock_file) {
		DEBUG(0,("You must specifiy the location of a recovery lock file with --reclock\n"));
		exit(1);
	}

	block_signal(SIGPIPE);

	ev = event_context_init(NULL);

	ctdb = ctdb_cmdline_init(ev);

	ctdb->recovery_mode    = CTDB_RECOVERY_NORMAL;
	ctdb->recovery_master  = (uint32_t)-1;
	ctdb->upcalls          = &ctdb_upcalls;
	ctdb->idr              = idr_init(ctdb);
	ctdb->recovery_lock_fd = -1;
	ctdb->monitoring_mode  = CTDB_MONITORING_ACTIVE;

	ctdb_tunables_set_defaults(ctdb);

	ret = ctdb_set_recovery_lock_file(ctdb, options.recovery_lock_file);
	if (ret == -1) {
		printf("ctdb_set_recovery_lock_file failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
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
