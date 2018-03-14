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

#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"
#include "system/wait.h"
#include "system/network.h"

#include <popt.h>
#include <talloc.h>
/* Allow use of deprecated function tevent_loop_allow_nesting() */
#define TEVENT_DEPRECATED
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#include "ctdb_private.h"

#include "common/reqid.h"
#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

static struct {
	const char *debuglevel;
	const char *transport;
	const char *myaddress;
	const char *notification_script;
	const char *logging;
	const char *recovery_lock;
	const char *db_dir;
	const char *db_dir_persistent;
	const char *db_dir_state;
	int         valgrinding;
	int         nosetsched;
	int         start_as_disabled;
	int         start_as_stopped;
	int         no_lmaster;
	int         no_recmaster;
	int	    script_log_level;
	int         no_publicipcheck;
	int         max_persistent_check_errors;
	int         torture;
} options = {
	.debuglevel = "NOTICE",
	.transport = "tcp",
	.logging = "file:" LOGDIR "/log.ctdb",
	.db_dir = CTDB_VARDIR,
	.db_dir_persistent = CTDB_VARDIR "/persistent",
	.db_dir_state = CTDB_VARDIR "/state",
	.script_log_level = DEBUG_ERR,
};

int script_log_level;
bool fast_start;

/*
  called by the transport layer when a packet comes in
*/
static void ctdb_recv_pkt(struct ctdb_context *ctdb, uint8_t *data, uint32_t length)
{
	struct ctdb_req_header *hdr = (struct ctdb_req_header *)data;

	CTDB_INCREMENT_STAT(ctdb, node_packets_recv);

	/* up the counter for this source node, so we know its alive */
	if (ctdb_validate_pnn(ctdb, hdr->srcnode)) {
		/* as a special case, redirected calls don't increment the rx_cnt */
		if (hdr->operation != CTDB_REQ_CALL ||
		    ((struct ctdb_req_call_old *)hdr)->hopcount == 0) {
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
	const char *ctdb_socket;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "debug", 'd', POPT_ARG_STRING, &options.debuglevel, 0, "debug level", NULL },
		{ "interactive", 'i', POPT_ARG_NONE, &interactive, 0, "don't fork", NULL },
		{ "logging", 0, POPT_ARG_STRING, &options.logging, 0, "logging method to be used", NULL },
		{ "notification-script", 0, POPT_ARG_STRING, &options.notification_script, 0, "notification script", "filename" },
		{ "listen", 0, POPT_ARG_STRING, &options.myaddress, 0, "address to listen on", "address" },
		{ "transport", 0, POPT_ARG_STRING, &options.transport, 0, "protocol transport", NULL },
		{ "dbdir", 0, POPT_ARG_STRING, &options.db_dir, 0, "directory for the tdb files", NULL },
		{ "dbdir-persistent", 0, POPT_ARG_STRING, &options.db_dir_persistent, 0, "directory for persistent tdb files", NULL },
		{ "dbdir-state", 0, POPT_ARG_STRING, &options.db_dir_state, 0, "directory for internal state tdb files", NULL },
		{ "reclock", 0, POPT_ARG_STRING, &options.recovery_lock, 0, "recovery lock", "lock" },
		{ "valgrinding", 0, POPT_ARG_NONE, &options.valgrinding, 0, "disable setscheduler SCHED_FIFO call, use mmap for tdbs", NULL },
		{ "nosetsched", 0, POPT_ARG_NONE, &options.nosetsched, 0, "disable setscheduler SCHED_FIFO call, use mmap for tdbs", NULL },
		{ "start-as-disabled", 0, POPT_ARG_NONE, &options.start_as_disabled, 0, "Node starts in disabled state", NULL },
		{ "start-as-stopped", 0, POPT_ARG_NONE, &options.start_as_stopped, 0, "Node starts in stopped state", NULL },
		{ "no-lmaster", 0, POPT_ARG_NONE, &options.no_lmaster, 0, "disable lmaster role on this node", NULL },
		{ "no-recmaster", 0, POPT_ARG_NONE, &options.no_recmaster, 0, "disable recmaster role on this node", NULL },
		{ "script-log-level", 0, POPT_ARG_INT, &options.script_log_level, 0, "log level of event script output", NULL },
		{ "nopublicipcheck", 0, POPT_ARG_NONE, &options.no_publicipcheck, 0, "don't check we have/don't have the correct public ip addresses", NULL },
		{ "max-persistent-check-errors", 0, POPT_ARG_INT,
		  &options.max_persistent_check_errors, 0,
		  "max allowed persistent check errors (default 0)", NULL },
		{ "sloppy-start", 0, POPT_ARG_NONE, &fast_start, 0, "Do not perform full recovery on start", NULL },
		{ "torture", 0, POPT_ARG_NONE, &options.torture, 0, "enable nastiness in library", NULL },
		POPT_TABLEEND
	};
	int opt, ret;
	const char **extra_argv;
	poptContext pc;
	struct tevent_context *ev;

	/* Environment variable overrides default */
	ctdbd_pidfile = getenv("CTDB_PIDFILE");
	if (ctdbd_pidfile == NULL) {
		ctdbd_pidfile = CTDB_RUNDIR "/ctdbd.pid";
	}

	/* Environment variable overrides default */
	ctdb_socket = getenv("CTDB_SOCKET");
	if (ctdb_socket == NULL) {
		ctdb_socket = CTDB_SOCKET;
	}

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			exit(1);
		}
	}

	/* If there are extra arguments then exit with usage message */
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		if (extra_argv[0])  {
			poptPrintHelp(pc, stdout, 0);
			exit(1);
		}
	}

	talloc_enable_null_tracking();

	fault_setup();

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init() failed\n");
		exit(1);
	}
	tevent_loop_allow_nesting(ev);

	ctdb = ctdb_init(ev);
	if (ctdb == NULL) {
		fprintf(stderr, "Failed to init ctdb\n");
		exit(1);
	}

	if (options.torture == 1) {
		ctdb_set_flags(ctdb, CTDB_FLAG_TORTURE);
	}

	/* Log to stderr when running as interactive */
	if (interactive) {
		options.logging = "file:";
	}

	/* Initialize logging and set the debug level */
	if (!ctdb_logging_init(ctdb, options.logging, options.debuglevel)) {
		exit(1);
	}
	setenv("CTDB_LOGGING", options.logging, 1);
	setenv("CTDB_DEBUGLEVEL", debug_level_to_string(DEBUGLEVEL), 1);

	ret = ctdb_set_socketname(ctdb, ctdb_socket);
	if (ret == -1) {
		DEBUG(DEBUG_ERR, ("ctdb_set_socketname() failed\n"));
		exit(1);
	}

	ctdb->start_as_disabled = options.start_as_disabled;
	ctdb->start_as_stopped  = options.start_as_stopped;

	script_log_level = options.script_log_level;

	DEBUG(DEBUG_NOTICE,("CTDB starting on node\n"));

	gettimeofday(&ctdb->ctdbd_start_time, NULL);
	gettimeofday(&ctdb->last_recovery_started, NULL);
	gettimeofday(&ctdb->last_recovery_finished, NULL);
	ctdb->recovery_mode    = CTDB_RECOVERY_NORMAL;
	ctdb->recovery_master  = (uint32_t)-1;
	ctdb->upcalls          = &ctdb_upcalls;

	if (options.recovery_lock == NULL) {
		DEBUG(DEBUG_WARNING, ("Recovery lock not set\n"));
	}
	ctdb->recovery_lock = options.recovery_lock;

	TALLOC_FREE(ctdb->idr);
	ret = reqid_init(ctdb, 0, &ctdb->idr);;
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("reqid_init failed (%s)\n", strerror(ret)));
		exit(1);
	}

	ctdb_tunables_set_defaults(ctdb);

	ret = ctdb_set_transport(ctdb, options.transport);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,("ctdb_set_transport failed - %s\n",
				 ctdb_errstr(ctdb)));
		exit(1);
	}

	/* tell ctdb what address to listen on */
	if (options.myaddress) {
		ret = ctdb_set_address(ctdb, options.myaddress);
		if (ret == -1) {
			DEBUG(DEBUG_ERR,("ctdb_set_address failed - %s\n",
					 ctdb_errstr(ctdb)));
			exit(1);
		}
	}

	/* set ctdbd capabilities */
	ctdb->capabilities = CTDB_CAP_DEFAULT;
	if (options.no_lmaster != 0) {
		ctdb->capabilities &= ~CTDB_CAP_LMASTER;
	}
	if (options.no_recmaster != 0) {
		ctdb->capabilities &= ~CTDB_CAP_RECMASTER;
	}

	/* Initialise this node's PNN to the unknown value.  This will
	 * be set to the correct value by either ctdb_add_node() as
	 * part of loading the nodes file or by
	 * ctdb_tcp_listen_automatic() when the transport is
	 * initialised.  At some point we should de-optimise this and
	 * pull it out into ctdb_start_daemon() so it is done clearly
	 * and only in one place.
	 */
	ctdb->pnn = -1;

	/* Default value for CTDB_BASE - don't override */
	setenv("CTDB_BASE", CTDB_ETCDIR, 0);

	/* tell ctdb what nodes are available */
	ctdb->nodes_file =
		talloc_asprintf(ctdb, "%s/nodes", getenv("CTDB_BASE"));
	if (ctdb->nodes_file == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		exit(1);
	}
	ctdb_load_nodes_file(ctdb);

	ctdb->db_directory = options.db_dir;
	mkdir_p_or_die(ctdb->db_directory, 0700);

	ctdb->db_directory_persistent = options.db_dir_persistent;
	mkdir_p_or_die(ctdb->db_directory_persistent, 0700);

	ctdb->db_directory_state = options.db_dir_state;
	mkdir_p_or_die(ctdb->db_directory_state, 0700);

	ctdb->event_script_dir = talloc_asprintf(ctdb,
						 "%s/events.d",
						 getenv("CTDB_BASE"));
	if (ctdb->event_script_dir == NULL) {
		DBG_ERR("Out of memory\n");
		exit(1);
	}

	if (options.notification_script != NULL) {
		ret = ctdb_set_notification_script(ctdb, options.notification_script);
		if (ret == -1) {
			DEBUG(DEBUG_ERR,("Unable to setup notification script\n"));
			exit(1);
		}
	}

	ctdb->valgrinding = (options.valgrinding == 1);
	ctdb->do_setsched = (options.nosetsched != 1);
	if (ctdb->valgrinding) {
		ctdb->do_setsched = false;
	}

	ctdb->do_checkpublicip = (options.no_publicipcheck == 0);

	if (options.max_persistent_check_errors < 0) {
		ctdb->max_persistent_check_errors = 0xFFFFFFFFFFFFFFFFLL;
	} else {
		ctdb->max_persistent_check_errors = (uint64_t)options.max_persistent_check_errors;
	}

	/* start the protocol running (as a child) */
	return ctdb_start_daemon(ctdb, interactive?false:true);
}
