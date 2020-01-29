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
#include "system/syslog.h"

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
#include "common/path.h"
#include "common/logging.h"
#include "common/logging_conf.h"

#include "ctdb_config.h"

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

static struct ctdb_context *ctdb_init(struct tevent_context *ev)
{
	int ret;
	struct ctdb_context *ctdb;

	ctdb = talloc_zero(ev, struct ctdb_context);
	if (ctdb == NULL) {
		DBG_ERR("Memory error\n");
		return NULL;
	}
	ctdb->ev  = ev;

	/* Wrap early to exercise code. */
	ret = reqid_init(ctdb, INT_MAX-200, &ctdb->idr);
	if (ret != 0) {
		D_ERR("reqid_init failed (%s)\n", strerror(ret));
		talloc_free(ctdb);
		return NULL;
	}

	ret = srvid_init(ctdb, &ctdb->srv);
	if (ret != 0) {
		D_ERR("srvid_init failed (%s)\n", strerror(ret));
		talloc_free(ctdb);
		return NULL;
	}

	ctdb->daemon.name = path_socket(ctdb, "ctdbd");
	if (ctdb->daemon.name == NULL) {
		DBG_ERR("Memory allocation error\n");
		talloc_free(ctdb);
		return NULL;
	}

	ctdbd_pidfile = path_pidfile(ctdb, "ctdbd");
	if (ctdbd_pidfile == NULL) {
		DBG_ERR("Memory allocation error\n");
		talloc_free(ctdb);
		return NULL;
	}

	gettimeofday(&ctdb->ctdbd_start_time, NULL);

	gettimeofday(&ctdb->last_recovery_started, NULL);
	gettimeofday(&ctdb->last_recovery_finished, NULL);

	ctdb->recovery_mode    = CTDB_RECOVERY_NORMAL;
	ctdb->recovery_master  = (uint32_t)-1;

	ctdb->upcalls = &ctdb_upcalls;

	ctdb->statistics.statistics_start_time = timeval_current();

	ctdb->capabilities = CTDB_CAP_DEFAULT;

	/*
	 * Initialise this node's PNN to the unknown value.  This will
	 * be set to the correct value by either ctdb_add_node() as
	 * part of loading the nodes file or by
	 * ctdb_tcp_listen_automatic() when the transport is
	 * initialised.  At some point we should de-optimise this and
	 * pull it out into ctdb_start_daemon() so it is done clearly
	 * and only in one place.
	 */
	ctdb->pnn = CTDB_UNKNOWN_PNN;

	ctdb->do_checkpublicip = true;

	return ctdb;
}


/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb = NULL;
	int interactive_opt = 0;
	bool interactive = false;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "interactive", 'i', POPT_ARG_NONE, &interactive_opt, 0,
		  "don't fork, log to stderr", NULL },
		POPT_TABLEEND
	};
	int opt, ret;
	const char **extra_argv;
	poptContext pc;
	struct tevent_context *ev;
	const char *ctdb_base;
	struct conf_context *conf;
	const char *logging_location;
	const char *test_mode;
	bool ok;

	/*
	 * Basic setup
	 */

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

	/* Default value for CTDB_BASE - don't override */
	setenv("CTDB_BASE", CTDB_ETCDIR, 0);
	ctdb_base = getenv("CTDB_BASE");
	if (ctdb_base == NULL) {
		D_ERR("CTDB_BASE not set\n");
		exit(1);
	}

	/*
	 * Command-line option handling
	 */

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			goto fail;
		}
	}

	/* If there are extra arguments then exit with usage message */
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		if (extra_argv[0])  {
			poptPrintHelp(pc, stdout, 0);
			goto fail;
		}
	}

	interactive = (interactive_opt != 0);

	/*
	 * Configuration file handling
	 */

	ret = ctdbd_config_load(ctdb, &conf);
	if (ret != 0) {
		/* ctdbd_config_load() logs the failure */
		goto fail;
	}

	/*
	 * Logging setup/options
	 */

	test_mode = getenv("CTDB_TEST_MODE");

	/* Log to stderr (ignoring configuration) when running as interactive */
	if (interactive) {
		logging_location = "file:";
		setenv("CTDB_INTERACTIVE", "true", 1);
	} else {
		logging_location = logging_conf_location(conf);
	}

	if (strcmp(logging_location, "syslog") != 0 && test_mode == NULL) {
		/* This can help when CTDB logging is misconfigured */
		syslog(LOG_DAEMON|LOG_NOTICE,
		       "CTDB logging to location %s",
		       logging_location);
	}

	/* Initialize logging and set the debug level */
	ok = ctdb_logging_init(ctdb,
			       logging_location,
			       logging_conf_log_level(conf));
	if (!ok) {
		goto fail;
	}
	setenv("CTDB_LOGGING", logging_location, 1);
	setenv("CTDB_DEBUGLEVEL", debug_level_to_string(DEBUGLEVEL), 1);

	script_log_level = debug_level_from_string(
					ctdb_config.script_log_level);

	D_NOTICE("CTDB starting on node\n");

	/*
	 * Cluster setup/options
	 */

	ret = ctdb_set_transport(ctdb, ctdb_config.transport);
	if (ret == -1) {
		D_ERR("ctdb_set_transport failed - %s\n", ctdb_errstr(ctdb));
		goto fail;
	}

	if (ctdb_config.recovery_lock == NULL) {
		D_WARNING("Recovery lock not set\n");
	}
	ctdb->recovery_lock = ctdb_config.recovery_lock;

	/* tell ctdb what address to listen on */
	if (ctdb_config.node_address) {
		ret = ctdb_set_address(ctdb, ctdb_config.node_address);
		if (ret == -1) {
			D_ERR("ctdb_set_address failed - %s\n",
			      ctdb_errstr(ctdb));
			goto fail;
		}
	}

	/* tell ctdb what nodes are available */
	ctdb->nodes_file = talloc_asprintf(ctdb, "%s/nodes", ctdb_base);
	if (ctdb->nodes_file == NULL) {
		DBG_ERR(" Out of memory\n");
		goto fail;
	}
	ctdb_load_nodes_file(ctdb);

	/*
	 * Database setup/options
	 */

	ctdb->db_directory = ctdb_config.dbdir_volatile;
	ok = directory_exist(ctdb->db_directory);
	if (! ok) {
		D_ERR("Volatile database directory %s does not exist\n",
		      ctdb->db_directory);
		goto fail;
	}

	ctdb->db_directory_persistent = ctdb_config.dbdir_persistent;
	ok = directory_exist(ctdb->db_directory_persistent);
	if (! ok) {
		D_ERR("Persistent database directory %s does not exist\n",
		      ctdb->db_directory_persistent);
		goto fail;
	}

	ctdb->db_directory_state = ctdb_config.dbdir_state;
	ok = directory_exist(ctdb->db_directory_state);
	if (! ok) {
		D_ERR("State database directory %s does not exist\n",
		      ctdb->db_directory_state);
		goto fail;
	}

	if (ctdb_config.lock_debug_script != NULL) {
		ret = setenv("CTDB_DEBUG_LOCKS",
			     ctdb_config.lock_debug_script,
			     1);
		if (ret != 0) {
			D_ERR("Failed to set up lock debugging (%s)\n",
			      strerror(errno));
			goto fail;
		}
	}

	/*
	 * Legacy setup/options
	 */

	ctdb->start_as_disabled = (int)ctdb_config.start_as_disabled;
	ctdb->start_as_stopped  = (int)ctdb_config.start_as_stopped;

	/* set ctdbd capabilities */
	if (!ctdb_config.lmaster_capability) {
		ctdb->capabilities &= ~CTDB_CAP_LMASTER;
	}
	if (!ctdb_config.recmaster_capability) {
		ctdb->capabilities &= ~CTDB_CAP_RECMASTER;
	}

	ctdb->do_setsched = ctdb_config.realtime_scheduling;

	/*
	 * Miscellaneous setup
	 */

	ctdb_tunables_set_defaults(ctdb);

	ctdb->event_script_dir = talloc_asprintf(ctdb,
						 "%s/events/legacy",
						 ctdb_base);
	if (ctdb->event_script_dir == NULL) {
		DBG_ERR("Out of memory\n");
		goto fail;
	}

	ctdb->notification_script = talloc_asprintf(ctdb,
						    "%s/notify.sh",
						    ctdb_base);
	if (ctdb->notification_script == NULL) {
		D_ERR("Unable to set notification script\n");
		goto fail;
	}

	/*
	 * Testing and debug options
	 */

	if (test_mode != NULL) {
		ctdb->do_setsched = false;
		ctdb->do_checkpublicip = false;
		fast_start = true;
	}

	/* start the protocol running (as a child) */
	return ctdb_start_daemon(ctdb, interactive, test_mode != NULL);

fail:
	talloc_free(ctdb);
	exit(1);
}
