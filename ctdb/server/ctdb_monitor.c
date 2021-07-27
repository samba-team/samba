/* 
   monitoring links to all other nodes to detect dead nodes


   Copyright (C) Ronnie Sahlberg 2007

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
#include "system/network.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/util_process.h"

#include "ctdb_private.h"

#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

struct ctdb_monitor_state {
	TALLOC_CTX *monitor_context;
	uint32_t next_interval;
	uint32_t event_script_timeouts;
};

static void ctdb_check_health(struct tevent_context *ev,
			      struct tevent_timer *te,
			      struct timeval t, void *private_data);

static int ctdb_run_notification_script_child(struct ctdb_context *ctdb, const char *event)
{
	struct stat st;
	int ret;
	char *cmd;

	if (stat(ctdb->notification_script, &st) != 0) {
		DEBUG(DEBUG_ERR,("Could not stat notification script %s. Can not send notifications.\n", ctdb->notification_script));
		return -1;
	}
	if (!(st.st_mode & S_IXUSR)) {
		DEBUG(DEBUG_ERR,("Notification script %s is not executable.\n", ctdb->notification_script));
		return -1;
	}

	cmd = talloc_asprintf(ctdb, "%s %s\n", ctdb->notification_script, event);
	CTDB_NO_MEMORY(ctdb, cmd);

	ret = system(cmd);
	/* if the system() call was successful, translate ret into the
	   return code from the command
	*/
	if (ret != -1) {
		ret = WEXITSTATUS(ret);
	}
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Notification script \"%s\" failed with error %d\n", cmd, ret));
	}

	return ret;
}

void ctdb_run_notification_script(struct ctdb_context *ctdb, const char *event)
{
	pid_t child;

	if (ctdb->notification_script == NULL) {
		return;
	}

	child = ctdb_fork(ctdb);
	if (child == (pid_t)-1) {
		DEBUG(DEBUG_ERR,("Failed to fork() a notification child process\n"));
		return;
	}
	if (child == 0) {
		int ret;

		prctl_set_comment("ctdb_notification");
		ret = ctdb_run_notification_script_child(ctdb, event);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Notification script failed\n"));
		}
		_exit(0);
	}

	return;
}

/*
  called when a health monitoring event script finishes
 */
static void ctdb_health_callback(struct ctdb_context *ctdb, int status, void *p)
{
	struct ctdb_node *node = ctdb->nodes[ctdb->pnn];
	TDB_DATA data;
	struct ctdb_node_flag_change c;
	uint32_t next_interval;
	int ret;
	TDB_DATA rddata;
	struct ctdb_srvid_message rd;
	const char *state_str = NULL;

	c.pnn = ctdb->pnn;
	c.old_flags = node->flags;

	ZERO_STRUCT(rd);
	rd.pnn   = ctdb->pnn;
	rd.srvid = 0;

	rddata.dptr = (uint8_t *)&rd;
	rddata.dsize = sizeof(rd);

	if (status == ECANCELED) {
		DEBUG(DEBUG_ERR,("Monitoring event was cancelled\n"));
		goto after_change_status;
	}

	if (status == ETIMEDOUT) {
		ctdb->monitor->event_script_timeouts++;

		if (ctdb->monitor->event_script_timeouts >=
		    ctdb->tunable.monitor_timeout_count) {
			DEBUG(DEBUG_ERR,
			      ("Maximum monitor timeout count %u reached."
			       " Making node unhealthy\n",
			       ctdb->tunable.monitor_timeout_count));
		} else {
			/* We pretend this is OK. */
			goto after_change_status;
		}
	} else {
		ctdb->monitor->event_script_timeouts = 0;
	}

	if (status != 0 && !(node->flags & NODE_FLAGS_UNHEALTHY)) {
		DEBUG(DEBUG_NOTICE,("monitor event failed - disabling node\n"));
		node->flags |= NODE_FLAGS_UNHEALTHY;
		ctdb->monitor->next_interval = 5;

		ctdb_run_notification_script(ctdb, "unhealthy");
	} else if (status == 0 && (node->flags & NODE_FLAGS_UNHEALTHY)) {
		DEBUG(DEBUG_NOTICE,("monitor event OK - node re-enabled\n"));
		node->flags &= ~NODE_FLAGS_UNHEALTHY;
		ctdb->monitor->next_interval = 5;

		ctdb_run_notification_script(ctdb, "healthy");
	}

after_change_status:
	next_interval = ctdb->monitor->next_interval;

	ctdb->monitor->next_interval *= 2;
	if (ctdb->monitor->next_interval > ctdb->tunable.monitor_interval) {
		ctdb->monitor->next_interval = ctdb->tunable.monitor_interval;
	}

	tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
			 timeval_current_ofs(next_interval, 0),
			 ctdb_check_health, ctdb);

	if (c.old_flags == node->flags) {
		return;
	}

	c.new_flags = node->flags;

	data.dptr = (uint8_t *)&c;
	data.dsize = sizeof(c);

	/* ask the recovery daemon to push these changes out to all nodes */
	ctdb_daemon_send_message(ctdb, ctdb->pnn,
				 CTDB_SRVID_PUSH_NODE_FLAGS, data);

	if (c.new_flags & NODE_FLAGS_UNHEALTHY) {
		state_str = "UNHEALTHY";
	} else {
		state_str = "HEALTHY";
	}

	/* ask the recmaster to reallocate all addresses */
	DEBUG(DEBUG_ERR,
	      ("Node became %s. Ask recovery master to reallocate IPs\n",
	       state_str));
	ret = ctdb_daemon_send_message(ctdb, CTDB_BROADCAST_CONNECTED, CTDB_SRVID_TAKEOVER_RUN, rddata);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      (__location__
		       " Failed to send IP takeover run request\n"));
	}
}


static void ctdb_run_startup(struct tevent_context *ev,
			     struct tevent_timer *te,
			     struct timeval t, void *private_data);
/*
  called when the startup event script finishes
 */
static void ctdb_startup_callback(struct ctdb_context *ctdb, int status, void *p)
{
	if (status != 0) {
		DEBUG(DEBUG_ERR,("startup event failed\n"));
		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(5, 0),
				 ctdb_run_startup, ctdb);
		return;
	}

	DEBUG(DEBUG_NOTICE,("startup event OK - enabling monitoring\n"));
	ctdb_set_runstate(ctdb, CTDB_RUNSTATE_RUNNING);
	ctdb->monitor->next_interval = 2;
	ctdb_run_notification_script(ctdb, "startup");

	/* tell all other nodes we've just started up */
	ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_CONNECTED,
				 0, CTDB_CONTROL_STARTUP, 0,
				 CTDB_CTRL_FLAG_NOREPLY,
				 tdb_null, NULL, NULL);

	tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
			 timeval_current_ofs(ctdb->monitor->next_interval, 0),
			 ctdb_check_health, ctdb);
}

static void ctdb_run_startup(struct tevent_context *ev,
			     struct tevent_timer *te,
			     struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data,
						    struct ctdb_context);
	int ret;

	/* This is necessary to avoid the "startup" event colliding
	 * with the "ipreallocated" event from the takeover run
	 * following the first recovery.  We might as well serialise
	 * these things if we can.
	 */
	if (ctdb->runstate < CTDB_RUNSTATE_STARTUP) {
		DEBUG(DEBUG_NOTICE,
		      ("Not yet in startup runstate. Wait one more second\n"));
		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(1, 0),
				 ctdb_run_startup, ctdb);
		return;
	}

	DEBUG(DEBUG_NOTICE,("Running the \"startup\" event.\n"));
	ret = ctdb_event_script_callback(ctdb,
					 ctdb->monitor->monitor_context,
					 ctdb_startup_callback,
					 ctdb, CTDB_EVENT_STARTUP, "%s", "");

	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unable to launch startup event script\n"));
		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(5, 0),
				 ctdb_run_startup, ctdb);
	}
}

/*
  wait until we have finished initial recoveries before we start the
  monitoring events
 */
static void ctdb_wait_until_recovered(struct tevent_context *ev,
				      struct tevent_timer *te,
				      struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int ret;
	static int count = 0;

	count++;

	if (count < 60 || count%600 == 0) { 
		DEBUG(DEBUG_NOTICE,("CTDB_WAIT_UNTIL_RECOVERED\n"));
		if (ctdb->nodes[ctdb->pnn]->flags & NODE_FLAGS_STOPPED) {
			DEBUG(DEBUG_NOTICE,("Node is STOPPED. Node will NOT recover.\n"));
		}
	}

	if (ctdb->vnn_map->generation == INVALID_GENERATION) {
		ctdb->db_persistent_startup_generation = INVALID_GENERATION;

		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(1, 0),
				 ctdb_wait_until_recovered, ctdb);
		return;
	}

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		ctdb->db_persistent_startup_generation = INVALID_GENERATION;

		DEBUG(DEBUG_NOTICE,(__location__ " in recovery. Wait one more second\n"));
		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(1, 0),
				 ctdb_wait_until_recovered, ctdb);
		return;
	}


	if (!fast_start && timeval_elapsed(&ctdb->last_recovery_finished) < (ctdb->tunable.rerecovery_timeout + 3)) {
		ctdb->db_persistent_startup_generation = INVALID_GENERATION;

		DEBUG(DEBUG_NOTICE,(__location__ " wait for pending recoveries to end. Wait one more second.\n"));

		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(1, 0),
				 ctdb_wait_until_recovered, ctdb);
		return;
	}

	if (ctdb->vnn_map->generation == ctdb->db_persistent_startup_generation) {
		DEBUG(DEBUG_INFO,(__location__ " skip ctdb_recheck_persistent_health() "
				  "until the next recovery\n"));
		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(1, 0),
				 ctdb_wait_until_recovered, ctdb);
		return;
	}

	ctdb->db_persistent_startup_generation = ctdb->vnn_map->generation;
	ret = ctdb_recheck_persistent_health(ctdb);
	if (ret != 0) {
		ctdb->db_persistent_check_errors++;
		if (ctdb->db_persistent_check_errors < ctdb->max_persistent_check_errors) {
			DEBUG(DEBUG_ERR,
			      (__location__ "ctdb_recheck_persistent_health() "
			      "failed (%llu of %llu times) - retry later\n",
			      (unsigned long long)ctdb->db_persistent_check_errors,
			      (unsigned long long)ctdb->max_persistent_check_errors));
			tevent_add_timer(ctdb->ev,
					 ctdb->monitor->monitor_context,
					 timeval_current_ofs(1, 0),
					 ctdb_wait_until_recovered, ctdb);
			return;
		}
		DEBUG(DEBUG_ALERT,(__location__
				  "ctdb_recheck_persistent_health() failed (%llu times) - prepare shutdown\n",
				  (unsigned long long)ctdb->db_persistent_check_errors));
		ctdb_shutdown_sequence(ctdb, 11);
		/* In case above returns due to duplicate shutdown */
		return;
	}
	ctdb->db_persistent_check_errors = 0;

	tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
			 timeval_current(), ctdb_run_startup, ctdb);
}


/*
  see if the event scripts think we are healthy
 */
static void ctdb_check_health(struct tevent_context *ev,
			      struct tevent_timer *te,
			      struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	bool skip_monitoring = false;
	int ret = 0;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL ||
	    ctdb->nodes[ctdb->pnn]->flags & NODE_FLAGS_INACTIVE ||
	    ctdb->runstate != CTDB_RUNSTATE_RUNNING) {
		skip_monitoring = true;
	} else {
		if (ctdb_db_all_frozen(ctdb)) {
			DEBUG(DEBUG_ERR,
			      ("Skip monitoring since databases are frozen\n"));
			skip_monitoring = true;
		}
	}

	if (skip_monitoring) {
		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(ctdb->monitor->next_interval, 0),
				 ctdb_check_health, ctdb);
		return;
	}

	ret = ctdb_event_script_callback(ctdb,
					 ctdb->monitor->monitor_context,
					 ctdb_health_callback,
					 ctdb, CTDB_EVENT_MONITOR, "%s", "");
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unable to launch monitor event script\n"));
		ctdb->monitor->next_interval = 5;
		tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
				 timeval_current_ofs(5, 0),
				 ctdb_check_health, ctdb);
	}
}

/* stop any monitoring 
   this should only be done when shutting down the daemon
*/
void ctdb_stop_monitoring(struct ctdb_context *ctdb)
{
	if (ctdb->monitor == NULL) {
		D_NOTICE("Monitoring not yet initialised\n");
		return;
	}

	TALLOC_FREE(ctdb->monitor->monitor_context);

	ctdb->monitor->next_interval = 5;
	DEBUG(DEBUG_NOTICE,("Monitoring has been stopped\n"));
}

/*
  start watching for nodes that might be dead
 */
void ctdb_wait_for_first_recovery(struct ctdb_context *ctdb)
{
	ctdb_set_runstate(ctdb, CTDB_RUNSTATE_FIRST_RECOVERY);

	ctdb->monitor = talloc(ctdb, struct ctdb_monitor_state);
	CTDB_NO_MEMORY_FATAL(ctdb, ctdb->monitor);

	ctdb->monitor->monitor_context = talloc_new(ctdb->monitor);
	CTDB_NO_MEMORY_FATAL(ctdb, ctdb->monitor->monitor_context);

	tevent_add_timer(ctdb->ev, ctdb->monitor->monitor_context,
			 timeval_current_ofs(1, 0),
			 ctdb_wait_until_recovered, ctdb);
}


/*
  modify flags on a node
 */
int32_t ctdb_control_modflags(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_node_flag_change *c = (struct ctdb_node_flag_change *)indata.dptr;
	struct ctdb_node *node;
	uint32_t old_flags;

	/*
	 * Don't let other nodes override the current node's flags.
	 * The recovery master fetches flags from this node so there's
	 * no need to push them back.  Doing so is racy.
	 */
	if (c->pnn == ctdb->pnn) {
		DBG_DEBUG("Ignoring flag changes for current node\n");
		return 0;
	}

	node = ctdb_find_node(ctdb, c->pnn);
	if (node == NULL) {
		DBG_ERR("Node %u is invalid\n", c->pnn);
		return -1;
	}

	if (node->flags & NODE_FLAGS_DISCONNECTED) {
		DBG_DEBUG("Ignoring flag changes for disconnected node\n");
		return 0;
	}

	/*
	 * Remember the old flags.  We don't care what some other node
	 * thought the old flags were - that's irrelevant.
	 */
	old_flags = node->flags;

	/*
	 * This node tracks nodes it is connected to, so don't let
	 * another node override this
	 */
	node->flags =
		(old_flags & NODE_FLAGS_DISCONNECTED) |
		(c->new_flags & ~NODE_FLAGS_DISCONNECTED);

	if (node->flags == old_flags) {
		return 0;
	}

	D_NOTICE("Node %u has changed flags - 0x%x -> 0x%x\n",
		 c->pnn,
		 old_flags,
		 node->flags);

	if (node->flags == 0 && ctdb->runstate <= CTDB_RUNSTATE_STARTUP) {
		DBG_ERR("Node %u became healthy - force recovery for startup\n",
			c->pnn);
		ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
	}

	return 0;
}
