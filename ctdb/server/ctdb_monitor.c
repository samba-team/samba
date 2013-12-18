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

#include "includes.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"

struct ctdb_monitor_state {
	uint32_t monitoring_mode;
	TALLOC_CTX *monitor_context;
	uint32_t next_interval;
};

static void ctdb_check_health(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data);

/*
  setup the notification script
*/
int ctdb_set_notification_script(struct ctdb_context *ctdb, const char *script)
{
	ctdb->notification_script = talloc_strdup(ctdb, script);
	CTDB_NO_MEMORY(ctdb, ctdb->notification_script);
	return 0;
}

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

		ctdb_set_process_name("ctdb_notification");
		debug_extra = talloc_asprintf(NULL, "notification-%s:", event);
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
	struct srvid_request rd;
	const char *state_str = NULL;

	c.pnn = ctdb->pnn;
	c.old_flags = node->flags;

	rd.pnn   = ctdb->pnn;
	rd.srvid = CTDB_SRVID_TAKEOVER_RUN_RESPONSE;

	rddata.dptr = (uint8_t *)&rd;
	rddata.dsize = sizeof(rd);

	if (status == -ECANCELED) {
		DEBUG(DEBUG_ERR,("Monitoring event was cancelled\n"));
		goto after_change_status;
	}

	if (status == -ETIME) {
		ctdb->event_script_timeouts++;

		if (ctdb->event_script_timeouts >= ctdb->tunable.script_timeout_count) {
			DEBUG(DEBUG_ERR, ("Maximum timeout count %u reached for eventscript. Making node unhealthy\n", ctdb->tunable.script_timeout_count));
		} else {
			/* We pretend this is OK. */
			goto after_change_status;
		}
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

	event_add_timed(ctdb->ev, ctdb->monitor->monitor_context, 
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
	DEBUG(DEBUG_ERR,("Node became %s. Ask recovery master %u to perform ip reallocation\n",
			 state_str, ctdb->recovery_master));
	ret = ctdb_daemon_send_message(ctdb, ctdb->recovery_master, CTDB_SRVID_TAKEOVER_RUN, rddata);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to send ip takeover run request message to %u\n", ctdb->recovery_master));
	}
}


static void ctdb_run_startup(struct event_context *ev, struct timed_event *te,
			     struct timeval t, void *private_data);
/*
  called when the startup event script finishes
 */
static void ctdb_startup_callback(struct ctdb_context *ctdb, int status, void *p)
{
	if (status != 0) {
		DEBUG(DEBUG_ERR,("startup event failed\n"));
		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
				timeval_current_ofs(5, 0),
				ctdb_run_startup, ctdb);
		return;
	}

	DEBUG(DEBUG_NOTICE,("startup event OK - enabling monitoring\n"));
	ctdb_set_runstate(ctdb, CTDB_RUNSTATE_RUNNING);
	ctdb->monitor->next_interval = 2;
	ctdb_run_notification_script(ctdb, "startup");

	ctdb->monitor->monitoring_mode = CTDB_MONITORING_ACTIVE;

	event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
			timeval_current_ofs(ctdb->monitor->next_interval, 0),
			ctdb_check_health, ctdb);
}

static void ctdb_run_startup(struct event_context *ev, struct timed_event *te,
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
		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
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
		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
				timeval_current_ofs(5, 0),
				ctdb_run_startup, ctdb);
	}
}

/*
  wait until we have finished initial recoveries before we start the
  monitoring events
 */
static void ctdb_wait_until_recovered(struct event_context *ev, struct timed_event *te, 
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

		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
				     timeval_current_ofs(1, 0), 
				     ctdb_wait_until_recovered, ctdb);
		return;
	}

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		ctdb->db_persistent_startup_generation = INVALID_GENERATION;

		DEBUG(DEBUG_NOTICE,(__location__ " in recovery. Wait one more second\n"));
		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
				     timeval_current_ofs(1, 0), 
				     ctdb_wait_until_recovered, ctdb);
		return;
	}


	if (!fast_start && timeval_elapsed(&ctdb->last_recovery_finished) < (ctdb->tunable.rerecovery_timeout + 3)) {
		ctdb->db_persistent_startup_generation = INVALID_GENERATION;

		DEBUG(DEBUG_NOTICE,(__location__ " wait for pending recoveries to end. Wait one more second.\n"));

		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
				     timeval_current_ofs(1, 0), 
				     ctdb_wait_until_recovered, ctdb);
		return;
	}

	if (ctdb->vnn_map->generation == ctdb->db_persistent_startup_generation) {
		DEBUG(DEBUG_INFO,(__location__ " skip ctdb_recheck_persistent_health() "
				  "until the next recovery\n"));
		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
				     timeval_current_ofs(1, 0),
				     ctdb_wait_until_recovered, ctdb);
		return;
	}

	ctdb->db_persistent_startup_generation = ctdb->vnn_map->generation;
	ret = ctdb_recheck_persistent_health(ctdb);
	if (ret != 0) {
		ctdb->db_persistent_check_errors++;
		if (ctdb->db_persistent_check_errors < ctdb->max_persistent_check_errors) {
			DEBUG(ctdb->db_persistent_check_errors==1?DEBUG_ERR:DEBUG_WARNING,
			      (__location__ "ctdb_recheck_persistent_health() "
			      "failed (%llu of %llu times) - retry later\n",
			      (unsigned long long)ctdb->db_persistent_check_errors,
			      (unsigned long long)ctdb->max_persistent_check_errors));
			event_add_timed(ctdb->ev,
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

	event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
			timeval_current(), ctdb_run_startup, ctdb);
}


/*
  see if the event scripts think we are healthy
 */
static void ctdb_check_health(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	bool skip_monitoring = false;
	int ret = 0;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL ||
	    ctdb->monitor->monitoring_mode == CTDB_MONITORING_DISABLED) {
		skip_monitoring = true;
	} else {
		int i;
		for (i=1; i<=NUM_DB_PRIORITIES; i++) {
			if (ctdb->freeze_handles[i] != NULL) {
				DEBUG(DEBUG_ERR,
				      ("Skip monitoring since databases are frozen\n"));
				skip_monitoring = true;
				break;
			}
		}
	}

	if (skip_monitoring) {
		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
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
		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
				timeval_current_ofs(5, 0),
				ctdb_check_health, ctdb);
	}
}

/* 
  (Temporaily) Disabling monitoring will stop the monitor event scripts
  from running   but node health checks will still occur
*/
void ctdb_disable_monitoring(struct ctdb_context *ctdb)
{
	ctdb->monitor->monitoring_mode = CTDB_MONITORING_DISABLED;
	DEBUG(DEBUG_INFO,("Monitoring has been disabled\n"));
}

/* 
   Re-enable running monitor events after they have been disabled
 */
void ctdb_enable_monitoring(struct ctdb_context *ctdb)
{
	ctdb->monitor->monitoring_mode  = CTDB_MONITORING_ACTIVE;
	ctdb->monitor->next_interval = 5;
	DEBUG(DEBUG_INFO,("Monitoring has been enabled\n"));
}

/* stop any monitoring 
   this should only be done when shutting down the daemon
*/
void ctdb_stop_monitoring(struct ctdb_context *ctdb)
{
	talloc_free(ctdb->monitor->monitor_context);
	ctdb->monitor->monitor_context = NULL;

	ctdb->monitor->monitoring_mode  = CTDB_MONITORING_DISABLED;
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

	event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
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

	if (c->pnn >= ctdb->num_nodes) {
		DEBUG(DEBUG_ERR,(__location__ " Node %d is invalid, num_nodes :%d\n", c->pnn, ctdb->num_nodes));
		return -1;
	}

	node         = ctdb->nodes[c->pnn];
	old_flags    = node->flags;
	if (c->pnn != ctdb->pnn) {
		c->old_flags  = node->flags;
	}
	node->flags   = c->new_flags & ~NODE_FLAGS_DISCONNECTED;
	node->flags  |= (c->old_flags & NODE_FLAGS_DISCONNECTED);

	/* we dont let other nodes modify our STOPPED status */
	if (c->pnn == ctdb->pnn) {
		node->flags &= ~NODE_FLAGS_STOPPED;
		if (old_flags & NODE_FLAGS_STOPPED) {
			node->flags |= NODE_FLAGS_STOPPED;
		}
	}

	/* we dont let other nodes modify our BANNED status */
	if (c->pnn == ctdb->pnn) {
		node->flags &= ~NODE_FLAGS_BANNED;
		if (old_flags & NODE_FLAGS_BANNED) {
			node->flags |= NODE_FLAGS_BANNED;
		}
	}

	if (node->flags == c->old_flags) {
		DEBUG(DEBUG_INFO, ("Control modflags on node %u - Unchanged - flags 0x%x\n", c->pnn, node->flags));
		return 0;
	}

	DEBUG(DEBUG_INFO, ("Control modflags on node %u - flags now 0x%x\n", c->pnn, node->flags));

	if (node->flags == 0 && ctdb->runstate <= CTDB_RUNSTATE_STARTUP) {
		DEBUG(DEBUG_ERR, (__location__ " Node %u became healthy - force recovery for startup\n",
				  c->pnn));
		ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
	}

	/* tell the recovery daemon something has changed */
	ctdb_daemon_send_message(ctdb, ctdb->pnn,
				 CTDB_SRVID_SET_NODE_FLAGS, indata);

	/* if we have become banned, we should go into recovery mode */
	if ((node->flags & NODE_FLAGS_BANNED) && !(c->old_flags & NODE_FLAGS_BANNED) && (node->pnn == ctdb->pnn)) {
		ctdb_local_node_got_banned(ctdb);
	}
	
	return 0;
}

/*
  return the monitoring mode
 */
int32_t ctdb_monitoring_mode(struct ctdb_context *ctdb)
{
	if (ctdb->monitor == NULL) {
		return CTDB_MONITORING_DISABLED;
	}
	return ctdb->monitor->monitoring_mode;
}

/*
 * Check if monitoring has been stopped
 */
bool ctdb_stopped_monitoring(struct ctdb_context *ctdb)
{
	return (ctdb->monitor->monitor_context == NULL ? true : false);
}
