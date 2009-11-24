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
#include "lib/events/events.h"
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

static void ctdb_run_notification_script(struct ctdb_context *ctdb, const char *event)
{
	pid_t child;

	if (ctdb->notification_script == NULL) {
		return;
	}

	child = fork();
	if (child == (pid_t)-1) {
		DEBUG(DEBUG_ERR,("Failed to fork() a notification child process\n"));
		return;
	}
	if (child == 0) {
		int ret;

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
	struct takeover_run_reply rd;

	c.pnn = ctdb->pnn;
	c.old_flags = node->flags;

	rd.pnn   = ctdb->pnn;
	rd.srvid = CTDB_SRVID_TAKEOVER_RUN_RESPONSE;

	rddata.dptr = (uint8_t *)&rd;
	rddata.dsize = sizeof(rd);

	if (status != 0 && !(node->flags & NODE_FLAGS_UNHEALTHY)) {
		DEBUG(DEBUG_NOTICE,("monitor event failed - disabling node\n"));
		node->flags |= NODE_FLAGS_UNHEALTHY;
		ctdb->monitor->next_interval = 5;
		if (ctdb->tunable.disable_when_unhealthy != 0) {
			DEBUG(DEBUG_INFO, ("DISABLING node since it became unhealthy\n"));
			node->flags |= NODE_FLAGS_DISABLED;
		}

		ctdb_run_notification_script(ctdb, "unhealthy");

		/* ask the recmaster to reallocate all addresses */
		DEBUG(DEBUG_ERR,("Node became UNHEALTHY. Ask recovery master %u to perform ip reallocation\n", ctdb->recovery_master));
		ret = ctdb_daemon_send_message(ctdb, ctdb->recovery_master, CTDB_SRVID_TAKEOVER_RUN, rddata);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to send ip takeover run request message to %u\n", ctdb->recovery_master));
		}

	} else if (status == 0 && (node->flags & NODE_FLAGS_UNHEALTHY)) {
		DEBUG(DEBUG_NOTICE,("monitor event OK - node re-enabled\n"));
		node->flags &= ~NODE_FLAGS_UNHEALTHY;
		ctdb->monitor->next_interval = 5;

		ctdb_run_notification_script(ctdb, "healthy");

		/* ask the recmaster to reallocate all addresses */
		DEBUG(DEBUG_ERR,("Node became HEALTHY. Ask recovery master %u to perform ip reallocation\n", ctdb->recovery_master));
		ret = ctdb_daemon_send_message(ctdb, ctdb->recovery_master, CTDB_SRVID_TAKEOVER_RUN, rddata);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to send ip takeover run request message to %u\n", ctdb->recovery_master));
		}

	}

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

}


/*
  called when the startup event script finishes
 */
static void ctdb_startup_callback(struct ctdb_context *ctdb, int status, void *p)
{
	if (status != 0) {
		DEBUG(DEBUG_ERR,("startup event failed\n"));
	} else if (status == 0) {
		DEBUG(DEBUG_NOTICE,("startup event OK - enabling monitoring\n"));
		ctdb->done_startup = true;
		ctdb->monitor->next_interval = 5;
		ctdb_run_notification_script(ctdb, "startup");
	}

	event_add_timed(ctdb->ev, ctdb->monitor->monitor_context, 
			timeval_current_ofs(ctdb->monitor->next_interval, 0),
			ctdb_check_health, ctdb);
}


/*
  see if the event scripts think we are healthy
 */
static void ctdb_check_health(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int ret = 0;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL ||
	    (ctdb->monitor->monitoring_mode == CTDB_MONITORING_DISABLED && ctdb->done_startup)) {
		event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
				timeval_current_ofs(ctdb->monitor->next_interval, 0), 
				ctdb_check_health, ctdb);
		return;
	}
	
	if (!ctdb->done_startup) {
		ret = ctdb_event_script_callback(ctdb, 
						 ctdb->monitor->monitor_context, ctdb_startup_callback, 
						 ctdb, "startup");
	} else {
		int i;
		int skip_monitoring = 0;
		
		if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
			skip_monitoring = 1;
			DEBUG(DEBUG_ERR,("Skip monitoring during recovery\n"));
		}
		for (i=1; i<=NUM_DB_PRIORITIES; i++) {
			if (ctdb->freeze_handles[i] != NULL) {
				DEBUG(DEBUG_ERR,("Skip monitoring since databases are frozen\n"));
				skip_monitoring = 1;
				break;
			}
		}
		if (skip_monitoring != 0) {
			event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
					timeval_current_ofs(ctdb->monitor->next_interval, 0), 
					ctdb_check_health, ctdb);
			return;
		} else {
			ret = ctdb_event_script_callback(ctdb, 
					ctdb->monitor->monitor_context, ctdb_health_callback,
					ctdb, "monitor");
		}
	}

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
void ctdb_start_monitoring(struct ctdb_context *ctdb)
{
	struct timed_event *te;

	if (ctdb->monitor != NULL) {
		return;
	}

	ctdb->monitor = talloc(ctdb, struct ctdb_monitor_state);
	CTDB_NO_MEMORY_FATAL(ctdb, ctdb->monitor);

	ctdb->monitor->next_interval = 5;

	ctdb->monitor->monitor_context = talloc_new(ctdb->monitor);
	CTDB_NO_MEMORY_FATAL(ctdb, ctdb->monitor->monitor_context);

	te = event_add_timed(ctdb->ev, ctdb->monitor->monitor_context,
			     timeval_current_ofs(1, 0), 
			     ctdb_check_health, ctdb);
	CTDB_NO_MEMORY_FATAL(ctdb, te);

	ctdb->monitor->monitoring_mode  = CTDB_MONITORING_ACTIVE;
	DEBUG(DEBUG_NOTICE,("Monitoring has been started\n"));
}


/*
  modify flags on a node
 */
int32_t ctdb_control_modflags(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_node_flag_change *c = (struct ctdb_node_flag_change *)indata.dptr;
	struct ctdb_node *node;
	uint32_t old_flags;
	int i;

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


	/* tell the recovery daemon something has changed */
	ctdb_daemon_send_message(ctdb, ctdb->pnn,
				 CTDB_SRVID_SET_NODE_FLAGS, indata);

	/* if we have become banned, we should go into recovery mode */
	if ((node->flags & NODE_FLAGS_BANNED) && !(c->old_flags & NODE_FLAGS_BANNED) && (node->pnn == ctdb->pnn)) {
		/* make sure we are frozen */
		DEBUG(DEBUG_NOTICE,("This node has been banned - forcing freeze and recovery\n"));
		/* Reset the generation id to 1 to make us ignore any
		   REQ/REPLY CALL/DMASTER someone sends to us.
		   We are now banned so we shouldnt service database calls
		   anymore.
		*/
		ctdb->vnn_map->generation = INVALID_GENERATION;

		for (i=1; i<=NUM_DB_PRIORITIES; i++) {
			if (ctdb_start_freeze(ctdb, i) != 0) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to freeze db priority %u\n", i));
			}
		}
		ctdb_release_all_ips(ctdb);
		ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
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

