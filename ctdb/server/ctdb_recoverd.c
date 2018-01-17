/* 
   ctdb recovery daemon

   Copyright (C) Ronnie Sahlberg  2007

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
#include "system/network.h"
#include "system/wait.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/util_process.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/system_socket.h"
#include "common/common.h"
#include "common/logging.h"

#include "server/ctdb_config.h"

#include "ctdb_cluster_mutex.h"

/* List of SRVID requests that need to be processed */
struct srvid_list {
	struct srvid_list *next, *prev;
	struct ctdb_srvid_message *request;
};

struct srvid_requests {
	struct srvid_list *requests;
};

static void srvid_request_reply(struct ctdb_context *ctdb,
				struct ctdb_srvid_message *request,
				TDB_DATA result)
{
	/* Someone that sent srvid==0 does not want a reply */
	if (request->srvid == 0) {
		talloc_free(request);
		return;
	}

	if (ctdb_client_send_message(ctdb, request->pnn, request->srvid,
				     result) == 0) {
		DEBUG(DEBUG_INFO,("Sent SRVID reply to %u:%llu\n",
				  (unsigned)request->pnn,
				  (unsigned long long)request->srvid));
	} else {
		DEBUG(DEBUG_ERR,("Failed to send SRVID reply to %u:%llu\n",
				 (unsigned)request->pnn,
				 (unsigned long long)request->srvid));
	}

	talloc_free(request);
}

static void srvid_requests_reply(struct ctdb_context *ctdb,
				 struct srvid_requests **requests,
				 TDB_DATA result)
{
	struct srvid_list *r;

	if (*requests == NULL) {
		return;
	}

	for (r = (*requests)->requests; r != NULL; r = r->next) {
		srvid_request_reply(ctdb, r->request, result);
	}

	/* Free the list structure... */
	TALLOC_FREE(*requests);
}

static void srvid_request_add(struct ctdb_context *ctdb,
			      struct srvid_requests **requests,
			      struct ctdb_srvid_message *request)
{
	struct srvid_list *t;
	int32_t ret;
	TDB_DATA result;

	if (*requests == NULL) {
		*requests = talloc_zero(ctdb, struct srvid_requests);
		if (*requests == NULL) {
			goto nomem;
		}
	}

	t = talloc_zero(*requests, struct srvid_list);
	if (t == NULL) {
		/* If *requests was just allocated above then free it */
		if ((*requests)->requests == NULL) {
			TALLOC_FREE(*requests);
		}
		goto nomem;
	}

	t->request = (struct ctdb_srvid_message *)talloc_steal(t, request);
	DLIST_ADD((*requests)->requests, t);

	return;

nomem:
	/* Failed to add the request to the list.  Send a fail. */
	DEBUG(DEBUG_ERR, (__location__
			  " Out of memory, failed to queue SRVID request\n"));
	ret = -ENOMEM;
	result.dsize = sizeof(ret);
	result.dptr = (uint8_t *)&ret;
	srvid_request_reply(ctdb, request, result);
}

/* An abstraction to allow an operation (takeover runs, recoveries,
 * ...) to be disabled for a given timeout */
struct ctdb_op_state {
	struct tevent_timer *timer;
	bool in_progress;
	const char *name;
};

static struct ctdb_op_state *ctdb_op_init(TALLOC_CTX *mem_ctx, const char *name)
{
	struct ctdb_op_state *state = talloc_zero(mem_ctx, struct ctdb_op_state);

	if (state != NULL) {
		state->in_progress = false;
		state->name = name;
	}

	return state;
}

static bool ctdb_op_is_disabled(struct ctdb_op_state *state)
{
	return state->timer != NULL;
}

static bool ctdb_op_begin(struct ctdb_op_state *state)
{
	if (ctdb_op_is_disabled(state)) {
		DEBUG(DEBUG_NOTICE,
		      ("Unable to begin - %s are disabled\n", state->name));
		return false;
	}

	state->in_progress = true;
	return true;
}

static bool ctdb_op_end(struct ctdb_op_state *state)
{
	return state->in_progress = false;
}

static bool ctdb_op_is_in_progress(struct ctdb_op_state *state)
{
	return state->in_progress;
}

static void ctdb_op_enable(struct ctdb_op_state *state)
{
	TALLOC_FREE(state->timer);
}

static void ctdb_op_timeout_handler(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval yt, void *p)
{
	struct ctdb_op_state *state =
		talloc_get_type(p, struct ctdb_op_state);

	DEBUG(DEBUG_NOTICE,("Reenabling %s after timeout\n", state->name));
	ctdb_op_enable(state);
}

static int ctdb_op_disable(struct ctdb_op_state *state,
			   struct tevent_context *ev,
			   uint32_t timeout)
{
	if (timeout == 0) {
		DEBUG(DEBUG_NOTICE,("Reenabling %s\n", state->name));
		ctdb_op_enable(state);
		return 0;
	}

	if (state->in_progress) {
		DEBUG(DEBUG_ERR,
		      ("Unable to disable %s - in progress\n", state->name));
		return -EAGAIN;
	}

	DEBUG(DEBUG_NOTICE,("Disabling %s for %u seconds\n",
			    state->name, timeout));

	/* Clear any old timers */
	talloc_free(state->timer);

	/* Arrange for the timeout to occur */
	state->timer = tevent_add_timer(ev, state,
					timeval_current_ofs(timeout, 0),
					ctdb_op_timeout_handler, state);
	if (state->timer == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Unable to setup timer\n"));
		return -ENOMEM;
	}

	return 0;
}

struct ctdb_banning_state {
	uint32_t count;
	struct timeval last_reported_time;
};

struct ctdb_recovery_lock_handle;

/*
  private state of recovery daemon
 */
struct ctdb_recoverd {
	struct ctdb_context *ctdb;
	uint32_t recmaster;
	uint32_t last_culprit_node;
	struct ctdb_node_map_old *nodemap;
	struct timeval priority_time;
	bool need_takeover_run;
	bool need_recovery;
	uint32_t node_flags;
	struct tevent_timer *send_election_te;
	struct tevent_timer *election_timeout;
	struct srvid_requests *reallocate_requests;
	struct ctdb_op_state *takeover_run;
	struct ctdb_op_state *recovery;
	struct ctdb_iface_list_old *ifaces;
	uint32_t *force_rebalance_nodes;
	struct ctdb_node_capabilities *caps;
	bool frozen_on_inactive;
	struct ctdb_recovery_lock_handle *recovery_lock_handle;
};

#define CONTROL_TIMEOUT() timeval_current_ofs(ctdb->tunable.recover_timeout, 0)
#define MONITOR_TIMEOUT() timeval_current_ofs(ctdb->tunable.recover_interval, 0)

static void ctdb_restart_recd(struct tevent_context *ev,
			      struct tevent_timer *te, struct timeval t,
			      void *private_data);

/*
  ban a node for a period of time
 */
static void ctdb_ban_node(struct ctdb_recoverd *rec, uint32_t pnn, uint32_t ban_time)
{
	int ret;
	struct ctdb_context *ctdb = rec->ctdb;
	struct ctdb_ban_state bantime;

	if (!ctdb_validate_pnn(ctdb, pnn)) {
		DEBUG(DEBUG_ERR,("Bad pnn %u in ctdb_ban_node\n", pnn));
		return;
	}

	DEBUG(DEBUG_NOTICE,("Banning node %u for %u seconds\n", pnn, ban_time));

	bantime.pnn  = pnn;
	bantime.time = ban_time;

	ret = ctdb_ctrl_set_ban(ctdb, CONTROL_TIMEOUT(), pnn, &bantime);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to ban node %d\n", pnn));
		return;
	}

}

enum monitor_result { MONITOR_OK, MONITOR_RECOVERY_NEEDED, MONITOR_ELECTION_NEEDED, MONITOR_FAILED};


/*
  remember the trouble maker
 */
static void ctdb_set_culprit_count(struct ctdb_recoverd *rec, uint32_t culprit, uint32_t count)
{
	struct ctdb_context *ctdb = talloc_get_type(rec->ctdb, struct ctdb_context);
	struct ctdb_banning_state *ban_state;

	if (culprit > ctdb->num_nodes) {
		DEBUG(DEBUG_ERR,("Trying to set culprit %d but num_nodes is %d\n", culprit, ctdb->num_nodes));
		return;
	}

	/* If we are banned or stopped, do not set other nodes as culprits */
	if (rec->node_flags & NODE_FLAGS_INACTIVE) {
		DEBUG(DEBUG_NOTICE, ("This node is INACTIVE, cannot set culprit node %d\n", culprit));
		return;
	}

	if (ctdb->nodes[culprit]->ban_state == NULL) {
		ctdb->nodes[culprit]->ban_state = talloc_zero(ctdb->nodes[culprit], struct ctdb_banning_state);
		CTDB_NO_MEMORY_VOID(ctdb, ctdb->nodes[culprit]->ban_state);

		
	}
	ban_state = ctdb->nodes[culprit]->ban_state;
	if (timeval_elapsed(&ban_state->last_reported_time) > ctdb->tunable.recovery_grace_period) {
		/* this was the first time in a long while this node
		   misbehaved so we will forgive any old transgressions.
		*/
		ban_state->count = 0;
	}

	ban_state->count += count;
	ban_state->last_reported_time = timeval_current();
	rec->last_culprit_node = culprit;
}

/*
  remember the trouble maker
 */
static void ctdb_set_culprit(struct ctdb_recoverd *rec, uint32_t culprit)
{
	ctdb_set_culprit_count(rec, culprit, 1);
}

/*
  Retrieve capabilities from all connected nodes
 */
static int update_capabilities(struct ctdb_recoverd *rec,
			       struct ctdb_node_map_old *nodemap)
{
	uint32_t *capp;
	TALLOC_CTX *tmp_ctx;
	struct ctdb_node_capabilities *caps;
	struct ctdb_context *ctdb = rec->ctdb;

	tmp_ctx = talloc_new(rec);
	CTDB_NO_MEMORY(ctdb, tmp_ctx);

	caps = ctdb_get_capabilities(ctdb, tmp_ctx,
				     CONTROL_TIMEOUT(), nodemap);

	if (caps == NULL) {
		DEBUG(DEBUG_ERR,
		      (__location__ " Failed to get node capabilities\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	capp = ctdb_get_node_capabilities(caps, ctdb_get_pnn(ctdb));
	if (capp == NULL) {
		DEBUG(DEBUG_ERR,
		      (__location__
		       " Capabilities don't include current node.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}
	ctdb->capabilities = *capp;

	TALLOC_FREE(rec->caps);
	rec->caps = talloc_steal(rec, caps);

	talloc_free(tmp_ctx);
	return 0;
}

/*
  change recovery mode on all nodes
 */
static int set_recovery_mode(struct ctdb_context *ctdb,
			     struct ctdb_recoverd *rec,
			     struct ctdb_node_map_old *nodemap,
			     uint32_t rec_mode)
{
	TDB_DATA data;
	uint32_t *nodes;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, tmp_ctx);

	nodes = list_of_active_nodes(ctdb, nodemap, tmp_ctx, true);

	data.dsize = sizeof(uint32_t);
	data.dptr = (unsigned char *)&rec_mode;

	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_SET_RECMODE,
					nodes, 0,
					CONTROL_TIMEOUT(),
					false, data,
					NULL, NULL,
					NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set recovery mode. Recovery failed.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
 * Update flags on all connected nodes
 */
static int update_flags_on_all_nodes(struct ctdb_recoverd *rec,
				     uint32_t pnn,
				     uint32_t flags)
{
	struct ctdb_context *ctdb = rec->ctdb;
	struct timeval timeout = CONTROL_TIMEOUT();
	TDB_DATA data;
	struct ctdb_node_map_old *nodemap=NULL;
	struct ctdb_node_flag_change c;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	uint32_t *nodes;
	uint32_t i;
	int ret;

	nodemap = rec->nodemap;

	for (i = 0; i < nodemap->num; i++) {
		if (pnn == nodemap->nodes[i].pnn) {
			break;
		}
	}
	if (i >= nodemap->num) {
		DBG_ERR("Nodemap does not contain node %d\n", pnn);
		talloc_free(tmp_ctx);
		return -1;
	}

	c.pnn       = pnn;
	c.old_flags = nodemap->nodes[i].flags;
	c.new_flags = flags;

	data.dsize = sizeof(c);
	data.dptr = (unsigned char *)&c;

	/* send the flags update to all connected nodes */
	nodes = list_of_connected_nodes(ctdb, nodemap, tmp_ctx, true);

	ret = ctdb_client_async_control(ctdb,
					CTDB_CONTROL_MODIFY_FLAGS,
					nodes,
					0,
					timeout,
					false,
					data,
					NULL,
					NULL,
					NULL);
	if (ret != 0) {
		DBG_ERR("Unable to update flags on remote nodes\n");
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

/*
  called when ctdb_wait_timeout should finish
 */
static void ctdb_wait_handler(struct tevent_context *ev,
			      struct tevent_timer *te,
			      struct timeval yt, void *p)
{
	uint32_t *timed_out = (uint32_t *)p;
	(*timed_out) = 1;
}

/*
  wait for a given number of seconds
 */
static void ctdb_wait_timeout(struct ctdb_context *ctdb, double secs)
{
	uint32_t timed_out = 0;
	time_t usecs = (secs - (time_t)secs) * 1000000;
	tevent_add_timer(ctdb->ev, ctdb, timeval_current_ofs(secs, usecs),
			 ctdb_wait_handler, &timed_out);
	while (!timed_out) {
		tevent_loop_once(ctdb->ev);
	}
}

/*
  called when an election times out (ends)
 */
static void ctdb_election_timeout(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval t, void *p)
{
	struct ctdb_recoverd *rec = talloc_get_type(p, struct ctdb_recoverd);
	rec->election_timeout = NULL;
	fast_start = false;

	D_WARNING("Election period ended, master=%u\n", rec->recmaster);
}


/*
  wait for an election to finish. It finished election_timeout seconds after
  the last election packet is received
 */
static void ctdb_wait_election(struct ctdb_recoverd *rec)
{
	struct ctdb_context *ctdb = rec->ctdb;
	while (rec->election_timeout) {
		tevent_loop_once(ctdb->ev);
	}
}

/*
 * Update local flags from all remote connected nodes and push out
 * flags changes to all nodes.  This is only run by the recovery
 * master.
 */
static int update_flags(struct ctdb_recoverd *rec,
			struct ctdb_node_map_old *nodemap,
			struct ctdb_node_map_old **remote_nodemaps)
{
	unsigned int j;
	struct ctdb_context *ctdb = rec->ctdb;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);

	/* Check flags from remote nodes */
	for (j=0; j<nodemap->num; j++) {
		struct ctdb_node_map_old *remote_nodemap=NULL;
		uint32_t local_flags = nodemap->nodes[j].flags;
		uint32_t remote_pnn = nodemap->nodes[j].pnn;
		uint32_t remote_flags;
		unsigned int i;
		int ret;

		if (local_flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}
		if (remote_pnn == ctdb->pnn) {
			/*
			 * No remote nodemap for this node since this
			 * is the local nodemap.  However, still need
			 * to check this against the remote nodes and
			 * push it if they are out-of-date.
			 */
			goto compare_remotes;
		}

		remote_nodemap = remote_nodemaps[j];
		remote_flags = remote_nodemap->nodes[j].flags;

		if (local_flags != remote_flags) {
			/*
			 * Update the local copy of the flags in the
			 * recovery daemon.
			 */
			D_NOTICE("Remote node %u had flags 0x%x, "
				 "local had 0x%x - updating local\n",
				 remote_pnn,
				 remote_flags,
				 local_flags);
			nodemap->nodes[j].flags = remote_flags;
			local_flags = remote_flags;
			goto push;
		}

compare_remotes:
		for (i = 0; i < nodemap->num; i++) {
			if (i == j) {
				continue;
			}
			if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
				continue;
			}
			if (nodemap->nodes[i].pnn == ctdb->pnn) {
				continue;
			}

			remote_nodemap = remote_nodemaps[i];
			remote_flags = remote_nodemap->nodes[j].flags;

			if (local_flags != remote_flags) {
				goto push;
			}
		}

		continue;

push:
		D_NOTICE("Pushing updated flags for node %u (0x%x)\n",
			 remote_pnn,
			 local_flags);
		ret = update_flags_on_all_nodes(rec, remote_pnn, local_flags);
		if (ret != 0) {
			DBG_ERR("Unable to update flags on remote nodes\n");
			talloc_free(mem_ctx);
			return -1;
		}
	}
	talloc_free(mem_ctx);
	return 0;
}


/* Create a new random generation id.
   The generation id can not be the INVALID_GENERATION id
*/
static uint32_t new_generation(void)
{
	uint32_t generation;

	while (1) {
		generation = random();

		if (generation != INVALID_GENERATION) {
			break;
		}
	}

	return generation;
}

static bool ctdb_recovery_have_lock(struct ctdb_recoverd *rec)
{
	return (rec->recovery_lock_handle != NULL);
}

struct ctdb_recovery_lock_handle {
	bool done;
	bool locked;
	double latency;
	struct ctdb_cluster_mutex_handle *h;
	struct ctdb_recoverd *rec;
};

static void take_reclock_handler(char status,
				 double latency,
				 void *private_data)
{
	struct ctdb_recovery_lock_handle *s =
		(struct ctdb_recovery_lock_handle *) private_data;

	s->locked = (status == '0') ;

	/*
	 * If unsuccessful then ensure the process has exited and that
	 * the file descriptor event handler has been cancelled
	 */
	if (! s->locked) {
		TALLOC_FREE(s->h);
	}

	switch (status) {
	case '0':
		s->latency = latency;
		break;

	case '1':
		D_ERR("Unable to take recovery lock - contention\n");
		break;

	case '2':
		D_ERR("Unable to take recovery lock - timeout\n");
		break;

	default:
		D_ERR("Unable to take recover lock - unknown error\n");

		{
			struct ctdb_recoverd *rec = s->rec;
			struct ctdb_context *ctdb = rec->ctdb;
			uint32_t pnn = ctdb_get_pnn(ctdb);

			D_ERR("Banning this node\n");
			ctdb_ban_node(rec,
				      pnn,
				      ctdb->tunable.recovery_ban_period);
		}
	}

	s->done = true;
}

static void force_election(struct ctdb_recoverd *rec,
			   uint32_t pnn,
			   struct ctdb_node_map_old *nodemap);

static void lost_reclock_handler(void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type_abort(
		private_data, struct ctdb_recoverd);

	D_ERR("Recovery lock helper terminated, triggering an election\n");
	TALLOC_FREE(rec->recovery_lock_handle);

	force_election(rec, ctdb_get_pnn(rec->ctdb), rec->nodemap);
}

static bool ctdb_recovery_lock(struct ctdb_recoverd *rec)
{
	struct ctdb_context *ctdb = rec->ctdb;
	struct ctdb_cluster_mutex_handle *h;
	struct ctdb_recovery_lock_handle *s;

	s = talloc_zero(rec, struct ctdb_recovery_lock_handle);
	if (s == NULL) {
		DBG_ERR("Memory allocation error\n");
		return false;
	};

	s->rec = rec;

	h = ctdb_cluster_mutex(s,
			       ctdb,
			       ctdb->recovery_lock,
			       120,
			       take_reclock_handler,
			       s,
			       lost_reclock_handler,
			       rec);
	if (h == NULL) {
		talloc_free(s);
		return false;
	}

	rec->recovery_lock_handle = s;
	s->h = h;

	while (! s->done) {
		tevent_loop_once(ctdb->ev);
	}

	if (! s->locked) {
		TALLOC_FREE(rec->recovery_lock_handle);
		return false;
	}

	ctdb_ctrl_report_recd_lock_latency(ctdb,
					   CONTROL_TIMEOUT(),
					   s->latency);

	return true;
}

static void ctdb_recovery_unlock(struct ctdb_recoverd *rec)
{
	if (rec->recovery_lock_handle == NULL) {
		return;
	}

	if (! rec->recovery_lock_handle->done) {
		/*
		 * Taking of recovery lock still in progress.  Free
		 * the cluster mutex handle to release it but leave
		 * the recovery lock handle in place to allow taking
		 * of the lock to fail.
		 */
		D_NOTICE("Cancelling recovery lock\n");
		TALLOC_FREE(rec->recovery_lock_handle->h);
		rec->recovery_lock_handle->done = true;
		rec->recovery_lock_handle->locked = false;
		return;
	}

	D_NOTICE("Releasing recovery lock\n");
	TALLOC_FREE(rec->recovery_lock_handle);
}

static void ban_misbehaving_nodes(struct ctdb_recoverd *rec, bool *self_ban)
{
	struct ctdb_context *ctdb = rec->ctdb;
	unsigned int i;
	struct ctdb_banning_state *ban_state;

	*self_ban = false;
	for (i=0; i<ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->ban_state == NULL) {
			continue;
		}
		ban_state = (struct ctdb_banning_state *)ctdb->nodes[i]->ban_state;
		if (ban_state->count < 2*ctdb->num_nodes) {
			continue;
		}

		DEBUG(DEBUG_NOTICE,("Node %u reached %u banning credits - banning it for %u seconds\n",
			ctdb->nodes[i]->pnn, ban_state->count,
			ctdb->tunable.recovery_ban_period));
		ctdb_ban_node(rec, ctdb->nodes[i]->pnn, ctdb->tunable.recovery_ban_period);
		ban_state->count = 0;

		/* Banning ourself? */
		if (ctdb->nodes[i]->pnn == rec->ctdb->pnn) {
			*self_ban = true;
		}
	}
}

struct helper_state {
	int fd[2];
	pid_t pid;
	int result;
	bool done;
};

static void helper_handler(struct tevent_context *ev,
			   struct tevent_fd *fde,
			   uint16_t flags, void *private_data)
{
	struct helper_state *state = talloc_get_type_abort(
		private_data, struct helper_state);
	int ret;

	ret = sys_read(state->fd[0], &state->result, sizeof(state->result));
	if (ret != sizeof(state->result)) {
		state->result = EPIPE;
	}

	state->done = true;
}

static int helper_run(struct ctdb_recoverd *rec, TALLOC_CTX *mem_ctx,
		      const char *prog, const char *arg, const char *type)
{
	struct helper_state *state;
	struct tevent_fd *fde;
	const char **args;
	int nargs, ret;
	uint32_t recmaster = rec->recmaster;

	state = talloc_zero(mem_ctx, struct helper_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " memory error\n"));
		return -1;
	}

	state->pid = -1;

	ret = pipe(state->fd);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Failed to create pipe for %s helper\n", type));
		goto fail;
	}

	set_close_on_exec(state->fd[0]);

	nargs = 4;
	args = talloc_array(state, const char *, nargs);
	if (args == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " memory error\n"));
		goto fail;
	}

	args[0] = talloc_asprintf(args, "%d", state->fd[1]);
	if (args[0] == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " memory error\n"));
		goto fail;
	}
	args[1] = rec->ctdb->daemon.name;
	args[2] = arg;
	args[3] = NULL;

	if (args[2] == NULL) {
		nargs = 3;
	}

	state->pid = ctdb_vfork_exec(state, rec->ctdb, prog, nargs, args);
	if (state->pid == -1) {
		DEBUG(DEBUG_ERR,
		      ("Failed to create child for %s helper\n", type));
		goto fail;
	}

	close(state->fd[1]);
	state->fd[1] = -1;

	state->done = false;

	fde = tevent_add_fd(rec->ctdb->ev, state, state->fd[0],
			    TEVENT_FD_READ, helper_handler, state);
	if (fde == NULL) {
		goto fail;
	}
	tevent_fd_set_auto_close(fde);

	while (!state->done) {
		tevent_loop_once(rec->ctdb->ev);

		/* If recmaster changes, we have lost election */
		if (recmaster != rec->recmaster) {
			D_ERR("Recmaster changed to %u, aborting %s\n",
			      rec->recmaster, type);
			state->result = 1;
			break;
		}
	}

	close(state->fd[0]);
	state->fd[0] = -1;

	if (state->result != 0) {
		goto fail;
	}

	ctdb_kill(rec->ctdb, state->pid, SIGKILL);
	talloc_free(state);
	return 0;

fail:
	if (state->fd[0] != -1) {
		close(state->fd[0]);
	}
	if (state->fd[1] != -1) {
		close(state->fd[1]);
	}
	if (state->pid != -1) {
		ctdb_kill(rec->ctdb, state->pid, SIGKILL);
	}
	talloc_free(state);
	return -1;
}


static int ctdb_takeover(struct ctdb_recoverd *rec,
			 uint32_t *force_rebalance_nodes)
{
	static char prog[PATH_MAX+1] = "";
	char *arg;
	unsigned int i;
	int ret;

	if (!ctdb_set_helper("takeover_helper", prog, sizeof(prog),
			     "CTDB_TAKEOVER_HELPER", CTDB_HELPER_BINDIR,
			     "ctdb_takeover_helper")) {
		ctdb_die(rec->ctdb, "Unable to set takeover helper\n");
	}

	arg = NULL;
	for (i = 0; i < talloc_array_length(force_rebalance_nodes); i++) {
		uint32_t pnn = force_rebalance_nodes[i];
		if (arg == NULL) {
			arg = talloc_asprintf(rec, "%u", pnn);
		} else {
			arg = talloc_asprintf_append(arg, ",%u", pnn);
		}
		if (arg == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " memory error\n"));
			return -1;
		}
	}

	if (ctdb_config.failover_disabled) {
		ret = setenv("CTDB_DISABLE_IP_FAILOVER", "1", 1);
		if (ret != 0) {
			D_ERR("Failed to set CTDB_DISABLE_IP_FAILOVER variable\n");
			return -1;
		}
	}

	return helper_run(rec, rec, prog, arg, "takeover");
}

static bool do_takeover_run(struct ctdb_recoverd *rec,
			    struct ctdb_node_map_old *nodemap)
{
	uint32_t *nodes = NULL;
	struct ctdb_disable_message dtr;
	TDB_DATA data;
	size_t i;
	uint32_t *rebalance_nodes = rec->force_rebalance_nodes;
	int ret;
	bool ok;

	DEBUG(DEBUG_NOTICE, ("Takeover run starting\n"));

	if (ctdb_op_is_in_progress(rec->takeover_run)) {
		DEBUG(DEBUG_ERR, (__location__
				  " takeover run already in progress \n"));
		ok = false;
		goto done;
	}

	if (!ctdb_op_begin(rec->takeover_run)) {
		ok = false;
		goto done;
	}

	/* Disable IP checks (takeover runs, really) on other nodes
	 * while doing this takeover run.  This will stop those other
	 * nodes from triggering takeover runs when think they should
	 * be hosting an IP but it isn't yet on an interface.  Don't
	 * wait for replies since a failure here might cause some
	 * noise in the logs but will not actually cause a problem.
	 */
	ZERO_STRUCT(dtr);
	dtr.srvid = 0; /* No reply */
	dtr.pnn = -1;

	data.dptr  = (uint8_t*)&dtr;
	data.dsize = sizeof(dtr);

	nodes = list_of_connected_nodes(rec->ctdb, nodemap, rec, false);

	/* Disable for 60 seconds.  This can be a tunable later if
	 * necessary.
	 */
	dtr.timeout = 60;
	for (i = 0; i < talloc_array_length(nodes); i++) {
		if (ctdb_client_send_message(rec->ctdb, nodes[i],
					     CTDB_SRVID_DISABLE_TAKEOVER_RUNS,
					     data) != 0) {
			DEBUG(DEBUG_INFO,("Failed to disable takeover runs\n"));
		}
	}

	ret = ctdb_takeover(rec, rec->force_rebalance_nodes);

	/* Reenable takeover runs and IP checks on other nodes */
	dtr.timeout = 0;
	for (i = 0; i < talloc_array_length(nodes); i++) {
		if (ctdb_client_send_message(rec->ctdb, nodes[i],
					     CTDB_SRVID_DISABLE_TAKEOVER_RUNS,
					     data) != 0) {
			DEBUG(DEBUG_INFO,("Failed to re-enable takeover runs\n"));
		}
	}

	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("ctdb_takeover_run() failed\n"));
		ok = false;
		goto done;
	}

	ok = true;
	/* Takeover run was successful so clear force rebalance targets */
	if (rebalance_nodes == rec->force_rebalance_nodes) {
		TALLOC_FREE(rec->force_rebalance_nodes);
	} else {
		DEBUG(DEBUG_WARNING,
		      ("Rebalance target nodes changed during takeover run - not clearing\n"));
	}
done:
	rec->need_takeover_run = !ok;
	talloc_free(nodes);
	ctdb_op_end(rec->takeover_run);

	DEBUG(DEBUG_NOTICE, ("Takeover run %s\n", ok ? "completed successfully" : "unsuccessful"));
	return ok;
}

static int db_recovery_parallel(struct ctdb_recoverd *rec, TALLOC_CTX *mem_ctx)
{
	static char prog[PATH_MAX+1] = "";
	const char *arg;

	if (!ctdb_set_helper("recovery_helper", prog, sizeof(prog),
			     "CTDB_RECOVERY_HELPER", CTDB_HELPER_BINDIR,
			     "ctdb_recovery_helper")) {
		ctdb_die(rec->ctdb, "Unable to set recovery helper\n");
	}

	arg = talloc_asprintf(mem_ctx, "%u", new_generation());
	if (arg == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " memory error\n"));
		return -1;
	}

	setenv("CTDB_DBDIR_STATE", rec->ctdb->db_directory_state, 1);

	return helper_run(rec, mem_ctx, prog, arg, "recovery");
}

/*
  we are the recmaster, and recovery is needed - start a recovery run
 */
static int do_recovery(struct ctdb_recoverd *rec,
		       TALLOC_CTX *mem_ctx, uint32_t pnn,
		       struct ctdb_node_map_old *nodemap, struct ctdb_vnn_map *vnnmap)
{
	struct ctdb_context *ctdb = rec->ctdb;
	unsigned int i;
	int ret;
	bool self_ban;

	DEBUG(DEBUG_NOTICE, (__location__ " Starting do_recovery\n"));

	/* Check if the current node is still the recmaster.  It's possible that
	 * re-election has changed the recmaster.
	 */
	if (pnn != rec->recmaster) {
		DEBUG(DEBUG_NOTICE,
		      ("Recovery master changed to %u, aborting recovery\n",
		       rec->recmaster));
		return -1;
	}

	/* if recovery fails, force it again */
	rec->need_recovery = true;

	if (!ctdb_op_begin(rec->recovery)) {
		return -1;
	}

	if (rec->election_timeout) {
		/* an election is in progress */
		DEBUG(DEBUG_ERR, ("do_recovery called while election in progress - try again later\n"));
		goto fail;
	}

	ban_misbehaving_nodes(rec, &self_ban);
	if (self_ban) {
		DEBUG(DEBUG_NOTICE, ("This node was banned, aborting recovery\n"));
		goto fail;
	}

	if (ctdb->recovery_lock != NULL) {
		if (ctdb_recovery_have_lock(rec)) {
			D_NOTICE("Already holding recovery lock\n");
		} else {
			bool ok;

			D_NOTICE("Attempting to take recovery lock (%s)\n",
				 ctdb->recovery_lock);

			ok = ctdb_recovery_lock(rec);
			if (! ok) {
				D_ERR("Unable to take recovery lock\n");

				if (pnn != rec->recmaster) {
					D_NOTICE("Recovery master changed to %u,"
						 " aborting recovery\n",
						 rec->recmaster);
					rec->need_recovery = false;
					goto fail;
				}

				if (ctdb->runstate ==
				    CTDB_RUNSTATE_FIRST_RECOVERY) {
					/*
					 * First recovery?  Perhaps
					 * current node does not yet
					 * know who the recmaster is.
					 */
					D_ERR("Retrying recovery\n");
					goto fail;
				}

				D_ERR("Abort recovery, "
				      "ban this node for %u seconds\n",
				      ctdb->tunable.recovery_ban_period);
				ctdb_ban_node(rec,
					      pnn,
					      ctdb->tunable.recovery_ban_period);
				goto fail;
			}
			D_NOTICE("Recovery lock taken successfully\n");
		}
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery initiated due to problem with node %u\n", rec->last_culprit_node));

	/* Retrieve capabilities from all connected nodes */
	ret = update_capabilities(rec, nodemap);
	if (ret!=0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to update node capabilities.\n"));
		return -1;
	}

	/*
	  update all nodes to have the same flags that we have
	 */
	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		ret = update_flags_on_all_nodes(rec,
						nodemap->nodes[i].pnn,
						nodemap->nodes[i].flags);
		if (ret != 0) {
			if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
				DEBUG(DEBUG_WARNING, (__location__ "Unable to update flags on inactive node %d\n", i));
			} else {
				DEBUG(DEBUG_ERR, (__location__ " Unable to update flags on all nodes for node %d\n", i));
				return -1;
			}
		}
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery - updated flags\n"));

	ret = db_recovery_parallel(rec, mem_ctx);
	if (ret != 0) {
		goto fail;
	}

	do_takeover_run(rec, nodemap);

	/* send a message to all clients telling them that the cluster 
	   has been reconfigured */
	ret = ctdb_client_send_message(ctdb, CTDB_BROADCAST_CONNECTED,
				       CTDB_SRVID_RECONFIGURE, tdb_null);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to send reconfigure message\n"));
		goto fail;
	}

	DEBUG(DEBUG_NOTICE, (__location__ " Recovery complete\n"));

	rec->need_recovery = false;
	ctdb_op_end(rec->recovery);

	/* we managed to complete a full recovery, make sure to forgive
	   any past sins by the nodes that could now participate in the
	   recovery.
	*/
	DEBUG(DEBUG_ERR,("Resetting ban count to 0 for all nodes\n"));
	for (i=0;i<nodemap->num;i++) {
		struct ctdb_banning_state *ban_state;

		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		ban_state = (struct ctdb_banning_state *)ctdb->nodes[nodemap->nodes[i].pnn]->ban_state;
		if (ban_state == NULL) {
			continue;
		}

		ban_state->count = 0;
	}

	/* We just finished a recovery successfully.
	   We now wait for rerecovery_timeout before we allow
	   another recovery to take place.
	*/
	DEBUG(DEBUG_NOTICE, ("Just finished a recovery. New recoveries will now be suppressed for the rerecovery timeout (%d seconds)\n", ctdb->tunable.rerecovery_timeout));
	ctdb_op_disable(rec->recovery, ctdb->ev,
			ctdb->tunable.rerecovery_timeout);
	return 0;

fail:
	ctdb_op_end(rec->recovery);
	return -1;
}


/*
  elections are won by first checking the number of connected nodes, then
  the priority time, then the pnn
 */
struct election_message {
	uint32_t num_connected;
	struct timeval priority_time;
	uint32_t pnn;
	uint32_t node_flags;
};

/*
  form this nodes election data
 */
static void ctdb_election_data(struct ctdb_recoverd *rec, struct election_message *em)
{
	unsigned int i;
	int ret;
	struct ctdb_node_map_old *nodemap;
	struct ctdb_context *ctdb = rec->ctdb;

	ZERO_STRUCTP(em);

	em->pnn = rec->ctdb->pnn;
	em->priority_time = rec->priority_time;

	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, rec, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " unable to get node map\n"));
		return;
	}

	rec->node_flags = nodemap->nodes[ctdb->pnn].flags;
	em->node_flags = rec->node_flags;

	for (i=0;i<nodemap->num;i++) {
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED)) {
			em->num_connected++;
		}
	}

	/* we shouldnt try to win this election if we cant be a recmaster */
	if ((ctdb->capabilities & CTDB_CAP_RECMASTER) == 0) {
		em->num_connected = 0;
		em->priority_time = timeval_current();
	}

	talloc_free(nodemap);
}

/*
  see if the given election data wins
 */
static bool ctdb_election_win(struct ctdb_recoverd *rec, struct election_message *em)
{
	struct election_message myem;
	int cmp = 0;

	ctdb_election_data(rec, &myem);

	/* we cant win if we don't have the recmaster capability */
	if ((rec->ctdb->capabilities & CTDB_CAP_RECMASTER) == 0) {
		return false;
	}

	/* we cant win if we are banned */
	if (rec->node_flags & NODE_FLAGS_BANNED) {
		return false;
	}

	/* we cant win if we are stopped */
	if (rec->node_flags & NODE_FLAGS_STOPPED) {
		return false;
	}

	/* we will automatically win if the other node is banned */
	if (em->node_flags & NODE_FLAGS_BANNED) {
		return true;
	}

	/* we will automatically win if the other node is banned */
	if (em->node_flags & NODE_FLAGS_STOPPED) {
		return true;
	}

	/* then the longest running node */
	if (cmp == 0) {
		cmp = timeval_compare(&em->priority_time, &myem.priority_time);
	}

	if (cmp == 0) {
		cmp = (int)myem.pnn - (int)em->pnn;
	}

	return cmp > 0;
}

/*
  send out an election request
 */
static int send_election_request(struct ctdb_recoverd *rec, uint32_t pnn)
{
	int ret;
	TDB_DATA election_data;
	struct election_message emsg;
	uint64_t srvid;
	struct ctdb_context *ctdb = rec->ctdb;

	srvid = CTDB_SRVID_ELECTION;

	ctdb_election_data(rec, &emsg);

	election_data.dsize = sizeof(struct election_message);
	election_data.dptr  = (unsigned char *)&emsg;


	/* first we assume we will win the election and set 
	   recoverymaster to be ourself on the current node
	 */
	ret = ctdb_ctrl_setrecmaster(ctdb, CONTROL_TIMEOUT(),
				     CTDB_CURRENT_NODE, pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " failed to set recmaster\n"));
		return -1;
	}
	rec->recmaster = pnn;

	/* send an election message to all active nodes */
	DEBUG(DEBUG_INFO,(__location__ " Send election request to all active nodes\n"));
	return ctdb_client_send_message(ctdb, CTDB_BROADCAST_ALL, srvid, election_data);
}

/*
  we think we are winning the election - send a broadcast election request
 */
static void election_send_request(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval t, void *p)
{
	struct ctdb_recoverd *rec = talloc_get_type(p, struct ctdb_recoverd);
	int ret;

	ret = send_election_request(rec, ctdb_get_pnn(rec->ctdb));
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send election request!\n"));
	}

	TALLOC_FREE(rec->send_election_te);
}

/*
  handler for memory dumps
*/
static void mem_dump_handler(uint64_t srvid, TDB_DATA data, void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);
	struct ctdb_context *ctdb = rec->ctdb;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	TDB_DATA *dump;
	int ret;
	struct ctdb_srvid_message *rd;

	if (data.dsize != sizeof(struct ctdb_srvid_message)) {
		DEBUG(DEBUG_ERR, (__location__ " Wrong size of return address.\n"));
		talloc_free(tmp_ctx);
		return;
	}
	rd = (struct ctdb_srvid_message *)data.dptr;

	dump = talloc_zero(tmp_ctx, TDB_DATA);
	if (dump == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to allocate memory for memdump\n"));
		talloc_free(tmp_ctx);
		return;
	}
	ret = ctdb_dump_memory(ctdb, dump);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " ctdb_dump_memory() failed\n"));
		talloc_free(tmp_ctx);
		return;
	}

DEBUG(DEBUG_ERR, ("recovery master memory dump\n"));		

	ret = ctdb_client_send_message(ctdb, rd->pnn, rd->srvid, *dump);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to send rd memdump reply message\n"));
		talloc_free(tmp_ctx);
		return;
	}

	talloc_free(tmp_ctx);
}

/*
  handler for reload_nodes
*/
static void reload_nodes_handler(uint64_t srvid, TDB_DATA data,
				 void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);

	DEBUG(DEBUG_ERR, (__location__ " Reload nodes file from recovery daemon\n"));

	ctdb_load_nodes_file(rec->ctdb);
}


static void recd_node_rebalance_handler(uint64_t srvid, TDB_DATA data,
					void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);
	struct ctdb_context *ctdb = rec->ctdb;
	uint32_t pnn;
	uint32_t *t;
	int len;

	if (rec->recmaster != ctdb_get_pnn(ctdb)) {
		return;
	}

	if (data.dsize != sizeof(uint32_t)) {
		DEBUG(DEBUG_ERR,(__location__ " Incorrect size of node rebalance message. Was %zd but expected %zd bytes\n", data.dsize, sizeof(uint32_t)));
		return;
	}

	pnn = *(uint32_t *)&data.dptr[0];

	DEBUG(DEBUG_NOTICE,("Setting up rebalance of IPs to node %u\n", pnn));

	/* Copy any existing list of nodes.  There's probably some
	 * sort of realloc variant that will do this but we need to
	 * make sure that freeing the old array also cancels the timer
	 * event for the timeout... not sure if realloc will do that.
	 */
	len = (rec->force_rebalance_nodes != NULL) ?
		talloc_array_length(rec->force_rebalance_nodes) :
		0;

	/* This allows duplicates to be added but they don't cause
	 * harm.  A call to add a duplicate PNN arguably means that
	 * the timeout should be reset, so this is the simplest
	 * solution.
	 */
	t = talloc_zero_array(rec, uint32_t, len+1);
	CTDB_NO_MEMORY_VOID(ctdb, t);
	if (len > 0) {
		memcpy(t, rec->force_rebalance_nodes, sizeof(uint32_t) * len);
	}
	t[len] = pnn;

	talloc_free(rec->force_rebalance_nodes);

	rec->force_rebalance_nodes = t;
}



static void srvid_disable_and_reply(struct ctdb_context *ctdb,
				    TDB_DATA data,
				    struct ctdb_op_state *op_state)
{
	struct ctdb_disable_message *r;
	uint32_t timeout;
	TDB_DATA result;
	int32_t ret = 0;

	/* Validate input data */
	if (data.dsize != sizeof(struct ctdb_disable_message)) {
		DEBUG(DEBUG_ERR,(__location__ " Wrong size for data :%lu "
				 "expecting %lu\n", (long unsigned)data.dsize,
				 (long unsigned)sizeof(struct ctdb_srvid_message)));
		return;
	}
	if (data.dptr == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " No data received\n"));
		return;
	}

	r = (struct ctdb_disable_message *)data.dptr;
	timeout = r->timeout;

	ret = ctdb_op_disable(op_state, ctdb->ev, timeout);
	if (ret != 0) {
		goto done;
	}

	/* Returning our PNN tells the caller that we succeeded */
	ret = ctdb_get_pnn(ctdb);
done:
	result.dsize = sizeof(int32_t);
	result.dptr  = (uint8_t *)&ret;
	srvid_request_reply(ctdb, (struct ctdb_srvid_message *)r, result);
}

static void disable_takeover_runs_handler(uint64_t srvid, TDB_DATA data,
					  void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);

	srvid_disable_and_reply(rec->ctdb, data, rec->takeover_run);
}

/* Backward compatibility for this SRVID */
static void disable_ip_check_handler(uint64_t srvid, TDB_DATA data,
				     void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);
	uint32_t timeout;

	if (data.dsize != sizeof(uint32_t)) {
		DEBUG(DEBUG_ERR,(__location__ " Wrong size for data :%lu "
				 "expecting %lu\n", (long unsigned)data.dsize,
				 (long unsigned)sizeof(uint32_t)));
		return;
	}
	if (data.dptr == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " No data received\n"));
		return;
	}

	timeout = *((uint32_t *)data.dptr);

	ctdb_op_disable(rec->takeover_run, rec->ctdb->ev, timeout);
}

static void disable_recoveries_handler(uint64_t srvid, TDB_DATA data,
				       void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);

	srvid_disable_and_reply(rec->ctdb, data, rec->recovery);
}

/*
  handler for ip reallocate, just add it to the list of requests and 
  handle this later in the monitor_cluster loop so we do not recurse
  with other requests to takeover_run()
*/
static void ip_reallocate_handler(uint64_t srvid, TDB_DATA data,
				  void *private_data)
{
	struct ctdb_srvid_message *request;
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);

	if (data.dsize != sizeof(struct ctdb_srvid_message)) {
		DEBUG(DEBUG_ERR, (__location__ " Wrong size of return address.\n"));
		return;
	}

	request = (struct ctdb_srvid_message *)data.dptr;

	srvid_request_add(rec->ctdb, &rec->reallocate_requests, request);
}

static void process_ipreallocate_requests(struct ctdb_context *ctdb,
					  struct ctdb_recoverd *rec)
{
	TDB_DATA result;
	int32_t ret;
	struct srvid_requests *current;

	/* Only process requests that are currently pending.  More
	 * might come in while the takeover run is in progress and
	 * they will need to be processed later since they might
	 * be in response flag changes.
	 */
	current = rec->reallocate_requests;
	rec->reallocate_requests = NULL;

	if (do_takeover_run(rec, rec->nodemap)) {
		ret = ctdb_get_pnn(ctdb);
	} else {
		ret = -1;
	}

	result.dsize = sizeof(int32_t);
	result.dptr  = (uint8_t *)&ret;

	srvid_requests_reply(ctdb, &current, result);
}

/*
 * handler for assigning banning credits
 */
static void banning_handler(uint64_t srvid, TDB_DATA data, void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);
	uint32_t ban_pnn;

	/* Ignore if we are not recmaster */
	if (rec->ctdb->pnn != rec->recmaster) {
		return;
	}

	if (data.dsize != sizeof(uint32_t)) {
		DEBUG(DEBUG_ERR, (__location__ "invalid data size %zu\n",
				  data.dsize));
		return;
	}

	ban_pnn = *(uint32_t *)data.dptr;

	ctdb_set_culprit_count(rec, ban_pnn, rec->nodemap->num);
}

/*
  handler for recovery master elections
*/
static void election_handler(uint64_t srvid, TDB_DATA data, void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);
	struct ctdb_context *ctdb = rec->ctdb;
	int ret;
	struct election_message *em = (struct election_message *)data.dptr;

	/* Ignore election packets from ourself */
	if (ctdb->pnn == em->pnn) {
		return;
	}

	/* we got an election packet - update the timeout for the election */
	talloc_free(rec->election_timeout);
	rec->election_timeout = tevent_add_timer(
			ctdb->ev, ctdb,
			fast_start ?
				timeval_current_ofs(0, 500000) :
				timeval_current_ofs(ctdb->tunable.election_timeout, 0),
			ctdb_election_timeout, rec);

	/* someone called an election. check their election data
	   and if we disagree and we would rather be the elected node, 
	   send a new election message to all other nodes
	 */
	if (ctdb_election_win(rec, em)) {
		if (!rec->send_election_te) {
			rec->send_election_te = tevent_add_timer(
					ctdb->ev, rec,
					timeval_current_ofs(0, 500000),
					election_send_request, rec);
		}
		return;
	}

	/* we didn't win */
	TALLOC_FREE(rec->send_election_te);

	/* Release the recovery lock file */
	if (ctdb_recovery_have_lock(rec)) {
		ctdb_recovery_unlock(rec);
	}

	/* ok, let that guy become recmaster then */
	ret = ctdb_ctrl_setrecmaster(ctdb, CONTROL_TIMEOUT(),
				     CTDB_CURRENT_NODE, em->pnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " failed to set recmaster"));
		return;
	}
	rec->recmaster = em->pnn;

	return;
}


/*
  force the start of the election process
 */
static void force_election(struct ctdb_recoverd *rec, uint32_t pnn, 
			   struct ctdb_node_map_old *nodemap)
{
	int ret;
	struct ctdb_context *ctdb = rec->ctdb;

	DEBUG(DEBUG_INFO,(__location__ " Force an election\n"));

	/* set all nodes to recovery mode to stop all internode traffic */
	ret = set_recovery_mode(ctdb, rec, nodemap, CTDB_RECOVERY_ACTIVE);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to set recovery mode to active on cluster\n"));
		return;
	}

	talloc_free(rec->election_timeout);
	rec->election_timeout = tevent_add_timer(
			ctdb->ev, ctdb,
			fast_start ?
				timeval_current_ofs(0, 500000) :
				timeval_current_ofs(ctdb->tunable.election_timeout, 0),
			ctdb_election_timeout, rec);

	ret = send_election_request(rec, pnn);
	if (ret!=0) {
		DEBUG(DEBUG_ERR, (__location__ " failed to initiate recmaster election"));
		return;
	}

	/* wait for a few seconds to collect all responses */
	ctdb_wait_election(rec);
}


static void srvid_not_implemented(uint64_t srvid,
				  TDB_DATA data,
				  void *private_data)
{
	const char *s;

	switch (srvid) {
	case CTDB_SRVID_SET_NODE_FLAGS:
		s = "CTDB_SRVID_SET_NODE_FLAGS";
		break;
	default:
		s = "UNKNOWN";
	}

	D_WARNING("SRVID %s (0x%" PRIx64 ") is obsolete\n", s, srvid);
}

/*
  handler for when we need to push out flag changes to all other nodes
*/
static void push_flags_handler(uint64_t srvid, TDB_DATA data,
			       void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type(
		private_data, struct ctdb_recoverd);
	struct ctdb_context *ctdb = rec->ctdb;
	int ret;
	struct ctdb_node_flag_change *c = (struct ctdb_node_flag_change *)data.dptr;
	struct ctdb_node_map_old *nodemap=NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	uint32_t *nodes;

	/* read the node flags from the recmaster */
	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), rec->recmaster,
				   tmp_ctx, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to get nodemap from node %u\n", c->pnn));
		talloc_free(tmp_ctx);
		return;
	}
	if (c->pnn >= nodemap->num) {
		DEBUG(DEBUG_ERR,(__location__ " Nodemap from recmaster does not contain node %d\n", c->pnn));
		talloc_free(tmp_ctx);
		return;
	}

	/* send the flags update to all connected nodes */
	nodes = list_of_connected_nodes(ctdb, nodemap, tmp_ctx, true);

	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_MODIFY_FLAGS,
				      nodes, 0, CONTROL_TIMEOUT(),
				      false, data,
				      NULL, NULL,
				      NULL) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " ctdb_control to modify node flags failed\n"));

		talloc_free(tmp_ctx);
		return;
	}

	talloc_free(tmp_ctx);
}


struct verify_recmode_normal_data {
	uint32_t count;
	enum monitor_result status;
};

static void verify_recmode_normal_callback(struct ctdb_client_control_state *state)
{
	struct verify_recmode_normal_data *rmdata = talloc_get_type(state->async.private_data, struct verify_recmode_normal_data);


	/* one more node has responded with recmode data*/
	rmdata->count--;

	/* if we failed to get the recmode, then return an error and let
	   the main loop try again.
	*/
	if (state->state != CTDB_CONTROL_DONE) {
		if (rmdata->status == MONITOR_OK) {
			rmdata->status = MONITOR_FAILED;
		}
		return;
	}

	/* if we got a response, then the recmode will be stored in the
	   status field
	*/
	if (state->status != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_NOTICE, ("Node:%u was in recovery mode. Start recovery process\n", state->c->hdr.destnode));
		rmdata->status = MONITOR_RECOVERY_NEEDED;
	}

	return;
}


/* verify that all nodes are in normal recovery mode */
static enum monitor_result verify_recmode(struct ctdb_context *ctdb, struct ctdb_node_map_old *nodemap)
{
	struct verify_recmode_normal_data *rmdata;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);
	struct ctdb_client_control_state *state;
	enum monitor_result status;
	unsigned int j;

	rmdata = talloc(mem_ctx, struct verify_recmode_normal_data);
	CTDB_NO_MEMORY_FATAL(ctdb, rmdata);
	rmdata->count  = 0;
	rmdata->status = MONITOR_OK;

	/* loop over all active nodes and send an async getrecmode call to 
	   them*/
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		state = ctdb_ctrl_getrecmode_send(ctdb, mem_ctx, 
					CONTROL_TIMEOUT(), 
					nodemap->nodes[j].pnn);
		if (state == NULL) {
			/* we failed to send the control, treat this as 
			   an error and try again next iteration
			*/			
			DEBUG(DEBUG_ERR,("Failed to call ctdb_ctrl_getrecmode_send during monitoring\n"));
			talloc_free(mem_ctx);
			return MONITOR_FAILED;
		}

		/* set up the callback functions */
		state->async.fn = verify_recmode_normal_callback;
		state->async.private_data = rmdata;

		/* one more control to wait for to complete */
		rmdata->count++;
	}


	/* now wait for up to the maximum number of seconds allowed
	   or until all nodes we expect a response from has replied
	*/
	while (rmdata->count > 0) {
		tevent_loop_once(ctdb->ev);
	}

	status = rmdata->status;
	talloc_free(mem_ctx);
	return status;
}


struct verify_recmaster_data {
	struct ctdb_recoverd *rec;
	uint32_t count;
	uint32_t pnn;
	enum monitor_result status;
};

static void verify_recmaster_callback(struct ctdb_client_control_state *state)
{
	struct verify_recmaster_data *rmdata = talloc_get_type(state->async.private_data, struct verify_recmaster_data);


	/* one more node has responded with recmaster data*/
	rmdata->count--;

	/* if we failed to get the recmaster, then return an error and let
	   the main loop try again.
	*/
	if (state->state != CTDB_CONTROL_DONE) {
		if (rmdata->status == MONITOR_OK) {
			rmdata->status = MONITOR_FAILED;
		}
		return;
	}

	/* if we got a response, then the recmaster will be stored in the
	   status field
	*/
	if ((uint32_t)state->status != rmdata->pnn) {
		DEBUG(DEBUG_ERR,("Node %d thinks node %d is recmaster. Need a new recmaster election\n", state->c->hdr.destnode, state->status));
		ctdb_set_culprit(rmdata->rec, state->c->hdr.destnode);
		rmdata->status = MONITOR_ELECTION_NEEDED;
	}

	return;
}


/* verify that all nodes agree that we are the recmaster */
static enum monitor_result verify_recmaster(struct ctdb_recoverd *rec, struct ctdb_node_map_old *nodemap, uint32_t pnn)
{
	struct ctdb_context *ctdb = rec->ctdb;
	struct verify_recmaster_data *rmdata;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);
	struct ctdb_client_control_state *state;
	enum monitor_result status;
	unsigned int j;

	rmdata = talloc(mem_ctx, struct verify_recmaster_data);
	CTDB_NO_MEMORY_FATAL(ctdb, rmdata);
	rmdata->rec    = rec;
	rmdata->count  = 0;
	rmdata->pnn    = pnn;
	rmdata->status = MONITOR_OK;

	/* loop over all active nodes and send an async getrecmaster call to
	   them*/
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].pnn == rec->recmaster) {
			continue;
		}
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		state = ctdb_ctrl_getrecmaster_send(ctdb, mem_ctx, 
					CONTROL_TIMEOUT(),
					nodemap->nodes[j].pnn);
		if (state == NULL) {
			/* we failed to send the control, treat this as 
			   an error and try again next iteration
			*/			
			DEBUG(DEBUG_ERR,("Failed to call ctdb_ctrl_getrecmaster_send during monitoring\n"));
			talloc_free(mem_ctx);
			return MONITOR_FAILED;
		}

		/* set up the callback functions */
		state->async.fn = verify_recmaster_callback;
		state->async.private_data = rmdata;

		/* one more control to wait for to complete */
		rmdata->count++;
	}


	/* now wait for up to the maximum number of seconds allowed
	   or until all nodes we expect a response from has replied
	*/
	while (rmdata->count > 0) {
		tevent_loop_once(ctdb->ev);
	}

	status = rmdata->status;
	talloc_free(mem_ctx);
	return status;
}

static bool interfaces_have_changed(struct ctdb_context *ctdb,
				    struct ctdb_recoverd *rec)
{
	struct ctdb_iface_list_old *ifaces = NULL;
	TALLOC_CTX *mem_ctx;
	bool ret = false;

	mem_ctx = talloc_new(NULL);

	/* Read the interfaces from the local node */
	if (ctdb_ctrl_get_ifaces(ctdb, CONTROL_TIMEOUT(),
				 CTDB_CURRENT_NODE, mem_ctx, &ifaces) != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get interfaces from local node %u\n", ctdb->pnn));
		/* We could return an error.  However, this will be
		 * rare so we'll decide that the interfaces have
		 * actually changed, just in case.
		 */
		talloc_free(mem_ctx);
		return true;
	}

	if (!rec->ifaces) {
		/* We haven't been here before so things have changed */
		DEBUG(DEBUG_NOTICE, ("Initial interface fetched\n"));
		ret = true;
	} else if (rec->ifaces->num != ifaces->num) {
		/* Number of interfaces has changed */
		DEBUG(DEBUG_NOTICE, ("Interface count changed from %d to %d\n",
				     rec->ifaces->num, ifaces->num));
		ret = true;
	} else {
		/* See if interface names or link states have changed */
		unsigned int i;
		for (i = 0; i < rec->ifaces->num; i++) {
			struct ctdb_iface * iface = &rec->ifaces->ifaces[i];
			if (strcmp(iface->name, ifaces->ifaces[i].name) != 0) {
				DEBUG(DEBUG_NOTICE,
				      ("Interface in slot %d changed: %s => %s\n",
				       i, iface->name, ifaces->ifaces[i].name));
				ret = true;
				break;
			}
			if (iface->link_state != ifaces->ifaces[i].link_state) {
				DEBUG(DEBUG_NOTICE,
				      ("Interface %s changed state: %d => %d\n",
				       iface->name, iface->link_state,
				       ifaces->ifaces[i].link_state));
				ret = true;
				break;
			}
		}
	}

	talloc_free(rec->ifaces);
	rec->ifaces = talloc_steal(rec, ifaces);

	talloc_free(mem_ctx);
	return ret;
}

/* Check that the local allocation of public IP addresses is correct
 * and do some house-keeping */
static int verify_local_ip_allocation(struct ctdb_context *ctdb,
				      struct ctdb_recoverd *rec,
				      uint32_t pnn,
				      struct ctdb_node_map_old *nodemap)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	unsigned int j;
	int ret;
	bool need_takeover_run = false;
	struct ctdb_public_ip_list_old *ips = NULL;

	/* If we are not the recmaster then do some housekeeping */
	if (rec->recmaster != pnn) {
		/* Ignore any IP reallocate requests - only recmaster
		 * processes them
		 */
		TALLOC_FREE(rec->reallocate_requests);
		/* Clear any nodes that should be force rebalanced in
		 * the next takeover run.  If the recovery master role
		 * has moved then we don't want to process these some
		 * time in the future.
		 */
		TALLOC_FREE(rec->force_rebalance_nodes);
	}

	/* Return early if disabled... */
	if (ctdb_config.failover_disabled ||
	    ctdb_op_is_disabled(rec->takeover_run)) {
		talloc_free(mem_ctx);
		return  0;
	}

	if (interfaces_have_changed(ctdb, rec)) {
		need_takeover_run = true;
	}

	/* If there are unhosted IPs but this node can host them then
	 * trigger an IP reallocation */

	/* Read *available* IPs from local node */
	ret = ctdb_ctrl_get_public_ips_flags(
		ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, mem_ctx,
		CTDB_PUBLIC_IP_FLAGS_ONLY_AVAILABLE, &ips);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to retrieve available public IPs\n"));
		talloc_free(mem_ctx);
		return -1;
	}

	for (j=0; j<ips->num; j++) {
		if (ips->ips[j].pnn == CTDB_UNKNOWN_PNN &&
		    nodemap->nodes[pnn].flags == 0) {
			DEBUG(DEBUG_WARNING,
			      ("Unassigned IP %s can be served by this node\n",
			       ctdb_addr_to_str(&ips->ips[j].addr)));
			need_takeover_run = true;
		}
	}

	talloc_free(ips);

	if (!ctdb->do_checkpublicip) {
		goto done;
	}

	/* Validate the IP addresses that this node has on network
	 * interfaces.  If there is an inconsistency between reality
	 * and the state expected by CTDB then try to fix it by
	 * triggering an IP reallocation or releasing extraneous IP
	 * addresses. */

	/* Read *known* IPs from local node */
	ret = ctdb_ctrl_get_public_ips_flags(
		ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, mem_ctx, 0, &ips);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to retrieve known public IPs\n"));
		talloc_free(mem_ctx);
		return -1;
	}

	for (j=0; j<ips->num; j++) {
		if (ips->ips[j].pnn == pnn) {
			if (!ctdb_sys_have_ip(&ips->ips[j].addr)) {
				DEBUG(DEBUG_ERR,
				      ("Assigned IP %s not on an interface\n",
				       ctdb_addr_to_str(&ips->ips[j].addr)));
				need_takeover_run = true;
			}
		} else {
			if (ctdb_sys_have_ip(&ips->ips[j].addr)) {
				DEBUG(DEBUG_ERR,
				      ("IP %s incorrectly on an interface\n",
				       ctdb_addr_to_str(&ips->ips[j].addr)));
				need_takeover_run = true;
			}
		}
	}

done:
	if (need_takeover_run) {
		struct ctdb_srvid_message rd;
		TDB_DATA data;

		DEBUG(DEBUG_NOTICE,("Trigger takeoverrun\n"));

		ZERO_STRUCT(rd);
		rd.pnn = ctdb->pnn;
		rd.srvid = 0;
		data.dptr = (uint8_t *)&rd;
		data.dsize = sizeof(rd);

		ret = ctdb_client_send_message(ctdb, rec->recmaster, CTDB_SRVID_TAKEOVER_RUN, data);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,
			      ("Failed to send takeover run request\n"));
		}
	}
	talloc_free(mem_ctx);
	return 0;
}


struct remote_nodemaps_state {
	struct ctdb_node_map_old **remote_nodemaps;
	struct ctdb_recoverd *rec;
};

static void async_getnodemap_callback(struct ctdb_context *ctdb,
				      uint32_t node_pnn,
				      int32_t res,
				      TDB_DATA outdata,
				      void *callback_data)
{
	struct remote_nodemaps_state *state =
		(struct remote_nodemaps_state *)callback_data;
	struct ctdb_node_map_old **remote_nodemaps = state->remote_nodemaps;
	struct ctdb_node_map_old *nodemap = state->rec->nodemap;
	size_t i;

	for (i = 0; i < nodemap->num; i++) {
		if (nodemap->nodes[i].pnn == node_pnn) {
			break;
		}
	}

	if (i >= nodemap->num) {
		DBG_ERR("Invalid PNN %"PRIu32"\n", node_pnn);
		return;
	}

	remote_nodemaps[i] = (struct ctdb_node_map_old *)talloc_steal(
					remote_nodemaps, outdata.dptr);

}

static void async_getnodemap_error(struct ctdb_context *ctdb,
				   uint32_t node_pnn,
				   int32_t res,
				   TDB_DATA outdata,
				   void *callback_data)
{
	struct remote_nodemaps_state *state =
		(struct remote_nodemaps_state *)callback_data;
	struct ctdb_recoverd *rec = state->rec;

	DBG_ERR("Failed to retrieve nodemap from node %u\n", node_pnn);
	ctdb_set_culprit(rec, node_pnn);
}

static int get_remote_nodemaps(struct ctdb_recoverd *rec,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_node_map_old ***remote_nodemaps)
{
	struct ctdb_context *ctdb = rec->ctdb;
	struct ctdb_node_map_old **t;
	uint32_t *nodes;
	struct remote_nodemaps_state state;
	int ret;

	t = talloc_zero_array(mem_ctx,
			      struct ctdb_node_map_old *,
			      rec->nodemap->num);
	if (t == NULL) {
		DBG_ERR("Memory allocation error\n");
		return -1;
	}

	nodes = list_of_connected_nodes(ctdb, rec->nodemap, mem_ctx, false);

	state.remote_nodemaps = t;
	state.rec = rec;

	ret = ctdb_client_async_control(ctdb,
					CTDB_CONTROL_GET_NODEMAP,
					nodes,
					0,
					CONTROL_TIMEOUT(),
					false,
					tdb_null,
					async_getnodemap_callback,
					async_getnodemap_error,
					&state);
	talloc_free(nodes);

	if (ret != 0) {
		talloc_free(t);
		return ret;
	}

	*remote_nodemaps = t;
	return 0;
}

static bool validate_recovery_master(struct ctdb_recoverd *rec,
				     TALLOC_CTX *mem_ctx)
{
	struct ctdb_context *ctdb = rec->ctdb;
	uint32_t pnn = ctdb_get_pnn(ctdb);
	struct ctdb_node_map_old *nodemap = rec->nodemap;
	struct ctdb_node_map_old *recmaster_nodemap = NULL;
	int ret;

	/* When recovery daemon is started, recmaster is set to
	 * "unknown" so it knows to start an election.
	 */
	if (rec->recmaster == CTDB_UNKNOWN_PNN) {
		DEBUG(DEBUG_NOTICE,
		      ("Initial recovery master set - forcing election\n"));
		force_election(rec, pnn, nodemap);
		return false;
	}

	/*
	 * If the current recmaster does not have CTDB_CAP_RECMASTER,
	 * but we have, then force an election and try to become the new
	 * recmaster.
	 */
	if (!ctdb_node_has_capabilities(rec->caps,
					rec->recmaster,
					CTDB_CAP_RECMASTER) &&
	    (rec->ctdb->capabilities & CTDB_CAP_RECMASTER) &&
	    !(nodemap->nodes[pnn].flags & NODE_FLAGS_INACTIVE)) {
		DEBUG(DEBUG_ERR,
		      (" Current recmaster node %u does not have CAP_RECMASTER,"
		       " but we (node %u) have - force an election\n",
		       rec->recmaster, pnn));
		force_election(rec, pnn, nodemap);
		return false;
	}

	/* Verify that the master node has not been deleted.  This
	 * should not happen because a node should always be shutdown
	 * before being deleted, causing a new master to be elected
	 * before now.  However, if something strange has happened
	 * then checking here will ensure we don't index beyond the
	 * end of the nodemap array. */
	if (rec->recmaster >= nodemap->num) {
		DEBUG(DEBUG_ERR,
		      ("Recmaster node %u has been deleted. Force election\n",
		       rec->recmaster));
		force_election(rec, pnn, nodemap);
		return false;
	}

	/* if recovery master is disconnected/deleted we must elect a new recmaster */
	if (nodemap->nodes[rec->recmaster].flags &
	    (NODE_FLAGS_DISCONNECTED|NODE_FLAGS_DELETED)) {
		DEBUG(DEBUG_NOTICE,
		      ("Recmaster node %u is disconnected/deleted. Force election\n",
		       rec->recmaster));
		force_election(rec, pnn, nodemap);
		return false;
	}

	/* get nodemap from the recovery master to check if it is inactive */
	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), rec->recmaster,
				   mem_ctx, &recmaster_nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      (__location__
		       " Unable to get nodemap from recovery master %u\n",
			  rec->recmaster));
		/* No election, just error */
		return false;
	}


	if ((recmaster_nodemap->nodes[rec->recmaster].flags & NODE_FLAGS_INACTIVE) &&
	    (rec->node_flags & NODE_FLAGS_INACTIVE) == 0) {
		DEBUG(DEBUG_NOTICE,
		      ("Recmaster node %u is inactive. Force election\n",
		       rec->recmaster));
		/*
		 * update our nodemap to carry the recmaster's notion of
		 * its own flags, so that we don't keep freezing the
		 * inactive recmaster node...
		 */
		nodemap->nodes[rec->recmaster].flags =
			recmaster_nodemap->nodes[rec->recmaster].flags;
		force_election(rec, pnn, nodemap);
		return false;
	}

	return true;
}

static void main_loop(struct ctdb_context *ctdb, struct ctdb_recoverd *rec,
		      TALLOC_CTX *mem_ctx)
{
	uint32_t pnn;
	struct ctdb_node_map_old *nodemap=NULL;
	struct ctdb_node_map_old **remote_nodemaps=NULL;
	struct ctdb_vnn_map *vnnmap=NULL;
	struct ctdb_vnn_map *remote_vnnmap=NULL;
	uint32_t num_lmasters;
	int32_t debug_level;
	unsigned int i, j;
	int ret;
	bool self_ban;


	/* verify that the main daemon is still running */
	if (ctdb_kill(ctdb, ctdb->ctdbd_pid, 0) != 0) {
		DEBUG(DEBUG_CRIT,("CTDB daemon is no longer available. Shutting down recovery daemon\n"));
		exit(-1);
	}

	/* ping the local daemon to tell it we are alive */
	ctdb_ctrl_recd_ping(ctdb);

	if (rec->election_timeout) {
		/* an election is in progress */
		return;
	}

	/* read the debug level from the parent and update locally */
	ret = ctdb_ctrl_get_debuglevel(ctdb, CTDB_CURRENT_NODE, &debug_level);
	if (ret !=0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to read debuglevel from parent\n"));
		return;
	}
	debuglevel_set(debug_level);

	/* get relevant tunables */
	ret = ctdb_ctrl_get_all_tunables(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, &ctdb->tunable);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to get tunables - retrying\n"));
		return;
	}

	/* get runstate */
	ret = ctdb_ctrl_get_runstate(ctdb, CONTROL_TIMEOUT(),
				     CTDB_CURRENT_NODE, &ctdb->runstate);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to get runstate - retrying\n"));
		return;
	}

	pnn = ctdb_get_pnn(ctdb);

	/* get nodemap */
	ret = ctdb_ctrl_getnodemap(ctdb, CONTROL_TIMEOUT(), pnn, rec, &nodemap);
	if (ret != 0) {
		DBG_ERR("Unable to get nodemap from node %"PRIu32"\n", pnn);
		return;
	}
	talloc_free(rec->nodemap);
	rec->nodemap = nodemap;

	/* remember our own node flags */
	rec->node_flags = nodemap->nodes[pnn].flags;

	ban_misbehaving_nodes(rec, &self_ban);
	if (self_ban) {
		DEBUG(DEBUG_NOTICE, ("This node was banned, restart main_loop\n"));
		return;
	}

	ret = ctdb_ctrl_getrecmode(ctdb, mem_ctx, CONTROL_TIMEOUT(),
				   CTDB_CURRENT_NODE, &ctdb->recovery_mode);
	if (ret != 0) {
		D_ERR("Failed to read recmode from local node\n");
		return;
	}

	/* if the local daemon is STOPPED or BANNED, we verify that the databases are
	   also frozen and that the recmode is set to active.
	*/
	if (rec->node_flags & (NODE_FLAGS_STOPPED | NODE_FLAGS_BANNED)) {
		/* If this node has become inactive then we want to
		 * reduce the chances of it taking over the recovery
		 * master role when it becomes active again.  This
		 * helps to stabilise the recovery master role so that
		 * it stays on the most stable node.
		 */
		rec->priority_time = timeval_current();

		if (ctdb->recovery_mode == CTDB_RECOVERY_NORMAL) {
			DEBUG(DEBUG_ERR,("Node is stopped or banned but recovery mode is not active. Activate recovery mode and lock databases\n"));

			ret = ctdb_ctrl_setrecmode(ctdb, CONTROL_TIMEOUT(), CTDB_CURRENT_NODE, CTDB_RECOVERY_ACTIVE);
			if (ret != 0) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to activate recovery mode in STOPPED or BANNED state\n"));

				return;
			}
		}
		if (! rec->frozen_on_inactive) {
			ret = ctdb_ctrl_freeze(ctdb, CONTROL_TIMEOUT(),
					       CTDB_CURRENT_NODE);
			if (ret != 0) {
				DEBUG(DEBUG_ERR,
				      (__location__ " Failed to freeze node "
				       "in STOPPED or BANNED state\n"));
				return;
			}

			rec->frozen_on_inactive = true;
		}

		/* If this node is stopped or banned then it is not the recovery
		 * master, so don't do anything. This prevents stopped or banned
		 * node from starting election and sending unnecessary controls.
		 */
		return;
	}

	rec->frozen_on_inactive = false;

	/* Retrieve capabilities from all connected nodes */
	ret = update_capabilities(rec, nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to update node capabilities.\n"));
		return;
	}

	if (! validate_recovery_master(rec, mem_ctx)) {
		return;
	}

	if (ctdb->recovery_mode == CTDB_RECOVERY_NORMAL) {
		/* Check if an IP takeover run is needed and trigger one if
		 * necessary */
		verify_local_ip_allocation(ctdb, rec, pnn, nodemap);
	}

	/* if we are not the recmaster then we do not need to check
	   if recovery is needed
	 */
	if (pnn != rec->recmaster) {
		return;
	}


	/* Get the nodemaps for all connected remote nodes */
	ret = get_remote_nodemaps(rec, mem_ctx, &remote_nodemaps);
	if (ret != 0) {
		DBG_ERR("Failed to read remote nodemaps\n");
		return;
	}

	/* Ensure our local and remote flags are correct */
	ret = update_flags(rec, nodemap, remote_nodemaps);
	if (ret != 0) {
		D_ERR("Unable to update flags\n");
		return;
	}

	if (ctdb->num_nodes != nodemap->num) {
		DEBUG(DEBUG_ERR, (__location__ " ctdb->num_nodes (%d) != nodemap->num (%d) reloading nodes file\n", ctdb->num_nodes, nodemap->num));
		ctdb_load_nodes_file(ctdb);
		return;
	}

	/* verify that all active nodes agree that we are the recmaster */
	switch (verify_recmaster(rec, nodemap, pnn)) {
	case MONITOR_RECOVERY_NEEDED:
		/* can not happen */
		return;
	case MONITOR_ELECTION_NEEDED:
		force_election(rec, pnn, nodemap);
		return;
	case MONITOR_OK:
		break;
	case MONITOR_FAILED:
		return;
	}


	/* get the vnnmap */
	ret = ctdb_ctrl_getvnnmap(ctdb, CONTROL_TIMEOUT(), pnn, mem_ctx, &vnnmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Unable to get vnnmap from node %u\n", pnn));
		return;
	}

	if (rec->need_recovery) {
		/* a previous recovery didn't finish */
		do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap);
		return;
	}

	/* verify that all active nodes are in normal mode 
	   and not in recovery mode 
	*/
	switch (verify_recmode(ctdb, nodemap)) {
	case MONITOR_RECOVERY_NEEDED:
		do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap);
		return;
	case MONITOR_FAILED:
		return;
	case MONITOR_ELECTION_NEEDED:
		/* can not happen */
	case MONITOR_OK:
		break;
	}


        if (ctdb->recovery_lock != NULL) {
		/* We must already hold the recovery lock */
		if (!ctdb_recovery_have_lock(rec)) {
			DEBUG(DEBUG_ERR,("Failed recovery lock sanity check.  Force a recovery\n"));
			ctdb_set_culprit(rec, ctdb->pnn);
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap);
			return;
		}
	}


	/* If recoveries are disabled then there is no use doing any
	 * nodemap or flags checks.  Recoveries might be disabled due
	 * to "reloadnodes", so doing these checks might cause an
	 * unnecessary recovery.  */
	if (ctdb_op_is_disabled(rec->recovery)) {
		goto takeover_run_checks;
	}

	/* verify that all other nodes have the same nodemap as we have
	*/
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].pnn == ctdb->pnn) {
			continue;
		}
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

 		/* if the nodes disagree on how many nodes there are
		   then this is a good reason to try recovery
		 */
		if (remote_nodemaps[j]->num != nodemap->num) {
			DEBUG(DEBUG_ERR, (__location__ " Remote node:%u has different node count. %u vs %u of the local node\n",
				  nodemap->nodes[j].pnn, remote_nodemaps[j]->num, nodemap->num));
			ctdb_set_culprit(rec, nodemap->nodes[j].pnn);
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap);
			return;
		}

		/* if the nodes disagree on which nodes exist and are
		   active, then that is also a good reason to do recovery
		 */
		for (i=0;i<nodemap->num;i++) {
			if (remote_nodemaps[j]->nodes[i].pnn != nodemap->nodes[i].pnn) {
				DEBUG(DEBUG_ERR, (__location__ " Remote node:%u has different nodemap pnn for %d (%u vs %u).\n", 
					  nodemap->nodes[j].pnn, i, 
					  remote_nodemaps[j]->nodes[i].pnn, nodemap->nodes[i].pnn));
				ctdb_set_culprit(rec, nodemap->nodes[j].pnn);
				do_recovery(rec, mem_ctx, pnn, nodemap, 
					    vnnmap);
				return;
			}
		}
	}

	/* count how many active nodes there are */
	num_lmasters  = 0;
	for (i=0; i<nodemap->num; i++) {
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE)) {
			if (ctdb_node_has_capabilities(rec->caps,
						       ctdb->nodes[i]->pnn,
						       CTDB_CAP_LMASTER)) {
				num_lmasters++;
			}
		}
	}


	/* There must be the same number of lmasters in the vnn map as
	 * there are active nodes with the lmaster capability...  or
	 * do a recovery.
	 */
	if (vnnmap->size != num_lmasters) {
		DEBUG(DEBUG_ERR, (__location__ " The vnnmap count is different from the number of active lmaster nodes: %u vs %u\n",
			  vnnmap->size, num_lmasters));
		ctdb_set_culprit(rec, ctdb->pnn);
		do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap);
		return;
	}

	/*
	 * Verify that all active lmaster nodes in the nodemap also
	 * exist in the vnnmap
	 */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (! ctdb_node_has_capabilities(rec->caps,
						 nodemap->nodes[j].pnn,
						 CTDB_CAP_LMASTER)) {
			continue;
		}
		if (nodemap->nodes[j].pnn == pnn) {
			continue;
		}

		for (i=0; i<vnnmap->size; i++) {
			if (vnnmap->map[i] == nodemap->nodes[j].pnn) {
				break;
			}
		}
		if (i == vnnmap->size) {
			D_ERR("Active LMASTER node %u is not in the vnnmap\n",
			      nodemap->nodes[j].pnn);
			ctdb_set_culprit(rec, nodemap->nodes[j].pnn);
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap);
			return;
		}
	}

	
	/* verify that all other nodes have the same vnnmap
	   and are from the same generation
	 */
	for (j=0; j<nodemap->num; j++) {
		if (nodemap->nodes[j].flags & NODE_FLAGS_INACTIVE) {
			continue;
		}
		if (nodemap->nodes[j].pnn == pnn) {
			continue;
		}

		ret = ctdb_ctrl_getvnnmap(ctdb, CONTROL_TIMEOUT(), nodemap->nodes[j].pnn, 
					  mem_ctx, &remote_vnnmap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Unable to get vnnmap from remote node %u\n", 
				  nodemap->nodes[j].pnn));
			return;
		}

		/* verify the vnnmap generation is the same */
		if (vnnmap->generation != remote_vnnmap->generation) {
			DEBUG(DEBUG_ERR, (__location__ " Remote node %u has different generation of vnnmap. %u vs %u (ours)\n", 
				  nodemap->nodes[j].pnn, remote_vnnmap->generation, vnnmap->generation));
			ctdb_set_culprit(rec, nodemap->nodes[j].pnn);
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap);
			return;
		}

		/* verify the vnnmap size is the same */
		if (vnnmap->size != remote_vnnmap->size) {
			DEBUG(DEBUG_ERR, (__location__ " Remote node %u has different size of vnnmap. %u vs %u (ours)\n", 
				  nodemap->nodes[j].pnn, remote_vnnmap->size, vnnmap->size));
			ctdb_set_culprit(rec, nodemap->nodes[j].pnn);
			do_recovery(rec, mem_ctx, pnn, nodemap, vnnmap);
			return;
		}

		/* verify the vnnmap is the same */
		for (i=0;i<vnnmap->size;i++) {
			if (remote_vnnmap->map[i] != vnnmap->map[i]) {
				DEBUG(DEBUG_ERR, (__location__ " Remote node %u has different vnnmap.\n", 
					  nodemap->nodes[j].pnn));
				ctdb_set_culprit(rec, nodemap->nodes[j].pnn);
				do_recovery(rec, mem_ctx, pnn, nodemap, 
					    vnnmap);
				return;
			}
		}
	}

	/* FIXME: Add remote public IP checking to ensure that nodes
	 * have the IP addresses that are allocated to them. */

takeover_run_checks:

	/* If there are IP takeover runs requested or the previous one
	 * failed then perform one and notify the waiters */
	if (!ctdb_op_is_disabled(rec->takeover_run) &&
	    (rec->reallocate_requests || rec->need_takeover_run)) {
		process_ipreallocate_requests(ctdb, rec);
	}
}

static void recd_sig_term_handler(struct tevent_context *ev,
				  struct tevent_signal *se, int signum,
				  int count, void *dont_care,
				  void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type_abort(
		private_data, struct ctdb_recoverd);

	DEBUG(DEBUG_ERR, ("Received SIGTERM, exiting\n"));
	ctdb_recovery_unlock(rec);
	exit(0);
}

/*
 * Periodically log elements of the cluster state
 *
 * This can be used to confirm a split brain has occurred
 */
static void maybe_log_cluster_state(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *private_data)
{
	struct ctdb_recoverd *rec = talloc_get_type_abort(
		private_data, struct ctdb_recoverd);
	struct ctdb_context *ctdb = rec->ctdb;
	struct tevent_timer *tt;

	static struct timeval start_incomplete = {
		.tv_sec = 0,
	};

	bool is_complete;
	bool was_complete;
	unsigned int i;
	double seconds;
	unsigned int minutes;
	unsigned int num_connected;

	if (rec->recmaster != ctdb_get_pnn(ctdb)) {
		goto done;
	}

	if (rec->nodemap == NULL) {
		goto done;
	}

	is_complete = true;
	num_connected = 0;
	for (i = 0; i < rec->nodemap->num; i++) {
		struct ctdb_node_and_flags *n = &rec->nodemap->nodes[i];

		if (n->pnn == ctdb_get_pnn(ctdb)) {
			continue;
		}
		if ((n->flags & NODE_FLAGS_DELETED) != 0) {
			continue;
		}
		if ((n->flags & NODE_FLAGS_DISCONNECTED) != 0) {
			is_complete = false;
			continue;
		}

		num_connected++;
	}

	was_complete = timeval_is_zero(&start_incomplete);

	if (is_complete) {
		if (! was_complete) {
			D_WARNING("Cluster complete with master=%u\n",
				  rec->recmaster);
			start_incomplete = timeval_zero();
		}
		goto done;
	}

	/* Cluster is newly incomplete... */
	if (was_complete) {
		start_incomplete = current_time;
		minutes = 0;
		goto log;
	}

	/*
	 * Cluster has been incomplete since previous check, so figure
	 * out how long (in minutes) and decide whether to log anything
	 */
	seconds = timeval_elapsed2(&start_incomplete, &current_time);
	minutes = (unsigned int)seconds / 60;
	if (minutes >= 60) {
		/* Over an hour, log every hour */
		if (minutes % 60 != 0) {
			goto done;
		}
	} else if (minutes >= 10) {
		/* Over 10 minutes, log every 10 minutes */
		if (minutes % 10 != 0) {
			goto done;
		}
	}

log:
	D_WARNING("Cluster incomplete with master=%u, elapsed=%u minutes, "
		  "connected=%u\n",
		  rec->recmaster,
		  minutes,
		  num_connected);

done:
	tt = tevent_add_timer(ctdb->ev,
			      rec,
			      timeval_current_ofs(60, 0),
			      maybe_log_cluster_state,
			      rec);
	if (tt == NULL) {
		DBG_WARNING("Failed to set up cluster state timer\n");
	}
}

/*
  the main monitoring loop
 */
static void monitor_cluster(struct ctdb_context *ctdb)
{
	struct tevent_signal *se;
	struct ctdb_recoverd *rec;

	DEBUG(DEBUG_NOTICE,("monitor_cluster starting\n"));

	rec = talloc_zero(ctdb, struct ctdb_recoverd);
	CTDB_NO_MEMORY_FATAL(ctdb, rec);

	rec->ctdb = ctdb;
	rec->recmaster = CTDB_UNKNOWN_PNN;
	rec->recovery_lock_handle = NULL;

	rec->takeover_run = ctdb_op_init(rec, "takeover runs");
	CTDB_NO_MEMORY_FATAL(ctdb, rec->takeover_run);

	rec->recovery = ctdb_op_init(rec, "recoveries");
	CTDB_NO_MEMORY_FATAL(ctdb, rec->recovery);

	rec->priority_time = timeval_current();
	rec->frozen_on_inactive = false;

	se = tevent_add_signal(ctdb->ev, ctdb, SIGTERM, 0,
			       recd_sig_term_handler, rec);
	if (se == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to install SIGTERM handler\n"));
		exit(1);
	}

	if (ctdb->recovery_lock == NULL) {
		struct tevent_timer *tt;

		tt = tevent_add_timer(ctdb->ev,
				      rec,
				      timeval_current_ofs(60, 0),
				      maybe_log_cluster_state,
				      rec);
		if (tt == NULL) {
			DBG_WARNING("Failed to set up cluster state timer\n");
		}
	}

	/* register a message port for sending memory dumps */
	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_MEM_DUMP, mem_dump_handler, rec);

	/* when a node is assigned banning credits */
	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_BANNING,
					banning_handler, rec);

	/* register a message port for recovery elections */
	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_ELECTION, election_handler, rec);

	ctdb_client_set_message_handler(ctdb,
					CTDB_SRVID_SET_NODE_FLAGS,
					srvid_not_implemented,
					rec);

	/* when we are asked to puch out a flag change */
	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_PUSH_NODE_FLAGS, push_flags_handler, rec);

	/* register a message port for reloadnodes  */
	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_RELOAD_NODES, reload_nodes_handler, rec);

	/* register a message port for performing a takeover run */
	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_TAKEOVER_RUN, ip_reallocate_handler, rec);

	/* register a message port for disabling the ip check for a short while */
	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_DISABLE_IP_CHECK, disable_ip_check_handler, rec);

	/* register a message port for forcing a rebalance of a node next
	   reallocation */
	ctdb_client_set_message_handler(ctdb, CTDB_SRVID_REBALANCE_NODE, recd_node_rebalance_handler, rec);

	/* Register a message port for disabling takeover runs */
	ctdb_client_set_message_handler(ctdb,
					CTDB_SRVID_DISABLE_TAKEOVER_RUNS,
					disable_takeover_runs_handler, rec);

	/* Register a message port for disabling recoveries */
	ctdb_client_set_message_handler(ctdb,
					CTDB_SRVID_DISABLE_RECOVERIES,
					disable_recoveries_handler, rec);

	for (;;) {
		TALLOC_CTX *mem_ctx = talloc_new(ctdb);
		struct timeval start;
		double elapsed;

		if (!mem_ctx) {
			DEBUG(DEBUG_CRIT,(__location__
					  " Failed to create temp context\n"));
			exit(-1);
		}

		start = timeval_current();
		main_loop(ctdb, rec, mem_ctx);
		talloc_free(mem_ctx);

		/* we only check for recovery once every second */
		elapsed = timeval_elapsed(&start);
		if (elapsed < ctdb->tunable.recover_interval) {
			ctdb_wait_timeout(ctdb, ctdb->tunable.recover_interval
					  - elapsed);
		}
	}
}

/*
  event handler for when the main ctdbd dies
 */
static void ctdb_recoverd_parent(struct tevent_context *ev,
				 struct tevent_fd *fde,
				 uint16_t flags, void *private_data)
{
	DEBUG(DEBUG_ALERT,("recovery daemon parent died - exiting\n"));
	_exit(1);
}

/*
  called regularly to verify that the recovery daemon is still running
 */
static void ctdb_check_recd(struct tevent_context *ev,
			    struct tevent_timer *te,
			    struct timeval yt, void *p)
{
	struct ctdb_context *ctdb = talloc_get_type(p, struct ctdb_context);

	if (ctdb_kill(ctdb, ctdb->recoverd_pid, 0) != 0) {
		DEBUG(DEBUG_ERR,("Recovery daemon (pid:%d) is no longer running. Trying to restart recovery daemon.\n", (int)ctdb->recoverd_pid));

		tevent_add_timer(ctdb->ev, ctdb, timeval_zero(),
				 ctdb_restart_recd, ctdb);

		return;
	}

	tevent_add_timer(ctdb->ev, ctdb->recd_ctx,
			 timeval_current_ofs(30, 0),
			 ctdb_check_recd, ctdb);
}

static void recd_sig_child_handler(struct tevent_context *ev,
				   struct tevent_signal *se, int signum,
				   int count, void *dont_care,
				   void *private_data)
{
//	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int status;
	pid_t pid = -1;

	while (pid != 0) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1) {
			if (errno != ECHILD) {
				DEBUG(DEBUG_ERR, (__location__ " waitpid() returned error. errno:%s(%d)\n", strerror(errno),errno));
			}
			return;
		}
		if (pid > 0) {
			DEBUG(DEBUG_DEBUG, ("RECD SIGCHLD from %d\n", (int)pid));
		}
	}
}

/*
  startup the recovery daemon as a child of the main ctdb daemon
 */
int ctdb_start_recoverd(struct ctdb_context *ctdb)
{
	int fd[2];
	struct tevent_signal *se;
	struct tevent_fd *fde;
	int ret;

	if (pipe(fd) != 0) {
		return -1;
	}

	ctdb->recoverd_pid = ctdb_fork(ctdb);
	if (ctdb->recoverd_pid == -1) {
		return -1;
	}

	if (ctdb->recoverd_pid != 0) {
		talloc_free(ctdb->recd_ctx);
		ctdb->recd_ctx = talloc_new(ctdb);
		CTDB_NO_MEMORY(ctdb, ctdb->recd_ctx);

		close(fd[0]);
		tevent_add_timer(ctdb->ev, ctdb->recd_ctx,
				 timeval_current_ofs(30, 0),
				 ctdb_check_recd, ctdb);
		return 0;
	}

	close(fd[1]);

	srandom(getpid() ^ time(NULL));

	ret = logging_init(ctdb, NULL, NULL, "ctdb-recoverd");
	if (ret != 0) {
		return -1;
	}

	prctl_set_comment("ctdb_recoverd");
	if (switch_from_server_to_client(ctdb) != 0) {
		DEBUG(DEBUG_CRIT, (__location__ "ERROR: failed to switch recovery daemon into client mode. shutting down.\n"));
		exit(1);
	}

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d to recovery daemon\n", fd[0]));

	fde = tevent_add_fd(ctdb->ev, ctdb, fd[0], TEVENT_FD_READ,
			    ctdb_recoverd_parent, &fd[0]);
	tevent_fd_set_auto_close(fde);

	/* set up a handler to pick up sigchld */
	se = tevent_add_signal(ctdb->ev, ctdb, SIGCHLD, 0,
			       recd_sig_child_handler, ctdb);
	if (se == NULL) {
		DEBUG(DEBUG_CRIT,("Failed to set up signal handler for SIGCHLD in recovery daemon\n"));
		exit(1);
	}

	monitor_cluster(ctdb);

	DEBUG(DEBUG_ALERT,("ERROR: ctdb_recoverd finished!?\n"));
	return -1;
}

/*
  shutdown the recovery daemon
 */
void ctdb_stop_recoverd(struct ctdb_context *ctdb)
{
	if (ctdb->recoverd_pid == 0) {
		return;
	}

	DEBUG(DEBUG_NOTICE,("Shutting down recovery daemon\n"));
	ctdb_kill(ctdb, ctdb->recoverd_pid, SIGTERM);

	TALLOC_FREE(ctdb->recd_ctx);
	TALLOC_FREE(ctdb->recd_ping_count);
}

static void ctdb_restart_recd(struct tevent_context *ev,
			      struct tevent_timer *te,
			      struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);

	DEBUG(DEBUG_ERR,("Restarting recovery daemon\n"));
	ctdb_stop_recoverd(ctdb);
	ctdb_start_recoverd(ctdb);
}
