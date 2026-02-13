/*
 * Samba rate limiting coordination daemon
 *
 * Copyright (c) 2026 Avan Thakkar <athakkar@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd_ratelimitd.h"
#include "ratelimit_protocol.h"
#include "lib/util/time.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/tevent_unix.h"
#include "messages.h"
#include "librpc/gen_ndr/messaging.h"
#include "system/filesys.h"
#include <sys/socket.h>
#include <sys/un.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define MODULE_NAME "ratelimitd"

/* Activity timeout - 5 seconds */
#define RATELIMITD_ACTIVITY_TIMEOUT_US (5000000L)

/* Broadcast interval - 1 second */
#define RATELIMITD_BROADCAST_INTERVAL_US (1000000L)

/* Remove processes inactive for more than 1 hour */
#define INACTIVE_CLEANUP_THRESHOLD_US (3600000000L)

/* Per-process activity tracking */
struct process_activity {
	struct process_activity *prev, *next;
	pid_t pid;
	char share_name[RATELIMIT_SHARE_NAME_LEN];
	char op[8];
	int64_t recent_iops;
	uint32_t inflight_ios;
	uint64_t last_seen_usec;
	bool is_active;
};

struct smbd_ratelimitd_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	int unix_sock;
	char *socket_path;
	uint32_t my_vnn;

	struct process_activity *processes;

	struct tevent_timer *broadcast_timer;
	uint64_t last_broadcast_usec;

	uint64_t total_reports_received;
	uint64_t total_broadcasts_sent;
};

static int smbd_ratelimitd_state_destructor(
	struct smbd_ratelimitd_state *state)
{
	int ret;

	if (state->unix_sock != -1) {
		close(state->unix_sock);
		state->unix_sock = -1;
	}

	if (state->socket_path != NULL) {
		ret = unlink(state->socket_path);
		if (ret == 0) {
			DBG_DEBUG("[%s] Removed socket: %s\n",
				  MODULE_NAME,
				  state->socket_path);
		} else if (errno != ENOENT) {
			DBG_WARNING("[%s] Failed to remove socket %s: %s\n",
				    MODULE_NAME,
				    state->socket_path,
				    strerror(errno));
		}
	}

	return 0;
}

static struct process_activity *find_process_activity(
	struct smbd_ratelimitd_state *state,
	pid_t pid,
	const char *share_name,
	const char *op)
{
	struct process_activity *proc;

	for (proc = state->processes; proc != NULL; proc = proc->next) {
		if (proc->pid == pid &&
		    strcmp(proc->share_name, share_name) == 0 &&
		    strcmp(proc->op, op) == 0)
		{
			DBG_DEBUG("[%s] find_process_activity: FOUND\n",
				  MODULE_NAME);
			return proc;
		}
	}

	DBG_DEBUG("[%s] find_process_activity: NOT FOUND\n", MODULE_NAME);
	return NULL;
}

static void update_process_activity(
	struct smbd_ratelimitd_state *state,
	const struct ratelimit_activity_report *report)
{
	struct process_activity *proc;
	const char *op_str;
	bool is_new = false;

	op_str = ratelimit_op_to_string(report->operation);

	proc = find_process_activity(state,
				     (pid_t)report->pid,
				     report->share_name,
				     op_str);

	if (proc == NULL) {
		DBG_DEBUG("[%s] update_process_activity: process not found, "
			  "creating new\n",
			  MODULE_NAME);

		proc = talloc_zero(state, struct process_activity);
		if (proc == NULL) {
			DBG_ERR("[%s] update_process_activity: failed to "
				"allocate process entry\n",
				MODULE_NAME);
			return;
		}

		proc->pid = report->pid;
		strlcpy(proc->share_name,
			report->share_name,
			sizeof(proc->share_name));
		strlcpy(proc->op, op_str, sizeof(proc->op));
		is_new = true;

		DLIST_ADD(state->processes, proc);

		DBG_DEBUG("[%s] NEW process tracked: pid=%d share=%s op=%s\n",
			  MODULE_NAME,
			  proc->pid,
			  proc->share_name,
			  proc->op);
	} else {
		DBG_DEBUG("[%s] update_process_activity: updating existing "
			  "process\n",
			  MODULE_NAME);
	}

	proc->recent_iops = report->recent_iops;
	proc->inflight_ios = report->inflight_ios;
	proc->last_seen_usec = report->timestamp_usec;
	proc->is_active = (report->recent_iops > 0 ||
			   report->inflight_ios > 0);

	DBG_DEBUG("[%s] Updated: pid=%d share=%s op=%s iops=%" PRId64 " "
		  "inflight=%u active=%d %s\n",
		  MODULE_NAME,
		  proc->pid,
		  proc->share_name,
		  proc->op,
		  proc->recent_iops,
		  proc->inflight_ios,
		  proc->is_active,
		  is_new ? "[NEW]" : "[EXISTING]");
}

static void handle_unix_socket_read(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data)
{
	struct smbd_ratelimitd_state *state = private_data;
	struct ratelimit_activity_report report;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	ssize_t ret;

	ret = recvfrom(state->unix_sock,
		       &report,
		       sizeof(report),
		       0,
		       (struct sockaddr *)&from,
		       &fromlen);

	if (ret < 0) {
		DBG_ERR("[%s] recvfrom() failed: %s\n",
			MODULE_NAME,
			strerror(errno));
		return;
	}

	if (ret != sizeof(report)) {
		DBG_ERR("[%s] Short read: got %zd, expected %zu\n",
			MODULE_NAME,
			ret,
			sizeof(report));
		return;
	}

	report.share_name[sizeof(report.share_name) - 1] = '\0';

	DBG_DEBUG("[%s] handle_unix_socket_read: received report "
		  "pid=%d share=%s op=%s recent_iops=%" PRId64 "\n",
		  MODULE_NAME,
		  report.pid,
		  report.share_name,
		  ratelimit_op_to_string(report.operation),
		  report.recent_iops);

	if (report.protocol_version != RATELIMIT_PROTOCOL_VERSION) {
		DBG_ERR("[%s] Protocol mismatch: got %u, expected %u\n",
			MODULE_NAME,
			report.protocol_version,
			RATELIMIT_PROTOCOL_VERSION);
		return;
	}

	update_process_activity(state, &report);
	state->total_reports_received++;

	DBG_DEBUG("[%s] handle_unix_socket_read: DONE total_reports=%" PRIu64
		  "\n",
		  MODULE_NAME,
		  state->total_reports_received);
}

static void cleanup_inactive_processes(struct smbd_ratelimitd_state *state)
{
	uint64_t now = time_now_usec();
	struct process_activity *proc, *next;
	unsigned int removed = 0;

	for (proc = state->processes; proc != NULL; proc = next) {
		uint64_t age_us = now - proc->last_seen_usec;
		next = proc->next;

		if (!proc->is_active && age_us > INACTIVE_CLEANUP_THRESHOLD_US)
		{
			DLIST_REMOVE(state->processes, proc);
			TALLOC_FREE(proc);
			removed++;
		}
	}

	if (removed > 0) {
		DBG_NOTICE("[%s] Cleaned up %d inactive processes\n",
			   MODULE_NAME,
			   removed);
	}
}

static void broadcast_summary(struct smbd_ratelimitd_state *state,
			      const char *op,
			      const char *share_name,
			      int32_t count,
			      uint64_t timestamp_usec)
{
	struct ratelimit_node_summary summary = {0};
	DATA_BLOB blob;

	if (count <= 0) {
		return;
	}

	summary.vnn = state->my_vnn;
	summary.process_count = count;
	summary.timestamp_usec = timestamp_usec;
	strlcpy(summary.share_name, share_name, sizeof(summary.share_name));

	blob = data_blob_const(&summary, sizeof(summary));

	messaging_send_all(state->msg_ctx,
			   ratelimit_msg_type_summary(
				   ratelimit_op_from_string(op)),
			   blob.data,
			   blob.length);

	state->total_broadcasts_sent++;

	DBG_DEBUG("[%s] Broadcast: op=%s share=%s count=%d\n",
		  MODULE_NAME,
		  op,
		  share_name,
		  count);
}

/*
 * Broadcast one ratelimit_node_summary per active (snum, op) pair.
 * Each VFS ratelimiter gets only the count of processes that are
 * actually doing I/O on a particular share, so it divides the correct
 * per-share limit.
 */
static void broadcast_per_share_summaries(struct smbd_ratelimitd_state *state,
					  uint64_t now)
{
	struct process_activity *proc, *inner;
	int broadcasts = 0;
	int timed_out = 0;

	for (proc = state->processes; proc != NULL; proc = proc->next) {
		uint64_t age_us = now - proc->last_seen_usec;
		bool already_done = false;
		int32_t count = 0;

		if (age_us > RATELIMITD_ACTIVITY_TIMEOUT_US) {
			if (proc->is_active) {
				DBG_NOTICE("[%s] Process TIMED OUT "
					   "(pid=%d share=%s op=%s "
					   "age=%" PRIu64 " ms)\n",
					   MODULE_NAME,
					   proc->pid,
					   proc->share_name,
					   proc->op,
					   age_us / 1000);
				proc->is_active = false;
				timed_out++;
			}
			continue;
		}

		if (!proc->is_active) {
			continue;
		}

		/*
		 * Skip if an earlier active process with the same
		 * (share_name, op) already triggered a broadcast for this
		 * combination.
		 */
		for (inner = state->processes; inner != proc;
		     inner = inner->next)
		{
			uint64_t inner_age = now - inner->last_seen_usec;
			if (strcmp(inner->share_name, proc->share_name) == 0 &&
			    strcmp(inner->op, proc->op) == 0 &&
			    inner->is_active &&
			    inner_age <= RATELIMITD_ACTIVITY_TIMEOUT_US)
			{
				already_done = true;
				break;
			}
		}
		if (already_done) {
			continue;
		}

		/*
		 * Count all active non-timed-out procs for this
		 * (share_name, op)
		 */
		for (inner = state->processes; inner != NULL;
		     inner = inner->next)
		{
			uint64_t inner_age = now - inner->last_seen_usec;
			if (strcmp(inner->share_name, proc->share_name) == 0 &&
			    strcmp(inner->op, proc->op) == 0 &&
			    inner->is_active &&
			    inner_age <= RATELIMITD_ACTIVITY_TIMEOUT_US)
			{
				count++;
			}
		}

		broadcast_summary(
			state, proc->op, proc->share_name, count, now);
		broadcasts++;
	}

	if (broadcasts == 0) {
		DBG_DEBUG("[%s] No active processes, skipped broadcasts "
			  "(timed_out=%d)\n",
			  MODULE_NAME,
			  timed_out);
	} else {
		DBG_DEBUG("[%s] Sent %d per-share broadcasts "
			  "(timed_out=%d)\n",
			  MODULE_NAME,
			  broadcasts,
			  timed_out);
	}
}

static void broadcast_timer_handler(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *private_data)
{
	struct smbd_ratelimitd_state *state = private_data;
	uint64_t now = time_now_usec();

	broadcast_per_share_summaries(state, now);

	state->last_broadcast_usec = now;

	/* Cleanup old inactive entries every 100 timer ticks (~100 seconds) */
	if ((state->total_broadcasts_sent > 0) &&
	    (state->total_broadcasts_sent % 100 == 0))
	{
		cleanup_inactive_processes(state);
	}

	DBG_DEBUG("[%s] broadcast_timer_handler: rescheduling timer\n",
		  MODULE_NAME);

	state->broadcast_timer = tevent_add_timer(
		state->ev,
		state,
		timeval_current_ofs(RATELIMITD_BROADCAST_INTERVAL_US / 1000000,
				    RATELIMITD_BROADCAST_INTERVAL_US %
					    1000000),
		broadcast_timer_handler,
		state);
	if (state->broadcast_timer == NULL) {
		DBG_ERR("[%s] Failed to reschedule broadcast timer: "
			"cluster coordination suspended\n",
			MODULE_NAME);
	}
}

struct tevent_req *smbd_ratelimitd_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct messaging_context *msg)
{
	struct tevent_req *req;
	struct smbd_ratelimitd_state *state;
	struct sockaddr_un addr;
	struct tevent_fd *fde;
	size_t len;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct smbd_ratelimitd_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->msg_ctx = msg;
	state->my_vnn = get_my_vnn();
	state->unix_sock = -1;
	state->socket_path = NULL;

	talloc_set_destructor(state, smbd_ratelimitd_state_destructor);

	state->processes = NULL;

	state->socket_path = state_path(state, RATELIMITD_SOCKET_NAME);
	if (state->socket_path == NULL) {
		DBG_ERR("[%s] Failed to allocate socket path\n", MODULE_NAME);
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}

	DBG_NOTICE("[%s] Creating socket at: %s\n",
		   MODULE_NAME,
		   state->socket_path);

	state->unix_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (state->unix_sock < 0) {
		DBG_ERR("[%s] socket() failed: %s\n",
			MODULE_NAME,
			strerror(errno));
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	/* Remove stale socket from previous daemon instance */
	ret = unlink(state->socket_path);
	if (ret == 0) {
		DBG_DEBUG("[%s] Removed stale socket: %s\n",
			  MODULE_NAME,
			  state->socket_path);
	} else if (errno != ENOENT) {
		DBG_DEBUG("[%s] unlink(%s) failed: %s (continuing anyway)\n",
			  MODULE_NAME,
			  state->socket_path,
			  strerror(errno));
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	len = strlcpy(addr.sun_path,
		      state->socket_path,
		      sizeof(addr.sun_path));
	if (len >= sizeof(addr.sun_path)) {
		DBG_ERR("[%s] Socket path too long: %s\n",
			MODULE_NAME,
			state->socket_path);
		close(state->unix_sock);
		state->unix_sock = -1;
		tevent_req_error(req, ENAMETOOLONG);
		return tevent_req_post(req, ev);
	}

	ret = bind(state->unix_sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		DBG_ERR("[%s] bind() failed on %s: %s\n",
			MODULE_NAME,
			state->socket_path,
			strerror(errno));
		close(state->unix_sock);
		state->unix_sock = -1;
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	ret = chmod(state->socket_path, 0660);
	if (ret < 0) {
		DBG_WARNING("[%s] chmod() failed: %s\n",
			    MODULE_NAME,
			    strerror(errno));
	}

	fde = tevent_add_fd(state->ev,
			    state,
			    state->unix_sock,
			    TEVENT_FD_READ,
			    handle_unix_socket_read,
			    state);
	if (fde == NULL) {
		DBG_ERR("[%s] tevent_add_fd failed\n", MODULE_NAME);
		close(state->unix_sock);
		state->unix_sock = -1;
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}

	state->broadcast_timer = tevent_add_timer(
		state->ev,
		state,
		timeval_current_ofs(RATELIMITD_BROADCAST_INTERVAL_US / 1000000,
				    RATELIMITD_BROADCAST_INTERVAL_US %
					    1000000),
		broadcast_timer_handler,
		state);
	if (state->broadcast_timer == NULL) {
		DBG_ERR("[%s] tevent_add_timer failed\n", MODULE_NAME);
		close(state->unix_sock);
		state->unix_sock = -1;
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}

	DBG_NOTICE("[%s] Daemon initialized: vnn=%u socket=%s\n",
		   MODULE_NAME,
		   state->my_vnn,
		   state->socket_path);

	return req;
}

int smbd_ratelimitd_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}
