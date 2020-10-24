/*
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002-2003
   Copyright (C) Volker Lendecke		1993-2007
   Copyright (C) Jeremy Allison			1993-2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "popt_common.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "registry/reg_init_full.h"
#include "libcli/auth/schannel.h"
#include "secrets.h"
#include "../lib/util/memcache.h"
#include "ctdbd_conn.h"
#include "util_cluster.h"
#include "printing/queue_process.h"
#include "rpc_server/rpc_service_setup.h"
#include "rpc_server/rpc_config.h"
#include "passdb.h"
#include "auth.h"
#include "messages.h"
#include "messages_ctdb.h"
#include "smbprofile.h"
#include "lib/id_cache.h"
#include "lib/param/param.h"
#include "lib/background.h"
#include "../lib/util/pidfile.h"
#include "lib/smbd_shim.h"
#include "scavenger.h"
#include "locking/leases_db.h"
#include "smbd/notifyd/notifyd.h"
#include "smbd/smbd_cleanupd.h"
#include "lib/util/sys_rw.h"
#include "cleanupdb.h"
#include "g_lock.h"
#include "rpc_server/epmd.h"
#include "rpc_server/lsasd.h"
#include "rpc_server/fssd.h"
#include "rpc_server/mdssd.h"

#ifdef CLUSTER_SUPPORT
#include "ctdb_protocol.h"
#endif

struct smbd_open_socket;
struct smbd_child_pid;

struct smbd_parent_context {
	bool interactive;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx;

	/* the list of listening sockets */
	struct smbd_open_socket *sockets;

	/* the list of current child processes */
	struct smbd_child_pid *children;
	size_t num_children;

	struct server_id cleanupd;
	struct server_id notifyd;

	struct tevent_timer *cleanup_te;
};

struct smbd_open_socket {
	struct smbd_open_socket *prev, *next;
	struct smbd_parent_context *parent;
	int fd;
	struct tevent_fd *fde;
};

struct smbd_child_pid {
	struct smbd_child_pid *prev, *next;
	pid_t pid;
};

/*******************************************************************
 What to do when smb.conf is updated.
 ********************************************************************/

static void smbd_parent_conf_updated(struct messaging_context *msg,
				     void *private_data,
				     uint32_t msg_type,
				     struct server_id server_id,
				     DATA_BLOB *data)
{
	struct tevent_context *ev_ctx =
		talloc_get_type_abort(private_data, struct tevent_context);
	bool ok;

	DEBUG(10,("smbd_parent_conf_updated: Got message saying smb.conf was "
		  "updated. Reloading.\n"));
	change_to_root_user();
	reload_services(NULL, NULL, false);
	printing_subsystem_update(ev_ctx, msg, false);

	ok = reinit_guest_session_info(NULL);
	if (!ok) {
		DBG_ERR("Failed to reinit guest info\n");
	}
}

/*******************************************************************
 Delete a statcache entry.
 ********************************************************************/

static void smb_stat_cache_delete(struct messaging_context *msg,
				  void *private_data,
				  uint32_t msg_tnype,
				  struct server_id server_id,
				  DATA_BLOB *data)
{
	const char *name = (const char *)data->data;
	DEBUG(10,("smb_stat_cache_delete: delete name %s\n", name));
	stat_cache_delete(name);
}

/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/

static void  killkids(void)
{
	if(am_parent) kill(0,SIGTERM);
}

static void msg_exit_server(struct messaging_context *msg,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id server_id,
			    DATA_BLOB *data)
{
	DEBUG(3, ("got a SHUTDOWN message\n"));
	exit_server_cleanly(NULL);
}

#ifdef DEVELOPER
static void msg_inject_fault(struct messaging_context *msg,
			     void *private_data,
			     uint32_t msg_type,
			     struct server_id src,
			     DATA_BLOB *data)
{
	int sig;
	struct server_id_buf tmp;

	if (data->length != sizeof(sig)) {
		DEBUG(0, ("Process %s sent bogus signal injection request\n",
			  server_id_str_buf(src, &tmp)));
		return;
	}

	sig = *(int *)data->data;
	if (sig == -1) {
		exit_server("internal error injected");
		return;
	}

#ifdef HAVE_STRSIGNAL
	DEBUG(0, ("Process %s requested injection of signal %d (%s)\n",
		  server_id_str_buf(src, &tmp), sig, strsignal(sig)));
#else
	DEBUG(0, ("Process %s requested injection of signal %d\n",
		  server_id_str_buf(src, &tmp), sig));
#endif

	kill(getpid(), sig);
}
#endif /* DEVELOPER */

#if defined(DEVELOPER) || defined(ENABLE_SELFTEST)
/*
 * Sleep for the specified number of seconds.
 */
static void msg_sleep(struct messaging_context *msg,
		      void *private_data,
		      uint32_t msg_type,
		      struct server_id src,
		      DATA_BLOB *data)
{
	unsigned int seconds;
	struct server_id_buf tmp;

	if (data->length != sizeof(seconds)) {
		DBG_ERR("Process %s sent bogus sleep request\n",
			server_id_str_buf(src, &tmp));
		return;
	}

	seconds = *(unsigned int *)data->data;
	DBG_ERR("Process %s request a sleep of %u seconds\n",
		server_id_str_buf(src, &tmp),
		seconds);
	sleep(seconds);
	DBG_ERR("Restarting after %u second sleep requested by process %s\n",
		seconds,
		server_id_str_buf(src, &tmp));
}
#endif /* DEVELOPER */

static NTSTATUS messaging_send_to_children(struct messaging_context *msg_ctx,
					   uint32_t msg_type, DATA_BLOB* data)
{
	NTSTATUS status;
	struct smbd_parent_context *parent = am_parent;
	struct smbd_child_pid *child;

	if (parent == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (child = parent->children; child != NULL; child = child->next) {
		status = messaging_send(parent->msg_ctx,
					pid_to_procid(child->pid),
					msg_type, data);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("messaging_send(%d) failed: %s\n",
				  (int)child->pid, nt_errstr(status));
		}
	}
	return NT_STATUS_OK;
}

static void smb_parent_send_to_children(struct messaging_context *ctx,
					void* data,
					uint32_t msg_type,
					struct server_id srv_id,
					DATA_BLOB* msg_data)
{
	messaging_send_to_children(ctx, msg_type, msg_data);
}

/*
 * Parent smbd process sets its own debug level first and then
 * sends a message to all the smbd children to adjust their debug
 * level to that of the parent.
 */

static void smbd_msg_debug(struct messaging_context *msg_ctx,
			   void *private_data,
			   uint32_t msg_type,
			   struct server_id server_id,
			   DATA_BLOB *data)
{
	debug_message(msg_ctx, private_data, MSG_DEBUG, server_id, data);

	messaging_send_to_children(msg_ctx, MSG_DEBUG, data);
}

static void smbd_parent_id_cache_kill(struct messaging_context *msg_ctx,
				      void *private_data,
				      uint32_t msg_type,
				      struct server_id server_id,
				      DATA_BLOB* data)
{
	const char *msg = (data && data->data)
		? (const char *)data->data : "<NULL>";
	struct id_cache_ref id;

	if (!id_cache_ref_parse(msg, &id)) {
		DEBUG(0, ("Invalid ?ID: %s\n", msg));
		return;
	}

	id_cache_delete_from_cache(&id);

	messaging_send_to_children(msg_ctx, msg_type, data);
}

static void smbd_parent_id_cache_delete(struct messaging_context *ctx,
					void* data,
					uint32_t msg_type,
					struct server_id srv_id,
					DATA_BLOB* msg_data)
{
	id_cache_delete_message(ctx, data, msg_type, srv_id, msg_data);

	messaging_send_to_children(ctx, msg_type, msg_data);
}

static void add_child_pid(struct smbd_parent_context *parent,
			  pid_t pid)
{
	struct smbd_child_pid *child;

	child = talloc_zero(parent, struct smbd_child_pid);
	if (child == NULL) {
		DEBUG(0, ("Could not add child struct -- malloc failed\n"));
		return;
	}
	child->pid = pid;
	DLIST_ADD(parent->children, child);
	parent->num_children += 1;
}

static void smb_tell_num_children(struct messaging_context *ctx, void *data,
				  uint32_t msg_type, struct server_id srv_id,
				  DATA_BLOB *msg_data)
{
	uint8_t buf[sizeof(uint32_t)];

	if (am_parent) {
		SIVAL(buf, 0, am_parent->num_children);
		messaging_send_buf(ctx, srv_id, MSG_SMB_NUM_CHILDREN,
				   buf, sizeof(buf));
	}
}

static void notifyd_stopped(struct tevent_req *req);

static struct tevent_req *notifyd_req(struct messaging_context *msg_ctx,
				      struct tevent_context *ev)
{
	struct tevent_req *req;
	sys_notify_watch_fn sys_notify_watch = NULL;
	struct sys_notify_context *sys_notify_ctx = NULL;
	struct ctdbd_connection *ctdbd_conn = NULL;

	if (lp_kernel_change_notify()) {

#ifdef HAVE_INOTIFY
		if (lp_parm_bool(-1, "notify", "inotify", true)) {
			sys_notify_watch = inotify_watch;
		}
#endif

#ifdef HAVE_FAM
		if (lp_parm_bool(-1, "notify", "fam",
				 (sys_notify_watch == NULL))) {
			sys_notify_watch = fam_watch;
		}
#endif
	}

	if (sys_notify_watch != NULL) {
		sys_notify_ctx = sys_notify_context_create(msg_ctx, ev);
		if (sys_notify_ctx == NULL) {
			return NULL;
		}
	}

	if (lp_clustering()) {
		ctdbd_conn = messaging_ctdb_connection();
	}

	req = notifyd_send(msg_ctx, ev, msg_ctx, ctdbd_conn,
			   sys_notify_watch, sys_notify_ctx);
	if (req == NULL) {
		TALLOC_FREE(sys_notify_ctx);
		return NULL;
	}
	tevent_req_set_callback(req, notifyd_stopped, msg_ctx);

	return req;
}

static void notifyd_stopped(struct tevent_req *req)
{
	int ret;

	ret = notifyd_recv(req);
	TALLOC_FREE(req);
	DEBUG(1, ("notifyd stopped: %s\n", strerror(ret)));
}

static void notifyd_sig_hup_handler(struct tevent_context *ev,
				    struct tevent_signal *se,
				    int signum,
				    int count,
				    void *siginfo,
				    void *pvt)
{
	DBG_NOTICE("notifyd: Reloading services after SIGHUP\n");
	reload_services(NULL, NULL, false);
}

static bool smbd_notifyd_init(struct messaging_context *msg, bool interactive,
			      struct server_id *ppid)
{
	struct tevent_context *ev = messaging_tevent_context(msg);
	struct tevent_req *req;
	pid_t pid;
	NTSTATUS status;
	bool ok;
	struct tevent_signal *se;

	if (interactive) {
		req = notifyd_req(msg, ev);
		return (req != NULL);
	}

	pid = fork();
	if (pid == -1) {
		DEBUG(1, ("%s: fork failed: %s\n", __func__,
			  strerror(errno)));
		return false;
	}

	if (pid != 0) {
		if (am_parent != NULL) {
			add_child_pid(am_parent, pid);
		}
		*ppid = pid_to_procid(pid);
		return true;
	}

	status = smbd_reinit_after_fork(msg, ev, true, "smbd-notifyd");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("%s: reinit_after_fork failed: %s\n",
			  __func__, nt_errstr(status)));
		exit(1);
	}

	reopen_logs();

	/* Set up sighup handler for notifyd */
	se = tevent_add_signal(ev,
			       ev,
			       SIGHUP, 0,
			       notifyd_sig_hup_handler,
			       NULL);
	if (!se) {
		DEBUG(0, ("failed to setup notifyd SIGHUP handler\n"));
		exit(1);
	}

	req = notifyd_req(msg, ev);
	if (req == NULL) {
		exit(1);
	}
	tevent_req_set_callback(req, notifyd_stopped, msg);

	/* Block those signals that we are not handling */
	BlockSignals(True, SIGUSR1);

	messaging_send(msg, pid_to_procid(getppid()), MSG_SMB_NOTIFY_STARTED,
		       NULL);

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		DBG_WARNING("tevent_req_poll returned %s\n", strerror(errno));
		exit(1);
	}
	exit(0);
}

static void notifyd_init_trigger(struct tevent_req *req);

struct notifyd_init_state {
	bool ok;
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct server_id *ppid;
};

static struct tevent_req *notifyd_init_send(struct tevent_context *ev,
					    TALLOC_CTX *mem_ctx,
					    struct messaging_context *msg,
					    struct server_id *ppid)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct notifyd_init_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct notifyd_init_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct notifyd_init_state) {
		.msg = msg,
		.ev = ev,
		.ppid = ppid
	};

	subreq = tevent_wakeup_send(state, ev, tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, notifyd_init_trigger, req);
	return req;
}

static void notifyd_init_trigger(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notifyd_init_state *state = tevent_req_data(
		req, struct notifyd_init_state);
	bool ok;

	DBG_NOTICE("Triggering notifyd startup\n");

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	state->ok = smbd_notifyd_init(state->msg, false, state->ppid);
	if (state->ok) {
		DBG_WARNING("notifyd restarted\n");
		tevent_req_done(req);
		return;
	}

	DBG_NOTICE("notifyd startup failed, rescheduling\n");

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		DBG_ERR("scheduling notifyd restart failed, giving up\n");
		return;
	}

	tevent_req_set_callback(subreq, notifyd_init_trigger, req);
	return;
}

static bool notifyd_init_recv(struct tevent_req *req)
{
	struct notifyd_init_state *state = tevent_req_data(
		req, struct notifyd_init_state);

	return state->ok;
}

static void notifyd_started(struct tevent_req *req)
{
	bool ok;

	ok = notifyd_init_recv(req);
	TALLOC_FREE(req);
	if (!ok) {
		DBG_ERR("Failed to restart notifyd, giving up\n");
		return;
	}
}

static void cleanupd_stopped(struct tevent_req *req);

static bool cleanupd_init(struct messaging_context *msg, bool interactive,
			  struct server_id *ppid)
{
	struct tevent_context *ev = messaging_tevent_context(msg);
	struct server_id parent_id = messaging_server_id(msg);
	struct tevent_req *req;
	pid_t pid;
	NTSTATUS status;
	ssize_t rwret;
	int ret;
	bool ok;
	char c;
	int up_pipe[2];

	if (interactive) {
		req = smbd_cleanupd_send(msg, ev, msg, parent_id.pid);
		*ppid = messaging_server_id(msg);
		return (req != NULL);
	}

	ret = pipe(up_pipe);
	if (ret == -1) {
		DBG_WARNING("pipe failed: %s\n", strerror(errno));
		return false;
	}

	pid = fork();
	if (pid == -1) {
		DBG_WARNING("fork failed: %s\n", strerror(errno));
		close(up_pipe[0]);
		close(up_pipe[1]);
		return false;
	}

	if (pid != 0) {

		close(up_pipe[1]);
		rwret = sys_read(up_pipe[0], &c, 1);
		close(up_pipe[0]);

		if (rwret == -1) {
			DBG_WARNING("sys_read failed: %s\n", strerror(errno));
			return false;
		}
		if (rwret == 0) {
			DBG_WARNING("cleanupd could not start\n");
			return false;
		}
		if (c != 0) {
			DBG_WARNING("cleanupd returned %d\n", (int)c);
			return false;
		}

		DBG_DEBUG("Started cleanupd pid=%d\n", (int)pid);

		if (am_parent != NULL) {
			add_child_pid(am_parent, pid);
		}

		*ppid = pid_to_procid(pid);
		return true;
	}

	close(up_pipe[0]);

	status = smbd_reinit_after_fork(msg, ev, true, "cleanupd");
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("reinit_after_fork failed: %s\n",
			    nt_errstr(status));
		c = 1;
		sys_write(up_pipe[1], &c, 1);

		exit(1);
	}

	req = smbd_cleanupd_send(msg, ev, msg, parent_id.pid);
	if (req == NULL) {
		DBG_WARNING("smbd_cleanupd_send failed\n");
		c = 2;
		sys_write(up_pipe[1], &c, 1);

		exit(1);
	}

	tevent_req_set_callback(req, cleanupd_stopped, msg);

	c = 0;
	rwret = sys_write(up_pipe[1], &c, 1);
	close(up_pipe[1]);

	if (rwret == -1) {
		DBG_WARNING("sys_write failed: %s\n", strerror(errno));
		exit(1);
	}
	if (rwret != 1) {
		DBG_WARNING("sys_write could not write result\n");
		exit(1);
	}

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		DBG_WARNING("tevent_req_poll returned %s\n", strerror(errno));
	}
	exit(0);
}

static void cleanupd_stopped(struct tevent_req *req)
{
	NTSTATUS status;

	status = smbd_cleanupd_recv(req);
	DBG_WARNING("cleanupd stopped: %s\n", nt_errstr(status));
}

static void cleanupd_init_trigger(struct tevent_req *req);

struct cleanup_init_state {
	bool ok;
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct server_id *ppid;
};

static struct tevent_req *cleanupd_init_send(struct tevent_context *ev,
					     TALLOC_CTX *mem_ctx,
					     struct messaging_context *msg,
					     struct server_id *ppid)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct cleanup_init_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cleanup_init_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct cleanup_init_state) {
		.msg = msg,
		.ev = ev,
		.ppid = ppid
	};

	subreq = tevent_wakeup_send(state, ev, tevent_timeval_current_ofs(0, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, cleanupd_init_trigger, req);
	return req;
}

static void cleanupd_init_trigger(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cleanup_init_state *state = tevent_req_data(
		req, struct cleanup_init_state);
	bool ok;

	DBG_NOTICE("Triggering cleanupd startup\n");

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	state->ok = cleanupd_init(state->msg, false, state->ppid);
	if (state->ok) {
		DBG_WARNING("cleanupd restarted\n");
		tevent_req_done(req);
		return;
	}

	DBG_NOTICE("cleanupd startup failed, rescheduling\n");

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		DBG_ERR("scheduling cleanupd restart failed, giving up\n");
		return;
	}

	tevent_req_set_callback(subreq, cleanupd_init_trigger, req);
	return;
}

static bool cleanupd_init_recv(struct tevent_req *req)
{
	struct cleanup_init_state *state = tevent_req_data(
		req, struct cleanup_init_state);

	return state->ok;
}

static void cleanupd_started(struct tevent_req *req)
{
	bool ok;
	NTSTATUS status;
	struct smbd_parent_context *parent = tevent_req_callback_data(
		req, struct smbd_parent_context);

	ok = cleanupd_init_recv(req);
	TALLOC_FREE(req);
	if (!ok) {
		DBG_ERR("Failed to restart cleanupd, giving up\n");
		return;
	}

	status = messaging_send(parent->msg_ctx,
				parent->cleanupd,
				MSG_SMB_NOTIFY_CLEANUP,
				&data_blob_null);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("messaging_send returned %s\n",
			nt_errstr(status));
	}
}

static void remove_child_pid(struct smbd_parent_context *parent,
			     pid_t pid,
			     bool unclean_shutdown)
{
	struct smbd_child_pid *child;
	NTSTATUS status;
	bool ok;

	for (child = parent->children; child != NULL; child = child->next) {
		if (child->pid == pid) {
			struct smbd_child_pid *tmp = child;
			DLIST_REMOVE(parent->children, child);
			TALLOC_FREE(tmp);
			parent->num_children -= 1;
			break;
		}
	}

	if (child == NULL) {
		/* not all forked child processes are added to the children list */
		DEBUG(2, ("Could not find child %d -- ignoring\n", (int)pid));
		return;
	}

	if (pid == procid_to_pid(&parent->cleanupd)) {
		struct tevent_req *req;

		server_id_set_disconnected(&parent->cleanupd);

		DBG_WARNING("Restarting cleanupd\n");
		req = cleanupd_init_send(messaging_tevent_context(parent->msg_ctx),
					 parent,
					 parent->msg_ctx,
					 &parent->cleanupd);
		if (req == NULL) {
			DBG_ERR("Failed to restart cleanupd\n");
			return;
		}
		tevent_req_set_callback(req, cleanupd_started, parent);
		return;
	}

	if (pid == procid_to_pid(&parent->notifyd)) {
		struct tevent_req *req;
		struct tevent_context *ev = messaging_tevent_context(
			parent->msg_ctx);

		server_id_set_disconnected(&parent->notifyd);

		DBG_WARNING("Restarting notifyd\n");
		req = notifyd_init_send(ev,
					parent,
					parent->msg_ctx,
					&parent->notifyd);
		if (req == NULL) {
			DBG_ERR("Failed to restart notifyd\n");
			return;
		}
		tevent_req_set_callback(req, notifyd_started, parent);
		return;
	}

	ok = cleanupdb_store_child(pid, unclean_shutdown);
	if (!ok) {
		DBG_ERR("cleanupdb_store_child failed\n");
		return;
	}

	if (!server_id_is_disconnected(&parent->cleanupd)) {
		status = messaging_send(parent->msg_ctx,
					parent->cleanupd,
					MSG_SMB_NOTIFY_CLEANUP,
					&data_blob_null);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("messaging_send returned %s\n",
				nt_errstr(status));
		}
	}
}

/****************************************************************************
 Have we reached the process limit ?
****************************************************************************/

static bool allowable_number_of_smbd_processes(struct smbd_parent_context *parent)
{
	int max_processes = lp_max_smbd_processes();

	if (!max_processes)
		return True;

	return parent->num_children < max_processes;
}

static void smbd_sig_chld_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *private_data)
{
	pid_t pid;
	int status;
	struct smbd_parent_context *parent =
		talloc_get_type_abort(private_data,
		struct smbd_parent_context);

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		bool unclean_shutdown = False;

		/* If the child terminated normally, assume
		   it was an unclean shutdown unless the
		   status is 0
		*/
		if (WIFEXITED(status)) {
			unclean_shutdown = WEXITSTATUS(status);
		}
		/* If the child terminated due to a signal
		   we always assume it was unclean.
		*/
		if (WIFSIGNALED(status)) {
			unclean_shutdown = True;
		}
		remove_child_pid(parent, pid, unclean_shutdown);
	}
}

static void smbd_setup_sig_chld_handler(struct smbd_parent_context *parent)
{
	struct tevent_signal *se;

	se = tevent_add_signal(parent->ev_ctx,
			       parent, /* mem_ctx */
			       SIGCHLD, 0,
			       smbd_sig_chld_handler,
			       parent);
	if (!se) {
		exit_server("failed to setup SIGCHLD handler");
	}
}

static void smbd_open_socket_close_fn(struct tevent_context *ev,
				      struct tevent_fd *fde,
				      int fd,
				      void *private_data)
{
	/* this might be the socket_wrapper swrap_close() */
	close(fd);
}

static void smbd_accept_connection(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data)
{
	struct smbd_open_socket *s = talloc_get_type_abort(private_data,
				     struct smbd_open_socket);
	struct messaging_context *msg_ctx = s->parent->msg_ctx;
	struct dcesrv_context *dce_ctx = s->parent->dce_ctx;
	struct sockaddr_storage addr;
	socklen_t in_addrlen = sizeof(addr);
	int fd;
	pid_t pid = 0;

	fd = accept(s->fd, (struct sockaddr *)(void *)&addr,&in_addrlen);
	if (fd == -1 && errno == EINTR)
		return;

	if (fd == -1) {
		DEBUG(0,("accept: %s\n",
			 strerror(errno)));
		return;
	}
	smb_set_close_on_exec(fd);

	if (s->parent->interactive) {
		reinit_after_fork(msg_ctx, ev, true, NULL);
		smbd_process(ev, msg_ctx, dce_ctx, fd, true);
		exit_server_cleanly("end of interactive mode");
		return;
	}

	if (!allowable_number_of_smbd_processes(s->parent)) {
		close(fd);
		return;
	}

	pid = fork();
	if (pid == 0) {
		NTSTATUS status = NT_STATUS_OK;

		/*
		 * Can't use TALLOC_FREE here. Nulling out the argument to it
		 * would overwrite memory we've just freed.
		 */
		talloc_free(s->parent);
		s = NULL;

		/* Stop zombies, the parent explicitly handles
		 * them, counting worker smbds. */
		CatchChild();

		status = smbd_reinit_after_fork(msg_ctx, ev, true, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status,
					    NT_STATUS_TOO_MANY_OPENED_FILES)) {
				DEBUG(0,("child process cannot initialize "
					 "because too many files are open\n"));
				goto exit;
			}
			if (lp_clustering() &&
			    (NT_STATUS_EQUAL(
				    status, NT_STATUS_INTERNAL_DB_ERROR) ||
			     NT_STATUS_EQUAL(
				    status, NT_STATUS_CONNECTION_REFUSED))) {
				DEBUG(1, ("child process cannot initialize "
					  "because connection to CTDB "
					  "has failed: %s\n",
					  nt_errstr(status)));
				goto exit;
			}

			DEBUG(0,("reinit_after_fork() failed\n"));
			smb_panic("reinit_after_fork() failed");
		}

		smbd_process(ev, msg_ctx, dce_ctx, fd, false);
	 exit:
		exit_server_cleanly("end of child");
		return;
	}

	if (pid < 0) {
		DEBUG(0,("smbd_accept_connection: fork() failed: %s\n",
			 strerror(errno)));
	}

	/* The parent doesn't need this socket */
	close(fd);

	/* Sun May 6 18:56:14 2001 ackley@cs.unm.edu:
		Clear the closed fd info out of server_fd --
		and more importantly, out of client_fd in
		util_sock.c, to avoid a possible
		getpeername failure if we reopen the logs
		and use %I in the filename.
	*/

	if (pid != 0) {
		add_child_pid(s->parent, pid);
	}

	/* Force parent to check log size after
	 * spawning child.  Fix from
	 * klausr@ITAP.Physik.Uni-Stuttgart.De.  The
	 * parent smbd will log to logserver.smb.  It
	 * writes only two messages for each child
	 * started/finished. But each child writes,
	 * say, 50 messages also in logserver.smb,
	 * beginning with the debug_count of the
	 * parent, before the child opens its own log
	 * file logserver.client. In a worst case
	 * scenario the size of logserver.smb would be
	 * checked after about 50*50=2500 messages
	 * (ca. 100kb).
	 * */
	force_check_log_size();
}

static bool smbd_open_one_socket(struct smbd_parent_context *parent,
				 struct tevent_context *ev_ctx,
				 const struct sockaddr_storage *ifss,
				 uint16_t port)
{
	struct smbd_open_socket *s;

	s = talloc(parent, struct smbd_open_socket);
	if (!s) {
		return false;
	}

	s->parent = parent;
	s->fd = open_socket_in(SOCK_STREAM,
			       port,
			       parent->sockets == NULL ? 0 : 2,
			       ifss,
			       true);
	if (s->fd == -1) {
		DEBUG(0,("smbd_open_one_socket: open_socket_in: "
			"%s\n", strerror(errno)));
		TALLOC_FREE(s);
		/*
		 * We ignore an error here, as we've done before
		 */
		return true;
	}

	/* ready to listen */
	set_socket_options(s->fd, "SO_KEEPALIVE");
	set_socket_options(s->fd, lp_socket_options());

	/* Set server socket to
	 * non-blocking for the accept. */
	set_blocking(s->fd, False);

	if (listen(s->fd, SMBD_LISTEN_BACKLOG) == -1) {
		DEBUG(0,("smbd_open_one_socket: listen: "
			"%s\n", strerror(errno)));
			close(s->fd);
		TALLOC_FREE(s);
		return false;
	}

	s->fde = tevent_add_fd(ev_ctx,
			       s,
			       s->fd, TEVENT_FD_READ,
			       smbd_accept_connection,
			       s);
	if (!s->fde) {
		DEBUG(0,("smbd_open_one_socket: "
			 "tevent_add_fd: %s\n",
			 strerror(errno)));
		close(s->fd);
		TALLOC_FREE(s);
		return false;
	}
	tevent_fd_set_close_fn(s->fde, smbd_open_socket_close_fn);

	DLIST_ADD_END(parent->sockets, s);

	return true;
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/

static bool open_sockets_smbd(struct smbd_parent_context *parent,
			      struct tevent_context *ev_ctx,
			      struct messaging_context *msg_ctx,
			      const char *smb_ports)
{
	int num_interfaces = iface_count();
	int i,j;
	const char **ports;
	unsigned dns_port = 0;

#ifdef HAVE_ATEXIT
	atexit(killkids);
#endif

	/* Stop zombies */
	smbd_setup_sig_chld_handler(parent);

	ports = lp_smb_ports();

	/* use a reasonable default set of ports - listing on 445 and 139 */
	if (smb_ports) {
		char **l;
		l = str_list_make_v3(talloc_tos(), smb_ports, NULL);
		ports = discard_const_p(const char *, l);
	}

	for (j = 0; ports && ports[j]; j++) {
		unsigned port = atoi(ports[j]);

		if (port == 0 || port > 0xffff) {
			exit_server_cleanly("Invalid port in the config or on "
					    "the commandline specified!");
		}
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		/* We have been given an interfaces line, and been
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/

		/* Now open a listen socket for each of the
		   interfaces. */
		for(i = 0; i < num_interfaces; i++) {
			const struct sockaddr_storage *ifss =
					iface_n_sockaddr_storage(i);
			if (ifss == NULL) {
				DEBUG(0,("open_sockets_smbd: "
					"interface %d has NULL IP address !\n",
					i));
				continue;
			}

			for (j = 0; ports && ports[j]; j++) {
				unsigned port = atoi(ports[j]);

				/* Keep the first port for mDNS service
				 * registration.
				 */
				if (dns_port == 0) {
					dns_port = port;
				}

				if (!smbd_open_one_socket(parent,
							  ev_ctx,
							  ifss,
							  port)) {
					return false;
				}
			}
		}
	} else {
		/* Just bind to 0.0.0.0 - accept connections
		   from anywhere. */

		const char *sock_addr;
		char *sock_tok;
		const char *sock_ptr;

#ifdef HAVE_IPV6
		sock_addr = "::,0.0.0.0";
#else
		sock_addr = "0.0.0.0";
#endif

		for (sock_ptr=sock_addr;
		     next_token_talloc(talloc_tos(), &sock_ptr, &sock_tok, " \t,"); ) {
			for (j = 0; ports && ports[j]; j++) {
				struct sockaddr_storage ss;
				unsigned port = atoi(ports[j]);

				/* Keep the first port for mDNS service
				 * registration.
				 */
				if (dns_port == 0) {
					dns_port = port;
				}

				/* open an incoming socket */
				if (!interpret_string_addr(&ss, sock_tok,
						AI_NUMERICHOST|AI_PASSIVE)) {
					continue;
				}

				/*
				 * If we fail to open any sockets
				 * in this loop the parent-sockets == NULL
				 * case below will prevent us from starting.
				 */

				(void)smbd_open_one_socket(parent,
						  ev_ctx,
						  &ss,
						  port);
			}
		}
	}

	if (parent->sockets == NULL) {
		DEBUG(0,("open_sockets_smbd: No "
			"sockets available to bind to.\n"));
		return false;
	}

        /* Listen to messages */

	messaging_register(msg_ctx, NULL, MSG_SHUTDOWN, msg_exit_server);
	messaging_register(msg_ctx, ev_ctx, MSG_SMB_CONF_UPDATED,
			   smbd_parent_conf_updated);
	messaging_register(msg_ctx, NULL, MSG_SMB_STAT_CACHE_DELETE,
			   smb_stat_cache_delete);
	messaging_register(msg_ctx, NULL, MSG_DEBUG, smbd_msg_debug);
	messaging_register(msg_ctx, NULL, MSG_SMB_FORCE_TDIS,
			   smb_parent_send_to_children);
	messaging_register(msg_ctx, NULL, MSG_SMB_FORCE_TDIS_DENIED,
			   smb_parent_send_to_children);
	messaging_register(msg_ctx, NULL, MSG_SMB_KILL_CLIENT_IP,
			   smb_parent_send_to_children);
	messaging_register(msg_ctx, NULL, MSG_SMB_TELL_NUM_CHILDREN,
			   smb_tell_num_children);

	messaging_register(msg_ctx, NULL,
			   ID_CACHE_DELETE, smbd_parent_id_cache_delete);
	messaging_register(msg_ctx, NULL,
			   ID_CACHE_KILL, smbd_parent_id_cache_kill);
	messaging_register(msg_ctx, NULL, MSG_SMB_NOTIFY_STARTED,
			   smb_parent_send_to_children);

#ifdef DEVELOPER
	messaging_register(msg_ctx, NULL, MSG_SMB_INJECT_FAULT,
			   msg_inject_fault);
#endif

#if defined(DEVELOPER) || defined(ENABLE_SELFTEST)
	messaging_register(msg_ctx, NULL, MSG_SMB_SLEEP, msg_sleep);
#endif

	if (lp_multicast_dns_register() && (dns_port != 0)) {
#ifdef WITH_DNSSD_SUPPORT
		smbd_setup_mdns_registration(ev_ctx,
					     parent, dns_port);
#endif
#ifdef WITH_AVAHI_SUPPORT
		void *avahi_conn;

		avahi_conn = avahi_start_register(ev_ctx,
						  ev_ctx,
						  dns_port);
		if (avahi_conn == NULL) {
			DEBUG(10, ("avahi_start_register failed\n"));
		}
#endif
	}

	return true;
}


/*
  handle stdin becoming readable when we are in --foreground mode
 */
static void smbd_stdin_handler(struct tevent_context *ev,
			       struct tevent_fd *fde,
			       uint16_t flags,
			       void *private_data)
{
	char c;
	if (read(0, &c, 1) != 1) {
		/* we have reached EOF on stdin, which means the
		   parent has exited. Shutdown the server */
		exit_server_cleanly("EOF on stdin");
	}
}

struct smbd_parent_tevent_trace_state {
	TALLOC_CTX *frame;
};

static void smbd_parent_tevent_trace_callback(enum tevent_trace_point point,
					      void *private_data)
{
	struct smbd_parent_tevent_trace_state *state =
		(struct smbd_parent_tevent_trace_state *)private_data;

	switch (point) {
	case TEVENT_TRACE_BEFORE_WAIT:
		break;
	case TEVENT_TRACE_AFTER_WAIT:
		break;
	case TEVENT_TRACE_BEFORE_LOOP_ONCE:
		TALLOC_FREE(state->frame);
		state->frame = talloc_stackframe();
		break;
	case TEVENT_TRACE_AFTER_LOOP_ONCE:
		TALLOC_FREE(state->frame);
		break;
	}

	errno = 0;
}

static void smbd_parent_loop(struct tevent_context *ev_ctx,
			     struct smbd_parent_context *parent)
{
	struct smbd_parent_tevent_trace_state trace_state = {
		.frame = NULL,
	};
	int ret = 0;

	tevent_set_trace_callback(ev_ctx, smbd_parent_tevent_trace_callback,
				  &trace_state);

	/* now accept incoming connections - forking a new process
	   for each incoming connection */
	DEBUG(2,("waiting for connections\n"));

	ret = tevent_loop_wait(ev_ctx);
	if (ret != 0) {
		DEBUG(0, ("tevent_loop_wait failed: %d, %s, exiting\n",
			  ret, strerror(errno)));
	}

	TALLOC_FREE(trace_state.frame);

/* NOTREACHED	return True; */
}


/****************************************************************************
 Initialise connect, service and file structs.
****************************************************************************/

static bool init_structs(void )
{
	/*
	 * Set the machine NETBIOS name if not already
	 * set from the config file.
	 */

	if (!init_names())
		return False;

	if (!secrets_init())
		return False;

	return True;
}

static void smbd_parent_sig_term_handler(struct tevent_context *ev,
					 struct tevent_signal *se,
					 int signum,
					 int count,
					 void *siginfo,
					 void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void smbd_parent_sig_hup_handler(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data)
{
	struct smbd_parent_context *parent =
		talloc_get_type_abort(private_data,
		struct smbd_parent_context);

	change_to_root_user();
	DEBUG(1,("parent: Reloading services after SIGHUP\n"));
	reload_services(NULL, NULL, false);

	printing_subsystem_update(parent->ev_ctx, parent->msg_ctx, true);
}

struct smbd_claim_version_state {
	TALLOC_CTX *mem_ctx;
	char *version;
};

static void smbd_claim_version_parser(struct server_id exclusive,
				      size_t num_shared,
				      struct server_id *shared,
				      const uint8_t *data,
				      size_t datalen,
				      void *private_data)
{
	struct smbd_claim_version_state *state = private_data;

	if (datalen == 0) {
		state->version = NULL;
		return;
	}
	if (data[datalen-1] != '\0') {
		DBG_WARNING("Invalid samba version\n");
		dump_data(DBGLVL_WARNING, data, datalen);
		state->version = NULL;
		return;
	}
	state->version = talloc_strdup(state->mem_ctx, (const char *)data);
}

static NTSTATUS smbd_claim_version(struct messaging_context *msg,
				   const char *version)
{
	const char *name = "samba_version_string";
	const TDB_DATA key = string_term_tdb_data(name);
	struct smbd_claim_version_state state;
	struct g_lock_ctx *ctx;
	NTSTATUS status;

	ctx = g_lock_ctx_init(msg, msg);
	if (ctx == NULL) {
		DBG_WARNING("g_lock_ctx_init failed\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = g_lock_lock(
		ctx, key, G_LOCK_READ, (struct timeval) { .tv_sec = 60 });
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("g_lock_lock(G_LOCK_READ) failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(ctx);
		return status;
	}

	state = (struct smbd_claim_version_state) { .mem_ctx = ctx };

	status = g_lock_dump(ctx, key, smbd_claim_version_parser, &state);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DBG_ERR("Could not read samba_version_string\n");
		g_lock_unlock(ctx, key);
		TALLOC_FREE(ctx);
		return status;
	}

	if ((state.version != NULL) && (strcmp(version, state.version) == 0)) {
		/*
		 * Leave the read lock for us around. Someone else already
		 * set the version correctly
		 */
		TALLOC_FREE(ctx);
		return NT_STATUS_OK;
	}

	status = g_lock_lock(
		ctx, key, G_LOCK_UPGRADE, (struct timeval) { .tv_sec = 60 });
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("g_lock_lock(G_LOCK_WRITE) failed: %s\n",
			    nt_errstr(status));
		DBG_ERR("smbd %s already running, refusing to start "
			"version %s\n", state.version, version);
		TALLOC_FREE(ctx);
		return NT_STATUS_SXS_VERSION_CONFLICT;
	}

	status = g_lock_write_data(
		ctx, key, (const uint8_t *)version, strlen(version)+1);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("g_lock_write_data failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(ctx);
		return status;
	}

	status = g_lock_lock(
		ctx, key, G_LOCK_DOWNGRADE, (struct timeval) { .tv_sec = 60 });
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("g_lock_lock(G_LOCK_READ) failed: %s\n",
			    nt_errstr(status));
		TALLOC_FREE(ctx);
		return status;
	}

	/*
	 * Leave "ctx" dangling so that g_lock.tdb keeps opened.
	 */
	return NT_STATUS_OK;
}

/****************************************************************************
 main program.
****************************************************************************/

/* Declare prototype for build_options() to avoid having to run it through
   mkproto.h.  Mixing $(builddir) and $(srcdir) source files in the current
   prototype generation system is too complicated. */

extern void build_options(bool screen);

 int main(int argc,const char *argv[])
{
	/* shall I run as a daemon */
	bool is_daemon = false;
	bool interactive = false;
	bool Fork = true;
	bool no_process_group = false;
	bool log_stdout = false;
	char *ports = NULL;
	char *profile_level = NULL;
	int opt;
	poptContext pc;
	bool print_build_options = False;
	struct server_id main_server_id = {0};
        enum {
		OPT_DAEMON = 1000,
		OPT_INTERACTIVE,
		OPT_FORK,
		OPT_NO_PROCESS_GROUP,
		OPT_LOG_STDOUT
	};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "daemon",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_DAEMON,
			.descrip    = "Become a daemon (default)" ,
		},
		{
			.longName   = "interactive",
			.shortName  = 'i',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_INTERACTIVE,
			.descrip    = "Run interactive (not a daemon) and log to stdout",
		},
		{
			.longName   = "foreground",
			.shortName  = 'F',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_FORK,
			.descrip    = "Run daemon in foreground (for daemontools, etc.)",
		},
		{
			.longName   = "no-process-group",
			.shortName  = '\0',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_NO_PROCESS_GROUP,
			.descrip    = "Don't create a new process group" ,
		},
		{
			.longName   = "log-stdout",
			.shortName  = 'S',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = OPT_LOG_STDOUT,
			.descrip    = "Log to stdout" ,
		},
		{
			.longName   = "build-options",
			.shortName  = 'b',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'b',
			.descrip    = "Print build options" ,
		},
		{
			.longName   = "port",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &ports,
			.val        = 0,
			.descrip    = "Listen on the specified ports",
		},
		{
			.longName   = "profiling-level",
			.shortName  = 'P',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &profile_level,
			.val        = 0,
			.descrip    = "Set profiling level","PROFILE_LEVEL",
		},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	struct smbd_parent_context *parent = NULL;
	TALLOC_CTX *frame;
	NTSTATUS status;
	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx = NULL;
	struct server_id server_id;
	struct tevent_signal *se;
	int profiling_level;
	char *np_dir = NULL;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	static const struct smbd_shim smbd_shim_fns =
	{
		.send_stat_cache_delete_message = smbd_send_stat_cache_delete_message,
		.change_to_root_user = smbd_change_to_root_user,
		.become_authenticated_pipe_user = smbd_become_authenticated_pipe_user,
		.unbecome_authenticated_pipe_user = smbd_unbecome_authenticated_pipe_user,

		.contend_level2_oplocks_begin = smbd_contend_level2_oplocks_begin,
		.contend_level2_oplocks_end = smbd_contend_level2_oplocks_end,

		.become_root = smbd_become_root,
		.unbecome_root = smbd_unbecome_root,

		.exit_server = smbd_exit_server,
		.exit_server_cleanly = smbd_exit_server_cleanly,
	};

	/*
	 * Do this before any other talloc operation
	 */
	talloc_enable_null_tracking();
	frame = talloc_stackframe();

	setup_logging(argv[0], DEBUG_DEFAULT_STDOUT);

	smb_init_locale();

	set_smbd_shim(&smbd_shim_fns);

	smbd_init_globals();

	TimeInit();

#ifdef HAVE_SET_AUTH_PARAMETERS
	set_auth_parameters(argc,argv);
#endif

	pc = poptGetContext("smbd", argc, argv, long_options, 0);
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt)  {
		case OPT_DAEMON:
			is_daemon = true;
			break;
		case OPT_INTERACTIVE:
			interactive = true;
			break;
		case OPT_FORK:
			Fork = false;
			break;
		case OPT_NO_PROCESS_GROUP:
			no_process_group = true;
			break;
		case OPT_LOG_STDOUT:
			log_stdout = true;
			break;
		case 'b':
			print_build_options = True;
			break;
		default:
			d_fprintf(stderr, "\nInvalid option %s: %s\n\n",
				  poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}
	poptFreeContext(pc);

	if (interactive) {
		Fork = False;
		log_stdout = True;
	}

	if (log_stdout) {
		setup_logging(argv[0], DEBUG_STDOUT);
	} else {
		setup_logging(argv[0], DEBUG_FILE);
	}

	if (print_build_options) {
		build_options(True); /* Display output to screen as well as debug */
		exit(0);
	}

#ifdef HAVE_SETLUID
	/* needed for SecureWare on SCO */
	setluid(0);
#endif

	set_remote_machine_name("smbd", False);

	if (interactive && (DEBUGLEVEL >= 9)) {
		talloc_enable_leak_report();
	}

	if (log_stdout && Fork) {
		DEBUG(0,("ERROR: Can't log to stdout (-S) unless daemon is in foreground (-F) or interactive (-i)\n"));
		exit(1);
	}

	/*
	 * We want to die early if we can't open /dev/urandom
	 */
	generate_random_buffer(NULL, 0);

	/* get initial effective uid and gid */
	sec_init();

	/* make absolutely sure we run as root - to handle cases where people
	   are crazy enough to have it setuid */
	gain_root_privilege();
	gain_root_group_privilege();

	fault_setup();
	dump_core_setup("smbd", lp_logfile(talloc_tos(), lp_sub));

	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif

#if defined(SIGUSR2)
	/* We are no longer interested in USR2 */
	BlockSignals(True,SIGUSR2);
#endif

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems, as we won't recieve them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGTERM);

	/* Ensure we leave no zombies until we
	 * correctly set up child handling below. */

	CatchChild();

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	reopen_logs();

	DEBUG(0,("smbd version %s started.\n", samba_version_string()));
	DEBUGADD(0,("%s\n", COPYRIGHT_STARTUP_MESSAGE));

	DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
		 (int)getuid(),(int)getgid(),(int)geteuid(),(int)getegid()));

	/* Output the build options to the debug log */ 
	build_options(False);

	if (sizeof(uint16_t) < 2 || sizeof(uint32_t) < 4) {
		DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
		exit(1);
	}

	if (!lp_load_initial_only(get_dyn_CONFIGFILE())) {
		DEBUG(0, ("error opening config file '%s'\n", get_dyn_CONFIGFILE()));
		exit(1);
	}

	/*
	 * This calls unshare(CLONE_FS); on linux
	 * in order to check if the running kernel/container
	 * environment supports it.
	 */
	per_thread_cwd_check();

	if (!cluster_probe_ok()) {
		exit(1);
	}

	/* Init the security context and global current_user */
	init_sec_ctx();

	/*
	 * Initialize the event context. The event context needs to be
	 * initialized before the messaging context, cause the messaging
	 * context holds an event context.
	 */
	ev_ctx = global_event_context();
	if (ev_ctx == NULL) {
		exit(1);
	}

	/*
	 * Init the messaging context
	 * FIXME: This should only call messaging_init()
	 */
	msg_ctx = global_messaging_context();
	if (msg_ctx == NULL) {
		exit(1);
	}

	dce_ctx = global_dcesrv_context();
	if (dce_ctx == NULL) {
		exit(1);
	}

	/*
	 * Reloading of the printers will not work here as we don't have a
	 * server info and rpc services set up. It will be called later.
	 */
	if (!reload_services(NULL, NULL, false)) {
		exit(1);
	}

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC
	    && !lp_parm_bool(-1, "server role check", "inhibit", false)) {
		DEBUG(0, ("server role = 'active directory domain controller' not compatible with running smbd standalone. \n"));
		DEBUGADD(0, ("You should start 'samba' instead, and it will control starting smbd if required\n"));
		exit(1);
	}

	/* ...NOTE... Log files are working from this point! */

	DEBUG(3,("loaded services\n"));

	init_structs();

	if (!profile_setup(msg_ctx, False)) {
		DEBUG(0,("ERROR: failed to setup profiling\n"));
		return -1;
	}

	if (profile_level != NULL) {
		profiling_level = atoi(profile_level);
	} else {
		profiling_level = lp_smbd_profiling_level();
	}
	main_server_id = messaging_server_id(msg_ctx);
	set_profile_level(profiling_level, &main_server_id);

	if (!is_daemon && !is_a_socket(0)) {
		if (!interactive) {
			DEBUG(3, ("Standard input is not a socket, "
				  "assuming -D option\n"));
		}

		/*
		 * Setting is_daemon here prevents us from eventually calling
		 * the open_sockets_inetd()
		 */

		is_daemon = True;
	}

	if (is_daemon && !interactive) {
		DEBUG(3, ("Becoming a daemon.\n"));
		become_daemon(Fork, no_process_group, log_stdout);
	} else {
		daemon_status("smbd", "Starting process ...");
	}

#ifdef HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management.
	 */
	if (interactive && !no_process_group)
		setpgid( (pid_t)0, (pid_t)0);
#endif

	if (!directory_exist(lp_lock_directory()))
		mkdir(lp_lock_directory(), 0755);

	if (!directory_exist(lp_pid_directory()))
		mkdir(lp_pid_directory(), 0755);

	if (is_daemon)
		pidfile_create(lp_pid_directory(), "smbd");

	status = reinit_after_fork(msg_ctx, ev_ctx, false, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("reinit_after_fork() failed", map_errno_from_nt_status(status));
	}

	if (!interactive) {
		/*
		 * Do not initialize the parent-child-pipe before becoming a
		 * daemon: this is used to detect a died parent in the child
		 * process.
		 */
		status = init_before_fork();
		if (!NT_STATUS_IS_OK(status)) {
			exit_daemon(nt_errstr(status), map_errno_from_nt_status(status));
		}
	}

	parent = talloc_zero(ev_ctx, struct smbd_parent_context);
	if (!parent) {
		exit_server("talloc(struct smbd_parent_context) failed");
	}
	parent->interactive = interactive;
	parent->ev_ctx = ev_ctx;
	parent->msg_ctx = msg_ctx;
	parent->dce_ctx = dce_ctx;
	am_parent = parent;

	se = tevent_add_signal(parent->ev_ctx,
			       parent,
			       SIGTERM, 0,
			       smbd_parent_sig_term_handler,
			       parent);
	if (!se) {
		exit_server("failed to setup SIGTERM handler");
	}
	se = tevent_add_signal(parent->ev_ctx,
			       parent,
			       SIGHUP, 0,
			       smbd_parent_sig_hup_handler,
			       parent);
	if (!se) {
		exit_server("failed to setup SIGHUP handler");
	}

	/* Setup all the TDB's - including CLEAR_IF_FIRST tdb's. */

	if (smbd_memcache() == NULL) {
		exit_daemon("no memcache available", EACCES);
	}

	memcache_set_global(smbd_memcache());

	/* Initialise the password backed before the global_sam_sid
	   to ensure that we fetch from ldap before we make a domain sid up */

	if(!initialize_password_db(false, ev_ctx))
		exit(1);

	if (!secrets_init()) {
		exit_daemon("smbd can not open secrets.tdb", EACCES);
	}

	if (lp_server_role() == ROLE_DOMAIN_BDC || lp_server_role() == ROLE_DOMAIN_PDC) {
		struct loadparm_context *lp_ctx = loadparm_init_s3(NULL, loadparm_s3_helpers());
		if (!open_schannel_session_store(NULL, lp_ctx)) {
			exit_daemon("ERROR: Samba cannot open schannel store for secured NETLOGON operations.", EACCES);
		}
		TALLOC_FREE(lp_ctx);
	}

	if(!get_global_sam_sid()) {
		exit_daemon("Samba cannot create a SAM SID", EACCES);
	}

	server_id = messaging_server_id(msg_ctx);
	status = smbXsrv_version_global_init(&server_id);
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("Samba cannot init server context", EACCES);
	}

	status = smbXsrv_client_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("Samba cannot init clients context", EACCES);
	}

	status = smbXsrv_session_global_init(msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("Samba cannot init session context", EACCES);
	}

	status = smbXsrv_tcon_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("Samba cannot init tcon context", EACCES);
	}

	if (!locking_init())
		exit_daemon("Samba cannot init locking", EACCES);

	if (!leases_db_init(false)) {
		exit_daemon("Samba cannot init leases", EACCES);
	}

	if (!smbd_notifyd_init(msg_ctx, interactive, &parent->notifyd)) {
		exit_daemon("Samba cannot init notification", EACCES);
	}

	if (!cleanupd_init(msg_ctx, interactive, &parent->cleanupd)) {
		exit_daemon("Samba cannot init the cleanupd", EACCES);
	}

	if (!messaging_parent_dgm_cleanup_init(msg_ctx)) {
		exit(1);
	}

	if (!smbd_scavenger_init(NULL, msg_ctx, ev_ctx)) {
		exit_daemon("Samba cannot init scavenging", EACCES);
	}

	if (!W_ERROR_IS_OK(registry_init_full()))
		exit_daemon("Samba cannot init registry", EACCES);

	/* Open the share_info.tdb here, so we don't have to open
	   after the fork on every single connection.  This is a small
	   performance improvment and reduces the total number of system
	   fds used. */
	status = share_info_db_init();
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("ERROR: failed to load share info db.", EACCES);
	}

	status = init_system_session_info(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("ERROR: failed to setup system user info: %s.\n",
			  nt_errstr(status)));
		return -1;
	}

	if (!init_guest_session_info(NULL)) {
		DEBUG(0,("ERROR: failed to setup guest info.\n"));
		return -1;
	}

	if (!file_init_global()) {
		DEBUG(0, ("ERROR: file_init_global() failed\n"));
		return -1;
	}
	status = smbXsrv_open_global_init();
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("Samba cannot init global open", map_errno_from_nt_status(status));
	}

	if (lp_clustering() && !lp_allow_unsafe_cluster_upgrade()) {
		status = smbd_claim_version(msg_ctx, samba_version_string());
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Could not claim version: %s\n",
				    nt_errstr(status));
			return -1;
		}
	}

	/* This MUST be done before start_epmd() because otherwise
	 * start_epmd() forks and races against dcesrv_ep_setup() to
	 * call directory_create_or_exist() */
	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  lp_ncalrpc_dir(), strerror(errno)));
		return -1;
	}

	np_dir = talloc_asprintf(talloc_tos(), "%s/np", lp_ncalrpc_dir());
	if (!np_dir) {
		DEBUG(0, ("%s: Out of memory\n", __location__));
		return -1;
	}

	if (!directory_create_or_exist_strict(np_dir, geteuid(), 0700)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  np_dir, strerror(errno)));
		return -1;
	}

	status = dcesrv_init(ev_ctx, ev_ctx, msg_ctx, dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to setup RPC server: %s\n", nt_errstr(status));
		exit_daemon("Samba cannot setup ep pipe", EACCES);
	}

	if (!interactive) {
		daemon_ready("smbd");
	}

	/* only start other daemons if we are running as a daemon
	 * -- bad things will happen if smbd is launched via inetd
	 *  and we fork a copy of ourselves here */
	if (is_daemon && !interactive) {

		if (rpc_epmapper_daemon() == RPC_DAEMON_FORK) {
			start_epmd(ev_ctx, msg_ctx, dce_ctx);
		}

		if (rpc_lsasd_daemon() == RPC_DAEMON_FORK) {
			start_lsasd(ev_ctx, msg_ctx, dce_ctx);
		}

		if (rpc_fss_daemon() == RPC_DAEMON_FORK) {
			start_fssd(ev_ctx, msg_ctx, dce_ctx);
		}

		if (!lp__disable_spoolss() &&
		    (rpc_spoolss_daemon() != RPC_DAEMON_DISABLED)) {
			bool bgq = lp_parm_bool(-1, "smbd", "backgroundqueue", true);
			bool ok = printing_subsystem_init(ev_ctx,
							  msg_ctx,
							  dce_ctx,
							  true,
							  bgq);
			if (!ok) {
				exit_daemon("Samba failed to init printing subsystem", EACCES);
			}
		}

#ifdef WITH_SPOTLIGHT
		if ((rpc_mdssvc_mode() == RPC_SERVICE_MODE_EXTERNAL) &&
		    (rpc_mdssd_daemon() == RPC_DAEMON_FORK)) {
			start_mdssd(ev_ctx, msg_ctx, dce_ctx);
		}
#endif
	} else if (!lp__disable_spoolss() &&
		   (rpc_spoolss_daemon() != RPC_DAEMON_DISABLED)) {
		bool ok = printing_subsystem_init(ev_ctx,
						  msg_ctx,
						  dce_ctx,
						  false,
						  false);
		if (!ok) {
			exit(1);
		}
	}

	if (!is_daemon) {
		int sock;

		/* inetd mode */
		TALLOC_FREE(frame);

		/* Started from inetd. fd 0 is the socket. */
		/* We will abort gracefully when the client or remote system
		   goes away */
		sock = dup(0);

		/* close stdin, stdout (if not logging to it), but not stderr */
		close_low_fds(true, !debug_get_output_is_stdout(), false);

#ifdef HAVE_ATEXIT
		atexit(killkids);
#endif

	        /* Stop zombies */
		smbd_setup_sig_chld_handler(parent);

		smbd_process(ev_ctx, msg_ctx, dce_ctx, sock, true);

		exit_server_cleanly(NULL);
		return(0);
	}

	if (!open_sockets_smbd(parent, ev_ctx, msg_ctx, ports))
		exit_server("open_sockets_smbd() failed");

	/* do a printer update now that all messaging has been set up,
	 * before we allow clients to start connecting */
	if (!lp__disable_spoolss() &&
	    (rpc_spoolss_daemon() != RPC_DAEMON_DISABLED)) {
		printing_subsystem_update(ev_ctx, msg_ctx, false);
	}

	TALLOC_FREE(frame);
	/* make sure we always have a valid stackframe */
	frame = talloc_stackframe();

	if (!Fork) {
		/* if we are running in the foreground then look for
		   EOF on stdin, and exit if it happens. This allows
		   us to die if the parent process dies
		   Only do this on a pipe or socket, no other device.
		*/
		struct stat st;
		if (fstat(0, &st) != 0) {
			return false;
		}
		if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
			tevent_add_fd(ev_ctx,
					parent,
					0,
					TEVENT_FD_READ,
					smbd_stdin_handler,
					NULL);
		}
	}

	smbd_parent_loop(ev_ctx, parent);

	exit_server_cleanly(NULL);
	TALLOC_FREE(frame);
	return(0);
}
