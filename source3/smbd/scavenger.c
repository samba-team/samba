/*
   Unix SMB/CIFS implementation.
   smbd scavenger daemon

   Copyright (C) Gregor Beck                    2013

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
#include "messages.h"
#include "serverid.h"
#include "smbd/globals.h"
#include "smbd/smbXsrv_open.h"
#include "smbd/scavenger.h"
#include "locking/share_mode_lock.h"
#include "locking/leases_db.h"
#include "locking/proto.h"
#include "librpc/gen_ndr/open_files.h"
#include "lib/util/server_id.h"
#include "lib/util/util_process.h"
#include "lib/util/sys_rw_data.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SCAVENGER

struct smbd_scavenger_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct server_id parent_id;
	struct server_id *scavenger_id;
	bool am_scavenger;
};

static struct smbd_scavenger_state *smbd_scavenger_state = NULL;

struct scavenger_message {
	struct file_id file_id;
	uint64_t open_persistent_id;
	NTTIME until;
};

static int smbd_scavenger_main(struct smbd_scavenger_state *state)
{
	struct server_id_buf tmp1, tmp2;

	DEBUG(10, ("scavenger: %s started, parent: %s\n",
		   server_id_str_buf(*state->scavenger_id, &tmp1),
		   server_id_str_buf(state->parent_id, &tmp2)));

	while (true) {
		TALLOC_CTX *frame = talloc_stackframe();
		int ret;

		ret = tevent_loop_once(state->ev);
		if (ret != 0) {
			DEBUG(2, ("tevent_loop_once failed: %s\n",
				  strerror(errno)));
			TALLOC_FREE(frame);
			return 1;
		}

		DEBUG(10, ("scavenger: %s event loop iteration\n",
			   server_id_str_buf(*state->scavenger_id, &tmp1)));
		TALLOC_FREE(frame);
	}

	return 0;
}

static void smbd_scavenger_done(struct tevent_context *event_ctx, struct tevent_fd *fde,
			        uint16_t flags, void *private_data)
{
	struct smbd_scavenger_state *state = talloc_get_type_abort(
		private_data, struct smbd_scavenger_state);
	struct server_id_buf tmp;

	DEBUG(2, ("scavenger: %s died\n",
		  server_id_str_buf(*state->scavenger_id, &tmp)));

	TALLOC_FREE(state->scavenger_id);
}

static void smbd_scavenger_parent_dead(struct tevent_context *event_ctx,
				       struct tevent_fd *fde,
				       uint16_t flags, void *private_data)
{
	struct smbd_scavenger_state *state = talloc_get_type_abort(
		private_data, struct smbd_scavenger_state);
	struct server_id_buf tmp1, tmp2;

	DEBUG(2, ("scavenger: %s parent %s died\n",
		  server_id_str_buf(*state->scavenger_id, &tmp1),
		  server_id_str_buf(state->parent_id, &tmp2)));

	exit_server_cleanly("smbd_scavenger_parent_dead");
}

static void scavenger_sig_term_handler(struct tevent_context *ev,
				       struct tevent_signal *se,
				       int signum,
				       int count,
				       void *siginfo,
				       void *private_data)
{
	exit_server_cleanly("termination signal");
}

static void scavenger_setup_sig_term_handler(struct tevent_context *ev_ctx)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx,
			       ev_ctx,
			       SIGTERM, 0,
			       scavenger_sig_term_handler,
			       NULL);
	if (se == NULL) {
		exit_server("failed to setup SIGTERM handler");
	}
}

static bool smbd_scavenger_running(struct smbd_scavenger_state *state)
{
	if (state->scavenger_id == NULL) {
		return false;
	}

	return serverid_exists(state->scavenger_id);
}

static int smbd_scavenger_server_id_destructor(struct server_id *id)
{
	return 0;
}

static bool scavenger_say_hello(int fd, struct server_id self)
{
	ssize_t ret;
	struct server_id_buf tmp;

	ret = write_data(fd, &self, sizeof(self));
	if (ret == -1) {
		DEBUG(2, ("Failed to write to pipe: %s\n", strerror(errno)));
		return false;
	}
	if (ret < sizeof(self)) {
		DBG_WARNING("Could not write serverid\n");
		return false;
	}

	DEBUG(4, ("scavenger_say_hello: self[%s]\n",
		  server_id_str_buf(self, &tmp)));
	return true;
}

static bool scavenger_wait_hello(int fd, struct server_id *child)
{
	struct server_id_buf tmp;
	ssize_t ret;

	ret = read_data(fd, child, sizeof(struct server_id));
	if (ret == -1) {
		DEBUG(2, ("Failed to read from pipe: %s\n",
			  strerror(errno)));
		return false;
	}
	if (ret < sizeof(struct server_id)) {
		DBG_WARNING("Could not read serverid\n");
		return false;
	}

	DEBUG(4, ("scavenger_say_hello: child[%s]\n",
		  server_id_str_buf(*child, &tmp)));
	return true;
}

static bool smbd_scavenger_start(struct smbd_scavenger_state *state)
{
	struct server_id self = messaging_server_id(state->msg);
	struct tevent_fd *fde = NULL;
	int fds[2];
	int ret;
	bool ok;

	SMB_ASSERT(server_id_equal(&state->parent_id, &self));

	if (smbd_scavenger_running(state)) {
		struct server_id_buf tmp;
		DEBUG(10, ("scavenger %s already running\n",
			   server_id_str_buf(*state->scavenger_id,
					     &tmp)));
		return true;
	}

	if (state->scavenger_id != NULL) {
		struct server_id_buf tmp;
		DEBUG(10, ("scavenger zombie %s, cleaning up\n",
			   server_id_str_buf(*state->scavenger_id,
					     &tmp)));
		TALLOC_FREE(state->scavenger_id);
	}

	state->scavenger_id = talloc_zero(state, struct server_id);
	if (state->scavenger_id == NULL) {
		DEBUG(2, ("Out of memory\n"));
		goto fail;
	}
	talloc_set_destructor(state->scavenger_id,
			      smbd_scavenger_server_id_destructor);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (ret == -1) {
		DEBUG(2, ("socketpair failed: %s\n", strerror(errno)));
		goto fail;
	}

	smb_set_close_on_exec(fds[0]);
	smb_set_close_on_exec(fds[1]);

	ret = fork();
	if (ret == -1) {
		int err = errno;
		close(fds[0]);
		close(fds[1]);
		DEBUG(0, ("fork failed: %s\n", strerror(err)));
		goto fail;
	}

	if (ret == 0) {
		/* child */

		NTSTATUS status;

		close(fds[0]);

		status = smbd_reinit_after_fork(state->msg, state->ev,
						true);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("reinit_after_fork failed: %s\n",
				  nt_errstr(status)));
			exit_server("reinit_after_fork failed");
			return false;
		}

		process_set_title("smbd-scavenger", "scavenger");
		reopen_logs();

		state->am_scavenger = true;
		*state->scavenger_id = messaging_server_id(state->msg);

		scavenger_setup_sig_term_handler(state->ev);

		ok = scavenger_say_hello(fds[1], *state->scavenger_id);
		if (!ok) {
			DEBUG(2, ("scavenger_say_hello failed\n"));
			exit_server("scavenger_say_hello failed");
			return false;
		}

		fde = tevent_add_fd(state->ev, state->scavenger_id,
				    fds[1], TEVENT_FD_READ,
				    smbd_scavenger_parent_dead, state);
		if (fde == NULL) {
			DEBUG(2, ("tevent_add_fd(smbd_scavenger_parent_dead) "
				  "failed\n"));
			exit_server("tevent_add_fd(smbd_scavenger_parent_dead) "
				    "failed");
			return false;
		}
		tevent_fd_set_auto_close(fde);

		ret = smbd_scavenger_main(state);

		DEBUG(10, ("scavenger ended: %d\n", ret));
		exit_server_cleanly("scavenger ended");
		return false;
	}

	/* parent */
	close(fds[1]);

	ok = scavenger_wait_hello(fds[0], state->scavenger_id);
	if (!ok) {
		close(fds[0]);
		goto fail;
	}

	fde = tevent_add_fd(state->ev, state->scavenger_id,
			    fds[0], TEVENT_FD_READ,
			    smbd_scavenger_done, state);
	if (fde == NULL) {
		close(fds[0]);
		goto fail;
	}
	tevent_fd_set_auto_close(fde);

	return true;
fail:
	TALLOC_FREE(state->scavenger_id);
	return false;
}

static void scavenger_add_timer(struct smbd_scavenger_state *state,
				struct scavenger_message *msg);

static void smbd_scavenger_msg(struct messaging_context *msg_ctx,
			       void *private_data,
			       uint32_t msg_type,
			       struct server_id src,
			       DATA_BLOB *data)
{
	struct smbd_scavenger_state *state =
		talloc_get_type_abort(private_data,
				      struct smbd_scavenger_state);
	TALLOC_CTX *frame = talloc_stackframe();
	struct server_id self = messaging_server_id(msg_ctx);
	struct scavenger_message *msg = NULL;
	struct server_id_buf tmp1, tmp2;

	DEBUG(10, ("smbd_scavenger_msg: %s got message from %s\n",
		   server_id_str_buf(self, &tmp1),
		   server_id_str_buf(src, &tmp2)));

	if (server_id_equal(&state->parent_id, &self)) {
		NTSTATUS status;

		if (!smbd_scavenger_running(state) &&
		    !smbd_scavenger_start(state))
		{
			DEBUG(2, ("Failed to start scavenger\n"));
			goto done;
		}
		DEBUG(10, ("forwarding message to scavenger\n"));

		status = messaging_send(msg_ctx,
					*state->scavenger_id, msg_type, data);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("forwarding message to scavenger failed: "
				  "%s\n", nt_errstr(status)));
			goto done;
		}
		goto done;
	}

	if (!state->am_scavenger) {
		DEBUG(10, ("im not the scavenger: ignore message\n"));
		goto done;
	}

	if (!server_id_equal(&state->parent_id, &src)) {
		DEBUG(10, ("scavenger: ignore spurious message\n"));
		goto done;
	}

	DEBUG(10, ("scavenger: got a message\n"));
	msg = (struct scavenger_message*)data->data;
	scavenger_add_timer(state, msg);
done:
	talloc_free(frame);
}

bool smbd_scavenger_init(TALLOC_CTX *mem_ctx,
			 struct messaging_context *msg,
			 struct tevent_context *ev)
{
	struct smbd_scavenger_state *state;
	NTSTATUS status;

	if (smbd_scavenger_state) {
		DEBUG(10, ("smbd_scavenger_init called again\n"));
		return true;
	}

	state = talloc_zero(mem_ctx, struct smbd_scavenger_state);
	if (state == NULL) {
		DEBUG(2, ("Out of memory\n"));
		return false;
	}

	state->msg = msg;
	state->ev = ev;
	state->parent_id = messaging_server_id(msg);

	status = messaging_register(msg, state, MSG_SMB_SCAVENGER,
				    smbd_scavenger_msg);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("failed to register message handler: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	smbd_scavenger_state = state;
	return true;
fail:
	talloc_free(state);
	return false;
}

void scavenger_schedule_disconnected(struct files_struct *fsp)
{
	NTSTATUS status;
	struct server_id self = messaging_server_id(fsp->conn->sconn->msg_ctx);
	struct timeval disconnect_time, until;
	uint64_t timeout_usec;
	struct scavenger_message msg;
	DATA_BLOB msg_blob;
	struct server_id_buf tmp;
	struct file_id_buf idbuf;

	if (fsp->op == NULL) {
		return;
	}
	nttime_to_timeval(&disconnect_time, fsp->op->global->disconnect_time);
	timeout_usec = UINT64_C(1000) * fsp->op->global->durable_timeout_msec;
	until = timeval_add(&disconnect_time,
			    timeout_usec / 1000000,
			    timeout_usec % 1000000);

	ZERO_STRUCT(msg);
	msg.file_id = fsp->file_id;
	msg.open_persistent_id = fsp->op->global->open_persistent_id;
	msg.until = timeval_to_nttime(&until);

	DEBUG(10, ("smbd: %s mark file %s as disconnected at %s with timeout "
		   "at %s in %fs\n",
		   server_id_str_buf(self, &tmp),
		   file_id_str_buf(fsp->file_id, &idbuf),
		   timeval_string(talloc_tos(), &disconnect_time, true),
		   timeval_string(talloc_tos(), &until, true),
		   fsp->op->global->durable_timeout_msec/1000.0));

	SMB_ASSERT(server_id_is_disconnected(&fsp->op->global->server_id));
	SMB_ASSERT(!server_id_equal(&self, &smbd_scavenger_state->parent_id));
	SMB_ASSERT(!smbd_scavenger_state->am_scavenger);

	msg_blob = data_blob_const(&msg, sizeof(msg));
	DEBUG(10, ("send message to scavenger\n"));

	status = messaging_send(smbd_scavenger_state->msg,
				smbd_scavenger_state->parent_id,
				MSG_SMB_SCAVENGER,
				&msg_blob);
	if (!NT_STATUS_IS_OK(status)) {
		struct server_id_buf tmp1, tmp2;
		DEBUG(2, ("Failed to send message to parent smbd %s "
			  "from %s: %s\n",
			  server_id_str_buf(smbd_scavenger_state->parent_id,
					    &tmp1),
			  server_id_str_buf(self, &tmp2),
			  nt_errstr(status)));
	}
}

struct scavenger_timer_context {
	struct smbd_scavenger_state *state;
	struct scavenger_message msg;
};

struct cleanup_disconnected_state {
	struct file_id fid;
	struct share_mode_lock *lck;
	uint64_t open_persistent_id;
	struct share_mode_entry e;
};

static bool cleanup_disconnected_share_mode_entry_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct cleanup_disconnected_state *state = private_data;
	bool disconnected;

	if (e->share_file_id != state->open_persistent_id) {
		return false;
	}

	disconnected = server_id_is_disconnected(&e->pid);
	if (!disconnected) {
		char *name = share_mode_filename(talloc_tos(), state->lck);
		struct file_id_buf tmp1;
		struct server_id_buf tmp2;
		DBG_ERR("file (file-id='%s', servicepath='%s', name='%s') "
			"is used by server %s ==> internal error\n",
			file_id_str_buf(state->fid, &tmp1),
			share_mode_servicepath(state->lck),
			name,
			server_id_str_buf(e->pid, &tmp2));
		TALLOC_FREE(name);
		smb_panic(__location__);
	}

	/*
	 * Setting e->stale = true is
	 * the indication to delete the entry.
	 */
	e->stale = true;
	state->e = *e;

	return true;
}

static bool share_mode_cleanup_disconnected(
	struct file_id fid, uint64_t open_persistent_id)
{
	struct cleanup_disconnected_state state = {
		.fid = fid,
		.open_persistent_id = open_persistent_id
	};
	bool ret = false;
	TALLOC_CTX *frame = talloc_stackframe();
	char *name = NULL;
	struct file_id_buf idbuf;
	NTSTATUS status;
	bool ok;

	state.lck = get_existing_share_mode_lock(frame, fid);
	if (state.lck == NULL) {
		DBG_INFO("Could not fetch share mode entry for %s\n",
			 file_id_str_buf(fid, &idbuf));
		goto done;
	}
	name = share_mode_filename(frame, state.lck);

	ok = brl_cleanup_disconnected(fid, open_persistent_id);
	if (!ok) {
		DBG_DEBUG("failed to clean up byte range locks associated "
			  "with file (file-id='%s', servicepath='%s', "
			  "name='%s') and open_persistent_id %"PRIu64" "
			  "==> do not cleanup\n",
			  file_id_str_buf(fid, &idbuf),
			  share_mode_servicepath(state.lck),
			  name,
			  open_persistent_id);
		goto done;
	}

	DBG_DEBUG("cleaning up entry for file "
		  "(file-id='%s', servicepath='%s', name='%s') "
		  "from open_persistent_id %"PRIu64"\n",
		  file_id_str_buf(fid, &idbuf),
		  share_mode_servicepath(state.lck),
		  name,
		  open_persistent_id);

	ok = share_mode_forall_entries(
		state.lck, cleanup_disconnected_share_mode_entry_fn, &state);
	if (!ok) {
		DBG_DEBUG("failed to clean up entry associated "
			  "with file (file-id='%s', servicepath='%s', "
			  "name='%s') and open_persistent_id %"PRIu64" "
			  "==> do not cleanup\n",
			  file_id_str_buf(fid, &idbuf),
			  share_mode_servicepath(state.lck),
			  name,
			  open_persistent_id);
		goto done;
	}

	if (state.e.stale && (state.e.op_type == LEASE_OPLOCK)) {
		status = remove_lease_if_stale(state.lck,
					       &state.e.client_guid,
					       &state.e.lease_key);
		if (!NT_STATUS_IS_OK(status)) {
			struct GUID_txt_buf gbuf;

			DBG_WARNING("Failed to clean up lease associated "
				    "with file (file-id='%s', servicepath='%s', "
				    "name='%s', open_persistent_id=%" PRIu64
				    "client_guid=%s, "
				    "lease_key=%"PRIx64"/%"PRIx64"): %s\n",
				    file_id_str_buf(fid, &idbuf),
				    share_mode_servicepath(state.lck),
				    name,
				    open_persistent_id,
				    GUID_buf_string(&state.e.client_guid, &gbuf),
				    state.e.lease_key.data[0],
				    state.e.lease_key.data[1],
				    nt_errstr(status));
			goto done;
		}
	}

	ret = true;
done:
	talloc_free(frame);
	return ret;
}

static void scavenger_timer(struct tevent_context *ev,
			    struct tevent_timer *te,
			    struct timeval t, void *data)
{
	struct scavenger_timer_context *ctx =
		talloc_get_type_abort(data, struct scavenger_timer_context);
	struct file_id_buf idbuf;
	NTSTATUS status;
	bool ok;

	DBG_DEBUG("do cleanup for file %s at %s\n",
		  file_id_str_buf(ctx->msg.file_id, &idbuf),
		  timeval_string(talloc_tos(), &t, true));

	ok = share_mode_cleanup_disconnected(ctx->msg.file_id,
					     ctx->msg.open_persistent_id);
	if (!ok) {
		DBG_WARNING("Failed to cleanup share modes and byte range "
			    "locks for file %s open %"PRIu64"\n",
			    file_id_str_buf(ctx->msg.file_id, &idbuf),
			    ctx->msg.open_persistent_id);
	}

	status = smbXsrv_open_cleanup(ctx->msg.open_persistent_id);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Failed to cleanup open global for file %s open "
			    "%"PRIu64": %s\n",
			    file_id_str_buf(ctx->msg.file_id, &idbuf),
			    ctx->msg.open_persistent_id,
			    nt_errstr(status));
	}
}

static void scavenger_add_timer(struct smbd_scavenger_state *state,
				struct scavenger_message *msg)
{
	struct tevent_timer *te;
	struct scavenger_timer_context *ctx;
	struct timeval until;
	struct file_id_buf idbuf;

	nttime_to_timeval(&until, msg->until);

	DBG_DEBUG("schedule file %s for cleanup at %s\n",
		  file_id_str_buf(msg->file_id, &idbuf),
		  timeval_string(talloc_tos(), &until, true));

	ctx = talloc_zero(state, struct scavenger_timer_context);
	if (ctx == NULL) {
		DEBUG(2, ("Failed to talloc_zero(scavenger_timer_context)\n"));
		return;
	}

	ctx->state = state;
	ctx->msg = *msg;

	te = tevent_add_timer(state->ev,
			      state,
			      until,
			      scavenger_timer,
			      ctx);
	if (te == NULL) {
		DEBUG(2, ("Failed to add scavenger_timer event\n"));
		talloc_free(ctx);
		return;
	}

	/* delete context after handler was running */
	talloc_steal(te, ctx);
}
