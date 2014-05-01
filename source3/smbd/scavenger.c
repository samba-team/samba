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
#include "smbd/scavenger.h"
#include "locking/proto.h"
#include "lib/util/util_process.h"

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
	DEBUG(10, ("scavenger: %s started, parent: %s\n",
		   server_id_str(talloc_tos(), state->scavenger_id),
		   server_id_str(talloc_tos(), &state->parent_id)));

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
			   server_id_str(talloc_tos(), state->scavenger_id)));
		TALLOC_FREE(frame);
	}

	return 0;
}

static void smbd_scavenger_done(struct tevent_context *event_ctx, struct tevent_fd *fde,
			        uint16_t flags, void *private_data)
{
	struct smbd_scavenger_state *state = talloc_get_type_abort(
		private_data, struct smbd_scavenger_state);

	DEBUG(2, ("scavenger: %s died\n",
		  server_id_str(talloc_tos(), state->scavenger_id)));

	TALLOC_FREE(state->scavenger_id);
}

static void smbd_scavenger_parent_dead(struct tevent_context *event_ctx,
				       struct tevent_fd *fde,
				       uint16_t flags, void *private_data)
{
	struct smbd_scavenger_state *state = talloc_get_type_abort(
		private_data, struct smbd_scavenger_state);

	DEBUG(2, ("scavenger: %s parent %s died\n",
		  server_id_str(talloc_tos(), state->scavenger_id),
		  server_id_str(talloc_tos(), &state->parent_id)));

	exit_server("smbd_scavenger_parent_dead");
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
	serverid_deregister(*id);
	return 0;
}

static bool scavenger_say_hello(int fd, struct server_id self)
{
	const uint8_t *msg = (const uint8_t *)&self;
	size_t remaining = sizeof(self);
	size_t ofs = 0;

	while (remaining > 0) {
		ssize_t ret;

		ret = sys_write(fd, msg + ofs, remaining);
		if (ret == -1) {
			DEBUG(2, ("Failed to write to pipe: %s\n",
				  strerror(errno)));
			return false;
		}
		remaining -= ret;
	}

	DEBUG(4, ("scavenger_say_hello: self[%s]\n",
		  server_id_str(talloc_tos(), &self)));
	return true;
}

static bool scavenger_wait_hello(int fd, struct server_id *child)
{
	uint8_t *msg = (uint8_t *)child;
	size_t remaining = sizeof(*child);
	size_t ofs = 0;

	while (remaining > 0) {
		ssize_t ret;

		ret = sys_read(fd, msg + ofs, remaining);
		if (ret == -1) {
			DEBUG(2, ("Failed to read from pipe: %s\n",
				  strerror(errno)));
			return false;
		}
		remaining -= ret;
	}

	DEBUG(4, ("scavenger_say_hello: child[%s]\n",
		  server_id_str(talloc_tos(), child)));
	return true;
}

static bool smbd_scavenger_start(struct smbd_scavenger_state *state)
{
	struct server_id self = messaging_server_id(state->msg);
	struct tevent_fd *fde = NULL;
	int fds[2];
	int ret;
	uint64_t unique_id;
	bool ok;

	SMB_ASSERT(server_id_equal(&state->parent_id, &self));

	if (smbd_scavenger_running(state)) {
		DEBUG(10, ("scavenger %s already running\n",
			   server_id_str(talloc_tos(),
					 state->scavenger_id)));
		return true;
	}

	if (state->scavenger_id != NULL) {
		DEBUG(10, ("scavenger zombie %s, cleaning up\n",
			   server_id_str(talloc_tos(),
					 state->scavenger_id)));
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
		DEBUG(2, ("socketpair failed: %s", strerror(errno)));
		goto fail;
	}

	smb_set_close_on_exec(fds[0]);
	smb_set_close_on_exec(fds[1]);

	unique_id = serverid_get_random_unique_id();

	ret = fork();
	if (ret == -1) {
		int err = errno;
		close(fds[0]);
		close(fds[1]);
		DEBUG(0, ("fork failed: %s", strerror(err)));
		goto fail;
	}

	if (ret == 0) {
		/* child */

		NTSTATUS status;

		close(fds[0]);

		am_parent = NULL;

		set_my_unique_id(unique_id);

		status = reinit_after_fork(state->msg, state->ev, true);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2, ("reinit_after_fork failed: %s\n",
				  nt_errstr(status)));
			exit_server("reinit_after_fork failed");
			return false;
		}

		prctl_set_comment("smbd-scavenger");

		state->am_scavenger = true;
		*state->scavenger_id = messaging_server_id(state->msg);

		scavenger_setup_sig_term_handler(state->ev);

		serverid_register(*state->scavenger_id, FLAG_MSG_GENERAL);

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

	DEBUG(10, ("smbd_scavenger_msg: %s got message from %s\n",
		   server_id_str(talloc_tos(), &self),
		   server_id_str(talloc_tos(), &src)));

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

	if (fsp->op == NULL) {
		return;
	}
	nttime_to_timeval(&disconnect_time, fsp->op->global->disconnect_time);
	timeout_usec = 1000 * fsp->op->global->durable_timeout_msec;
	until = timeval_add(&disconnect_time,
			    timeout_usec / 1000000,
			    timeout_usec % 1000000);

	ZERO_STRUCT(msg);
	msg.file_id = fsp->file_id;
	msg.open_persistent_id = fsp->op->global->open_persistent_id;
	msg.until = timeval_to_nttime(&until);

	DEBUG(10, ("smbd: %s mark file %s as disconnected at %s with timeout "
		   "at %s in %fs\n",
		   server_id_str(talloc_tos(), &self),
		   file_id_string_tos(&fsp->file_id),
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
		DEBUG(2, ("Failed to send message to parent smbd %s "
			  "from %s: %s\n",
			  server_id_str(talloc_tos(),
					&smbd_scavenger_state->parent_id),
			  server_id_str(talloc_tos(), &self),
			  nt_errstr(status)));
	}
}

struct scavenger_timer_context {
	struct smbd_scavenger_state *state;
	struct scavenger_message msg;
};

static void scavenger_timer(struct tevent_context *ev,
			    struct tevent_timer *te,
			    struct timeval t, void *data)
{
	struct scavenger_timer_context *ctx =
		talloc_get_type_abort(data, struct scavenger_timer_context);
	NTSTATUS status;
	bool ok;

	DEBUG(10, ("scavenger: do cleanup for file %s at %s\n",
		  file_id_string_tos(&ctx->msg.file_id),
		  timeval_string(talloc_tos(), &t, true)));

	ok = share_mode_cleanup_disconnected(ctx->msg.file_id,
					     ctx->msg.open_persistent_id);
	if (!ok) {
		DEBUG(2, ("Failed to cleanup share modes and byte range locks "
			  "for file %s open %llu\n",
			  file_id_string_tos(&ctx->msg.file_id),
			  (unsigned long long)ctx->msg.open_persistent_id));
	}

	status = smbXsrv_open_cleanup(ctx->msg.open_persistent_id);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to cleanup open global for file %s open %llu:"
			  " %s\n", file_id_string_tos(&ctx->msg.file_id),
			  (unsigned long long)ctx->msg.open_persistent_id,
			  nt_errstr(status)));
	}
}

static void scavenger_add_timer(struct smbd_scavenger_state *state,
				struct scavenger_message *msg)
{
	struct tevent_timer *te;
	struct scavenger_timer_context *ctx;
	struct timeval until;

	nttime_to_timeval(&until, msg->until);

	DEBUG(10, ("scavenger: schedule file %s for cleanup at %s\n",
		   file_id_string_tos(&msg->file_id),
		   timeval_string(talloc_tos(), &until, true)));

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
