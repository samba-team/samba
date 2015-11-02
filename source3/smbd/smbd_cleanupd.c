/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke 2015
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

#include "replace.h"
#include "smbd_cleanupd.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/debug.h"

struct smbd_cleanupd_state {
	pid_t parent_pid;
};

static void smbd_cleanupd_shutdown(struct messaging_context *msg,
				   void *private_data, uint32_t msg_type,
				   struct server_id server_id,
				   DATA_BLOB *data);
static void smbd_cleanupd_process_exited(struct messaging_context *msg,
					 void *private_data, uint32_t msg_type,
					 struct server_id server_id,
					 DATA_BLOB *data);

struct tevent_req *smbd_cleanupd_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct messaging_context *msg,
				      pid_t parent_pid)
{
	struct tevent_req *req;
	struct smbd_cleanupd_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct smbd_cleanupd_state);
	if (req == NULL) {
		return NULL;
	}
	state->parent_pid = parent_pid;

	status = messaging_register(msg, req, MSG_SHUTDOWN,
				    smbd_cleanupd_shutdown);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = messaging_register(msg, req, MSG_SMB_NOTIFY_CLEANUP,
				    smbd_cleanupd_process_exited);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void smbd_cleanupd_shutdown(struct messaging_context *msg,
				   void *private_data, uint32_t msg_type,
				   struct server_id server_id,
				   DATA_BLOB *data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	tevent_req_done(req);
}

static void smbd_cleanupd_process_exited(struct messaging_context *msg,
					 void *private_data, uint32_t msg_type,
					 struct server_id server_id,
					 DATA_BLOB *data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct smbd_cleanupd_state *state = tevent_req_data(
		req, struct smbd_cleanupd_state);
	pid_t pid;
	bool unclean_shutdown;

	if (data->length != (sizeof(pid) + sizeof(unclean_shutdown))) {
		DBG_WARNING("Got invalid length: %zu\n", data->length);
		return;
	}

	memcpy(&pid, data->data, sizeof(pid));
	memcpy(&unclean_shutdown, data->data + sizeof(pid),
	       sizeof(unclean_shutdown));

	DBG_DEBUG("%d exited %sclean\n", (int)pid,
		  unclean_shutdown ? "un" : "");
}

NTSTATUS smbd_cleanupd_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
