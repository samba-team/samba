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

#include "includes.h"
#include "smbd_cleanupd.h"
#include "lib/util_procid.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/debug.h"
#include "smbprofile.h"
#include "serverid.h"
#include "locking/proto.h"
#include "cleanupdb.h"

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

struct cleanup_child {
	struct cleanup_child *prev, *next;
	pid_t pid;
	bool unclean;
};

struct cleanupdb_traverse_state {
	TALLOC_CTX *mem_ctx;
	bool ok;
	struct cleanup_child *childs;
};

static int cleanupdb_traverse_fn(const pid_t pid,
				 const bool unclean,
				 void *private_data)
{
	struct cleanupdb_traverse_state *cleanup_state =
		(struct cleanupdb_traverse_state *)private_data;
	struct cleanup_child *child = NULL;

	child = talloc_zero(cleanup_state->mem_ctx, struct cleanup_child);
	if (child == NULL) {
		DBG_ERR("talloc_zero failed\n");
		return -1;
	}

	child->pid = pid;
	child->unclean = unclean;
	DLIST_ADD(cleanup_state->childs, child);

	return 0;
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
	int ret;
	struct cleanupdb_traverse_state cleanup_state;
	TALLOC_CTX *frame = talloc_stackframe();
	struct cleanup_child *child = NULL;

	cleanup_state = (struct cleanupdb_traverse_state) {
		.mem_ctx = frame
	};

	/*
	 * This merely collect childs in a list, whatever we're
	 * supposed to cleanup for every child, it has to take place
	 * *after* the db traverse in a list loop. This is to minimize
	 * locking interaction between the traverse and writers (ie
	 * the parent smbd).
	 */
	ret = cleanupdb_traverse_read(cleanupdb_traverse_fn, &cleanup_state);
	if (ret < 0) {
		DBG_ERR("cleanupdb_traverse_read failed\n");
		TALLOC_FREE(frame);
		return;
	}

	if (ret == 0) {
		TALLOC_FREE(frame);
		return;
	}

	for (child = cleanup_state.childs;
	     child != NULL;
	     child = child->next)
	{
		bool ok;

		ok = cleanupdb_delete_child(child->pid);
		if (!ok) {
			DBG_ERR("failed to delete pid %d\n", (int)child->pid);
		}

		smbprofile_cleanup(child->pid, state->parent_pid);

		ret = messaging_cleanup(msg, child->pid);

		if ((ret != 0) && (ret != ENOENT)) {
			DBG_DEBUG("messaging_cleanup returned %s\n",
				  strerror(ret));
		}

		DBG_DEBUG("cleaned up pid %d\n", (int)child->pid);
	}

	TALLOC_FREE(frame);
}

NTSTATUS smbd_cleanupd_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
