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
#include "g_lock.h"
#include "lib/util/util_tdb.h"
#include "smbd/globals.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "scavenger.h"
#include "source3/smbd/smbXsrv_open.h"

struct cleanup_rec {
	struct cleanup_rec *prev, *next;
	uint64_t open_persistent_id;
	struct file_id id;
	uint32_t name_hash;
};

struct smbd_cleanupd_state {
	pid_t parent_pid;
	struct messaging_context *msg;
	struct g_lock_ctx *glock_ctx;
	bool got_glock;
	struct cleanup_rec *cleanup_list;
};

static void smbd_cleanupd_shutdown(struct messaging_context *msg,
				   void *private_data, uint32_t msg_type,
				   struct server_id server_id,
				   DATA_BLOB *data);
static void smbd_cleanupd_process_exited(struct messaging_context *msg,
					 void *private_data, uint32_t msg_type,
					 struct server_id server_id,
					 DATA_BLOB *data);
static void smbd_cleanupd_got_glock(struct tevent_req *subreq);

struct tevent_req *smbd_cleanupd_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct messaging_context *msg,
				      pid_t parent_pid)
{
	struct tevent_req *req;
	struct tevent_req *subreq = NULL;
	struct smbd_cleanupd_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct smbd_cleanupd_state);
	if (req == NULL) {
		return NULL;
	}
	state->parent_pid = parent_pid;
	state->msg = msg;

	state->glock_ctx = g_lock_ctx_init(state, msg);
	if (state->glock_ctx == NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

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

	if (!lp_persistent_handles()) {
		return req;
	}

	subreq = g_lock_lock_send(state,
				  ev,
				  state->glock_ctx,
				  string_term_tdb_data("cleanupd"),
				  G_LOCK_WRITE,
				  NULL, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				smbd_cleanupd_got_glock,
				req);

	return req;
}

static int cleanup_ph_fn(struct db_record *dbrec,
			 struct smbXsrv_open_global0 *global,
			 TDB_DATA *rc_open_global_key,
			 void *private_data)
{
	struct smbd_cleanupd_state *state = talloc_get_type_abort(
		private_data, struct smbd_cleanupd_state);
	struct cleanup_rec *rec = NULL;

	if (global == NULL) {
		return 0;
	}

	rec = talloc_zero(state, struct cleanup_rec);
	if (rec == NULL) {
		DBG_ERR("talloc_zero failed\n");
		return -1;
	}
	*rec = (struct cleanup_rec) {
		.open_persistent_id = global->open_persistent_id,
		.id = global->file_id,
		.name_hash = global->name_hash,
	};

	DLIST_ADD(state->cleanup_list, rec);
	return 0;
}

static NTSTATUS cleanup_ph(struct smbd_cleanupd_state *state)
{
	struct cleanup_rec *rec = NULL;
	NTSTATUS status;

	if (!lp_persistent_handles()) {
		return NT_STATUS_OK;
	}

	DBG_INFO("Cleaning up persistent handles\n");

	status = smbXsrv_open_global_traverse_per_rec_persistent_read(
		cleanup_ph_fn, state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("PH cleanup failed\n");
		return status;
	}

	rec = state->cleanup_list;
	while (rec != NULL) {
		struct cleanup_rec *next = rec->next;

		scavenger_schedule_disconnected(state->msg,
						rec->open_persistent_id,
						&rec->id,
						rec->name_hash);
		DLIST_REMOVE(state->cleanup_list, rec);
		TALLOC_FREE(rec);
		rec = next;
	}


	return NT_STATUS_OK;
}

static void smbd_cleanupd_got_glock(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_cleanupd_state *state = tevent_req_data(
		req, struct smbd_cleanupd_state);
	NTSTATUS status;

	status = g_lock_lock_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	state->got_glock = true;

	status = cleanup_ph(state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Persistent handle cleanup failed\n");
		return;
	}
}

static void smbd_cleanupd_shutdown(struct messaging_context *msg,
				   void *private_data, uint32_t msg_type,
				   struct server_id server_id,
				   DATA_BLOB *data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct smbd_cleanupd_state *state = tevent_req_data(
		req, struct smbd_cleanupd_state);
	NTSTATUS status;

	if (!state->got_glock) {
		tevent_req_done(req);
		return;
	}

	status = g_lock_unlock(state->glock_ctx,
			       string_term_tdb_data("cleanupd"));
	if (tevent_req_nterror(req, status)) {
		return;
	}
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
	struct cleanup_child *children;
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
	DLIST_ADD(cleanup_state->children, child);

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
	bool unclean = false;
	NTSTATUS status;

	cleanup_state = (struct cleanupdb_traverse_state) {
		.mem_ctx = frame
	};

	/*
	 * This merely collect children in a list, whatever we're
	 * supposed to cleanup for every child, it has to take place
	 * *after* the db traverse in a list loop. This is to minimize
	 * locking interaction between the traverse and writers (i.e.
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

	for (child = cleanup_state.children;
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

		if (child->unclean) {
			unclean = true;
		}

		DBG_DEBUG("cleaned up pid %d\n", (int)child->pid);
	}

	if (unclean) {
		status = cleanup_ph(state);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Persistent handle cleanup failed\n");
		}
	}

	TALLOC_FREE(frame);
}

NTSTATUS smbd_cleanupd_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
