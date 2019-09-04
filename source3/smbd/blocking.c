/* 
   Unix SMB/CIFS implementation.
   Blocking Locking functions
   Copyright (C) Jeremy Allison 1998-2003

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "messages.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/dbwrap/dbwrap_watch.h"
#include "librpc/gen_ndr/ndr_open_files.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 We need a version of timeval_min that treats zero timval as infinite.
****************************************************************************/

struct timeval timeval_brl_min(const struct timeval *tv1,
					const struct timeval *tv2)
{
	if (timeval_is_zero(tv1)) {
		return *tv2;
	}
	if (timeval_is_zero(tv2)) {
		return *tv1;
	}
	return timeval_min(tv1, tv2);
}

NTSTATUS smbd_do_locks_try(
	struct files_struct *fsp,
	enum brl_flavour lock_flav,
	uint16_t num_locks,
	struct smbd_lock_element *locks,
	uint16_t *blocker_idx,
	struct server_id *blocking_pid,
	uint64_t *blocking_smblctx)
{
	NTSTATUS status = NT_STATUS_OK;
	uint16_t i;

	for (i=0; i<num_locks; i++) {
		struct smbd_lock_element *e = &locks[i];

		status = do_lock(
			fsp,
			e->smblctx,
			e->count,
			e->offset,
			e->brltype,
			lock_flav,
			blocking_pid,
			blocking_smblctx);
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}
	}

	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	*blocker_idx = i;

	/*
	 * Undo the locks we successfully got
	 */
	for (i = i-1; i != UINT16_MAX; i--) {
		struct smbd_lock_element *e = &locks[i];
		do_unlock(fsp,
			  e->smblctx,
			  e->count,
			  e->offset,
			  lock_flav);
	}

	return status;
}

static bool smbd_smb1_fsp_add_blocked_lock_req(
	struct files_struct *fsp, struct tevent_req *req)
{
	size_t num_reqs = talloc_array_length(fsp->blocked_smb1_lock_reqs);
	struct tevent_req **tmp = NULL;

	tmp = talloc_realloc(
		fsp,
		fsp->blocked_smb1_lock_reqs,
		struct tevent_req *,
		num_reqs+1);
	if (tmp == NULL) {
		return false;
	}
	fsp->blocked_smb1_lock_reqs = tmp;
	fsp->blocked_smb1_lock_reqs[num_reqs] = req;
	return true;
}

struct smbd_smb1_do_locks_state {
	struct tevent_context *ev;
	struct smb_request *smbreq;
	struct files_struct *fsp;
	struct timeval endtime;
	bool large_offset;	/* required for correct cancel */
	enum brl_flavour lock_flav;
	uint16_t num_locks;
	struct smbd_lock_element *locks;
	uint16_t blocker;
};

static void smbd_smb1_do_locks_retry(struct tevent_req *subreq);
static void smbd_smb1_blocked_locks_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state);

struct tevent_req *smbd_smb1_do_locks_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smb_request **smbreq, /* talloc_move()d into our state */
	struct files_struct *fsp,
	uint32_t timeout,
	bool large_offset,
	enum brl_flavour lock_flav,
	uint16_t num_locks,
	struct smbd_lock_element *locks)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct smbd_smb1_do_locks_state *state = NULL;
	struct share_mode_lock *lck = NULL;
	struct server_id blocking_pid = { 0 };
	uint64_t blocking_smblctx = 0;
	struct timeval endtime;
	NTSTATUS status = NT_STATUS_OK;
	bool ok;

	req = tevent_req_create(
		mem_ctx, &state, struct smbd_smb1_do_locks_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->smbreq = talloc_move(state, smbreq);
	state->fsp = fsp;
	state->large_offset = large_offset;
	state->lock_flav = lock_flav;
	state->num_locks = num_locks;
	state->locks = locks;

	DBG_DEBUG("state=%p, state->smbreq=%p\n", state, state->smbreq);

	if (num_locks == 0) {
		DBG_DEBUG("no locks\n");
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if ((timeout != 0) && (timeout != UINT32_MAX)) {
		/*
		 * Windows internal resolution for blocking locks
		 * seems to be about 200ms... Don't wait for less than
		 * that. JRA.
		 */
		timeout = MAX(timeout, lp_lock_spin_time());
	}

	lck = get_existing_share_mode_lock(state, state->fsp->file_id);
	if (tevent_req_nomem(lck, req)) {
		DBG_DEBUG("Could not get share mode lock\n");
		return tevent_req_post(req, ev);
	}

	status = smbd_do_locks_try(
		state->fsp,
		state->lock_flav,
		state->num_locks,
		state->locks,
		&state->blocker,
		&blocking_pid,
		&blocking_smblctx);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		goto done;
	}
	if (!ERROR_WAS_LOCK_DENIED(status)) {
		tevent_req_nterror(req, status);
		goto done;
	}

	if (timeout == 0) {
		struct smbd_lock_element *blocker = &locks[state->blocker];

		if ((blocker->offset >= 0xEF000000) &&
		    ((blocker->offset >> 63) == 0)) {
			/*
			 * This must be an optimization of an ancient
			 * application bug...
			 */
			timeout = lp_lock_spin_time();
		}

		if ((fsp->lock_failure_seen) &&
		    (blocker->offset == fsp->lock_failure_offset)) {
			/*
			 * Delay repeated lock attempts on the same
			 * lock. Maybe a more advanced version of the
			 * above check?
			 */
			DBG_DEBUG("Delaying lock request due to previous "
				  "failure\n");
			timeout = lp_lock_spin_time();
		}
	}

	DBG_DEBUG("timeout=%"PRIu32", blocking_smblctx=%"PRIu64"\n",
		  timeout,
		  blocking_smblctx);

	if (timeout == 0) {
		tevent_req_nterror(req, status);
		goto done;
	}

	subreq = dbwrap_watched_watch_send(
		state, state->ev, lck->data->record, blocking_pid);
	if (tevent_req_nomem(subreq, req)) {
		goto done;
	}
	TALLOC_FREE(lck);
	tevent_req_set_callback(subreq, smbd_smb1_do_locks_retry, req);

	state->endtime = timeval_current_ofs_msec(timeout);
	endtime = state->endtime;

	if (blocking_smblctx == UINT64_MAX) {
		struct timeval tmp;

		DBG_DEBUG("Blocked on a posix lock. Retry in one second\n");

		tmp = timeval_current_ofs(1, 0);
		endtime = timeval_min(&endtime, &tmp);
	}

	ok = tevent_req_set_endtime(subreq, state->ev, endtime);
	if (!ok) {
		tevent_req_oom(req);
		goto done;
	}

	ok = smbd_smb1_fsp_add_blocked_lock_req(fsp, req);
	if (!ok) {
		tevent_req_oom(req);
		goto done;
	}
	tevent_req_set_cleanup_fn(req, smbd_smb1_blocked_locks_cleanup);
	return req;
done:
	TALLOC_FREE(lck);
	return tevent_req_post(req, ev);
}

static void smbd_smb1_blocked_locks_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state)
{
	struct smbd_smb1_do_locks_state *state = tevent_req_data(
		req, struct smbd_smb1_do_locks_state);
	struct files_struct *fsp = state->fsp;
	struct tevent_req **blocked = fsp->blocked_smb1_lock_reqs;
	size_t num_blocked = talloc_array_length(blocked);
	size_t i, num_after;

	DBG_DEBUG("req=%p, state=%p, req_state=%d\n",
		  req,
		  state,
		  (int)req_state);

	if (req_state == TEVENT_REQ_RECEIVED) {
		DBG_DEBUG("already received\n");
		return;
	}

	for (i=0; i<num_blocked; i++) {
		if (blocked[i] == req) {
			break;
		}
	}
	SMB_ASSERT(i<num_blocked);

	num_after = num_blocked - (i+1);

	if (num_after > 0) {
		/*
		 * The locks need to be kept in order, see
		 * raw.lock.multilock2
		 */
		memmove(&blocked[i],
			&blocked[i+1],
			sizeof(*blocked) * num_after);
	}
	fsp->blocked_smb1_lock_reqs = talloc_realloc(
		fsp, blocked, struct tevent_req *, num_blocked-1);
}

static void smbd_smb1_do_locks_retry(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb1_do_locks_state *state = tevent_req_data(
		req, struct smbd_smb1_do_locks_state);
	struct files_struct *fsp = state->fsp;
	struct tevent_req **blocked = fsp->blocked_smb1_lock_reqs;
	struct tevent_req *retry_req = blocked[0];
	struct smbd_smb1_do_locks_state *retry_state = tevent_req_data(
		retry_req, struct smbd_smb1_do_locks_state);
	struct share_mode_lock *lck;
	struct timeval endtime;
	struct server_id blocking_pid = { 0 };
	uint64_t blocking_smblctx = 0;
	NTSTATUS status;
	bool ok;

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_by_fsp(state->fsp);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	status = dbwrap_watched_watch_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);

	DBG_DEBUG("dbwrap_watched_watch_recv returned %s\n",
		  nt_errstr(status));

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		double elapsed = timeval_elapsed(&state->endtime);
		if (elapsed > 0) {
			smbd_smb1_brl_finish_by_req(
				req, NT_STATUS_FILE_LOCK_CONFLICT);
			return;
		}
		/*
		 * This is a posix lock retry. Just retry.
		 */
	}

	lck = get_existing_share_mode_lock(state, fsp->file_id);
	if (tevent_req_nomem(lck, req)) {
		DBG_DEBUG("Could not get share mode lock\n");
		return;
	}

	status = smbd_do_locks_try(
		fsp,
		retry_state->lock_flav,
		retry_state->num_locks,
		retry_state->locks,
		&state->blocker,
		&blocking_pid,
		&blocking_smblctx);
	if (NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!ERROR_WAS_LOCK_DENIED(status)) {
		goto done;
	}

	subreq = dbwrap_watched_watch_send(
		state, state->ev, lck->data->record, blocking_pid);
	if (tevent_req_nomem(subreq, req)) {
		goto done;
	}
	TALLOC_FREE(lck);
	tevent_req_set_callback(subreq, smbd_smb1_do_locks_retry, req);

	endtime = state->endtime;

	if (blocking_smblctx == UINT64_MAX) {
		struct timeval tmp;

		DBG_DEBUG("Blocked on a posix lock. Retry in one second\n");

		tmp = timeval_current_ofs(1, 0);
		endtime = timeval_min(&endtime, &tmp);
	}

	ok = tevent_req_set_endtime(subreq, state->ev, endtime);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	return;
done:
	TALLOC_FREE(lck);
	smbd_smb1_brl_finish_by_req(req, status);
}

NTSTATUS smbd_smb1_do_locks_recv(struct tevent_req *req)
{
	struct smbd_smb1_do_locks_state *state = tevent_req_data(
		req, struct smbd_smb1_do_locks_state);
	NTSTATUS status = NT_STATUS_OK;
	bool err;

	err = tevent_req_is_nterror(req, &status);

	DBG_DEBUG("err=%d, status=%s\n", (int)err, nt_errstr(status));

	if (tevent_req_is_nterror(req, &status)) {
		struct files_struct *fsp = state->fsp;
		struct smbd_lock_element *blocker =
			&state->locks[state->blocker];

		DBG_DEBUG("Setting lock_failure_offset=%"PRIu64"\n",
			  blocker->offset);

		fsp->lock_failure_seen = true;
		fsp->lock_failure_offset = blocker->offset;
		return status;
	}

	tevent_req_received(req);

	return NT_STATUS_OK;
}

bool smbd_smb1_do_locks_extract_smbreq(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct smb_request **psmbreq)
{
	struct smbd_smb1_do_locks_state *state = tevent_req_data(
		req, struct smbd_smb1_do_locks_state);

	DBG_DEBUG("req=%p, state=%p, state->smbreq=%p\n",
		  req,
		  state,
		  state->smbreq);

	if (state->smbreq == NULL) {
		return false;
	}
	*psmbreq = talloc_move(mem_ctx, &state->smbreq);
	return true;
}

void smbd_smb1_brl_finish_by_req(struct tevent_req *req, NTSTATUS status)
{
	DBG_DEBUG("req=%p, status=%s\n", req, nt_errstr(status));

	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
	} else {
		tevent_req_nterror(req, status);
	}
}

bool smbd_smb1_brl_finish_by_lock(
	struct files_struct *fsp,
	bool large_offset,
	enum brl_flavour lock_flav,
	struct smbd_lock_element lock,
	NTSTATUS finish_status)
{
	struct tevent_req **blocked = fsp->blocked_smb1_lock_reqs;
	size_t num_blocked = talloc_array_length(blocked);
	size_t i;

	DBG_DEBUG("num_blocked=%zu\n", num_blocked);

	for (i=0; i<num_blocked; i++) {
		struct tevent_req *req = blocked[i];
		struct smbd_smb1_do_locks_state *state = tevent_req_data(
			req, struct smbd_smb1_do_locks_state);
		uint16_t j;

		DBG_DEBUG("i=%zu, req=%p\n", i, req);

		if ((state->large_offset != large_offset) ||
		    (state->lock_flav != lock_flav)) {
			continue;
		}

		for (j=0; j<state->num_locks; j++) {
			struct smbd_lock_element *l = &state->locks[j];

			if ((lock.smblctx == l->smblctx) &&
			    (lock.offset == l->offset) &&
			    (lock.count == l->count)) {
				smbd_smb1_brl_finish_by_req(
					req, finish_status);
				return true;
			}
		}
	}
	return false;
}

static struct files_struct *smbd_smb1_brl_finish_by_mid_fn(
	struct files_struct *fsp, void *private_data)
{
	struct tevent_req **blocked = fsp->blocked_smb1_lock_reqs;
	size_t num_blocked = talloc_array_length(blocked);
	uint64_t mid = *((uint64_t *)private_data);
	size_t i;

	DBG_DEBUG("fsp=%p, num_blocked=%zu\n", fsp, num_blocked);

	for (i=0; i<num_blocked; i++) {
		struct tevent_req *req = blocked[i];
		struct smbd_smb1_do_locks_state *state = tevent_req_data(
			req, struct smbd_smb1_do_locks_state);
		struct smb_request *smbreq = state->smbreq;

		if (smbreq->mid == mid) {
			tevent_req_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
			return fsp;
		}
	}

	return NULL;
}

/*
 * This walks the list of fsps, we store the blocked reqs attached to
 * them. It can be expensive, but this is legacy SMB1 and trying to
 * remember looking at traces I don't reall many of those calls.
 */

bool smbd_smb1_brl_finish_by_mid(
	struct smbd_server_connection *sconn, uint64_t mid)
{
	struct files_struct *found = files_forall(
		sconn, smbd_smb1_brl_finish_by_mid_fn, &mid);
	return (found != NULL);
}
