/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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
#include "../libcli/smb/smb_common.h"
#include "../lib/util/tevent_ntstatus.h"
#include "lib/dbwrap/dbwrap_watch.h"
#include "librpc/gen_ndr/open_files.h"
#include "messages.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

struct smbd_smb2_lock_element {
	uint64_t offset;
	uint64_t length;
	uint32_t flags;
};

struct smbd_smb2_lock_state {
	struct tevent_context *ev;
	struct smbd_smb2_request *smb2req;
	struct smb_request *smb1req;
	struct files_struct *fsp;
	bool blocking;
	uint32_t polling_msecs;
	uint32_t retry_msecs;
	uint16_t lock_count;
	struct smbd_lock_element *locks;
	uint8_t lock_sequence_value;
	uint8_t *lock_sequence_element;
};

static struct tevent_req *smbd_smb2_lock_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct smbd_smb2_request *smb2req,
						 struct files_struct *in_fsp,
						 uint32_t in_lock_sequence,
						 uint16_t in_lock_count,
						 struct smbd_smb2_lock_element *in_locks);
static NTSTATUS smbd_smb2_lock_recv(struct tevent_req *req);

static void smbd_smb2_request_lock_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_lock(struct smbd_smb2_request *req)
{
	const uint8_t *inbody;
	uint16_t in_lock_count;
	uint32_t in_lock_sequence;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp;
	struct smbd_smb2_lock_element *in_locks;
	struct tevent_req *subreq;
	const uint8_t *lock_buffer;
	uint16_t l;
	NTSTATUS status;

	status = smbd_smb2_request_verify_sizes(req, 0x30);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_lock_count			= CVAL(inbody, 0x02);
	if (req->xconn->protocol >= PROTOCOL_SMB2_10) {
		in_lock_sequence	= IVAL(inbody, 0x04);
	} else {
		/* 0x04 - 4 bytes reserved */
		in_lock_sequence	= 0;
	}
	in_file_id_persistent		= BVAL(inbody, 0x08);
	in_file_id_volatile		= BVAL(inbody, 0x10);

	if (in_lock_count < 1) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (((in_lock_count - 1) * 0x18) > SMBD_SMB2_IN_DYN_LEN(req)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_locks = talloc_array(req, struct smbd_smb2_lock_element,
				in_lock_count);
	if (in_locks == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	l = 0;
	lock_buffer = inbody + 0x18;

	in_locks[l].offset	= BVAL(lock_buffer, 0x00);
	in_locks[l].length	= BVAL(lock_buffer, 0x08);
	in_locks[l].flags	= IVAL(lock_buffer, 0x10);
	/* 0x14 - 4 reserved bytes */

	status = req->session->status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		/*
		 * We need to catch NT_STATUS_NETWORK_SESSION_EXPIRED
		 * for lock requests only.
		 *
		 * Unlock requests still need to be processed!
		 *
		 * This means smbd_smb2_request_check_session()
		 * can't handle the difference and always
		 * allows SMB2_OP_LOCK.
		 */
		if (in_locks[0].flags != SMB2_LOCK_FLAG_UNLOCK) {
			return smbd_smb2_request_error(req, status);
		}
	}

	lock_buffer = SMBD_SMB2_IN_DYN_PTR(req);

	for (l=1; l < in_lock_count; l++) {
		in_locks[l].offset	= BVAL(lock_buffer, 0x00);
		in_locks[l].length	= BVAL(lock_buffer, 0x08);
		in_locks[l].flags	= IVAL(lock_buffer, 0x10);
		/* 0x14 - 4 reserved bytes */

		lock_buffer += 0x18;
	}

	in_fsp = file_fsp_smb2(req, in_file_id_persistent, in_file_id_volatile);
	if (in_fsp == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_lock_send(req, req->sconn->ev_ctx,
				     req, in_fsp,
				     in_lock_sequence,
				     in_lock_count,
				     in_locks);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_lock_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_lock_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *smb2req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	DATA_BLOB outbody;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_lock_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(smb2req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	outbody = smbd_smb2_generate_outbody(smb2req, 0x04);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x04);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */

	error = smbd_smb2_request_done(smb2req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(smb2req->xconn,
						 nt_errstr(error));
		return;
	}
}

static void smbd_smb2_lock_cleanup(struct tevent_req *req,
				   enum tevent_req_state req_state);
static void smbd_smb2_lock_try(struct tevent_req *req);
static void smbd_smb2_lock_retry(struct tevent_req *subreq);
static bool smbd_smb2_lock_cancel(struct tevent_req *req);

static struct tevent_req *smbd_smb2_lock_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct smbd_smb2_request *smb2req,
						 struct files_struct *fsp,
						 uint32_t in_lock_sequence,
						 uint16_t in_lock_count,
						 struct smbd_smb2_lock_element *in_locks)
{
	struct tevent_req *req;
	struct smbd_smb2_lock_state *state;
	bool isunlock = false;
	uint16_t i;
	struct smbd_lock_element *locks;
	NTSTATUS status;
	bool check_lock_sequence = false;
	uint32_t lock_sequence_bucket = 0;

	req = tevent_req_create(mem_ctx, &state,
			struct smbd_smb2_lock_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fsp = fsp;
	state->smb2req = smb2req;
	smb2req->subreq = req; /* So we can find this when going async. */

	tevent_req_set_cleanup_fn(req, smbd_smb2_lock_cleanup);

	state->smb1req = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(state->smb1req, req)) {
		return tevent_req_post(req, ev);
	}

	DEBUG(10,("smbd_smb2_lock_send: %s - %s\n",
		  fsp_str_dbg(fsp), fsp_fnum_dbg(fsp)));

	/*
	 * Windows sets check_lock_sequence = true
	 * only for resilient and persistent handles.
	 *
	 * [MS-SMB2] 3.3.5.14 Receiving an SMB2 LOCK Request
	 *
	 *  ... if Open.IsResilient or Open.IsDurable or Open.IsPersistent is
	 *  TRUE or if Connection.Dialect belongs to the SMB 3.x dialect family
	 *  and Connection.ServerCapabilities includes
	 *  SMB2_GLOBAL_CAP_MULTI_CHANNEL bit, the server SHOULD<314>
	 *  perform lock sequence * verification ...

	 *  <314> Section 3.3.5.14: Windows 7 and Windows Server 2008 R2 perform
	 *  lock sequence verification only when Open.IsResilient is TRUE.
	 *  Windows 8 through Windows 10 v1909 and Windows Server 2012 through
	 *  Windows Server v1909 perform lock sequence verification only when
	 *  Open.IsResilient or Open.IsPersistent is TRUE.
	 *
	 * Note <314> also applies to all versions (at least) up to
	 * Windows Server v2004.
	 *
	 * Hopefully this will be fixed in future Windows versions and they
	 * will avoid Note <314>.
	 *
	 * We implement what the specification says by default, but
	 * allow "smb2 disable lock sequence checking = yes" to
	 * behave like Windows again.
	 *
	 * Note: that we already check the dialect before setting
	 * SMB2_CAP_MULTI_CHANNEL in smb2_negprot.c
	 */
	if (smb2req->xconn->smb2.server.capabilities & SMB2_CAP_MULTI_CHANNEL) {
		check_lock_sequence = true;
	}
	if (fsp->op->global->durable) {
		check_lock_sequence = true;
	}

	if (check_lock_sequence) {
		bool disable_lock_sequence_checking =
			lp_smb2_disable_lock_sequence_checking();

		if (disable_lock_sequence_checking) {
			check_lock_sequence = false;
		}
	}

	if (check_lock_sequence) {
		state->lock_sequence_value = in_lock_sequence & 0xF;
		lock_sequence_bucket = in_lock_sequence >> 4;
	}
	if ((lock_sequence_bucket > 0) &&
	    (lock_sequence_bucket <= sizeof(fsp->op->global->lock_sequence_array)))
	{
		uint32_t idx = lock_sequence_bucket - 1;
		uint8_t *array = fsp->op->global->lock_sequence_array;

		state->lock_sequence_element = &array[idx];
	}

	if (state->lock_sequence_element != NULL) {
		/*
		 * The incoming 'state->lock_sequence_value' is masked with 0xF.
		 *
		 * Note per default '*state->lock_sequence_element'
		 * is invalid, a value of 0xFF that can never match on
		 * incoming value.
		 */
		if (*state->lock_sequence_element == state->lock_sequence_value)
		{
			DBG_INFO("replayed smb2 lock request detected: "
				 "file %s, value %u, bucket %u\n",
				 fsp_str_dbg(fsp),
				 (unsigned)state->lock_sequence_value,
				 (unsigned)lock_sequence_bucket);
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
		/*
		 * If it's not a replay, mark the element as
		 * invalid again.
		 */
		*state->lock_sequence_element = 0xFF;
	}

	locks = talloc_array(state, struct smbd_lock_element, in_lock_count);
	if (locks == NULL) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return tevent_req_post(req, ev);
	}

	switch (in_locks[0].flags) {
	case SMB2_LOCK_FLAG_SHARED:
	case SMB2_LOCK_FLAG_EXCLUSIVE:
		if (in_lock_count > 1) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		state->blocking = true;
		break;

	case SMB2_LOCK_FLAG_SHARED|SMB2_LOCK_FLAG_FAIL_IMMEDIATELY:
	case SMB2_LOCK_FLAG_EXCLUSIVE|SMB2_LOCK_FLAG_FAIL_IMMEDIATELY:
		break;

	case SMB2_LOCK_FLAG_UNLOCK:
		/* only the first lock gives the UNLOCK bit - see
		   MS-SMB2 3.3.5.14 */
		isunlock = true;
		break;

	default:
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	if (!isunlock && (in_lock_count > 1)) {

		/*
		 * 3.3.5.14.2 says we SHOULD fail with INVALID_PARAMETER if we
		 * have more than one lock and one of those is blocking.
		 */

		for (i=0; i<in_lock_count; i++) {
			uint32_t flags = in_locks[i].flags;

			if ((flags & SMB2_LOCK_FLAG_FAIL_IMMEDIATELY) == 0) {
				tevent_req_nterror(
					req, NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}
		}
	}

	for (i=0; i<in_lock_count; i++) {
		bool invalid = false;

		switch (in_locks[i].flags) {
		case SMB2_LOCK_FLAG_SHARED:
		case SMB2_LOCK_FLAG_EXCLUSIVE:
			if (isunlock) {
				invalid = true;
				break;
			}
			break;

		case SMB2_LOCK_FLAG_SHARED|SMB2_LOCK_FLAG_FAIL_IMMEDIATELY:
		case SMB2_LOCK_FLAG_EXCLUSIVE|SMB2_LOCK_FLAG_FAIL_IMMEDIATELY:
			if (isunlock) {
				invalid = true;
			}
			break;

		case SMB2_LOCK_FLAG_UNLOCK:
			if (!isunlock) {
				tevent_req_nterror(req,
						   NT_STATUS_INVALID_PARAMETER);
				return tevent_req_post(req, ev);
			}
			break;

		default:
			if (isunlock) {
				/*
				 * If the first element was a UNLOCK
				 * we need to defer the error response
				 * to the backend, because we need to process
				 * all unlock elements before
				 */
				invalid = true;
				break;
			}
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		locks[i].req_guid = smbd_request_guid(smb2req->smb1req, i);
		locks[i].smblctx = fsp->op->global->open_persistent_id;
		locks[i].offset = in_locks[i].offset;
		locks[i].count  = in_locks[i].length;

		if (in_locks[i].flags & SMB2_LOCK_FLAG_EXCLUSIVE) {
			locks[i].brltype = WRITE_LOCK;
		} else if (in_locks[i].flags & SMB2_LOCK_FLAG_SHARED) {
			locks[i].brltype = READ_LOCK;
		} else if (invalid) {
			/*
			 * this is an invalid UNLOCK element
			 * and the backend needs to test for
			 * brltype != UNLOCK_LOCK and return
			 * NT_STATUS_INVALID_PARAMETER
			 */
			locks[i].brltype = READ_LOCK;
		} else {
			locks[i].brltype = UNLOCK_LOCK;
		}

		DBG_DEBUG("index %"PRIu16" offset=%"PRIu64", count=%"PRIu64", "
			  "smblctx = %"PRIu64" type %d\n",
			  i,
			  locks[i].offset,
			  locks[i].count,
			  locks[i].smblctx,
			  (int)locks[i].brltype);
	}

	state->locks = locks;
	state->lock_count = in_lock_count;

	if (isunlock) {
		status = smbd_do_unlocking(
			state->smb1req, fsp, in_lock_count, locks, WINDOWS_LOCK);

		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	smbd_smb2_lock_try(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, smb2req->sconn->ev_ctx);
	aio_add_req_to_fsp(state->fsp, req);
	tevent_req_set_cancel_fn(req, smbd_smb2_lock_cancel);

	return req;
}

static void smbd_smb2_lock_cleanup(struct tevent_req *req,
				   enum tevent_req_state req_state)
{
	struct smbd_smb2_lock_state *state = tevent_req_data(
		req, struct smbd_smb2_lock_state);

	if (req_state != TEVENT_REQ_DONE) {
		return;
	}

	if (state->lock_sequence_element != NULL) {
		/*
		 * On success we remember the given/incoming
		 * value (which was masked with 0xF.
		 */
		*state->lock_sequence_element = state->lock_sequence_value;
	}
}

static void smbd_smb2_lock_update_retry_msecs(
	struct smbd_smb2_lock_state *state)
{
	/*
	 * The default lp_lock_spin_time() is 200ms,
	 * we just use half of it to trigger the first retry.
	 *
	 * v_min is in the range of 0.001 to 10 secs
	 * (0.1 secs by default)
	 *
	 * v_max is in the range of 0.01 to 100 secs
	 * (1.0 secs by default)
	 *
	 * The typical steps are:
	 * 0.1, 0.2, 0.3, 0.4, ... 1.0
	 */
	uint32_t v_min = MAX(2, MIN(20000, lp_lock_spin_time()))/2;
	uint32_t v_max = 10 * v_min;

	if (state->retry_msecs >= v_max) {
		state->retry_msecs = v_max;
		return;
	}

	state->retry_msecs += v_min;
}

static void smbd_smb2_lock_update_polling_msecs(
	struct smbd_smb2_lock_state *state)
{
	/*
	 * The default lp_lock_spin_time() is 200ms.
	 *
	 * v_min is in the range of 0.002 to 20 secs
	 * (0.2 secs by default)
	 *
	 * v_max is in the range of 0.02 to 200 secs
	 * (2.0 secs by default)
	 *
	 * The typical steps are:
	 * 0.2, 0.4, 0.6, 0.8, ... 2.0
	 */
	uint32_t v_min = MAX(2, MIN(20000, lp_lock_spin_time()));
	uint32_t v_max = 10 * v_min;

	if (state->polling_msecs >= v_max) {
		state->polling_msecs = v_max;
		return;
	}

	state->polling_msecs += v_min;
}

static void smbd_smb2_lock_try(struct tevent_req *req)
{
	struct smbd_smb2_lock_state *state = tevent_req_data(
		req, struct smbd_smb2_lock_state);
	struct share_mode_lock *lck = NULL;
	uint16_t blocker_idx;
	struct server_id blocking_pid = { 0 };
	uint64_t blocking_smblctx;
	NTSTATUS status;
	struct tevent_req *subreq = NULL;
	struct timeval endtime = { 0 };

	lck = get_existing_share_mode_lock(
		talloc_tos(), state->fsp->file_id);
	if (tevent_req_nomem(lck, req)) {
		return;
	}

	status = smbd_do_locks_try(
		state->fsp,
		WINDOWS_LOCK,
		state->lock_count,
		state->locks,
		&blocker_idx,
		&blocking_pid,
		&blocking_smblctx);
	if (NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(lck);
		tevent_req_done(req);
		return;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		/*
		 * We got NT_STATUS_RETRY,
		 * we reset polling_msecs so that
		 * that the retries based on LOCK_NOT_GRANTED
		 * will later start with small intervalls again.
		 */
		state->polling_msecs = 0;

		/*
		 * The backend wasn't able to decide yet.
		 * We need to wait even for non-blocking
		 * locks.
		 *
		 * The backend uses blocking_smblctx == UINT64_MAX
		 * to indicate that we should use retry timers.
		 *
		 * It uses blocking_smblctx == 0 to indicate
		 * it will use share_mode_wakeup_waiters()
		 * to wake us. Note that unrelated changes in
		 * locking.tdb may cause retries.
		 */

		if (blocking_smblctx != UINT64_MAX) {
			SMB_ASSERT(blocking_smblctx == 0);
			goto setup_retry;
		}

		smbd_smb2_lock_update_retry_msecs(state);

		DBG_DEBUG("Waiting for a backend decision. "
			  "Retry in %"PRIu32" msecs\n",
			  state->retry_msecs);

		/*
		 * We completely ignore state->endtime here
		 * we we'll wait for a backend decision forever.
		 * If the backend is smart enough to implement
		 * some NT_STATUS_RETRY logic, it has to
		 * switch to any other status after in order
		 * to avoid waiting forever.
		 */
		endtime = timeval_current_ofs_msec(state->retry_msecs);
		goto setup_retry;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_LOCK_CONFLICT)) {
		/*
		 * This is a bug and will be changed into an assert
		 * in future version. We should only
		 * ever get NT_STATUS_LOCK_NOT_GRANTED here!
		 */
		static uint64_t _bug_count;
		int _level = (_bug_count++ == 0) ? DBGLVL_ERR: DBGLVL_DEBUG;
		DBG_PREFIX(_level, ("BUG: Got %s mapping to "
			   "NT_STATUS_LOCK_NOT_GRANTED\n",
			   nt_errstr(status)));
		status = NT_STATUS_LOCK_NOT_GRANTED;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_LOCK_NOT_GRANTED)) {
		TALLOC_FREE(lck);
		tevent_req_nterror(req, status);
		return;
	}
	/*
	 * We got LOCK_NOT_GRANTED, make sure
	 * a following STATUS_RETRY will start
	 * with short intervalls again.
	 */
	state->retry_msecs = 0;

	if (!state->blocking) {
		TALLOC_FREE(lck);
		tevent_req_nterror(req, status);
		return;
	}

	if (blocking_smblctx == UINT64_MAX) {
		smbd_smb2_lock_update_polling_msecs(state);

		DBG_DEBUG("Blocked on a posix lock. Retry in %"PRIu32" msecs\n",
			  state->polling_msecs);

		endtime = timeval_current_ofs_msec(state->polling_msecs);
	}

setup_retry:
	DBG_DEBUG("Watching share mode lock\n");

	subreq = share_mode_watch_send(
		state, state->ev, lck->data->id, blocking_pid);
	TALLOC_FREE(lck);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smbd_smb2_lock_retry, req);

	if (!timeval_is_zero(&endtime)) {
		bool ok;

		ok = tevent_req_set_endtime(subreq,
					    state->ev,
					    endtime);
		if (!ok) {
			tevent_req_oom(req);
			return;
		}
	}
}

static void smbd_smb2_lock_retry(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_lock_state *state = tevent_req_data(
		req, struct smbd_smb2_lock_state);
	NTSTATUS status;
	bool ok;

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service_by_fsp(state->fsp);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	status = share_mode_watch_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		/*
		 * This is just a trigger for a timed retry.
		 */
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	smbd_smb2_lock_try(req);
}

static NTSTATUS smbd_smb2_lock_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/****************************************************************
 Cancel an outstanding blocking lock request.
*****************************************************************/

static bool smbd_smb2_lock_cancel(struct tevent_req *req)
{
	struct smbd_smb2_request *smb2req = NULL;
	struct smbd_smb2_lock_state *state = tevent_req_data(req,
				struct smbd_smb2_lock_state);
	if (!state) {
		return false;
	}

	if (!state->smb2req) {
		return false;
	}

	smb2req = state->smb2req;

	/*
	 * If the request is canceled because of close, logoff or tdis
	 * the status is NT_STATUS_RANGE_NOT_LOCKED instead of
	 * NT_STATUS_CANCELLED.
	 */
	if (state->fsp->fsp_flags.closing ||
	    !NT_STATUS_IS_OK(smb2req->session->status) ||
	    !NT_STATUS_IS_OK(smb2req->tcon->status)) {
		tevent_req_nterror(req, NT_STATUS_RANGE_NOT_LOCKED);
		return true;
	}

	tevent_req_nterror(req, NT_STATUS_CANCELLED);
	return true;
}
