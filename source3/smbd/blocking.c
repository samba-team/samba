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

static void received_unlock_msg(struct messaging_context *msg,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data);

void brl_timeout_fn(struct tevent_context *event_ctx,
			   struct tevent_timer *te,
			   struct timeval now,
			   void *private_data)
{
	struct smbd_server_connection *sconn = talloc_get_type_abort(
		private_data, struct smbd_server_connection);

	if (sconn->using_smb2) {
		SMB_ASSERT(sconn->smb2.locks.brl_timeout == te);
		TALLOC_FREE(sconn->smb2.locks.brl_timeout);
	} else {
		SMB_ASSERT(sconn->smb1.locks.brl_timeout == te);
		TALLOC_FREE(sconn->smb1.locks.brl_timeout);
	}

	change_to_root_user();	/* TODO: Possibly run all timed events as
				 * root */

	process_blocking_lock_queue(sconn);
}

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

/****************************************************************************
 After a change to blocking_lock_queue, recalculate the timed_event for the
 next processing.
****************************************************************************/

static bool recalc_brl_timeout(struct smbd_server_connection *sconn)
{
	struct blocking_lock_record *blr;
	struct timeval next_timeout;
	int max_brl_timeout = lp_parm_int(-1, "brl", "recalctime", 5);

	TALLOC_FREE(sconn->smb1.locks.brl_timeout);

	next_timeout = timeval_zero();

	for (blr = sconn->smb1.locks.blocking_lock_queue; blr; blr = blr->next) {
		if (timeval_is_zero(&blr->expire_time)) {
			/*
			 * If we're blocked on pid 0xFFFFFFFFFFFFFFFFLL this is
			 * a POSIX lock, so calculate a timeout of
			 * 10 seconds into the future.
			 */
                        if (blr->blocking_smblctx == 0xFFFFFFFFFFFFFFFFLL) {
				struct timeval psx_to = timeval_current_ofs(10, 0);
				next_timeout = timeval_brl_min(&next_timeout, &psx_to);
                        }

			continue;
		}

		next_timeout = timeval_brl_min(&next_timeout, &blr->expire_time);
	}

	if (timeval_is_zero(&next_timeout)) {
		DEBUG(10, ("Next timeout = Infinite.\n"));
		return True;
	}

	/*
	 to account for unclean shutdowns by clients we need a
	 maximum timeout that we use for checking pending locks. If
	 we have any pending locks at all, then check if the pending
	 lock can continue at least every brl:recalctime seconds
	 (default 5 seconds).

	 This saves us needing to do a message_send_all() in the
	 SIGCHLD handler in the parent daemon. That
	 message_send_all() caused O(n^2) work to be done when IP
	 failovers happened in clustered Samba, which could make the
	 entire system unusable for many minutes.
	*/

	if (max_brl_timeout > 0) {
		struct timeval min_to = timeval_current_ofs(max_brl_timeout, 0);
		next_timeout = timeval_min(&next_timeout, &min_to);
	}

	if (DEBUGLVL(10)) {
		struct timeval cur, from_now;

		cur = timeval_current();
		from_now = timeval_until(&cur, &next_timeout);
		DEBUG(10, ("Next timeout = %d.%d seconds from now.\n",
		    (int)from_now.tv_sec, (int)from_now.tv_usec));
	}

	sconn->smb1.locks.brl_timeout = tevent_add_timer(sconn->ev_ctx,
							 NULL, next_timeout,
							 brl_timeout_fn, sconn);
	if (sconn->smb1.locks.brl_timeout == NULL) {
		return False;
	}

	return True;
}


/****************************************************************************
 Function to push a blocking lock request onto the lock queue.
****************************************************************************/

bool push_blocking_lock_request( struct byte_range_lock *br_lck,
		struct smb_request *req,
		files_struct *fsp,
		int lock_timeout,
		int lock_num,
		uint64_t smblctx,
		enum brl_type lock_type,
		enum brl_flavour lock_flav,
		uint64_t offset,
		uint64_t count,
		uint64_t blocking_smblctx)
{
	struct smbd_server_connection *sconn = req->sconn;
	struct blocking_lock_record *blr;
	struct server_id blocker_pid;
	NTSTATUS status;

	if (req->smb2req) {
		return push_blocking_lock_request_smb2(br_lck,
				req,
				fsp,
				lock_timeout,
				lock_num,
				smblctx,
				lock_type,
				lock_flav,
				offset,
				count,
				blocking_smblctx);
	}

	if(req_is_in_chain(req)) {
		DEBUG(0,("push_blocking_lock_request: cannot queue a chained request (currently).\n"));
		return False;
	}

	/*
	 * Now queue an entry on the blocking lock queue. We setup
	 * the expiration time here.
	 */

	blr = talloc(NULL, struct blocking_lock_record);
	if (blr == NULL) {
		DEBUG(0,("push_blocking_lock_request: Malloc fail !\n" ));
		return False;
	}

	blr->next = NULL;
	blr->prev = NULL;

	blr->fsp = fsp;
	if (lock_timeout == -1) {
		blr->expire_time.tv_sec = 0;
		blr->expire_time.tv_usec = 0; /* Never expire. */
	} else {
		blr->expire_time = timeval_current_ofs_msec(lock_timeout);
	}
	blr->lock_num = lock_num;
	blr->smblctx = smblctx;
	blr->blocking_smblctx = blocking_smblctx;
	blr->lock_flav = lock_flav;
	blr->lock_type = lock_type;
	blr->offset = offset;
	blr->count = count;

	/* Specific brl_lock() implementations can fill this in. */
	blr->blr_private = NULL;

	/* Add a pending lock record for this. */
	status = brl_lock(req->sconn->msg_ctx,
			br_lck,
			smblctx,
			messaging_server_id(req->sconn->msg_ctx),
			offset,
			count,
			lock_type == READ_LOCK ? PENDING_READ_LOCK : PENDING_WRITE_LOCK,
			blr->lock_flav,
			True,
			&blocker_pid,
			NULL);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("push_blocking_lock_request: failed to add PENDING_LOCK record.\n"));
		TALLOC_FREE(blr);
		return False;
	}

	SMB_PERFCOUNT_DEFER_OP(&req->pcd, &req->pcd);
	blr->req = talloc_move(blr, &req);

	DLIST_ADD_END(sconn->smb1.locks.blocking_lock_queue, blr);
	recalc_brl_timeout(sconn);

	/* Ensure we'll receive messages when this is unlocked. */
	if (!sconn->smb1.locks.blocking_lock_unlock_state) {
		messaging_register(sconn->msg_ctx, sconn,
				   MSG_SMB_UNLOCK, received_unlock_msg);
		sconn->smb1.locks.blocking_lock_unlock_state = true;
	}

	DEBUG(3,("push_blocking_lock_request: lock request blocked with "
		"expiry time (%u sec. %u usec) (+%d msec) for %s, name = %s\n",
		(unsigned int)blr->expire_time.tv_sec,
		(unsigned int)blr->expire_time.tv_usec, lock_timeout,
		fsp_fnum_dbg(blr->fsp), fsp_str_dbg(blr->fsp)));

	return True;
}

/****************************************************************************
 Return a lockingX success SMB.
*****************************************************************************/

static void reply_lockingX_success(struct blocking_lock_record *blr)
{
	struct smb_request *req = blr->req;

	reply_outbuf(req, 2, 0);
	SSVAL(req->outbuf, smb_vwv0, 0xff); /* andx chain ends */
	SSVAL(req->outbuf, smb_vwv1, 0);    /* no andx offset */

	/*
	 * As this message is a lockingX call we must handle
	 * any following chained message correctly.
	 * This is normally handled in construct_reply(),
	 * but as that calls switch_message, we can't use
	 * that here and must set up the chain info manually.
	 */

	if (!srv_send_smb(req->xconn,
			(char *)req->outbuf,
			true, req->seqnum+1,
			IS_CONN_ENCRYPTED(req->conn)||req->encrypted,
			&req->pcd)) {
		exit_server_cleanly("reply_lockingX_success: srv_send_smb "
				    "failed.");
	}

	TALLOC_FREE(req->outbuf);
}

/****************************************************************************
 Return a generic lock fail error blocking call.
*****************************************************************************/

static void generic_blocking_lock_error(struct blocking_lock_record *blr, NTSTATUS status)
{
	/* whenever a timeout is given w2k maps LOCK_NOT_GRANTED to
	   FILE_LOCK_CONFLICT! (tridge) */
	if (NT_STATUS_EQUAL(status, NT_STATUS_LOCK_NOT_GRANTED)) {
		status = NT_STATUS_FILE_LOCK_CONFLICT;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_LOCK_CONFLICT)) {
		/* Store the last lock error. */
		files_struct *fsp = blr->fsp;

		if (fsp) {
			fsp->last_lock_failure.context.smblctx = blr->smblctx;
			fsp->last_lock_failure.context.tid = fsp->conn->cnum;
			fsp->last_lock_failure.context.pid =
				messaging_server_id(fsp->conn->sconn->msg_ctx);
			fsp->last_lock_failure.start = blr->offset;
			fsp->last_lock_failure.size = blr->count;
			fsp->last_lock_failure.fnum = fsp->fnum;
			fsp->last_lock_failure.lock_type = READ_LOCK; /* Don't care. */
			fsp->last_lock_failure.lock_flav = blr->lock_flav;
		}
	}

	reply_nterror(blr->req, status);
	if (!srv_send_smb(blr->req->xconn, (char *)blr->req->outbuf,
			  true, blr->req->seqnum+1,
			  blr->req->encrypted, NULL)) {
		exit_server_cleanly("generic_blocking_lock_error: srv_send_smb failed.");
	}
	TALLOC_FREE(blr->req->outbuf);
}

/****************************************************************************
 Return a lock fail error for a lockingX call. Undo all the locks we have
 obtained first.
*****************************************************************************/

static void undo_locks_obtained(struct blocking_lock_record *blr)
{
	files_struct *fsp = blr->fsp;
	uint16_t num_ulocks = SVAL(blr->req->vwv+6, 0);
	uint64_t count = (uint64_t)0, offset = (uint64_t) 0;
	uint64_t smblctx;
	unsigned char locktype = CVAL(blr->req->vwv+3, 0);
	bool large_file_format = (locktype & LOCKING_ANDX_LARGE_FILES);
	uint8_t *data;
	int i;

	data = discard_const_p(uint8_t, blr->req->buf)
		+ ((large_file_format ? 20 : 10)*num_ulocks);

	/*
	 * Data now points at the beginning of the list
	 * of smb_lkrng structs.
	 */

	/*
	 * Ensure we don't do a remove on the lock that just failed,
	 * as under POSIX rules, if we have a lock already there, we
	 * will delete it (and we shouldn't) .....
	 */

	for(i = blr->lock_num - 1; i >= 0; i--) {

		smblctx = get_lock_pid( data, i, large_file_format);
		count = get_lock_count( data, i, large_file_format);
		offset = get_lock_offset( data, i, large_file_format);

		/*
		 * We know err cannot be set as if it was the lock
		 * request would never have been queued. JRA.
		 */

		do_unlock(fsp->conn->sconn->msg_ctx,
			fsp,
			smblctx,
			count,
			offset,
			WINDOWS_LOCK);
	}
}

/****************************************************************************
 Return a lock fail error.
*****************************************************************************/

static void blocking_lock_reply_error(struct blocking_lock_record *blr, NTSTATUS status)
{
	DEBUG(10, ("Replying with error=%s. BLR = %p\n", nt_errstr(status), blr));

	switch(blr->req->cmd) {
	case SMBlockingX:
		/*
		 * This code can be called during the rundown of a
		 * file after it was already closed. In that case,
		 * blr->fsp==NULL and we do not need to undo any
		 * locks, they are already gone.
		 */
		if (blr->fsp != NULL) {
			undo_locks_obtained(blr);
		}
		generic_blocking_lock_error(blr, status);
		break;
	case SMBtrans2:
	case SMBtranss2:
		reply_nterror(blr->req, status);

		/*
		 * construct_reply_common has done us the favor to pre-fill
		 * the command field with SMBtranss2 which is wrong :-)
		 */
		SCVAL(blr->req->outbuf,smb_com,SMBtrans2);

		if (!srv_send_smb(blr->req->xconn,
				  (char *)blr->req->outbuf,
				  true, blr->req->seqnum+1,
				  IS_CONN_ENCRYPTED(blr->fsp->conn),
				  NULL)) {
			exit_server_cleanly("blocking_lock_reply_error: "
					    "srv_send_smb failed.");
		}
		TALLOC_FREE(blr->req->outbuf);
		break;
	default:
		DEBUG(0,("blocking_lock_reply_error: PANIC - unknown type on blocking lock queue - exiting.!\n"));
		exit_server("PANIC - unknown type on blocking lock queue");
	}
}

/****************************************************************************
 Utility function that returns true if a lock timed out.
*****************************************************************************/

static bool lock_timed_out(const struct blocking_lock_record *blr)
{
	struct timeval tv_curr;

	if (timeval_is_zero(&blr->expire_time)) {
		return false; /* Never times out. */
	}

	tv_curr = timeval_current();
	if (timeval_compare(&blr->expire_time, &tv_curr) <= 0) {
		return true;
	}
	return false;
}

/****************************************************************************
 Attempt to finish off getting all pending blocking locks for a lockingX call.
 Returns True if we want to be removed from the list.
*****************************************************************************/

static bool process_lockingX(struct blocking_lock_record *blr)
{
	unsigned char locktype = CVAL(blr->req->vwv+3, 0);
	files_struct *fsp = blr->fsp;
	uint16_t num_ulocks = SVAL(blr->req->vwv+6, 0);
	uint16_t num_locks = SVAL(blr->req->vwv+7, 0);
	bool large_file_format = (locktype & LOCKING_ANDX_LARGE_FILES);
	uint8_t *data;
	NTSTATUS status = NT_STATUS_OK;
	bool lock_timeout = lock_timed_out(blr);

	data = discard_const_p(uint8_t, blr->req->buf)
		+ ((large_file_format ? 20 : 10)*num_ulocks);

	/*
	 * Data now points at the beginning of the list
	 * of smb_lkrng structs.
	 */

	for(; blr->lock_num < num_locks; blr->lock_num++) {
		struct byte_range_lock *br_lck = NULL;

		/*
		 * Ensure the blr record gets updated with
		 * any lock we might end up blocked on.
		 */

		blr->smblctx = get_lock_pid( data, blr->lock_num, large_file_format);
		blr->count = get_lock_count( data, blr->lock_num, large_file_format);
		blr->offset = get_lock_offset( data, blr->lock_num, large_file_format);

		/*
		 * We know err cannot be set as if it was the lock
		 * request would never have been queued. JRA.
		 */
		errno = 0;
		br_lck = do_lock(fsp->conn->sconn->msg_ctx,
				fsp,
				blr->smblctx,
				blr->count,
				blr->offset,
				((locktype & LOCKING_ANDX_SHARED_LOCK) ?
					READ_LOCK : WRITE_LOCK),
				WINDOWS_LOCK,
				True,
				&status,
				NULL,
				&blr->blocking_smblctx);

		if (ERROR_WAS_LOCK_DENIED(status) && !lock_timeout) {
			struct server_id blocker_pid;
			/*
			 * If we didn't timeout, but still need to wait,
			 * re-add the pending lock entry whilst holding
			 * the brlock db lock.
			 */
			NTSTATUS status1 =
				brl_lock(blr->fsp->conn->sconn->msg_ctx,
					br_lck,
					blr->smblctx,
					messaging_server_id(
						blr->fsp->conn->sconn->msg_ctx),
					blr->offset,
					blr->count,
					blr->lock_type == READ_LOCK ?
						PENDING_READ_LOCK :
						PENDING_WRITE_LOCK,
						blr->lock_flav,
					true, /* Blocking lock. */
					&blocker_pid,
					NULL);

			if (!NT_STATUS_IS_OK(status1)) {
				DEBUG(0,("failed to add PENDING_LOCK "
					"record.\n"));
			}
		}

		TALLOC_FREE(br_lck);

		if (NT_STATUS_IS_ERR(status)) {
			break;
		}
	}

	if(blr->lock_num == num_locks) {
		/*
		 * Success - we got all the locks.
		 */

		DEBUG(3,("process_lockingX file = %s, %s, type=%d "
			 "num_locks=%d\n", fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
			 (unsigned int)locktype, num_locks));

		reply_lockingX_success(blr);
		return True;
	}

	if (!ERROR_WAS_LOCK_DENIED(status)) {
		/*
		 * We have other than a "can't get lock"
		 * error. Free any locks we had and return an error.
		 * Return True so we get dequeued.
		 */
		blocking_lock_reply_error(blr, status);
		return True;
	}

	/*
	 * Return an error to the client if we timed out.
	 */
	if (lock_timeout) {
		blocking_lock_reply_error(blr,NT_STATUS_FILE_LOCK_CONFLICT);
		return true;
	}

	/*
	 * Still can't get all the locks - keep waiting.
	 */

	DEBUG(10, ("process_lockingX: only got %d locks of %d needed for "
		   "file %s, %s. Waiting....\n",
		   blr->lock_num, num_locks, fsp_str_dbg(fsp),
		   fsp_fnum_dbg(fsp)));

	return False;
}

/****************************************************************************
 Attempt to get the posix lock request from a SMBtrans2 call.
 Returns True if we want to be removed from the list.
*****************************************************************************/

static bool process_trans2(struct blocking_lock_record *blr)
{
	char params[2];
	NTSTATUS status;
	bool lock_timeout = lock_timed_out(blr);

	struct byte_range_lock *br_lck = do_lock(
						blr->fsp->conn->sconn->msg_ctx,
						blr->fsp,
						blr->smblctx,
						blr->count,
						blr->offset,
						blr->lock_type,
						blr->lock_flav,
						True,
						&status,
						NULL,
						&blr->blocking_smblctx);
	if (ERROR_WAS_LOCK_DENIED(status) && !lock_timeout) {
		struct server_id blocker_pid;
		/*
		 * If we didn't timeout, but still need to wait,
		 * re-add the pending lock entry whilst holding
		 * the brlock db lock.
		 */
		NTSTATUS status1 =
			brl_lock(blr->fsp->conn->sconn->msg_ctx,
				br_lck,
				blr->smblctx,
				messaging_server_id(
					blr->fsp->conn->sconn->msg_ctx),
				blr->offset,
				blr->count,
				blr->lock_type == READ_LOCK ?
					PENDING_READ_LOCK :
					PENDING_WRITE_LOCK,
				blr->lock_flav,
				true, /* Blocking lock. */
				&blocker_pid,
				NULL);

		if (!NT_STATUS_IS_OK(status1)) {
			DEBUG(0,("failed to add PENDING_LOCK record.\n"));
		}
	}

	TALLOC_FREE(br_lck);

	if (!NT_STATUS_IS_OK(status)) {
		if (ERROR_WAS_LOCK_DENIED(status)) {
			if (lock_timeout) {
				/*
				 * Return an error if we timed out
				 * and return true to get dequeued.
				 */
				blocking_lock_reply_error(blr,
					NT_STATUS_FILE_LOCK_CONFLICT);
				return true;
			}
			/* Still can't get the lock, just keep waiting. */
			return False;
		}
		/*
		 * We have other than a "can't get lock"
		 * error. Send an error and return True so we get dequeued.
		 */
		blocking_lock_reply_error(blr, status);
		return True;
	}

	/* We finally got the lock, return success. */

	SSVAL(params,0,0);
	/* Fake up max_data_bytes here - we know it fits. */
	send_trans2_replies(blr->fsp->conn, blr->req, NT_STATUS_OK, params, 2, NULL, 0, 0xffff);
	return True;
}


/****************************************************************************
 Process a blocking lock SMB.
 Returns True if we want to be removed from the list.
*****************************************************************************/

static bool blocking_lock_record_process(struct blocking_lock_record *blr)
{
	switch(blr->req->cmd) {
		case SMBlockingX:
			return process_lockingX(blr);
		case SMBtrans2:
		case SMBtranss2:
			return process_trans2(blr);
		default:
			DEBUG(0,("blocking_lock_record_process: PANIC - unknown type on blocking lock queue - exiting.!\n"));
			exit_server("PANIC - unknown type on blocking lock queue");
	}
	return False; /* Keep compiler happy. */
}

/****************************************************************************
 Cancel entries by fnum from the blocking lock pending queue.
 Called when a file is closed.
*****************************************************************************/

void smbd_cancel_pending_lock_requests_by_fid(files_struct *fsp,
					      struct byte_range_lock *br_lck,
					      enum file_close_type close_type)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	struct blocking_lock_record *blr, *blr_cancelled, *next = NULL;

	if (sconn->using_smb2) {
		cancel_pending_lock_requests_by_fid_smb2(fsp,
					br_lck,
					close_type);
		return;
	}

	for(blr = sconn->smb1.locks.blocking_lock_queue; blr; blr = next) {
		unsigned char locktype = 0;

		next = blr->next;
		if (blr->fsp->fnum != fsp->fnum) {
			continue;
		}

		if (blr->req->cmd == SMBlockingX) {
			locktype = CVAL(blr->req->vwv+3, 0);
		}

		DEBUG(10, ("remove_pending_lock_requests_by_fid - removing "
			   "request type %d for file %s, %s\n",
			   blr->req->cmd, fsp_str_dbg(fsp), fsp_fnum_dbg(fsp)));

		blr_cancelled = blocking_lock_cancel_smb1(fsp,
				     blr->smblctx,
				     blr->offset,
				     blr->count,
				     blr->lock_flav,
				     locktype,
				     NT_STATUS_RANGE_NOT_LOCKED);

		SMB_ASSERT(blr_cancelled == blr);

		brl_lock_cancel(br_lck,
				blr->smblctx,
				messaging_server_id(sconn->msg_ctx),
				blr->offset,
				blr->count,
				blr->lock_flav);

		/* We're closing the file fsp here, so ensure
		 * we don't have a dangling pointer. */
		blr->fsp = NULL;
	}
}

/****************************************************************************
 Delete entries by mid from the blocking lock pending queue. Always send reply.
 Only called from the SMB1 cancel code.
*****************************************************************************/

void remove_pending_lock_requests_by_mid_smb1(
	struct smbd_server_connection *sconn, uint64_t mid)
{
	struct blocking_lock_record *blr, *next = NULL;

	for(blr = sconn->smb1.locks.blocking_lock_queue; blr; blr = next) {
		files_struct *fsp;
		struct byte_range_lock *br_lck;

		next = blr->next;

		if (blr->req->mid != mid) {
			continue;
		}

		fsp = blr->fsp;
		br_lck = brl_get_locks(talloc_tos(), fsp);

		if (br_lck) {
			DEBUG(10, ("remove_pending_lock_requests_by_mid_smb1 - "
				   "removing request type %d for file %s, %s\n",
				   blr->req->cmd, fsp_str_dbg(fsp),
				   fsp_fnum_dbg(fsp)));

			brl_lock_cancel(br_lck,
					blr->smblctx,
					messaging_server_id(sconn->msg_ctx),
					blr->offset,
					blr->count,
					blr->lock_flav);
			TALLOC_FREE(br_lck);
		}

		blocking_lock_reply_error(blr,NT_STATUS_FILE_LOCK_CONFLICT);
		DLIST_REMOVE(sconn->smb1.locks.blocking_lock_queue, blr);
		TALLOC_FREE(blr);
	}
}

/****************************************************************************
 Is this mid a blocking lock request on the queue ?
 Currently only called from the SMB1 unix extensions POSIX lock code.
*****************************************************************************/

bool blocking_lock_was_deferred_smb1(
	struct smbd_server_connection *sconn, uint64_t mid)
{
	struct blocking_lock_record *blr, *next = NULL;

	for(blr = sconn->smb1.locks.blocking_lock_queue; blr; blr = next) {
		next = blr->next;
		if(blr->req->mid == mid) {
			return True;
		}
	}
	return False;
}

/****************************************************************************
  Set a flag as an unlock request affects one of our pending locks.
*****************************************************************************/

static void received_unlock_msg(struct messaging_context *msg,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data)
{
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	DEBUG(10,("received_unlock_msg\n"));
	process_blocking_lock_queue(sconn);
}

/****************************************************************************
 Process the blocking lock queue. Note that this is only called as root.
*****************************************************************************/

void process_blocking_lock_queue(struct smbd_server_connection *sconn)
{
	struct blocking_lock_record *blr, *next = NULL;

	if (sconn->using_smb2) {
		process_blocking_lock_queue_smb2(sconn, timeval_current());
		return;
	}

	/*
	 * Go through the queue and see if we can get any of the locks.
	 */

	for (blr = sconn->smb1.locks.blocking_lock_queue; blr; blr = next) {
		struct byte_range_lock *br_lck = NULL;

		next = blr->next;

		/*
		 * Go through the remaining locks and try and obtain them.
		 * The call returns True if all locks were obtained successfully
		 * and False if we still need to wait.
		 */

		DEBUG(10, ("Processing BLR = %p\n", blr));

		/*
		 * Connections with pending locks are not marked as idle.
		 */
		blr->fsp->conn->lastused_count++;

		/*
		 * Remove the pending lock we're waiting on.
		 * If we need to keep waiting blocking_lock_record_process()
		 * will re-add it.
		 */

		br_lck = brl_get_locks(talloc_tos(), blr->fsp);
		if (br_lck) {
			brl_lock_cancel(br_lck,
				blr->smblctx,
				messaging_server_id(sconn->msg_ctx),
				blr->offset,
				blr->count,
				blr->lock_flav);
		}
		TALLOC_FREE(br_lck);

		if(!blocking_lock_record_process(blr)) {
			DEBUG(10, ("still waiting for lock. BLR = %p\n", blr));
			continue;
		}

		DEBUG(10, ("BLR_process returned true: removing BLR = %p\n",
			blr));

		DLIST_REMOVE(sconn->smb1.locks.blocking_lock_queue, blr);
		TALLOC_FREE(blr);
	}

	recalc_brl_timeout(sconn);
}

/****************************************************************************
 Handle a cancel message. Lock already moved onto the cancel queue.
*****************************************************************************/

#define MSG_BLOCKING_LOCK_CANCEL_SIZE (sizeof(struct blocking_lock_record *) + sizeof(NTSTATUS))

static void process_blocking_lock_cancel_message(struct messaging_context *ctx,
						 void *private_data,
						 uint32_t msg_type,
						 struct server_id server_id,
						 DATA_BLOB *data)
{
	NTSTATUS err;
	const char *msg = (const char *)data->data;
	struct blocking_lock_record *blr;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	if (data->data == NULL) {
		smb_panic("process_blocking_lock_cancel_message: null msg");
	}

	if (data->length != MSG_BLOCKING_LOCK_CANCEL_SIZE) {
		DEBUG(0, ("process_blocking_lock_cancel_message: "
			  "Got invalid msg len %d\n", (int)data->length));
		smb_panic("process_blocking_lock_cancel_message: bad msg");
        }

	memcpy(&blr, msg, sizeof(blr));
	memcpy(&err, &msg[sizeof(blr)], sizeof(NTSTATUS));

	DEBUG(10,("process_blocking_lock_cancel_message: returning error %s\n",
		nt_errstr(err) ));

	blocking_lock_reply_error(blr, err);
	DLIST_REMOVE(sconn->smb1.locks.blocking_lock_cancelled_queue, blr);
	TALLOC_FREE(blr);
}

/****************************************************************************
 Send ourselves a blocking lock cancelled message. Handled asynchronously above.
 Returns the blocking_lock_record that is being cancelled.
 Only called from the SMB1 code.
*****************************************************************************/

struct blocking_lock_record *blocking_lock_cancel_smb1(files_struct *fsp,
			uint64_t smblctx,
			uint64_t offset,
			uint64_t count,
			enum brl_flavour lock_flav,
			unsigned char locktype,
                        NTSTATUS err)
{
	struct smbd_server_connection *sconn = fsp->conn->sconn;
	char msg[MSG_BLOCKING_LOCK_CANCEL_SIZE];
	struct blocking_lock_record *blr;

	if (!sconn->smb1.locks.blocking_lock_cancel_state) {
		/* Register our message. */
		messaging_register(sconn->msg_ctx, sconn,
				   MSG_SMB_BLOCKING_LOCK_CANCEL,
				   process_blocking_lock_cancel_message);

		sconn->smb1.locks.blocking_lock_cancel_state = True;
	}

	for (blr = sconn->smb1.locks.blocking_lock_queue; blr; blr = blr->next) {
		if (fsp == blr->fsp &&
				smblctx == blr->smblctx &&
				offset == blr->offset &&
				count == blr->count &&
				lock_flav == blr->lock_flav) {
			break;
		}
	}

	if (!blr) {
		return NULL;
	}

	/* Check the flags are right. */
	if (blr->req->cmd == SMBlockingX &&
		(locktype & LOCKING_ANDX_LARGE_FILES) !=
			(CVAL(blr->req->vwv+3, 0) & LOCKING_ANDX_LARGE_FILES)) {
		return NULL;
	}

	/* Move to cancelled queue. */
	DLIST_REMOVE(sconn->smb1.locks.blocking_lock_queue, blr);
	DLIST_ADD(sconn->smb1.locks.blocking_lock_cancelled_queue, blr);

	/* Create the message. */
	memcpy(msg, &blr, sizeof(blr));
	memcpy(&msg[sizeof(blr)], &err, sizeof(NTSTATUS));

	messaging_send_buf(sconn->msg_ctx, messaging_server_id(sconn->msg_ctx),
			   MSG_SMB_BLOCKING_LOCK_CANCEL,
			   (uint8_t *)&msg, sizeof(msg));

	return blr;
}

NTSTATUS smbd_do_locks_try(
	struct messaging_context *msg_ctx,
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
		struct byte_range_lock *br_lck;

		br_lck = do_lock(
			msg_ctx,
			fsp,
			e->smblctx,
			e->count,
			e->offset,
			e->brltype,
			lock_flav,
			false,	/* blocking_lock */
			&status,
			blocking_pid,
			blocking_smblctx);
		if (br_lck == NULL) {
			return status;
		}
		TALLOC_FREE(br_lck);

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
		do_unlock(msg_ctx,
			  fsp,
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
	struct messaging_context *msg_ctx;
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
	struct messaging_context *msg_ctx,
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
	state->msg_ctx = msg_ctx;
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
		state->msg_ctx,
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
		retry_state->msg_ctx,
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
