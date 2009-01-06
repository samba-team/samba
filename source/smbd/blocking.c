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
#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/****************************************************************************
 This is the structure to queue to implement blocking locks.
 notify. It consists of the requesting SMB and the expiry time.
*****************************************************************************/

typedef struct _blocking_lock_record {
	struct _blocking_lock_record *next;
	struct _blocking_lock_record *prev;
	int com_type;
	files_struct *fsp;
	struct timeval expire_time;
	int lock_num;
	SMB_BIG_UINT offset;
	SMB_BIG_UINT count;
	uint32 lock_pid;
	uint32 blocking_pid; /* PID that blocks us. */
	enum brl_flavour lock_flav;
	enum brl_type lock_type;
	char *inbuf;
	int length;
	bool encrypted;
} blocking_lock_record;

/* dlink list we store pending lock records on. */
static blocking_lock_record *blocking_lock_queue;

/* dlink list we move cancelled lock records onto. */
static blocking_lock_record *blocking_lock_cancelled_queue;

/* The event that makes us process our blocking lock queue */
static struct timed_event *brl_timeout;

/****************************************************************************
 Destructor for the above structure.
****************************************************************************/

static void free_blocking_lock_record(blocking_lock_record *blr)
{
	SAFE_FREE(blr->inbuf);
	SAFE_FREE(blr);
}

/****************************************************************************
 Determine if this is a secondary element of a chained SMB.
  **************************************************************************/

static bool in_chained_smb(void)
{
	return (chain_size != 0);
}

static void received_unlock_msg(struct messaging_context *msg,
				void *private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB *data);
static void process_blocking_lock_queue(void);

static void brl_timeout_fn(struct event_context *event_ctx,
			   struct timed_event *te,
			   struct timeval now,
			   void *private_data)
{
	SMB_ASSERT(brl_timeout == te);
	TALLOC_FREE(brl_timeout);

	change_to_root_user();	/* TODO: Possibly run all timed events as
				 * root */

	process_blocking_lock_queue();
}

/****************************************************************************
 After a change to blocking_lock_queue, recalculate the timed_event for the
 next processing.
****************************************************************************/

static bool recalc_brl_timeout(void)
{
	blocking_lock_record *brl;
	struct timeval next_timeout;

	TALLOC_FREE(brl_timeout);

	next_timeout = timeval_zero();	

	for (brl = blocking_lock_queue; brl; brl = brl->next) {
		if (timeval_is_zero(&brl->expire_time)) {
			/*
			 * If we're blocked on pid 0xFFFFFFFF this is
			 * a POSIX lock, so calculate a timeout of
			 * 10 seconds into the future.
			 */
                        if (brl->blocking_pid == 0xFFFFFFFF) {
				struct timeval psx_to = timeval_current_ofs(10, 0);
				next_timeout = timeval_min(&next_timeout, &psx_to);
                        }

			continue;
		}

		if (timeval_is_zero(&next_timeout)) {
			next_timeout = brl->expire_time;
		}
		else {
			next_timeout = timeval_min(&next_timeout,
						   &brl->expire_time);
		}
	}

	if (timeval_is_zero(&next_timeout)) {
		return True;
	}

	if (!(brl_timeout = event_add_timed(smbd_event_context(), NULL,
					    next_timeout,
					    brl_timeout_fn, NULL))) {
		return False;
	}

	return True;
}


/****************************************************************************
 Function to push a blocking lock request onto the lock queue.
****************************************************************************/

bool push_blocking_lock_request( struct byte_range_lock *br_lck,
		const struct smb_request *req,
		files_struct *fsp,
		int lock_timeout,
		int lock_num,
		uint32 lock_pid,
		enum brl_type lock_type,
		enum brl_flavour lock_flav,
		SMB_BIG_UINT offset,
		SMB_BIG_UINT count,
		uint32 blocking_pid)
{
	static bool set_lock_msg;
	size_t length = smb_len(req->inbuf)+4;
	blocking_lock_record *blr;
	NTSTATUS status;

	if(in_chained_smb() ) {
		DEBUG(0,("push_blocking_lock_request: cannot queue a chained request (currently).\n"));
		return False;
	}

	/*
	 * Now queue an entry on the blocking lock queue. We setup
	 * the expiration time here.
	 */

	if((blr = SMB_MALLOC_P(blocking_lock_record)) == NULL) {
		DEBUG(0,("push_blocking_lock_request: Malloc fail !\n" ));
		return False;
	}

	blr->next = NULL;
	blr->prev = NULL;

	if((blr->inbuf = (char *)SMB_MALLOC(length)) == NULL) {
		DEBUG(0,("push_blocking_lock_request: Malloc fail (2)!\n" ));
		SAFE_FREE(blr);
		return False;
	}

	blr->com_type = CVAL(req->inbuf,smb_com);
	blr->fsp = fsp;
	if (lock_timeout == -1) {
		blr->expire_time.tv_sec = 0;
		blr->expire_time.tv_usec = 0; /* Never expire. */
	} else {
		blr->expire_time = timeval_current_ofs(lock_timeout/1000,
					(lock_timeout % 1000) * 1000);
	}
	blr->lock_num = lock_num;
	blr->lock_pid = lock_pid;
	blr->blocking_pid = blocking_pid;
	blr->lock_flav = lock_flav;
	blr->lock_type = lock_type;
	blr->offset = offset;
	blr->count = count;
	memcpy(blr->inbuf, req->inbuf, length);
	blr->length = length;
	blr->encrypted = req->encrypted;

	/* Add a pending lock record for this. */
	status = brl_lock(smbd_messaging_context(), br_lck,
			lock_pid,
			procid_self(),
			offset,
			count,
			lock_type == READ_LOCK ? PENDING_READ_LOCK : PENDING_WRITE_LOCK,
			blr->lock_flav,
			lock_timeout ? True : False, /* blocking_lock. */
			NULL);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("push_blocking_lock_request: failed to add PENDING_LOCK record.\n"));
		DLIST_REMOVE(blocking_lock_queue, blr);
		free_blocking_lock_record(blr);
		return False;
	}

	DLIST_ADD_END(blocking_lock_queue, blr, blocking_lock_record *);
	recalc_brl_timeout();

	/* Ensure we'll receive messages when this is unlocked. */
	if (!set_lock_msg) {
		messaging_register(smbd_messaging_context(), NULL,
				   MSG_SMB_UNLOCK, received_unlock_msg);
		set_lock_msg = True;
	}

	DEBUG(3,("push_blocking_lock_request: lock request length=%u blocked with "
		"expiry time (%u sec. %u usec) (+%d msec) for fnum = %d, name = %s\n",
		(unsigned int)length, (unsigned int)blr->expire_time.tv_sec,
		(unsigned int)blr->expire_time.tv_usec, lock_timeout,
		blr->fsp->fnum, blr->fsp->fsp_name ));

	/* Push the MID of this packet on the signing queue. */
	srv_defer_sign_response(SVAL(req->inbuf,smb_mid));

	return True;
}

/****************************************************************************
 Return a lockingX success SMB.
*****************************************************************************/

static void reply_lockingX_success(blocking_lock_record *blr)
{
	struct smb_request *req;

	if (!(req = talloc(talloc_tos(), struct smb_request))) {
		smb_panic("Could not allocate smb_request");
	}

	init_smb_request(req, (uint8 *)blr->inbuf, 0, blr->encrypted);
	reply_outbuf(req, 2, 0);

	/*
	 * As this message is a lockingX call we must handle
	 * any following chained message correctly.
	 * This is normally handled in construct_reply(),
	 * but as that calls switch_message, we can't use
	 * that here and must set up the chain info manually.
	 */

	chain_reply(req);

	if (!srv_send_smb(smbd_server_fd(),
			(char *)req->outbuf,
			IS_CONN_ENCRYPTED(blr->fsp->conn))) {
		exit_server_cleanly("send_blocking_reply: srv_send_smb failed.");
	}
}

/****************************************************************************
 Return a generic lock fail error blocking call.
*****************************************************************************/

static void generic_blocking_lock_error(blocking_lock_record *blr, NTSTATUS status)
{
	char outbuf[smb_size];
	char *inbuf = blr->inbuf;

	construct_reply_common(inbuf, outbuf);

	/* whenever a timeout is given w2k maps LOCK_NOT_GRANTED to
	   FILE_LOCK_CONFLICT! (tridge) */
	if (NT_STATUS_EQUAL(status, NT_STATUS_LOCK_NOT_GRANTED)) {
		status = NT_STATUS_FILE_LOCK_CONFLICT;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_LOCK_CONFLICT)) {
		/* Store the last lock error. */
		files_struct *fsp = blr->fsp;

		if (fsp) {
			fsp->last_lock_failure.context.smbpid = blr->lock_pid;
			fsp->last_lock_failure.context.tid = fsp->conn->cnum;
			fsp->last_lock_failure.context.pid = procid_self();
			fsp->last_lock_failure.start = blr->offset;
			fsp->last_lock_failure.size = blr->count;
			fsp->last_lock_failure.fnum = fsp->fnum;
			fsp->last_lock_failure.lock_type = READ_LOCK; /* Don't care. */
			fsp->last_lock_failure.lock_flav = blr->lock_flav;
		}
	}

	ERROR_NT(status);
	if (!srv_send_smb(smbd_server_fd(),outbuf, blr->encrypted)) {
		exit_server_cleanly("generic_blocking_lock_error: srv_send_smb failed.");
	}
}

/****************************************************************************
 Return a lock fail error for a lockingX call. Undo all the locks we have 
 obtained first.
*****************************************************************************/

static void reply_lockingX_error(blocking_lock_record *blr, NTSTATUS status)
{
	char *inbuf = blr->inbuf;
	files_struct *fsp = blr->fsp;
	uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
	SMB_BIG_UINT count = (SMB_BIG_UINT)0, offset = (SMB_BIG_UINT) 0;
	uint32 lock_pid;
	unsigned char locktype = CVAL(inbuf,smb_vwv3);
	bool large_file_format = (locktype & LOCKING_ANDX_LARGE_FILES);
	char *data;
	int i;

	data = smb_buf(inbuf) + ((large_file_format ? 20 : 10)*num_ulocks);
	
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
		bool err;
		
		lock_pid = get_lock_pid( data, i, large_file_format);
		count = get_lock_count( data, i, large_file_format);
		offset = get_lock_offset( data, i, large_file_format, &err);
		
		/*
		 * We know err cannot be set as if it was the lock
		 * request would never have been queued. JRA.
		 */
		
		do_unlock(smbd_messaging_context(),
			fsp,
			lock_pid,
			count,
			offset,
			WINDOWS_LOCK);
	}
	
	generic_blocking_lock_error(blr, status);
}

/****************************************************************************
 Return a lock fail error.
*****************************************************************************/

static void blocking_lock_reply_error(blocking_lock_record *blr, NTSTATUS status)
{
	switch(blr->com_type) {
	case SMBlockingX:
		reply_lockingX_error(blr, status);
		break;
	case SMBtrans2:
	case SMBtranss2:
		{
			char outbuf[smb_size];
			char *inbuf = blr->inbuf;
			construct_reply_common(inbuf, outbuf);
			/* construct_reply_common has done us the favor to pre-fill the
			 * command field with SMBtranss2 which is wrong :-)
			 */
			SCVAL(outbuf,smb_com,SMBtrans2);
			ERROR_NT(status);
			if (!srv_send_smb(smbd_server_fd(),
					outbuf,
					IS_CONN_ENCRYPTED(blr->fsp->conn))) {
				exit_server_cleanly("blocking_lock_reply_error: srv_send_smb failed.");
			}
			break;
		}
	default:
		DEBUG(0,("blocking_lock_reply_error: PANIC - unknown type on blocking lock queue - exiting.!\n"));
		exit_server("PANIC - unknown type on blocking lock queue");
	}
}

/****************************************************************************
 Attempt to finish off getting all pending blocking locks for a lockingX call.
 Returns True if we want to be removed from the list.
*****************************************************************************/

static bool process_lockingX(blocking_lock_record *blr)
{
	char *inbuf = blr->inbuf;
	unsigned char locktype = CVAL(inbuf,smb_vwv3);
	files_struct *fsp = blr->fsp;
	uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
	uint16 num_locks = SVAL(inbuf,smb_vwv7);
	SMB_BIG_UINT count = (SMB_BIG_UINT)0, offset = (SMB_BIG_UINT)0;
	uint32 lock_pid;
	bool large_file_format = (locktype & LOCKING_ANDX_LARGE_FILES);
	char *data;
	NTSTATUS status = NT_STATUS_OK;

	data = smb_buf(inbuf) + ((large_file_format ? 20 : 10)*num_ulocks);

	/* 
	 * Data now points at the beginning of the list
	 * of smb_lkrng structs.
	 */

	for(; blr->lock_num < num_locks; blr->lock_num++) {
		struct byte_range_lock *br_lck = NULL;
		bool err;

		lock_pid = get_lock_pid( data, blr->lock_num, large_file_format);
		count = get_lock_count( data, blr->lock_num, large_file_format);
		offset = get_lock_offset( data, blr->lock_num, large_file_format, &err);
		
		/*
		 * We know err cannot be set as if it was the lock
		 * request would never have been queued. JRA.
		 */
		errno = 0;
		br_lck = do_lock(smbd_messaging_context(),
				fsp,
				lock_pid,
				count,
				offset, 
				((locktype & LOCKING_ANDX_SHARED_LOCK) ?
					READ_LOCK : WRITE_LOCK),
				WINDOWS_LOCK,
				True,
				&status,
				&blr->blocking_pid);

		TALLOC_FREE(br_lck);

		if (NT_STATUS_IS_ERR(status)) {
			break;
		}
	}

	if(blr->lock_num == num_locks) {
		/*
		 * Success - we got all the locks.
		 */
		
		DEBUG(3,("process_lockingX file = %s, fnum=%d type=%d num_locks=%d\n",
			 fsp->fsp_name, fsp->fnum, (unsigned int)locktype, num_locks) );

		reply_lockingX_success(blr);
		return True;
	} else if (!NT_STATUS_EQUAL(status,NT_STATUS_LOCK_NOT_GRANTED) &&
			!NT_STATUS_EQUAL(status,NT_STATUS_FILE_LOCK_CONFLICT)) {
			/*
			 * We have other than a "can't get lock"
			 * error. Free any locks we had and return an error.
			 * Return True so we get dequeued.
			 */
		
		blocking_lock_reply_error(blr, status);
		return True;
	}

	/*
	 * Still can't get all the locks - keep waiting.
	 */
	
	DEBUG(10,("process_lockingX: only got %d locks of %d needed for file %s, fnum = %d. \
Waiting....\n", 
		  blr->lock_num, num_locks, fsp->fsp_name, fsp->fnum));
	
	return False;
}

/****************************************************************************
 Attempt to get the posix lock request from a SMBtrans2 call.
 Returns True if we want to be removed from the list.
*****************************************************************************/

static bool process_trans2(blocking_lock_record *blr)
{
	struct smb_request *req;
	char params[2];
	NTSTATUS status;
	struct byte_range_lock *br_lck = do_lock(smbd_messaging_context(),
						blr->fsp,
						blr->lock_pid,
						blr->count,
						blr->offset,
						blr->lock_type,
						blr->lock_flav,
						True,
						&status,
						&blr->blocking_pid);
	TALLOC_FREE(br_lck);

	if (!NT_STATUS_IS_OK(status)) {
		if (ERROR_WAS_LOCK_DENIED(status)) {
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

	if (!(req = talloc(talloc_tos(), struct smb_request))) {
		blocking_lock_reply_error(blr, NT_STATUS_NO_MEMORY);
		return True;
	}

	init_smb_request(req, (uint8 *)blr->inbuf, 0, blr->encrypted);

	SCVAL(req->inbuf, smb_com, SMBtrans2);
	SSVAL(params,0,0);
	/* Fake up max_data_bytes here - we know it fits. */
	send_trans2_replies(blr->fsp->conn, req, params, 2, NULL, 0, 0xffff);
	return True;
}


/****************************************************************************
 Process a blocking lock SMB.
 Returns True if we want to be removed from the list.
*****************************************************************************/

static bool blocking_lock_record_process(blocking_lock_record *blr)
{
	switch(blr->com_type) {
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
*****************************************************************************/

void cancel_pending_lock_requests_by_fid(files_struct *fsp, struct byte_range_lock *br_lck)
{
	blocking_lock_record *blr, *next = NULL;

	for(blr = blocking_lock_queue; blr; blr = next) {
		next = blr->next;
		if(blr->fsp->fnum == fsp->fnum) {
			unsigned char locktype = 0;

			if (blr->com_type == SMBlockingX) {
				locktype = CVAL(blr->inbuf,smb_vwv3);
			}

			if (br_lck) {
				DEBUG(10,("remove_pending_lock_requests_by_fid - removing request type %d for \
file %s fnum = %d\n", blr->com_type, fsp->fsp_name, fsp->fnum ));

				brl_lock_cancel(br_lck,
					blr->lock_pid,
					procid_self(),
					blr->offset,
					blr->count,
					blr->lock_flav);

				blocking_lock_cancel(fsp,
					blr->lock_pid,
					blr->offset,
					blr->count,
					blr->lock_flav,
					locktype,
					NT_STATUS_RANGE_NOT_LOCKED);
			}
			/* We're closing the file fsp here, so ensure
			 * we don't have a dangling pointer. */
			blr->fsp = NULL;
		}
	}
}

/****************************************************************************
 Delete entries by mid from the blocking lock pending queue. Always send reply.
*****************************************************************************/

void remove_pending_lock_requests_by_mid(int mid)
{
	blocking_lock_record *blr, *next = NULL;

	for(blr = blocking_lock_queue; blr; blr = next) {
		next = blr->next;
		if(SVAL(blr->inbuf,smb_mid) == mid) {
			files_struct *fsp = blr->fsp;
			struct byte_range_lock *br_lck = brl_get_locks(talloc_tos(), fsp);

			if (br_lck) {
				DEBUG(10,("remove_pending_lock_requests_by_mid - removing request type %d for \
file %s fnum = %d\n", blr->com_type, fsp->fsp_name, fsp->fnum ));

				brl_lock_cancel(br_lck,
					blr->lock_pid,
					procid_self(),
					blr->offset,
					blr->count,
					blr->lock_flav);
				TALLOC_FREE(br_lck);
			}

			blocking_lock_reply_error(blr,NT_STATUS_FILE_LOCK_CONFLICT);
			DLIST_REMOVE(blocking_lock_queue, blr);
			free_blocking_lock_record(blr);
		}
	}
}

/****************************************************************************
 Is this mid a blocking lock request on the queue ?
*****************************************************************************/

bool blocking_lock_was_deferred(int mid)
{
	blocking_lock_record *blr, *next = NULL;

	for(blr = blocking_lock_queue; blr; blr = next) {
		next = blr->next;
		if(SVAL(blr->inbuf,smb_mid) == mid) {
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
	DEBUG(10,("received_unlock_msg\n"));
	process_blocking_lock_queue();
}

/****************************************************************************
 Process the blocking lock queue. Note that this is only called as root.
*****************************************************************************/

static void process_blocking_lock_queue(void)
{
	struct timeval tv_curr = timeval_current();
	blocking_lock_record *blr, *next = NULL;
	bool recalc_timeout = False;

	/*
	 * Go through the queue and see if we can get any of the locks.
	 */

	for (blr = blocking_lock_queue; blr; blr = next) {
		connection_struct *conn = NULL;
		uint16 vuid;
		files_struct *fsp = NULL;

		next = blr->next;

		/*
		 * Ensure we don't have any old chain_fsp values
		 * sitting around....
		 */
		chain_size = 0;
		file_chain_reset();
		fsp = blr->fsp;

		conn = conn_find(SVAL(blr->inbuf,smb_tid));
		vuid = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID :
				SVAL(blr->inbuf,smb_uid);

		DEBUG(5,("process_blocking_lock_queue: examining pending lock fnum = %d for file %s\n",
			fsp->fnum, fsp->fsp_name ));

		if(!change_to_user(conn,vuid)) {
			struct byte_range_lock *br_lck = brl_get_locks(talloc_tos(), fsp);

			/*
			 * Remove the entry and return an error to the client.
			 */

			if (br_lck) {
				brl_lock_cancel(br_lck,
					blr->lock_pid,
					procid_self(),
					blr->offset,
					blr->count,
					blr->lock_flav);
				TALLOC_FREE(br_lck);
			}

			DEBUG(0,("process_blocking_lock_queue: Unable to become user vuid=%d.\n",
				vuid ));
			blocking_lock_reply_error(blr,NT_STATUS_ACCESS_DENIED);
			DLIST_REMOVE(blocking_lock_queue, blr);
			free_blocking_lock_record(blr);
			recalc_timeout = True;
			continue;
		}

		if(!set_current_service(conn,SVAL(blr->inbuf,smb_flg),True)) {
			struct byte_range_lock *br_lck = brl_get_locks(talloc_tos(), fsp);

			/*
			 * Remove the entry and return an error to the client.
			 */

			if (br_lck) {
				brl_lock_cancel(br_lck,
					blr->lock_pid,
					procid_self(),
					blr->offset,
					blr->count,
					blr->lock_flav);
				TALLOC_FREE(br_lck);
			}

			DEBUG(0,("process_blocking_lock_queue: Unable to become service Error was %s.\n", strerror(errno) ));
			blocking_lock_reply_error(blr,NT_STATUS_ACCESS_DENIED);
			DLIST_REMOVE(blocking_lock_queue, blr);
			free_blocking_lock_record(blr);
			recalc_timeout = True;
			change_to_root_user();
			continue;
		}

		/*
		 * Go through the remaining locks and try and obtain them.
		 * The call returns True if all locks were obtained successfully
		 * and False if we still need to wait.
		 */

		if(blocking_lock_record_process(blr)) {
			struct byte_range_lock *br_lck = brl_get_locks(talloc_tos(), fsp);

			if (br_lck) {
				brl_lock_cancel(br_lck,
					blr->lock_pid,
					procid_self(),
					blr->offset,
					blr->count,
					blr->lock_flav);
				TALLOC_FREE(br_lck);
			}

			DLIST_REMOVE(blocking_lock_queue, blr);
			free_blocking_lock_record(blr);
			recalc_timeout = True;
			change_to_root_user();
			continue;
		}

		change_to_root_user();

		/*
		 * We couldn't get the locks for this record on the list.
		 * If the time has expired, return a lock error.
		 */

		if (!timeval_is_zero(&blr->expire_time) && timeval_compare(&blr->expire_time, &tv_curr) <= 0) {
			struct byte_range_lock *br_lck = brl_get_locks(talloc_tos(), fsp);

			/*
			 * Lock expired - throw away all previously
			 * obtained locks and return lock error.
			 */

			if (br_lck) {
				DEBUG(5,("process_blocking_lock_queue: pending lock fnum = %d for file %s timed out.\n",
					fsp->fnum, fsp->fsp_name ));

				brl_lock_cancel(br_lck,
					blr->lock_pid,
					procid_self(),
					blr->offset,
					blr->count,
					blr->lock_flav);
				TALLOC_FREE(br_lck);
			}

			blocking_lock_reply_error(blr,NT_STATUS_FILE_LOCK_CONFLICT);
			DLIST_REMOVE(blocking_lock_queue, blr);
			free_blocking_lock_record(blr);
			recalc_timeout = True;
		}
	}

	if (recalc_timeout) {
		recalc_brl_timeout();
	}
}

/****************************************************************************
 Handle a cancel message. Lock already moved onto the cancel queue.
*****************************************************************************/

#define MSG_BLOCKING_LOCK_CANCEL_SIZE (sizeof(blocking_lock_record *) + sizeof(NTSTATUS))

static void process_blocking_lock_cancel_message(struct messaging_context *ctx,
						 void *private_data,
						 uint32_t msg_type,
						 struct server_id server_id,
						 DATA_BLOB *data)
{
	NTSTATUS err;
	const char *msg = (const char *)data->data;
	blocking_lock_record *blr;

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
	DLIST_REMOVE(blocking_lock_cancelled_queue, blr);
	free_blocking_lock_record(blr);
}

/****************************************************************************
 Send ourselves a blocking lock cancelled message. Handled asynchronously above.
*****************************************************************************/

bool blocking_lock_cancel(files_struct *fsp,
			uint32 lock_pid,
			SMB_BIG_UINT offset,
			SMB_BIG_UINT count,
			enum brl_flavour lock_flav,
			unsigned char locktype,
                        NTSTATUS err)
{
	static bool initialized;
	char msg[MSG_BLOCKING_LOCK_CANCEL_SIZE];
	blocking_lock_record *blr;

	if (!initialized) {
		/* Register our message. */
		messaging_register(smbd_messaging_context(), NULL,
				   MSG_SMB_BLOCKING_LOCK_CANCEL,
				   process_blocking_lock_cancel_message);

		initialized = True;
	}

	for (blr = blocking_lock_queue; blr; blr = blr->next) {
		if (fsp == blr->fsp &&
				lock_pid == blr->lock_pid &&
				offset == blr->offset &&
				count == blr->count &&
				lock_flav == blr->lock_flav) {
			break;
		}
	}

	if (!blr) {
		return False;
	}

	/* Check the flags are right. */
	if (blr->com_type == SMBlockingX &&
		(locktype & LOCKING_ANDX_LARGE_FILES) !=
			(CVAL(blr->inbuf,smb_vwv3) & LOCKING_ANDX_LARGE_FILES)) {
		return False;
	}

	/* Move to cancelled queue. */
	DLIST_REMOVE(blocking_lock_queue, blr);
	DLIST_ADD(blocking_lock_cancelled_queue, blr);

	/* Create the message. */
	memcpy(msg, &blr, sizeof(blr));
	memcpy(&msg[sizeof(blr)], &err, sizeof(NTSTATUS));

	messaging_send_buf(smbd_messaging_context(), procid_self(),
			   MSG_SMB_BLOCKING_LOCK_CANCEL,
			   (uint8 *)&msg, sizeof(msg));

	return True;
}
