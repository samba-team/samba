/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - locking

   Copyright (C) Andrew Tridgell 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "include/includes.h"
#include "vfs_posix.h"


/*
  check if we can perform IO on a range that might be locked
*/
NTSTATUS pvfs_check_lock(struct pvfs_state *pvfs,
			 struct pvfs_file *f,
			 uint16_t smbpid,
			 uint64_t offset, uint64_t count,
			 enum brl_type rw)
{
	if (!(pvfs->flags & PVFS_FLAG_STRICT_LOCKING)) {
		return NT_STATUS_OK;
	}

	return brl_locktest(pvfs->brl_context,
			    &f->locking_key,
			    f->fnum,
			    smbpid,
			    offset, count, rw);
}

/* this state structure holds information about a lock we are waiting on */
struct pvfs_pending_lock {
	struct pvfs_pending_lock *next, *prev;
	struct pvfs_state *pvfs;
	union smb_lock *lck;
	struct pvfs_file *f;
	struct smbsrv_request *req;
	int pending_lock;
	void *wait_handle;
	time_t end_time;
};

/*
  a secondary attempt to setup a lock has failed - back out
  the locks we did get and send an error
*/
static void pvfs_lock_async_failed(struct pvfs_state *pvfs,
				   struct smbsrv_request *req,
				   struct pvfs_file *f,
				   struct smb_lock_entry *locks,
				   int i,
				   NTSTATUS status)
{
	/* undo the locks we just did */
	for (i=i-1;i>=0;i--) {
		brl_unlock(pvfs->brl_context,
			   &f->locking_key,
			   locks[i].pid,
			   f->fnum,
			   locks[i].offset,
			   locks[i].count);
	}
	req->async.status = status;
	req->async.send_fn(req);
}


/*
  called when we receive a pending lock notification. It means that
  either our lock timed out or somoene else has unlocked a overlapping
  range, so we should try the lock again. Note that on timeout we
  do retry the lock, giving it a last chance.
*/
static void pvfs_pending_lock_continue(void *private, BOOL timed_out)
{
	struct pvfs_pending_lock *pending = private;
	struct pvfs_state *pvfs = pending->pvfs;
	struct pvfs_file *f = pending->f;
	struct smbsrv_request *req = pending->req;
	union smb_lock *lck = pending->lck;
	struct smb_lock_entry *locks;
	enum brl_type rw;
	NTSTATUS status;
	int i;

	locks = lck->lockx.in.locks + lck->lockx.in.ulock_cnt;

	if (lck->lockx.in.mode & LOCKING_ANDX_SHARED_LOCK) {
		rw = READ_LOCK;
	} else {
		rw = WRITE_LOCK;
	}

	DLIST_REMOVE(f->pending_list, pending);

	status = brl_lock(pvfs->brl_context,
			  &f->locking_key,
			  req->smbpid,
			  f->fnum,
			  locks[pending->pending_lock].offset,
			  locks[pending->pending_lock].count,
			  rw, NULL);

	/* if we have failed and timed out, or succeeded, then we
	   don't need the pending lock any more */
	if (NT_STATUS_IS_OK(status) || timed_out) {
		NTSTATUS status2;
		status2 = brl_remove_pending(pvfs->brl_context, &f->locking_key, pending);
		if (!NT_STATUS_IS_OK(status2)) {
			DEBUG(0,("pvfs_lock: failed to remove pending lock - %s\n", nt_errstr(status2)));
		}
		talloc_free(pending->wait_handle);
	}

	if (!NT_STATUS_IS_OK(status)) {
		if (timed_out) {
			/* no more chances */
			pvfs_lock_async_failed(pvfs, req, f, locks, pending->pending_lock, status);
		} else {
			/* we can try again */
			DLIST_ADD(f->pending_list, pending);
		}
		return;
	}

	/* if we haven't timed out yet, then we can do more pending locks */
	if (timed_out) {
		pending = NULL;
	} else {
		if (rw == READ_LOCK) {
			rw = PENDING_READ_LOCK;
		} else {
			rw = PENDING_WRITE_LOCK;
		}
	}

	/* we've now got the pending lock. try and get the rest, which might
	   lead to more pending locks */
	for (i=pending->pending_lock;i<lck->lockx.in.lock_cnt;i++) {		
		if (pending) {
			pending->pending_lock = i;
		}

		status = brl_lock(pvfs->brl_context,
				  &f->locking_key,
				  req->smbpid,
				  f->fnum,
				  locks[i].offset,
				  locks[i].count,
				  rw, pending);
		if (!NT_STATUS_IS_OK(status)) {
			if (pending) {
				/* a timed lock failed - setup a wait message to handle
				   the pending lock notification or a timeout */
				pending->wait_handle = pvfs_wait_message(pvfs, req, MSG_BRL_RETRY, 
									 pending->end_time,
									 pvfs_pending_lock_continue,
									 pending);
				if (pending->wait_handle == NULL) {
					pvfs_lock_async_failed(pvfs, req, f, locks, i, NT_STATUS_NO_MEMORY);
				} else {
					DLIST_ADD(f->pending_list, pending);
				}
				return;
			}
			pvfs_lock_async_failed(pvfs, req, f, locks, i, status);
			return;
		}
	}

	brl_unlock(pvfs->brl_context,
		   &f->locking_key,
		   req->smbpid,
		   f->fnum,
		   lck->lock.in.offset,
		   lck->lock.in.count);

	/* we've managed to get all the locks. Tell the client */
	req->async.status = NT_STATUS_OK;
	req->async.send_fn(req);
}


/*
  cancel a set of locks
*/
static NTSTATUS pvfs_lock_cancel(struct pvfs_state *pvfs, struct smbsrv_request *req, union smb_lock *lck,
				 struct pvfs_file *f)
{
	struct pvfs_pending_lock *p;

	for (p=f->pending_list;p;p=p->next) {
		/* check if the lock request matches exactly - you can only cancel with exact matches */
		if (p->lck->lockx.in.ulock_cnt == lck->lockx.in.ulock_cnt &&
		    p->lck->lockx.in.lock_cnt  == lck->lockx.in.lock_cnt &&
		    p->lck->lockx.in.fnum      == lck->lockx.in.fnum &&
		    p->lck->lockx.in.mode      == (lck->lockx.in.mode & ~LOCKING_ANDX_CANCEL_LOCK)) {
			int i;

			for (i=0;i<lck->lockx.in.ulock_cnt + lck->lockx.in.lock_cnt;i++) {
				if (p->lck->lockx.in.locks[i].pid != lck->lockx.in.locks[i].pid ||
				    p->lck->lockx.in.locks[i].offset != lck->lockx.in.locks[i].offset ||
				    p->lck->lockx.in.locks[i].count != lck->lockx.in.locks[i].count) {
					break;
				}
			}
			if (i < lck->lockx.in.ulock_cnt) continue;

			/* an exact match! we can cancel it, which is equivalent
			   to triggering the timeout early */
			pvfs_pending_lock_continue(p ,True);
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_UNSUCCESSFUL;
}


/*
  lock or unlock a byte range
*/
NTSTATUS pvfs_lock(struct ntvfs_module_context *ntvfs,
		   struct smbsrv_request *req, union smb_lock *lck)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f;
	struct smb_lock_entry *locks;
	int i;
	enum brl_type rw;
	struct pvfs_pending_lock *pending = NULL;

	f = pvfs_find_fd(pvfs, req, lck->generic.in.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (lck->generic.level) {
	case RAW_LOCK_LOCK:
		return brl_lock(pvfs->brl_context,
				&f->locking_key,
				req->smbpid,
				f->fnum,
				lck->lock.in.offset,
				lck->lock.in.count,
				WRITE_LOCK, NULL);
				
	case RAW_LOCK_UNLOCK:
		return brl_unlock(pvfs->brl_context,
				  &f->locking_key,
				  req->smbpid,
				  f->fnum,
				  lck->lock.in.offset,
				  lck->lock.in.count);

	case RAW_LOCK_GENERIC:
		return NT_STATUS_INVALID_LEVEL;

	case RAW_LOCK_LOCKX:
		/* fall through to the most complex case */
		break;
	}

	/* now the lockingX case, most common and also most complex */
	if (lck->lockx.in.timeout != 0) {
		pending = talloc_p(req, struct pvfs_pending_lock);
		if (pending == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		pending->pvfs = pvfs;
		pending->lck = lck;
		pending->f = f;
		pending->req = req;

		/* round up to the nearest second */
		pending->end_time = time(NULL) + ((lck->lockx.in.timeout+999)/1000);
	}

	if (lck->lockx.in.mode & LOCKING_ANDX_SHARED_LOCK) {
		rw = pending? PENDING_READ_LOCK : READ_LOCK;
	} else {
		rw = pending? PENDING_WRITE_LOCK : WRITE_LOCK;
	}

	if (lck->lockx.in.mode & LOCKING_ANDX_CANCEL_LOCK) {
		return pvfs_lock_cancel(pvfs, req, lck, f);
	}

	if (lck->lockx.in.mode & 
	    (LOCKING_ANDX_OPLOCK_RELEASE |
	     LOCKING_ANDX_CHANGE_LOCKTYPE |
	     LOCKING_ANDX_CANCEL_LOCK)) {
		/* todo: need to add support for these */
		return NT_STATUS_NOT_IMPLEMENTED;
	}


	/* the unlocks happen first */
	locks = lck->lockx.in.locks;

	for (i=0;i<lck->lockx.in.ulock_cnt;i++) {
		NTSTATUS status;
		status = brl_unlock(pvfs->brl_context,
				    &f->locking_key,
				    locks[i].pid,
				    f->fnum,
				    locks[i].offset,
				    locks[i].count);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	locks += i;

	for (i=0;i<lck->lockx.in.lock_cnt;i++) {
		NTSTATUS status;

		if (pending) {
			pending->pending_lock = i;
		}

		status = brl_lock(pvfs->brl_context,
				  &f->locking_key,
				  locks[i].pid,
				  f->fnum,
				  locks[i].offset,
				  locks[i].count,
				  rw, pending);
		if (!NT_STATUS_IS_OK(status)) {
			if (pending) {
				/* a timed lock failed - setup a wait message to handle
				   the pending lock notification or a timeout */
				pending->wait_handle = pvfs_wait_message(pvfs, req, MSG_BRL_RETRY, 
									 pending->end_time,
									 pvfs_pending_lock_continue,
									 pending);
				if (pending->wait_handle == NULL) {
					return NT_STATUS_NO_MEMORY;
				}
				DLIST_ADD(f->pending_list, pending);
				return NT_STATUS_OK;
			}
			/* undo the locks we just did */
			for (i=i-1;i>=0;i--) {
				brl_unlock(pvfs->brl_context,
					   &f->locking_key,
					   locks[i].pid,
					   f->fnum,
					   locks[i].offset,
					   locks[i].count);
			}
			return status;
		}
	}

	return NT_STATUS_OK;
}

