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
				WRITE_LOCK);
				
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

	if (lck->lockx.in.mode & LOCKING_ANDX_SHARED_LOCK) {
		rw = READ_LOCK;
	} else {
		rw = WRITE_LOCK;
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

		status = brl_lock(pvfs->brl_context,
				  &f->locking_key,
				  locks[i].pid,
				  f->fnum,
				  locks[i].offset,
				  locks[i].count,
				  rw);
		if (!NT_STATUS_IS_OK(status)) {
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

