/* 
   Unix SMB/CIFS implementation.

   generic byte range locking code - ctdb backend

   Copyright (C) Andrew Tridgell 2006
   
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

#include "includes.h"
#include "system/filesys.h"
#include "lib/tdb/include/tdb.h"
#include "messaging/messaging.h"
#include "db_wrap.h"
#include "lib/messaging/irpc.h"
#include "libcli/libcli.h"
#include "cluster/cluster.h"
#include "ntvfs/common/brlock.h"
#include "include/ctdb.h"

#define ENABLE_NOTIFIES 0

enum my_functions {FUNC_BRL_LOCK=1, FUNC_BRL_UNLOCK=2, 
		   FUNC_BRL_REMOVE_PENDING=3, FUNC_BRL_LOCKTEST=4,
		   FUNC_BRL_CLOSE=5};

/*
  in this module a "DATA_BLOB *file_key" is a blob that uniquely identifies
  a file. For a local posix filesystem this will usually be a combination
  of the device and inode numbers of the file, but it can be anything 
  that uniquely idetifies a file for locking purposes, as long
  as it is applied consistently.
*/

/* this struct is typically attached to tcon */
struct brl_context {
	struct ctdb_context *ctdb;
	struct server_id server;
	struct messaging_context *messaging_ctx;
};

/*
  the lock context contains the elements that define whether one
  lock is the same as another lock
*/
struct lock_context {
	struct server_id server;
	uint16_t smbpid;
	struct brl_context *ctx;
};

/* The data in brlock records is an unsorted linear array of these
   records.  It is unnecessary to store the count as tdb provides the
   size of the record */
struct lock_struct {
	struct lock_context context;
	struct ntvfs_handle *ntvfs;
	uint64_t start;
	uint64_t size;
	enum brl_type lock_type;
	void *notify_ptr;
};

/* this struct is attached to on open file handle */
struct brl_handle {
	DATA_BLOB key;
	struct ntvfs_handle *ntvfs;
	struct lock_struct last_lock;
};

#if 0
static void show_locks(const char *op, struct lock_struct *locks, int count)
{
	int i;
	DEBUG(0,("OP: %s\n", op));
	if (locks == NULL) return;
	for (i=0;i<count;i++) {
		DEBUG(0,("%2d: %4d %4d %d.%d.%d %p %p\n",
			 i, (int)locks[i].start, (int)locks[i].size, 
			 locks[i].context.server.node,
			 locks[i].context.server.id,
			 locks[i].context.smbpid,
			 locks[i].context.ctx,
			 locks[i].ntvfs));
	}
}
#endif

/*
  Open up the brlock.tdb database. Close it down using
  talloc_free(). We need the messaging_ctx to allow for
  pending lock notifications.
*/
static struct brl_context *brl_ctdb_init(TALLOC_CTX *mem_ctx, struct server_id server, 
				    struct messaging_context *messaging_ctx)
{
	struct ctdb_context *ctdb = talloc_get_type(cluster_private(), struct ctdb_context);
	struct brl_context *brl;

	brl = talloc(mem_ctx, struct brl_context);
	if (brl == NULL) {
		return NULL;
	}

	brl->ctdb = ctdb;
	brl->server = server;
	brl->messaging_ctx = messaging_ctx;

	return brl;
}

static struct brl_handle *brl_ctdb_create_handle(TALLOC_CTX *mem_ctx, struct ntvfs_handle *ntvfs, 
						    DATA_BLOB *file_key)
{
	struct brl_handle *brlh;

	brlh = talloc(mem_ctx, struct brl_handle);
	if (brlh == NULL) {
		return NULL;
	}

	brlh->key = *file_key;
	brlh->ntvfs = ntvfs;
	ZERO_STRUCT(brlh->last_lock);

	return brlh;
}

/*
  see if two locking contexts are equal
*/
static BOOL brl_ctdb_same_context(struct lock_context *ctx1, struct lock_context *ctx2)
{
	return (cluster_id_equal(&ctx1->server, &ctx2->server) &&
		ctx1->smbpid == ctx2->smbpid &&
		ctx1->ctx == ctx2->ctx);
}

/*
  see if lck1 and lck2 overlap
*/
static BOOL brl_ctdb_overlap(struct lock_struct *lck1, 
			struct lock_struct *lck2)
{
	/* this extra check is not redundent - it copes with locks
	   that go beyond the end of 64 bit file space */
	if (lck1->size != 0 &&
	    lck1->start == lck2->start &&
	    lck1->size == lck2->size) {
		return True;
	}
	    
	if (lck1->start >= (lck2->start+lck2->size) ||
	    lck2->start >= (lck1->start+lck1->size)) {
		return False;
	}
	return True;
} 

/*
 See if lock2 can be added when lock1 is in place.
*/
static BOOL brl_ctdb_conflict(struct lock_struct *lck1, 
			 struct lock_struct *lck2)
{
	/* pending locks don't conflict with anything */
	if (lck1->lock_type >= PENDING_READ_LOCK ||
	    lck2->lock_type >= PENDING_READ_LOCK) {
		return False;
	}

	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) {
		return False;
	}

	if (brl_ctdb_same_context(&lck1->context, &lck2->context) &&
	    lck2->lock_type == READ_LOCK && lck1->ntvfs == lck2->ntvfs) {
		return False;
	}

	return brl_ctdb_overlap(lck1, lck2);
} 


/*
 Check to see if this lock conflicts, but ignore our own locks on the
 same fnum only.
*/
static BOOL brl_ctdb_conflict_other(struct lock_struct *lck1, struct lock_struct *lck2)
{
	/* pending locks don't conflict with anything */
	if (lck1->lock_type >= PENDING_READ_LOCK ||
	    lck2->lock_type >= PENDING_READ_LOCK) {
		return False;
	}

	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) 
		return False;

	/*
	 * note that incoming write calls conflict with existing READ
	 * locks even if the context is the same. JRA. See LOCKTEST7
	 * in smbtorture.
	 */
	if (brl_ctdb_same_context(&lck1->context, &lck2->context) &&
	    lck1->ntvfs == lck2->ntvfs &&
	    (lck2->lock_type == READ_LOCK || lck1->lock_type == WRITE_LOCK)) {
		return False;
	}

	return brl_ctdb_overlap(lck1, lck2);
} 


/*
  amazingly enough, w2k3 "remembers" whether the last lock failure
  is the same as this one and changes its error code. I wonder if any
  app depends on this?
*/
static NTSTATUS brl_ctdb_lock_failed(struct brl_handle *brlh, struct lock_struct *lock)
{
	/*
	 * this function is only called for non pending lock!
	 */

	/* 
	 * if the notify_ptr is non NULL,
	 * it means that we're at the end of a pending lock
	 * and the real lock is requested after the timeout went by
	 * In this case we need to remember the last_lock and always
	 * give FILE_LOCK_CONFLICT
	 */
	if (lock->notify_ptr) {
		brlh->last_lock = *lock;
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	/* 
	 * amazing the little things you learn with a test
	 * suite. Locks beyond this offset (as a 64 bit
	 * number!) always generate the conflict error code,
	 * unless the top bit is set
	 */
	if (lock->start >= 0xEF000000 && (lock->start >> 63) == 0) {
		brlh->last_lock = *lock;
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	/*
	 * if the current lock matches the last failed lock on the file handle
	 * and starts at the same offset, then FILE_LOCK_CONFLICT should be returned
	 */
	if (cluster_id_equal(&lock->context.server, &brlh->last_lock.context.server) &&
	    lock->context.ctx == brlh->last_lock.context.ctx &&
	    lock->ntvfs == brlh->last_lock.ntvfs &&
	    lock->start == brlh->last_lock.start) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	brlh->last_lock = *lock;
	return NT_STATUS_LOCK_NOT_GRANTED;
}

struct ctdb_lock_req {
	uint16_t smbpid;
	uint64_t start;
	uint64_t size;
	enum brl_type lock_type;
	void *notify_ptr;
	struct server_id server;
	struct brl_context *brl;
	struct ntvfs_handle *ntvfs;
};

/*
  ctdb call handling brl_lock()
*/
static int brl_ctdb_lock_func(struct ctdb_call_info *call)
{
	struct ctdb_lock_req *req = (struct ctdb_lock_req *)call->call_data->dptr;
	TDB_DATA dbuf;
	int count=0, i;
	struct lock_struct lock, *locks=NULL;
	NTSTATUS status = NT_STATUS_OK;

#if ENABLE_NOTIFIES
	/* if this is a pending lock, then with the chainlock held we
	   try to get the real lock. If we succeed then we don't need
	   to make it pending. This prevents a possible race condition
	   where the pending lock gets created after the lock that is
	   preventing the real lock gets removed */
	if (lock_type >= PENDING_READ_LOCK) {
		enum brl_type rw = (lock_type==PENDING_READ_LOCK? READ_LOCK : WRITE_LOCK);

		/* here we need to force that the last_lock isn't overwritten */
		lock = brlh->last_lock;
		status = brl_ctdb_lock(brl, brlh, smbpid, start, size, rw, NULL);
		brlh->last_lock = lock;

		if (NT_STATUS_IS_OK(status)) {
			tdb_chainunlock(brl->w->tdb, kbuf);
			return NT_STATUS_OK;
		}
	}
#endif

	dbuf = call->record_data;

	ZERO_STRUCT(lock);
	lock.context.smbpid = req->smbpid;
	lock.context.server = req->server;
	lock.context.ctx = req->brl;
	lock.ntvfs = req->ntvfs;
	lock.start = req->start;
	lock.size = req->size;
	lock.lock_type = req->lock_type;
	lock.notify_ptr = req->notify_ptr;

	if (dbuf.dptr) {
		/* there are existing locks - make sure they don't conflict */
		locks = (struct lock_struct *)dbuf.dptr;
		count = dbuf.dsize / sizeof(*locks);

		for (i=0; i<count; i++) {
			if (brl_ctdb_conflict(&locks[i], &lock)) {
				status = NT_STATUS_LOCK_NOT_GRANTED;
				goto reply;
			}
		}
	}

	call->new_data = talloc(call, TDB_DATA);
	if (call->new_data == NULL) {
		return CTDB_ERR_NOMEM;
	}

	call->new_data->dptr = talloc_size(call, dbuf.dsize + sizeof(lock));
	if (call->new_data->dptr == NULL) {
		return CTDB_ERR_NOMEM;
	}
	memcpy(call->new_data->dptr, locks, dbuf.dsize);
	memcpy(call->new_data->dptr+dbuf.dsize, &lock, sizeof(lock));
	call->new_data->dsize = dbuf.dsize + sizeof(lock);

	if (req->lock_type >= PENDING_READ_LOCK) {
		status = NT_STATUS_LOCK_NOT_GRANTED;
	}

reply:
	call->status = NT_STATUS_V(status);

	return 0;
}


/*
  Lock a range of bytes.  The lock_type can be a PENDING_*_LOCK, in
  which case a real lock is first tried, and if that fails then a
  pending lock is created. When the pending lock is triggered (by
  someone else closing an overlapping lock range) a messaging
  notification is sent, identified by the notify_ptr
*/
static NTSTATUS brl_ctdb_lock(struct brl_context *brl,
			      struct brl_handle *brlh,
			      uint16_t smbpid,
			      uint64_t start, uint64_t size, 
			      enum brl_type lock_type,
			      void *notify_ptr)
{
	struct ctdb_lock_req req;
	struct ctdb_call call;
	int ret;

	call.call_id = FUNC_BRL_LOCK;
	call.key.dptr = brlh->key.data;
	call.key.dsize = brlh->key.length;
	call.call_data.dptr = (uint8_t *)&req;
	call.call_data.dsize = sizeof(req);

	ZERO_STRUCT(req);
	req.smbpid = smbpid;
	req.start  = start;
	req.size   = size;
	req.lock_type = lock_type;
	req.notify_ptr = notify_ptr;
	req.server = brl->server;
	req.brl = brl;
	req.ntvfs = brlh->ntvfs;

	ret = ctdb_call(brl->ctdb, &call);
	if (ret == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS(call.status);
}

#if ENABLE_NOTIFIES
/*
  we are removing a lock that might be holding up a pending lock. Scan for pending
  locks that cover this range and if we find any then notify the server that it should
  retry the lock
*/
static void brl_ctdb_notify_unlock(struct brl_context *brl,
			      struct lock_struct *locks, int count, 
			      struct lock_struct *removed_lock)
{
	int i, last_notice;

	/* the last_notice logic is to prevent stampeding on a lock
	   range. It prevents us sending hundreds of notifies on the
	   same range of bytes. It doesn't prevent all possible
	   stampedes, but it does prevent the most common problem */
	last_notice = -1;

	for (i=0;i<count;i++) {
		if (locks[i].lock_type >= PENDING_READ_LOCK &&
		    brl_ctdb_overlap(&locks[i], removed_lock)) {
			if (last_notice != -1 && brl_ctdb_overlap(&locks[i], &locks[last_notice])) {
				continue;
			}
			if (locks[i].lock_type == PENDING_WRITE_LOCK) {
				last_notice = i;
			}
			messaging_send_ptr(brl->messaging_ctx, locks[i].context.server, 
					   MSG_BRL_RETRY, locks[i].notify_ptr);
		}
	}
}
#endif

/*
  send notifications for all pending locks - the file is being closed by this
  user
*/
static void brl_ctdb_notify_all(struct brl_context *brl,
			   struct lock_struct *locks, int count)
{
	int i;
	for (i=0;i<count;i++) {
		if (locks->lock_type >= PENDING_READ_LOCK) {
#if ENABLE_NOTIFIES
			brl_ctdb_notify_unlock(brl, locks, count, &locks[i]);
#endif
		}
	}
}

struct ctdb_unlock_req {
	uint16_t smbpid;
	uint64_t start;
	uint64_t size;
	struct server_id server;
	struct brl_context *brl;
	struct ntvfs_handle *ntvfs;
};

/*
 Unlock a range of bytes.
*/
static int brl_ctdb_unlock_func(struct ctdb_call_info *call)
{
	struct ctdb_unlock_req *req = (struct ctdb_unlock_req *)call->call_data->dptr;
	TDB_DATA dbuf;
	int count, i;
	struct lock_struct *locks, *lock;
	struct lock_context context;
	NTSTATUS status = NT_STATUS_OK;

	dbuf = call->record_data;

	context.smbpid = req->smbpid;
	context.server = req->server;
	context.ctx = req->brl;

	/* there are existing locks - find a match */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	for (i=0; i<count; i++) {
		lock = &locks[i];
		if (brl_ctdb_same_context(&lock->context, &context) &&
		    lock->ntvfs == req->ntvfs &&
		    lock->start == req->start &&
		    lock->size == req->size &&
		    lock->lock_type == WRITE_LOCK) {
			break;
		}
	}
	if (i < count) goto found;

	for (i=0; i<count; i++) {
		lock = &locks[i];
		if (brl_ctdb_same_context(&lock->context, &context) &&
		    lock->ntvfs == req->ntvfs &&
		    lock->start == req->start &&
		    lock->size == req->size &&
		    lock->lock_type < PENDING_READ_LOCK) {
			break;
		}
	}

found:
	if (i < count) {
#if ENABLE_NOTIFIES
		struct lock_struct removed_lock = *lock;
#endif

		call->new_data = talloc(call, TDB_DATA);
		if (call->new_data == NULL) {
			return CTDB_ERR_NOMEM;
		}
		
		call->new_data->dptr = talloc_size(call, dbuf.dsize - sizeof(*lock));
		if (call->new_data->dptr == NULL) {
			return CTDB_ERR_NOMEM;
		}
		call->new_data->dsize = dbuf.dsize - sizeof(*lock);
		
		memcpy(call->new_data->dptr, locks, i*sizeof(*lock));
		memcpy(call->new_data->dptr+i*sizeof(*lock), locks+i+1,
		       (count-(i+1))*sizeof(*lock));
		
		if (count > 1) {
#if ENABLE_NOTIFIES
			brl_ctdb_notify_unlock(req->brl, locks, count, &removed_lock);
#endif
		}
	}

	if (i == count) {
		/* we didn't find it */
		status = NT_STATUS_RANGE_NOT_LOCKED;
	}

	call->status = NT_STATUS_V(status);

	return 0;
}


/*
 Unlock a range of bytes.
*/
static NTSTATUS brl_ctdb_unlock(struct brl_context *brl,
				struct brl_handle *brlh, 
				uint16_t smbpid,
				uint64_t start, uint64_t size)
{
	struct ctdb_call call;
	struct ctdb_unlock_req req;
	int ret;

	call.call_id = FUNC_BRL_UNLOCK;
	call.key.dptr = brlh->key.data;
	call.key.dsize = brlh->key.length;
	call.call_data.dptr = (uint8_t *)&req;
	call.call_data.dsize = sizeof(req);

	ZERO_STRUCT(req);
	req.smbpid = smbpid;
	req.start  = start;
	req.size   = size;
	req.server = brl->server;
	req.brl = brl;
	req.ntvfs = brlh->ntvfs;
		
	ret = ctdb_call(brl->ctdb, &call);
	if (ret == -1) {
		DEBUG(0,("ctdb_call failed - %s\n", __location__));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS(call.status);
}


struct ctdb_remove_pending_req {
	struct server_id server;
	void *notify_ptr;
};

/*
  remove a pending lock. This is called when the caller has either
  given up trying to establish a lock or when they have succeeded in
  getting it. In either case they no longer need to be notified.
*/
static int brl_ctdb_remove_pending_func(struct ctdb_call_info *call)
{
	struct ctdb_remove_pending_req *req = (struct ctdb_remove_pending_req *)call->call_data->dptr;
	TDB_DATA dbuf;
	int count, i;
	struct lock_struct *locks;
	NTSTATUS status = NT_STATUS_OK;

	dbuf = call->record_data;

	/* there are existing locks - find a match */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];
		
		if (lock->lock_type >= PENDING_READ_LOCK &&
		    lock->notify_ptr == req->notify_ptr &&
		    cluster_id_equal(&lock->context.server, &req->server)) {
			call->new_data = talloc(call, TDB_DATA);
			if (call->new_data == NULL) {
				return CTDB_ERR_NOMEM;
			}

			call->new_data->dptr = talloc_size(call, dbuf.dsize - sizeof(*lock));
			if (call->new_data->dptr == NULL) {
				return CTDB_ERR_NOMEM;
			}
			call->new_data->dsize = dbuf.dsize - sizeof(*lock);

			memcpy(call->new_data->dptr, locks, i*sizeof(*lock));
			memcpy(call->new_data->dptr+i*sizeof(*lock), locks+i+1,
			       (count-(i+1))*sizeof(*lock));
			break;
		}
	}
	
	if (i == count) {
		/* we didn't find it */
		status = NT_STATUS_RANGE_NOT_LOCKED;
	}

	call->status = NT_STATUS_V(status);

	return 0;
}

static NTSTATUS brl_ctdb_remove_pending(struct brl_context *brl,
					struct brl_handle *brlh, 
					void *notify_ptr)
{
	struct ctdb_call call;
	struct ctdb_remove_pending_req req;
	int ret;

	call.call_id = FUNC_BRL_REMOVE_PENDING;
	call.key.dptr = brlh->key.data;
	call.key.dsize = brlh->key.length;
	call.call_data.dptr = (uint8_t *)&req;
	call.call_data.dsize = sizeof(req);

	ZERO_STRUCT(req);
	req.notify_ptr = notify_ptr;
	req.server = brl->server;
		
	ret = ctdb_call(brl->ctdb, &call);
	if (ret == -1) {
		DEBUG(0,("ctdb_call failed - %s\n", __location__));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS(call.status);
}


struct ctdb_locktest_req {
	uint16_t smbpid;
	uint64_t start;
	uint64_t size;
	enum brl_type lock_type;
	struct brl_context *brl;
	struct server_id server;
	struct ntvfs_handle *ntvfs;
};

/*
  remove a pending lock. This is called when the caller has either
  given up trying to establish a lock or when they have succeeded in
  getting it. In either case they no longer need to be notified.
*/
static int brl_ctdb_locktest_func(struct ctdb_call_info *call)
{
	struct ctdb_locktest_req *req = (struct ctdb_locktest_req *)call->call_data->dptr;
	TDB_DATA dbuf;
	int count, i;
	struct lock_struct *locks, lock;
	NTSTATUS status = NT_STATUS_OK;

	lock.context.smbpid = req->smbpid;
	lock.context.server = req->server;
	lock.context.ctx = req->brl;
	lock.ntvfs = req->ntvfs;
	lock.start = req->start;
	lock.size = req->size;
	lock.lock_type = req->lock_type;

	dbuf = call->record_data;

	/* there are existing locks - find a match */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	for (i=0; i<count; i++) {
		if (brl_ctdb_conflict_other(&locks[i], &lock)) {
			status = NT_STATUS_FILE_LOCK_CONFLICT;
			break;
		}
	}
	
	call->status = NT_STATUS_V(status);

	return 0;
}

/*
  Test if we are allowed to perform IO on a region of an open file
*/
static NTSTATUS brl_ctdb_locktest(struct brl_context *brl,
				  struct brl_handle *brlh,
				  uint16_t smbpid, 
				  uint64_t start, uint64_t size, 
				  enum brl_type lock_type)
{
	struct ctdb_call call;
	struct ctdb_locktest_req req;
	int ret;

	call.call_id = FUNC_BRL_LOCKTEST;
	call.key.dptr = brlh->key.data;
	call.key.dsize = brlh->key.length;
	call.call_data.dptr = (uint8_t *)&req;
	call.call_data.dsize = sizeof(req);

	ZERO_STRUCT(req);
	req.smbpid = smbpid;
	req.start  = start;
	req.size   = size;
	req.lock_type = lock_type;
	req.server = brl->server;
	req.brl = brl;
	req.ntvfs = brlh->ntvfs;

	ret = ctdb_call(brl->ctdb, &call);
	if (ret == -1) {
		DEBUG(0,("ctdb_call failed - %s\n", __location__));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS(call.status);
}


struct ctdb_close_req {
	struct brl_context *brl;
	struct server_id server;
	struct ntvfs_handle *ntvfs;
};

/*
  remove a pending lock. This is called when the caller has either
  given up trying to establish a lock or when they have succeeded in
  getting it. In either case they no longer need to be notified.
*/
static int brl_ctdb_close_func(struct ctdb_call_info *call)
{
	struct ctdb_close_req *req = (struct ctdb_close_req *)call->call_data->dptr;
	TDB_DATA dbuf;
	int count, dcount=0, i;
	struct lock_struct *locks;
	NTSTATUS status = NT_STATUS_OK;

	dbuf = call->record_data;

	/* there are existing locks - find a match */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];

		if (lock->context.ctx == req->brl &&
		    cluster_id_equal(&lock->context.server, &req->server) &&
		    lock->ntvfs == req->ntvfs) {
			/* found it - delete it */
			if (count > 1 && i < count-1) {
				memmove(&locks[i], &locks[i+1], 
					sizeof(*locks)*((count-1) - i));
			}
			count--;
			i--;
			dcount++;
		}
	}

	if (dcount > 0) {
		call->new_data = talloc(call, TDB_DATA);
		if (call->new_data == NULL) {
			return CTDB_ERR_NOMEM;
		}
		
		call->new_data->dptr = talloc_size(call, count*sizeof(struct lock_struct));
		if (call->new_data->dptr == NULL) {
			return CTDB_ERR_NOMEM;
		}
		call->new_data->dsize = count*sizeof(struct lock_struct);

		memcpy(call->new_data->dptr, locks, count*sizeof(struct lock_struct));
	}

	call->status = NT_STATUS_V(status);

	return 0;
}

/*
  Test if we are allowed to perform IO on a region of an open file
*/
static NTSTATUS brl_ctdb_close(struct brl_context *brl,
			       struct brl_handle *brlh)
{
	struct ctdb_call call;
	struct ctdb_close_req req;
	int ret;

	call.call_id = FUNC_BRL_CLOSE;
	call.key.dptr = brlh->key.data;
	call.key.dsize = brlh->key.length;
	call.call_data.dptr = (uint8_t *)&req;
	call.call_data.dsize = sizeof(req);

	ZERO_STRUCT(req);
	req.brl = brl;
	req.server = brl->server;
	req.ntvfs = brlh->ntvfs;

	ret = ctdb_call(brl->ctdb, &call);
	if (ret == -1) {
		DEBUG(0,("ctdb_call failed - %s\n", __location__));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS(call.status);
}


static const struct brlock_ops brlock_tdb_ops = {
	.brl_init           = brl_ctdb_init,
	.brl_create_handle  = brl_ctdb_create_handle,
	.brl_lock           = brl_ctdb_lock,
	.brl_unlock         = brl_ctdb_unlock,
	.brl_remove_pending = brl_ctdb_remove_pending,
	.brl_locktest       = brl_ctdb_locktest,
	.brl_close          = brl_ctdb_close
};


void brl_ctdb_init_ops(void)
{
	struct ctdb_context *ctdb = talloc_get_type(cluster_private(), struct ctdb_context);

	brl_set_ops(&brlock_tdb_ops);

	ctdb_set_call(ctdb, brl_ctdb_lock_func,  FUNC_BRL_LOCK);
	ctdb_set_call(ctdb, brl_ctdb_unlock_func,  FUNC_BRL_UNLOCK);
	ctdb_set_call(ctdb, brl_ctdb_remove_pending_func,  FUNC_BRL_REMOVE_PENDING);
	ctdb_set_call(ctdb, brl_ctdb_locktest_func,  FUNC_BRL_LOCKTEST);
	ctdb_set_call(ctdb, brl_ctdb_close_func,  FUNC_BRL_CLOSE);
}
