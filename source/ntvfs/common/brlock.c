/* 
   Unix SMB/CIFS implementation.

   generic byte range locking code

   Copyright (C) Andrew Tridgell 1992-2004
   Copyright (C) Jeremy Allison 1992-2000
   
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

/* This module implements a tdb based byte range locking service,
   replacing the fcntl() based byte range locking previously
   used. This allows us to provide the same semantics as NT */

#include "includes.h"

struct brl_context {
	struct tdb_wrap *w;
	servid_t server;
	uint16_t tid;
};

/*
  in this module a "DATA_BLOB *file_key" is a blob that uniquely identifies
  a file. For a local posix filesystem this will usually be a combination
  of the device and inode numbers of the file, but it can be anything 
  that uniquely idetifies a file for locking purposes, as long
  as it is applied consistently.
*/

/*
  the lock context contains the elements that define whether one
  lock is the same as another lock
*/
struct lock_context {
	servid_t server;
	uint16_t smbpid;
	uint16_t tid;
};

/* The data in brlock records is an unsorted linear array of these
   records.  It is unnecessary to store the count as tdb provides the
   size of the record */
struct lock_struct {
	struct lock_context context;
	uint64_t start;
	uint64_t size;
	uint16_t fnum;
	enum brl_type lock_type;
};

/*
  Open up the brlock.tdb database. Close it down using
  talloc_free()
*/
void *brl_init(TALLOC_CTX *mem_ctx, servid_t server, uint16_t tid)
{
	char *path;
	struct brl_context *brl;

	brl = talloc_p(mem_ctx, struct brl_context);
	if (brl == NULL) {
		return NULL;
	}

	path = lock_path(brl, "brlock.tdb");
	brl->w = tdb_wrap_open(brl, path, 0,  
			       TDB_DEFAULT|TDB_CLEAR_IF_FIRST,
			       O_RDWR|O_CREAT, 0600);
	talloc_free(path);
	if (brl->w == NULL) {
		talloc_free(brl);
		return NULL;
	}

	brl->server = server;
	brl->tid = tid;

	return (void *)brl;
}


/*
  see if two locking contexts are equal
*/
static BOOL brl_same_context(struct lock_context *ctx1, struct lock_context *ctx2)
{
	return (ctx1->server == ctx2->server &&
		ctx1->smbpid == ctx2->smbpid &&
		ctx1->tid == ctx2->tid);
}

/*
 See if lock2 can be added when lock1 is in place.
*/
static BOOL brl_conflict(struct lock_struct *lck1, 
			 struct lock_struct *lck2)
{
	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) {
		return False;
	}

	if (brl_same_context(&lck1->context, &lck2->context) &&
	    lck2->lock_type == READ_LOCK && lck1->fnum == lck2->fnum) {
		return False;
	}

	if (lck1->start >= (lck2->start + lck2->size) ||
	    lck2->start >= (lck1->start + lck1->size)) {
		return False;
	}
	    
	return True;
} 


/*
 Check to see if this lock conflicts, but ignore our own locks on the
 same fnum only.
*/
static BOOL brl_conflict_other(struct lock_struct *lck1, struct lock_struct *lck2)
{
	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) 
		return False;

	if (brl_same_context(&lck1->context, &lck2->context) &&
	    lck1->fnum == lck2->fnum) {
		return False;
	}

	if (lck1->start >= (lck2->start + lck2->size) ||
	    lck2->start >= (lck1->start + lck1->size))
		return False;
	    
	return True;
} 



/*
 Lock a range of bytes.
*/
NTSTATUS brl_lock(void *brl_ctx,
		  DATA_BLOB *file_key, 
		  uint16_t smbpid,
		  uint16_t fnum, 
		  uint64_t start, uint64_t size, 
		  enum brl_type lock_type)
{
	struct brl_context *brl = brl_ctx;
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct lock, *locks;
	char *tp;
	NTSTATUS status;

	kbuf.dptr = file_key->data;
	kbuf.dsize = file_key->length;

	if (tdb_chainlock(brl->w->tdb, kbuf) != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	dbuf = tdb_fetch(brl->w->tdb, kbuf);

	lock.context.smbpid = smbpid;
	lock.context.server = brl->server;
	lock.context.tid = brl->tid;
	lock.start = start;
	lock.size = size;
	lock.fnum = fnum;
	lock.lock_type = lock_type;

	if (dbuf.dptr) {
		/* there are existing locks - make sure they don't conflict */
		locks = (struct lock_struct *)dbuf.dptr;
		count = dbuf.dsize / sizeof(*locks);
		for (i=0; i<count; i++) {
			if (brl_conflict(&locks[i], &lock)) {
				status = NT_STATUS_LOCK_NOT_GRANTED;
				goto fail;
			}
		}
	}

	/* no conflicts - add it to the list of locks */
	tp = Realloc(dbuf.dptr, dbuf.dsize + sizeof(*locks));
	if (!tp) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	} else {
		dbuf.dptr = tp;
	}
	memcpy(dbuf.dptr + dbuf.dsize, &lock, sizeof(lock));
	dbuf.dsize += sizeof(lock);

	if (tdb_store(brl->w->tdb, kbuf, dbuf, TDB_REPLACE) != 0) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto fail;
	}

	free(dbuf.dptr);
	tdb_chainunlock(brl->w->tdb, kbuf);
	return NT_STATUS_OK;

 fail:

	free(dbuf.dptr);
	tdb_chainunlock(brl->w->tdb, kbuf);
	return status;
}


/*
 Unlock a range of bytes.
*/
NTSTATUS brl_unlock(void *brl_ctx,
		    DATA_BLOB *file_key, 
		    uint16_t smbpid,
		    uint16_t fnum,
		    uint64_t start, uint64_t size)
{
	struct brl_context *brl = brl_ctx;
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct *locks;
	struct lock_context context;
	NTSTATUS status;

	kbuf.dptr = file_key->data;
	kbuf.dsize = file_key->length;

	if (tdb_chainlock(brl->w->tdb, kbuf) != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	dbuf = tdb_fetch(brl->w->tdb, kbuf);
	if (!dbuf.dptr) {
		tdb_chainunlock(brl->w->tdb, kbuf);
		return NT_STATUS_RANGE_NOT_LOCKED;
	}

	context.smbpid = smbpid;
	context.server = brl->server;
	context.tid = brl->tid;

	/* there are existing locks - find a match */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);
	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];
		
		if (brl_same_context(&lock->context, &context) &&
		    lock->fnum == fnum &&
		    lock->start == start &&
		    lock->size == size) {
			/* found it - delete it */
			if (count == 1) {
				if (tdb_delete(brl->w->tdb, kbuf) != 0) {
					status = NT_STATUS_INTERNAL_DB_CORRUPTION;
					goto fail;
				}
			} else {
				if (i < count-1) {
					memmove(&locks[i], &locks[i+1], 
						sizeof(*locks)*((count-1) - i));
				}
				dbuf.dsize -= sizeof(*locks);
				if (tdb_store(brl->w->tdb, kbuf, dbuf, TDB_REPLACE) != 0) {
					status = NT_STATUS_INTERNAL_DB_CORRUPTION;
					goto fail;
				}
			}
			
			free(dbuf.dptr);
			tdb_chainunlock(brl->w->tdb, kbuf);
			return NT_STATUS_OK;
		}
	}
	
	/* we didn't find it */
	status = NT_STATUS_RANGE_NOT_LOCKED;

 fail:
	free(dbuf.dptr);
	tdb_chainunlock(brl->w->tdb, kbuf);
	return status;
}


/*
  Test if we are allowed to perform IO on a region of an open file
*/
NTSTATUS brl_locktest(void *brl_ctx,
		      DATA_BLOB *file_key, 
		      uint16_t fnum,
		      uint16 smbpid, 
		      uint64_t start, uint64_t size, 
		      enum brl_type lock_type)
{
	struct brl_context *brl = brl_ctx;
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct lock, *locks;

	kbuf.dptr = file_key->data;
	kbuf.dsize = file_key->length;

	dbuf = tdb_fetch(brl->w->tdb, kbuf);
	if (dbuf.dptr == NULL) {
		return NT_STATUS_OK;
	}

	lock.context.smbpid = smbpid;
	lock.context.server = brl->server;
	lock.context.tid = brl->tid;
	lock.start = start;
	lock.size = size;
	lock.fnum = fnum;
	lock.lock_type = lock_type;

	/* there are existing locks - make sure they don't conflict */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	for (i=0; i<count; i++) {
		if (brl_conflict_other(&locks[i], &lock)) {
			free(dbuf.dptr);
			return NT_STATUS_FILE_LOCK_CONFLICT;
		}
	}

	free(dbuf.dptr);
	return NT_STATUS_OK;
}


/*
 Remove any locks associated with a open file.
*/
NTSTATUS brl_close(void *brl_ctx,
		   DATA_BLOB *file_key, int fnum)
{
	struct brl_context *brl = brl_ctx;
	TDB_DATA kbuf, dbuf;
	int count, i, dcount=0;
	struct lock_struct *locks;
	NTSTATUS status;

	kbuf.dptr = file_key->data;
	kbuf.dsize = file_key->length;

	if (tdb_chainlock(brl->w->tdb, kbuf) != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	dbuf = tdb_fetch(brl->w->tdb, kbuf);
	if (!dbuf.dptr) {
		tdb_chainunlock(brl->w->tdb, kbuf);
		return NT_STATUS_OK;
	}

	/* there are existing locks - remove any for this fnum */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];

		if (lock->context.tid == brl->tid &&
		    lock->context.server == brl->server &&
		    lock->fnum == fnum) {
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

	status = NT_STATUS_OK;

	if (count == 0) {
		if (tdb_delete(brl->w->tdb, kbuf) != 0) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else if (dcount != 0) {
		dbuf.dsize -= dcount * sizeof(*locks);
		if (tdb_store(brl->w->tdb, kbuf, dbuf, TDB_REPLACE) != 0) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	free(dbuf.dptr);
	tdb_chainunlock(brl->w->tdb, kbuf);

	return status;
}

