/* 
   Unix SMB/CIFS implementation.
   byte range locking code
   Updated to handle range splits/merges.

   Copyright (C) Andrew Tridgell 1992-2000
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

#define ZERO_ZERO 0

/* This contains elements that differentiate locks. The smbpid is a
   client supplied pid, and is essentially the locking context for
   this client */

struct lock_context {
	uint16 smbpid;
	uint16 tid;
	pid_t pid;
};

/* The data in brlock records is an unsorted linear array of these
   records.  It is unnecessary to store the count as tdb provides the
   size of the record */

struct lock_struct {
	struct lock_context context;
	br_off start;
	br_off size;
	int fnum;
	enum brl_type lock_type;
};

/* The key used in the brlock database. */

struct lock_key {
	SMB_DEV_T device;
	SMB_INO_T inode;
};

/* The open brlock.tdb database. */

static TDB_CONTEXT *tdb;

/****************************************************************************
 Create a locking key - ensuring zero filled for pad purposes.
****************************************************************************/

static TDB_DATA locking_key(SMB_DEV_T dev, SMB_INO_T inode)
{
        static struct lock_key key;
        TDB_DATA kbuf;

        memset(&key, '\0', sizeof(key));
        key.device = dev;
        key.inode = inode;
        kbuf.dptr = (char *)&key;
        kbuf.dsize = sizeof(key);
        return kbuf;
}

/****************************************************************************
 See if two locking contexts are equal.
****************************************************************************/

static BOOL brl_same_context(struct lock_context *ctx1, 
			     struct lock_context *ctx2)
{
	return (ctx1->pid == ctx2->pid) &&
		(ctx1->smbpid == ctx2->smbpid) &&
		(ctx1->tid == ctx2->tid);
}

/****************************************************************************
 See if lock2 can be added when lock1 is in place.
****************************************************************************/

static BOOL brl_conflict(struct lock_struct *lck1, 
			 struct lock_struct *lck2)
{
	if (lck1->lock_type == PENDING_LOCK || lck2->lock_type == PENDING_LOCK )
		return False;

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

#if ZERO_ZERO
static BOOL brl_conflict1(struct lock_struct *lck1, 
			 struct lock_struct *lck2)
{
	if (lck1->lock_type == PENDING_LOCK || lck2->lock_type == PENDING_LOCK )
		return False;

	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) {
		return False;
	}

	if (brl_same_context(&lck1->context, &lck2->context) &&
	    lck2->lock_type == READ_LOCK && lck1->fnum == lck2->fnum) {
		return False;
	}

	if (lck2->start == 0 && lck2->size == 0 && lck1->size != 0) {
		return True;
	}

	if (lck1->start >= (lck2->start + lck2->size) ||
	    lck2->start >= (lck1->start + lck1->size)) {
		return False;
	}
	    
	return True;
} 
#endif

/****************************************************************************
 Check to see if this lock conflicts, but ignore our own locks on the
 same fnum only.
****************************************************************************/

static BOOL brl_conflict_other(struct lock_struct *lck1, struct lock_struct *lck2)
{
	if (lck1->lock_type == PENDING_LOCK || lck2->lock_type == PENDING_LOCK )
		return False;

	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) 
		return False;

	/*
	 * Incoming WRITE locks conflict with existing READ locks even
	 * if the context is the same. JRA. See LOCKTEST7 in smbtorture.
	 */

	if (!(lck2->lock_type == WRITE_LOCK && lck1->lock_type == READ_LOCK)) {
		if (brl_same_context(&lck1->context, &lck2->context) &&
					lck1->fnum == lck2->fnum)
			return False;
	}

	if (lck1->start >= (lck2->start + lck2->size) ||
	    lck2->start >= (lck1->start + lck1->size)) return False;
	    
	return True;
} 


#if DONT_DO_THIS
	/* doing this traversal could kill solaris machines under high load (tridge) */
	/* delete any dead locks */

/****************************************************************************
 Delete a record if it is for a dead process, if check_self is true, then
 delete any records belonging to this pid also (there shouldn't be any).
****************************************************************************/

static int delete_fn(TDB_CONTEXT *ttdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	struct lock_struct *locks;
	int count, i;
	BOOL check_self = *(BOOL *)state;
	pid_t mypid = sys_getpid();

	tdb_chainlock(tdb, kbuf);

	locks = (struct lock_struct *)dbuf.dptr;

	count = dbuf.dsize / sizeof(*locks);
	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];

		/* If check_self is true we want to remove our own records. */
		if (check_self && (mypid == lock->context.pid)) {

			DEBUG(0,("brlock : delete_fn. LOGIC ERROR ! Shutting down and a record for my pid (%u) exists !\n",
					(unsigned int)lock->context.pid ));

		} else if (process_exists(lock->context.pid)) {

			DEBUG(10,("brlock : delete_fn. pid %u exists.\n", (unsigned int)lock->context.pid ));
			continue;
		}

		DEBUG(10,("brlock : delete_fn. Deleting record for process %u\n",
				(unsigned int)lock->context.pid ));

		if (count > 1 && i < count-1) {
			memmove(&locks[i], &locks[i+1], 
				sizeof(*locks)*((count-1) - i));
		}
		count--;
		i--;
	}

	if (count == 0) {
		tdb_delete(tdb, kbuf);
	} else if (count < (dbuf.dsize / sizeof(*locks))) {
		dbuf.dsize = count * sizeof(*locks);
		tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
	}

	tdb_chainunlock(tdb, kbuf);
	return 0;
}
#endif

/****************************************************************************
 Open up the brlock.tdb database.
****************************************************************************/

void brl_init(int read_only)
{
	if (tdb)
		return;
	tdb = tdb_open_log(lock_path("brlock.tdb"), 0,  TDB_DEFAULT|(read_only?0x0:TDB_CLEAR_IF_FIRST),
		       read_only?O_RDONLY:(O_RDWR|O_CREAT), 0644);
	if (!tdb) {
		DEBUG(0,("Failed to open byte range locking database\n"));
		return;
	}

#if DONT_DO_THIS
	/* doing this traversal could kill solaris machines under high load (tridge) */
	/* delete any dead locks */
	if (!read_only) {
		BOOL check_self = False;
		tdb_traverse(tdb, delete_fn, &check_self);
	}
#endif
}

/****************************************************************************
 Close down the brlock.tdb database.
****************************************************************************/

void brl_shutdown(int read_only)
{
	if (!tdb)
		return;

#if DONT_DO_THIS
	/* doing this traversal could kill solaris machines under high load (tridge) */
	/* delete any dead locks */
	if (!read_only) {
		BOOL check_self = True;
		tdb_traverse(tdb, delete_fn, &check_self);
	}
#endif

	tdb_close(tdb);
}

#if ZERO_ZERO
/****************************************************************************
compare two locks for sorting
****************************************************************************/
static int lock_compare(struct lock_struct *lck1, 
			 struct lock_struct *lck2)
{
	if (lck1->start != lck2->start) return (lck1->start - lck2->start);
	if (lck2->size != lck1->size) {
		return ((int)lck1->size - (int)lck2->size);
	}
	return 0;
}
#endif

/****************************************************************************
 Lock a range of bytes.
****************************************************************************/

NTSTATUS brl_lock(SMB_DEV_T dev, SMB_INO_T ino, int fnum,
		  uint16 smbpid, pid_t pid, uint16 tid,
		  br_off start, br_off size, 
		  enum brl_type lock_type)
{
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct lock, *locks;
	char *tp;
	NTSTATUS status = NT_STATUS_OK;
	static int last_failed = -1;
	static br_off last_failed_start;

	kbuf = locking_key(dev,ino);

	dbuf.dptr = NULL;

#if !ZERO_ZERO
	if (start == 0 && size == 0) {
		DEBUG(0,("client sent 0/0 lock - please report this\n"));
	}
#endif

	tdb_chainlock(tdb, kbuf);
	dbuf = tdb_fetch(tdb, kbuf);

	lock.context.smbpid = smbpid;
	lock.context.pid = pid;
	lock.context.tid = tid;
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
#if ZERO_ZERO
			if (lock.start == 0 && lock.size == 0 && 
			    locks[i].size == 0) {
				break;
			}
#endif
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

#if ZERO_ZERO
	/* sort the lock list */
	qsort(dbuf.dptr, dbuf.dsize/sizeof(lock), sizeof(lock), lock_compare);
#endif

	tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	SAFE_FREE(dbuf.dptr);
	tdb_chainunlock(tdb, kbuf);
	return NT_STATUS_OK;

 fail:
	/* this is a nasty hack to try to simulate the lock result cache code in w2k.
	   It isn't completely accurate as I haven't yet worked out the correct
	   semantics (tridge)
	*/
	if (last_failed == fnum &&
	    last_failed_start == start &&
	    NT_STATUS_EQUAL(status, NT_STATUS_LOCK_NOT_GRANTED)) {
		status = NT_STATUS_FILE_LOCK_CONFLICT;
	}
	last_failed = fnum;
	last_failed_start = start;

	SAFE_FREE(dbuf.dptr);
	tdb_chainunlock(tdb, kbuf);
	return status;
}

/****************************************************************************
 Check if an unlock overlaps a pending lock.
****************************************************************************/

static BOOL brl_pending_overlap(struct lock_struct *lock, struct lock_struct *pend_lock)
{
	if ((lock->start <= pend_lock->start) && (lock->start + lock->size > pend_lock->start))
		return True;
	if ((lock->start >= pend_lock->start) && (lock->start <= pend_lock->start + pend_lock->size))
		return True;
	return False;
}

/****************************************************************************
 Unlock a range of bytes.
****************************************************************************/

BOOL brl_unlock(SMB_DEV_T dev, SMB_INO_T ino, int fnum,
		uint16 smbpid, pid_t pid, uint16 tid,
		br_off start, br_off size,
		BOOL remove_pending_locks_only)
{
	TDB_DATA kbuf, dbuf;
	int count, i, j;
	struct lock_struct *locks;
	struct lock_context context;

	kbuf = locking_key(dev,ino);

	dbuf.dptr = NULL;

	tdb_chainlock(tdb, kbuf);
	dbuf = tdb_fetch(tdb, kbuf);

	if (!dbuf.dptr) {
		DEBUG(10,("brl_unlock: tdb_fetch failed !\n"));
		goto fail;
	}

	context.smbpid = smbpid;
	context.pid = pid;
	context.tid = tid;

	/* there are existing locks - find a match */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

#if ZERO_ZERO
	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];

		if (lock->lock_type == WRITE_LOCK &&
		    brl_same_context(&lock->context, &context) &&
		    lock->fnum == fnum &&
		    lock->start == start &&
		    lock->size == size) {
			/* found it - delete it */
			if (count == 1) {
				tdb_delete(tdb, kbuf);
			} else {
				if (i < count-1) {
					memmove(&locks[i], &locks[i+1], 
						sizeof(*locks)*((count-1) - i));
				}
				dbuf.dsize -= sizeof(*locks);
				tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
			}

			SAFE_FREE(dbuf.dptr);
			tdb_chainunlock(tdb, kbuf);
			return True;
		}
	}
#endif

	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);
	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];

		if (brl_same_context(&lock->context, &context) &&
				lock->fnum == fnum &&
				lock->start == start &&
				lock->size == size) {

			if (remove_pending_locks_only && lock->lock_type != PENDING_LOCK)
				continue;

			if (lock->lock_type != PENDING_LOCK) {
				/* Send unlock messages to any pending waiters that overlap. */
				for (j=0; j<count; j++) {
					struct lock_struct *pend_lock = &locks[j];

					/* Ignore non-pending locks. */
					if (pend_lock->lock_type != PENDING_LOCK)
						continue;

					/* We could send specific lock info here... */
					if (brl_pending_overlap(lock, pend_lock)) {
						DEBUG(10,("brl_unlock: sending unlock message to pid %u\n",
									(unsigned int)pend_lock->context.pid ));

						message_send_pid(pend_lock->context.pid,
								MSG_SMB_UNLOCK,
								NULL, 0, True);
					}
				}
			}

			/* found it - delete it */
			if (count == 1) {
				tdb_delete(tdb, kbuf);
			} else {
				if (i < count-1) {
					memmove(&locks[i], &locks[i+1], 
						sizeof(*locks)*((count-1) - i));
				}
				dbuf.dsize -= sizeof(*locks);
				tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
			}

			SAFE_FREE(dbuf.dptr);
			tdb_chainunlock(tdb, kbuf);
			return True;
		}
	}

	/* we didn't find it */

 fail:
	SAFE_FREE(dbuf.dptr);
	tdb_chainunlock(tdb, kbuf);
	return False;
}


/****************************************************************************
 Test if we could add a lock if we wanted to.
****************************************************************************/

BOOL brl_locktest(SMB_DEV_T dev, SMB_INO_T ino, int fnum,
		  uint16 smbpid, pid_t pid, uint16 tid,
		  br_off start, br_off size, 
		  enum brl_type lock_type, int check_self)
{
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct lock, *locks;

	kbuf = locking_key(dev,ino);

	dbuf.dptr = NULL;

	tdb_chainlock(tdb, kbuf);
	dbuf = tdb_fetch(tdb, kbuf);

	lock.context.smbpid = smbpid;
	lock.context.pid = pid;
	lock.context.tid = tid;
	lock.start = start;
	lock.size = size;
	lock.fnum = fnum;
	lock.lock_type = lock_type;

	if (dbuf.dptr) {
		/* there are existing locks - make sure they don't conflict */
		locks = (struct lock_struct *)dbuf.dptr;
		count = dbuf.dsize / sizeof(*locks);
		for (i=0; i<count; i++) {
			if (check_self) {
				if (brl_conflict(&locks[i], &lock))
					goto fail;
			} else {
				/*
				 * Our own locks don't conflict.
				 */
				if (brl_conflict_other(&locks[i], &lock))
					goto fail;
			}
		}
	}

	/* no conflicts - we could have added it */
	SAFE_FREE(dbuf.dptr);
	tdb_chainunlock(tdb, kbuf);
	return True;

 fail:
	SAFE_FREE(dbuf.dptr);
	tdb_chainunlock(tdb, kbuf);
	return False;
}

/****************************************************************************
 Remove any locks associated with a open file.
****************************************************************************/

void brl_close(SMB_DEV_T dev, SMB_INO_T ino, pid_t pid, int tid, int fnum)
{
	TDB_DATA kbuf, dbuf;
	int count, i, j, dcount=0;
	struct lock_struct *locks;

	kbuf = locking_key(dev,ino);

	dbuf.dptr = NULL;

	tdb_chainlock(tdb, kbuf);
	dbuf = tdb_fetch(tdb, kbuf);

	if (!dbuf.dptr) goto fail;

	/* there are existing locks - remove any for this fnum */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];

		if (lock->context.tid == tid &&
		    lock->context.pid == pid &&
		    lock->fnum == fnum) {

			/* Send unlock messages to any pending waiters that overlap. */
			for (j=0; j<count; j++) {
				struct lock_struct *pend_lock = &locks[j];

				/* Ignore our own or non-pending locks. */
				if (pend_lock->lock_type != PENDING_LOCK)
					continue;

				if (pend_lock->context.tid == tid &&
				    pend_lock->context.pid == pid &&
				    pend_lock->fnum == fnum)
					continue;

				/* We could send specific lock info here... */
				if (brl_pending_overlap(lock, pend_lock))
					message_send_pid(pend_lock->context.pid,
							MSG_SMB_UNLOCK,
							NULL, 0, True);
			}

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

	if (count == 0) {
		tdb_delete(tdb, kbuf);
	} else if (count < (dbuf.dsize / sizeof(*locks))) {
		dbuf.dsize -= dcount * sizeof(*locks);
		tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
	}

	/* we didn't find it */
 fail:
	SAFE_FREE(dbuf.dptr);
	tdb_chainunlock(tdb, kbuf);
}

/****************************************************************************
 Traverse the whole database with this function, calling traverse_callback
 on each lock.
****************************************************************************/

static int traverse_fn(TDB_CONTEXT *ttdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	struct lock_struct *locks;
	struct lock_key *key;
	int i;

	BRLOCK_FN(traverse_callback) = (BRLOCK_FN_CAST())state;

	locks = (struct lock_struct *)dbuf.dptr;
	key = (struct lock_key *)kbuf.dptr;

	for (i=0;i<dbuf.dsize/sizeof(*locks);i++) {
		traverse_callback(key->device, key->inode,
				  locks[i].context.pid,
				  locks[i].lock_type,
				  locks[i].start,
				  locks[i].size);
	}
	return 0;
}

/*******************************************************************
 Call the specified function on each lock in the database.
********************************************************************/

int brl_forall(BRLOCK_FN(fn))
{
	if (!tdb) return 0;
	return tdb_traverse(tdb, traverse_fn, (void *)fn);
}
