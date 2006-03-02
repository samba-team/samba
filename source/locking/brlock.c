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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

#define ZERO_ZERO 0

/* This contains elements that differentiate locks. The smbpid is a
   client supplied pid, and is essentially the locking context for
   this client */

struct lock_context {
	uint16 smbpid;
	uint16 tid;
	struct process_id pid;
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
	enum brl_flavour lock_flav;
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
	return (procid_equal(&ctx1->pid, &ctx2->pid) &&
		(ctx1->smbpid == ctx2->smbpid) &&
		(ctx1->tid == ctx2->tid));
}

/****************************************************************************
 See if lck1 and lck2 overlap.
****************************************************************************/

static BOOL brl_overlap(struct lock_struct *lck1,
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

	return brl_overlap(lck1, lck2);
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
 same fnum only. This is the read/write lock check code path.
****************************************************************************/

static BOOL brl_conflict_other(struct lock_struct *lck1, struct lock_struct *lck2)
{
	if (lck1->lock_type == PENDING_LOCK || lck2->lock_type == PENDING_LOCK )
		return False;

	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) 
		return False;

	/* POSIX flavour locks never conflict here - this is only called
	   in the read/write path. */

	if (lck1->lock_flav == POSIX_LOCK && lck2->lock_flav == POSIX_LOCK)
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

	return brl_overlap(lck1, lck2);
} 

/****************************************************************************
 Amazingly enough, w2k3 "remembers" whether the last lock failure
 is the same as this one and changes its error code. I wonder if any
 app depends on this ?
****************************************************************************/

static NTSTATUS brl_lock_failed(struct lock_struct *lock)
{
	static struct lock_struct last_lock_failure;

	if (brl_same_context(&lock->context, &last_lock_failure.context) &&
			lock->fnum == last_lock_failure.fnum &&
			lock->start == last_lock_failure.start &&
			lock->size == last_lock_failure.size) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}
	last_lock_failure = *lock;
	if (lock->start >= 0xEF000000 &&
			(lock->start >> 63) == 0) {
		/* amazing the little things you learn with a test
		   suite. Locks beyond this offset (as a 64 bit
		   number!) always generate the conflict error code,
		   unless the top bit is set */
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}
	return NT_STATUS_LOCK_NOT_GRANTED;
}

/****************************************************************************
 Open up the brlock.tdb database.
****************************************************************************/

void brl_init(int read_only)
{
	if (tdb) {
		return;
	}
	tdb = tdb_open_log(lock_path("brlock.tdb"), 0,  TDB_DEFAULT|(read_only?0x0:TDB_CLEAR_IF_FIRST),
		       read_only?O_RDONLY:(O_RDWR|O_CREAT), 0644 );
	if (!tdb) {
		DEBUG(0,("Failed to open byte range locking database %s\n",
			lock_path("brlock.tdb")));
		return;
	}
}

/****************************************************************************
 Close down the brlock.tdb database.
****************************************************************************/

void brl_shutdown(int read_only)
{
	if (!tdb) {
		return;
	}
	tdb_close(tdb);
}

#if ZERO_ZERO
/****************************************************************************
 Compare two locks for sorting.
****************************************************************************/

static int lock_compare(struct lock_struct *lck1, 
			 struct lock_struct *lck2)
{
	if (lck1->start != lck2->start) {
		return (lck1->start - lck2->start);
	}
	if (lck2->size != lck1->size) {
		return ((int)lck1->size - (int)lck2->size);
	}
	return 0;
}
#endif

/****************************************************************************
 Lock a range of bytes - Windows lock semantics.
****************************************************************************/

static NTSTATUS brl_lock_windows(struct byte_range_lock *br_lck,
			struct lock_struct *plock,
			BOOL *my_lock_ctx)
{
	unsigned int i;
	struct lock_struct *locks = (struct lock_struct *)br_lck->lock_data;
	char *tp;

	for (i=0; i < br_lck->num_locks; i++) {
		if (brl_conflict(&locks[i], plock)) {
			NTSTATUS status = brl_lock_failed(plock);;
			/* Did we block ourselves ? */
			if (brl_same_context(&locks[i].context, &plock->context)) {
				*my_lock_ctx = True;
			}
			return status;
		}
#if ZERO_ZERO
		if (plock->start == 0 && plock->size == 0 && 
				locks[i].size == 0) {
			break;
		}
#endif
	}

	/* no conflicts - add it to the list of locks */
	tp = SMB_REALLOC(locks, (br_lck->num_locks + 1) * sizeof(*locks));
	if (!tp) {
		return NT_STATUS_NO_MEMORY;
	} else {
		locks = (struct lock_struct *)tp;
		memcpy(&locks[br_lck->num_locks], plock, sizeof(struct lock_struct));
		br_lck->num_locks += 1;
		br_lck->lock_data = (void *)locks;
		br_lck->modified = True;
	}

#if ZERO_ZERO
	/* sort the lock list */
	qsort(br_lck->lock_data, (size_t)br_lck->num_locks, sizeof(lock), lock_compare);
#endif

	return NT_STATUS_OK;
}

/****************************************************************************
 Lock a range of bytes - POSIX lock semantics.
****************************************************************************/

static NTSTATUS brl_lock_posix(struct byte_range_lock *br_lck,
			struct lock_struct *plock)
{
	/* Placeholder until I fix this. */
	return NT_STATUS_LOCK_NOT_GRANTED;
}

/****************************************************************************
 Lock a range of bytes.
****************************************************************************/

NTSTATUS brl_lock(struct byte_range_lock *br_lck,
		uint16 smbpid,
		struct process_id pid,
		br_off start,
		br_off size, 
		enum brl_type lock_type,
		enum brl_flavour lock_flav,
		BOOL *my_lock_ctx)
{
	struct lock_struct lock;

	*my_lock_ctx = False;

#if !ZERO_ZERO
	if (start == 0 && size == 0) {
		DEBUG(0,("client sent 0/0 lock - please report this\n"));
	}
#endif

	lock.context.smbpid = smbpid;
	lock.context.pid = pid;
	lock.context.tid = br_lck->fsp->conn->cnum;
	lock.start = start;
	lock.size = size;
	lock.fnum = br_lck->fsp->fnum;
	lock.lock_type = lock_type;
	lock.lock_flav = lock_flav;

	if (lock_flav == WINDOWS_LOCK) {
		return brl_lock_windows(br_lck, &lock, my_lock_ctx);
	} else {
		return brl_lock_posix(br_lck, &lock);
	}
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
 Unlock a range of bytes - Windows semantics.
****************************************************************************/

static BOOL brl_unlock_windows(struct byte_range_lock *br_lck,
		struct lock_struct *plock,
		BOOL remove_pending_locks_only,
		void (*pre_unlock_fn)(void *),
		void *pre_unlock_data)
{
	unsigned int i, j;
	struct lock_struct *locks = (struct lock_struct *)br_lck->lock_data;

#if ZERO_ZERO
	for (i = 0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &locks[i];

		if (lock->lock_type == WRITE_LOCK &&
		    brl_same_context(&lock->context, &plock->context) &&
		    lock->fnum == plock->fnum &&
		    lock->start == plock->start &&
		    lock->size == plock->size) {

			if (pre_unlock_fn) {
				(*pre_unlock_fn)(pre_unlock_data);
			}

			/* found it - delete it */
			if (i < br_lck->num_locks - 1) {
				memmove(&locks[i], &locks[i+1], 
					sizeof(*locks)*((br_lck->num_locks-1) - i));
			}

			br_lck->num_locks -= 1;
			br_lck->modified = True;
			return True;
		}
	}
#endif

	for (i = 0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &locks[i];

		if (brl_same_context(&lock->context, &plock->context) &&
				lock->fnum == plock->fnum &&
				lock->start == plock->start &&
				lock->size == plock->size) {

			if (remove_pending_locks_only && lock->lock_type != PENDING_LOCK) {
				continue;
			}

			if (lock->lock_type != PENDING_LOCK) {

				/* Do any POSIX unlocks needed. */
				if (pre_unlock_fn) {
					(*pre_unlock_fn)(pre_unlock_data);
				}

				/* Send unlock messages to any pending waiters that overlap. */
				for (j=0; j < br_lck->num_locks; j++) {
					struct lock_struct *pend_lock = &locks[j];

					/* Ignore non-pending locks. */
					if (pend_lock->lock_type != PENDING_LOCK) {
						continue;
					}

					/* We could send specific lock info here... */
					if (brl_pending_overlap(lock, pend_lock)) {
						DEBUG(10,("brl_unlock: sending unlock message to pid %s\n",
							procid_str_static(&pend_lock->context.pid )));

						become_root();
						message_send_pid(pend_lock->context.pid,
								MSG_SMB_UNLOCK,
								NULL, 0, True);
						unbecome_root();
					}
				}
			}

			/* found it - delete it */
			if (i < br_lck->num_locks - 1) {
				memmove(&locks[i], &locks[i+1], 
					sizeof(*locks)*((br_lck->num_locks-1) - i));
			}

			br_lck->num_locks -= 1;
			br_lck->modified = True;
			return True;
		}
	}

	/* we didn't find it */
	return False;
}

/****************************************************************************
 Unlock a range of bytes - POSIX semantics.
****************************************************************************/

static BOOL brl_unlock_posix(struct byte_range_lock *br_lck,
		struct lock_struct *plock,
		BOOL remove_pending_locks_only,
		void (*pre_unlock_fn)(void *),
		void *pre_unlock_data)
{
	/* Placeholder for now. */
	return True;
}

/****************************************************************************
 Unlock a range of bytes.
****************************************************************************/

BOOL brl_unlock(struct byte_range_lock *br_lck,
		uint16 smbpid,
		struct process_id pid,
		br_off start,
		br_off size,
		enum brl_flavour lock_flav,
		BOOL remove_pending_locks_only,
		void (*pre_unlock_fn)(void *),
		void *pre_unlock_data)
{
	struct lock_struct lock;

	lock.context.smbpid = smbpid;
	lock.context.pid = pid;
	lock.context.tid = br_lck->fsp->conn->cnum;
	lock.start = start;
	lock.size = size;
	lock.fnum = br_lck->fsp->fnum;
	lock.lock_type = READ_LOCK; /* We don't really care about this... */
	lock.lock_flav = lock_flav;

	if (lock_flav == WINDOWS_LOCK) {
		return brl_unlock_windows(br_lck,
				&lock,
				remove_pending_locks_only,
				pre_unlock_fn,
				pre_unlock_data);
	} else {
		return brl_unlock_posix(br_lck,
				&lock,
				remove_pending_locks_only,
				pre_unlock_fn,
				pre_unlock_data);
	}
}

/****************************************************************************
 Test if we could add a lock if we wanted to.
****************************************************************************/

BOOL brl_locktest(struct byte_range_lock *br_lck,
		uint16 smbpid,
		struct process_id pid,
		br_off start,
		br_off size, 
		enum brl_type lock_type,
		enum brl_flavour lock_flav)
{
	unsigned int i;
	struct lock_struct lock;
	struct lock_struct *locks = (struct lock_struct *)br_lck->lock_data;

	lock.context.smbpid = smbpid;
	lock.context.pid = pid;
	lock.context.tid = br_lck->fsp->conn->cnum;
	lock.start = start;
	lock.size = size;
	lock.fnum = br_lck->fsp->fnum;
	lock.lock_type = lock_type;
	lock.lock_flav = lock_flav;

	/* Make sure existing locks don't conflict */
	for (i=0; i < br_lck->num_locks; i++) {
		/*
		 * Our own locks don't conflict.
		 */
		if (brl_conflict_other(&locks[i], &lock)) {
			return False;
		}
	}

	/* no conflicts - we could have added it */
	return True;
}

/****************************************************************************
 Remove any locks associated with a open file.
****************************************************************************/

void brl_close_fnum(struct byte_range_lock *br_lck, struct process_id pid)
{
	files_struct *fsp = br_lck->fsp;
	uint16 tid = fsp->conn->cnum;
	int fnum = fsp->fnum;
	unsigned int i, j, dcount=0;
	struct lock_struct *locks = (struct lock_struct *)br_lck->lock_data;

	/* Remove any existing locks for this fnum */

	for (i=0; i < br_lck->num_locks; i++) {
		struct lock_struct *lock = &locks[i];

		if (lock->context.tid == tid &&
		    procid_equal(&lock->context.pid, &pid) &&
		    lock->fnum == fnum) {

			/* Send unlock messages to any pending waiters that overlap. */
			for (j=0; j < br_lck->num_locks; j++) {
				struct lock_struct *pend_lock = &locks[j];

				/* Ignore our own or non-pending locks. */
				if (pend_lock->lock_type != PENDING_LOCK) {
					continue;
				}

				if (pend_lock->context.tid == tid &&
				    procid_equal(&pend_lock->context.pid, &pid) &&
				    pend_lock->fnum == fnum) {
					continue;
				}

				/* We could send specific lock info here... */
				if (brl_pending_overlap(lock, pend_lock)) {
					become_root();
					message_send_pid(pend_lock->context.pid,
							MSG_SMB_UNLOCK,
							NULL, 0, True);
					unbecome_root();
				}
			}

			/* found it - delete it */
			if (br_lck->num_locks > 1 && i < br_lck->num_locks - 1) {
				memmove(&locks[i], &locks[i+1], 
					sizeof(*locks)*((br_lck->num_locks-1) - i));
			}
			br_lck->num_locks--;
			br_lck->modified = True;
			i--;
			dcount++;
		}
	}
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
		traverse_callback(key->device,
				  key->inode,
				  locks[i].context.pid,
				  locks[i].lock_type,
				  locks[i].lock_flav,
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
	if (!tdb) {
		return 0;
	}
	return tdb_traverse(tdb, traverse_fn, (void *)fn);
}

/*******************************************************************
 Store a potentially modified set of byte range lock data back into
 the database.
 Unlock the record.
********************************************************************/

static int byte_range_lock_destructor(void *p)
{
	struct byte_range_lock *br_lck =
		talloc_get_type_abort(p, struct byte_range_lock);
	TDB_DATA key = locking_key(br_lck->fsp->dev, br_lck->fsp->inode);

	if (!br_lck->modified) {
		goto done;
	}

	if (br_lck->num_locks == 0) {
		/* No locks - delete this entry. */
		if (tdb_delete(tdb, key) == -1) {
			smb_panic("Could not delete byte range lock entry\n");
		}
	} else {
		TDB_DATA data;
		data.dptr = br_lck->lock_data;
		data.dsize = br_lck->num_locks * sizeof(struct lock_struct);

		if (tdb_store(tdb, key, data, TDB_REPLACE) == -1) {
			smb_panic("Could not store byte range mode entry\n");
		}
	}

 done:

	SAFE_FREE(br_lck->lock_data);
	tdb_chainunlock(tdb, key);
	return 0;
}

static void print_lock_struct(unsigned int i, struct lock_struct *pls)
{
	DEBUG(10,("[%u]: smbpid = %u, tid = %u, pid = %u, ",
			i,
			(unsigned int)pls->context.smbpid,
			(unsigned int)pls->context.tid,
			(unsigned int)procid_to_pid(&pls->context.pid) ));
	
	DEBUG(10,("start = %.0f, size = %.0f, fnum = %d, %s %s\n",
		(double)pls->start,
		(double)pls->size,
		pls->fnum,
		lock_type_name(pls->lock_type),
		lock_flav_name(pls->lock_flav) ));
}

/*******************************************************************
 Fetch a set of byte range lock data from the database.
 Leave the record locked.
********************************************************************/

struct byte_range_lock *brl_get_locks(TALLOC_CTX *mem_ctx,
					files_struct *fsp)
{
	TDB_DATA key = locking_key(fsp->dev, fsp->inode);
	TDB_DATA data;
	struct byte_range_lock *br_lck;

	br_lck = TALLOC_P(mem_ctx, struct byte_range_lock);
	if (br_lck == NULL) {
		return NULL;
	}

	br_lck->fsp = fsp;
	br_lck->num_locks = 0;
	br_lck->modified = False;

	if (tdb_chainlock(tdb, key) != 0) {
		DEBUG(3, ("Could not lock byte range lock entry\n"));
		TALLOC_FREE(br_lck);
		return NULL;
	}

	talloc_set_destructor(br_lck, byte_range_lock_destructor);

	data = tdb_fetch(tdb, key);
	br_lck->lock_data = (void *)data.dptr;
	br_lck->num_locks = data.dsize / sizeof(struct lock_struct);

	if (DEBUGLEVEL >= 10) {
		unsigned int i;
		struct lock_struct *locks = (struct lock_struct *)br_lck->lock_data;
		DEBUG(10,("brl_get_locks: %u current locks on dev=%.0f, inode=%.0f\n",
			br_lck->num_locks,
			(double)fsp->dev, (double)fsp->inode ));
		for( i = 0; i < br_lck->num_locks; i++) {
			print_lock_struct(i, &locks[i]);
		}
	}
	return br_lck;
}
