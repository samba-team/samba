/* 
   Unix SMB/Netbios implementation.
   Version 3.0
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

extern int DEBUGLEVEL;

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
	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) 
		return False;

	if (brl_same_context(&lck1->context, &lck2->context) &&
	    lck2->lock_type == READ_LOCK) return False;

	if (lck1->start >= (lck2->start + lck2->size) ||
	    lck2->start >= (lck1->start + lck1->size)) return False;
	    
	return True;
} 


/****************************************************************************
 Open up the brlock.tdb database.
****************************************************************************/

void brl_init(int read_only)
{
	if (tdb) return;
	tdb = tdb_open(lock_path("brlock.tdb"), 0, TDB_CLEAR_IF_FIRST, 
		       read_only?O_RDONLY:O_RDWR|O_CREAT, 0644);
	if (!tdb) {
		DEBUG(0,("Failed to open byte range locking database\n"));
	}
}


/****************************************************************************
 Lock a range of bytes.
****************************************************************************/

BOOL brl_lock(SMB_DEV_T dev, SMB_INO_T ino, int fnum,
	      uint16 smbpid, pid_t pid, uint16 tid,
	      br_off start, br_off size, 
	      enum brl_type lock_type)
{
	struct lock_key key;
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct lock, *locks;

	key.device = dev;
	key.inode = ino;
	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	dbuf.dptr = NULL;

	tdb_lockchain(tdb, kbuf);
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
				goto fail;
			}
		}
	}

	/* no conflicts - add it to the list of locks */
	dbuf.dptr = Realloc(dbuf.dptr, dbuf.dsize + sizeof(*locks));
	if (!dbuf.dptr) goto fail;
	memcpy(dbuf.dptr + dbuf.dsize, &lock, sizeof(lock));
	dbuf.dsize += sizeof(lock);
	tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);
	return True;

 fail:
	if (dbuf.dptr) free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);
	return False;
}

/****************************************************************************
 Create a list of lock ranges that don't overlap a given range. Used in calculating
 POSIX lock unlocks. This is a difficult function that requires ASCII art to
 understand it :-).
****************************************************************************/

struct unlock_list *brl_unlock_list(TALLOC_CTX *ctx, struct unlock_list *ulhead,
							pid_t pid, SMB_DEV_T dev, SMB_INO_T ino)
{
	struct lock_key key;
	TDB_DATA kbuf, dbuf;
	struct lock_struct *locks;
	int num_locks, i;

	/*
	 * Setup the key for this fetch.
	 */
	key.device = dev;
	key.inode = ino;
	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	dbuf.dptr = NULL;

	tdb_lockchain(tdb, kbuf);
	dbuf = tdb_fetch(tdb, kbuf);

	if (!dbuf.dptr) {
		tdb_unlockchain(tdb, kbuf);
		return ulhead;
	}
	
	locks = (struct lock_struct *)dbuf.dptr;
	num_locks = dbuf.dsize / sizeof(*locks);

	/*
	 * Check the current lock list on this dev/inode pair.
	 * Quit if the list is deleted.
	 */

	DEBUG(10,("brl_unlock_list: curr: start=%.0f,size=%.0f\n",
		(double)ulhead->start, (double)ulhead->size ));

	for (i=0; i<num_locks && ulhead; i++) {

		struct lock_struct *lock = &locks[i];
		struct unlock_list *ul_curr;

		/* If it's not this process, ignore it. */
		if (lock->context.pid != pid)
			continue;

		/*
		 * Walk the unlock list, checking for overlaps. Note that
		 * the unlock list can expand within this loop if the current
		 * range being examined needs to be split.
		 */

		for (ul_curr = ulhead; ul_curr;) {

			DEBUG(10,("brl_unlock_list: lock: start=%.0f,size=%.0f:",
				(double)lock->start, (double)lock->size ));

			if ( (ul_curr->start >= (lock->start + lock->size)) ||
				 (lock->start > (ul_curr->start + ul_curr->size))) {

				/* No overlap with this lock - leave this range alone. */
/*********************************************
                                             +---------+
                                             | ul_curr |
                                             +---------+
                                +-------+
                                | lock  |
                                +-------+
OR....
             +---------+
             | ul_curr |
             +---------+
**********************************************/

				DEBUG(10,("no overlap case.\n" ));

				ul_curr = ul_curr->next;

			} else if ( (ul_curr->start >= lock->start) &&
						(ul_curr->start + ul_curr->size <= lock->start + lock->size) ) {

				/*
				 * This unlock is completely overlapped by this existing lock range
				 * and thus should have no effect (not be unlocked). Delete it from the list.
				 */
/*********************************************
                +---------+
                | ul_curr |
                +---------+
        +---------------------------+
        |       lock                |
        +---------------------------+
**********************************************/
				/* Save the next pointer */
				struct unlock_list *ul_next = ul_curr->next;

				DEBUG(10,("delete case.\n" ));

				DLIST_REMOVE(ulhead, ul_curr);
				if(ulhead == NULL)
					break; /* No more list... */

				ul_curr = ul_next;
				
			} else if ( (ul_curr->start >= lock->start) &&
						(ul_curr->start < lock->start + lock->size) &&
						(ul_curr->start + ul_curr->size > lock->start + lock->size) ) {

				/*
				 * This unlock overlaps the existing lock range at the high end.
				 * Truncate by moving start to existing range end and reducing size.
				 */
/*********************************************
                +---------------+
                | ul_curr       |
                +---------------+
        +---------------+
        |    lock       |
        +---------------+
BECOMES....
                        +-------+
                        |ul_curr|
                        +-------+
**********************************************/

				ul_curr->size = (ul_curr->start + ul_curr->size) - (lock->start + lock->size);
				ul_curr->start = lock->start + lock->size;

				DEBUG(10,("truncate high case: start=%.0f,size=%.0f\n",
								(double)ul_curr->start, (double)ul_curr->size ));

				ul_curr = ul_curr->next;

			} else if ( (ul_curr->start < lock->start) &&
						(ul_curr->start + ul_curr->size > lock->start) ) {

				/*
				 * This unlock overlaps the existing lock range at the low end.
				 * Truncate by reducing size.
				 */
/*********************************************
   +---------------+
   | ul_curr       |
   +---------------+
           +---------------+
           |    lock       |
           +---------------+
BECOMES....
   +-------+
   |ul_curr|
   +-------+
**********************************************/

				ul_curr->size = lock->start - ul_curr->start;

				DEBUG(10,("truncate low case: start=%.0f,size=%.0f\n",
								(double)ul_curr->start, (double)ul_curr->size ));

				ul_curr = ul_curr->next;
		
			} else if ( (ul_curr->start < lock->start) &&
						(ul_curr->start + ul_curr->size > lock->start + lock->size) ) {
				/*
				 * Worst case scenario. Unlock request completely overlaps an existing
				 * lock range. Split the request into two, push the new (upper) request
				 * into the dlink list, and continue with the entry after ul_new (as we
				 * know that ul_new will not overlap with this lock).
				 */
/*********************************************
        +---------------------------+
        |       ul_curr             |
        +---------------------------+
                +---------+
                | lock    |
                +---------+
BECOMES.....
        +-------+         +---------+
        |ul_curr|         |ul_new   |
        +-------+         +---------+
**********************************************/
				struct unlock_list *ul_new = (struct unlock_list *)talloc(ctx,
													sizeof(struct unlock_list));

				if(ul_new == NULL) {
					DEBUG(0,("brl_unlock_list: talloc fail.\n"));
					return NULL; /* The talloc_destroy takes care of cleanup. */
				}

				ZERO_STRUCTP(ul_new);
				ul_new->start = lock->start + lock->size;
				ul_new->size = ul_curr->start + ul_curr->size - ul_new->start;
				ul_new->smbpid = ul_curr->smbpid;

				/* Add into the dlink list after the ul_curr point - NOT at ulhead. */
				DLIST_ADD(ul_curr, ul_new);

				/* Truncate the ul_curr. */
				ul_curr->size = lock->start - ul_curr->start;

				DEBUG(10,("split case: curr: start=%.0f,size=%.0f \
new: start=%.0f,size=%.0f\n", (double)ul_curr->start, (double)ul_curr->size,
								(double)ul_new->start, (double)ul_new->size ));

				ul_curr = ul_new->next;

			} else {

				/*
				 * This logic case should never happen. Ensure this is the
				 * case by forcing an abort.... Remove in production.
				 */

				smb_panic("logic flaw in cases...\n");
			}
		} /* end for ( ul_curr = ulhead; ul_curr;) */
	} /* end for (i=0; i<num_locks && ul_head; i++) */

	tdb_unlockchain(tdb, kbuf);

	if (dbuf.dptr)
		free(dbuf.dptr);
	
	return ulhead;
}

/****************************************************************************
 Unlock a range of bytes.
****************************************************************************/

BOOL brl_unlock(SMB_DEV_T dev, SMB_INO_T ino, int fnum,
		uint16 smbpid, pid_t pid, uint16 tid,
		br_off start, br_off size)
{
	struct lock_key key;
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct *locks;
	struct lock_context context;

	key.device = dev;
	key.inode = ino;
	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	dbuf.dptr = NULL;

	tdb_lockchain(tdb, kbuf);
	dbuf = tdb_fetch(tdb, kbuf);

	if (!dbuf.dptr) {
		DEBUG(0,("brl_unlock: tdb_fetch failed !\n"));
		goto fail;
	}

	context.smbpid = smbpid;
	context.pid = pid;
	context.tid = tid;

	/* there are existing locks - find a match */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);
	for (i=0; i<count; i++) {

		struct lock_struct *lock = &locks[i];

#if 0
		/* JRATEST - DEBUGGING INFO */
		if(!brl_same_context(&lock->context, &context)) {
			DEBUG(10,("brl_unlock: Not same context. l_smbpid = %u, l_pid = %u, l_tid = %u: \
smbpid = %u, pid = %u, tid = %u\n",
				lock->context.smbpid, lock->context.pid, lock->context.tid,
				context.smbpid, context.pid, context.tid ));

		}
		/* JRATEST */
#endif

		if (brl_same_context(&lock->context, &context) &&
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

			free(dbuf.dptr);
			tdb_unlockchain(tdb, kbuf);
			return True;
		}
	}

	/* we didn't find it */

 fail:
	if (dbuf.dptr) free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);
	return False;
}

/****************************************************************************
 Test if we could add a lock if we wanted to.
****************************************************************************/

BOOL brl_locktest(SMB_DEV_T dev, SMB_INO_T ino, 
		  uint16 smbpid, pid_t pid, uint16 tid,
		  br_off start, br_off size, 
		  enum brl_type lock_type)
{
	struct lock_key key;
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct lock, *locks;

	key.device = dev;
	key.inode = ino;
	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	dbuf.dptr = NULL;

	tdb_lockchain(tdb, kbuf);
	dbuf = tdb_fetch(tdb, kbuf);

	lock.context.smbpid = smbpid;
	lock.context.pid = pid;
	lock.context.tid = tid;
	lock.start = start;
	lock.size = size;
	lock.lock_type = lock_type;

	if (dbuf.dptr) {
		/* there are existing locks - make sure they don't conflict */
		locks = (struct lock_struct *)dbuf.dptr;
		count = dbuf.dsize / sizeof(*locks);
		for (i=0; i<count; i++) {
			if (brl_conflict(&locks[i], &lock)) {
				goto fail;
			}
		}
	}

	/* no conflicts - we could have added it */
	free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);
	return True;

 fail:
	if (dbuf.dptr) free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);
	return False;
}

/****************************************************************************
 Remove any locks associated with a open file.
****************************************************************************/

void brl_close(SMB_DEV_T dev, SMB_INO_T ino, pid_t pid, int tid, int fnum)
{
	struct lock_key key;
	TDB_DATA kbuf, dbuf;
	int count, i;
	struct lock_struct *locks;

	key.device = dev;
	key.inode = ino;
	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	dbuf.dptr = NULL;

	tdb_lockchain(tdb, kbuf);
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
			/* found it - delete it */
			if (count > 1 && i < count-1) {
				memmove(&locks[i], &locks[i+1], 
					sizeof(*locks)*((count-1) - i));
			}
			count--;
			i--;
		}
	}

	if (count == 0) {
		tdb_delete(tdb, kbuf);
	} else if (count < (dbuf.dsize / sizeof(*locks))) {
		tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
	}

	/* we didn't find it */
 fail:
	if (dbuf.dptr) free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);
}

/****************************************************************************
 Return a lock list associated with an open file.
****************************************************************************/

struct unlock_list *brl_getlocklist( TALLOC_CTX *ctx, SMB_DEV_T dev, SMB_INO_T ino, pid_t pid, int tid, int fnum)
{
	struct lock_key key;
	TDB_DATA kbuf, dbuf;
	int i, count;
	struct lock_struct *locks;
	struct unlock_list *ulist = NULL;

	key.device = dev;
	key.inode = ino;
	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);

	dbuf.dptr = NULL;

	tdb_lockchain(tdb, kbuf);
	dbuf = tdb_fetch(tdb, kbuf);

	if (!dbuf.dptr) {
		tdb_unlockchain(tdb, kbuf);
		return NULL;
	}

	/* There are existing locks - allocate an entry for each one. */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);

	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];

		if (lock->context.tid == tid &&
		    lock->context.pid == pid &&
		    lock->fnum == fnum) {

				struct unlock_list *ul_new = (struct unlock_list *)talloc(ctx,
													sizeof(struct unlock_list));

				if(ul_new == NULL) {
					DEBUG(0,("brl_getlocklist: talloc fail.\n"));
					return NULL; /* The talloc_destroy takes care of cleanup. */
				}

				ZERO_STRUCTP(ul_new);
				ul_new->start = lock->start;
				ul_new->size = lock->size;
				ul_new->smbpid = lock->context.smbpid;

				DLIST_ADD(ulist, ul_new);
		}
	}

	if (dbuf.dptr)
		free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);

	return ulist;
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
	return tdb_traverse(tdb, traverse_fn, (BRLOCK_FN_CAST())fn);
}
