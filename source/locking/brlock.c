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
	    lck2->lock_type == READ_LOCK && lck1->fnum == lck2->fnum) return False;

	if (lck1->start >= (lck2->start + lck2->size) ||
	    lck2->start >= (lck1->start + lck1->size)) return False;
	    
	return True;
} 


/****************************************************************************
delete a record if it is for a dead process
****************************************************************************/
static int delete_fn(TDB_CONTEXT *ttdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	struct lock_struct *locks;
	struct lock_key *key;
	int count, i;

	tdb_lockchain(tdb, kbuf);

	locks = (struct lock_struct *)dbuf.dptr;
	key = (struct lock_key *)kbuf.dptr;

	count = dbuf.dsize / sizeof(*locks);
	for (i=0; i<count; i++) {
		struct lock_struct *lock = &locks[i];

		if (process_exists(lock->context.pid)) continue;

		if (count > 1 && i < count-1) {
			memmove(&locks[i], &locks[i+1], 
				sizeof(*locks)*((count-1) - i));
		}
		count--;
		i--;
		dbuf.dsize -= sizeof(*locks);
	}

	if (count == 0) {
		tdb_delete(tdb, kbuf);
	} else if (count < (dbuf.dsize / sizeof(*locks))) {
		tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);
	}

	tdb_unlockchain(tdb, kbuf);
	return 0;
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
		return;
	}

	/* delete any dead locks */
	if (!read_only) {
		tdb_traverse(tdb, delete_fn, NULL);
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
		DEBUG(10,("brl_unlock: tdb_fetch failed !\n"));
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
	int count, i, dcount=0;
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
	if (dbuf.dptr) free(dbuf.dptr);
	tdb_unlockchain(tdb, kbuf);
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
