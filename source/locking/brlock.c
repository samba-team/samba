/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   byte range locking code
   Copyright (C) Andrew Tridgell 1992-1998
   
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

/* this module implements a tdb based byte range locking service,
   replacing the fcntl() based byte range locking previously
   used. This allows us to provide the same semantics as NT */

#include "includes.h"

extern int DEBUGLEVEL;

/* this contains elements that differentiate locks. The smbpid is a
   client supplied pid, and is essentially the locking context for
   this client */
struct lock_context {
	uint16 smbpid;
	uint16 tid;
	pid_t pid;
};

/* the data in brlock records is an unsorted linear array of these
   records.  It is unnecessary to store the count as tdb provides the
   size of the record */
struct lock_struct {
	struct lock_context context;
	br_off start;
	br_off size;
	enum lock_type lock_type;
};

/* the key used in the brlock database */
struct lock_key {
	SMB_DEV_T device;
	SMB_INO_T inode;
};

/* the open brlock.tdb database */
static TDB_CONTEXT *tdb;


/****************************************************************************
see if two locking contexts are equal
****************************************************************************/
static BOOL brl_same_context(struct lock_context *ctx1, 
			     struct lock_context *ctx2)
{
	return (ctx1->pid == ctx2->pid) &&
		(ctx1->smbpid == ctx2->smbpid) &&
		(ctx1->tid == ctx2->tid);
}

/****************************************************************************
see if lock2 can be added when lock1 is in place
****************************************************************************/
static BOOL brl_conflict(struct lock_struct *lck1, 
			 struct lock_struct *lck2)
{
	if (lck1->lock_type == READ_LOCK && lck2->lock_type == READ_LOCK) return False;

	if (brl_same_context(&lck1->context, &lck2->context) &&
	    lck2->lock_type == READ_LOCK) return False;

	if (lck1->start >= (lck2->start + lck2->size) ||
	    lck2->start >= (lck1->start + lck1->size)) return False;
	    
	return True;
} 


/****************************************************************************
open up the brlock.tdb database 
****************************************************************************/
void brl_init(void)
{
	if (tdb) return;
	tdb = tdb_open(lock_path("brlock.tdb"), 0, TDB_CLEAR_IF_FIRST, 
		       O_RDWR | O_CREAT, 0644);
	if (!tdb) {
		DEBUG(0,("Failed to open byte range locking database\n"));
	}
}


/****************************************************************************
lock a range of bytes
****************************************************************************/
BOOL brl_lock(SMB_DEV_T dev, SMB_INO_T ino, 
	      uint16 smbpid, pid_t pid, uint16 tid,
	      br_off start, br_off size, 
	      enum lock_type lock_type)
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
unlock a range of bytes
****************************************************************************/
BOOL brl_unlock(SMB_DEV_T dev, SMB_INO_T ino, 
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

	if (!dbuf.dptr) goto fail;

	context.smbpid = smbpid;
	context.pid = pid;
	context.tid = tid;

	/* there are existing locks - find a match */
	locks = (struct lock_struct *)dbuf.dptr;
	count = dbuf.dsize / sizeof(*locks);
	for (i=0; i<count; i++) {
		if (brl_same_context(&locks[i].context, &context) &&
		    locks[i].start == start &&
		    locks[i].size == size) {
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
test if we could add a lock if we wanted to
****************************************************************************/
BOOL brl_locktest(SMB_DEV_T dev, SMB_INO_T ino, 
		  uint16 smbpid, pid_t pid, uint16 tid,
		  br_off start, br_off size, 
		  enum lock_type lock_type)
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
