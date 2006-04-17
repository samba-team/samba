 /* 
   Unix SMB/CIFS implementation.

   trivial database library

   Copyright (C) Andrew Tridgell              1999-2005
   Copyright (C) Paul `Rusty' Russell		   2000
   Copyright (C) Jeremy Allison			   2000-2003
   
     ** NOTE! The following LGPL license applies to the tdb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "tdb_private.h"

/* a byte range locking function - return 0 on success
   this functions locks/unlocks 1 byte at the specified offset.

   On error, errno is also set so that errors are passed back properly
   through tdb_open(). 

   note that a len of zero means lock to end of file
*/
 int tdb_brlock_len(struct tdb_context *tdb, tdb_off_t offset, 
		   int rw_type, int lck_type, int probe, size_t len)
{
	struct flock fl;
	int ret;

	if (tdb->flags & TDB_NOLOCK) {
		return 0;
	}

	if ((rw_type == F_WRLCK) && (tdb->read_only || tdb->traverse_read)) {
		tdb->ecode = TDB_ERR_RDONLY;
		return -1;
	}

	fl.l_type = rw_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = offset;
	fl.l_len = len;
	fl.l_pid = 0;

	do {
		ret = fcntl(tdb->fd,lck_type,&fl);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		/* Generic lock error. errno set by fcntl.
		 * EAGAIN is an expected return from non-blocking
		 * locks. */
		if (!probe && lck_type != F_SETLK) {
			/* Ensure error code is set for log fun to examine. */
			tdb->ecode = TDB_ERR_LOCK;
			TDB_LOG((tdb, 5,"tdb_brlock failed (fd=%d) at offset %d rw_type=%d lck_type=%d len=%d\n", 
				 tdb->fd, offset, rw_type, lck_type, len));
		}
		return TDB_ERRCODE(TDB_ERR_LOCK, -1);
	}
	return 0;
}


/*
  upgrade a read lock to a write lock. This needs to be handled in a
  special way as some OSes (such as solaris) have too conservative
  deadlock detection and claim a deadlock when progress can be
  made. For those OSes we may loop for a while.  
*/
 int tdb_brlock_upgrade(struct tdb_context *tdb, tdb_off_t offset, size_t len)
{
	int count = 1000;
	while (count--) {
		struct timeval tv;
		if (tdb_brlock_len(tdb, offset, F_WRLCK, F_SETLKW, 1, len) == 0) {
			return 0;
		}
		if (errno != EDEADLK) {
			break;
		}
		/* sleep for as short a time as we can - more portable than usleep() */
		tv.tv_sec = 0;
		tv.tv_usec = 1;
		select(0, NULL, NULL, NULL, &tv);
	}
	TDB_LOG((tdb, 5,"tdb_brlock_upgrade failed at offset %d\n", offset));
	return -1;
}


/* a byte range locking function - return 0 on success
   this functions locks/unlocks 1 byte at the specified offset.

   On error, errno is also set so that errors are passed back properly
   through tdb_open(). */
 int tdb_brlock(struct tdb_context *tdb, tdb_off_t offset, 
	       int rw_type, int lck_type, int probe)
{
	return tdb_brlock_len(tdb, offset, rw_type, lck_type, probe, 1);
}

/* lock a list in the database. list -1 is the alloc list */
int tdb_lock(struct tdb_context *tdb, int list, int ltype)
{
	if (list < -1 || list >= (int)tdb->header.hash_size) {
		TDB_LOG((tdb, 0,"tdb_lock: invalid list %d for ltype=%d\n", 
			   list, ltype));
		return -1;
	}
	if (tdb->flags & TDB_NOLOCK)
		return 0;

	/* Since fcntl locks don't nest, we do a lock for the first one,
	   and simply bump the count for future ones */
	if (tdb->locked[list+1].count == 0) {
		if (tdb->methods->tdb_brlock(tdb,FREELIST_TOP+4*list,ltype,F_SETLKW, 0)) {
			TDB_LOG((tdb, 0,"tdb_lock failed on list %d ltype=%d (%s)\n", 
				 list, ltype, strerror(errno)));
			return -1;
		}
		tdb->locked[list+1].ltype = ltype;
		tdb->num_locks++;
	}
	tdb->locked[list+1].count++;
	return 0;
}

/* unlock the database: returns void because it's too late for errors. */
	/* changed to return int it may be interesting to know there
	   has been an error  --simo */
int tdb_unlock(struct tdb_context *tdb, int list, int ltype)
{
	int ret = -1;

	if (tdb->flags & TDB_NOLOCK)
		return 0;

	/* Sanity checks */
	if (list < -1 || list >= (int)tdb->header.hash_size) {
		TDB_LOG((tdb, 0, "tdb_unlock: list %d invalid (%d)\n", list, tdb->header.hash_size));
		return ret;
	}

	if (tdb->locked[list+1].count==0) {
		TDB_LOG((tdb, 0, "tdb_unlock: count is 0\n"));
		return ret;
	}

	if (tdb->locked[list+1].count == 1) {
		/* Down to last nested lock: unlock underneath */
		ret = tdb->methods->tdb_brlock(tdb, FREELIST_TOP+4*list, F_UNLCK, F_SETLKW, 0);
		tdb->num_locks--;
	} else {
		ret = 0;
	}
	tdb->locked[list+1].count--;

	if (ret)
		TDB_LOG((tdb, 0,"tdb_unlock: An error occurred unlocking!\n")); 
	return ret;
}



/* lock/unlock entire database */
int tdb_lockall(struct tdb_context *tdb)
{
	u32 i;

	/* There are no locks on read-only dbs */
	if (tdb->read_only || tdb->traverse_read)
		return TDB_ERRCODE(TDB_ERR_LOCK, -1);
	for (i = 0; i < tdb->header.hash_size; i++) 
		if (tdb_lock(tdb, i, F_WRLCK))
			break;

	/* If error, release locks we have... */
	if (i < tdb->header.hash_size) {
		u32 j;

		for ( j = 0; j < i; j++)
			tdb_unlock(tdb, j, F_WRLCK);
		return TDB_ERRCODE(TDB_ERR_NOLOCK, -1);
	}

	return 0;
}
void tdb_unlockall(struct tdb_context *tdb)
{
	u32 i;
	for (i=0; i < tdb->header.hash_size; i++)
		tdb_unlock(tdb, i, F_WRLCK);
}

/* lock/unlock one hash chain. This is meant to be used to reduce
   contention - it cannot guarantee how many records will be locked */
int tdb_chainlock(struct tdb_context *tdb, TDB_DATA key)
{
	return tdb_lock(tdb, BUCKET(tdb->hash_fn(&key)), F_WRLCK);
}

int tdb_chainunlock(struct tdb_context *tdb, TDB_DATA key)
{
	return tdb_unlock(tdb, BUCKET(tdb->hash_fn(&key)), F_WRLCK);
}

int tdb_chainlock_read(struct tdb_context *tdb, TDB_DATA key)
{
	return tdb_lock(tdb, BUCKET(tdb->hash_fn(&key)), F_RDLCK);
}

int tdb_chainunlock_read(struct tdb_context *tdb, TDB_DATA key)
{
	return tdb_unlock(tdb, BUCKET(tdb->hash_fn(&key)), F_RDLCK);
}



/* record lock stops delete underneath */
 int tdb_lock_record(struct tdb_context *tdb, tdb_off_t off)
{
	return off ? tdb->methods->tdb_brlock(tdb, off, F_RDLCK, F_SETLKW, 0) : 0;
}

/*
  Write locks override our own fcntl readlocks, so check it here.
  Note this is meant to be F_SETLK, *not* F_SETLKW, as it's not
  an error to fail to get the lock here.
*/
 int tdb_write_lock_record(struct tdb_context *tdb, tdb_off_t off)
{
	struct tdb_traverse_lock *i;
	for (i = &tdb->travlocks; i; i = i->next)
		if (i->off == off)
			return -1;
	return tdb->methods->tdb_brlock(tdb, off, F_WRLCK, F_SETLK, 1);
}

/*
  Note this is meant to be F_SETLK, *not* F_SETLKW, as it's not
  an error to fail to get the lock here.
*/
 int tdb_write_unlock_record(struct tdb_context *tdb, tdb_off_t off)
{
	return tdb->methods->tdb_brlock(tdb, off, F_UNLCK, F_SETLK, 0);
}

/* fcntl locks don't stack: avoid unlocking someone else's */
 int tdb_unlock_record(struct tdb_context *tdb, tdb_off_t off)
{
	struct tdb_traverse_lock *i;
	u32 count = 0;

	if (off == 0)
		return 0;
	for (i = &tdb->travlocks; i; i = i->next)
		if (i->off == off)
			count++;
	return (count == 1 ? tdb->methods->tdb_brlock(tdb, off, F_UNLCK, F_SETLKW, 0) : 0);
}
