/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Locking functions
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

   Revision History:

   POSIX locking support. Jeremy Allison (jeremy@valinux.com), Apr. 2000.
*/

#include "includes.h"
extern int DEBUGLEVEL;
extern int global_smbpid;

/*
 * The POSIX locking database handle.
 */

static TDB_CONTEXT *posix_lock_tdb;

/*
 * The pending close database handle.
 */

static TDB_CONTEXT *posix_pending_close_tdb;

/*
 * The data in POSIX lock records is an unsorted linear array of these
 * records.  It is unnecessary to store the count as tdb provides the
 * size of the record.
 */

struct posix_lock {
	int fd;
	SMB_OFF_T start;
	SMB_OFF_T size;
	int lock_type;
};

/*
 * The data in POSIX pending close records is an unsorted linear array of int
 * records.  It is unnecessary to store the count as tdb provides the
 * size of the record.
 */

/* The key used in both the POSIX databases. */

struct posix_lock_key {
	SMB_DEV_T device;
	SMB_INO_T inode;
}; 

/*******************************************************************
 Form a static locking key for a dev/inode pair.
******************************************************************/

static TDB_DATA locking_key(SMB_DEV_T dev, SMB_INO_T inode)
{
	static struct posix_lock_key key;
	TDB_DATA kbuf;
	key.device = dev;
	key.inode = inode;
	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);
	return kbuf;
}

/*******************************************************************
 Convenience function to get a key from an fsp.
******************************************************************/

static TDB_DATA locking_key_fsp(files_struct *fsp)
{
	return locking_key(fsp->dev, fsp->inode);
}

/****************************************************************************
 Add an fd to the pending close tdb.
****************************************************************************/

static BOOL add_fd_to_close_entry(files_struct *fsp)
{
	TDB_DATA kbuf = locking_key_fsp(fsp);
	TDB_DATA dbuf;

	dbuf.dptr = NULL;

	dbuf = tdb_fetch(posix_pending_close_tdb, kbuf);

	dbuf.dptr = Realloc(dbuf.dptr, dbuf.dsize + sizeof(int));
	if (!dbuf.dptr) {
		DEBUG(0,("add_fd_to_close_entry: Realloc fail !\n"));
		return False;
	}
	memcpy(dbuf.dptr + dbuf.dsize, &fsp->fd, sizeof(int));
	dbuf.dsize += sizeof(int);

	if (tdb_store(posix_pending_close_tdb, kbuf, dbuf, TDB_REPLACE) == -1) {
		DEBUG(0,("add_fd_to_close_entry: tdb_store fail !\n"));
	}

	free(dbuf.dptr);
	return True;
}

/****************************************************************************
 Remove all fd entries for a specific dev/inode pair from the tdb.
****************************************************************************/

static void delete_close_entries(files_struct *fsp)
{
	TDB_DATA kbuf = locking_key_fsp(fsp);

	if (tdb_delete(posix_pending_close_tdb, kbuf) == -1)
		DEBUG(0,("delete_close_entries: tdb_delete fail !\n"));
}

/****************************************************************************
 Get the array of POSIX pending close records for an open fsp. Caller must
 free. Returns number of entries.
****************************************************************************/

static size_t get_posix_pending_close_entries(files_struct *fsp, int **entries)
{
	TDB_DATA kbuf = locking_key_fsp(fsp);
	TDB_DATA dbuf;
	size_t count = 0;

	*entries = NULL;
	dbuf.dptr = NULL;

	dbuf = tdb_fetch(posix_pending_close_tdb, kbuf);

    if (!dbuf.dptr) {
		return 0;
	}

	*entries = (int *)dbuf.dptr;
	count = (size_t)(dbuf.dsize / sizeof(int));

	return count;
}

/****************************************************************************
 Get the array of POSIX locks for an fsp. Caller must free. Returns
 number of entries.
****************************************************************************/

static size_t get_posix_lock_entries(files_struct *fsp, struct posix_lock **entries)
{
	TDB_DATA kbuf = locking_key_fsp(fsp);
	TDB_DATA dbuf;
	size_t count = 0;

	*entries = NULL;

	dbuf.dptr = NULL;

	dbuf = tdb_fetch(posix_lock_tdb, kbuf);

    if (!dbuf.dptr) {
		return 0;
	}

	*entries = (struct posix_lock *)dbuf.dptr;
	count = (size_t)(dbuf.dsize / sizeof(struct posix_lock));

	return count;
}

/****************************************************************************
 Deal with pending closes needed by POSIX locking support.
****************************************************************************/

int fd_close_posix(struct connection_struct *conn, files_struct *fsp)
{
	int saved_errno = 0;
	int ret;
	size_t count, i;
	struct posix_lock *entries = NULL;
	int *fd_array = NULL;

	if (!lp_posix_locking(SNUM(conn))) {
		/*
		 * No POSIX to worry about, just close.
		 */
		ret = conn->vfs_ops.close(fsp->fd);
		fsp->fd = -1;
		return ret;
	}

	/*
	 * Get the number of outstanding POSIX locks on this dev/inode pair.
	 */

	count = get_posix_lock_entries(fsp, &entries);
	
	if (count) {

		/*
		 * There are outstanding locks on this dev/inode pair on other fds.
		 * Add our fd to the pending close tdb and set fsp->fd to -1.
		 */

		if (!add_fd_to_close_entry(fsp)) {
			free((char *)entries);
			return False;
		}

		free((char *)entries);
		fsp->fd = -1;
		return 0;
	}

	if(entries)
		free((char *)entries);

	/*
	 * No outstanding POSIX locks. Get the pending close fd's
	 * from the tdb and close them all.
	 */

	count = get_posix_pending_close_entries(fsp, &fd_array);

	if (count) {
		DEBUG(10,("fd_close_posix: doing close on %u fd's.\n", (unsigned int)count ));

		for(i = 0; i < count; i++) {
			if (conn->vfs_ops.close(fd_array[i]) == -1) {
				saved_errno = errno;
			}
		}

		if (fd_array)
			free((char *)fd_array);

		/*
		 * Delete all fd's stored in the tdb
		 * for this dev/inode pair.
		 */

		delete_close_entries(fsp);
	}

	if (fd_array)
		free((char *)fd_array);

	/*
	 * Finally close the fd associated with this fsp.
	 */

	ret = conn->vfs_ops.close(fsp->fd);

	if (saved_errno != 0) {
        errno = saved_errno;
		ret = -1;
    } 

	fsp->fd = -1;

	return ret;
}

/****************************************************************************
 Debugging aid :-).
****************************************************************************/

static const char *posix_lock_type_name(int lock_type)
{
	return (lock_type == F_RDLCK) ? "READ" : "WRITE";
}

/****************************************************************************
 Add an entry into the POSIX locking tdb.
****************************************************************************/

static BOOL add_posix_lock_entry(files_struct *fsp, SMB_OFF_T start, SMB_OFF_T size, int lock_type)
{
	TDB_DATA kbuf = locking_key_fsp(fsp);
	TDB_DATA dbuf;
	struct posix_lock pl;

	/*
	 * Now setup the new record.
	 */

	pl.fd = fsp->fd;
	pl.start = start;
	pl.size = size;
	pl.lock_type = lock_type;

	dbuf.dptr = NULL;

	dbuf = tdb_fetch(posix_lock_tdb, kbuf);

	dbuf.dptr = Realloc(dbuf.dptr, dbuf.dsize + sizeof(pl));
	if (!dbuf.dptr) {
		DEBUG(0,("add_posix_lock_entry: Realloc fail !\n"));
		goto fail;
	}

	memcpy(dbuf.dptr + dbuf.dsize, &pl, sizeof(pl));
	dbuf.dsize += sizeof(pl);

	if (tdb_store(posix_lock_tdb, kbuf, dbuf, TDB_REPLACE) == -1) {
		DEBUG(0,("add_posix_lock: Failed to add lock entry on file %s\n", fsp->fsp_name));
		goto fail;
	}

    free(dbuf.dptr);

	DEBUG(10,("add_posix_lock: File %s: type = %s: start=%.0f size=%.0f:dev=%.0f inode=%.0f\n",
			fsp->fsp_name, posix_lock_type_name(lock_type), (double)start, (double)size,
			(double)fsp->dev, (double)fsp->inode ));

    return True;

 fail:
    if (dbuf.dptr)
		free(dbuf.dptr);
    return False;
}

/****************************************************************************
 Delete an entry from the POSIX locking tdb.
****************************************************************************/

static BOOL delete_posix_lock_entry(files_struct *fsp, SMB_OFF_T start, SMB_OFF_T size)
{
	TDB_DATA kbuf = locking_key_fsp(fsp);
	TDB_DATA dbuf;
	struct posix_lock *locks;
	size_t i, count;

	dbuf.dptr = NULL;

	dbuf = tdb_fetch(posix_lock_tdb, kbuf);

	if (!dbuf.dptr) {
		DEBUG(10,("delete_posix_lock_entry: tdb_fetch failed !\n"));
		goto fail;
	}

	/* There are existing locks - find a match. */
	locks = (struct posix_lock *)dbuf.dptr;
	count = (size_t)(dbuf.dsize / sizeof(*locks));

	for (i=0; i<count; i++) { 
		struct posix_lock *pl = &locks[i];

		if (pl->fd == fsp->fd &&
			pl->start == start &&
			pl->size == size) {
			/* Found it - delete it. */
			if (count == 1) {
				tdb_delete(posix_lock_tdb, kbuf);
			} else {
				if (i < count-1) {
					memmove(&locks[i], &locks[i+1], sizeof(*locks)*((count-1) - i));
				}
				dbuf.dsize -= sizeof(*locks);
				tdb_store(posix_lock_tdb, kbuf, dbuf, TDB_REPLACE);
			}

			free(dbuf.dptr);
			return True;
		}
	}

	/* We didn't find it. */

 fail:
    if (dbuf.dptr)
		free(dbuf.dptr);
    return False;
}

/****************************************************************************
 Utility function to map a lock type correctly depending on the open
 mode of a file.
****************************************************************************/

static int map_posix_lock_type( files_struct *fsp, enum brl_type lock_type)
{
	if((lock_type == WRITE_LOCK) && !fsp->can_write) {
		/*
		 * Many UNIX's cannot get a write lock on a file opened read-only.
		 * Win32 locking semantics allow this.
		 * Do the best we can and attempt a read-only lock.
		 */
		DEBUG(10,("map_posix_lock_type: Downgrading write lock to read due to read-only file.\n"));
		return F_RDLCK;
	} else if((lock_type == READ_LOCK) && !fsp->can_read) {
		/*
		 * Ditto for read locks on write only files.
		 */
		DEBUG(10,("map_posix_lock_type: Changing read lock to write due to write-only file.\n"));
		return F_WRLCK;
	}

  /*
   * This return should be the most normal, as we attempt
   * to always open files read/write.
   */

  return (lock_type == READ_LOCK) ? F_RDLCK : F_WRLCK;
}

/****************************************************************************
 Check to see if the given unsigned lock range is within the possible POSIX
 range. Modifies the given args to be in range if possible, just returns
 False if not.
****************************************************************************/

static BOOL posix_lock_in_range(SMB_OFF_T *offset_out, SMB_OFF_T *count_out,
								SMB_BIG_UINT u_offset, SMB_BIG_UINT u_count)
{
	SMB_OFF_T offset;
	SMB_OFF_T count;

#if defined(LARGE_SMB_OFF_T) && !defined(HAVE_BROKEN_FCNTL64_LOCKS)

    SMB_OFF_T mask2 = ((SMB_OFF_T)0x4) << (SMB_OFF_T_BITS-4);
    SMB_OFF_T mask = (mask2<<1);
    SMB_OFF_T neg_mask = ~mask;

	/*
	 * In this case SMB_OFF_T is 64 bits,
	 * and the underlying system can handle 64 bit signed locks.
	 * Cast to signed type.
	 */

	offset = (SMB_OFF_T)u_offset;
	count = (SMB_OFF_T)u_count;

	/*
	 * Deal with a very common case of count of all ones.
	 * (lock entire file).
	 */

	if(count == (SMB_OFF_T)-1)
		count &= ~mask;

	/*
	 * POSIX lock ranges cannot be negative.
	 * Fail if any combination becomes negative.
	 */

	if(offset < 0 || count < 0 || (offset + count < 0)) {
		DEBUG(10,("posix_lock_in_range: negative range: offset = %.0f, count = %.0f. Ignoring lock.\n",
				(double)offset, (double)count ));
		return False;
	}

	/*
	 * In this case SMB_OFF_T is 64 bits, the offset and count
	 * fit within the positive range, and the underlying
	 * system can handle 64 bit locks. Just return as the
	 * cast values are ok.
	 */

#else /* !LARGE_SMB_OFF_T || HAVE_BROKEN_FCNTL64_LOCKS */

	/*
	 * In this case either SMB_OFF_T is 32 bits,
	 * or the underlying system cannot handle 64 bit signed locks.
	 * Either way we have to try and mangle to fit within 31 bits.
	 * This is difficult.
	 */

#if defined(HAVE_BROKEN_FCNTL64_LOCKS)

	/*
	 * SMB_OFF_T is 64 bits, but we need to use 31 bits due to
	 * broken large locking.
	 */

	/*
	 * Deal with a very common case of count of all ones.
	 * (lock entire file).
	 */

	if(u_count == (SMB_BIG_UINT)-1)
		count = 0x7FFFFFFF;

	if(((u_offset >> 32) & 0xFFFFFFFF) || ((u_count >> 32) & 0xFFFFFFFF)) {
		DEBUG(10,("posix_lock_in_range: top 32 bits not zero. offset = %.0f, count = %.0f. Ignoring lock.\n",
				(double)u_offset, (double)u_count ));
		/* Top 32 bits of offset or count were not zero. */
		return False;
	}

	/* Cast from 64 bits unsigned to 64 bits signed. */
	offset = (SMB_OFF_T)u_offset;
	count = (SMB_OFF_T)u_count;

	/*
	 * Check if we are within the 2^31 range.
	 */

	{
		int32 low_offset = (int32)offset;
		int32 low_count = (int32)count;

		if(low_offset < 0 || low_count < 0 || (low_offset + low_count < 0)) {
			DEBUG(10,("posix_lock_in_range: not within 2^31 range. low_offset = %d, low_count = %d. Ignoring lock.\n",
					low_offset, low_count ));
			return False;
		}
	}

	/*
	 * Ok - we can map from a 64 bit number to a 31 bit lock.
	 */

#else /* HAVE_BROKEN_FCNTL64_LOCKS */

	/*
	 * SMB_OFF_T is 32 bits.
	 */

#if defined(HAVE_LONGLONG)

	/*
	 * SMB_BIG_UINT is 64 bits, we can do a 32 bit shift.
	 */

	/*
	 * Deal with a very common case of count of all ones.
	 * (lock entire file).
	 */

	if(u_count == (SMB_BIG_UINT)-1)
		count = 0x7FFFFFFF;

	if(((u_offset >> 32) & 0xFFFFFFFF) || ((u_count >> 32) & 0xFFFFFFFF)) {
		DEBUG(10,("posix_lock_in_range: top 32 bits not zero. u_offset = %.0f, u_count = %.0f. Ignoring lock.\n",
				(double)u_offset, (double)u_count ));
		return False;
	}

	/* Cast from 64 bits unsigned to 32 bits signed. */
	offset = (SMB_OFF_T)u_offset;
	count = (SMB_OFF_T)u_count;

	/*
	 * Check if we are within the 2^31 range.
	 */

	if(offset < 0 || count < 0 || (offset + count < 0)) {
		DEBUG(10,("posix_lock_in_range: not within 2^31 range. offset = %d, count = %d. Ignoring lock.\n",
				(int)offset, (int)count ));
		return False;
	}

#else /* HAVE_LONGLONG */

	/*
	 * SMB_BIG_UINT and SMB_OFF_T are both 32 bits,
	 * just cast.
	 */

	/*
	 * Deal with a very common case of count of all ones.
	 * (lock entire file).
	 */

	if(u_count == (SMB_BIG_UINT)-1)
		count = 0x7FFFFFFF;

	/* Cast from 32 bits unsigned to 32 bits signed. */
	offset = (SMB_OFF_T)u_offset;
	count = (SMB_OFF_T)u_count;

	/*
	 * Check if we are within the 2^31 range.
	 */

	if(offset < 0 || count < 0 || (offset + count < 0)) {
		DEBUG(10,("posix_lock_in_range: not within 2^31 range. offset = %d, count = %d. Ignoring lock.\n",
				(int)offset, (int)count ));
		return False;
	}

#endif /* HAVE_LONGLONG */
#endif /* LARGE_SMB_OFF_T */
#endif /* !LARGE_SMB_OFF_T || HAVE_BROKEN_FCNTL64_LOCKS */

	/*
	 * The mapping was successful.
	 */

	DEBUG(10,("posix_lock_in_range: offset_out = %.0f, count_out = %.0f\n",
			(double)offset, (double)count ));

	*offset_out = offset;
	*count_out = count;
	
	return True;
}

/****************************************************************************
 POSIX function to see if a file region is locked. Returns True if the
 region is locked, False otherwise.
****************************************************************************/

BOOL is_posix_locked(files_struct *fsp, SMB_BIG_UINT u_offset, SMB_BIG_UINT u_count, enum brl_type lock_type)
{
	SMB_OFF_T offset;
	SMB_OFF_T count;
	int posix_lock_type = map_posix_lock_type(fsp,lock_type);

	DEBUG(10,("is_posix_locked: File %s, offset = %.0f, count = %.0f, type = %s\n",
			fsp->fsp_name, (double)u_offset, (double)u_count, posix_lock_type_name(lock_type) ));

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * never set it, so presume it is not locked.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count))
		return False;

	/*
	 * Note that most UNIX's can *test* for a write lock on
	 * a read-only fd, just not *set* a write lock on a read-only
	 * fd. So we don't need to use map_lock_type here.
	 */ 

	return fcntl_lock(fsp->fd,SMB_F_GETLK,offset,count,posix_lock_type);
}

/****************************************************************************
 POSIX function to acquire a lock. Returns True if the
 lock could be granted, False if not.
****************************************************************************/

BOOL set_posix_lock(files_struct *fsp, SMB_BIG_UINT u_offset, SMB_BIG_UINT u_count, enum brl_type lock_type)
{
	SMB_OFF_T offset;
	SMB_OFF_T count;
	BOOL ret = True;
	int posix_lock_type = map_posix_lock_type(fsp,lock_type);

	DEBUG(5,("set_posix_lock: File %s, offset = %.0f, count = %.0f, type = %s\n",
			fsp->fsp_name, (double)u_offset, (double)u_count, posix_lock_type_name(lock_type) ));

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * pretend it was successful.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count))
		return True;

	/*
	 * Note that setting multiple overlapping locks on different
	 * file descriptors will not be held separately by the kernel (POSIX
	 * braindamage), but will be merged into one continuous lock
	 * range. We cope with this case in the release_posix_lock code
	 * below. JRA.
	 */

    ret = fcntl_lock(fsp->fd,SMB_F_SETLK,offset,count,posix_lock_type);

	if (ret)
		add_posix_lock_entry(fsp,offset,count,posix_lock_type);

	return ret;
}

/*
 * Structure used when splitting a lock range
 * into a POSIX lock range. Doubly linked list.
 */

struct unlock_list {
    struct unlock_list *next;
    struct unlock_list *prev;
    SMB_OFF_T start;
    SMB_OFF_T size;
};

/****************************************************************************
 Create a list of lock ranges that don't overlap a given range. Used in calculating
 POSIX lock unlocks. This is a difficult function that requires ASCII art to
 understand it :-).
****************************************************************************/

static struct unlock_list *posix_unlock_list(TALLOC_CTX *ctx, struct unlock_list *ulhead, files_struct *fsp)
{
	TDB_DATA kbuf = locking_key_fsp(fsp);
	TDB_DATA dbuf;
	struct posix_lock *locks;
	size_t num_locks, i;

	dbuf.dptr = NULL;

	dbuf = tdb_fetch(posix_lock_tdb, kbuf);

	if (!dbuf.dptr) {
		return ulhead;
	}
	
	locks = (struct posix_lock *)dbuf.dptr;
	num_locks = (size_t)(dbuf.dsize / sizeof(*locks));

	/*
	 * Check the current lock list on this dev/inode pair.
	 * Quit if the list is deleted.
	 */

	DEBUG(10,("posix_unlock_list: curr: start=%.0f,size=%.0f\n",
		(double)ulhead->start, (double)ulhead->size ));

	for (i=0; i<num_locks && ulhead; i++) {

		struct posix_lock *lock = &locks[i];
		struct unlock_list *ul_curr;

		/*
		 * Walk the unlock list, checking for overlaps. Note that
		 * the unlock list can expand within this loop if the current
		 * range being examined needs to be split.
		 */

		for (ul_curr = ulhead; ul_curr;) {

			DEBUG(10,("posix_unlock_list: lock: start=%.0f,size=%.0f:",
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
					DEBUG(0,("posix_unlock_list: talloc fail.\n"));
					return NULL; /* The talloc_destroy takes care of cleanup. */
				}

				ZERO_STRUCTP(ul_new);
				ul_new->start = lock->start + lock->size;
				ul_new->size = ul_curr->start + ul_curr->size - ul_new->start;

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

	if (dbuf.dptr)
		free(dbuf.dptr);
	
	return ulhead;
}

/****************************************************************************
 POSIX function to release a lock. Returns True if the
 lock could be released, False if not.
****************************************************************************/

BOOL release_posix_lock(files_struct *fsp, SMB_BIG_UINT u_offset, SMB_BIG_UINT u_count)
{
	SMB_OFF_T offset;
	SMB_OFF_T count;
	BOOL ret = True;
	TALLOC_CTX *ul_ctx = NULL;
	struct unlock_list *ulist = NULL;
	struct unlock_list *ul = NULL;

	DEBUG(5,("release_posix_lock: File %s, offset = %.0f, count = %.0f\n",
		fsp->fsp_name, (double)u_offset, (double)u_count ));

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * pretend it was successful.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count))
		return True;

	/*
	 * We treat this as one unlock request for POSIX accounting purposes even
	 * if it may have been split into multiple smaller POSIX unlock ranges.
	 */ 

	delete_posix_lock_entry(fsp, offset, count);

	if ((ul_ctx = talloc_init()) == NULL) {
        DEBUG(0,("release_posix_lock: unable to init talloc context.\n"));
		return True; /* Not a fatal error. */
	}

	if ((ul = (struct unlock_list *)talloc(ul_ctx, sizeof(struct unlock_list))) == NULL) {
		DEBUG(0,("release_posix_lock: unable to talloc unlock list.\n"));
		talloc_destroy(ul_ctx);
		return True; /* Not a fatal error. */
	}

	/*
	 * Create the initial list entry containing the
	 * lock we want to remove.
	 */

	ZERO_STRUCTP(ul);
	ul->start = offset;
	ul->size = count;

	DLIST_ADD(ulist, ul);

	/*
	 * The following call calculates if there are any
	 * overlapping locks held by this process on
	 * fd's open on the same file and creates a
	 * list of unlock ranges that will allow
	 * POSIX lock ranges to remain on the file whilst the
	 * unlocks are performed.
	 */

	ulist = posix_unlock_list(ul_ctx, ulist, fsp);

	/*
	 * Release the POSIX locks on the list of ranges returned.
	 */

	for(; ulist; ulist = ulist->next) {
		offset = ulist->start;
		count = ulist->size;

		if(u_count == 0) {

			/*
			 * This lock must overlap with an existing lock.
			 * Don't do any POSIX call.
			 */

			continue;
		}

		DEBUG(5,("release_posix_lock: Real unlock: offset = %.0f, count = %.0f\n",
			(double)offset, (double)count ));

		if (!fcntl_lock(fsp->fd,SMB_F_SETLK,offset,count,F_UNLCK))
			ret = False;
	}

    talloc_destroy(ul_ctx);

	return ret;
}

/****************************************************************************
 Remove all lock entries for a specific dev/inode pair from the tdb.
****************************************************************************/

static void delete_posix_lock_entries(files_struct *fsp)
{
	TDB_DATA kbuf = locking_key_fsp(fsp);

	if (tdb_delete(posix_lock_tdb, kbuf) == -1)
		DEBUG(0,("delete_close_entries: tdb_delete fail !\n"));
}

/****************************************************************************
 Debug function.
****************************************************************************/

void dump_entry(struct posix_lock *pl)
{
	DEBUG(10,("entry: start=%.0f, size=%.0f, type=%d, fd=%i\n",
		(double)pl->start, (double)pl->size, (int)pl->lock_type, pl->fd ));
}

/****************************************************************************
 Remove any locks on this fd. Called from file_close().
****************************************************************************/

void posix_locking_close_file(files_struct *fsp)
{
	struct posix_lock *entries = NULL;
	size_t count, i;

	/*
	 * Optimization for the common case where we are the only
	 * opener of a file. If all fd entries are our own, we don't
	 * need to explicitly release all the locks via the POSIX functions,
	 * we can just remove all the entries in the tdb and allow the
	 * close to remove the real locks.
	 */

	count = get_posix_lock_entries(fsp, &entries);

	if (count == 0) {
		DEBUG(10,("posix_locking_close_file: file %s has no outstanding locks.\n", fsp->fsp_name ));
		return;
	}

	for (i = 0; i < count; i++) {
		if (entries[i].fd != fsp->fd )
			break;

		dump_entry(&entries[i]);
	}

	if (i == count) {
		/* All locks are ours. */
		DEBUG(10,("posix_locking_close_file: file %s has %u outstanding locks, but all on one fd.\n", 
			fsp->fsp_name, (unsigned int)count ));
		free((char *)entries);
		delete_posix_lock_entries(fsp);
		return;
	}

	/*
	 * Difficult case. We need to delete all our locks, whilst leaving
	 * all other POSIX locks in place.
	 */

	for (i = 0; i < count; i++) {
		struct posix_lock *pl = &entries[i];
		release_posix_lock(fsp, (SMB_BIG_UINT)pl->start, (SMB_BIG_UINT)pl->size );
	}
	free((char *)entries);
}

/*******************************************************************
 Create the in-memory POSIX lock databases.
********************************************************************/

BOOL posix_locking_init(void)
{
	if (posix_lock_tdb && posix_pending_close_tdb)
		return True;

	if (!posix_lock_tdb)
		posix_lock_tdb = tdb_open(NULL, 0, TDB_CLEAR_IF_FIRST,
   	            O_RDWR|O_CREAT, 0644);
    if (!posix_lock_tdb) {
        DEBUG(0,("Failed to open POSIX byte range locking database.\n"));
		return False;
    }
	if (!posix_pending_close_tdb)
		posix_pending_close_tdb = tdb_open(NULL, 0, TDB_CLEAR_IF_FIRST,
   	            O_RDWR|O_CREAT, 0644);
    if (!posix_pending_close_tdb) {
        DEBUG(0,("Failed to open POSIX pending close database.\n"));
		return False;
    }

	return True;
}

/*******************************************************************
 Delete the in-memory POSIX lock databases.
********************************************************************/

BOOL posix_locking_end(void)
{
    if (posix_lock_tdb && tdb_close(posix_lock_tdb) != 0)
		return False;
    if (posix_pending_close_tdb && tdb_close(posix_pending_close_tdb) != 0)
		return False;
	return True;
}
