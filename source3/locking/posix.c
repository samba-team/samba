/* 
   Unix SMB/CIFS implementation.
   Locking functions
   Copyright (C) Jeremy Allison 1992-2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   Revision History:

   POSIX locking support. Jeremy Allison (jeremy@valinux.com), Apr. 2000.
*/

#include "includes.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "locking/proto.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "util_tdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

/*
 * The pending close database handle.
 */

static struct db_context *posix_pending_close_db;

/****************************************************************************
 First - the functions that deal with the underlying system locks - these
 functions are used no matter if we're mapping CIFS Windows locks or CIFS
 POSIX locks onto POSIX.
****************************************************************************/

/****************************************************************************
 Utility function to map a lock type correctly depending on the open
 mode of a file.
****************************************************************************/

static int map_posix_lock_type( files_struct *fsp, enum brl_type lock_type)
{
	if ((lock_type == WRITE_LOCK) && !fsp->fsp_flags.can_write) {
		/*
		 * Many UNIX's cannot get a write lock on a file opened read-only.
		 * Win32 locking semantics allow this.
		 * Do the best we can and attempt a read-only lock.
		 */
		DEBUG(10,("map_posix_lock_type: Downgrading write lock to read due to read-only file.\n"));
		return F_RDLCK;
	}

	/*
	 * This return should be the most normal, as we attempt
	 * to always open files read/write.
	 */

	return (lock_type == READ_LOCK) ? F_RDLCK : F_WRLCK;
}

/****************************************************************************
 Debugging aid :-).
****************************************************************************/

static const char *posix_lock_type_name(int lock_type)
{
	return (lock_type == F_RDLCK) ? "READ" : "WRITE";
}

/****************************************************************************
 Check to see if the given unsigned lock range is within the possible POSIX
 range. Modifies the given args to be in range if possible, just returns
 False if not.
****************************************************************************/

#define SMB_OFF_T_BITS (sizeof(off_t)*8)

static bool posix_lock_in_range(off_t *offset_out, off_t *count_out,
				uint64_t u_offset, uint64_t u_count)
{
	off_t offset = (off_t)u_offset;
	off_t count = (off_t)u_count;

	/*
	 * For the type of system we are, attempt to
	 * find the maximum positive lock offset as an off_t.
	 */

#if defined(MAX_POSITIVE_LOCK_OFFSET) /* Some systems have arbitrary limits. */

	off_t max_positive_lock_offset = (MAX_POSITIVE_LOCK_OFFSET);
#else
	/*
	 * In this case off_t is 64 bits,
	 * and the underlying system can handle 64 bit signed locks.
	 */

	off_t mask2 = ((off_t)0x4) << (SMB_OFF_T_BITS-4);
	off_t mask = (mask2<<1);
	off_t max_positive_lock_offset = ~mask;

#endif
	/*
	 * POSIX locks of length zero mean lock to end-of-file.
	 * Win32 locks of length zero are point probes. Ignore
	 * any Win32 locks of length zero. JRA.
	 */

	if (count == 0) {
		DEBUG(10,("posix_lock_in_range: count = 0, ignoring.\n"));
		return False;
	}

	/*
	 * If the given offset was > max_positive_lock_offset then we cannot map this at all
	 * ignore this lock.
	 */

	if (u_offset & ~((uint64_t)max_positive_lock_offset)) {
		DEBUG(10, ("posix_lock_in_range: (offset = %ju) offset > %ju "
			   "and we cannot handle this. Ignoring lock.\n",
			   (uintmax_t)u_offset,
			   (uintmax_t)max_positive_lock_offset));
		return False;
	}

	/*
	 * We must truncate the count to less than max_positive_lock_offset.
	 */

	if (u_count & ~((uint64_t)max_positive_lock_offset)) {
		count = max_positive_lock_offset;
	}

	/*
	 * Truncate count to end at max lock offset.
	 */

	if (offset > INT64_MAX - count ||
	    offset + count > max_positive_lock_offset) {
		count = max_positive_lock_offset - offset;
	}

	/*
	 * If we ate all the count, ignore this lock.
	 */

	if (count == 0) {
		DEBUG(10, ("posix_lock_in_range: Count = 0. Ignoring lock "
			   "u_offset = %ju, u_count = %ju\n",
			   (uintmax_t)u_offset,
			   (uintmax_t)u_count));
		return False;
	}

	/*
	 * The mapping was successful.
	 */

	DEBUG(10, ("posix_lock_in_range: offset_out = %ju, "
		   "count_out = %ju\n",
		   (uintmax_t)offset, (uintmax_t)count));

	*offset_out = offset;
	*count_out = count;
	
	return True;
}

bool smb_vfs_call_lock(struct vfs_handle_struct *handle,
		       struct files_struct *fsp, int op, off_t offset,
		       off_t count, int type)
{
	VFS_FIND(lock);
	return handle->fns->lock_fn(handle, fsp, op, offset, count, type);
}

/****************************************************************************
 Actual function that does POSIX locks. Copes with 64 -> 32 bit cruft and
 broken NFS implementations.
****************************************************************************/

static bool posix_fcntl_lock(files_struct *fsp, int op, off_t offset, off_t count, int type)
{
	bool ret;

	DEBUG(8,("posix_fcntl_lock %d %d %jd %jd %d\n",
		 fsp->fh->fd,op,(intmax_t)offset,(intmax_t)count,type));

	ret = SMB_VFS_LOCK(fsp, op, offset, count, type);

	if (!ret && ((errno == EFBIG) || (errno == ENOLCK) || (errno ==  EINVAL))) {

		if ((errno == EINVAL) &&
				(op != F_GETLK &&
				 op != F_SETLK &&
				 op != F_SETLKW)) {
			DEBUG(0,("WARNING: OFD locks in use and no kernel "
				"support. Try setting "
				"'smbd:force process locks = true' "
				"in smb.conf\n"));
		} else {
			DEBUG(0, ("WARNING: lock request at offset "
			  "%ju, length %ju returned\n",
			  (uintmax_t)offset, (uintmax_t)count));
			DEBUGADD(0, ("an %s error. This can happen when using 64 bit "
			     "lock offsets\n", strerror(errno)));
			DEBUGADD(0, ("on 32 bit NFS mounted file systems.\n"));
		}

		/*
		 * If the offset is > 0x7FFFFFFF then this will cause problems on
		 * 32 bit NFS mounted filesystems. Just ignore it.
		 */

		if (offset & ~((off_t)0x7fffffff)) {
			DEBUG(0,("Offset greater than 31 bits. Returning success.\n"));
			return True;
		}

		if (count & ~((off_t)0x7fffffff)) {
			/* 32 bit NFS file system, retry with smaller offset */
			DEBUG(0,("Count greater than 31 bits - retrying with 31 bit truncated length.\n"));
			errno = 0;
			count &= 0x7fffffff;
			ret = SMB_VFS_LOCK(fsp, op, offset, count, type);
		}
	}

	DEBUG(8,("posix_fcntl_lock: Lock call %s\n", ret ? "successful" : "failed"));
	return ret;
}

bool smb_vfs_call_getlock(struct vfs_handle_struct *handle,
			  struct files_struct *fsp, off_t *poffset,
			  off_t *pcount, int *ptype, pid_t *ppid)
{
	VFS_FIND(getlock);
	return handle->fns->getlock_fn(handle, fsp, poffset, pcount, ptype, 
				       ppid);
}

/****************************************************************************
 Actual function that gets POSIX locks. Copes with 64 -> 32 bit cruft and
 broken NFS implementations.
****************************************************************************/

static bool posix_fcntl_getlock(files_struct *fsp, off_t *poffset, off_t *pcount, int *ptype)
{
	pid_t pid;
	bool ret;

	DEBUG(8, ("posix_fcntl_getlock %d %ju %ju %d\n",
		  fsp->fh->fd, (uintmax_t)*poffset, (uintmax_t)*pcount,
		  *ptype));

	ret = SMB_VFS_GETLOCK(fsp, poffset, pcount, ptype, &pid);

	if (!ret && ((errno == EFBIG) || (errno == ENOLCK) || (errno ==  EINVAL))) {

		DEBUG(0, ("posix_fcntl_getlock: WARNING: lock request at "
			  "offset %ju, length %ju returned\n",
			  (uintmax_t)*poffset, (uintmax_t)*pcount));
		DEBUGADD(0, ("an %s error. This can happen when using 64 bit "
			     "lock offsets\n", strerror(errno)));
		DEBUGADD(0, ("on 32 bit NFS mounted file systems.\n"));

		/*
		 * If the offset is > 0x7FFFFFFF then this will cause problems on
		 * 32 bit NFS mounted filesystems. Just ignore it.
		 */

		if (*poffset & ~((off_t)0x7fffffff)) {
			DEBUG(0,("Offset greater than 31 bits. Returning success.\n"));
			return True;
		}

		if (*pcount & ~((off_t)0x7fffffff)) {
			/* 32 bit NFS file system, retry with smaller offset */
			DEBUG(0,("Count greater than 31 bits - retrying with 31 bit truncated length.\n"));
			errno = 0;
			*pcount &= 0x7fffffff;
			ret = SMB_VFS_GETLOCK(fsp,poffset,pcount,ptype,&pid);
		}
	}

	DEBUG(8,("posix_fcntl_getlock: Lock query call %s\n", ret ? "successful" : "failed"));
	return ret;
}

/****************************************************************************
 POSIX function to see if a file region is locked. Returns True if the
 region is locked, False otherwise.
****************************************************************************/

bool is_posix_locked(files_struct *fsp,
			uint64_t *pu_offset,
			uint64_t *pu_count,
			enum brl_type *plock_type,
			enum brl_flavour lock_flav)
{
	off_t offset;
	off_t count;
	int posix_lock_type = map_posix_lock_type(fsp,*plock_type);

	DEBUG(10, ("is_posix_locked: File %s, offset = %ju, count = %ju, "
		   "type = %s\n", fsp_str_dbg(fsp), (uintmax_t)*pu_offset,
		   (uintmax_t)*pu_count,  posix_lock_type_name(*plock_type)));

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * never set it, so presume it is not locked.
	 */

	if(!posix_lock_in_range(&offset, &count, *pu_offset, *pu_count)) {
		return False;
	}

	if (!posix_fcntl_getlock(fsp,&offset,&count,&posix_lock_type)) {
		return False;
	}

	if (posix_lock_type == F_UNLCK) {
		return False;
	}

	if (lock_flav == POSIX_LOCK) {
		/* Only POSIX lock queries need to know the details. */
		*pu_offset = (uint64_t)offset;
		*pu_count = (uint64_t)count;
		*plock_type = (posix_lock_type == F_RDLCK) ? READ_LOCK : WRITE_LOCK;
	}
	return True;
}

/****************************************************************************
 Next - the functions that deal with in memory database storing representations
 of either Windows CIFS locks or POSIX CIFS locks.
****************************************************************************/

/* The key used in the in-memory POSIX databases. */

struct lock_ref_count_key {
	struct file_id id;
	char r;
}; 

/*******************************************************************
 Form a static locking key for a dev/inode pair for the lock ref count
******************************************************************/

static TDB_DATA locking_ref_count_key_fsp(const files_struct *fsp,
					  struct lock_ref_count_key *tmp)
{
	ZERO_STRUCTP(tmp);
	tmp->id = fsp->file_id;
	tmp->r = 'r';
	return make_tdb_data((uint8_t *)tmp, sizeof(*tmp));
}

/*******************************************************************
 Convenience function to get an fd_array key from an fsp.
******************************************************************/

static TDB_DATA fd_array_key_fsp(const files_struct *fsp)
{
	return make_tdb_data((const uint8_t *)&fsp->file_id, sizeof(fsp->file_id));
}

/*******************************************************************
 Create the in-memory POSIX lock databases.
********************************************************************/

bool posix_locking_init(bool read_only)
{
	if (posix_pending_close_db != NULL) {
		return true;
	}

	posix_pending_close_db = db_open_rbt(NULL);

	if (posix_pending_close_db == NULL) {
		DEBUG(0,("Failed to open POSIX pending close database.\n"));
		return false;
	}

	return true;
}

/*******************************************************************
 Delete the in-memory POSIX lock databases.
********************************************************************/

bool posix_locking_end(void)
{
	/*
	 * Shouldn't we close all fd's here?
	 */
	TALLOC_FREE(posix_pending_close_db);
	return true;
}

/****************************************************************************
 Next - the functions that deal with reference count of number of locks open
 on a dev/ino pair.
****************************************************************************/

/****************************************************************************
 Increase the lock ref count. Creates lock_ref_count entry if it doesn't exist.
****************************************************************************/

static void increment_lock_ref_count(const files_struct *fsp)
{
	struct lock_ref_count_key tmp;
	int32_t lock_ref_count = 0;
	NTSTATUS status;

	status = dbwrap_change_int32_atomic(
		posix_pending_close_db, locking_ref_count_key_fsp(fsp, &tmp),
		&lock_ref_count, 1);

	SMB_ASSERT(NT_STATUS_IS_OK(status));
	SMB_ASSERT(lock_ref_count < INT32_MAX);

	DEBUG(10,("lock_ref_count for file %s = %d\n",
		  fsp_str_dbg(fsp), (int)(lock_ref_count + 1)));
}

/****************************************************************************
 Reduce the lock ref count.
****************************************************************************/

static void decrement_lock_ref_count(const files_struct *fsp)
{
	struct lock_ref_count_key tmp;
	int32_t lock_ref_count = 0;
	NTSTATUS status;

	status = dbwrap_change_int32_atomic(
		posix_pending_close_db, locking_ref_count_key_fsp(fsp, &tmp),
		&lock_ref_count, -1);

	SMB_ASSERT(NT_STATUS_IS_OK(status));
	SMB_ASSERT(lock_ref_count > 0);

	DEBUG(10,("lock_ref_count for file %s = %d\n",
		  fsp_str_dbg(fsp), (int)(lock_ref_count - 1)));
}

/****************************************************************************
 Fetch the lock ref count.
****************************************************************************/

static int32_t get_lock_ref_count(const files_struct *fsp)
{
	struct lock_ref_count_key tmp;
	NTSTATUS status;
	int32_t lock_ref_count = 0;

	status = dbwrap_fetch_int32(
		posix_pending_close_db, locking_ref_count_key_fsp(fsp, &tmp),
		&lock_ref_count);

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DEBUG(0, ("Error fetching "
			  "lock ref count for file %s: %s\n",
			  fsp_str_dbg(fsp), nt_errstr(status)));
	}
	return lock_ref_count;
}

/****************************************************************************
 Delete a lock_ref_count entry.
****************************************************************************/

static void delete_lock_ref_count(const files_struct *fsp)
{
	struct lock_ref_count_key tmp;

	/* Not a bug if it doesn't exist - no locks were ever granted. */

	dbwrap_delete(posix_pending_close_db,
		      locking_ref_count_key_fsp(fsp, &tmp));

	DEBUG(10,("delete_lock_ref_count for file %s\n",
		  fsp_str_dbg(fsp)));
}

/****************************************************************************
 Next - the functions that deal with storing fd's that have outstanding
 POSIX locks when closed.
****************************************************************************/

/****************************************************************************
 The records in posix_pending_close_db are composed of an array of
 ints keyed by dev/ino pair. Those ints are the fd's that were open on
 this dev/ino pair that should have been closed, but can't as the lock
 ref count is non zero.
****************************************************************************/

struct add_fd_to_close_entry_state {
	const struct files_struct *fsp;
};

static void add_fd_to_close_entry_fn(
	struct db_record *rec,
	TDB_DATA value,
	void *private_data)
{
	struct add_fd_to_close_entry_state *state = private_data;
	TDB_DATA values[] = {
		value,
		{ .dptr = (uint8_t *)&(state->fsp->fh->fd),
		  .dsize = sizeof(state->fsp->fh->fd) },
	};
	NTSTATUS status;

	SMB_ASSERT((values[0].dsize % sizeof(int)) == 0);

	status = dbwrap_record_storev(rec, values, ARRAY_SIZE(values), 0);
	SMB_ASSERT(NT_STATUS_IS_OK(status));
}

/****************************************************************************
 Add an fd to the pending close db.
****************************************************************************/

static void add_fd_to_close_entry(const files_struct *fsp)
{
	struct add_fd_to_close_entry_state state = { .fsp = fsp };
	NTSTATUS status;

	status = dbwrap_do_locked(
		posix_pending_close_db,
		fd_array_key_fsp(fsp),
		add_fd_to_close_entry_fn,
		&state);
	SMB_ASSERT(NT_STATUS_IS_OK(status));

	DBG_DEBUG("added fd %d file %s\n",
		  fsp->fh->fd,
		  fsp_str_dbg(fsp));
}

static void fd_close_posix_fn(
	struct db_record *rec,
	TDB_DATA data,
	void *private_data)
{
	size_t num_fds, i;

	SMB_ASSERT((data.dsize % sizeof(int)) == 0);
	num_fds = data.dsize / sizeof(int);

	for (i=0; i<num_fds; i++) {
		int fd;
		memcpy(&fd, data.dptr, sizeof(int));
		close(fd);
		data.dptr += sizeof(int);
	}
	dbwrap_record_delete(rec);
}

/****************************************************************************
 Deal with pending closes needed by POSIX locking support.
 Note that locking_close_file() is expected to have been called
 to delete all locks on this fsp before this function is called.
****************************************************************************/

int fd_close_posix(const struct files_struct *fsp)
{
	NTSTATUS status;

	if (!lp_locking(fsp->conn->params) ||
	    !lp_posix_locking(fsp->conn->params) ||
	    fsp->fsp_flags.use_ofd_locks)
	{
		/*
		 * No locking or POSIX to worry about or we are using POSIX
		 * open file description lock semantics which only removes
		 * locks on the file descriptor we're closing. Just close.
		 */
		return close(fsp->fh->fd);
	}

	if (get_lock_ref_count(fsp)) {

		/*
		 * There are outstanding locks on this dev/inode pair on
		 * other fds. Add our fd to the pending close db. We also
		 * set fsp->fh->fd to -1 inside fd_close() after returning
		 * from VFS layer.
		 */

		add_fd_to_close_entry(fsp);
		return 0;
	}

	status = dbwrap_do_locked(
		posix_pending_close_db,
		fd_array_key_fsp(fsp),
		fd_close_posix_fn,
		NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("dbwrap_do_locked failed: %s\n",
			    nt_errstr(status));
	}

	/* Don't need a lock ref count on this dev/ino anymore. */
	delete_lock_ref_count(fsp);

	/*
	 * Finally close the fd associated with this fsp.
	 */

	return close(fsp->fh->fd);
}

/****************************************************************************
 Next - the functions that deal with the mapping CIFS Windows locks onto
 the underlying system POSIX locks.
****************************************************************************/

/*
 * Structure used when splitting a lock range
 * into a POSIX lock range. Doubly linked list.
 */

struct lock_list {
	struct lock_list *next;
	struct lock_list *prev;
	off_t start;
	off_t size;
};

/****************************************************************************
 Create a list of lock ranges that don't overlap a given range. Used in calculating
 POSIX locks and unlocks. This is a difficult function that requires ASCII art to
 understand it :-).
****************************************************************************/

static struct lock_list *posix_lock_list(TALLOC_CTX *ctx,
						struct lock_list *lhead,
						const struct lock_context *lock_ctx, /* Lock context lhead belongs to. */
						const struct lock_struct *plocks,
						int num_locks)
{
	int i;

	/*
	 * Check the current lock list on this dev/inode pair.
	 * Quit if the list is deleted.
	 */

	DEBUG(10, ("posix_lock_list: curr: start=%ju,size=%ju\n",
		   (uintmax_t)lhead->start, (uintmax_t)lhead->size ));

	for (i=0; i<num_locks && lhead; i++) {
		const struct lock_struct *lock = &plocks[i];
		struct lock_list *l_curr;

		/* Ignore all but read/write locks. */
		if (lock->lock_type != READ_LOCK && lock->lock_type != WRITE_LOCK) {
			continue;
		}

		/* Ignore locks not owned by this process. */
		if (!server_id_equal(&lock->context.pid, &lock_ctx->pid)) {
			continue;
		}

		/*
		 * Walk the lock list, checking for overlaps. Note that
		 * the lock list can expand within this loop if the current
		 * range being examined needs to be split.
		 */

		for (l_curr = lhead; l_curr;) {

			DEBUG(10, ("posix_lock_list: lock: fnum=%ju: "
				   "start=%ju,size=%ju:type=%s",
				   (uintmax_t)lock->fnum,
				   (uintmax_t)lock->start,
				   (uintmax_t)lock->size,
				   posix_lock_type_name(lock->lock_type) ));

			if ( (l_curr->start >= (lock->start + lock->size)) ||
				 (lock->start >= (l_curr->start + l_curr->size))) {

				/* No overlap with existing lock - leave this range alone. */
/*********************************************
                                             +---------+
                                             | l_curr  |
                                             +---------+
                                +-------+
                                | lock  |
                                +-------+
OR....
             +---------+
             |  l_curr |
             +---------+
**********************************************/

				DEBUG(10,(" no overlap case.\n" ));

				l_curr = l_curr->next;

			} else if ( (l_curr->start >= lock->start) &&
						(l_curr->start + l_curr->size <= lock->start + lock->size) ) {

				/*
				 * This range is completely overlapped by this existing lock range
				 * and thus should have no effect. Delete it from the list.
				 */
/*********************************************
                +---------+
                |  l_curr |
                +---------+
        +---------------------------+
        |       lock                |
        +---------------------------+
**********************************************/
				/* Save the next pointer */
				struct lock_list *ul_next = l_curr->next;

				DEBUG(10,(" delete case.\n" ));

				DLIST_REMOVE(lhead, l_curr);
				if(lhead == NULL) {
					break; /* No more list... */
				}

				l_curr = ul_next;
				
			} else if ( (l_curr->start >= lock->start) &&
						(l_curr->start < lock->start + lock->size) &&
						(l_curr->start + l_curr->size > lock->start + lock->size) ) {

				/*
				 * This range overlaps the existing lock range at the high end.
				 * Truncate by moving start to existing range end and reducing size.
				 */
/*********************************************
                +---------------+
                |  l_curr       |
                +---------------+
        +---------------+
        |    lock       |
        +---------------+
BECOMES....
                        +-------+
                        | l_curr|
                        +-------+
**********************************************/

				l_curr->size = (l_curr->start + l_curr->size) - (lock->start + lock->size);
				l_curr->start = lock->start + lock->size;

				DEBUG(10, (" truncate high case: start=%ju,"
					   "size=%ju\n",
					   (uintmax_t)l_curr->start,
					   (uintmax_t)l_curr->size ));

				l_curr = l_curr->next;

			} else if ( (l_curr->start < lock->start) &&
						(l_curr->start + l_curr->size > lock->start) &&
						(l_curr->start + l_curr->size <= lock->start + lock->size) ) {

				/*
				 * This range overlaps the existing lock range at the low end.
				 * Truncate by reducing size.
				 */
/*********************************************
   +---------------+
   |  l_curr       |
   +---------------+
           +---------------+
           |    lock       |
           +---------------+
BECOMES....
   +-------+
   | l_curr|
   +-------+
**********************************************/

				l_curr->size = lock->start - l_curr->start;

				DEBUG(10, (" truncate low case: start=%ju,"
					   "size=%ju\n",
					   (uintmax_t)l_curr->start,
					   (uintmax_t)l_curr->size ));

				l_curr = l_curr->next;
		
			} else if ( (l_curr->start < lock->start) &&
						(l_curr->start + l_curr->size > lock->start + lock->size) ) {
				/*
				 * Worst case scenario. Range completely overlaps an existing
				 * lock range. Split the request into two, push the new (upper) request
				 * into the dlink list, and continue with the entry after l_new (as we
				 * know that l_new will not overlap with this lock).
				 */
/*********************************************
        +---------------------------+
        |        l_curr             |
        +---------------------------+
                +---------+
                | lock    |
                +---------+
BECOMES.....
        +-------+         +---------+
        | l_curr|         | l_new   |
        +-------+         +---------+
**********************************************/
				struct lock_list *l_new = talloc(ctx, struct lock_list);

				if(l_new == NULL) {
					DEBUG(0,("posix_lock_list: talloc fail.\n"));
					return NULL; /* The talloc_destroy takes care of cleanup. */
				}

				ZERO_STRUCTP(l_new);
				l_new->start = lock->start + lock->size;
				l_new->size = l_curr->start + l_curr->size - l_new->start;

				/* Truncate the l_curr. */
				l_curr->size = lock->start - l_curr->start;

				DEBUG(10, (" split case: curr: start=%ju,"
					   "size=%ju new: start=%ju,"
					   "size=%ju\n",
					   (uintmax_t)l_curr->start,
					   (uintmax_t)l_curr->size,
					   (uintmax_t)l_new->start,
					   (uintmax_t)l_new->size ));

				/*
				 * Add into the dlink list after the l_curr point - NOT at lhead. 
				 */
				DLIST_ADD_AFTER(lhead, l_new, l_curr);

				/* And move after the link we added. */
				l_curr = l_new->next;

			} else {

				/*
				 * This logic case should never happen. Ensure this is the
				 * case by forcing an abort.... Remove in production.
				 */
				char *msg = NULL;

				if (asprintf(&msg, "logic flaw in cases: "
					     "l_curr: start = %ju, "
					     "size = %ju : lock: "
					     "start = %ju, size = %ju",
					     (uintmax_t)l_curr->start,
					     (uintmax_t)l_curr->size,
					     (uintmax_t)lock->start,
					     (uintmax_t)lock->size ) != -1) {
					smb_panic(msg);
				} else {
					smb_panic("posix_lock_list");
				}
			}
		} /* end for ( l_curr = lhead; l_curr;) */
	} /* end for (i=0; i<num_locks && ul_head; i++) */

	return lhead;
}

/****************************************************************************
 POSIX function to acquire a lock. Returns True if the
 lock could be granted, False if not.
****************************************************************************/

bool set_posix_lock_windows_flavour(files_struct *fsp,
			uint64_t u_offset,
			uint64_t u_count,
			enum brl_type lock_type,
			const struct lock_context *lock_ctx,
			const struct lock_struct *plocks,
			int num_locks,
			int *errno_ret)
{
	off_t offset;
	off_t count;
	int posix_lock_type = map_posix_lock_type(fsp,lock_type);
	bool ret = True;
	size_t lock_count;
	TALLOC_CTX *l_ctx = NULL;
	struct lock_list *llist = NULL;
	struct lock_list *ll = NULL;

	DEBUG(5, ("set_posix_lock_windows_flavour: File %s, offset = %ju, "
		  "count = %ju, type = %s\n", fsp_str_dbg(fsp),
		  (uintmax_t)u_offset, (uintmax_t)u_count,
		  posix_lock_type_name(lock_type)));

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * pretend it was successful.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count)) {
		increment_lock_ref_count(fsp);
		return True;
	}

	/*
	 * Windows is very strange. It allows read locks to be overlayed
	 * (even over a write lock), but leaves the write lock in force until the first
	 * unlock. It also reference counts the locks. This means the following sequence :
	 *
	 * process1                                      process2
	 * ------------------------------------------------------------------------
	 * WRITE LOCK : start = 2, len = 10
	 *                                            READ LOCK: start =0, len = 10 - FAIL
	 * READ LOCK : start = 0, len = 14 
	 *                                            READ LOCK: start =0, len = 10 - FAIL
	 * UNLOCK : start = 2, len = 10
	 *                                            READ LOCK: start =0, len = 10 - OK
	 *
	 * Under POSIX, the same sequence in steps 1 and 2 would not be reference counted, but
	 * would leave a single read lock over the 0-14 region.
	 */
	
	if ((l_ctx = talloc_init("set_posix_lock")) == NULL) {
		DEBUG(0,("set_posix_lock_windows_flavour: unable to init talloc context.\n"));
		return False;
	}

	if ((ll = talloc(l_ctx, struct lock_list)) == NULL) {
		DEBUG(0,("set_posix_lock_windows_flavour: unable to talloc unlock list.\n"));
		talloc_destroy(l_ctx);
		return False;
	}

	/*
	 * Create the initial list entry containing the
	 * lock we want to add.
	 */

	ZERO_STRUCTP(ll);
	ll->start = offset;
	ll->size = count;

	DLIST_ADD(llist, ll);

	/*
	 * The following call calculates if there are any
	 * overlapping locks held by this process on
	 * fd's open on the same file and splits this list
	 * into a list of lock ranges that do not overlap with existing
	 * POSIX locks.
	 */

	llist = posix_lock_list(l_ctx,
				llist,
				lock_ctx, /* Lock context llist belongs to. */
				plocks,
				num_locks);

	/*
	 * Add the POSIX locks on the list of ranges returned.
	 * As the lock is supposed to be added atomically, we need to
	 * back out all the locks if any one of these calls fail.
	 */

	for (lock_count = 0, ll = llist; ll; ll = ll->next, lock_count++) {
		offset = ll->start;
		count = ll->size;

		DEBUG(5, ("set_posix_lock_windows_flavour: Real lock: "
			  "Type = %s: offset = %ju, count = %ju\n",
			  posix_lock_type_name(posix_lock_type),
			  (uintmax_t)offset, (uintmax_t)count ));

		if (!posix_fcntl_lock(fsp,F_SETLK,offset,count,posix_lock_type)) {
			*errno_ret = errno;
			DEBUG(5, ("set_posix_lock_windows_flavour: Lock "
				  "fail !: Type = %s: offset = %ju, "
				  "count = %ju. Errno = %s\n",
				  posix_lock_type_name(posix_lock_type),
				  (uintmax_t)offset, (uintmax_t)count,
				  strerror(errno) ));
			ret = False;
			break;
		}
	}

	if (!ret) {

		/*
		 * Back out all the POSIX locks we have on fail.
		 */

		for (ll = llist; lock_count; ll = ll->next, lock_count--) {
			offset = ll->start;
			count = ll->size;

			DEBUG(5, ("set_posix_lock_windows_flavour: Backing "
				  "out locks: Type = %s: offset = %ju, "
				  "count = %ju\n",
				  posix_lock_type_name(posix_lock_type),
				  (uintmax_t)offset, (uintmax_t)count ));

			posix_fcntl_lock(fsp,F_SETLK,offset,count,F_UNLCK);
		}
	} else {
		/* Remember the number of locks we have on this dev/ino pair. */
		increment_lock_ref_count(fsp);
	}

	talloc_destroy(l_ctx);
	return ret;
}

/****************************************************************************
 POSIX function to release a lock. Returns True if the
 lock could be released, False if not.
****************************************************************************/

bool release_posix_lock_windows_flavour(files_struct *fsp,
				uint64_t u_offset,
				uint64_t u_count,
				enum brl_type deleted_lock_type,
				const struct lock_context *lock_ctx,
				const struct lock_struct *plocks,
				int num_locks)
{
	off_t offset;
	off_t count;
	bool ret = True;
	TALLOC_CTX *ul_ctx = NULL;
	struct lock_list *ulist = NULL;
	struct lock_list *ul = NULL;

	DEBUG(5, ("release_posix_lock_windows_flavour: File %s, offset = %ju, "
		  "count = %ju\n", fsp_str_dbg(fsp),
		  (uintmax_t)u_offset, (uintmax_t)u_count));

	/* Remember the number of locks we have on this dev/ino pair. */
	decrement_lock_ref_count(fsp);

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * pretend it was successful.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count)) {
		return True;
	}

	if ((ul_ctx = talloc_init("release_posix_lock")) == NULL) {
		DEBUG(0,("release_posix_lock_windows_flavour: unable to init talloc context.\n"));
		return False;
	}

	if ((ul = talloc(ul_ctx, struct lock_list)) == NULL) {
		DEBUG(0,("release_posix_lock_windows_flavour: unable to talloc unlock list.\n"));
		talloc_destroy(ul_ctx);
		return False;
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

	ulist = posix_lock_list(ul_ctx,
				ulist,
				lock_ctx, /* Lock context ulist belongs to. */
				plocks,
				num_locks);

	/*
	 * If there were any overlapped entries (list is > 1 or size or start have changed),
	 * and the lock_type we just deleted from
	 * the upper layer tdb was a write lock, then before doing the unlock we need to downgrade
	 * the POSIX lock to a read lock. This allows any overlapping read locks
	 * to be atomically maintained.
	 */

	if (deleted_lock_type == WRITE_LOCK &&
			(!ulist || ulist->next != NULL || ulist->start != offset || ulist->size != count)) {

		DEBUG(5, ("release_posix_lock_windows_flavour: downgrading "
			  "lock to READ: offset = %ju, count = %ju\n",
			  (uintmax_t)offset, (uintmax_t)count ));

		if (!posix_fcntl_lock(fsp,F_SETLK,offset,count,F_RDLCK)) {
			DEBUG(0,("release_posix_lock_windows_flavour: downgrade of lock failed with error %s !\n", strerror(errno) ));
			talloc_destroy(ul_ctx);
			return False;
		}
	}

	/*
	 * Release the POSIX locks on the list of ranges returned.
	 */

	for(; ulist; ulist = ulist->next) {
		offset = ulist->start;
		count = ulist->size;

		DEBUG(5, ("release_posix_lock_windows_flavour: Real unlock: "
			  "offset = %ju, count = %ju\n",
			  (uintmax_t)offset, (uintmax_t)count ));

		if (!posix_fcntl_lock(fsp,F_SETLK,offset,count,F_UNLCK)) {
			ret = False;
		}
	}

	talloc_destroy(ul_ctx);
	return ret;
}

/****************************************************************************
 Next - the functions that deal with mapping CIFS POSIX locks onto
 the underlying system POSIX locks.
****************************************************************************/

/****************************************************************************
 We only increment the lock ref count when we see a POSIX lock on a context
 that doesn't already have them.
****************************************************************************/

static void increment_posix_lock_count(const files_struct *fsp,
					uint64_t smblctx)
{
	NTSTATUS status;
	TDB_DATA ctx_key;
	TDB_DATA val = { 0 };

	ctx_key.dptr = (uint8_t *)&smblctx;
	ctx_key.dsize = sizeof(smblctx);

	/*
	 * Don't increment if we already have any POSIX flavor
	 * locks on this context.
	 */
	if (dbwrap_exists(posix_pending_close_db, ctx_key)) {
		return;
	}

	/* Remember that we have POSIX flavor locks on this context. */
	status = dbwrap_store(posix_pending_close_db, ctx_key, val, 0);
	SMB_ASSERT(NT_STATUS_IS_OK(status));

	increment_lock_ref_count(fsp);

	DEBUG(10,("posix_locks set for file %s\n",
		fsp_str_dbg(fsp)));
}

static void decrement_posix_lock_count(const files_struct *fsp, uint64_t smblctx)
{
	NTSTATUS status;
	TDB_DATA ctx_key;

	ctx_key.dptr = (uint8_t *)&smblctx;
	ctx_key.dsize = sizeof(smblctx);

	status = dbwrap_delete(posix_pending_close_db, ctx_key);
	SMB_ASSERT(NT_STATUS_IS_OK(status));

	decrement_lock_ref_count(fsp);

	DEBUG(10,("posix_locks deleted for file %s\n",
		fsp_str_dbg(fsp)));
}

/****************************************************************************
 Return true if any locks exist on the given lock context.
****************************************************************************/

static bool locks_exist_on_context(const struct lock_struct *plocks,
				int num_locks,
				const struct lock_context *lock_ctx)
{
	int i;

	for (i=0; i < num_locks; i++) {
		const struct lock_struct *lock = &plocks[i];

		/* Ignore all but read/write locks. */
		if (lock->lock_type != READ_LOCK && lock->lock_type != WRITE_LOCK) {
			continue;
		}

		/* Ignore locks not owned by this process. */
		if (!server_id_equal(&lock->context.pid, &lock_ctx->pid)) {
			continue;
		}

		if (lock_ctx->smblctx == lock->context.smblctx) {
			return true;
		}
	}
	return false;
}

/****************************************************************************
 POSIX function to acquire a lock. Returns True if the
 lock could be granted, False if not.
 As POSIX locks don't stack or conflict (they just overwrite)
 we can map the requested lock directly onto a system one. We
 know it doesn't conflict with locks on other contexts as the
 upper layer would have refused it.
****************************************************************************/

bool set_posix_lock_posix_flavour(files_struct *fsp,
			uint64_t u_offset,
			uint64_t u_count,
			enum brl_type lock_type,
			const struct lock_context *lock_ctx,
			int *errno_ret)
{
	off_t offset;
	off_t count;
	int posix_lock_type = map_posix_lock_type(fsp,lock_type);

	DEBUG(5,("set_posix_lock_posix_flavour: File %s, offset = %ju, count "
		 "= %ju, type = %s\n", fsp_str_dbg(fsp),
		 (uintmax_t)u_offset, (uintmax_t)u_count,
		 posix_lock_type_name(lock_type)));

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * pretend it was successful.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count)) {
		increment_posix_lock_count(fsp, lock_ctx->smblctx);
		return True;
	}

	if (!posix_fcntl_lock(fsp,F_SETLK,offset,count,posix_lock_type)) {
		*errno_ret = errno;
		DEBUG(5,("set_posix_lock_posix_flavour: Lock fail !: Type = %s: offset = %ju, count = %ju. Errno = %s\n",
			posix_lock_type_name(posix_lock_type), (intmax_t)offset, (intmax_t)count, strerror(errno) ));
		return False;
	}
	increment_posix_lock_count(fsp, lock_ctx->smblctx);
	return True;
}

/****************************************************************************
 POSIX function to release a lock. Returns True if the
 lock could be released, False if not.
 We are given a complete lock state from the upper layer which is what the lock
 state should be after the unlock has already been done, so what
 we do is punch out holes in the unlock range where locks owned by this process
 have a different lock context.
****************************************************************************/

bool release_posix_lock_posix_flavour(files_struct *fsp,
				uint64_t u_offset,
				uint64_t u_count,
				const struct lock_context *lock_ctx,
				const struct lock_struct *plocks,
				int num_locks)
{
	bool ret = True;
	off_t offset;
	off_t count;
	TALLOC_CTX *ul_ctx = NULL;
	struct lock_list *ulist = NULL;
	struct lock_list *ul = NULL;

	DEBUG(5, ("release_posix_lock_posix_flavour: File %s, offset = %ju, "
		  "count = %ju\n", fsp_str_dbg(fsp),
		  (uintmax_t)u_offset, (uintmax_t)u_count));

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * pretend it was successful.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count)) {
		if (!locks_exist_on_context(plocks, num_locks, lock_ctx)) {
			decrement_posix_lock_count(fsp, lock_ctx->smblctx);
		}
		return True;
	}

	if ((ul_ctx = talloc_init("release_posix_lock")) == NULL) {
		DEBUG(0,("release_posix_lock_windows_flavour: unable to init talloc context.\n"));
		return False;
	}

	if ((ul = talloc(ul_ctx, struct lock_list)) == NULL) {
		DEBUG(0,("release_posix_lock_windows_flavour: unable to talloc unlock list.\n"));
		talloc_destroy(ul_ctx);
		return False;
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
	 * Walk the given array creating a linked list
	 * of unlock requests.
	 */

	ulist = posix_lock_list(ul_ctx,
				ulist,
				lock_ctx, /* Lock context ulist belongs to. */
				plocks,
				num_locks);

	/*
	 * Release the POSIX locks on the list of ranges returned.
	 */

	for(; ulist; ulist = ulist->next) {
		offset = ulist->start;
		count = ulist->size;

		DEBUG(5, ("release_posix_lock_posix_flavour: Real unlock: "
			  "offset = %ju, count = %ju\n",
			  (uintmax_t)offset, (uintmax_t)count ));

		if (!posix_fcntl_lock(fsp,F_SETLK,offset,count,F_UNLCK)) {
			ret = False;
		}
	}

	if (!locks_exist_on_context(plocks, num_locks, lock_ctx)) {
		decrement_posix_lock_count(fsp, lock_ctx->smblctx);
	}
	talloc_destroy(ul_ctx);
	return ret;
}
