/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Locking functions
   Copyright (C) Andrew Tridgell 1992-1999
   
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

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking

   May 1997. Jeremy Allison (jallison@whistle.com). Modified share mode
   locking to deal with multiple share modes per open file.

   September 1997. Jeremy Allison (jallison@whistle.com). Added oplock
   support.

   rewrtten completely to use new tdb code. Tridge, Dec '99
*/

#include "includes.h"
extern int DEBUGLEVEL;

/* the locking database handle */
static TDB_CONTEXT *tdb;

int global_smbpid;

/****************************************************************************
 Debugging aid :-).
****************************************************************************/

static const char *lock_type_name(enum brl_type lock_type)
{
	return (lock_type == READ_LOCK) ? "READ" : "WRITE";
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

static BOOL is_posix_locked(files_struct *fsp, SMB_BIG_UINT u_offset, SMB_BIG_UINT u_count, enum brl_type lock_type)
{
	SMB_OFF_T offset;
	SMB_OFF_T count;

	DEBUG(10,("is_posix_locked: File %s, offset = %.0f, count = %.0f, type = %s\n",
			fsp->fsp_name, (double)u_offset, (double)u_count, lock_type_name(lock_type) ));

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

	return fcntl_lock(fsp->fd,SMB_F_GETLK,offset,count,lock_type);
}

/****************************************************************************
 POSIX function to acquire a lock. Returns True if the
 lock could be granted, False if not.
****************************************************************************/

static BOOL set_posix_lock(files_struct *fsp, SMB_BIG_UINT u_offset, SMB_BIG_UINT u_count, enum brl_type lock_type)
{
	SMB_OFF_T offset;
	SMB_OFF_T count;
	BOOL ret = True;

	DEBUG(5,("set_posix_lock: File %s, offset = %.0f, count = %.0f, type = %s\n",
			fsp->fsp_name, (double)u_offset, (double)u_count, lock_type_name(lock_type) ));

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * pretend it was successful.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count))
		return True;

	/*
	 * Note that setting multiple overlapping read locks on different
	 * file descriptors will not be held separately by the kernel (POSIX
	 * braindamage), but will be merged into one continuous read lock
	 * range. We cope with this case in the release_posix_lock code
	 * below. JRA.
	 */

    ret = fcntl_lock(fsp->fd,SMB_F_SETLK,offset,count,map_posix_lock_type(fsp,lock_type)); 

	return ret;
}

/****************************************************************************
 POSIX function to release a lock. Returns True if the
 lock could be released, False if not.
****************************************************************************/

static BOOL release_posix_lock(files_struct *fsp, SMB_BIG_UINT u_offset, SMB_BIG_UINT u_count)
{
	SMB_OFF_T offset;
	SMB_OFF_T count;
	BOOL ret = True;

	DEBUG(5,("release_posix_lock: File %s, offset = %.0f, count = %.0f\n",
			fsp->fsp_name, (double)u_offset, (double)u_count ));

	if(u_count == 0) {

		/*
		 * This lock must overlap with an existing read-only lock
		 * help by another fd. Don't do any POSIX call.
		 */

		return True;
	}

	/*
	 * If the requested lock won't fit in the POSIX range, we will
	 * pretend it was successful.
	 */

	if(!posix_lock_in_range(&offset, &count, u_offset, u_count))
		return True;

	ret = fcntl_lock(fsp->fd,SMB_F_SETLK,offset,count,F_UNLCK);

	return ret;
}

/****************************************************************************
 Utility function called to see if a file region is locked.
****************************************************************************/

BOOL is_locked(files_struct *fsp,connection_struct *conn,
	       SMB_BIG_UINT count,SMB_BIG_UINT offset, 
	       enum brl_type lock_type)
{
	int snum = SNUM(conn);
	BOOL ret;
	
	if (count == 0)
		return(False);

	if (!lp_locking(snum) || !lp_strict_locking(snum))
		return(False);

	ret = !brl_locktest(fsp->dev, fsp->inode, 
			     global_smbpid, getpid(), conn->cnum, 
			     offset, count, lock_type);

	/*
	 * There is no lock held by an SMB daemon, check to
	 * see if there is a POSIX lock from a UNIX or NFS process.
	 */

	if(!ret && lp_posix_locking(snum))
		ret = is_posix_locked(fsp, offset, count, lock_type);

	return ret;
}

/****************************************************************************
 Utility function called by locking requests.
****************************************************************************/

BOOL do_lock(files_struct *fsp,connection_struct *conn,
             SMB_BIG_UINT count,SMB_BIG_UINT offset,enum brl_type lock_type,
             int *eclass,uint32 *ecode)
{
	BOOL ok = False;

	if (!lp_locking(SNUM(conn)))
		return(True);

	if (count == 0) {
		*eclass = ERRDOS;
		*ecode = ERRnoaccess;
		return False;
	}
	
	DEBUG(10,("do_lock: lock type %s start=%.0f len=%.0f requested for file %s\n",
		  lock_type_name(lock_type), (double)offset, (double)count, fsp->fsp_name ));

	if (OPEN_FSP(fsp) && fsp->can_lock && (fsp->conn == conn)) {
		ok = brl_lock(fsp->dev, fsp->inode, fsp->fnum,
			      global_smbpid, getpid(), conn->cnum, 
			      offset, count, 
			      lock_type);

		if(ok && lp_posix_locking(SNUM(conn))) {

			/*
			 * Try and get a POSIX lock on this range.
			 * Note that this is ok if it is a read lock
			 * overlapping on a different fd. JRA.
			 */

			if((ok = set_posix_lock(fsp, offset, count, lock_type)) == True)
				fsp->num_posix_locks++;
			else {
				/*
				 * We failed to map - we must now remove the brl
				 * lock entry.
				 */
				(void)brl_unlock(fsp->dev, fsp->inode, fsp->fnum,
								global_smbpid, getpid(), conn->cnum, 
								offset, count);
			}
		}
	}

	if (!ok) {
		*eclass = ERRDOS;
		*ecode = ERRlock;
		return False;
	}
	return True; /* Got lock */
}

/****************************************************************************
 Utility function called by unlocking requests.
****************************************************************************/

BOOL do_unlock(files_struct *fsp,connection_struct *conn,
               SMB_BIG_UINT count,SMB_BIG_UINT offset, 
	       int *eclass,uint32 *ecode)
{
	BOOL ok = False;
	TALLOC_CTX *ul_ctx = NULL;
	struct unlock_list *ulist = NULL;
	struct unlock_list *ul = NULL;
	pid_t pid;
	
	if (!lp_locking(SNUM(conn)))
		return(True);
	
	if (!OPEN_FSP(fsp) || !fsp->can_lock || (fsp->conn != conn)) {
		*eclass = ERRDOS;
		*ecode = ERRlock;
		return False;
	}
	
	DEBUG(10,("do_unlock: unlock start=%.0f len=%.0f requested for file %s\n",
		  (double)offset, (double)count, fsp->fsp_name ));

	/*
	 * Remove the existing lock record from the tdb lockdb
	 * before looking at POSIX locks. If this record doesn't
	 * match then don't bother looking to remove POSIX locks.
	 */

	pid = getpid();

	ok = brl_unlock(fsp->dev, fsp->inode, fsp->fnum,
			global_smbpid, pid, conn->cnum, offset, count);
   
	if (!ok) {
		*eclass = ERRDOS;
		*ecode = ERRlock;
		return False;
	}

	if (!lp_posix_locking(SNUM(conn)))
		return True;

	if ((ul_ctx = talloc_init()) == NULL) {
		DEBUG(0,("do_unlock: unable to init talloc context.\n"));
		return True; /* Not a fatal error. */
	}

	if ((ul = (struct unlock_list *)talloc(ul_ctx, sizeof(struct unlock_list))) == NULL) {
		DEBUG(0,("do_unlock: unable to talloc unlock list.\n"));
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
	 * overlapping read locks held by this process on
	 * other fd's open on the same file and creates a
	 * list of unlock ranges that will allow other
	 * POSIX lock ranges to remain on the file whilst the
	 * unlocks are performed.
	 */

	ulist = brl_unlock_list(ul_ctx, ulist, pid, fsp->dev, fsp->inode);

	/*
	 * Release the POSIX locks on the list of ranges returned.
	 */

	for(; ulist; ulist = ulist->next)
		(void)release_posix_lock(fsp, ulist->start, ulist->size);

	talloc_destroy(ul_ctx);

	/*
	 * We treat this as one unlock request for POSIX accounting purposes even
	 * if it may have been split into multiple smaller POSIX unlock ranges.
	 */

	fsp->num_posix_locks--;

	SMB_ASSERT(fsp->num_posix_locks >= 0);

	return True; /* Did unlock */
}

/****************************************************************************
 Remove any locks on this fd. Called from file_close().
****************************************************************************/

void locking_close_file(files_struct *fsp)
{
	pid_t pid = getpid();

	if (!lp_locking(SNUM(fsp->conn)))
		return;

	if(lp_posix_locking(SNUM(fsp->conn))) {

		TALLOC_CTX *ul_ctx = NULL;
		struct unlock_list *ul = NULL;
		int eclass;
		uint32 ecode;

		if ((ul_ctx = talloc_init()) == NULL) {
			DEBUG(0,("locking_close_file: unable to init talloc context.\n"));
			return;
		}

		/*
		 * We need to release all POSIX locks we have on this
		 * fd. Get all our existing locks from the tdb locking database.
		 */

		ul = brl_getlocklist(ul_ctx, fsp->dev, fsp->inode, pid, fsp->conn->cnum, fsp->fnum);

		/*
		 * Now unlock all of them. This will remove the brl entry also
		 * for each lock.
		 */

		for(; ul; ul = ul->next)
			do_unlock(fsp,fsp->conn,ul->size,ul->start,&eclass,&ecode);
		
		talloc_destroy(ul_ctx);

	} else {

		/*
		 * Just release all the tdb locks, no need to release individually.
		 */

		brl_close(fsp->dev, fsp->inode, pid, fsp->conn->cnum, fsp->fnum);
	}
}

/****************************************************************************
 Initialise the locking functions.
****************************************************************************/
BOOL locking_init(int read_only)
{
	brl_init(read_only);

	if (tdb) return True;

	tdb = tdb_open(lock_path("locking.tdb"), 
		       0, TDB_CLEAR_IF_FIRST, 
		       read_only?O_RDONLY:O_RDWR|O_CREAT,
		       0644);

	if (!tdb) {
		DEBUG(0,("ERROR: Failed to initialise share modes\n"));
		return False;
	}
	
	return True;
}

/*******************************************************************
 Deinitialize the share_mode management.
******************************************************************/
BOOL locking_end(void)
{
	if (tdb && tdb_close(tdb) != 0) return False;
	return True;
}

/*******************************************************************
 form a static locking key for a dev/inode pair 
******************************************************************/
static TDB_DATA locking_key(SMB_DEV_T dev, SMB_INO_T inode)
{
	static struct locking_key key;
	TDB_DATA kbuf;
	key.dev = dev;
	key.inode = inode;
	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);
	return kbuf;
}
static TDB_DATA locking_key_fsp(files_struct *fsp)
{
	return locking_key(fsp->dev, fsp->inode);
}

/*******************************************************************
 Lock a hash bucket entry.
******************************************************************/
BOOL lock_share_entry(connection_struct *conn,
		      SMB_DEV_T dev, SMB_INO_T inode)
{
	return tdb_lockchain(tdb, locking_key(dev, inode)) == 0;
}

/*******************************************************************
 Unlock a hash bucket entry.
******************************************************************/
BOOL unlock_share_entry(connection_struct *conn,
			SMB_DEV_T dev, SMB_INO_T inode)
{
	return tdb_unlockchain(tdb, locking_key(dev, inode)) == 0;
}


/*******************************************************************
 Lock a hash bucket entry. use a fsp for convenience
******************************************************************/
BOOL lock_share_entry_fsp(files_struct *fsp)
{
	return tdb_lockchain(tdb, locking_key(fsp->dev, fsp->inode)) == 0;
}

/*******************************************************************
 Unlock a hash bucket entry.
******************************************************************/
BOOL unlock_share_entry_fsp(files_struct *fsp)
{
	return tdb_unlockchain(tdb, locking_key(fsp->dev, fsp->inode)) == 0;
}

/*******************************************************************
 Get all share mode entries for a dev/inode pair.
********************************************************************/
int get_share_modes(connection_struct *conn, 
		    SMB_DEV_T dev, SMB_INO_T inode, 
		    share_mode_entry **shares)
{
	TDB_DATA dbuf;
	struct locking_data *data;
	int ret;

	*shares = NULL;

	dbuf = tdb_fetch(tdb, locking_key(dev, inode));
	if (!dbuf.dptr) return 0;

	data = (struct locking_data *)dbuf.dptr;
	ret = data->num_share_mode_entries;
	if(ret)
		*shares = (share_mode_entry *)memdup(dbuf.dptr + sizeof(*data), ret * sizeof(**shares));
	free(dbuf.dptr);

	if (! *shares) return 0;

	return ret;
}

/*******************************************************************
 Del the share mode of a file for this process
********************************************************************/
void del_share_mode(files_struct *fsp)
{
	TDB_DATA dbuf;
	struct locking_data *data;
	int i, del_count=0;
	share_mode_entry *shares;
	pid_t pid = getpid();

	/* read in the existing share modes */
	dbuf = tdb_fetch(tdb, locking_key_fsp(fsp));
	if (!dbuf.dptr) return;

	data = (struct locking_data *)dbuf.dptr;
	shares = (share_mode_entry *)(dbuf.dptr + sizeof(*data));

	/* find any with our pid and delete it by overwriting with the rest of the data 
	   from the record */
	for (i=0;i<data->num_share_mode_entries;) {
		if (shares[i].pid == pid &&
		    memcmp(&shares[i].time, 
			   &fsp->open_time,sizeof(struct timeval)) == 0) {
			data->num_share_mode_entries--;
			memmove(&shares[i], &shares[i+1], 
				dbuf.dsize - (sizeof(*data) + (i+1)*sizeof(*shares)));
			del_count++;
		} else {
			i++;
		}
	}

	/* the record has shrunk a bit */
	dbuf.dsize -= del_count * sizeof(*shares);

	/* store it back in the database */
	if (data->num_share_mode_entries == 0) {
		tdb_delete(tdb, locking_key_fsp(fsp));
	} else {
		tdb_store(tdb, locking_key_fsp(fsp), dbuf, TDB_REPLACE);
	}

	free(dbuf.dptr);
}

/*******************************************************************
fill a share mode entry
********************************************************************/
static void fill_share_mode(char *p, files_struct *fsp, uint16 port, uint16 op_type)
{
	share_mode_entry *e = (share_mode_entry *)p;
	e->pid = getpid();
	e->share_mode = fsp->share_mode;
	e->op_port = port;
	e->op_type = op_type;
	memcpy((char *)&e->time, (char *)&fsp->open_time, sizeof(struct timeval));
}

/*******************************************************************
 Set the share mode of a file. Return False on fail, True on success.
********************************************************************/
BOOL set_share_mode(files_struct *fsp, uint16 port, uint16 op_type)
{
	TDB_DATA dbuf;
	struct locking_data *data;
	share_mode_entry *shares;
	char *p=NULL;
	int size;
		
	/* read in the existing share modes if any */
	dbuf = tdb_fetch(tdb, locking_key_fsp(fsp));
	if (!dbuf.dptr) {
		/* we'll need to create a new record */
		pstring fname;

		pstrcpy(fname, fsp->conn->connectpath);
		pstrcat(fname, "/");
		pstrcat(fname, fsp->fsp_name);

		size = sizeof(*data) + sizeof(*shares) + strlen(fname) + 1;
		p = (char *)malloc(size);
		data = (struct locking_data *)p;
		shares = (share_mode_entry *)(p + sizeof(*data));
		data->num_share_mode_entries = 1;
		pstrcpy(p + sizeof(*data) + sizeof(*shares), fname);
		fill_share_mode(p + sizeof(*data), fsp, port, op_type);
		dbuf.dptr = p;
		dbuf.dsize = size;
		tdb_store(tdb, locking_key_fsp(fsp), dbuf, TDB_REPLACE);
		free(p);
		return True;
	}

	/* we're adding to an existing entry - this is a bit fiddly */
	data = (struct locking_data *)dbuf.dptr;
	shares = (share_mode_entry *)(dbuf.dptr + sizeof(*data));

	data->num_share_mode_entries++;
	size = dbuf.dsize + sizeof(*shares);
	p = malloc(size);
	memcpy(p, dbuf.dptr, sizeof(*data));
	fill_share_mode(p + sizeof(*data), fsp, port, op_type);
	memcpy(p + sizeof(*data) + sizeof(*shares), dbuf.dptr + sizeof(*data),
	       dbuf.dsize - sizeof(*data));
	free(dbuf.dptr);
	dbuf.dptr = p;
	dbuf.dsize = size;
	tdb_store(tdb, locking_key_fsp(fsp), dbuf, TDB_REPLACE);
	free(p);
	return True;
}


/*******************************************************************
a generic in-place modification call for share mode entries
********************************************************************/
static BOOL mod_share_mode(files_struct *fsp,
			   void (*mod_fn)(share_mode_entry *, SMB_DEV_T, SMB_INO_T, void *),
			   void *param)
{
	TDB_DATA dbuf;
	struct locking_data *data;
	int i;
	share_mode_entry *shares;
	pid_t pid = getpid();
	int need_store=0;

	/* read in the existing share modes */
	dbuf = tdb_fetch(tdb, locking_key_fsp(fsp));
	if (!dbuf.dptr) return False;

	data = (struct locking_data *)dbuf.dptr;
	shares = (share_mode_entry *)(dbuf.dptr + sizeof(*data));

	/* find any with our pid and call the supplied function */
	for (i=0;i<data->num_share_mode_entries;i++) {
		if (pid == shares[i].pid && 
		    shares[i].share_mode == fsp->share_mode &&
		    memcmp(&shares[i].time, 
			   &fsp->open_time,sizeof(struct timeval)) == 0) {
			mod_fn(&shares[i], fsp->dev, fsp->inode, param);
			need_store=1;
		}
	}

	/* if the mod fn was called then store it back */
	if (need_store) {
		if (data->num_share_mode_entries == 0) {
			tdb_delete(tdb, locking_key_fsp(fsp));
		} else {
			tdb_store(tdb, locking_key_fsp(fsp), dbuf, TDB_REPLACE);
		}
	}

	free(dbuf.dptr);
	return need_store;
}


/*******************************************************************
 Static function that actually does the work for the generic function
 below.
********************************************************************/
static void remove_share_oplock_fn(share_mode_entry *entry, SMB_DEV_T dev, SMB_INO_T inode, 
                                   void *param)
{
	DEBUG(10,("remove_share_oplock_fn: removing oplock info for entry dev=%x ino=%.0f\n",
		  (unsigned int)dev, (double)inode ));
	/* Delete the oplock info. */
	entry->op_port = 0;
	entry->op_type = NO_OPLOCK;
}

/*******************************************************************
 Remove an oplock port and mode entry from a share mode.
********************************************************************/
BOOL remove_share_oplock(files_struct *fsp)
{
	return mod_share_mode(fsp, remove_share_oplock_fn, NULL);
}

/*******************************************************************
 Static function that actually does the work for the generic function
 below.
********************************************************************/
static void downgrade_share_oplock_fn(share_mode_entry *entry, SMB_DEV_T dev, SMB_INO_T inode, 
                                   void *param)
{
	DEBUG(10,("downgrade_share_oplock_fn: downgrading oplock info for entry dev=%x ino=%.0f\n",
		  (unsigned int)dev, (double)inode ));
	entry->op_type = LEVEL_II_OPLOCK;
}

/*******************************************************************
 Downgrade a oplock type from exclusive to level II.
********************************************************************/
BOOL downgrade_share_oplock(files_struct *fsp)
{
	return mod_share_mode(fsp, downgrade_share_oplock_fn, NULL);
}


/*******************************************************************
 Static function that actually does the work for the generic function
 below.
********************************************************************/
struct mod_val {
	int new_share_mode;
	uint16 new_oplock;
};

static void modify_share_mode_fn(share_mode_entry *entry, SMB_DEV_T dev, SMB_INO_T inode, 
                                   void *param)
{
	struct mod_val *mvp = (struct mod_val *)param;

	DEBUG(10,("modify_share_mode_fn: changing share mode info from %x to %x for entry dev=%x ino=%.0f\n",
        entry->share_mode, mvp->new_share_mode, (unsigned int)dev, (double)inode ));
	DEBUG(10,("modify_share_mode_fn: changing oplock state from %x to %x for entry dev=%x ino=%.0f\n",
        entry->op_type, (int)mvp->new_oplock, (unsigned int)dev, (double)inode ));
	/* Change the share mode info. */
	entry->share_mode = mvp->new_share_mode;
	entry->op_type = mvp->new_oplock;
}

/*******************************************************************
 Modify a share mode on a file. Used by the delete open file code.
 Return False on fail, True on success.
********************************************************************/
BOOL modify_share_mode(files_struct *fsp, int new_mode, uint16 new_oplock)
{
	struct mod_val mv;

	mv.new_share_mode = new_mode;
	mv.new_oplock = new_oplock;

	return mod_share_mode(fsp, modify_share_mode_fn, (void *)&mv);
}


/****************************************************************************
traverse the whole database with this function, calling traverse_callback
on each share mode
****************************************************************************/
static int traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA kbuf, TDB_DATA dbuf, 
                       void* state)
{
	struct locking_data *data;
	share_mode_entry *shares;
	char *name;
	int i;

	SHAREMODE_FN(traverse_callback) = (SHAREMODE_FN_CAST())state;

	data = (struct locking_data *)dbuf.dptr;
	shares = (share_mode_entry *)(dbuf.dptr + sizeof(*data));
	name = dbuf.dptr + sizeof(*data) + data->num_share_mode_entries*sizeof(*shares);

	for (i=0;i<data->num_share_mode_entries;i++) {
		traverse_callback(&shares[i], name);
	}
	return 0;
}

/*******************************************************************
 Call the specified function on each entry under management by the
 share mode system.
********************************************************************/
int share_mode_forall(SHAREMODE_FN(fn))
{
	if (!tdb) return 0;
	return tdb_traverse(tdb, traverse_fn, (void*)fn);
}
