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

/****************************************************************************
 Utility function to map a lock type correctly depending on the real open
 mode of a file.
****************************************************************************/
static int map_lock_type(files_struct *fsp, int lock_type)
{
	if((lock_type == F_WRLCK) && (fsp->fd_ptr->real_open_flags == O_RDONLY)) {
		/*
		 * Many UNIX's cannot get a write lock on a file opened read-only.
		 * Win32 locking semantics allow this.
		 * Do the best we can and attempt a read-only lock.
		 */
		DEBUG(10,("map_lock_type: Downgrading write lock to read due to read-only file.\n"));
		return F_RDLCK;
	} else if( (lock_type == F_RDLCK) && (fsp->fd_ptr->real_open_flags == O_WRONLY)) {
		/*
		 * Ditto for read locks on write only files.
		 */
		DEBUG(10,("map_lock_type: Changing read lock to write due to write-only file.\n"));
		return F_WRLCK;
	}
	
	/*
	 * This return should be the most normal, as we attempt
	 * to always open files read/write.
	 */
	
	return lock_type;
}

/****************************************************************************
 Utility function called to see if a file region is locked.
****************************************************************************/
BOOL is_locked(files_struct *fsp,connection_struct *conn,
	       SMB_OFF_T count,SMB_OFF_T offset, int lock_type)
{
	int snum = SNUM(conn);
	
	if (count == 0)
		return(False);

	if (!lp_locking(snum) || !lp_strict_locking(snum))
		return(False);

	/*
	 * Note that most UNIX's can *test* for a write lock on
	 * a read-only fd, just not *set* a write lock on a read-only
	 * fd. So we don't need to use map_lock_type here.
	 */
	
	return(fcntl_lock(fsp->fd_ptr->fd,SMB_F_GETLK,offset,count,lock_type));
}


/****************************************************************************
 Utility function called by locking requests.
****************************************************************************/
BOOL do_lock(files_struct *fsp,connection_struct *conn,
             SMB_OFF_T count,SMB_OFF_T offset,int lock_type,
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
	
	DEBUG(10,("do_lock: lock type %d start=%.0f len=%.0f requested for file %s\n",
		  lock_type, (double)offset, (double)count, fsp->fsp_name ));

	if (OPEN_FSP(fsp) && fsp->can_lock && (fsp->conn == conn))
		ok = fcntl_lock(fsp->fd_ptr->fd,SMB_F_SETLK,offset,count,
				map_lock_type(fsp,lock_type));

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
               SMB_OFF_T count,SMB_OFF_T offset,int *eclass,uint32 *ecode)
{
	BOOL ok = False;
	
	if (!lp_locking(SNUM(conn)))
		return(True);
	
	DEBUG(10,("do_unlock: unlock start=%.0f len=%.0f requested for file %s\n",
		  (double)offset, (double)count, fsp->fsp_name ));
	
	if (OPEN_FSP(fsp) && fsp->can_lock && (fsp->conn == conn))
		ok = fcntl_lock(fsp->fd_ptr->fd,SMB_F_SETLK,offset,count,F_UNLCK);
   
	if (!ok) {
		*eclass = ERRDOS;
		*ecode = ERRlock;
		return False;
	}
	return True; /* Did unlock */
}

/****************************************************************************
 Initialise the locking functions.
****************************************************************************/
BOOL locking_init(int read_only)
{
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
	return locking_key(fsp->fd_ptr->dev, fsp->fd_ptr->inode);
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
	tdb_store(tdb, locking_key_fsp(fsp), dbuf, TDB_REPLACE);

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
			mod_fn(&shares[i], fsp->fd_ptr->dev, fsp->fd_ptr->inode, param);
			need_store=1;
		}
	}

	/* if the mod fn was called then store it back */
	if (need_store) {
		tdb_store(tdb, locking_key_fsp(fsp), dbuf, TDB_REPLACE);
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

static void (*traverse_callback)(share_mode_entry *, char *);

/****************************************************************************
traverse the whole database with this function, calling traverse_callback
on each share mode
****************************************************************************/
int traverse_fn(TDB_CONTEXT *tdb, TDB_DATA kbuf, TDB_DATA dbuf)
{
	struct locking_data *data;
	share_mode_entry *shares;
	char *name;
	int i;

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
int share_mode_forall(void (*fn)(share_mode_entry *, char *))
{
	if (!tdb) return 0;
	traverse_callback = fn;
	return tdb_traverse(tdb, traverse_fn);
}
