/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Locking functions
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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking

   May 1997. Jeremy Allison (jallison@whistle.com). Modified share mode
   locking to deal with multiple share modes per open file.

   September 1997. Jeremy Allison (jallison@whistle.com). Added oplock
   support.

*/

#include "includes.h"
extern int DEBUGLEVEL;

static struct share_ops *share_ops;

/****************************************************************************
 Utility function to map a lock type correctly depending on the real open
 mode of a file.
****************************************************************************/

static int map_lock_type( files_struct *fsp, int lock_type)
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
	       uint32 count,uint32 offset, int lock_type)
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
	
	return(fcntl_lock(fsp->fd_ptr->fd,F_GETLK,offset,count,lock_type));
}


/****************************************************************************
 Utility function called by locking requests.
****************************************************************************/
BOOL do_lock(files_struct *fsp,connection_struct *conn,
	     uint32 count,uint32 offset,int lock_type,
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

  DEBUG(10,("do_lock: lock type %d start=%d len=%d requested for file %s\n",
        lock_type, (int)offset, (int)count, fsp->fsp_name ));

  if (OPEN_FSP(fsp) && fsp->can_lock && (fsp->conn == conn))
    ok = fcntl_lock(fsp->fd_ptr->fd,F_SETLK,offset,count,
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
	       uint32 count,uint32 offset,int *eclass,uint32 *ecode)
{
  BOOL ok = False;

  if (!lp_locking(SNUM(conn)))
    return(True);

  DEBUG(10,("do_unlock: unlock start=%d len=%d requested for file %s\n",
        (int)offset, (int)count, fsp->fsp_name ));

  if (OPEN_FSP(fsp) && fsp->can_lock && (fsp->conn == conn))
    ok = fcntl_lock(fsp->fd_ptr->fd,F_SETLK,offset,count,F_UNLCK);
   
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
	if (share_ops) return True;

#ifdef FAST_SHARE_MODES
	share_ops = locking_shm_init(read_only);
#else
	share_ops = locking_slow_init(read_only);
#endif

	if (!share_ops) {
		DEBUG(0,("ERROR: Failed to initialise share modes!\n"));
		return False;
	}
	
	return True;
}

/*******************************************************************
 Deinitialize the share_mode management.
******************************************************************/

BOOL locking_end(void)
{
	if (share_ops)
		return share_ops->stop_mgmt();
	return True;
}


/*******************************************************************
 Lock a hash bucket entry.
******************************************************************/
BOOL lock_share_entry(connection_struct *conn,
		      SMB_DEV_T dev, SMB_INO_T inode, int *ptok)
{
	return share_ops->lock_entry(conn, dev, inode, ptok);
}

/*******************************************************************
 Unlock a hash bucket entry.
******************************************************************/
BOOL unlock_share_entry(connection_struct *conn,
			SMB_DEV_T dev, SMB_INO_T inode, int token)
{
	return share_ops->unlock_entry(conn, dev, inode, token);
}

/*******************************************************************
 Get all share mode entries for a dev/inode pair.
********************************************************************/
int get_share_modes(connection_struct *conn, 
		    int token, SMB_DEV_T dev, SMB_INO_T inode, 
		    share_mode_entry **shares)
{
	return share_ops->get_entries(conn, token, dev, inode, shares);
}

/*******************************************************************
 Del the share mode of a file.
********************************************************************/
void del_share_mode(int token, files_struct *fsp)
{
	share_ops->del_entry(token, fsp);
}

/*******************************************************************
 Set the share mode of a file. Return False on fail, True on success.
********************************************************************/
BOOL set_share_mode(int token, files_struct *fsp, uint16 port, uint16 op_type)
{
	return share_ops->set_entry(token, fsp, port, op_type);
}

/*******************************************************************
 Remove an oplock port and mode entry from a share mode.
********************************************************************/
BOOL remove_share_oplock(files_struct *fsp, int token)
{
	return share_ops->remove_oplock(fsp, token);
}

/*******************************************************************
 Call the specified function on each entry under management by the
 share mode system.
********************************************************************/

int share_mode_forall(void (*fn)(share_mode_entry *, char *))
{
	return share_ops->forall(fn);
}

/*******************************************************************
 Dump the state of the system.
********************************************************************/

void share_status(FILE *f)
{
	share_ops->status(f);
}
