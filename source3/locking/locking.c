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
extern connection_struct Connections[];
extern files_struct Files[];

static struct share_ops *share_ops;

/****************************************************************************
  utility function called to see if a file region is locked
****************************************************************************/
BOOL is_locked(int fnum,int cnum,uint32 count,uint32 offset)
{
  int snum = SNUM(cnum);

  if (count == 0)
    return(False);

  if (!lp_locking(snum) || !lp_strict_locking(snum))
    return(False);

  return(fcntl_lock(Files[fnum].fd_ptr->fd,F_GETLK,offset,count,
                   (Files[fnum].can_write?F_WRLCK:F_RDLCK)));
}


/****************************************************************************
  utility function called by locking requests
****************************************************************************/
BOOL do_lock(int fnum,int cnum,uint32 count,uint32 offset,int *eclass,uint32 *ecode)
{
  BOOL ok = False;

  if (!lp_locking(SNUM(cnum)))
    return(True);

  if (count == 0) {
    *eclass = ERRDOS;
    *ecode = ERRnoaccess;
    return False;
  }

  if (Files[fnum].can_lock && OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
    ok = fcntl_lock(Files[fnum].fd_ptr->fd,F_SETLK,offset,count,
                    (Files[fnum].can_write?F_WRLCK:F_RDLCK));

  if (!ok) {
    *eclass = ERRDOS;
    *ecode = ERRlock;
    return False;
  }
  return True; /* Got lock */
}


/****************************************************************************
  utility function called by unlocking requests
****************************************************************************/
BOOL do_unlock(int fnum,int cnum,uint32 count,uint32 offset,int *eclass,uint32 *ecode)
{
  BOOL ok = False;

  if (!lp_locking(SNUM(cnum)))
    return(True);

  if (Files[fnum].can_lock && OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
    ok = fcntl_lock(Files[fnum].fd_ptr->fd,F_SETLK,offset,count,F_UNLCK);
   
  if (!ok) {
    *eclass = ERRDOS;
    *ecode = ERRlock;
    return False;
  }
  return True; /* Did unlock */
}



/****************************************************************************
  initialise the locking functions
****************************************************************************/
BOOL locking_init(int read_only)
{
	if (share_ops) return True;

#ifdef FAST_SHARE_MODES
	share_ops = locking_shm_init(read_only);
	if (!share_ops) {
		DEBUG(0,("ERROR: Failed to initialise fast share modes - trying slow code\n"));
	}
	if (share_ops) return True;
#endif	

	share_ops = locking_slow_init(read_only);
	if (!share_ops) {
		DEBUG(0,("ERROR: Failed to initialise share modes!\n"));
		return False;
	}
	
	return True;
}

/*******************************************************************
  deinitialize the share_mode management 
  ******************************************************************/
BOOL locking_end(void)
{
	if (share_ops)
		return share_ops->stop_mgmt();
	return True;
}


/*******************************************************************
  lock a hash bucket entry 
  ******************************************************************/
BOOL lock_share_entry(int cnum, uint32 dev, uint32 inode, int *ptok)
{
	return share_ops->lock_entry(cnum, dev, inode, ptok);
}

/*******************************************************************
  unlock a hash bucket entry
  ******************************************************************/
BOOL unlock_share_entry(int cnum, uint32 dev, uint32 inode, int token)
{
	return share_ops->unlock_entry(cnum, dev, inode, token);
}

/*******************************************************************
get all share mode entries for a dev/inode pair.
********************************************************************/
int get_share_modes(int cnum, int token, uint32 dev, uint32 inode, 
		    share_mode_entry **shares)
{
	return share_ops->get_entries(cnum, token, dev, inode, shares);
}

/*******************************************************************
del the share mode of a file.
********************************************************************/
void del_share_mode(int token, int fnum)
{
	share_ops->del_entry(token, fnum);
}

/*******************************************************************
set the share mode of a file. Return False on fail, True on success.
********************************************************************/
BOOL set_share_mode(int token, int fnum, uint16 port, uint16 op_type)
{
	return share_ops->set_entry(token, fnum, port, op_type);
}

/*******************************************************************
Remove an oplock port and mode entry from a share mode.
********************************************************************/
BOOL remove_share_oplock(int fnum, int token)
{
	return share_ops->remove_oplock(fnum, token);
}


/*******************************************************************
call the specified function on each entry under management by the
share mode system
********************************************************************/
int share_mode_forall(void (*fn)(share_mode_entry *, char *))
{
	return share_ops->forall(fn);
}

/*******************************************************************
dump the state of the system
********************************************************************/
void share_status(FILE *f)
{
	share_ops->status(f);
}
