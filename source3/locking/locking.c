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
extern int Client;

static struct share_ops *share_ops;

#if 0 /* JRATEST - blocking lock code - under development. */

/****************************************************************************
 This is the structure to queue to implement blocking locks.
 notify. It consists of the requesting SMB and the expiry time.
*****************************************************************************/

typedef struct {
  ubi_slNode msg_next;
  time_t expire_time;
  int lock_num;
  char *inbuf;
  int length;
} blocking_lock_record;

static ubi_slList blocking_lock_queue = { NULL, (ubi_slNodePtr)&blocking_lock_queue, 0};

/****************************************************************************
 Function to push a blocking lockingX request onto the lock queue.
****************************************************************************/

BOOL push_blocking_lock_request( char *inbuf, int length, int lock_timeout, int lock_num)
{
  blocking_lock_record *blr;
  int fnum = GETFNUM(inbuf,smb_vwv2);

  /*
   * Now queue an entry on the blocking lock queue. We setup
   * the expiration time here.
   */

  if((blr = (blocking_lock_record *)malloc(sizeof(blocking_lock_record))) == NULL) {
    DEBUG(0,("push_blocking_lock_request: Malloc fail !\n" ));
    return False;
  }

  if((blr->inbuf = (char *)malloc(length)) == NULL) {
    DEBUG(0,("push_blocking_lock_request: Malloc fail (2)!\n" ));
    free((char *)blr);
    return False;
  }

  memcpy(blr->inbuf, inbuf, length);
  blr->length = length;
  blr->lock_num = lock_num;
  blr->expire_time = (lock_timeout == -1) ? (time_t)-1 : time(NULL) + (time_t)lock_timeout;

  ubi_slAddTail(&blocking_lock_queue, blr);

  DEBUG(3,("push_blocking_lock_request: lock request blocked with expiry time %d \
for fnum = %d, name = %s\n", blr->expire_time, fnum, Files[fnum].name ));

  return True;
}

/****************************************************************************
 Return a blocking lock success SMB.
*****************************************************************************/

static void blocking_lock_reply_success(blocking_lock_record *blr)
{
  extern int chain_size;
  extern int chain_fnum;
  extern char *OutBuffer;
  char *outbuf = OutBuffer;
  int bufsize = BUFFER_SIZE;
  char *inbuf = blr->inbuf;
  int fnum = GETFNUM(inbuf,smb_vwv2);
  int outsize = 0;

  construct_reply_common(inbuf, outbuf);
  set_message(outbuf,2,0,True);

  /*
   * As this message is a lockingX call we must handle
   * any following chained message correctly.
   * This is normally handled in construct_reply(),
   * but as that calls switch_message, we can't use
   * that here and must set up the chain info manually.
   */

  chain_fnum = fnum;
  chain_size = 0;

  outsize = chain_reply(inbuf,outbuf,blr->length,bufsize);

  outsize += chain_size;

  if(outsize > 4)
    smb_setlen(outbuf,outsize - 4);

  send_smb(Client,outbuf);
}

/****************************************************************************
 Return a lock fail error. Undo all the locks we have obtained first.
*****************************************************************************/

static void blocking_lock_reply_error(blocking_lock_record *blr, int eclass, int32 ecode)
{
  extern char *OutBuffer;
  char *outbuf = OutBuffer;
  int bufsize = BUFFER_SIZE;
  char *inbuf = blr->inbuf;
  int fnum = GETFNUM(inbuf,smb_vwv2);
  uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
  uint16 num_locks = SVAL(inbuf,smb_vwv7);
  uint32 count, offset;
  int cnum;
  int lock_num = blr->lock_num;
  char *data;
  int i;

  cnum = SVAL(inbuf,smb_tid);

  data = smb_buf(inbuf) + 10*num_ulocks;

  /* 
   * Data now points at the beginning of the list
   * of smb_lkrng structs.
   */

  for(i = blr->lock_num; i >= 0; i--) {
    count = IVAL(data,SMB_LKLEN_OFFSET(i));
    offset = IVAL(data,SMB_LKOFF_OFFSET(i));
    do_unlock(fnum,cnum,count,offset,&dummy1,&dummy2);
  }

  construct_reply_common(inbuf, outbuf);
  ERROR(eclass,ecode);
  send_smb(Client,outbuf);
}

/****************************************************************************
 Attempt to finish off getting all pending blocking locks.
 Returns True if we want to be removed from the list.
*****************************************************************************/

static BOOL blocking_lock_record_process(blocking_lock_record *blr)
{
  char *inbuf = blr->inbuf;
  unsigned char locktype = CVAL(inbuf,smb_vwv3);
  int fnum = GETFNUM(inbuf,smb_vwv2);
  uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
  uint16 num_locks = SVAL(inbuf,smb_vwv7);
  uint32 count, offset;
  int cnum;
  int lock_num = blr->lock_num;
  char *data;
  int eclass=0;
  uint32 ecode=0;

  cnum = SVAL(inbuf,smb_tid);

  data = smb_buf(inbuf) + 10*num_ulocks;

  /* 
   * Data now points at the beginning of the list
   * of smb_lkrng structs.
   */

  for(; blr->lock_num < num_locks; blr->lock_num++) {
    count = IVAL(data,SMB_LKLEN_OFFSET(blr->lock_num));
    offset = IVAL(data,SMB_LKOFF_OFFSET(blr->lock_num));
    if(!do_lock(fnum,cnum,count,offset, ((locktype & 1) ? F_RDLCK : F_WRLCK),
                &eclass, &ecode))
      break;
  }

  if(blr->lock_num == num_locks) {

    /*
     * Success - we got all the locks.
     */

    DEBUG(3,("blocking_lock_record_process fnum=%d cnum=%d type=%d num_locks=%d\n",
          fnum, cnum, (unsigned int)locktype, num_locks) );

    blocking_lock_reply_success(blr);
    return True;

  } else if((errno != EACCES) && (errno != EAGAIN)) {

    /*
     * We have other than a "can't get lock" POSIX
     * error. Free any locks we had and return an error.
     * Return True so we get dequeued.
     */

    blocking_lock_reply_error(blr, eclass, ecode);
    return True;
  }

  /*
   * Still can't get all the locks - keep waiting.
   */

  DEBUG(10,("blocking_lock_record_process: only got %d locks of %d needed for fnum = %d. \
Waiting..\n", blr->lock_num, num_locks, fnum ));

  return False;
}

/****************************************************************************
 Process the blocking lock queue. Note that this is only called as root.
*****************************************************************************/

void process_blocking_lock_queue(time_t t)
{
  blocking_lock_record *blr = (blocking_lock_record *)ubi_slFirst( &blocking_lock_queue );
  blocking_lock_record *prev = NULL;

  if(blr == NULL)
    return;

  /*
   * Go through the queue and see if we can get any of the locks.
   */

  while(blr != NULL) {
    int fnum = GETFNUM(blr->inbuf,smb_vwv2);
    int cnum = SVAL(blr->inbuf,smb_tid);
    files_struct *fsp = &Files[fnum];
    uint16 vuid = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID :
                  SVAL(blr->inbuf,smb_uid);

    DEBUG(5,("process_blocking_lock_queue: examining pending lock fnum = %d for file %s\n",
          fnum, fsp->name ));

    if((blr->expire_time != -1) && (blr->expire_time > t)) {
      /*
       * Lock expired - throw away all previously
       * obtained locks and return lock error.
       */
      DEBUG(5,("process_blocking_lock_queue: pending lock fnum = %d for file %s timed out.\n",
          fnum, fsp->name ));

      blocking_lock_reply_error(blr,ERRSRV,ERRaccess);
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      continue;
    }

    if(!become_user(&Connections[cnum],cnum,vuid)) {
      DEBUG(0,("process_blocking_lock_queue: Unable to become user vuid=%d.\n",
            vuid ));
      /*
       * Remove the entry and return an error to the client.
       */
      blocking_lock_reply_error(blr,ERRSRV,ERRaccess);
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      continue;
    }

    if(!become_service(cnum,True)) {
      DEBUG(0,("process_blocking_lock_queue: Unable to become service cnum=%d. \
Error was %s.\n", cnum, strerror(errno) ));
      /*
       * Remove the entry and return an error to the client.
       */
      blocking_lock_reply_error(blr,ERRSRV,ERRaccess);
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      unbecome_user();
      continue;
    }

    /*
     * Go through the remaining locks and try and obtain them.
     * The call returns True if all locks were obtained successfully
     * and False if we still need to wait.
     */

    if(blocking_lock_record_process(blr)) {
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      unbecome_user();
      continue;
    }

    unbecome_user();

    /*
     * Move to the next in the list.
     */
    prev = blr;
    blr = (blocking_lock_record *)ubi_slNext(blr);
  }
}
#endif /* JRATEST */

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

BOOL is_locked(int fnum,int cnum,uint32 count,uint32 offset, int lock_type)
{
  int snum = SNUM(cnum);
  files_struct *fsp = &Files[fnum];

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

BOOL do_lock(int fnum,int cnum,uint32 count,uint32 offset,int lock_type,
             int *eclass,uint32 *ecode)
{
  BOOL ok = False;
  files_struct *fsp = &Files[fnum];

  if (!lp_locking(SNUM(cnum)))
    return(True);

  if (count == 0) {
    *eclass = ERRDOS;
    *ecode = ERRnoaccess;
    return False;
  }

  if (OPEN_FNUM(fnum) && fsp->can_lock && (fsp->cnum == cnum))
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

BOOL do_unlock(int fnum,int cnum,uint32 count,uint32 offset,int *eclass,uint32 *ecode)
{
  BOOL ok = False;
  files_struct *fsp = &Files[fnum];

  if (!lp_locking(SNUM(cnum)))
    return(True);

  if (OPEN_FNUM(fnum) && fsp->can_lock && (fsp->cnum == cnum))
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

BOOL lock_share_entry(int cnum, uint32 dev, uint32 inode, int *ptok)
{
	return share_ops->lock_entry(cnum, dev, inode, ptok);
}

/*******************************************************************
 Unlock a hash bucket entry.
******************************************************************/

BOOL unlock_share_entry(int cnum, uint32 dev, uint32 inode, int token)
{
	return share_ops->unlock_entry(cnum, dev, inode, token);
}

/*******************************************************************
 Get all share mode entries for a dev/inode pair.
********************************************************************/

int get_share_modes(int cnum, int token, uint32 dev, uint32 inode, 
		    share_mode_entry **shares)
{
	return share_ops->get_entries(cnum, token, dev, inode, shares);
}

/*******************************************************************
 Del the share mode of a file.
********************************************************************/

void del_share_mode(int token, int fnum)
{
	share_ops->del_entry(token, fnum);
}

/*******************************************************************
 Set the share mode of a file. Return False on fail, True on success.
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
