/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Blocking Locking functions
   Copyright (C) Jeremy Allison 1998
   
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

#include "includes.h"
extern int DEBUGLEVEL;
extern int Client;

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
 Destructor for the above structure.
****************************************************************************/

static void free_blocking_lock_record(blocking_lock_record *blr)
{
  free(blr->inbuf);
  free((char *)blr);
}

/****************************************************************************
 Function to push a blocking lockingX request onto the lock queue.
 NB. We can only get away with this as the CIFS spec only includes
 SMB_COM_LOCKING_ANDX as a head SMB, ie. it is not one that is ever
 generated as part of a chain.
****************************************************************************/

BOOL push_blocking_lock_request( char *inbuf, int length, int lock_timeout, int lock_num)
{
  blocking_lock_record *blr;
  files_struct *fsp = file_fsp(inbuf,smb_vwv2);

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
for fnum = %d, name = %s\n", (int)blr->expire_time, fsp->fnum, fsp->fsp_name ));

  return True;
}

/****************************************************************************
 Return a blocking lock success SMB.
*****************************************************************************/

static void blocking_lock_reply_success(blocking_lock_record *blr)
{
  extern int chain_size;
  extern char *OutBuffer;
  char *outbuf = OutBuffer;
  int bufsize = BUFFER_SIZE;
  char *inbuf = blr->inbuf;
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
  char *inbuf = blr->inbuf;
  files_struct *fsp = file_fsp(inbuf,smb_vwv2);
  connection_struct *conn = conn_find(SVAL(inbuf,smb_tid));
  uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
  uint32 count, offset;
  char *data;
  int i;

  data = smb_buf(inbuf) + 10*num_ulocks;

  /* 
   * Data now points at the beginning of the list
   * of smb_lkrng structs.
   */

  for(i = blr->lock_num; i >= 0; i--) {
    int dummy1;
    uint32 dummy2;
    count = IVAL(data,SMB_LKLEN_OFFSET(i));
    offset = IVAL(data,SMB_LKOFF_OFFSET(i));
    do_unlock(fsp,conn,count,offset,&dummy1,&dummy2);
  }

  construct_reply_common(inbuf, outbuf);

 if(eclass == 0) /* NT Error. */
    SSVAL(outbuf,smb_flg2, SVAL(outbuf,smb_flg2) | FLAGS2_32_BIT_ERROR_CODES);

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
  files_struct *fsp = file_fsp(inbuf,smb_vwv2);
  connection_struct *conn = conn_find(SVAL(inbuf,smb_tid));
  uint16 num_ulocks = SVAL(inbuf,smb_vwv6);
  uint16 num_locks = SVAL(inbuf,smb_vwv7);
  uint32 count, offset;
  char *data;
  int eclass=0;
  uint32 ecode=0;

  data = smb_buf(inbuf) + 10*num_ulocks;

  /* 
   * Data now points at the beginning of the list
   * of smb_lkrng structs.
   */

  for(; blr->lock_num < num_locks; blr->lock_num++) {
    count = IVAL(data,SMB_LKLEN_OFFSET(blr->lock_num));
    offset = IVAL(data,SMB_LKOFF_OFFSET(blr->lock_num));
    if(!do_lock(fsp,conn,count,offset, ((locktype & 1) ? F_RDLCK : F_WRLCK),
                &eclass, &ecode))
      break;
  }

  if(blr->lock_num == num_locks) {

    /*
     * Success - we got all the locks.
     */

    DEBUG(3,("blocking_lock_record_process fnum=%d type=%d num_locks=%d\n",
          fsp->fnum, (unsigned int)locktype, num_locks) );

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
Waiting....\n", blr->lock_num, num_locks, fsp->fnum));

  return False;
}

/****************************************************************************
 Delete entries by fnum from the blocking lock pending queue.
*****************************************************************************/

void remove_pending_lock_requests_by_fid(files_struct *fsp)
{
  blocking_lock_record *blr = (blocking_lock_record *)ubi_slFirst( &blocking_lock_queue );
  blocking_lock_record *prev = NULL;

  while(blr != NULL) {
    files_struct *req_fsp = file_fsp(blr->inbuf,smb_vwv2);

    if(req_fsp == fsp) {
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&blocking_lock_queue));
      continue;
    }

    prev = blr;
    blr = (blocking_lock_record *)ubi_slNext(blr);
  }
}

/****************************************************************************
 Delete entries by mid from the blocking lock pending queue. Always send reply.
*****************************************************************************/

void remove_pending_lock_requests_by_mid(int mid)
{
  blocking_lock_record *blr = (blocking_lock_record *)ubi_slFirst( &blocking_lock_queue );
  blocking_lock_record *prev = NULL;

  while(blr != NULL) {
    if(SVAL(blr->inbuf,smb_mid) == mid) {
      blocking_lock_reply_error(blr,0,NT_STATUS_CANCELLED);
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&blocking_lock_queue));
      continue;
    }

    prev = blr;
    blr = (blocking_lock_record *)ubi_slNext(blr);
  }
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
    files_struct *fsp = NULL;
    connection_struct *conn = NULL;
    uint16 vuid;

    /*
     * Ensure we don't have any old chain_fnum values
     * sitting around....
     */
    file_chain_reset();

    conn = conn_find(SVAL(blr->inbuf,smb_tid));
    fsp = file_fsp(blr->inbuf,smb_vwv2);
    vuid = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID :
                  SVAL(blr->inbuf,smb_uid);

    DEBUG(5,("process_blocking_lock_queue: examining pending lock fnum = %d for file %s\n",
          fsp->fnum, fsp->fsp_name ));

    if((blr->expire_time != -1) && (blr->expire_time > t)) {
      /*
       * Lock expired - throw away all previously
       * obtained locks and return lock error.
       */
      DEBUG(5,("process_blocking_lock_queue: pending lock fnum = %d for file %s timed out.\n",
          fsp->fnum, fsp->fsp_name ));

      blocking_lock_reply_error(blr,ERRSRV,ERRaccess);
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&blocking_lock_queue));
      continue;
    }

    if(!become_user(conn,vuid)) {
      DEBUG(0,("process_blocking_lock_queue: Unable to become user vuid=%d.\n",
            vuid ));
      /*
       * Remove the entry and return an error to the client.
       */
      blocking_lock_reply_error(blr,ERRSRV,ERRaccess);
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&blocking_lock_queue));
      continue;
    }

    if(!become_service(conn,True)) {
      DEBUG(0,("process_blocking_lock_queue: Unable to become service Error was %s.\n", strerror(errno) ));
      /*
       * Remove the entry and return an error to the client.
       */
      blocking_lock_reply_error(blr,ERRSRV,ERRaccess);
      free_blocking_lock_record((blocking_lock_record *)ubi_slRemNext( &blocking_lock_queue, prev));
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&blocking_lock_queue));
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
      blr = (blocking_lock_record *)(prev ? ubi_slNext(prev) : ubi_slFirst(&blocking_lock_queue));
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

