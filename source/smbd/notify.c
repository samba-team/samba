#define OLD_NTDOMAIN 1
/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB NT transaction handling
   Copyright (C) Jeremy Allison 1994-1998

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

/****************************************************************************
 This is the structure to keep the information needed to
 determine if a directory has changed.
*****************************************************************************/

typedef struct {
  time_t modify_time; /* Info from the directory we're monitoring. */ 
  time_t status_time; /* Info from the directory we're monitoring. */
  time_t total_time; /* Total time of all directory entries - don't care if it wraps. */
  unsigned int num_entries; /* Zero or the number of files in the directory. */
} change_hash_data;

/****************************************************************************
 This is the structure to queue to implement NT change
 notify. It consists of smb_size bytes stored from the
 transact command (to keep the mid, tid etc around).
 Plus the fid to examine and the time to check next.
*****************************************************************************/

typedef struct {
  ubi_slNode msg_next;
  files_struct *fsp;
  connection_struct *conn;
  uint32 flags;
  time_t next_check_time;
  change_hash_data change_data;
  char request_buf[smb_size];
} change_notify_buf;

static ubi_slList change_notify_queue = { NULL, (ubi_slNodePtr)&change_notify_queue, 0};

/****************************************************************************
 Setup the common parts of the return packet and send it.
*****************************************************************************/

static void change_notify_reply_packet(char *inbuf, int error_class, uint32 error_code)
{
  char outbuf[smb_size+38];

  memset(outbuf, '\0', sizeof(outbuf));
  construct_reply_common(inbuf, outbuf);

  /*
   * If we're returning a 'too much in the directory changed' we need to
   * set this is an NT error status flags. If we don't then the (probably
   * untested) code in the NT redirector has a bug in that it doesn't re-issue
   * the change notify.... Ah - I *love* it when I get so deeply into this I
   * can even determine how MS failed to test stuff and why.... :-). JRA.
   */

  if(error_class == 0) /* NT Error. */
    SSVAL(outbuf,smb_flg2, SVAL(outbuf,smb_flg2) | FLAGS2_32_BIT_ERROR_CODES);

  ERROR(error_class,error_code);

  /*
   * Seems NT needs a transact command with an error code
   * in it. This is a longer packet than a simple error.
   */
  set_message(outbuf,18,0,False);

  send_smb(smbd_server_fd(),outbuf);
}

/****************************************************************************
 Create the hash we will use to determine if the contents changed.
*****************************************************************************/

static BOOL create_directory_notify_hash( change_notify_buf *cnbp, change_hash_data *change_data)
{
  SMB_STRUCT_STAT st;
  files_struct *fsp = cnbp->fsp;

  memset((char *)change_data, '\0', sizeof(change_data));

  /* 
   * Store the current timestamp on the directory we are monitoring.
   */

  if(dos_stat(fsp->fsp_name, &st) < 0) {
    DEBUG(0,("create_directory_notify_hash: Unable to stat name = %s. \
Error was %s\n", fsp->fsp_name, strerror(errno) ));
    return False;
  }
 
  change_data->modify_time = st.st_mtime;
  change_data->status_time = st.st_ctime;

  /*
   * If we are to watch for changes that are only stored
   * in inodes of files, not in the directory inode, we must
   * scan the directory and produce a unique identifier with
   * which we can determine if anything changed. We use the
   * modify and change times from all the files in the
   * directory, added together (ignoring wrapping if it's
   * larger than the max time_t value).
   */

  if(cnbp->flags & (FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE)) {
    pstring full_name;
    char *p;
    char *fname;
    size_t remaining_len;
    size_t fullname_len;
    void *dp = OpenDir(cnbp->conn, fsp->fsp_name, True);

    if(dp == NULL) {
      DEBUG(0,("create_directory_notify_hash: Unable to open directory = %s. \
Error was %s\n", fsp->fsp_name, strerror(errno) ));
      return False;
    }

    change_data->num_entries = 0;

    pstrcpy(full_name, fsp->fsp_name);
    pstrcat(full_name, "/");

    fullname_len = strlen(full_name);
    remaining_len = sizeof(full_name) - fullname_len - 1;
    p = &full_name[fullname_len];

    while ((fname = ReadDirName(dp))) {
      if(strequal(fname, ".") || strequal(fname, ".."))
        continue;

      change_data->num_entries++;
      safe_strcpy( p, fname, remaining_len);

      memset(&st, '\0', sizeof(st));

      /*
       * Do the stat - but ignore errors.
       */

      if(dos_stat(full_name, &st) < 0) {
        DEBUG(5,("create_directory_notify_hash: Unable to stat content file = %s. \
Error was %s\n", fsp->fsp_name, strerror(errno) ));
      }
      change_data->total_time += (st.st_mtime + st.st_ctime);
    }

    CloseDir(dp);
  }

  return True;
}

/****************************************************************************
 Delete entries by fnum from the change notify pending queue.
*****************************************************************************/

void remove_pending_change_notify_requests_by_fid(files_struct *fsp)
{
  change_notify_buf *cnbp = (change_notify_buf *)ubi_slFirst( &change_notify_queue );
  change_notify_buf *prev = NULL;

  while(cnbp != NULL) {
    if(cnbp->fsp->fnum == fsp->fnum) {
      free((char *)ubi_slRemNext( &change_notify_queue, prev));
      cnbp = (change_notify_buf *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      continue;
    }

    prev = cnbp;
    cnbp = (change_notify_buf *)ubi_slNext(cnbp);
  }
}

/****************************************************************************
 Delete entries by mid from the change notify pending queue. Always send reply.
*****************************************************************************/

void remove_pending_change_notify_requests_by_mid(int mid)
{
  change_notify_buf *cnbp = (change_notify_buf *)ubi_slFirst( &change_notify_queue );
  change_notify_buf *prev = NULL;

  while(cnbp != NULL) {
    if(SVAL(cnbp->request_buf,smb_mid) == mid) {
      change_notify_reply_packet(cnbp->request_buf,0,0xC0000000 |NT_STATUS_CANCELLED);
      free((char *)ubi_slRemNext( &change_notify_queue, prev));
      cnbp = (change_notify_buf *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      continue;
    }

    prev = cnbp;
    cnbp = (change_notify_buf *)ubi_slNext(cnbp);
  }
}

/****************************************************************************
 Delete entries by filename and cnum from the change notify pending queue.
 Always send reply.
*****************************************************************************/

void remove_pending_change_notify_requests_by_filename(files_struct *fsp)
{
  change_notify_buf *cnbp = (change_notify_buf *)ubi_slFirst( &change_notify_queue );
  change_notify_buf *prev = NULL;

  while(cnbp != NULL) {
    /*
     * We know it refers to the same directory if the connection number and
     * the filename are identical.
     */
    if((cnbp->fsp->conn == fsp->conn) && strequal(cnbp->fsp->fsp_name,fsp->fsp_name)) {
      change_notify_reply_packet(cnbp->request_buf,0,0xC0000000 |NT_STATUS_CANCELLED);
      free((char *)ubi_slRemNext( &change_notify_queue, prev));
      cnbp = (change_notify_buf *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      continue;
    }

    prev = cnbp;
    cnbp = (change_notify_buf *)ubi_slNext(cnbp);
  }
}

/****************************************************************************
 Process the change notify queue. Note that this is only called as root.
 Returns True if there are still outstanding change notify requests on the
 queue.
*****************************************************************************/

BOOL process_pending_change_notify_queue(time_t t)
{
  change_notify_buf *cnbp = (change_notify_buf *)ubi_slFirst( &change_notify_queue );
  change_notify_buf *prev = NULL;

  if(cnbp == NULL)
    return False;

  if(cnbp->next_check_time >= t)
    return True;

  /*
   * It's time to check. Go through the queue and see if
   * the timestamps changed.
   */

  while((cnbp != NULL) && (cnbp->next_check_time <= t)) {
    change_hash_data change_data;
    connection_struct *conn = cnbp->conn;
    uint16 vuid = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID : 
                  SVAL(cnbp->request_buf,smb_uid);

    ZERO_STRUCT(change_data);

    /*
     * Ensure we don't have any old chain_fsp values
     * sitting around....
     */
    chain_size = 0;
    file_chain_reset();

    if(!become_user(conn,vuid)) {
      DEBUG(0,("process_pending_change_notify_queue: Unable to become user vuid=%d.\n",
            vuid ));
      /*
       * Remove the entry and return an error to the client.
       */
      change_notify_reply_packet(cnbp->request_buf,ERRSRV,ERRaccess);
      free((char *)ubi_slRemNext( &change_notify_queue, prev));
      cnbp = (change_notify_buf *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      continue;
    }

    if(!become_service(conn,True)) {
	    DEBUG(0,("process_pending_change_notify_queue: Unable to become service Error was %s.\n", strerror(errno) ));
      /*
       * Remove the entry and return an error to the client.
       */
      change_notify_reply_packet(cnbp->request_buf,ERRSRV,ERRaccess);
      free((char *)ubi_slRemNext( &change_notify_queue, prev));
      cnbp = (change_notify_buf *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      unbecome_user();
      continue;
    }

    if(!create_directory_notify_hash( cnbp, &change_data)) {
      DEBUG(0,("process_pending_change_notify_queue: Unable to create change data for \
directory %s\n", cnbp->fsp->fsp_name ));
      /*
       * Remove the entry and return an error to the client.
       */
      change_notify_reply_packet(cnbp->request_buf,ERRSRV,ERRaccess);
      free((char *)ubi_slRemNext( &change_notify_queue, prev));
      cnbp = (change_notify_buf *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      unbecome_user();
      continue;
    }

    if(memcmp( (char *)&cnbp->change_data, (char *)&change_data, sizeof(change_data))) {
      /*
       * Remove the entry and return a change notify to the client.
       */
      DEBUG(5,("process_pending_change_notify_queue: directory name = %s changed.\n",
            cnbp->fsp->fsp_name ));
      change_notify_reply_packet(cnbp->request_buf,0,NT_STATUS_NOTIFY_ENUM_DIR);
      free((char *)ubi_slRemNext( &change_notify_queue, prev));
      cnbp = (change_notify_buf *)(prev ? ubi_slNext(prev) : ubi_slFirst(&change_notify_queue));
      unbecome_user();
      continue;
    }

    unbecome_user();

    /*
     * Move to the next in the list.
     */
    prev = cnbp;
    cnbp = (change_notify_buf *)ubi_slNext(cnbp);
  }

  return (cnbp != NULL);
}

/****************************************************************************
 Return true if there are pending change notifies.
****************************************************************************/
BOOL change_notifies_pending(void)
{
  change_notify_buf *cnbp = (change_notify_buf *)ubi_slFirst( &change_notify_queue );
  return (cnbp != NULL);
}

/****************************************************************************
   * Now queue an entry on the notify change stack. We timestamp
   * the entry we are adding so that we know when to scan next.
   * We only need to save smb_size bytes from this incoming packet
   * as we will always by returning a 'read the directory yourself'
   * error.
****************************************************************************/
BOOL change_notify_set(char *inbuf, files_struct *fsp, connection_struct *conn, uint32 flags)
{
	change_notify_buf *cnbp;

	if((cnbp = (change_notify_buf *)malloc(sizeof(change_notify_buf))) == NULL) {
		DEBUG(0,("call_nt_transact_notify_change: malloc fail !\n" ));
		return -1;
	}

	ZERO_STRUCTP(cnbp);

	memcpy(cnbp->request_buf, inbuf, smb_size);
	cnbp->fsp = fsp;
	cnbp->conn = conn;
	cnbp->next_check_time = time(NULL) + lp_change_notify_timeout();
	cnbp->flags = flags;
	
	if (!create_directory_notify_hash(cnbp, &cnbp->change_data)) {
		free((char *)cnbp);
		return False;
	}
	
	/*
	 * Adding to the tail enables us to check only
	 * the head when scanning for change, as this entry
	 * is forced to have the first timeout expiration.
	 */
	
	ubi_slAddTail(&change_notify_queue, cnbp);

	return True;
}

#undef OLD_NTDOMAIN
