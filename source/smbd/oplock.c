/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   oplock processing
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
*/

#include "includes.h"

extern int DEBUGLEVEL;

/* Oplock ipc UDP socket. */
static int oplock_sock = -1;
uint16 global_oplock_port = 0;
#if defined(HAVE_KERNEL_OPLOCKS)
static int oplock_pipe_read = -1;
static int oplock_pipe_write = -1;
#endif /* HAVE_KERNEL_OPLOCKS */

/* Current number of oplocks we have outstanding. */
int32 global_oplocks_open = 0;
BOOL global_oplock_break = False;

extern int smb_read_error;

static BOOL oplock_break(SMB_DEV_T dev, SMB_INO_T inode, struct timeval *tval);

/****************************************************************************
 Setup the kernel level oplock backchannel for this process.
****************************************************************************/

BOOL setup_kernel_oplock_pipe(void)
{
#if defined(HAVE_KERNEL_OPLOCKS)
  if(lp_kernel_oplocks()) {
    int pfd[2];

    if(pipe(pfd) != 0) {
      DEBUG(0,("setup_kernel_oplock_pipe: Unable to create pipe. Error was %s\n",
            strerror(errno) ));
      return False;
    }

    oplock_pipe_read = pfd[0];
    oplock_pipe_write = pfd[1];
  }
#endif /* HAVE_KERNEL_OPLOCKS */
  return True;
}

/****************************************************************************
  open the oplock IPC socket communication
****************************************************************************/
BOOL open_oplock_ipc(void)
{
  struct sockaddr_in sock_name;
  int len = sizeof(sock_name);

  DEBUG(3,("open_oplock_ipc: opening loopback UDP socket.\n"));

  /* Open a lookback UDP socket on a random port. */
  oplock_sock = open_socket_in(SOCK_DGRAM, 0, 0, htonl(INADDR_LOOPBACK),False);
  if (oplock_sock == -1)
  {
    DEBUG(0,("open_oplock_ipc: Failed to get local UDP socket for \
address %lx. Error was %s\n", (long)htonl(INADDR_LOOPBACK), strerror(errno)));
    global_oplock_port = 0;
    return(False);
  }

  /* Find out the transient UDP port we have been allocated. */
  if(getsockname(oplock_sock, (struct sockaddr *)&sock_name, &len)<0)
  {
    DEBUG(0,("open_oplock_ipc: Failed to get local UDP port. Error was %s\n",
            strerror(errno)));
    close(oplock_sock);
    oplock_sock = -1;
    global_oplock_port = 0;
    return False;
  }
  global_oplock_port = ntohs(sock_name.sin_port);

  if(!setup_kernel_oplock_pipe())
    return False;

  DEBUG(3,("open_oplock ipc: pid = %d, global_oplock_port = %u\n", 
            (int)getpid(), global_oplock_port));

  return True;
}

/****************************************************************************
 Read an oplock break message from the either the oplock UDP fd
 or the kernel oplock pipe fd (if kernel oplocks are supported).

 If timeout is zero then *fds contains the file descriptors that
 are ready to be read and acted upon. If timeout is non-zero then
 *fds contains the file descriptors to be selected on for read.
 The timeout is in milliseconds

****************************************************************************/

BOOL receive_local_message(fd_set *fds, char *buffer, int buffer_len, int timeout)
{
  struct sockaddr_in from;
  int fromlen = sizeof(from);
  int32 msg_len = 0;

  smb_read_error = 0;

  if(timeout != 0) {
    struct timeval to;
    int selrtn;
    int maxfd = oplock_sock;

#if defined(HAVE_KERNEL_OPLOCKS)
    if(lp_kernel_oplocks())
      maxfd = MAX(maxfd, oplock_pipe_read);
#endif /* HAVE_KERNEL_OPLOCKS */

    to.tv_sec = timeout / 1000;
    to.tv_usec = (timeout % 1000) * 1000;

    selrtn = sys_select(maxfd+1,fds,NULL, &to);

    /* Check if error */
    if(selrtn == -1) {
      /* something is wrong. Maybe the socket is dead? */
      smb_read_error = READ_ERROR;
      return False;
    }

    /* Did we timeout ? */
    if (selrtn == 0) {
      smb_read_error = READ_TIMEOUT;
      return False;
    }
  }

#if defined(HAVE_KERNEL_OPLOCKS)
  if(FD_ISSET(oplock_pipe_read,fds)) {
    /*
     * Deal with the kernel <--> smbd
     * oplock break protocol.
     */

    oplock_stat_t os;
    SMB_DEV_T dev;
    SMB_INO_T inode;
    char dummy;

    /*
     * Read one byte of zero to clear the
     * kernel break notify message.
     */

    if(read(oplock_pipe_read, &dummy, 1) != 1) {
      DEBUG(0,("receive_local_message: read of kernel notification failed. \
Error was %s.\n", strerror(errno) ));
      smb_read_error = READ_ERROR;
      return False;
    }

    /*
     * Do a query to get the
     * device and inode of the file that has the break
     * request outstanding.
     */

    if(fcntl(oplock_pipe_read, F_OPLKSTAT, &os) < 0) {
      DEBUG(0,("receive_local_message: fcntl of kernel notification failed. \
Error was %s.\n", strerror(errno) ));
      if(errno == EAGAIN) {
        /*
         * Duplicate kernel break message - ignore.
         */
        memset(buffer, '\0', KERNEL_OPLOCK_BREAK_MSG_LEN);
        return True;
      }
      smb_read_error = READ_ERROR;
      return False;
    }

    dev = (SMB_DEV_T)os.os_dev;
    inode = (SMB_DEV_T)os.os_ino;

    DEBUG(5,("receive_local_message: kernel oplock break request received for \
dev = %x, inode = %.0f\n", (unsigned int)dev, (double)inode ));

    /*
     * Create a kernel oplock break message.
     */

    /* Setup the message header */
    SIVAL(buffer,OPBRK_CMD_LEN_OFFSET,KERNEL_OPLOCK_BREAK_MSG_LEN);
    SSVAL(buffer,OPBRK_CMD_PORT_OFFSET,0);

    buffer += OPBRK_CMD_HEADER_LEN;

    SSVAL(buffer,OPBRK_MESSAGE_CMD_OFFSET,KERNEL_OPLOCK_BREAK_CMD);
    SIVAL(buffer,KERNEL_OPLOCK_BREAK_DEV_OFFSET,dev);

#ifdef LARGE_SMB_INO_T
    SIVAL(buffer,KERNEL_OPLOCK_BREAK_INODE_OFFSET,inode & 0xFFFFFFFF);
    SIVAL(buffer,KERNEL_OPLOCK_BREAK_INODE_OFFSET+4, (inode >> 32 ) & 0xFFFFFFFF );
#else /* LARGE_SMB_INO_T */
    SIVAL(buffer,KERNEL_OPLOCK_BREAK_INODE_OFFSET,inode);
#endif /* LARGE_SMB_INO_T */

    return True;
  }
#endif /* HAVE_KERNEL_OPLOCKS */

  /*
   * From here down we deal with the smbd <--> smbd
   * oplock break protocol only.
   */

  /*
   * Read a loopback udp message.
   */
  msg_len = recvfrom(oplock_sock, &buffer[OPBRK_CMD_HEADER_LEN],
                     buffer_len - OPBRK_CMD_HEADER_LEN, 0,
                     (struct sockaddr *)&from, &fromlen);

  if(msg_len < 0) {
    DEBUG(0,("receive_local_message. Error in recvfrom. (%s).\n",strerror(errno)));
    return False;
  }

  /* Validate message length. */
  if(msg_len > (buffer_len - OPBRK_CMD_HEADER_LEN)) {
    DEBUG(0,("receive_local_message: invalid msg_len (%d) max can be %d\n",
              msg_len,
              buffer_len  - OPBRK_CMD_HEADER_LEN));
    return False;
  }

  /* Validate message from address (must be localhost). */
  if(from.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
    DEBUG(0,("receive_local_message: invalid 'from' address \
(was %lx should be 127.0.0.1\n", (long)from.sin_addr.s_addr));
   return False;
  }

  /* Setup the message header */
  SIVAL(buffer,OPBRK_CMD_LEN_OFFSET,msg_len);
  SSVAL(buffer,OPBRK_CMD_PORT_OFFSET,ntohs(from.sin_port));

  return True;
}

/****************************************************************************
 Attempt to set an oplock on a file. Always succeeds if kernel oplocks are
 disabled (just sets flags). Returns True if oplock set.
****************************************************************************/

BOOL set_file_oplock(files_struct *fsp)
{
#if defined(HAVE_KERNEL_OPLOCKS)
  if(lp_kernel_oplocks()) {

    if(fcntl(fsp->fd_ptr->fd, F_OPLKREG, oplock_pipe_write) < 0 ) {
      if(errno != EAGAIN) {
        DEBUG(0,("set_file_oplock: Unable to get kernel oplock on file %s, dev = %x, \
inode = %.0f. Error was %s\n", 
              fsp->fsp_name, (unsigned int)fsp->fd_ptr->dev, (double)fsp->fd_ptr->inode,
               strerror(errno) ));
      } else {
        DEBUG(5,("set_file_oplock: Refused oplock on file %s, fd = %d, dev = %x, \
inode = %.0f. Another process had the file open.\n",
              fsp->fsp_name, fsp->fd_ptr->fd, (unsigned int)fsp->fd_ptr->dev, (double)fsp->fd_ptr->inode ));
      }
      return False;
    }

    DEBUG(10,("set_file_oplock: got kernel oplock on file %s, dev = %x, inode = %.0f\n",
          fsp->fsp_name, (unsigned int)fsp->fd_ptr->dev, (double)fsp->fd_ptr->inode));

  }
#endif /* HAVE_KERNEL_OPLOCKS */

  DEBUG(5,("set_file_oplock: granted oplock on file %s, dev = %x, inode = %.0f\n", 
        fsp->fsp_name, (unsigned int)fsp->fd_ptr->dev, (double)fsp->fd_ptr->inode));

  fsp->granted_oplock = True;
  fsp->sent_oplock_break = False;
  global_oplocks_open++;

  return True;
}

/****************************************************************************
 Attempt to release an oplock on a file. Always succeeds if kernel oplocks are
 disabled (just clears flags).
****************************************************************************/

static void release_file_oplock(files_struct *fsp)
{
#if defined(HAVE_KERNEL_OPLOCKS)

  if(lp_kernel_oplocks())
  {
    if( DEBUGLVL( 10 ))
    {
      /*
       * Check and print out the current kernel
       * oplock state of this file.
       */
      int state = fcntl(fsp->fd_ptr->fd, F_OPLKACK, -1);
      dbgtext("release_file_oplock: file %s, dev = %x, inode = %.0f has kernel \
oplock state of %x.\n", fsp->fsp_name, (unsigned int)fsp->fd_ptr->dev,
                        (double)fsp->fd_ptr->inode, state );
    }

    /*
     * Remote the kernel oplock on this file.
     */

    if(fcntl(fsp->fd_ptr->fd, F_OPLKACK, OP_REVOKE) < 0)
    {
      if( DEBUGLVL( 0 ))
      {
        dbgtext("release_file_oplock: Error when removing kernel oplock on file " );
        dbgtext("%s, dev = %x, inode = %.0f. Error was %s\n",
                 fsp->fsp_name, (unsigned int)fsp->fd_ptr->dev, 
                 (double)fsp->fd_ptr->inode, strerror(errno) );
      }
    }
  }
#endif /* HAVE_KERNEL_OPLOCKS */

  fsp->granted_oplock = False;
  fsp->sent_oplock_break = False;
  global_oplocks_open--;
}

/****************************************************************************
 Setup the listening set of file descriptors for an oplock break
 message either from the UDP socket or from the kernel. Returns the maximum
 fd used.
****************************************************************************/

int setup_oplock_select_set( fd_set *fds)
{
  int maxfd = oplock_sock;
  FD_SET(oplock_sock,fds);

#if defined(HAVE_KERNEL_OPLOCKS)
  if(lp_kernel_oplocks()) {
    FD_SET(oplock_pipe_read,fds); 
    maxfd = MAX(maxfd,oplock_pipe_read);
  }
#endif /* HAVE_KERNEL_OPLOCKS */

  return maxfd;
}

/****************************************************************************
 Process an oplock break message - whether it came from the UDP socket
 or from the kernel.
****************************************************************************/

BOOL process_local_message(char *buffer, int buf_size)
{
  int32 msg_len;
  uint16 from_port;
  char *msg_start;
  SMB_DEV_T dev;
  SMB_INO_T inode;
  uint32 remotepid;
  struct timeval tval;
  struct timeval *ptval = NULL;

  msg_len = IVAL(buffer,OPBRK_CMD_LEN_OFFSET);
  from_port = SVAL(buffer,OPBRK_CMD_PORT_OFFSET);

  msg_start = &buffer[OPBRK_CMD_HEADER_LEN];

  DEBUG(5,("process_local_message: Got a message of length %d from port (%d)\n", 
            msg_len, from_port));

  /* 
   * Pull the info out of the requesting packet.
   */

  switch(SVAL(msg_start,OPBRK_MESSAGE_CMD_OFFSET))
  {
#if defined(HAVE_KERNEL_OPLOCKS)
    case KERNEL_OPLOCK_BREAK_CMD:
      /* Ensure that the msg length is correct. */
      if(msg_len != KERNEL_OPLOCK_BREAK_MSG_LEN)
      {
        DEBUG(0,("process_local_message: incorrect length for KERNEL_OPLOCK_BREAK_CMD (was %d, \
should be %d).\n", msg_len, KERNEL_OPLOCK_BREAK_MSG_LEN));
        return False;
      }
      {
        /*
         * Warning - beware of SMB_INO_T <> 4 bytes. !!
         */
#ifdef LARGE_SMB_INO_T
        SMB_INO_T inode_low = IVAL(msg_start, KERNEL_OPLOCK_BREAK_INODE_OFFSET);
        SMB_INO_T inode_high = IVAL(msg_start, KERNEL_OPLOCK_BREAK_INODE_OFFSET + 4);
        inode = inode_low | (inode_high << 32);
#else /* LARGE_SMB_INO_T */
        inode = IVAL(msg_start, KERNEL_OPLOCK_BREAK_INODE_OFFSET);
#endif /* LARGE_SMB_INO_T */

        dev = IVAL(msg_start,KERNEL_OPLOCK_BREAK_DEV_OFFSET);

        ptval = NULL;

        DEBUG(5,("process_local_message: kernel oplock break request for \
file dev = %x, inode = %.0f\n", (unsigned int)dev, (double)inode));
      }
      break;
#endif /* HAVE_KERNEL_OPLOCKS */

    case OPLOCK_BREAK_CMD:
      /* Ensure that the msg length is correct. */
      if(msg_len != OPLOCK_BREAK_MSG_LEN)
      {
        DEBUG(0,("process_local_message: incorrect length for OPLOCK_BREAK_CMD (was %d, \
should be %d).\n", msg_len, OPLOCK_BREAK_MSG_LEN));
        return False;
      }
      {
        /*
         * Warning - beware of SMB_INO_T <> 4 bytes. !!
         */
#ifdef LARGE_SMB_INO_T
        SMB_INO_T inode_low = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET);
        SMB_INO_T inode_high = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET + 4);
        inode = inode_low | (inode_high << 32);
#else /* LARGE_SMB_INO_T */
        inode = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET);
#endif /* LARGE_SMB_INO_T */

        dev = IVAL(msg_start,OPLOCK_BREAK_DEV_OFFSET);

        tval.tv_sec = (time_t)IVAL(msg_start, OPLOCK_BREAK_SEC_OFFSET);
        tval.tv_usec = (long)IVAL(msg_start, OPLOCK_BREAK_USEC_OFFSET);

        ptval = &tval;

        remotepid = IVAL(msg_start,OPLOCK_BREAK_PID_OFFSET);

        DEBUG(5,("process_local_message: oplock break request from \
pid %d, port %d, dev = %x, inode = %.0f\n", remotepid, from_port, (unsigned int)dev, (double)inode));
      }
      break;

    /* 
     * Keep this as a debug case - eventually we can remove it.
     */
    case 0x8001:
      DEBUG(0,("process_local_message: Received unsolicited break \
reply - dumping info.\n"));

      if(msg_len != OPLOCK_BREAK_MSG_LEN)
      {
        DEBUG(0,("process_local_message: ubr: incorrect length for reply \
(was %d, should be %d).\n", msg_len, OPLOCK_BREAK_MSG_LEN));
        return False;
      }

      {
        /*
         * Warning - beware of SMB_INO_T <> 4 bytes. !!
         */
#ifdef LARGE_SMB_INO_T
        SMB_INO_T inode_low = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET);
        SMB_INO_T inode_high = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET + 4);
        inode = inode_low | (inode_high << 32);
#else /* LARGE_SMB_INO_T */
        inode = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET);
#endif /* LARGE_SMB_INO_T */

        remotepid = IVAL(msg_start,OPLOCK_BREAK_PID_OFFSET);
        dev = IVAL(msg_start,OPLOCK_BREAK_DEV_OFFSET);

        DEBUG(0,("process_local_message: unsolicited oplock break reply from \
pid %d, port %d, dev = %x, inode = %.0f\n", remotepid, from_port, (unsigned int)dev, (double)inode));

       }
       return False;

    default:
      DEBUG(0,("process_local_message: unknown UDP message command code (%x) - ignoring.\n",
                (unsigned int)SVAL(msg_start,0)));
      return False;
  }

  /*
   * Now actually process the break request.
   */

  if(global_oplocks_open != 0)
  {
    if(oplock_break(dev, inode, ptval) == False)
    {
      DEBUG(0,("process_local_message: oplock break failed.\n"));
      return False;
    }
  }
  else
  {
    /*
     * If we have no record of any currently open oplocks,
     * it's not an error, as a close command may have
     * just been issued on the file that was oplocked.
     * Just log a message and return success in this case.
     */
    DEBUG(3,("process_local_message: oplock break requested with no outstanding \
oplocks. Returning success.\n"));
  }

  /* 
   * Do the appropriate reply - none in the kernel case.
   */

  if(SVAL(msg_start,OPBRK_MESSAGE_CMD_OFFSET) == OPLOCK_BREAK_CMD)
  {
    struct sockaddr_in toaddr;

    /* Send the message back after OR'ing in the 'REPLY' bit. */
    SSVAL(msg_start,OPBRK_MESSAGE_CMD_OFFSET,OPLOCK_BREAK_CMD | CMD_REPLY);

    bzero((char *)&toaddr,sizeof(toaddr));
    toaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    toaddr.sin_port = htons(from_port);
    toaddr.sin_family = AF_INET;

    if(sendto( oplock_sock, msg_start, OPLOCK_BREAK_MSG_LEN, 0,
            (struct sockaddr *)&toaddr, sizeof(toaddr)) < 0) 
    {
      DEBUG(0,("process_local_message: sendto process %d failed. Errno was %s\n",
                remotepid, strerror(errno)));
      return False;
    }

    DEBUG(5,("process_local_message: oplock break reply sent to \
pid %d, port %d, for file dev = %x, inode = %.0f\n",
          remotepid, from_port, (unsigned int)dev, (double)inode));
  }

  return True;
}

/****************************************************************************
 Process an oplock break directly.
****************************************************************************/

static BOOL oplock_break(SMB_DEV_T dev, SMB_INO_T inode, struct timeval *tval)
{
  extern struct current_user current_user;
  extern int Client;
  char *inbuf = NULL;
  char *outbuf = NULL;
  files_struct *fsp = NULL;
  time_t start_time;
  BOOL shutdown_server = False;
  connection_struct *saved_conn;
  int saved_vuid;
  pstring saved_dir; 
  int break_counter = OPLOCK_BREAK_RESENDS;

  if( DEBUGLVL( 3 ) )
  {
    dbgtext( "oplock_break: called for dev = %x, inode = %.0f.\n", (unsigned int)dev, (double)inode );
    dbgtext( "Current global_oplocks_open = %d\n", global_oplocks_open );
  }

  /* We need to search the file open table for the
     entry containing this dev and inode, and ensure
     we have an oplock on it. */
  fsp = file_find_dit(dev, inode, tval);

  if(fsp == NULL)
  {
    /* The file could have been closed in the meantime - return success. */
    if( DEBUGLVL( 0 ) )
    {
      dbgtext( "oplock_break: cannot find open file with " );
      dbgtext( "dev = %x, inode = %.0f ", (unsigned int)dev, (double)inode);
      dbgtext( "allowing break to succeed.\n" );
    }
    return True;
  }

  /* Ensure we have an oplock on the file */

  /* There is a potential race condition in that an oplock could
     have been broken due to another udp request, and yet there are
     still oplock break messages being sent in the udp message
     queue for this file. So return true if we don't have an oplock,
     as we may have just freed it.
   */

  if(!fsp->granted_oplock)
  {
    if( DEBUGLVL( 0 ) )
    {
      dbgtext( "oplock_break: file %s ", fsp->fsp_name );
      dbgtext( "(dev = %x, inode = %.0f) has no oplock.\n", (unsigned int)dev, (double)inode );
      dbgtext( "Allowing break to succeed regardless.\n" );
    }
    return True;
  }

  /* mark the oplock break as sent - we don't want to send twice! */
  if (fsp->sent_oplock_break)
  {
    if( DEBUGLVL( 0 ) )
    {
      dbgtext( "oplock_break: ERROR: oplock_break already sent for " );
      dbgtext( "file %s ", fsp->fsp_name);
      dbgtext( "(dev = %x, inode = %.0f)\n", (unsigned int)dev, (double)inode );
    }

    /* We have to fail the open here as we cannot send another oplock break on
       this file whilst we are awaiting a response from the client - neither
       can we allow another open to succeed while we are waiting for the
       client.
     */
    return False;
  }

  /* Now comes the horrid part. We must send an oplock break to the client,
     and then process incoming messages until we get a close or oplock release.
     At this point we know we need a new inbuf/outbuf buffer pair.
     We cannot use these staticaly as we may recurse into here due to
     messages crossing on the wire.
   */

  if((inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN))==NULL)
  {
    DEBUG(0,("oplock_break: malloc fail for input buffer.\n"));
    return False;
  }

  if((outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN))==NULL)
  {
    DEBUG(0,("oplock_break: malloc fail for output buffer.\n"));
    free(inbuf);
    inbuf = NULL;
    return False;
  }

  /* Prepare the SMBlockingX message. */
  bzero(outbuf,smb_size);
  set_message(outbuf,8,0,True);

  SCVAL(outbuf,smb_com,SMBlockingX);
  SSVAL(outbuf,smb_tid,fsp->conn->cnum);
  SSVAL(outbuf,smb_pid,0xFFFF);
  SSVAL(outbuf,smb_uid,0);
  SSVAL(outbuf,smb_mid,0xFFFF);
  SCVAL(outbuf,smb_vwv0,0xFF);
  SSVAL(outbuf,smb_vwv2,fsp->fnum);
  SCVAL(outbuf,smb_vwv3,LOCKING_ANDX_OPLOCK_RELEASE);
  /* Change this when we have level II oplocks. */
  SCVAL(outbuf,smb_vwv3+1,OPLOCKLEVEL_NONE);
 
  send_smb(Client, outbuf);

  /* Remember we just sent an oplock break on this file. */
  fsp->sent_oplock_break = True;

  /* We need this in case a readraw crosses on the wire. */
  global_oplock_break = True;
 
  /* Process incoming messages. */

  /* JRA - If we don't get a break from the client in OPLOCK_BREAK_TIMEOUT
     seconds we should just die.... */

  start_time = time(NULL);

  /*
   * Save the information we need to re-become the
   * user, then unbecome the user whilst we're doing this.
   */
  saved_conn = fsp->conn;
  saved_vuid = current_user.key.vuid;
  dos_GetWd(saved_dir);
  unbecome_user();
  /* Save the chain fnum. */
  file_chain_save();

  while(OPEN_FSP(fsp) && fsp->granted_oplock)
  {
    if(receive_smb(Client,inbuf,
		   (OPLOCK_BREAK_TIMEOUT/OPLOCK_BREAK_RESENDS) * 1000) == False)
    {

	    /* Isaac suggestd that if a MS client doesn't respond to a
	       oplock break request then we might try resending
	       it. Certainly it's no worse than just dropping the
	       socket! */
	    if (smb_read_error == READ_TIMEOUT && break_counter--) {
		    DEBUG(2, ( "oplock_break resend\n" ) );
		    send_smb(Client, outbuf);
		    continue;
	    }

      /*
       * Die if we got an error.
       */

      if (smb_read_error == READ_EOF)
        DEBUG( 0, ( "oplock_break: end of file from client\n" ) );
 
      if (smb_read_error == READ_ERROR)
        DEBUG( 0, ("oplock_break: receive_smb error (%s)\n", strerror(errno)) );

      if (smb_read_error == READ_TIMEOUT)
        DEBUG( 0, ( "oplock_break: receive_smb timed out after %d seconds.\n",
                     OPLOCK_BREAK_TIMEOUT ) );

      DEBUGADD( 0, ( "oplock_break failed for file %s ", fsp->fsp_name ) );
      DEBUGADD( 0, ( "(dev = %x, inode = %.0f).\n", (unsigned int)dev, (double)inode));

      shutdown_server = True;
      break;
    }

    /*
     * There are certain SMB requests that we shouldn't allow
     * to recurse. opens, renames and deletes are the obvious
     * ones. This is handled in the switch_message() function.
     * If global_oplock_break is set they will push the packet onto
     * the pending smb queue and return -1 (no reply).
     * JRA.
     */

    process_smb(inbuf, outbuf);

    /*
     * Die if we go over the time limit.
     */

    if((time(NULL) - start_time) > OPLOCK_BREAK_TIMEOUT)
    {
      if( DEBUGLVL( 0 ) )
        {
        dbgtext( "oplock_break: no break received from client " );
        dbgtext( "within %d seconds.\n", OPLOCK_BREAK_TIMEOUT );
        dbgtext( "oplock_break failed for file %s ", fsp->fsp_name );
        dbgtext( "(dev = %x, inode = %.0f).\n", (unsigned int)dev, (double)inode );
        }
      shutdown_server = True;
      break;
    }
  }

  /*
   * Go back to being the user who requested the oplock
   * break.
   */
  if(!become_user(saved_conn, saved_vuid))
  {
    DEBUG( 0, ( "oplock_break: unable to re-become user!" ) );
    DEBUGADD( 0, ( "Shutting down server\n" ) );
    close_sockets();
    close(oplock_sock);
    exit_server("unable to re-become user");
  }
  /* Including the directory. */
  dos_ChDir(saved_dir);

  /* Restore the chain fnum. */
  file_chain_restore();

  /* Free the buffers we've been using to recurse. */
  free(inbuf);
  free(outbuf);

  /* We need this in case a readraw crossed on the wire. */
  if(global_oplock_break)
    global_oplock_break = False;

  /*
   * If the client did not respond we must die.
   */

  if(shutdown_server)
  {
    DEBUG( 0, ( "oplock_break: client failure in break - " ) );
    DEBUGADD( 0, ( "shutting down this smbd.\n" ) );
    close_sockets();
    close(oplock_sock);
    exit_server("oplock break failure");
  }

  if(OPEN_FSP(fsp))
  {
    /* The lockingX reply will have removed the oplock flag 
       from the sharemode. */
    release_file_oplock(fsp);
  }

  /* Santity check - remove this later. JRA */
  if(global_oplocks_open < 0)
  {
    DEBUG(0,("oplock_break: global_oplocks_open < 0 (%d). PANIC ERROR\n",
              global_oplocks_open));
    exit_server("oplock_break: global_oplocks_open < 0");
  }


  if( DEBUGLVL( 3 ) )
  {
    dbgtext( "oplock_break: returning success for " );
    dbgtext( "dev = %x, inode = %.0f\n", (unsigned int)dev, (double)inode );
    dbgtext( "Current global_oplocks_open = %d\n", global_oplocks_open );
  }

  return True;
}

/****************************************************************************
Send an oplock break message to another smbd process. If the oplock is held 
by the local smbd then call the oplock break function directly.
****************************************************************************/

BOOL request_oplock_break(share_mode_entry *share_entry, 
                          SMB_DEV_T dev, SMB_INO_T inode)
{
  char op_break_msg[OPLOCK_BREAK_MSG_LEN];
  struct sockaddr_in addr_out;
  int pid = getpid();
  time_t start_time;
  int time_left;

  if(pid == share_entry->pid)
  {
    /* We are breaking our own oplock, make sure it's us. */
    if(share_entry->op_port != global_oplock_port)
    {
      DEBUG(0,("request_oplock_break: corrupt share mode entry - pid = %d, port = %d \
should be %d\n", pid, share_entry->op_port, global_oplock_port));
      return False;
    }

    DEBUG(5,("request_oplock_break: breaking our own oplock\n"));

    /* Call oplock break direct. */
    return oplock_break(dev, inode, &share_entry->time);
  }

  /* We need to send a OPLOCK_BREAK_CMD message to the
     port in the share mode entry. */

  SSVAL(op_break_msg,OPBRK_MESSAGE_CMD_OFFSET,OPLOCK_BREAK_CMD);
  SIVAL(op_break_msg,OPLOCK_BREAK_PID_OFFSET,pid);
  SIVAL(op_break_msg,OPLOCK_BREAK_SEC_OFFSET,(uint32)share_entry->time.tv_sec);
  SIVAL(op_break_msg,OPLOCK_BREAK_USEC_OFFSET,(uint32)share_entry->time.tv_usec);
  SIVAL(op_break_msg,OPLOCK_BREAK_DEV_OFFSET,dev);
  /*
   * WARNING - beware of SMB_INO_T <> 4 bytes.
   */
#ifdef LARGE_SMB_INO_T
  SIVAL(op_break_msg,OPLOCK_BREAK_INODE_OFFSET,(inode & 0xFFFFFFFFL));
  SIVAL(op_break_msg,OPLOCK_BREAK_INODE_OFFSET+4,((inode >> 32) & 0xFFFFFFFFL));
#else /* LARGE_SMB_INO_T */
  SIVAL(op_break_msg,OPLOCK_BREAK_INODE_OFFSET,inode);
#endif /* LARGE_SMB_INO_T */

  /* set the address and port */
  bzero((char *)&addr_out,sizeof(addr_out));
  addr_out.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_out.sin_port = htons( share_entry->op_port );
  addr_out.sin_family = AF_INET;
   
  if( DEBUGLVL( 3 ) )
  {
    dbgtext( "request_oplock_break: sending a oplock break message to " );
    dbgtext( "pid %d on port %d ", share_entry->pid, share_entry->op_port );
    dbgtext( "for dev = %x, inode = %.0f\n", (unsigned int)dev, (double)inode );
  }

  if(sendto(oplock_sock,op_break_msg,OPLOCK_BREAK_MSG_LEN,0,
         (struct sockaddr *)&addr_out,sizeof(addr_out)) < 0)
  {
    if( DEBUGLVL( 0 ) )
    {
      dbgtext( "request_oplock_break: failed when sending a oplock " );
      dbgtext( "break message to pid %d ", share_entry->pid );
      dbgtext( "on port %d ", share_entry->op_port );
      dbgtext( "for dev = %x, inode = %.0f\n", (unsigned int)dev, (double)inode );
      dbgtext( "Error was %s\n", strerror(errno) );
    }
    return False;
  }

  /*
   * Now we must await the oplock broken message coming back
   * from the target smbd process. Timeout if it fails to
   * return in (OPLOCK_BREAK_TIMEOUT + OPLOCK_BREAK_TIMEOUT_FUDGEFACTOR) seconds.
   * While we get messages that aren't ours, loop.
   */

  start_time = time(NULL);
  time_left = OPLOCK_BREAK_TIMEOUT+OPLOCK_BREAK_TIMEOUT_FUDGEFACTOR;

  while(time_left >= 0)
  {
    char op_break_reply[OPBRK_CMD_HEADER_LEN+OPLOCK_BREAK_MSG_LEN];
    int32 reply_msg_len;
    uint16 reply_from_port;
    char *reply_msg_start;
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(oplock_sock,&fds);
#if defined(HAVE_KERNEL_OPLOCKS)
    if(lp_kernel_oplocks())
      FD_SET(oplock_pipe_read,&fds);
#endif /* HAVE_KERNEL_OPLOCKS */

    if(receive_local_message(&fds, op_break_reply, sizeof(op_break_reply),
               time_left ? time_left * 1000 : 1) == False)
    {
      if(smb_read_error == READ_TIMEOUT)
      {
        if( DEBUGLVL( 0 ) )
        {
          dbgtext( "request_oplock_break: no response received to oplock " );
          dbgtext( "break request to pid %d ", share_entry->pid );
          dbgtext( "on port %d ", share_entry->op_port );
          dbgtext( "for dev = %x, inode = %.0f\n", (unsigned int)dev, (double)inode );
        }

        /*
         * This is a hack to make handling of failing clients more robust.
         * If a oplock break response message is not received in the timeout
         * period we may assume that the smbd servicing that client holding
         * the oplock has died and the client changes were lost anyway, so
         * we should continue to try and open the file.
         */
        break;
      }
      else
        if( DEBUGLVL( 0 ) )
        {
          dbgtext( "request_oplock_break: error in response received " );
          dbgtext( "to oplock break request to pid %d ", share_entry->pid );
          dbgtext( "on port %d ", share_entry->op_port );
          dbgtext( "for dev = %x, inode = %.0f\n", (unsigned int)dev, (double)inode );
          dbgtext( "Error was (%s).\n", strerror(errno) );
        }
      return False;
    }

    reply_msg_len = IVAL(op_break_reply,OPBRK_CMD_LEN_OFFSET);
    reply_from_port = SVAL(op_break_reply,OPBRK_CMD_PORT_OFFSET);

    reply_msg_start = &op_break_reply[OPBRK_CMD_HEADER_LEN];


#if defined(HAVE_KERNEL_OPLOCKS)
    if((reply_msg_len != OPLOCK_BREAK_MSG_LEN) && (reply_msg_len != KERNEL_OPLOCK_BREAK_MSG_LEN))
#else
    if(reply_msg_len != OPLOCK_BREAK_MSG_LEN)
#endif
    {
      /* Ignore it. */
      DEBUG( 0, ( "request_oplock_break: invalid message length (%d) received.", reply_msg_len ) );
      DEBUGADD( 0, ( "  Ignoring.\n" ) );
      continue;
    }

    /*
     * Test to see if this is the reply we are awaiting.
     */

    if((SVAL(reply_msg_start,OPBRK_MESSAGE_CMD_OFFSET) & CMD_REPLY) &&
       ((SVAL(reply_msg_start,OPBRK_MESSAGE_CMD_OFFSET) & ~CMD_REPLY) == OPLOCK_BREAK_CMD) &&
       (reply_from_port == share_entry->op_port) && 
       (memcmp(&reply_msg_start[OPLOCK_BREAK_PID_OFFSET], 
               &op_break_msg[OPLOCK_BREAK_PID_OFFSET],
               OPLOCK_BREAK_MSG_LEN - OPLOCK_BREAK_PID_OFFSET) == 0))
    {
      /*
       * This is the reply we've been waiting for.
       */
      break;
    }
    else
    {
      /*
       * This is another message - a break request.
       * Note that both kernel oplock break requests
       * and UDP inter-smbd oplock break requests will
       * be processed here.
       *
       * Process it to prevent potential deadlock.
       * Note that the code in switch_message() prevents
       * us from recursing into here as any SMB requests
       * we might process that would cause another oplock
       * break request to be made will be queued.
       * JRA.
       */

      process_local_message(op_break_reply, sizeof(op_break_reply));
    }

    time_left -= (time(NULL) - start_time);
  }

  DEBUG(3,("request_oplock_break: broke oplock.\n"));

  return True;
}

/****************************************************************************
  Attempt to break an oplock on a file (if oplocked).
  Returns True if the file was closed as a result of
  the oplock break, False otherwise.
  Used as a last ditch attempt to free a space in the 
  file table when we have run out.
****************************************************************************/
BOOL attempt_close_oplocked_file(files_struct *fsp)
{

  DEBUG(5,("attempt_close_oplocked_file: checking file %s.\n", fsp->fsp_name));

  if (fsp->open && fsp->granted_oplock && !fsp->sent_oplock_break && (fsp->fd_ptr != NULL)) {

    /* Try and break the oplock. */
    file_fd_struct *fd_ptr = fsp->fd_ptr;
    if(oplock_break( fd_ptr->dev, fd_ptr->inode, &fsp->open_time)) {
      if(!fsp->open) /* Did the oplock break close the file ? */
        return True;
    }
  }

  return False;
}

/****************************************************************************
 Init function to check if kernel level oplocks are available.
****************************************************************************/

void check_kernel_oplocks(void)
{
  static BOOL done;

  /*
   * We only do this check once on startup.
   */

  if(done)
    return;

  done = True;
  lp_set_kernel_oplocks(False);

#if defined(HAVE_KERNEL_OPLOCKS)
  {
    int fd;
    int pfd[2];
    pstring tmpname;

    set_process_capability(KERNEL_OPLOCK_CAPABILITY,True);
    set_inherited_process_capability(KERNEL_OPLOCK_CAPABILITY,True);

	slprintf(tmpname,sizeof(tmpname)-1, "%s/koplock.%d", lp_lockdir(), (int)getpid());

    if(pipe(pfd) != 0) {
      DEBUG(0,("check_kernel_oplocks: Unable to create pipe. Error was %s\n",
            strerror(errno) ));
      return;
    }

    if((fd = sys_open(tmpname, O_RDWR|O_CREAT|O_EXCL|O_TRUNC, 0600)) < 0) {
      DEBUG(0,("check_kernel_oplocks: Unable to open temp test file %s. Error was %s\n",
            tmpname, strerror(errno) ));
      unlink( tmpname );
      close(pfd[0]);
      close(pfd[1]);
      return;
    }

    unlink( tmpname );

    if(fcntl(fd, F_OPLKREG, pfd[1]) == -1) {
      DEBUG(0,("check_kernel_oplocks: Kernel oplocks are not available on this machine. \
Disabling kernel oplock support.\n" ));
      close(pfd[0]);
      close(pfd[1]);
      close(fd);
      return;
    }

    if(fcntl(fd, F_OPLKACK, OP_REVOKE) < 0 ) {
      DEBUG(0,("check_kernel_oplocks: Error when removing kernel oplock. Error was %s. \
Disabling kernel oplock support.\n", strerror(errno) ));
      close(pfd[0]);
      close(pfd[1]);
      close(fd);
      return;
    }

    close(pfd[0]);
    close(pfd[1]);
    close(fd);

    lp_set_kernel_oplocks(True);

    DEBUG(0,("check_kernel_oplocks: Kernel oplocks available and set to %s.\n",
          lp_kernel_oplocks() ? "True" : "False" ));

  }
#endif /* HAVE_KERNEL_OPLOCKS */
}
