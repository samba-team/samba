/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   process incoming packets - main loop
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

/* To be removed.... JRA */
#define SMB_ALIGNMENT 1

struct timeval smb_last_time;

static char *InBuffer = NULL;
char *OutBuffer = NULL;
char *last_inbuf = NULL;

/* 
 * Size of data we can send to client. Set
 *  by the client for all protocols above CORE.
 *  Set by us for CORE protocol.
 */
int max_send = BUFFER_SIZE;
/*
 * Size of the data we can receive. Set by us.
 * Can be modified by the max xmit parameter.
 */
int max_recv = BUFFER_SIZE;

extern int last_message;
extern int global_oplock_break;
extern userdom_struct current_user_info;
extern int smb_read_error;
extern SIG_ATOMIC_T reload_after_sighup;
extern SIG_ATOMIC_T got_sig_term;
extern BOOL global_machine_password_needs_changing;
extern fstring global_myworkgroup;
extern pstring global_myname;
extern int max_send;

/****************************************************************************
 structure to hold a linked list of queued messages.
 for processing.
****************************************************************************/

typedef struct {
   ubi_slNode msg_next;
   char *msg_buf;
   int msg_len;
} pending_message_list;

static ubi_slList smb_oplock_queue = { NULL, (ubi_slNodePtr)&smb_oplock_queue, 0};

/****************************************************************************
 Function to push a message onto the tail of a linked list of smb messages ready
 for processing.
****************************************************************************/

static BOOL push_message(ubi_slList *list_head, char *buf, int msg_len)
{
  pending_message_list *msg = (pending_message_list *)
                               malloc(sizeof(pending_message_list));

  if(msg == NULL)
  {
    DEBUG(0,("push_message: malloc fail (1)\n"));
    return False;
  }

  msg->msg_buf = (char *)malloc(msg_len);
  if(msg->msg_buf == NULL)
  {
    DEBUG(0,("push_message: malloc fail (2)\n"));
    SAFE_FREE(msg);
    return False;
  }

  memcpy(msg->msg_buf, buf, msg_len);
  msg->msg_len = msg_len;

  ubi_slAddTail( list_head, msg);

  return True;
}

/****************************************************************************
 Function to push a smb message onto a linked list of local smb messages ready
 for processing.
****************************************************************************/

BOOL push_oplock_pending_smb_message(char *buf, int msg_len)
{
	return push_message(&smb_oplock_queue, buf, msg_len);
}

/****************************************************************************
 Do all async processing in here. This includes UDB oplock messages, kernel
 oplock messages, change notify events etc.
****************************************************************************/

static void async_processing(char *buffer, int buffer_len)
{
	DEBUG(10,("async_processing: Doing async processing.\n"));

	/* check for oplock messages (both UDP and kernel) */
	if (receive_local_message(buffer, buffer_len, 1)) {
		process_local_message(buffer, buffer_len);
	}

	if (got_sig_term) {
		exit_server("Caught TERM signal");
	}

	/* check for async change notify events */
	process_pending_change_notify_queue(0);

	/* check for sighup processing */
	if (reload_after_sighup) {
		change_to_root_user();
		DEBUG(1,("Reloading services after SIGHUP\n"));
		reload_services(False);
		reload_after_sighup = 0;
	}
}

/****************************************************************************
  Do a select on an two fd's - with timeout. 

  If a local udp message has been pushed onto the
  queue (this can only happen during oplock break
  processing) call async_processing()

  If a pending smb message has been pushed onto the
  queue (this can only happen during oplock break
  processing) return this next.

  If the first smbfd is ready then read an smb from it.
  if the second (loopback UDP) fd is ready then read a message
  from it and setup the buffer header to identify the length
  and from address.
  Returns False on timeout or error.
  Else returns True.

The timeout is in milli seconds
****************************************************************************/

static BOOL receive_message_or_smb(char *buffer, int buffer_len, int timeout)
{
	fd_set fds;
	int selrtn;
	struct timeval to;
	int maxfd;

	smb_read_error = 0;

 again:

	/*
	 * Note that this call must be before processing any SMB
	 * messages as we need to synchronously process any messages
	 * we may have sent to ourselves from the previous SMB.
	 */
	message_dispatch();

	/*
	 * Check to see if we already have a message on the smb queue.
	 * If so - copy and return it.
	 */
  	if(ubi_slCount(&smb_oplock_queue) != 0) {
		pending_message_list *msg = (pending_message_list *)ubi_slRemHead(&smb_oplock_queue);
		memcpy(buffer, msg->msg_buf, MIN(buffer_len, msg->msg_len));
  
		/* Free the message we just copied. */
		SAFE_FREE(msg->msg_buf);
		SAFE_FREE(msg);
		
		DEBUG(5,("receive_message_or_smb: returning queued smb message.\n"));
		return True;
	}


	/*
	 * Setup the select read fd set.
	 */

	FD_ZERO(&fds);

	/*
	 * Ensure we process oplock break messages by preference.
	 * We have to do this before the select, after the select
	 * and if the select returns EINTR. This is due to the fact
	 * that the selects called from async_processing can eat an EINTR
	 * caused by a signal (we can't take the break message there).
	 * This is hideously complex - *MUST* be simplified for 3.0 ! JRA.
	 */

	if (oplock_message_waiting(&fds)) {
		DEBUG(10,("receive_message_or_smb: oplock_message is waiting.\n"));
		async_processing(buffer, buffer_len);
		/*
		 * After async processing we must go and do the select again, as
		 * the state of the flag in fds for the server file descriptor is
		 * indeterminate - we may have done I/O on it in the oplock processing. JRA.
		 */
		goto again;
	}
	
	FD_SET(smbd_server_fd(),&fds);
	maxfd = setup_oplock_select_set(&fds);

	to.tv_sec = timeout / 1000;
	to.tv_usec = (timeout % 1000) * 1000;

	selrtn = sys_select(MAX(maxfd,smbd_server_fd())+1,&fds,NULL,NULL,timeout>0?&to:NULL);

	/* if we get EINTR then maybe we have received an oplock
	   signal - treat this as select returning 1. This is ugly, but
	   is the best we can do until the oplock code knows more about
	   signals */
	if (selrtn == -1 && errno == EINTR) {
		async_processing(buffer, buffer_len);
		/*
		 * After async processing we must go and do the select again, as
		 * the state of the flag in fds for the server file descriptor is
		 * indeterminate - we may have done I/O on it in the oplock processing. JRA.
		 */
		goto again;
	}

	/* Check if error */
	if (selrtn == -1) {
		/* something is wrong. Maybe the socket is dead? */
		smb_read_error = READ_ERROR;
		return False;
	} 
    
	/* Did we timeout ? */
	if (selrtn == 0) {
		smb_read_error = READ_TIMEOUT;
		return False;
	}

	/*
	 * Ensure we process oplock break messages by preference.
	 * This is IMPORTANT ! Otherwise we can starve other processes
	 * sending us an oplock break message. JRA.
	 */

	if (oplock_message_waiting(&fds)) {
		DEBUG(10,("receive_message_or_smb: oplock_message is waiting.\n"));
		async_processing(buffer, buffer_len);
		/*
		 * After async processing we must go and do the select again, as
		 * the state of the flag in fds for the server file descriptor is
		 * indeterminate - we may have done I/O on it in the oplock processing. JRA.
		 */
		goto again;
	}
	
	return receive_smb(smbd_server_fd(), buffer, 0);
}

/****************************************************************************
Get the next SMB packet, doing the local message processing automatically.
****************************************************************************/

BOOL receive_next_smb(char *inbuf, int bufsize, int timeout)
{
	BOOL got_keepalive;
	BOOL ret;

	do {
		ret = receive_message_or_smb(inbuf,bufsize,timeout);
		
		got_keepalive = (ret && (CVAL(inbuf,0) == 0x85));
	} while (ret && got_keepalive);

	return ret;
}

/****************************************************************************
 We're terminating and have closed all our files/connections etc.
 If there are any pending local messages we need to respond to them
 before termination so that other smbds don't think we just died whilst
 holding oplocks.
****************************************************************************/

void respond_to_all_remaining_local_messages(void)
{
  char buffer[1024];

  /*
   * Assert we have no exclusive open oplocks.
   */

  if(get_number_of_exclusive_open_oplocks()) {
    DEBUG(0,("respond_to_all_remaining_local_messages: PANIC : we have %d exclusive oplocks.\n",
          get_number_of_exclusive_open_oplocks() ));
    return;
  }

  /*
   * Keep doing receive_local_message with a 1 ms timeout until
   * we have no more messages.
   */
  while(receive_local_message(buffer, sizeof(buffer), 1)) {
	  /* Deal with oplock break requests from other smbd's. */
	  process_local_message(buffer, sizeof(buffer));
  }

  return;
}


/*
These flags determine some of the permissions required to do an operation 

Note that I don't set NEED_WRITE on some write operations because they
are used by some brain-dead clients when printing, and I don't want to
force write permissions on print services.
*/
#define AS_USER (1<<0)
#define NEED_WRITE (1<<1)
#define TIME_INIT (1<<2)
#define CAN_IPC (1<<3)
#define AS_GUEST (1<<5)
#define QUEUE_IN_OPLOCK (1<<6)

/* 
   define a list of possible SMB messages and their corresponding
   functions. Any message that has a NULL function is unimplemented -
   please feel free to contribute implementations!
*/
struct smb_message_struct
{
  const char *name;
  int (*fn)(connection_struct *conn, char *, char *, int, int);
  int flags;
}
 smb_messages[256] = {

/* 0x00 */ { "SMBmkdir",reply_mkdir,AS_USER | NEED_WRITE},
/* 0x01 */ { "SMBrmdir",reply_rmdir,AS_USER | NEED_WRITE},
/* 0x02 */ { "SMBopen",reply_open,AS_USER | QUEUE_IN_OPLOCK },
/* 0x03 */ { "SMBcreate",reply_mknew,AS_USER},
/* 0x04 */ { "SMBclose",reply_close,AS_USER | CAN_IPC },
/* 0x05 */ { "SMBflush",reply_flush,AS_USER},
/* 0x06 */ { "SMBunlink",reply_unlink,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},
/* 0x07 */ { "SMBmv",reply_mv,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},
/* 0x08 */ { "SMBgetatr",reply_getatr,AS_USER},
/* 0x09 */ { "SMBsetatr",reply_setatr,AS_USER | NEED_WRITE},
/* 0x0a */ { "SMBread",reply_read,AS_USER},
/* 0x0b */ { "SMBwrite",reply_write,AS_USER | CAN_IPC },
/* 0x0c */ { "SMBlock",reply_lock,AS_USER},
/* 0x0d */ { "SMBunlock",reply_unlock,AS_USER},
/* 0x0e */ { "SMBctemp",reply_ctemp,AS_USER | QUEUE_IN_OPLOCK },
/* 0x0f */ { "SMBmknew",reply_mknew,AS_USER}, 
/* 0x10 */ { "SMBchkpth",reply_chkpth,AS_USER},
/* 0x11 */ { "SMBexit",reply_exit,0},
/* 0x12 */ { "SMBlseek",reply_lseek,AS_USER},
/* 0x13 */ { "SMBlockread",reply_lockread,AS_USER},
/* 0x14 */ { "SMBwriteunlock",reply_writeunlock,AS_USER},
/* 0x15 */ { NULL, NULL, 0 },
/* 0x16 */ { NULL, NULL, 0 },
/* 0x17 */ { NULL, NULL, 0 },
/* 0x18 */ { NULL, NULL, 0 },
/* 0x19 */ { NULL, NULL, 0 },
/* 0x1a */ { "SMBreadbraw",reply_readbraw,AS_USER},
/* 0x1b */ { "SMBreadBmpx",reply_readbmpx,AS_USER},
/* 0x1c */ { "SMBreadBs",NULL,0},
/* 0x1d */ { "SMBwritebraw",reply_writebraw,AS_USER},
/* 0x1e */ { "SMBwriteBmpx",reply_writebmpx,AS_USER},
/* 0x1f */ { "SMBwriteBs",reply_writebs,AS_USER},
/* 0x20 */ { "SMBwritec",NULL,0},
/* 0x21 */ { NULL, NULL, 0 },
/* 0x22 */ { "SMBsetattrE",reply_setattrE,AS_USER | NEED_WRITE },
/* 0x23 */ { "SMBgetattrE",reply_getattrE,AS_USER },
/* 0x24 */ { "SMBlockingX",reply_lockingX,AS_USER },
/* 0x25 */ { "SMBtrans",reply_trans,AS_USER | CAN_IPC | QUEUE_IN_OPLOCK},
/* 0x26 */ { "SMBtranss",NULL,AS_USER | CAN_IPC},
/* 0x27 */ { "SMBioctl",reply_ioctl,0},
/* 0x28 */ { "SMBioctls",NULL,AS_USER},
/* 0x29 */ { "SMBcopy",reply_copy,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK },
/* 0x2a */ { "SMBmove",NULL,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK },
/* 0x2b */ { "SMBecho",reply_echo,0},
/* 0x2c */ { "SMBwriteclose",reply_writeclose,AS_USER},
/* 0x2d */ { "SMBopenX",reply_open_and_X,AS_USER | CAN_IPC | QUEUE_IN_OPLOCK },
/* 0x2e */ { "SMBreadX",reply_read_and_X,AS_USER | CAN_IPC },
/* 0x2f */ { "SMBwriteX",reply_write_and_X,AS_USER | CAN_IPC },
/* 0x30 */ { NULL, NULL, 0 },
/* 0x31 */ { NULL, NULL, 0 },
/* 0x32 */ { "SMBtrans2", reply_trans2, AS_USER | CAN_IPC },
/* 0x33 */ { "SMBtranss2", reply_transs2, AS_USER},
/* 0x34 */ { "SMBfindclose", reply_findclose,AS_USER},
/* 0x35 */ { "SMBfindnclose", reply_findnclose, AS_USER},
/* 0x36 */ { NULL, NULL, 0 },
/* 0x37 */ { NULL, NULL, 0 },
/* 0x38 */ { NULL, NULL, 0 },
/* 0x39 */ { NULL, NULL, 0 },
/* 0x3a */ { NULL, NULL, 0 },
/* 0x3b */ { NULL, NULL, 0 },
/* 0x3c */ { NULL, NULL, 0 },
/* 0x3d */ { NULL, NULL, 0 },
/* 0x3e */ { NULL, NULL, 0 },
/* 0x3f */ { NULL, NULL, 0 },
/* 0x40 */ { NULL, NULL, 0 },
/* 0x41 */ { NULL, NULL, 0 },
/* 0x42 */ { NULL, NULL, 0 },
/* 0x43 */ { NULL, NULL, 0 },
/* 0x44 */ { NULL, NULL, 0 },
/* 0x45 */ { NULL, NULL, 0 },
/* 0x46 */ { NULL, NULL, 0 },
/* 0x47 */ { NULL, NULL, 0 },
/* 0x48 */ { NULL, NULL, 0 },
/* 0x49 */ { NULL, NULL, 0 },
/* 0x4a */ { NULL, NULL, 0 },
/* 0x4b */ { NULL, NULL, 0 },
/* 0x4c */ { NULL, NULL, 0 },
/* 0x4d */ { NULL, NULL, 0 },
/* 0x4e */ { NULL, NULL, 0 },
/* 0x4f */ { NULL, NULL, 0 },
/* 0x50 */ { NULL, NULL, 0 },
/* 0x51 */ { NULL, NULL, 0 },
/* 0x52 */ { NULL, NULL, 0 },
/* 0x53 */ { NULL, NULL, 0 },
/* 0x54 */ { NULL, NULL, 0 },
/* 0x55 */ { NULL, NULL, 0 },
/* 0x56 */ { NULL, NULL, 0 },
/* 0x57 */ { NULL, NULL, 0 },
/* 0x58 */ { NULL, NULL, 0 },
/* 0x59 */ { NULL, NULL, 0 },
/* 0x5a */ { NULL, NULL, 0 },
/* 0x5b */ { NULL, NULL, 0 },
/* 0x5c */ { NULL, NULL, 0 },
/* 0x5d */ { NULL, NULL, 0 },
/* 0x5e */ { NULL, NULL, 0 },
/* 0x5f */ { NULL, NULL, 0 },
/* 0x60 */ { NULL, NULL, 0 },
/* 0x61 */ { NULL, NULL, 0 },
/* 0x62 */ { NULL, NULL, 0 },
/* 0x63 */ { NULL, NULL, 0 },
/* 0x64 */ { NULL, NULL, 0 },
/* 0x65 */ { NULL, NULL, 0 },
/* 0x66 */ { NULL, NULL, 0 },
/* 0x67 */ { NULL, NULL, 0 },
/* 0x68 */ { NULL, NULL, 0 },
/* 0x69 */ { NULL, NULL, 0 },
/* 0x6a */ { NULL, NULL, 0 },
/* 0x6b */ { NULL, NULL, 0 },
/* 0x6c */ { NULL, NULL, 0 },
/* 0x6d */ { NULL, NULL, 0 },
/* 0x6e */ { NULL, NULL, 0 },
/* 0x6f */ { NULL, NULL, 0 },
/* 0x70 */ { "SMBtcon",reply_tcon,0},
/* 0x71 */ { "SMBtdis",reply_tdis,0},
/* 0x72 */ { "SMBnegprot",reply_negprot,0},
/* 0x73 */ { "SMBsesssetupX",reply_sesssetup_and_X,0},
/* 0x74 */ { "SMBulogoffX", reply_ulogoffX, 0}, /* ulogoff doesn't give a valid TID */
/* 0x75 */ { "SMBtconX",reply_tcon_and_X,0},
/* 0x76 */ { NULL, NULL, 0 },
/* 0x77 */ { NULL, NULL, 0 },
/* 0x78 */ { NULL, NULL, 0 },
/* 0x79 */ { NULL, NULL, 0 },
/* 0x7a */ { NULL, NULL, 0 },
/* 0x7b */ { NULL, NULL, 0 },
/* 0x7c */ { NULL, NULL, 0 },
/* 0x7d */ { NULL, NULL, 0 },
/* 0x7e */ { NULL, NULL, 0 },
/* 0x7f */ { NULL, NULL, 0 },
/* 0x80 */ { "SMBdskattr",reply_dskattr,AS_USER},
/* 0x81 */ { "SMBsearch",reply_search,AS_USER},
/* 0x82 */ { "SMBffirst",reply_search,AS_USER},
/* 0x83 */ { "SMBfunique",reply_search,AS_USER},
/* 0x84 */ { "SMBfclose",reply_fclose,AS_USER},
/* 0x85 */ { NULL, NULL, 0 },
/* 0x86 */ { NULL, NULL, 0 },
/* 0x87 */ { NULL, NULL, 0 },
/* 0x88 */ { NULL, NULL, 0 },
/* 0x89 */ { NULL, NULL, 0 },
/* 0x8a */ { NULL, NULL, 0 },
/* 0x8b */ { NULL, NULL, 0 },
/* 0x8c */ { NULL, NULL, 0 },
/* 0x8d */ { NULL, NULL, 0 },
/* 0x8e */ { NULL, NULL, 0 },
/* 0x8f */ { NULL, NULL, 0 },
/* 0x90 */ { NULL, NULL, 0 },
/* 0x91 */ { NULL, NULL, 0 },
/* 0x92 */ { NULL, NULL, 0 },
/* 0x93 */ { NULL, NULL, 0 },
/* 0x94 */ { NULL, NULL, 0 },
/* 0x95 */ { NULL, NULL, 0 },
/* 0x96 */ { NULL, NULL, 0 },
/* 0x97 */ { NULL, NULL, 0 },
/* 0x98 */ { NULL, NULL, 0 },
/* 0x99 */ { NULL, NULL, 0 },
/* 0x9a */ { NULL, NULL, 0 },
/* 0x9b */ { NULL, NULL, 0 },
/* 0x9c */ { NULL, NULL, 0 },
/* 0x9d */ { NULL, NULL, 0 },
/* 0x9e */ { NULL, NULL, 0 },
/* 0x9f */ { NULL, NULL, 0 },
/* 0xa0 */ { "SMBnttrans", reply_nttrans, AS_USER | CAN_IPC },
/* 0xa1 */ { "SMBnttranss", reply_nttranss, AS_USER | CAN_IPC },
/* 0xa2 */ { "SMBntcreateX", reply_ntcreate_and_X, AS_USER | CAN_IPC | QUEUE_IN_OPLOCK },
/* 0xa3 */ { NULL, NULL, 0 },
/* 0xa4 */ { "SMBntcancel", reply_ntcancel, 0 },
/* 0xa5 */ { NULL, NULL, 0 },
/* 0xa6 */ { NULL, NULL, 0 },
/* 0xa7 */ { NULL, NULL, 0 },
/* 0xa8 */ { NULL, NULL, 0 },
/* 0xa9 */ { NULL, NULL, 0 },
/* 0xaa */ { NULL, NULL, 0 },
/* 0xab */ { NULL, NULL, 0 },
/* 0xac */ { NULL, NULL, 0 },
/* 0xad */ { NULL, NULL, 0 },
/* 0xae */ { NULL, NULL, 0 },
/* 0xaf */ { NULL, NULL, 0 },
/* 0xb0 */ { NULL, NULL, 0 },
/* 0xb1 */ { NULL, NULL, 0 },
/* 0xb2 */ { NULL, NULL, 0 },
/* 0xb3 */ { NULL, NULL, 0 },
/* 0xb4 */ { NULL, NULL, 0 },
/* 0xb5 */ { NULL, NULL, 0 },
/* 0xb6 */ { NULL, NULL, 0 },
/* 0xb7 */ { NULL, NULL, 0 },
/* 0xb8 */ { NULL, NULL, 0 },
/* 0xb9 */ { NULL, NULL, 0 },
/* 0xba */ { NULL, NULL, 0 },
/* 0xbb */ { NULL, NULL, 0 },
/* 0xbc */ { NULL, NULL, 0 },
/* 0xbd */ { NULL, NULL, 0 },
/* 0xbe */ { NULL, NULL, 0 },
/* 0xbf */ { NULL, NULL, 0 },
/* 0xc0 */ { "SMBsplopen",reply_printopen,AS_USER | QUEUE_IN_OPLOCK },
/* 0xc1 */ { "SMBsplwr",reply_printwrite,AS_USER},
/* 0xc2 */ { "SMBsplclose",reply_printclose,AS_USER},
/* 0xc3 */ { "SMBsplretq",reply_printqueue,AS_USER},
/* 0xc4 */ { NULL, NULL, 0 },
/* 0xc5 */ { NULL, NULL, 0 },
/* 0xc6 */ { NULL, NULL, 0 },
/* 0xc7 */ { NULL, NULL, 0 },
/* 0xc8 */ { NULL, NULL, 0 },
/* 0xc9 */ { NULL, NULL, 0 },
/* 0xca */ { NULL, NULL, 0 },
/* 0xcb */ { NULL, NULL, 0 },
/* 0xcc */ { NULL, NULL, 0 },
/* 0xcd */ { NULL, NULL, 0 },
/* 0xce */ { NULL, NULL, 0 },
/* 0xcf */ { NULL, NULL, 0 },
/* 0xd0 */ { "SMBsends",reply_sends,AS_GUEST},
/* 0xd1 */ { "SMBsendb",NULL,AS_GUEST},
/* 0xd2 */ { "SMBfwdname",NULL,AS_GUEST},
/* 0xd3 */ { "SMBcancelf",NULL,AS_GUEST},
/* 0xd4 */ { "SMBgetmac",NULL,AS_GUEST},
/* 0xd5 */ { "SMBsendstrt",reply_sendstrt,AS_GUEST},
/* 0xd6 */ { "SMBsendend",reply_sendend,AS_GUEST},
/* 0xd7 */ { "SMBsendtxt",reply_sendtxt,AS_GUEST},
/* 0xd8 */ { NULL, NULL, 0 },
/* 0xd9 */ { NULL, NULL, 0 },
/* 0xda */ { NULL, NULL, 0 },
/* 0xdb */ { NULL, NULL, 0 },
/* 0xdc */ { NULL, NULL, 0 },
/* 0xdd */ { NULL, NULL, 0 },
/* 0xde */ { NULL, NULL, 0 },
/* 0xdf */ { NULL, NULL, 0 },
/* 0xe0 */ { NULL, NULL, 0 },
/* 0xe1 */ { NULL, NULL, 0 },
/* 0xe2 */ { NULL, NULL, 0 },
/* 0xe3 */ { NULL, NULL, 0 },
/* 0xe4 */ { NULL, NULL, 0 },
/* 0xe5 */ { NULL, NULL, 0 },
/* 0xe6 */ { NULL, NULL, 0 },
/* 0xe7 */ { NULL, NULL, 0 },
/* 0xe8 */ { NULL, NULL, 0 },
/* 0xe9 */ { NULL, NULL, 0 },
/* 0xea */ { NULL, NULL, 0 },
/* 0xeb */ { NULL, NULL, 0 },
/* 0xec */ { NULL, NULL, 0 },
/* 0xed */ { NULL, NULL, 0 },
/* 0xee */ { NULL, NULL, 0 },
/* 0xef */ { NULL, NULL, 0 },
/* 0xf0 */ { NULL, NULL, 0 },
/* 0xf1 */ { NULL, NULL, 0 },
/* 0xf2 */ { NULL, NULL, 0 },
/* 0xf3 */ { NULL, NULL, 0 },
/* 0xf4 */ { NULL, NULL, 0 },
/* 0xf5 */ { NULL, NULL, 0 },
/* 0xf6 */ { NULL, NULL, 0 },
/* 0xf7 */ { NULL, NULL, 0 },
/* 0xf8 */ { NULL, NULL, 0 },
/* 0xf9 */ { NULL, NULL, 0 },
/* 0xfa */ { NULL, NULL, 0 },
/* 0xfb */ { NULL, NULL, 0 },
/* 0xfc */ { NULL, NULL, 0 },
/* 0xfd */ { NULL, NULL, 0 },
/* 0xfe */ { NULL, NULL, 0 },
/* 0xff */ { NULL, NULL, 0 }

};

/*******************************************************************
dump a prs to a file
 ********************************************************************/
static void smb_dump(const char *name, int type, const char *data, ssize_t len)
{
	int fd, i;
	pstring fname;
	if (DEBUGLEVEL < 50) return;

	if (len < 4) len = smb_len(data)+4;
	for (i=1;i<100;i++) {
		slprintf(fname,sizeof(fname)-1, "/tmp/%s.%d.%s", name, i,
				type ? "req" : "resp");
		fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, 0644);
		if (fd != -1 || errno != EEXIST) break;
	}
	if (fd != -1) {
		ssize_t ret = write(fd, data, len);
		if (ret != len)
			DEBUG(0,("smb_dump: problem: write returned %d\n", (int)ret ));
		close(fd);
		DEBUG(0,("created %s len %d\n", fname, len));
	}
}


/****************************************************************************
 Do a switch on the message type, and return the response size.
****************************************************************************/

static int switch_message(int type,char *inbuf,char *outbuf,int size,int bufsize)
{
  static pid_t pid= (pid_t)-1;
  int outsize = 0;
  extern uint16 global_smbpid;

  type &= 0xff;

  if (pid == (pid_t)-1)
    pid = sys_getpid();

  errno = 0;
  last_message = type;

  /* make sure this is an SMB packet. smb_size contains NetBIOS header so subtract 4 from it. */
  if ((strncmp(smb_base(inbuf),"\377SMB",4) != 0) || (size < (smb_size-4))) {
    DEBUG(0,("Non-SMB packet of length %d. Terminating server\n",smb_len(inbuf)));
    exit_server("Non-SMB packet");
    return(-1);
  }

  /* yuck! this is an interim measure before we get rid of our
     current inbuf/outbuf system */
  global_smbpid = SVAL(inbuf,smb_pid);

  if (smb_messages[type].fn == NULL)
  {
    DEBUG(0,("Unknown message type %d!\n",type));
    smb_dump("Unknown", 1, inbuf, size);
    outsize = reply_unknown(inbuf,outbuf);
  }
  else
  {
    int flags = smb_messages[type].flags;
    static uint16 last_session_tag = UID_FIELD_INVALID;
    /* In share mode security we must ignore the vuid. */
    uint16 session_tag = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID : SVAL(inbuf,smb_uid);
    connection_struct *conn = conn_find(SVAL(inbuf,smb_tid));

    DEBUG(3,("switch message %s (pid %d)\n",smb_fn_name(type),(int)pid));

    smb_dump(smb_fn_name(type), 1, inbuf, size);
    if(global_oplock_break)
    {
      if(flags & QUEUE_IN_OPLOCK)
      {
        /* 
         * Queue this message as we are the process of an oplock break.
         */

        DEBUG( 2, ( "switch_message: queueing message due to being in " ) );
        DEBUGADD( 2, ( "oplock break state.\n" ) );

        push_oplock_pending_smb_message( inbuf, size );
        return -1;
      }          
    }

    /* Ensure this value is replaced in the incoming packet. */
    SSVAL(inbuf,smb_uid,session_tag);

    /*
     * Ensure the correct username is in current_user_info.
     * This is a really ugly bugfix for problems with
     * multiple session_setup_and_X's being done and
     * allowing %U and %G substitutions to work correctly.
     * There is a reason this code is done here, don't
     * move it unless you know what you're doing... :-).
     * JRA.
     */

    if (session_tag != last_session_tag) {
      user_struct *vuser = NULL;

      last_session_tag = session_tag;
      if(session_tag != UID_FIELD_INVALID)
        vuser = get_valid_user_struct(session_tag);           
      if(vuser != NULL)
        current_user_info = vuser->user;
    }

    /* does this protocol need to be run as root? */
    if (!(flags & AS_USER))
      change_to_root_user();

    /* does this protocol need a valid tree connection? */
    if ((flags & AS_USER) && !conn) {
	    return ERROR_DOS(ERRSRV, ERRinvnid);
    }


    /* does this protocol need to be run as the connected user? */
    if ((flags & AS_USER) && !change_to_user(conn,session_tag)) {
      if (flags & AS_GUEST) 
        flags &= ~AS_USER;
      else
        return(ERROR_DOS(ERRSRV,ERRaccess));
    }

    /* this code is to work around a bug is MS client 3 without
       introducing a security hole - it needs to be able to do
       print queue checks as guest if it isn't logged in properly */
    if (flags & AS_USER)
      flags &= ~AS_GUEST;

    /* does it need write permission? */
    if ((flags & NEED_WRITE) && !CAN_WRITE(conn))
      return(ERROR_DOS(ERRSRV,ERRaccess));

    /* ipc services are limited */
    if (IS_IPC(conn) && (flags & AS_USER) && !(flags & CAN_IPC)) {
      return(ERROR_DOS(ERRSRV,ERRaccess));	    
    }

    /* load service specific parameters */
    if (conn && !set_current_service(conn,(flags & AS_USER)?True:False)) {
      return(ERROR_DOS(ERRSRV,ERRaccess));
    }

    /* does this protocol need to be run as guest? */
    if ((flags & AS_GUEST) && 
		 (!change_to_guest() || 
		!check_access(smbd_server_fd(), lp_hostsallow(-1), lp_hostsdeny(-1)))) {
      return(ERROR_DOS(ERRSRV,ERRaccess));
    }

    last_inbuf = inbuf;

    outsize = smb_messages[type].fn(conn, inbuf,outbuf,size,bufsize);
  }

  smb_dump(smb_fn_name(type), 0, outbuf, outsize);

  return(outsize);
}


/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
static int construct_reply(char *inbuf,char *outbuf,int size,int bufsize)
{
  int type = CVAL(inbuf,smb_com);
  int outsize = 0;
  int msg_type = CVAL(inbuf,0);

  GetTimeOfDay(&smb_last_time);

  chain_size = 0;
  file_chain_reset();
  reset_chain_p();

  if (msg_type != 0)
    return(reply_special(inbuf,outbuf));  

  construct_reply_common(inbuf, outbuf);

  outsize = switch_message(type,inbuf,outbuf,size,bufsize);

  outsize += chain_size;

  if(outsize > 4)
    smb_setlen(outbuf,outsize - 4);
  return(outsize);
}

/****************************************************************************
  process an smb from the client - split out from the process() code so
  it can be used by the oplock break code.
****************************************************************************/
void process_smb(char *inbuf, char *outbuf)
{
#ifdef WITH_SSL
  extern BOOL sslEnabled;     /* don't use function for performance reasons */
  static int sslConnected = 0;
#endif /* WITH_SSL */
  static int trans_num;
  int msg_type = CVAL(inbuf,0);
  int32 len = smb_len(inbuf);
  int nread = len + 4;

  DO_PROFILE_INC(smb_count);

  if (trans_num == 0) {
	  /* on the first packet, check the global hosts allow/ hosts
	     deny parameters before doing any parsing of the packet
	     passed to us by the client.  This prevents attacks on our
	     parsing code from hosts not in the hosts allow list */
	  if (!check_access(smbd_server_fd(), lp_hostsallow(-1), lp_hostsdeny(-1))) {
		  /* send a negative session response "not listening on calling
		   name" */
		  static unsigned char buf[5] = {0x83, 0, 0, 1, 0x81};
		  DEBUG( 1, ( "Connection denied from %s\n",
			      client_addr() ) );
		  (void)send_smb(smbd_server_fd(),(char *)buf);
		  exit_server("connection denied");
	  }
  }

  DEBUG( 6, ( "got message type 0x%x of len 0x%x\n", msg_type, len ) );
  DEBUG( 3, ( "Transaction %d of length %d\n", trans_num, nread ) );

#ifdef WITH_SSL
    if(sslEnabled && !sslConnected){
        sslConnected = sslutil_negotiate_ssl(smbd_server_fd(), msg_type);
        if(sslConnected < 0){   /* an error occured */
            exit_server("SSL negotiation failed");
        }else if(sslConnected){
            trans_num++;
            return;
        }
    }
#endif  /* WITH_SSL */

  if (msg_type == 0)
    show_msg(inbuf);
  else if(msg_type == 0x85)
    return; /* Keepalive packet. */

  nread = construct_reply(inbuf,outbuf,nread,max_send);
      
  if(nread > 0) 
  {
    if (CVAL(outbuf,0) == 0)
      show_msg(outbuf);
	
    if (nread != smb_len(outbuf) + 4) 
    {
      DEBUG(0,("ERROR: Invalid message response size! %d %d\n",
                 nread, smb_len(outbuf)));
    }
    else
      if (!send_smb(smbd_server_fd(),outbuf))
        exit_server("process_smb: send_smb failed.\n");
  }
  trans_num++;
}



/****************************************************************************
return a string containing the function name of a SMB command
****************************************************************************/
const char *smb_fn_name(int type)
{
	static const char *unknown_name = "SMBunknown";

	if (smb_messages[type].name == NULL)
		return(unknown_name);

	return(smb_messages[type].name);
}


/****************************************************************************
 Helper function for contruct_reply.
****************************************************************************/

void construct_reply_common(char *inbuf,char *outbuf)
{
  memset(outbuf,'\0',smb_size);

  set_message(outbuf,0,0,True);
  SCVAL(outbuf,smb_com,CVAL(inbuf,smb_com));

  memcpy(outbuf+4,inbuf+4,4);
  SCVAL(outbuf,smb_rcls,SMB_SUCCESS);
  SCVAL(outbuf,smb_reh,0);
  SCVAL(outbuf,smb_flg, FLAG_REPLY | (CVAL(inbuf,smb_flg) & FLAG_CASELESS_PATHNAMES)); /* bit 7 set
                                 means a reply */
  SSVAL(outbuf,smb_flg2,FLAGS2_LONG_PATH_COMPONENTS);
	/* say we support long filenames */

  SSVAL(outbuf,smb_err,SMB_SUCCESS);
  SSVAL(outbuf,smb_tid,SVAL(inbuf,smb_tid));
  SSVAL(outbuf,smb_pid,SVAL(inbuf,smb_pid));
  SSVAL(outbuf,smb_uid,SVAL(inbuf,smb_uid));
  SSVAL(outbuf,smb_mid,SVAL(inbuf,smb_mid));
}

/****************************************************************************
  construct a chained reply and add it to the already made reply
  **************************************************************************/
int chain_reply(char *inbuf,char *outbuf,int size,int bufsize)
{
  static char *orig_inbuf;
  static char *orig_outbuf;
  int smb_com1, smb_com2 = CVAL(inbuf,smb_vwv0);
  unsigned smb_off2 = SVAL(inbuf,smb_vwv1);
  char *inbuf2, *outbuf2;
  int outsize2;
  char inbuf_saved[smb_wct];
  char outbuf_saved[smb_wct];
  int wct = CVAL(outbuf,smb_wct);
  int outsize = smb_size + 2*wct + SVAL(outbuf,smb_vwv0+2*wct);

  /* maybe its not chained */
  if (smb_com2 == 0xFF) {
    SCVAL(outbuf,smb_vwv0,0xFF);
    return outsize;
  }

  if (chain_size == 0) {
    /* this is the first part of the chain */
    orig_inbuf = inbuf;
    orig_outbuf = outbuf;
  }

  /*
   * The original Win95 redirector dies on a reply to
   * a lockingX and read chain unless the chain reply is
   * 4 byte aligned. JRA.
   */

  outsize = (outsize + 3) & ~3;

  /* we need to tell the client where the next part of the reply will be */
  SSVAL(outbuf,smb_vwv1,smb_offset(outbuf+outsize,outbuf));
  SCVAL(outbuf,smb_vwv0,smb_com2);

  /* remember how much the caller added to the chain, only counting stuff
     after the parameter words */
  chain_size += outsize - smb_wct;

  /* work out pointers into the original packets. The
     headers on these need to be filled in */
  inbuf2 = orig_inbuf + smb_off2 + 4 - smb_wct;
  outbuf2 = orig_outbuf + SVAL(outbuf,smb_vwv1) + 4 - smb_wct;

  /* remember the original command type */
  smb_com1 = CVAL(orig_inbuf,smb_com);

  /* save the data which will be overwritten by the new headers */
  memcpy(inbuf_saved,inbuf2,smb_wct);
  memcpy(outbuf_saved,outbuf2,smb_wct);

  /* give the new packet the same header as the last part of the SMB */
  memmove(inbuf2,inbuf,smb_wct);

  /* create the in buffer */
  SCVAL(inbuf2,smb_com,smb_com2);

  /* create the out buffer */
  construct_reply_common(inbuf2, outbuf2);

  DEBUG(3,("Chained message\n"));
  show_msg(inbuf2);

  /* process the request */
  outsize2 = switch_message(smb_com2,inbuf2,outbuf2,size-chain_size,
			    bufsize-chain_size);

  /* copy the new reply and request headers over the old ones, but
     preserve the smb_com field */
  memmove(orig_outbuf,outbuf2,smb_wct);
  SCVAL(orig_outbuf,smb_com,smb_com1);

  /* restore the saved data, being careful not to overwrite any
   data from the reply header */
  memcpy(inbuf2,inbuf_saved,smb_wct);
  {
    int ofs = smb_wct - PTR_DIFF(outbuf2,orig_outbuf);
    if (ofs < 0) ofs = 0;
    memmove(outbuf2+ofs,outbuf_saved+ofs,smb_wct-ofs);
  }

  return outsize2;
}

/****************************************************************************
 Setup the needed select timeout.
****************************************************************************/

static int setup_select_timeout(void)
{
	int select_timeout;
	int t;

	select_timeout = blocking_locks_timeout(SMBD_SELECT_TIMEOUT);
	select_timeout *= 1000;

	t = change_notify_timeout();
	if (t != -1) select_timeout = MIN(select_timeout, t*1000);

	return select_timeout;
}

/****************************************************************************
 Check if services need reloading.
****************************************************************************/

void check_reload(int t)
{
  static time_t last_smb_conf_reload_time = 0;

  if(last_smb_conf_reload_time == 0)
    last_smb_conf_reload_time = t;

  if (reload_after_sighup || (t >= last_smb_conf_reload_time+SMBD_RELOAD_CHECK))
  {
    reload_services(True);
    reload_after_sighup = 0;
    last_smb_conf_reload_time = t;
  }
}

/****************************************************************************
 Process any timeout housekeeping. Return False if the caller should exit.
****************************************************************************/

static BOOL timeout_processing(int deadtime, int *select_timeout, time_t *last_timeout_processing_time)
{
  static time_t last_keepalive_sent_time = 0;
  static time_t last_idle_closed_check = 0;
  time_t t;
  BOOL allidle = True;
  extern int keepalive;

  if (smb_read_error == READ_EOF) 
  {
    DEBUG(3,("end of file from client\n"));
    return False;
  }

  if (smb_read_error == READ_ERROR) 
  {
    DEBUG(3,("receive_smb error (%s) exiting\n",
              strerror(errno)));
    return False;
  }

  *last_timeout_processing_time = t = time(NULL);

  if(last_keepalive_sent_time == 0)
    last_keepalive_sent_time = t;

  if(last_idle_closed_check == 0)
    last_idle_closed_check = t;

  /* become root again if waiting */
  change_to_root_user();

  /* check if we need to reload services */
  check_reload(t);

  /* automatic timeout if all connections are closed */      
  if (conn_num_open()==0 && (t - last_idle_closed_check) >= IDLE_CLOSED_TIMEOUT) 
  {
    DEBUG( 2, ( "Closing idle connection\n" ) );
    return False;
  }
  else
    last_idle_closed_check = t;

  if (keepalive && (t - last_keepalive_sent_time)>keepalive) 
  {
    struct cli_state *cli = server_client();
    if (!send_keepalive(smbd_server_fd())) {
      DEBUG( 2, ( "Keepalive failed - exiting.\n" ) );
      return False;
    }	    
    /* also send a keepalive to the password server if its still
       connected */
    if (cli && cli->initialised)
      if (!send_keepalive(cli->fd)) {
        DEBUG( 2, ( "password server keepalive failed.\n"));
        cli_shutdown(cli);
      }
    last_keepalive_sent_time = t;
  }

  /* check for connection timeouts */
  allidle = conn_idle_all(t, deadtime);

  if (allidle && conn_num_open()>0) {
    DEBUG(2,("Closing idle connection 2.\n"));
    return False;
  }

  if(global_machine_password_needs_changing && lp_security() == SEC_DOMAIN)
  {
    unsigned char trust_passwd_hash[16];
    time_t lct;
    pstring remote_machine_list;

    /*
     * We're in domain level security, and the code that
     * read the machine password flagged that the machine
     * password needs changing.
     */

    DEBUG(10,("timeout_processing: checking to see if machine account password need changing.\n"));

    /*
     * First, open the machine password file with an exclusive lock.
     */

    if (secrets_lock_trust_account_password(global_myworkgroup, True) == False) {
      DEBUG(0,("process: unable to lock the machine account password for \
machine %s in domain %s.\n", global_myname, global_myworkgroup ));
      return True;
    }

    if(!secrets_fetch_trust_account_password(global_myworkgroup, trust_passwd_hash, &lct)) {
      DEBUG(0,("process: unable to read the machine account password for \
machine %s in domain %s.\n", global_myname, global_myworkgroup ));
      secrets_lock_trust_account_password(global_myworkgroup, False);
      return True;
    }

    /*
     * Make sure someone else hasn't already done this.
     */

    if(t < lct + lp_machine_password_timeout()) {
      global_machine_password_needs_changing = False;
      secrets_lock_trust_account_password(global_myworkgroup, False);
      return True;
    }

    DEBUG(10,("timeout_processing: machine account password last change time = (%u) %s.\n",
			    (unsigned int)lct, http_timestring(lct)));

    pstrcpy(remote_machine_list, lp_passwordserver());

    change_trust_account_password( global_myworkgroup, remote_machine_list);
    global_machine_password_needs_changing = False;
    secrets_lock_trust_account_password(global_myworkgroup, False);
  }

  /*
   * Check to see if we have any blocking locks
   * outstanding on the queue.
   */
  process_blocking_lock_queue(t);

  /*
   * Check to see if we have any change notifies 
   * outstanding on the queue.
   */
  process_pending_change_notify_queue(t);

  /*
   * Now we are root, check if the log files need pruning.
   * Force a log file check.
   */
  force_check_log_size();
  check_log_size();

  /*
   * Modify the select timeout depending upon
   * what we have remaining in our queues.
   */

  *select_timeout = setup_select_timeout();

  return True;
}

/****************************************************************************
  process commands from the client
****************************************************************************/

void smbd_process(void)
{
	extern int smb_echo_count;
	time_t last_timeout_processing_time = time(NULL);
	unsigned int num_smbs = 0;

	InBuffer = (char *)malloc(BUFFER_SIZE + LARGE_WRITEX_HDR_SIZE + SAFETY_MARGIN);
	OutBuffer = (char *)malloc(BUFFER_SIZE + LARGE_WRITEX_HDR_SIZE + SAFETY_MARGIN);
	if ((InBuffer == NULL) || (OutBuffer == NULL)) 
		return;

	InBuffer += SMB_ALIGNMENT;
	OutBuffer += SMB_ALIGNMENT;

	max_recv = MIN(lp_maxxmit(),BUFFER_SIZE);

	/* re-initialise the timezone */
	TimeInit();

	/* register our message handlers */
	message_register(MSG_SMB_FORCE_TDIS, msg_force_tdis);

	while (True) {
		int deadtime = lp_deadtime()*60;
		int select_timeout = setup_select_timeout();
		int num_echos;

		if (deadtime <= 0)
			deadtime = DEFAULT_SMBD_TIMEOUT;

		errno = 0;      
		
		/* free up temporary memory */
		lp_talloc_free();
		main_loop_talloc_free();

		/* Did someone ask for immediate checks on things like blocking locks ? */
		if (select_timeout == 0) {
			if(!timeout_processing( deadtime, &select_timeout, &last_timeout_processing_time))
				return;
			num_smbs = 0; /* Reset smb counter. */
		}

		while (!receive_message_or_smb(InBuffer,BUFFER_SIZE+LARGE_WRITEX_HDR_SIZE,select_timeout)) {
			if(!timeout_processing( deadtime, &select_timeout, &last_timeout_processing_time))
				return;
			num_smbs = 0; /* Reset smb counter. */
		}

		/*
		 * Ensure we do timeout processing if the SMB we just got was
		 * only an echo request. This allows us to set the select
		 * timeout in 'receive_message_or_smb()' to any value we like
		 * without worrying that the client will send echo requests
		 * faster than the select timeout, thus starving out the
		 * essential processing (change notify, blocking locks) that
		 * the timeout code does. JRA.
		 */ 
		num_echos = smb_echo_count;

		process_smb(InBuffer, OutBuffer);

		if (smb_echo_count != num_echos) {
			if(!timeout_processing( deadtime, &select_timeout, &last_timeout_processing_time))
				return;
			num_smbs = 0; /* Reset smb counter. */
		}

		num_smbs++;

		/*
		 * If we are getting smb requests in a constant stream
		 * with no echos, make sure we attempt timeout processing
		 * every select_timeout milliseconds - but only check for this
		 * every 200 smb requests.
		 */
		
		if ((num_smbs % 200) == 0) {
			time_t new_check_time = time(NULL);
			if(new_check_time - last_timeout_processing_time >= (select_timeout/1000)) {
				if(!timeout_processing( deadtime, &select_timeout, &last_timeout_processing_time))
					return;
				num_smbs = 0; /* Reset smb counter. */
				last_timeout_processing_time = new_check_time; /* Reset time. */
			}
		}
	}
}
