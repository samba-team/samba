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

extern int DEBUGLEVEL;

time_t smb_last_time=(time_t)0;

char *InBuffer = NULL;
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
extern pstring sesssetup_user;
extern char *last_inbuf;
extern char *InBuffer;
extern char *OutBuffer;
extern int smb_read_error;
extern BOOL reload_after_sighup;
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
    free((char *)msg);
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
  Do a select on an two fd's - with timeout. 

  If a local udp message has been pushed onto the
  queue (this can only happen during oplock break
  processing) return this first.

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

static BOOL receive_message_or_smb(char *buffer, int buffer_len, 
                                   int timeout, BOOL *got_smb)
{
  extern int Client;
  fd_set fds;
  int selrtn;
  struct timeval to;
  int maxfd;

  smb_read_error = 0;

  *got_smb = False;

  /*
   * Check to see if we already have a message on the smb queue.
   * If so - copy and return it.
   */
  
  if(ubi_slCount(&smb_oplock_queue) != 0)
  {
    pending_message_list *msg = (pending_message_list *)ubi_slRemHead(&smb_oplock_queue);
    memcpy(buffer, msg->msg_buf, MIN(buffer_len, msg->msg_len));
  
    /* Free the message we just copied. */
    free((char *)msg->msg_buf);
    free((char *)msg);
    *got_smb = True;

    DEBUG(5,("receive_message_or_smb: returning queued smb message.\n"));
    return True;
  }

  /*
   * Setup the select read fd set.
   */

  FD_ZERO(&fds);
  FD_SET(Client,&fds);
  maxfd = setup_oplock_select_set(&fds);

  to.tv_sec = timeout / 1000;
  to.tv_usec = (timeout % 1000) * 1000;

  selrtn = sys_select(MAX(maxfd,Client)+1,&fds,NULL, timeout>0?&to:NULL);

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

  if (FD_ISSET(Client,&fds))
  {
    *got_smb = True;
    return receive_smb(Client, buffer, 0);
  }
  else
  {
    return receive_local_message(&fds, buffer, buffer_len, 0);
  }
}

/****************************************************************************
Get the next SMB packet, doing the local message processing automatically.
****************************************************************************/

BOOL receive_next_smb(char *inbuf, int bufsize, int timeout)
{
  BOOL got_smb = False;
  BOOL ret;

  do
  {
    ret = receive_message_or_smb(inbuf,bufsize,timeout,&got_smb);

    if(ret && !got_smb)
    {
      /* Deal with oplock break requests from other smbd's. */
      process_local_message(inbuf, bufsize);
      continue;
    }

    if(ret && (CVAL(inbuf,0) == 0x85))
    {
      /* Keepalive packet. */
      got_smb = False;
    }

  }
  while(ret && !got_smb);

  return ret;
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
  int code;
  char *name;
  int (*fn)(connection_struct *conn, char *, char *, int, int);
  int flags;
}
 smb_messages[] = {

    /* CORE PROTOCOL */

   {SMBnegprot,"SMBnegprot",reply_negprot,0},
   {SMBtcon,"SMBtcon",reply_tcon,0},
   {SMBtdis,"SMBtdis",reply_tdis,0},
   {SMBexit,"SMBexit",reply_exit,0},
   {SMBioctl,"SMBioctl",reply_ioctl,0},
   {SMBecho,"SMBecho",reply_echo,0},
   {SMBsesssetupX,"SMBsesssetupX",reply_sesssetup_and_X,0},
   {SMBtconX,"SMBtconX",reply_tcon_and_X,0},
   {SMBulogoffX, "SMBulogoffX", reply_ulogoffX, 0}, /* ulogoff doesn't give a valid TID */
   {SMBgetatr,"SMBgetatr",reply_getatr,AS_USER},
   {SMBsetatr,"SMBsetatr",reply_setatr,AS_USER | NEED_WRITE},
   {SMBchkpth,"SMBchkpth",reply_chkpth,AS_USER},
   {SMBsearch,"SMBsearch",reply_search,AS_USER},
   {SMBopen,"SMBopen",reply_open,AS_USER | QUEUE_IN_OPLOCK },

   /* note that SMBmknew and SMBcreate are deliberately overloaded */   
   {SMBcreate,"SMBcreate",reply_mknew,AS_USER},
   {SMBmknew,"SMBmknew",reply_mknew,AS_USER}, 

   {SMBunlink,"SMBunlink",reply_unlink,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},
   {SMBread,"SMBread",reply_read,AS_USER},
   {SMBwrite,"SMBwrite",reply_write,AS_USER | CAN_IPC},
   {SMBclose,"SMBclose",reply_close,AS_USER | CAN_IPC},
   {SMBmkdir,"SMBmkdir",reply_mkdir,AS_USER | NEED_WRITE},
   {SMBrmdir,"SMBrmdir",reply_rmdir,AS_USER | NEED_WRITE},
   {SMBdskattr,"SMBdskattr",reply_dskattr,AS_USER},
   {SMBmv,"SMBmv",reply_mv,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},

   /* this is a Pathworks specific call, allowing the 
      changing of the root path */
   {pSETDIR,"pSETDIR",reply_setdir,AS_USER}, 

   {SMBlseek,"SMBlseek",reply_lseek,AS_USER},
   {SMBflush,"SMBflush",reply_flush,AS_USER},
   {SMBctemp,"SMBctemp",reply_ctemp,AS_USER | QUEUE_IN_OPLOCK },
   {SMBsplopen,"SMBsplopen",reply_printopen,AS_USER | QUEUE_IN_OPLOCK },
   {SMBsplclose,"SMBsplclose",reply_printclose,AS_USER},
   {SMBsplretq,"SMBsplretq",reply_printqueue,AS_USER},
   {SMBsplwr,"SMBsplwr",reply_printwrite,AS_USER},
   {SMBlock,"SMBlock",reply_lock,AS_USER},
   {SMBunlock,"SMBunlock",reply_unlock,AS_USER},
   
   /* CORE+ PROTOCOL FOLLOWS */
   
   {SMBreadbraw,"SMBreadbraw",reply_readbraw,AS_USER},
   {SMBwritebraw,"SMBwritebraw",reply_writebraw,AS_USER},
   {SMBwriteclose,"SMBwriteclose",reply_writeclose,AS_USER},
   {SMBlockread,"SMBlockread",reply_lockread,AS_USER},
   {SMBwriteunlock,"SMBwriteunlock",reply_writeunlock,AS_USER},
   
   /* LANMAN1.0 PROTOCOL FOLLOWS */
   
   {SMBreadBmpx,"SMBreadBmpx",reply_readbmpx,AS_USER},
   {SMBreadBs,"SMBreadBs",NULL,AS_USER},
   {SMBwriteBmpx,"SMBwriteBmpx",reply_writebmpx,AS_USER},
   {SMBwriteBs,"SMBwriteBs",reply_writebs,AS_USER},
   {SMBwritec,"SMBwritec",NULL,AS_USER},
   {SMBsetattrE,"SMBsetattrE",reply_setattrE,AS_USER | NEED_WRITE},
   {SMBgetattrE,"SMBgetattrE",reply_getattrE,AS_USER},
   {SMBtrans,"SMBtrans",reply_trans,AS_USER | CAN_IPC},
   {SMBtranss,"SMBtranss",NULL,AS_USER | CAN_IPC},
   {SMBioctls,"SMBioctls",NULL,AS_USER},
   {SMBcopy,"SMBcopy",reply_copy,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK },
   {SMBmove,"SMBmove",NULL,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK },
   
   {SMBopenX,"SMBopenX",reply_open_and_X,AS_USER | CAN_IPC | QUEUE_IN_OPLOCK },
   {SMBreadX,"SMBreadX",reply_read_and_X,AS_USER | CAN_IPC },
   {SMBwriteX,"SMBwriteX",reply_write_and_X,AS_USER | CAN_IPC },
   {SMBlockingX,"SMBlockingX",reply_lockingX,AS_USER},
   
   {SMBffirst,"SMBffirst",reply_search,AS_USER},
   {SMBfunique,"SMBfunique",reply_search,AS_USER},
   {SMBfclose,"SMBfclose",reply_fclose,AS_USER},

   /* LANMAN2.0 PROTOCOL FOLLOWS */
   {SMBfindnclose, "SMBfindnclose", reply_findnclose, AS_USER},
   {SMBfindclose, "SMBfindclose", reply_findclose,AS_USER},
   {SMBtrans2, "SMBtrans2", reply_trans2, AS_USER | CAN_IPC},
   {SMBtranss2, "SMBtranss2", reply_transs2, AS_USER},

   /* NT PROTOCOL FOLLOWS */
   {SMBntcreateX, "SMBntcreateX", reply_ntcreate_and_X, AS_USER | CAN_IPC | QUEUE_IN_OPLOCK },
   {SMBnttrans, "SMBnttrans", reply_nttrans, AS_USER | CAN_IPC },
   {SMBnttranss, "SMBnttranss", reply_nttranss, AS_USER | CAN_IPC },
   {SMBntcancel, "SMBntcancel", reply_ntcancel, AS_USER },

   /* messaging routines */
   {SMBsends,"SMBsends",reply_sends,AS_GUEST},
   {SMBsendstrt,"SMBsendstrt",reply_sendstrt,AS_GUEST},
   {SMBsendend,"SMBsendend",reply_sendend,AS_GUEST},
   {SMBsendtxt,"SMBsendtxt",reply_sendtxt,AS_GUEST},

   /* NON-IMPLEMENTED PARTS OF THE CORE PROTOCOL */
   
   {SMBsendb,"SMBsendb",NULL,AS_GUEST},
   {SMBfwdname,"SMBfwdname",NULL,AS_GUEST},
   {SMBcancelf,"SMBcancelf",NULL,AS_GUEST},
   {SMBgetmac,"SMBgetmac",NULL,AS_GUEST}
 };


/****************************************************************************
do a switch on the message type, and return the response size
****************************************************************************/
static int switch_message(int type,char *inbuf,char *outbuf,int size,int bufsize)
{
  static int pid= -1;
  int outsize = 0;
  static int num_smb_messages = 
    sizeof(smb_messages) / sizeof(struct smb_message_struct);
  int match;
  extern int Client;

  if (pid == -1)
    pid = getpid();

  errno = 0;
  last_message = type;

  /* make sure this is an SMB packet */
  if (strncmp(smb_base(inbuf),"\377SMB",4) != 0)
  {
    DEBUG(2,("Non-SMB packet of length %d\n",smb_len(inbuf)));
    return(-1);
  }

  for (match=0;match<num_smb_messages;match++)
    if (smb_messages[match].code == type)
      break;

  if (match == num_smb_messages)
  {
    DEBUG(0,("Unknown message type %d!\n",type));
    outsize = reply_unknown(inbuf,outbuf);
  }
  else
  {
    DEBUG(3,("switch message %s (pid %d)\n",smb_messages[match].name,pid));

    if(global_oplock_break && (smb_messages[match].flags & QUEUE_IN_OPLOCK))
    {
      /* 
       * Queue this message as we are the process of an oplock break.
       */

      DEBUG( 2, ( "switch_message: queueing message due to being in " ) );
      DEBUGADD( 2, ( "oplock break state.\n" ) );

      push_oplock_pending_smb_message( inbuf, size );
      return -1;
    }          

    if (smb_messages[match].fn)
    {
      int flags = smb_messages[match].flags;
      static uint16 last_session_tag = UID_FIELD_INVALID;
      /* In share mode security we must ignore the vuid. */
      uint16 session_tag = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID : SVAL(inbuf,smb_uid);
      connection_struct *conn = conn_find(SVAL(inbuf,smb_tid));


      /* Ensure this value is replaced in the incoming packet. */
      SSVAL(inbuf,smb_uid,session_tag);

      /*
       * Ensure the correct username is in sesssetup_user.
       * This is a really ugly bugfix for problems with
       * multiple session_setup_and_X's being done and
       * allowing %U and %G substitutions to work correctly.
       * There is a reason this code is done here, don't
       * move it unless you know what you're doing... :-).
       * JRA.
       */
      if (session_tag != last_session_tag)
      {
        user_struct *vuser = NULL;
        vuser_key key = { pid, session_tag };

        last_session_tag = session_tag;
        if(session_tag != UID_FIELD_INVALID)
          vuser = get_valid_user_struct(&key);           
        if(vuser != NULL)
        {
          pstrcpy( sesssetup_user, vuser->requested_name);
		vuid_free_user_struct(vuser);
	}
      }

      /* does this protocol need to be run as root? */
      if (!(flags & AS_USER))
        unbecome_user();

      /* does this protocol need to be run as the connected user? */
      if ((flags & AS_USER) && !become_user(conn,session_tag)) {
        if (flags & AS_GUEST) 
          flags &= ~AS_USER;
        else
          return(ERROR(ERRSRV,ERRinvnid));
      }
      /* this code is to work around a bug is MS client 3 without
         introducing a security hole - it needs to be able to do
         print queue checks as guest if it isn't logged in properly */
      if (flags & AS_USER)
        flags &= ~AS_GUEST;

      /* does it need write permission? */
      if ((flags & NEED_WRITE) && !CAN_WRITE(conn))
        return(ERROR(ERRSRV,ERRaccess));

      /* ipc services are limited */
      if (IS_IPC(conn) && (flags & AS_USER) && !(flags & CAN_IPC)) {
        return(ERROR(ERRSRV,ERRaccess));	    
      }

      /* load service specific parameters */
      if (conn && 
	  !become_service(conn,(flags & AS_USER)?True:False)) {
        return(ERROR(ERRSRV,ERRaccess));
      }

      /* does this protocol need to be run as guest? */
      if ((flags & AS_GUEST) && 
	  (!become_guest() || 
	   !check_access(Client, lp_hostsallow(-1), lp_hostsdeny(-1)))) {
        return(ERROR(ERRSRV,ERRaccess));
      }

      last_inbuf = inbuf;

      outsize = smb_messages[match].fn(conn, inbuf,outbuf,size,bufsize);
    }
    else
    {
      outsize = reply_unknown(inbuf,outbuf);
    }
  }

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
  extern int chain_size;

  smb_last_time = time(NULL);

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
  extern int Client;
#ifdef WITH_SSL
  extern BOOL sslEnabled;     /* don't use function for performance reasons */
  static int sslConnected = 0;
#endif /* WITH_SSL */
  static int trans_num;
  int msg_type = CVAL(inbuf,0);
  int32 len = smb_len(inbuf);
  int nread = len + 4;

#ifdef WITH_PROFILE
  profile_p->smb_count++;
#endif

  if (trans_num == 0) {
	  /* on the first packet, check the global hosts allow/ hosts
	     deny parameters before doing any parsing of the packet
	     passed to us by the client.  This prevents attacks on our
	     parsing code from hosts not in the hosts allow list */
	  if (!check_access(Client, lp_hostsallow(-1), lp_hostsdeny(-1))) {
		  /* send a negative session response "not listining on calling
		   name" */
		  static unsigned char buf[5] = {0x83, 0, 0, 1, 0x81};
		  DEBUG( 1, ( "Connection denied from %s\n",
			      client_connection_addr() ) );
		  send_smb(Client,(char *)buf);
		  exit_server("connection denied");
	  }
  }

  DEBUG( 6, ( "got message type 0x%x of len 0x%x\n", msg_type, len ) );
  DEBUG( 3, ( "Transaction %d of length %d\n", trans_num, nread ) );

#ifdef WITH_SSL
    if(sslEnabled && !sslConnected){
        sslConnected = sslutil_negotiate_ssl(Client, msg_type);
        if(sslConnected < 0){   /* an error occured */
            exit_server("SSL negotiation failed");
        }else if(sslConnected){
            trans_num++;
            return;
        }
    }
#endif  /* WITH_SSL */

#ifdef WITH_VTP
  if(trans_num == 1 && VT_Check(inbuf)) 
  {
    VT_Process();
    return;
  }
#endif

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
      send_smb(Client,outbuf);
  }
  trans_num++;
}



/****************************************************************************
return a string containing the function name of a SMB command
****************************************************************************/
char *smb_fn_name(int type)
{
	static char *unknown_name = "SMBunknown";
	static int num_smb_messages = 
		sizeof(smb_messages) / sizeof(struct smb_message_struct);
	int match;

	for (match=0;match<num_smb_messages;match++)
		if (smb_messages[match].code == type)
			break;

	if (match == num_smb_messages)
		return(unknown_name);

	return(smb_messages[match].name);
}


/****************************************************************************
 Helper function for contruct_reply.
****************************************************************************/

void construct_reply_common(char *inbuf,char *outbuf)
{
  bzero(outbuf,smb_size);

  set_message(outbuf,0,0,True);
  CVAL(outbuf,smb_com) = CVAL(inbuf,smb_com);

  memcpy(outbuf+4,inbuf+4,4);
  CVAL(outbuf,smb_rcls) = SMB_SUCCESS;
  CVAL(outbuf,smb_reh) = 0;
  SCVAL(outbuf,smb_flg, FLAG_REPLY | (CVAL(inbuf,smb_flg) & FLAG_CASELESS_PATHNAMES)); /* bit 7 set
                                 means a reply */
  SSVAL(outbuf,smb_flg2,FLAGS2_LONG_PATH_COMPONENTS); /* say we support long filenames */
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
  extern int chain_size;
  int wct = CVAL(outbuf,smb_wct);
  int outsize = smb_size + 2*wct + SVAL(outbuf,smb_vwv0+2*wct);

  /* maybe its not chained */
  if (smb_com2 == 0xFF) {
    CVAL(outbuf,smb_vwv0) = 0xFF;
    return outsize;
  }

  if (chain_size == 0) {
    /* this is the first part of the chain */
    orig_inbuf = inbuf;
    orig_outbuf = outbuf;
  }

  /* we need to tell the client where the next part of the reply will be */
  SSVAL(outbuf,smb_vwv1,smb_offset(outbuf+outsize,outbuf));
  CVAL(outbuf,smb_vwv0) = smb_com2;

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
  CVAL(inbuf2,smb_com) = smb_com2;

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
  CVAL(orig_outbuf,smb_com) = smb_com1;

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
  process commands from the client
****************************************************************************/
void smbd_process(void)
{
  extern int Client;
  extern int ClientPort;

  InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return;

  InBuffer += SMB_ALIGNMENT;
  OutBuffer += SMB_ALIGNMENT;

#if PRIME_NMBD
  DEBUG(3,("priming nmbd\n"));
  {
    struct in_addr ip;
    ip = *interpret_addr2("localhost");
    if (zero_ip(ip)) ip = *interpret_addr2("127.0.0.1");
    *OutBuffer = 0;
    send_one_packet(OutBuffer,1,ip,NMB_PORT,SOCK_DGRAM);
  }
#endif    


  max_recv = MIN(lp_maxxmit(),BUFFER_SIZE);

  /* re-initialise the timezone */
  TimeInit();

  /* if connection on port 445, fake session setup... */
  if(ClientPort == 445)
  {
    extern fstring remote_machine;
    extern fstring local_machine;

    fstrcpy(remote_machine, dns_to_netbios_name(client_connection_name()));
    fstrcpy(local_machine, global_myname);
    remote_machine[15] = 0;
    local_machine[15] = 0;
    strlower(remote_machine);
    strlower(local_machine);

    DEBUG(2, ("smbd_process(): faking session setup\n"
              "client_name: %s my_name: %s\n", remote_machine, local_machine));

    add_session_user(remote_machine);

    reload_services(True);
    reopen_logs();

    if(lp_status(-1)) {
      claim_connection(NULL,"STATUS.",MAXSTATUS,True);
    }
  }

  while (True)
  {
    int deadtime = lp_deadtime()*60;
    int counter;
    int last_keepalive=0;
    int service_load_counter = 0;
    BOOL got_smb = False;

    if (deadtime <= 0)
      deadtime = DEFAULT_SMBD_TIMEOUT;

#if USE_READ_PREDICTION
    if (lp_readprediction())
      do_read_prediction();
#endif

    errno = 0;      

    for (counter=SMBD_SELECT_LOOP; 
          !receive_message_or_smb(InBuffer,BUFFER_SIZE,
                                  SMBD_SELECT_LOOP*1000,&got_smb); 
          counter += SMBD_SELECT_LOOP)
    {
      time_t t;
      BOOL allidle = True;
      extern int keepalive;

      if (counter > 365 * 3600) /* big number of seconds. */
      {
        counter = 0;
        service_load_counter = 0;
      }

      if (smb_read_error == READ_EOF) 
      {
        DEBUG(3,("end of file from client\n"));
        return;
      }

      if (smb_read_error == READ_ERROR) 
      {
        DEBUG(3,("receive_smb error (%s) exiting\n",
                  strerror(errno)));
        return;
      }

      t = time(NULL);

      /* become root again if waiting */
      unbecome_user();

      /* check for smb.conf reload */
      if (counter >= service_load_counter + SMBD_RELOAD_CHECK)
      {
        service_load_counter = counter;

        /* reload services, if files have changed. */
        reload_services(True);
      }

      /*
       * If reload_after_sighup == True then we got a SIGHUP
       * and are being asked to reload. Fix from <branko.cibej@hermes.si>
       */

      if (reload_after_sighup)
      {
        DEBUG(0,("Reloading services after SIGHUP\n"));
        reload_services(False);
        reload_after_sighup = False;
        /*
         * Use this as an excuse to print some stats.
         */
        print_stat_cache_statistics();
      }

      /* automatic timeout if all connections are closed */      
      if (conn_num_open()==0 && counter >= IDLE_CLOSED_TIMEOUT) 
      {
        DEBUG( 2, ( "Closing idle connection\n" ) );
        return;
      }

      if (keepalive && (counter-last_keepalive)>keepalive) 
      {
	      if (!send_keepalive(Client)) {
		      DEBUG( 2, ( "Keepalive failed - exiting.\n" ) );
		      return;
	      }	    
	      last_keepalive = counter;
      }

	/* close down all idle client-side MSRPC connections */
	free_connections();

      /* check for connection timeouts */
      allidle = conn_idle_all(t, deadtime);

      if (allidle && conn_num_open()>0) {
	      DEBUG(2,("Closing idle connection 2.\n"));
	      return;
      }

      if(global_machine_password_needs_changing)
      {
        unsigned char trust_passwd_hash[16];
        time_t lct;
        pstring remote_machine_list;
        int sec_chan = SEC_CHAN_WKSTA;

        /*
         * We're in domain level security, and the code that
         * read the machine password flagged that the machine
         * password needs changing.
         */

        /*
         * First, open the machine password file with an exclusive lock.
         */

        if(!trust_password_lock( global_myworkgroup, global_myname, True)) {
          DEBUG(0,("process: unable to open the machine account password file for \
machine %s in domain %s.\n", global_myname, global_myworkgroup ));
          continue;
        }

        if(!get_trust_account_password( trust_passwd_hash, &lct)) {
          DEBUG(0,("process: unable to read the machine account password for \
machine %s in domain %s.\n", global_myname, global_myworkgroup ));
          trust_password_unlock();
          continue;
        }

        /*
         * Make sure someone else hasn't already done this.
         */

        if(t < lct + lp_machine_password_timeout()) {
          trust_password_unlock();
          global_machine_password_needs_changing = False;
          continue;
        }

        pstrcpy(remote_machine_list, lp_passwordserver());
        if (lp_server_role() == ROLE_DOMAIN_BDC)
          sec_chan = SEC_CHAN_BDC;

        change_trust_account_password(global_myworkgroup, remote_machine_list,
                                        sec_chan);
        trust_password_unlock();
        global_machine_password_needs_changing = False;
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
    }

    if(got_smb)
      process_smb(InBuffer, OutBuffer);
    else
      process_local_message(InBuffer, BUFFER_SIZE);
  }
}
