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
static struct pipes_struct static_pipe;

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
extern pstring sesssetup_user;
extern char *last_inbuf;
extern char *InBuffer;
extern char *OutBuffer;
extern int smb_read_error;
extern BOOL reload_after_sighup;
extern int max_send;


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
  
  /*
   * Setup the select read fd set.
   */

  FD_ZERO(&fds);
  FD_SET(Client,&fds);
  maxfd = 0;

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
	return False;
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

/****************************************************************************
do a switch on the message type, and return the response size
****************************************************************************/
static int do_message(char *inbuf,char *outbuf,int size,int bufsize)
{
  static int pid= -1;

	pipes_struct *p = &static_pipe;
	prs_struct pd;
	int outsize = -1;

 	/* make a static data parsing structure from the api_fd_reply data */
 	prs_init(&pd, 0, 4, 0, True);
 	mem_create(pd.data, smb_base(inbuf), 0, smb_len(inbuf), 0, False);

  if (pid == -1)
    pid = getpid();

	/* dce/rpc command */
	if (rpc_command(p, &pd))
	{
		char *copy_into = smb_base(outbuf);
		outsize = mem_buf_len(p->rhdr.data);
		if (!mem_buf_copy(copy_into, p->rhdr.data, 0, outsize))
		{
			return -1;
		}
	}
 	mem_free_data(pd.data);

	mem_free_data(p->rhdr .data);
	mem_free_data(p->rfault .data);
	mem_free_data(p->rdata  .data);
	mem_free_data(p->rdata_i.data);		
	mem_free_data(p->rauth  .data);
	mem_free_data(p->rverf  .data);
	mem_free_data(p->rntlm  .data);		

	return outsize;
}


/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
static int construct_reply(char *inbuf,char *outbuf,int size,int bufsize)
{
  int outsize = 0;
  smb_last_time = time(NULL);

  outsize = do_message(inbuf,outbuf,size,bufsize) + 4;

  if(outsize > 4)
    _smb_setlen(outbuf,outsize - 4);
  return(outsize);
}


/****************************************************************************
  process an smb from the client - split out from the process() code so
  it can be used by the oplock break code.
****************************************************************************/
void process_smb(char *inbuf, char *outbuf)
{
  extern int Client;
  static int trans_num;
  int32 len = smb_len(inbuf);
  int nread = len + 4;

  if (trans_num == 0) {
	  /* on the first packet, check the global hosts allow/ hosts
	     deny parameters before doing any parsing of the packet
	     passed to us by the client.  This prevents attacks on our
	     parsing code from hosts not in the hosts allow list */
	  if (!check_access(Client, lp_hostsallow(-1), lp_hostsdeny(-1))) {
		  /* send a negative session response "not listining on calling
		   name" */
		  DEBUG( 1, ( "Connection denied from %s\n",
			      client_addr(Client) ) );
		  exit_server("connection denied");
	  }
  }

  DEBUG( 6, ( "got message of len 0x%x\n", len ) );
  DEBUG( 3, ( "Transaction %d of length %d\n", trans_num, nread ) );

	dump_data(10, inbuf, len);

#ifdef WITH_VTP
  if(trans_num == 1 && VT_Check(inbuf)) 
  {
    VT_Process();
    return;
  }
#endif

  nread = construct_reply(inbuf,outbuf,nread,max_send);
      
  if(nread > 0) 
  {
      dump_data(10, outbuf, nread);
	
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


BOOL get_user_creds(struct user_creds *usr)
{
	pstring buf;
	int rl;
	uint32 len;
	BOOL new_con = False;
	extern int Client;
	uint32 status;

	CREDS_CMD cmd;
	prs_struct ps;

	ZERO_STRUCTP(usr);
	ZERO_STRUCT(cmd);
	cmd.cred = usr;

	DEBUG(10,("get_user_creds: first request\n"));

	rl = read(Client, &buf, sizeof(len));

	if (rl != sizeof(len))
	{
		DEBUG(0,("Unable to read length\n"));
		dump_data(0, buf, sizeof(len));
		return False;
	}

	len = IVAL(buf, 0);

	if (len > sizeof(buf))
	{
		DEBUG(0,("length %d too long\n", len));
		return False;
	}

	rl = read(Client, buf, len);

	if (rl < 0)
	{
		DEBUG(0,("Unable to read from connection\n"));
		return False;
	}
	
#ifdef DEBUG_PASSWORD
	dump_data(100, buf, rl);
#endif

 	/* make a static data parsing structure from the api_fd_reply data */
 	prs_init(&ps, 0, 4, 0, True);
 	mem_create(ps.data, buf, 0, len, 0, False);

	if (!creds_io_cmd("creds", &cmd, &ps, 0))
	{
		DEBUG(0,("Unable to parse credentials\n"));
		mem_free_data(ps.data);
		return False;
	}

 	mem_free_data(ps.data);

	if (ps.offset != rl)
	{
		DEBUG(0,("Buffer size %d %d!\n", ps.offset, rl));
		return False;
	}

	switch (cmd.command)
	{
		case AGENT_CMD_CON:
		case AGENT_CMD_CON_ANON:
		{
			new_con = True;
			break;
		}
		case AGENT_CMD_CON_REUSE:
		{
			new_con = True;
			break;
		}
		default:
		{
			DEBUG(0,("unknown command %d\n", cmd.command));
			return False;
		}
	}

	status = new_con ? 0x0 : 0x1;

	if (write(Client, &status, sizeof(status)) !=
	    sizeof(status))
	{
		return False;
	}

	return new_con;
}

/****************************************************************************
  process commands from the client
****************************************************************************/
void lsarpcd_process(void)
{
	struct user_creds usr;

	ZERO_STRUCT(static_pipe);

	fstrcpy(static_pipe.name, "lsarpc");
	
	if (!get_user_creds(&usr))
	{
		DEBUG(0,("authentication failed\n"));
		free_user_creds(&usr);
		return;
	}

	free_user_creds(&usr);

  InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return;

  InBuffer += SMB_ALIGNMENT;
  OutBuffer += SMB_ALIGNMENT;

  max_recv = MIN(lp_maxxmit(),BUFFER_SIZE);

  /* re-initialise the timezone */
  TimeInit();

  while (True)
  {
    int counter;
    int service_load_counter = 0;
    BOOL got_smb = False;

    errno = 0;      

    for (counter=SMBD_SELECT_LOOP; 
          !receive_message_or_smb(InBuffer,BUFFER_SIZE,
                                  SMBD_SELECT_LOOP*1000,&got_smb); 
          counter += SMBD_SELECT_LOOP)
    {
      time_t t;

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
      }

      /* automatic timeout if all connections are closed */      
      if (counter >= IDLE_CLOSED_TIMEOUT) 
      {
        DEBUG( 2, ( "Closing idle connection\n" ) );
        return;
      }

    }

    if(got_smb)
      process_smb(InBuffer, OutBuffer);
  }
}
