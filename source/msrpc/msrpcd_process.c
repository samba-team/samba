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
#include "rpc_parse.h"

extern int DEBUGLEVEL;

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

static BOOL receive_message_or_msrpc(int c, prs_struct *ps,
                                   int timeout, BOOL *got_msrpc)
{
  fd_set fds;
  int selrtn;
  struct timeval to;
  int maxfd;

  smb_read_error = 0;

  *got_msrpc = False;

  /*
   * Check to see if we already have a message on the smb queue.
   * If so - copy and return it.
   */
  
  /*
   * Setup the select read fd set.
   */

  FD_ZERO(&fds);
  FD_SET(c,&fds);
  maxfd = 0;

  to.tv_sec = timeout / 1000;
  to.tv_usec = (timeout % 1000) * 1000;

  selrtn = sys_select(MAX(maxfd,c)+1,&fds,NULL, timeout>0?&to:NULL);

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

  if (FD_ISSET(c,&fds))
  {
    *got_msrpc = True;
    return receive_msrpc(c, ps, 0);
  }
	return False;
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


static prs_struct pdu;

/****************************************************************************
  process an smb from the client - split out from the process() code so
  it can be used by the oplock break code.
****************************************************************************/
static void process_msrpc(msrpc_pipes_struct *p, int c)
{
  static int trans_num;
  int32 len = prs_buf_len(&pdu);

  DEBUG( 6, ( "got message of len 0x%x\n", len ) );

	dump_data(10, pdu.data, len);

#ifdef WITH_VTP
  if(trans_num == 1 && VT_Check(pdu.data)) 
  {
    VT_Process();
    return;
  }
#endif

	if (rpc_local(p->l, pdu.data, len, p->name) &&
	    msrpc_send(c, &p->l->rsmb_pdu))
	{
		prs_free_data(&p->l->rsmb_pdu);

		while (rpc_local(p->l, NULL, 0, p->name))
		{
			fd_set fds;
			int selrtn;
			struct timeval to;
			int maxfd;
			int timeout = SMBD_SELECT_LOOP*1000;

			smb_read_error = 0;

			FD_ZERO(&fds);
			FD_SET(c,&fds);
			maxfd = 0;

			to.tv_sec = timeout / 1000;
			to.tv_usec = (timeout % 1000) * 1000;

			selrtn = sys_select(MAX(maxfd,c)+1,NULL,&fds, timeout>0?&to:NULL);

			/* Check if error */
			if(selrtn == -1) {
				smb_read_error = READ_ERROR;
				return;
			} 

			/* Did we timeout ? */
			if (selrtn == 0) {
				smb_read_error = READ_TIMEOUT;
				return;
			}

			if (FD_ISSET(c,&fds))
			{
				if (!msrpc_send(c, &p->l->rsmb_pdu))
				prs_free_data(&p->l->rsmb_pdu);
				break;
			}
			prs_free_data(&p->l->rsmb_pdu);
		}
	}
  trans_num++;
}

/****************************************************************************
 reads user credentials from the socket
****************************************************************************/
BOOL get_user_creds(int c, struct user_creds *usr, vuser_key *uk)
{
	pstring buf;
	int rl;
	uint32 len;
	BOOL new_con = False;
	uint32 status;

	CREDS_CMD cmd;
	prs_struct ps;

	ZERO_STRUCTP(usr);
	ZERO_STRUCT(cmd);
	cmd.cred = usr;

	DEBUG(10,("get_user_creds: first request\n"));

	rl = read(c, &buf, sizeof(len));

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

	rl = read(c, buf, len);

	if (rl < 0)
	{
		DEBUG(0,("Unable to read from connection\n"));
		return False;
	}
	
#ifdef DEBUG_PASSWORD
	dump_data(100, buf, rl);
#endif

 	/* make a static data parsing structure from the api_fd_reply data */
 	prs_create(&ps, buf, len, 4, True);

	if (!creds_io_cmd("creds", &cmd, &ps, 0))
	{
		DEBUG(0,("Unable to parse credentials\n"));
		return False;
	}

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

	/* obtain the remote process id and vuid */
	(*uk) = cmd.key;

	status = new_con ? 0x0 : 0x1;

	if (write(c, &status, sizeof(status)) !=
	    sizeof(status))
	{
		return False;
	}

	return new_con;
}

static void free_srv_auth_fns_array(uint32 num_entries, srv_auth_fns **entries)
{
	free_void_array(num_entries, (void**)entries, NULL);
}

static srv_auth_fns* add_srv_auth_fns_to_array(uint32 *len,
				srv_auth_fns ***array,
				srv_auth_fns *name)
{
	return (srv_auth_fns*)add_item_to_array(len,
	                     (void***)array, (void*)name);
}

void close_srv_auth_array(rpcsrv_struct *l)
{
	free_srv_auth_fns_array(l->num_auths, l->auth_fns);
}

void add_srv_auth_fn(rpcsrv_struct *l, srv_auth_fns *fn)
{
	add_srv_auth_fns_to_array(&l->num_auths, &l->auth_fns, fn);
	DEBUG(10,("add_srv_auth_fn: %d\n", l->num_auths));
}
/****************************************************************************
  initialise from pipe
****************************************************************************/
BOOL msrpcd_init(int c, msrpc_pipes_struct *p)
{
#if 0
	struct user_creds usr;
	vuser_key uk;
	user_struct *vuser;

	if (!get_user_creds(c, &usr, &uk))
	{
		DEBUG(0,("authentication failed\n"));
		free_user_creds(&usr);
		return False;
	}

	if (uk.vuid == UID_FIELD_INVALID)
	{
		free_user_creds(&usr);
		return False;
	}

	free_user_creds(&usr);

	if (!become_vuser(&uk))
	{
		return False;
	}

	vuser = get_valid_user_struct(&uk);
	if (vuser == NULL)
	{
		return False;
	}
#endif
	p->l = malloc(sizeof(*p->l));
	if (p->l == NULL)
	{
#if 0
		vuid_free_user_struct(vuser);
		safe_free(vuser);
#endif
		return False;
	}

	ZERO_STRUCTP(p->l);

#if 0
	p->l->key = uk;

	if (!vuser->guest)
	{
		char *user = vuser->name;
		if (!strequal(user,lp_guestaccount(-1)) &&
		     lp_servicenumber(user) < 0)      
		{
			int homes = lp_servicenumber(HOMES_NAME);
			char *home = get_unixhome_dir(user);
			if (homes >= 0 && home)
			{
				pstring home_dir;
				fstrcpy(home_dir, home);
				lp_add_home(user,homes,home_dir);
			}
		}
	}

	vuid_free_user_struct(vuser);
	safe_free(vuser);
#endif
	return True;
}

/****************************************************************************
  process commands from the client
****************************************************************************/
void msrpcd_process(msrpc_service_fns *fn, int c, msrpc_pipes_struct *p)
{
    extern fstring remote_machine;
    extern fstring local_machine;
    extern pstring global_myname;

  max_recv = MIN(lp_maxxmit(),BUFFER_SIZE);

  /* re-initialise the timezone */
  TimeInit();

    fstrcpy(remote_machine, p->name);
    fstrcpy(local_machine, global_myname);
    local_machine[15] = 0;
    strlower(local_machine);

    DEBUG(2, ("msrpc_process: client_name: %s my_name: %s\n",
                         remote_machine, local_machine));

    fn->reload_services(True);
    reopen_logs();

  while (True)
  {
    int counter;
    int service_load_counter = 0;
    BOOL got_msrpc = False;

    errno = 0;      

    for (counter=SMBD_SELECT_LOOP; 
          !receive_message_or_msrpc(c, &pdu, 
                                  SMBD_SELECT_LOOP*1000,&got_msrpc); 
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
        DEBUG(3,("receive error (%s) exiting\n",
                  strerror(errno)));
        return;
      }

      t = time(NULL);

      /* check for smb.conf reload */
      if (counter >= service_load_counter + SMBD_RELOAD_CHECK)
      {
        service_load_counter = counter;

        /* reload services, if files have changed. */
        fn->reload_services(True);
      }

      /*
       * If reload_after_sighup == True then we got a SIGHUP
       * and are being asked to reload. Fix from <branko.cibej@hermes.si>
       */

      if (reload_after_sighup)
      {
        DEBUG(0,("Reloading services after SIGHUP\n"));
        fn->reload_services(False);
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

    if(got_msrpc)
      process_msrpc(p, c);
  }
}
