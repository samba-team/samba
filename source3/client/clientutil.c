/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1995
   
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

#ifndef REGISTER
#define REGISTER 0
#endif

pstring service="";
pstring desthost="";
extern pstring myname;
pstring password = "";
pstring username="";
pstring workgroup=WORKGROUP;
BOOL got_pass = False;
BOOL connect_as_printer = False;
BOOL connect_as_ipc = False;

char cryptkey[8];
BOOL doencrypt=False;

extern pstring user_socket_options;

/* 30 second timeout on most commands */
#define CLIENT_TIMEOUT (30*1000)
#define SHORT_TIMEOUT (5*1000)

int name_type = 0x20;

int max_protocol = PROTOCOL_NT1;

BOOL readbraw_supported = False;
BOOL writebraw_supported = False;

extern int DEBUGLEVEL;

int cnum = 0;
int pid = 0;
int gid = 0;
int uid = 0;
int mid = 0;

int max_xmit = BUFFER_SIZE;

BOOL have_ip = False;

struct in_addr dest_ip;

extern int Protocol;

extern int Client;


/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
void cli_setup_pkt(char *outbuf)
{
  SSVAL(outbuf,smb_pid,pid);
  SSVAL(outbuf,smb_uid,uid);
  SSVAL(outbuf,smb_mid,mid);
  if (Protocol > PROTOCOL_CORE)
    {
      SCVAL(outbuf,smb_flg,0x8);
      SSVAL(outbuf,smb_flg2,0x1);
    }
}

/****************************************************************************
  receive a SMB trans or trans2 response allocating the necessary memory
  ****************************************************************************/
BOOL cli_receive_trans_response(char *inbuf,int trans,int *data_len,
				int *param_len, char **data,char **param)
{
  int total_data=0;
  int total_param=0;
  int this_data,this_param;

  *data_len = *param_len = 0;

  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  show_msg(inbuf);

  /* sanity check */
  if (CVAL(inbuf,smb_com) != trans)
    {
      DEBUG(0,("Expected %s response, got command 0x%02x\n",
	       trans==SMBtrans?"SMBtrans":"SMBtrans2", CVAL(inbuf,smb_com)));
      return(False);
    }
  if (CVAL(inbuf,smb_rcls) != 0)
    return(False);

  /* parse out the lengths */
  total_data = SVAL(inbuf,smb_tdrcnt);
  total_param = SVAL(inbuf,smb_tprcnt);

  /* allocate it */
  *data = Realloc(*data,total_data);
  *param = Realloc(*param,total_param);

  while (1)
    {
      this_data = SVAL(inbuf,smb_drcnt);
      this_param = SVAL(inbuf,smb_prcnt);
      if (this_data)
	memcpy(*data + SVAL(inbuf,smb_drdisp),
	       smb_base(inbuf) + SVAL(inbuf,smb_droff),
	       this_data);
      if (this_param)
	memcpy(*param + SVAL(inbuf,smb_prdisp),
	       smb_base(inbuf) + SVAL(inbuf,smb_proff),
	       this_param);
      *data_len += this_data;
      *param_len += this_param;

      /* parse out the total lengths again - they can shrink! */
      total_data = SVAL(inbuf,smb_tdrcnt);
      total_param = SVAL(inbuf,smb_tprcnt);

      if (total_data <= *data_len && total_param <= *param_len)
	break;

      receive_smb(Client,inbuf,CLIENT_TIMEOUT);
      show_msg(inbuf);

      /* sanity check */
      if (CVAL(inbuf,smb_com) != trans)
	{
	  DEBUG(0,("Expected %s response, got command 0x%02x\n",
		   trans==SMBtrans?"SMBtrans":"SMBtrans2", CVAL(inbuf,smb_com)));
	  return(False);
	}
      if (CVAL(inbuf,smb_rcls) != 0)
	  return(False);
    }
  
  return(True);
}

/****************************************************************************
send a session request
****************************************************************************/
BOOL cli_send_session_request(char *inbuf, char *outbuf)
{
  fstring dest;
  char *p;
  int len = 4;
  /* send a session request (RFC 8002) */

  strcpy(dest,desthost);
  p = strchr(dest,'.');
  if (p) *p = 0;

  /* put in the destination name */
  p = outbuf+len;
  name_mangle(dest,p,name_type);
  len += name_len(p);

  /* and my name */
  p = outbuf+len;
  name_mangle(myname,p,0);
  len += name_len(p);

  /* setup the packet length */
  _smb_setlen(outbuf,len);
  CVAL(outbuf,0) = 0x81;

  send_smb(Client,outbuf);
  DEBUG(5,("Sent session request\n"));

  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,0) == 0x84) /* C. Hoch  9/14/95 Start */
    {
      /* For information, here is the response structure.
       * We do the byte-twiddling to for portability.
       struct RetargetResponse{
       unsigned char type;
       unsigned char flags;
       int16 length;
       int32 ip_addr;
       int16 port;
       };
       */
      extern int Client;
      int port = (CVAL(inbuf,8)<<8)+CVAL(inbuf,9);
      /* SESSION RETARGET */
      putip((char *)&dest_ip,inbuf+4);

      close_sockets();
      Client = open_socket_out(SOCK_STREAM, &dest_ip, port, SHORT_CONNECT_TIMEOUT);
      if (Client == -1)
        return False;

      DEBUG(5,("Retargeted\n"));

      set_socket_options(Client,user_socket_options);

      /* Try again */
      return cli_send_session_request(inbuf,outbuf);
    } /* C. Hoch 9/14/95 End */


  if (CVAL(inbuf,0) != 0x82)
    {
      int ecode = CVAL(inbuf,4);
      DEBUG(0,("Session request failed (%d,%d) with myname=%s destname=%s\n",
	       CVAL(inbuf,0),ecode,myname,desthost));
      switch (ecode)
	{
	case 0x80: 
	  DEBUG(0,("Not listening on called name\n")); 
	  DEBUG(0,("Try to connect to another name (instead of %s)\n",desthost));
	  DEBUG(0,("You may find the -I option useful for this\n"));
	  break;
	case 0x81: 
	  DEBUG(0,("Not listening for calling name\n")); 
	  DEBUG(0,("Try to connect as another name (instead of %s)\n",myname));
	  DEBUG(0,("You may find the -n option useful for this\n"));
	  break;
	case 0x82: 
	  DEBUG(0,("Called name not present\n")); 
	  DEBUG(0,("Try to connect to another name (instead of %s)\n",desthost));
	  DEBUG(0,("You may find the -I option useful for this\n"));
	  break;
	case 0x83: 
	  DEBUG(0,("Called name present, but insufficient resources\n")); 
	  DEBUG(0,("Perhaps you should try again later?\n")); 
	  break;
	default:
	  DEBUG(0,("Unspecified error 0x%X\n",ecode)); 
	  DEBUG(0,("Your server software is being unfriendly\n"));
	  break;	  
	}
      return(False);
    }
  return(True);
}


static  struct {
    int prot;
    char *name;
  }
prots[] = 
    {
      {PROTOCOL_CORE,"PC NETWORK PROGRAM 1.0"},
      {PROTOCOL_COREPLUS,"MICROSOFT NETWORKS 1.03"},
      {PROTOCOL_LANMAN1,"MICROSOFT NETWORKS 3.0"},
      {PROTOCOL_LANMAN1,"LANMAN1.0"},
      {PROTOCOL_LANMAN2,"LM1.2X002"},
      {PROTOCOL_LANMAN2,"Samba"},
      {PROTOCOL_NT1,"NT LM 0.12"},
      {PROTOCOL_NT1,"NT LANMAN 1.0"},
      {-1,NULL}
    };

/****************************************************************************
send a login command
****************************************************************************/
BOOL cli_send_login(char *inbuf, char *outbuf, BOOL start_session, BOOL use_setup)
{
  BOOL was_null = (!inbuf && !outbuf);
  int sesskey=0;
  time_t servertime = 0;
  extern int serverzone;
  int sec_mode=0;
  int crypt_len;
  int max_vcs=0;
  char *pass = NULL;  
  pstring dev;
  char *p;
  int numprots;

  if (was_null)
    {
      inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
      outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
    }

  strcpy(dev,"A:");
  if (connect_as_printer)
    strcpy(dev,"LPT1:");
  if (connect_as_ipc)
    strcpy(dev,"IPC");


  if (start_session && !cli_send_session_request(inbuf,outbuf))
    {
      if (was_null)
	{
	  free(inbuf);
	  free(outbuf);
	}      
      return(False);
    }

  bzero(outbuf,smb_size);

  /* setup the protocol strings */
  {
    int plength;

    for (plength=0,numprots=0;
	 prots[numprots].name && prots[numprots].prot<=max_protocol;
	 numprots++)
      plength += strlen(prots[numprots].name)+2;
    
    set_message(outbuf,0,plength,True);

    p = smb_buf(outbuf);
    for (numprots=0;
	 prots[numprots].name && prots[numprots].prot<=max_protocol;
	 numprots++)
      {
	*p++ = 2;
	strcpy(p,prots[numprots].name);
	p += strlen(p) + 1;
      }
  }

  CVAL(outbuf,smb_com) = SMBnegprot;
  cli_setup_pkt(outbuf);

  CVAL(smb_buf(outbuf),0) = 2;

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  show_msg(inbuf);

  if (CVAL(inbuf,smb_rcls) != 0 || ((int)SVAL(inbuf,smb_vwv0) >= numprots))
    {
      DEBUG(0,("SMBnegprot failed. myname=%s destname=%s - %s \n",
	    myname,desthost,smb_errstr(inbuf)));
      if (was_null)
	{
	  free(inbuf);
	  free(outbuf);
	}
      return(False);
    }

  Protocol = prots[SVAL(inbuf,smb_vwv0)].prot;


  if (Protocol < PROTOCOL_NT1) {    
    sec_mode = SVAL(inbuf,smb_vwv1);
    max_xmit = SVAL(inbuf,smb_vwv2);
    sesskey = IVAL(inbuf,smb_vwv6);
    serverzone = SVALS(inbuf,smb_vwv10)*60;
    /* this time is converted to GMT by make_unix_date */
    servertime = make_unix_date(inbuf+smb_vwv8);
    if (Protocol >= PROTOCOL_COREPLUS) {
      readbraw_supported = ((SVAL(inbuf,smb_vwv5) & 0x1) != 0);
      writebraw_supported = ((SVAL(inbuf,smb_vwv5) & 0x2) != 0);
    }
    crypt_len = smb_buflen(inbuf);
    memcpy(cryptkey,smb_buf(inbuf),8);
    DEBUG(5,("max mux %d\n",SVAL(inbuf,smb_vwv3)));
    max_vcs = SVAL(inbuf,smb_vwv4); 
    DEBUG(5,("max vcs %d\n",max_vcs)); 
    DEBUG(5,("max blk %d\n",SVAL(inbuf,smb_vwv5)));
  } else {
    /* NT protocol */
    sec_mode = CVAL(inbuf,smb_vwv1);
    max_xmit = IVAL(inbuf,smb_vwv3+1);
    sesskey = IVAL(inbuf,smb_vwv7+1);
    serverzone = SVALS(inbuf,smb_vwv15+1)*60;
    /* this time arrives in real GMT */
    servertime = interpret_long_date(inbuf+smb_vwv11+1);
    crypt_len = CVAL(inbuf,smb_vwv16+1);
    memcpy(cryptkey,smb_buf(inbuf),8);
    if (IVAL(inbuf,smb_vwv9+1) & 1)
      readbraw_supported = writebraw_supported = True;      
    DEBUG(5,("max mux %d\n",SVAL(inbuf,smb_vwv1+1)));
    max_vcs = SVAL(inbuf,smb_vwv2+1); 
    DEBUG(5,("max vcs %d\n",max_vcs));
    DEBUG(5,("max raw %d\n",IVAL(inbuf,smb_vwv5+1)));
    DEBUG(5,("capabilities 0x%x\n",IVAL(inbuf,smb_vwv9+1)));
  }

  DEBUG(5,("Sec mode %d\n",SVAL(inbuf,smb_vwv1)));
  DEBUG(5,("max xmt %d\n",max_xmit));
  DEBUG(5,("Got %d byte crypt key\n",crypt_len));
  DEBUG(5,("Chose protocol [%s]\n",prots[SVAL(inbuf,smb_vwv0)].name));

  doencrypt = ((sec_mode & 2) != 0);

  if (servertime) {
    static BOOL done_time = False;
    if (!done_time) {
      DEBUG(1,("Server time is %sTimezone is UTC%+02.1f\n",
	       asctime(LocalTime(&servertime)),
	       -(double)(serverzone/3600.0)));
      done_time = True;
    }
  }

 get_pass:

  if (got_pass)
    pass = password;
  else
    pass = (char *)getpass("Password: ");

  if (Protocol >= PROTOCOL_LANMAN1 && use_setup)
    {
      fstring pword;
      int passlen = strlen(pass)+1;
      strcpy(pword,pass);      

#ifdef SMB_PASSWD
      if (doencrypt && *pass) {
	DEBUG(5,("Using encrypted passwords\n"));
	passlen = 24;
	SMBencrypt(pass,cryptkey,pword);
      }
#else
      doencrypt = False;
#endif

      /* if in share level security then don't send a password now */
      if (!(sec_mode & 1)) {strcpy(pword, "");passlen=1;} 

      /* send a session setup command */
      bzero(outbuf,smb_size);

      if (Protocol < PROTOCOL_NT1) {
	set_message(outbuf,10,1 + strlen(username) + passlen,True);
	CVAL(outbuf,smb_com) = SMBsesssetupX;
	cli_setup_pkt(outbuf);

	CVAL(outbuf,smb_vwv0) = 0xFF;
	SSVAL(outbuf,smb_vwv2,max_xmit);
	SSVAL(outbuf,smb_vwv3,2);
	SSVAL(outbuf,smb_vwv4,max_vcs-1);
	SIVAL(outbuf,smb_vwv5,sesskey);
	SSVAL(outbuf,smb_vwv7,passlen);
	p = smb_buf(outbuf);
	memcpy(p,pword,passlen);
	p += passlen;
	strcpy(p,username);
      } else {
	if (!doencrypt) passlen--;
	/* for Win95 */
	set_message(outbuf,13,0,True);
	CVAL(outbuf,smb_com) = SMBsesssetupX;
	cli_setup_pkt(outbuf);

	CVAL(outbuf,smb_vwv0) = 0xFF;
	SSVAL(outbuf,smb_vwv2,BUFFER_SIZE);
	SSVAL(outbuf,smb_vwv3,2);
	SSVAL(outbuf,smb_vwv4,getpid());
	SIVAL(outbuf,smb_vwv5,sesskey);
	SSVAL(outbuf,smb_vwv7,passlen);
	SSVAL(outbuf,smb_vwv8,0);
	p = smb_buf(outbuf);
	memcpy(p,pword,passlen); p += SVAL(outbuf,smb_vwv7);
	strcpy(p,username);p = skip_string(p,1);
	strcpy(p,workgroup);p = skip_string(p,1);
	strcpy(p,"Unix");p = skip_string(p,1);
	strcpy(p,"Samba");p = skip_string(p,1);
	set_message(outbuf,13,PTR_DIFF(p,smb_buf(outbuf)),False);
      }

      send_smb(Client,outbuf);
      receive_smb(Client,inbuf,CLIENT_TIMEOUT);

      show_msg(inbuf);

      if (CVAL(inbuf,smb_rcls) != 0)
	{
	  if (! *pass &&
	      ((CVAL(inbuf,smb_rcls) == ERRDOS && 
		SVAL(inbuf,smb_err) == ERRnoaccess) ||
	       (CVAL(inbuf,smb_rcls) == ERRSRV && 
		SVAL(inbuf,smb_err) == ERRbadpw)))
	    {
	      got_pass = False;
	      DEBUG(5,("resending login\n"));
	      goto get_pass;
	    }
	      
	  DEBUG(0,("Session setup failed for username=%s myname=%s destname=%s   %s\n",
		username,myname,desthost,smb_errstr(inbuf)));
	  DEBUG(0,("You might find the -U or -n options useful\n"));
	  DEBUG(0,("Sometimes you have to use `-n USERNAME' (particularly with OS/2)\n"));
	  DEBUG(0,("Some servers also insist on uppercase-only passwords\n"));
	  if (was_null)
	    {
	      free(inbuf);
	      free(outbuf);
	    }
	  return(False);
	}

      if (Protocol >= PROTOCOL_NT1) {
	char *domain,*os,*lanman;
	p = smb_buf(inbuf);
	os = p;
	lanman = skip_string(os,1);
	domain = skip_string(lanman,1);
	if (*domain || *os || *lanman)
	  DEBUG(1,("Domain=[%s] OS=[%s] Server=[%s]\n",domain,os,lanman));
      }

      /* use the returned uid from now on */
      if (SVAL(inbuf,smb_uid) != uid)
	DEBUG(5,("Server gave us a UID of %d. We gave %d\n",
	      SVAL(inbuf,smb_uid),uid));
      uid = SVAL(inbuf,smb_uid);
    }

  /* now we've got a connection - send a tcon message */
  bzero(outbuf,smb_size);

  if (strncmp(service,"\\\\",2) != 0)
    {
      DEBUG(0,("\nWarning: Your service name doesn't start with \\\\. This is probably incorrect.\n"));
      DEBUG(0,("Perhaps try replacing each \\ with \\\\ on the command line?\n\n"));
    }


 again2:

  {
    int passlen = strlen(pass)+1;
    fstring pword;
    strcpy(pword,pass);

#ifdef SMB_PASSWD
    if (doencrypt && *pass) {
      passlen=24;
      SMBencrypt(pass,cryptkey,pword);      
    }
#endif

    /* if in user level security then don't send a password now */
    if ((sec_mode & 1)) {
      strcpy(pword, ""); passlen=1; 
    }

    set_message(outbuf,4,2 + strlen(service) + passlen + strlen(dev),True);
    CVAL(outbuf,smb_com) = SMBtconX;
    cli_setup_pkt(outbuf);

    SSVAL(outbuf,smb_vwv0,0xFF);
    SSVAL(outbuf,smb_vwv3,passlen);

    p = smb_buf(outbuf);
    memcpy(p,pword,passlen);
    p += passlen;
    strcpy(p,service);
    p = skip_string(p,1);
    strcpy(p,dev);
  }

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  /* trying again with a blank password */
  if (CVAL(inbuf,smb_rcls) != 0 && 
      (int)strlen(pass) > 0 && 
      !doencrypt &&
      Protocol >= PROTOCOL_LANMAN1)
    {
      DEBUG(2,("first SMBtconX failed, trying again. %s\n",smb_errstr(inbuf)));
      strcpy(pass,"");
      goto again2;
    }  

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("SMBtconX failed. %s\n",smb_errstr(inbuf)));
      DEBUG(0,("Perhaps you are using the wrong sharename, username or password?\n"));
      DEBUG(0,("Some servers insist that these be in uppercase\n"));
      if (was_null)
	{
	  free(inbuf);
	  free(outbuf);
	}
      return(False);
    }
  

  max_xmit = MIN(max_xmit,BUFFER_SIZE-4);
  if (max_xmit <= 0)
    max_xmit = BUFFER_SIZE - 4;

  cnum = SVAL(inbuf,smb_tid);

  DEBUG(5,("Connected with cnum=%d max_xmit=%d\n",cnum,max_xmit));

  if (was_null)
    {
      free(inbuf);
      free(outbuf);
    }
  return True;
}


/****************************************************************************
send a logout command
****************************************************************************/
void cli_send_logout(void)
{
  pstring inbuf,outbuf;

  bzero(outbuf,smb_size);
  set_message(outbuf,0,0,True);
  CVAL(outbuf,smb_com) = SMBtdis;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,SHORT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("SMBtdis failed %s\n",smb_errstr(inbuf)));
    }

  
#ifdef STATS
  stats_report();
#endif
  exit(0);
}



/****************************************************************************
call a remote api
****************************************************************************/
BOOL cli_call_api(int prcnt,int drcnt,int mprcnt,int mdrcnt,int *rprcnt,
	      int *rdrcnt, char *param,char *data, char **rparam,char **rdata)
{
  static char *inbuf=NULL;
  static char *outbuf=NULL;

  if (!inbuf) inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  if (!outbuf) outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  cli_send_trans_request(outbuf,SMBtrans,"\\PIPE\\LANMAN",0,0,
			 data,param,NULL,
			 drcnt,prcnt,0,
			 mdrcnt,mprcnt,0);

  return (cli_receive_trans_response(inbuf,SMBtrans,
				     rdrcnt,rprcnt,
				     rdata,rparam));
}

/****************************************************************************
  send a SMB trans or trans2 request
  ****************************************************************************/
BOOL cli_send_trans_request(char *outbuf, int trans, char *name, int fid, int flags,
			char *data,char *param,uint16 *setup, int ldata,int lparam,
			int lsetup,int mdata,int mparam,int msetup)
{
  int i;
  int this_ldata,this_lparam;
  int tot_data=0,tot_param=0;
  char *outdata,*outparam;
  pstring inbuf;
  char *p;

  this_lparam = MIN(lparam,max_xmit - (500+lsetup*SIZEOFWORD)); /* hack */
  this_ldata = MIN(ldata,max_xmit - (500+lsetup*SIZEOFWORD+this_lparam));

  bzero(outbuf,smb_size);
  set_message(outbuf,14+lsetup,0,True);
  CVAL(outbuf,smb_com) = trans;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  outparam = smb_buf(outbuf)+(trans==SMBtrans ? strlen(name)+1 : 3);
  outdata = outparam+this_lparam;

  /* primary request */
  SSVAL(outbuf,smb_tpscnt,lparam);	/* tpscnt */
  SSVAL(outbuf,smb_tdscnt,ldata);	/* tdscnt */
  SSVAL(outbuf,smb_mprcnt,mparam);	/* mprcnt */
  SSVAL(outbuf,smb_mdrcnt,mdata);	/* mdrcnt */
  SCVAL(outbuf,smb_msrcnt,msetup);	/* msrcnt */
  SSVAL(outbuf,smb_flags,flags);	/* flags */
  SIVAL(outbuf,smb_timeout,0);		/* timeout */
  SSVAL(outbuf,smb_pscnt,this_lparam);	/* pscnt */
  SSVAL(outbuf,smb_psoff,smb_offset(outparam,outbuf)); /* psoff */
  SSVAL(outbuf,smb_dscnt,this_ldata);	/* dscnt */
  SSVAL(outbuf,smb_dsoff,smb_offset(outdata,outbuf)); /* dsoff */
  SCVAL(outbuf,smb_suwcnt,lsetup);	/* suwcnt */
  for (i=0;i<lsetup;i++)		/* setup[] */
    SSVAL(outbuf,smb_setup+i*SIZEOFWORD,setup[i]);
  p = smb_buf(outbuf);
  if (trans==SMBtrans)
    strcpy(p,name);			/* name[] */
  else
    {
      *p++ = 0;				/* put in a null smb_name */
      *p++ = 'D'; *p++ = ' ';		/* this was added because OS/2 does it */
    }
  if (this_lparam)			/* param[] */
    memcpy(outparam,param,this_lparam);
  if (this_ldata)			/* data[] */
    memcpy(outdata,data,this_ldata);
  set_message(outbuf,14+lsetup,		/* wcnt, bcc */
	      PTR_DIFF(outdata+this_ldata,smb_buf(outbuf)),False);

  show_msg(outbuf);
  send_smb(Client,outbuf);

  if (this_ldata < ldata || this_lparam < lparam)
    {
      /* receive interim response */
      if (!receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
	{
	  DEBUG(0,("%s request failed (%s)\n",
	           trans==SMBtrans?"SMBtrans":"SMBtrans2", smb_errstr(inbuf)));
	  return(False);
	}      

      tot_data = this_ldata;
      tot_param = this_lparam;

      while (tot_data < ldata || tot_param < lparam)
    {
	  this_lparam = MIN(lparam-tot_param,max_xmit - 500); /* hack */
	  this_ldata = MIN(ldata-tot_data,max_xmit - (500+this_lparam));

	  set_message(outbuf,trans==SMBtrans?8:9,0,True);
	  CVAL(outbuf,smb_com) = trans==SMBtrans ? SMBtranss : SMBtranss2;

	  outparam = smb_buf(outbuf);
	  outdata = outparam+this_lparam;

	  /* secondary request */
	  SSVAL(outbuf,smb_tpscnt,lparam);	/* tpscnt */
	  SSVAL(outbuf,smb_tdscnt,ldata);	/* tdscnt */
	  SSVAL(outbuf,smb_spscnt,this_lparam);	/* pscnt */
	  SSVAL(outbuf,smb_spsoff,smb_offset(outparam,outbuf)); /* psoff */
	  SSVAL(outbuf,smb_spsdisp,tot_param);	/* psdisp */
	  SSVAL(outbuf,smb_sdscnt,this_ldata);	/* dscnt */
	  SSVAL(outbuf,smb_sdsoff,smb_offset(outdata,outbuf)); /* dsoff */
	  SSVAL(outbuf,smb_sdsdisp,tot_data);	/* dsdisp */
	  if (trans==SMBtrans2)
	    SSVAL(outbuf,smb_sfid,fid);		/* fid */
	  if (this_lparam)			/* param[] */
	    memcpy(outparam,param,this_lparam);
	  if (this_ldata)			/* data[] */
	    memcpy(outdata,data,this_ldata);
	  set_message(outbuf,trans==SMBtrans?8:9, /* wcnt, bcc */
		      PTR_DIFF(outdata+this_ldata,smb_buf(outbuf)),False);

	  show_msg(outbuf);
	  send_smb(Client,outbuf);

	  tot_data += this_ldata;
	  tot_param += this_lparam;
	}
    }

    return(True);
}


/****************************************************************************
open the client sockets
****************************************************************************/
BOOL cli_open_sockets(int port)
{
  static int last_port;
  char *host;
  pstring service2;
  extern int Client;

  if (port == 0) port=last_port;
  last_port=port;

  strupper(service);

  if (*desthost)
    {
      host = desthost;
    }
  else
    {
      strcpy(service2,service);
      host = strtok(service2,"\\/");
      strcpy(desthost,host);
    }

  DEBUG(5,("Opening sockets\n"));

  if (*myname == 0)
    get_myname(myname,NULL);
  strupper(myname);

  if (!have_ip)
    {
      struct hostent *hp;

      if ((hp = Get_Hostbyname(host)) == 0) 
	{
	  DEBUG(0,("Get_Hostbyname: Unknown host %s.\n",host));
	  return False;
	}

      putip((char *)&dest_ip,(char *)hp->h_addr);
    }

  Client = open_socket_out(SOCK_STREAM, &dest_ip, port, SHORT_CONNECT_TIMEOUT);
  if (Client == -1)
    return False;

  DEBUG(5,("Connected\n"));

  set_socket_options(Client,user_socket_options);  

  return True;
}

/****************************************************************************
close and open the connection again
****************************************************************************/
BOOL cli_reopen_connection(char *inbuf,char *outbuf)
{
  static int open_count=0;

  open_count++;

  if (open_count>5) return(False);

  DEBUG(1,("Trying to re-open connection\n"));

  set_message(outbuf,0,0,True);
  SCVAL(outbuf,smb_com,SMBtdis);
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,SHORT_TIMEOUT);

  close_sockets();
  if (!cli_open_sockets(0)) return(False);

  return(cli_send_login(inbuf,outbuf,True,True));
}

/* error code stuff - put together by Merik Karman
   merik@blackadder.dsh.oz.au */

typedef struct
{
  char *name;
  int code;
  char *message;
} err_code_struct;

/* Dos Error Messages */
err_code_struct dos_msgs[] = {
  {"ERRbadfunc",1,"Invalid function."},
  {"ERRbadfile",2,"File not found."},
  {"ERRbadpath",3,"Directory invalid."},
  {"ERRnofids",4,"No file descriptors available"},
  {"ERRnoaccess",5,"Access denied."},
  {"ERRbadfid",6,"Invalid file handle."},
  {"ERRbadmcb",7,"Memory control blocks destroyed."},
  {"ERRnomem",8,"Insufficient server memory to perform the requested function."},
  {"ERRbadmem",9,"Invalid memory block address."},
  {"ERRbadenv",10,"Invalid environment."},
  {"ERRbadformat",11,"Invalid format."},
  {"ERRbadaccess",12,"Invalid open mode."},
  {"ERRbaddata",13,"Invalid data."},
  {"ERR",14,"reserved."},
  {"ERRbaddrive",15,"Invalid drive specified."},
  {"ERRremcd",16,"A Delete Directory request attempted  to  remove  the  server's  current directory."},
  {"ERRdiffdevice",17,"Not same device."},
  {"ERRnofiles",18,"A File Search command can find no more files matching the specified criteria."},
  {"ERRbadshare",32,"The sharing mode specified for an Open conflicts with existing  FIDs  on the file."},
  {"ERRlock",33,"A Lock request conflicted with an existing lock or specified an  invalid mode,  or an Unlock requested attempted to remove a lock held by another process."},
  {"ERRfilexists",80,"The file named in a Create Directory, Make  New  File  or  Link  request already exists."},
  {"ERRbadpipe",230,"Pipe invalid."},
  {"ERRpipebusy",231,"All instances of the requested pipe are busy."},
  {"ERRpipeclosing",232,"Pipe close in progress."},
  {"ERRnotconnected",233,"No process on other end of pipe."},
  {"ERRmoredata",234,"There is more data to be returned."},
  {NULL,-1,NULL}};

/* Server Error Messages */
err_code_struct server_msgs[] = {
  {"ERRerror",1,"Non-specific error code."},
  {"ERRbadpw",2,"Bad password - name/password pair in a Tree Connect or Session Setup are invalid."},
  {"ERRbadtype",3,"reserved."},
  {"ERRaccess",4,"The requester does not have  the  necessary  access  rights  within  the specified  context for the requested function. The context is defined by the TID or the UID."},
  {"ERRinvnid",5,"The tree ID (TID) specified in a command was invalid."},
  {"ERRinvnetname",6,"Invalid network name in tree connect."},
  {"ERRinvdevice",7,"Invalid device - printer request made to non-printer connection or  non-printer request made to printer connection."},
  {"ERRqfull",49,"Print queue full (files) -- returned by open print file."},
  {"ERRqtoobig",50,"Print queue full -- no space."},
  {"ERRqeof",51,"EOF on print queue dump."},
  {"ERRinvpfid",52,"Invalid print file FID."},
  {"ERRsmbcmd",64,"The server did not recognize the command received."},
  {"ERRsrverror",65,"The server encountered an internal error, e.g., system file unavailable."},
  {"ERRfilespecs",67,"The file handle (FID) and pathname parameters contained an invalid  combination of values."},
  {"ERRreserved",68,"reserved."},
  {"ERRbadpermits",69,"The access permissions specified for a file or directory are not a valid combination.  The server cannot set the requested attribute."},
  {"ERRreserved",70,"reserved."},
  {"ERRsetattrmode",71,"The attribute mode in the Set File Attribute request is invalid."},
  {"ERRpaused",81,"Server is paused."},
  {"ERRmsgoff",82,"Not receiving messages."},
  {"ERRnoroom",83,"No room to buffer message."},
  {"ERRrmuns",87,"Too many remote user names."},
  {"ERRtimeout",88,"Operation timed out."},
  {"ERRnoresource",89,"No resources currently available for request."},
  {"ERRtoomanyuids",90,"Too many UIDs active on this session."},
  {"ERRbaduid",91,"The UID is not known as a valid ID on this session."},
  {"ERRusempx",250,"Temp unable to support Raw, use MPX mode."},
  {"ERRusestd",251,"Temp unable to support Raw, use standard read/write."},
  {"ERRcontmpx",252,"Continue in MPX mode."},
  {"ERRreserved",253,"reserved."},
  {"ERRreserved",254,"reserved."},
  {"ERRnosupport",0xFFFF,"Function not supported."},
  {NULL,-1,NULL}};

/* Hard Error Messages */
err_code_struct hard_msgs[] = {
  {"ERRnowrite",19,"Attempt to write on write-protected diskette."},
  {"ERRbadunit",20,"Unknown unit."},
  {"ERRnotready",21,"Drive not ready."},
  {"ERRbadcmd",22,"Unknown command."},
  {"ERRdata",23,"Data error (CRC)."},
  {"ERRbadreq",24,"Bad request structure length."},
  {"ERRseek",25 ,"Seek error."},
  {"ERRbadmedia",26,"Unknown media type."},
  {"ERRbadsector",27,"Sector not found."},
  {"ERRnopaper",28,"Printer out of paper."},
  {"ERRwrite",29,"Write fault."},
  {"ERRread",30,"Read fault."},
  {"ERRgeneral",31,"General failure."},
  {"ERRbadshare",32,"A open conflicts with an existing open."},
  {"ERRlock",33,"A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process."},
  {"ERRwrongdisk",34,"The wrong disk was found in a drive."},
  {"ERRFCBUnavail",35,"No FCBs are available to process request."},
  {"ERRsharebufexc",36,"A sharing buffer has been exceeded."},
  {NULL,-1,NULL}};


struct
{
  int code;
  char *class;
  err_code_struct *err_msgs;
} err_classes[] = { 
  {0,"SUCCESS",NULL},
  {0x01,"ERRDOS",dos_msgs},
  {0x02,"ERRSRV",server_msgs},
  {0x03,"ERRHRD",hard_msgs},
  {0x04,"ERRXOS",NULL},
  {0xE1,"ERRRMX1",NULL},
  {0xE2,"ERRRMX2",NULL},
  {0xE3,"ERRRMX3",NULL},
  {0xFF,"ERRCMD",NULL},
  {-1,NULL,NULL}};


/****************************************************************************
return a SMB error string from a SMB buffer
****************************************************************************/
char *smb_errstr(char *inbuf)
{
  static pstring ret;
  int class = CVAL(inbuf,smb_rcls);
  int num = SVAL(inbuf,smb_err);
  int i,j;

  for (i=0;err_classes[i].class;i++)
    if (err_classes[i].code == class)
      {
	if (err_classes[i].err_msgs)
	  {
	    err_code_struct *err = err_classes[i].err_msgs;
	    for (j=0;err[j].name;j++)
	      if (num == err[j].code)
		{
		  if (DEBUGLEVEL > 0)
		    sprintf(ret,"%s - %s (%s)",err_classes[i].class,
			    err[j].name,err[j].message);
		  else
		    sprintf(ret,"%s - %s",err_classes[i].class,err[j].name);
		  return ret;
		}
	  }

	sprintf(ret,"%s - %d",err_classes[i].class,num);
	return ret;
      }
  
  sprintf(ret,"ERROR: Unknown error (%d,%d)",class,num);
  return(ret);
}
