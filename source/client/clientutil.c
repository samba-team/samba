/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1998
   
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

#define NO_SYSLOG

#include "includes.h"

#ifndef REGISTER
#define REGISTER 0
#endif

pstring service="";
pstring desthost="";
extern pstring global_myname;
pstring password = "";
pstring smb_login_passwd = "";
pstring username="";
pstring workgroup="";
BOOL got_pass = False;
BOOL no_pass = False;
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

uint16 cnum = 0;
uint16 pid = 0;
uint16 vuid = 0;
uint16 mid = 0;

int max_xmit = BUFFER_SIZE;

BOOL have_ip = False;

extern struct in_addr dest_ip;

extern int Protocol;

extern int Client;


/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
void cli_setup_pkt(char *outbuf)
{
  SSVAL(outbuf,smb_pid,pid);
  SSVAL(outbuf,smb_uid,vuid);
  SSVAL(outbuf,smb_mid,mid);
  if (Protocol > PROTOCOL_COREPLUS)
    {
      SCVAL(outbuf,smb_flg,0x8);
      SSVAL(outbuf,smb_flg2,0x1);
    }
}

/****************************************************************************
call a remote api
****************************************************************************/
BOOL cli_call_api(char *pipe_name, int pipe_name_len,
			int prcnt,int drcnt, int srcnt,
		     int mprcnt,int mdrcnt,
		     int *rprcnt,int *rdrcnt,
		     char *param,char *data, uint16 *setup,
		     char **rparam,char **rdata)
{
  static char *inbuf=NULL;
  static char *outbuf=NULL;

  if (!inbuf) inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  if (!outbuf) outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if(!inbuf || !outbuf) {
    DEBUG(0,("cli_call_api: malloc fail.\n"));
    return False;
  }

  if (pipe_name_len == 0) pipe_name_len = strlen(pipe_name);

  cli_send_trans_request(outbuf,SMBtrans,pipe_name, pipe_name_len, 0,0,
		     data, param, setup,
		     drcnt, prcnt, srcnt,
		     mdrcnt, mprcnt, 0);

  return (cli_receive_trans_response(inbuf,SMBtrans,
                                 rdrcnt,rprcnt,
                                 rdata,rparam));
}


/****************************************************************************
  receive a SMB trans or trans2 response allocating the necessary memory
  ****************************************************************************/
BOOL cli_receive_trans_response(char *inbuf,int trans,
                                   int *data_len,int *param_len,
				   char **data,char **param)
{
  int total_data=0;
  int total_param=0;
  int this_data,this_param;

  *data_len = *param_len = 0;

  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
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

  if((total_data && !data) || (total_param && !param)) {
    DEBUG(0,("cli_receive_trans_response: Realloc fail !\n"));
    return(False);
  }

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

      client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
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
  send a SMB trans or trans2 request
  ****************************************************************************/
BOOL cli_send_trans_request(char *outbuf,int trans,
			       char *name,int namelen, int fid,int flags,
			       char *data,char *param,uint16 *setup,
			       int ldata,int lparam,int lsetup,
			       int mdata,int mparam,int msetup)
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

  outparam = smb_buf(outbuf)+(trans==SMBtrans ? namelen+1 : 3);
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
    memcpy(p,name, namelen+1);			/* name[] */
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
      if (!client_receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
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
send a session request
****************************************************************************/
BOOL cli_send_session_request(char *inbuf,char *outbuf)
{
  fstring dest;
  char *p;
  int len = 4;
  /* send a session request (RFC 8002) */

  fstrcpy(dest,desthost);
  p = strchr(dest,'.');
  if (p) *p = 0;

  /* put in the destination name */
  p = outbuf+len;
  name_mangle(dest,p,name_type); /* 0x20 is the SMB server NetBIOS type. */
  len += name_len(p);

  /* and my name */
  p = outbuf+len;
  name_mangle(global_myname,p,0);
  len += name_len(p);

  /* setup the packet length */
  _smb_setlen(outbuf,len);
  CVAL(outbuf,0) = 0x81;

#ifdef WITH_SSL
retry:
#endif /* WITH_SSL */

  send_smb(Client,outbuf);
  DEBUG(5,("Sent session request\n"));

  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
      Client = open_socket_out(SOCK_STREAM, &dest_ip, port, LONG_CONNECT_TIMEOUT);
      if (Client == -1)
        return False;

      DEBUG(3,("Retargeted\n"));

      set_socket_options(Client,user_socket_options);

      /* Try again */
      return cli_send_session_request(inbuf,outbuf);
    } /* C. Hoch 9/14/95 End */

#ifdef WITH_SSL
    if(CVAL(inbuf,0) == 0x83 && CVAL(inbuf,4) == 0x8e) {       /* use ssl */
              fprintf(stderr, "Making secure connection\n");
        if(!sslutil_fd_is_ssl(Client)){
            if(sslutil_connect(Client) == 0)
                goto retry;
        }
    }
#endif

  if (CVAL(inbuf,0) != 0x82)
    {
      int ecode = CVAL(inbuf,4);
      DEBUG(0,("Session request failed (%d,%d) with myname=%s destname=%s\n",
	       CVAL(inbuf,0),ecode,global_myname,desthost));
      switch (ecode)
	{
	case 0x80: 
	  DEBUG(0,("Not listening on called name\n")); 
	  DEBUG(0,("Try to connect to another name (instead of %s)\n",desthost));
	  DEBUG(0,("You may find the -I option useful for this\n"));
	  break;
	case 0x81: 
	  DEBUG(0,("Not listening for calling name\n")); 
	  DEBUG(0,("Try to connect as another name (instead of %s)\n",global_myname));
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

static struct {
  int prot;
  char *name;
} prots[] = {
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
send a login command.  
****************************************************************************/
BOOL cli_send_login(char *inbuf,char *outbuf,BOOL start_session,BOOL use_setup, struct connection_options *options)
{
  BOOL was_null = (!inbuf && !outbuf);
  time_t servertime = 0;
  extern int serverzone;
  int crypt_len=0;
  char *pass = NULL;  
  uchar enc_ntpass[24];
  int ntpasslen = 0;
  pstring dev;
  char *p;
  int numprots;
  int tries=0;
  struct connection_options opt;

  bzero(&opt, sizeof(opt));

  if (was_null)
  {
    inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
    outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

    if(!inbuf || !outbuf) {
      DEBUG(0,("cli_send_login: malloc fail !\n"));
      return False;
    }
  }

  if (strstr(service,"IPC$")) connect_as_ipc = True;

  pstrcpy(dev,"A:");
  if (connect_as_printer)
    pstrcpy(dev,"LPT1:");
  if (connect_as_ipc)
    pstrcpy(dev,"IPC");


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
	pstrcpy(p,prots[numprots].name);
	p += strlen(p) + 1;
      }
  }

  CVAL(outbuf,smb_com) = SMBnegprot;
  cli_setup_pkt(outbuf);

  CVAL(smb_buf(outbuf),0) = 2;

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  show_msg(inbuf);

  if (CVAL(inbuf,smb_rcls) != 0 || ((int)SVAL(inbuf,smb_vwv0) >= numprots))
    {
      DEBUG(0,("SMBnegprot failed. myname=%s destname=%s - %s \n",
	    global_myname,desthost,smb_errstr(inbuf)));
      if (was_null)
	{
	  free(inbuf);
	  free(outbuf);
	}
      return(False);
    }

  opt.protocol = Protocol = prots[SVAL(inbuf,smb_vwv0)].prot;


  if (Protocol < PROTOCOL_LANMAN1) {    
	  /* no extra params */
  } else if (Protocol < PROTOCOL_NT1) {
    opt.sec_mode = SVAL(inbuf,smb_vwv1);
    opt.max_xmit = max_xmit = SVAL(inbuf,smb_vwv2);
    opt.sesskey = IVAL(inbuf,smb_vwv6);
    opt.serverzone = serverzone = SVALS(inbuf,smb_vwv10)*60;
    /* this time is converted to GMT by make_unix_date */
    servertime = make_unix_date(inbuf+smb_vwv8);
    if (Protocol >= PROTOCOL_COREPLUS) {
      opt.rawmode = SVAL(inbuf,smb_vwv5);
      readbraw_supported = ((SVAL(inbuf,smb_vwv5) & 0x1) != 0);
      writebraw_supported = ((SVAL(inbuf,smb_vwv5) & 0x2) != 0);
    }
    crypt_len = smb_buflen(inbuf);
    memcpy(cryptkey,smb_buf(inbuf),8);
    DEBUG(3,("max mux %d\n",SVAL(inbuf,smb_vwv3)));
    opt.max_vcs = SVAL(inbuf,smb_vwv4); 
    DEBUG(3,("max vcs %d\n",opt.max_vcs)); 
    DEBUG(3,("max blk %d\n",SVAL(inbuf,smb_vwv5)));
  } else {
    /* NT protocol */
    opt.sec_mode = CVAL(inbuf,smb_vwv1);
    opt.max_xmit = max_xmit = IVAL(inbuf,smb_vwv3+1);
    opt.sesskey = IVAL(inbuf,smb_vwv7+1);
    opt.serverzone = SVALS(inbuf,smb_vwv15+1)*60;
    /* this time arrives in real GMT */
    servertime = interpret_long_date(inbuf+smb_vwv11+1);
    crypt_len = CVAL(inbuf,smb_vwv16+1);
    memcpy(cryptkey,smb_buf(inbuf),8);
    if (IVAL(inbuf,smb_vwv9+1) & 1)
      readbraw_supported = writebraw_supported = True;      
    DEBUG(3,("max mux %d\n",SVAL(inbuf,smb_vwv1+1)));
    opt.max_vcs = SVAL(inbuf,smb_vwv2+1); 
    DEBUG(3,("max vcs %d\n",opt.max_vcs));
    DEBUG(3,("max raw %d\n",IVAL(inbuf,smb_vwv5+1)));
    DEBUG(3,("capabilities 0x%x\n",IVAL(inbuf,smb_vwv9+1)));
  }

  DEBUG(3,("Sec mode %d\n",SVAL(inbuf,smb_vwv1)));
  DEBUG(3,("max xmt %d\n",max_xmit));
  DEBUG(3,("Got %d byte crypt key\n",crypt_len));
  DEBUG(3,("Chose protocol [%s]\n",prots[SVAL(inbuf,smb_vwv0)].name));

  doencrypt = ((opt.sec_mode & 2) != 0);

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

  if(!pass)
    pass = "";

  pstrcpy(smb_login_passwd, pass);

  /* use a blank username for the 2nd try with a blank password */
  if (tries++ && !*pass)
    *username = 0;

  if (Protocol >= PROTOCOL_LANMAN1 && use_setup)
  {
    fstring pword;
    int passlen = strlen(pass)+1;
    fstrcpy(pword,pass);      

    if (doencrypt && *pass)
    {
      DEBUG(3,("Using encrypted passwords\n"));
      passlen = 24;
      SMBencrypt((uchar *)pass,(uchar *)cryptkey,(uchar *)pword);
      ntpasslen = 24;
      SMBNTencrypt((uchar *)pass,(uchar *)cryptkey,enc_ntpass);
    }

    /* if in share level security then don't send a password now */
    if (!(opt.sec_mode & 1)) {fstrcpy(pword, "");passlen=1;} 

    /* send a session setup command */
    bzero(outbuf,smb_size);

    if (Protocol < PROTOCOL_NT1)
    {
      set_message(outbuf,10,1 + strlen(username) + passlen,True);
      CVAL(outbuf,smb_com) = SMBsesssetupX;
      cli_setup_pkt(outbuf);

      CVAL(outbuf,smb_vwv0) = 0xFF;
      SSVAL(outbuf,smb_vwv2,max_xmit);
      SSVAL(outbuf,smb_vwv3,2);
      SSVAL(outbuf,smb_vwv4,opt.max_vcs-1);
      SIVAL(outbuf,smb_vwv5,opt.sesskey);
      SSVAL(outbuf,smb_vwv7,passlen);
      p = smb_buf(outbuf);
      memcpy(p,pword,passlen);
      p += passlen;
      pstrcpy(p,username);
    }
    else
    {
      if (!doencrypt) passlen--;
      /* for Win95 */
      set_message(outbuf,13,0,True);
      CVAL(outbuf,smb_com) = SMBsesssetupX;
      cli_setup_pkt(outbuf);

      CVAL(outbuf,smb_vwv0) = 0xFF;
      SSVAL(outbuf,smb_vwv2,BUFFER_SIZE);
      SSVAL(outbuf,smb_vwv3,2);
      SSVAL(outbuf,smb_vwv4,getpid());
      SIVAL(outbuf,smb_vwv5,opt.sesskey);
      SSVAL(outbuf,smb_vwv7,passlen);
      SSVAL(outbuf,smb_vwv8,doencrypt ? ntpasslen : 0);
      p = smb_buf(outbuf);
      memcpy(p,pword,passlen); p += SVAL(outbuf,smb_vwv7);
      if(doencrypt)
        memcpy(p,enc_ntpass,ntpasslen); p += SVAL(outbuf,smb_vwv8);
      pstrcpy(p,username);p = skip_string(p,1);
      pstrcpy(p,workgroup);p = skip_string(p,1);
      pstrcpy(p,"Unix");p = skip_string(p,1);
      pstrcpy(p,"Samba");p = skip_string(p,1);
      set_message(outbuf,13,PTR_DIFF(p,smb_buf(outbuf)),False);
    }

    send_smb(Client,outbuf);
    client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
        DEBUG(3,("resending login\n"));
        if (! no_pass)
          goto get_pass;
      }
      
      DEBUG(0,("Session setup failed for username=%s myname=%s destname=%s   %s\n",
            username,global_myname,desthost,smb_errstr(inbuf)));
      DEBUG(0,("You might find the -U, -W or -n options useful\n"));
      DEBUG(0,("Sometimes you have to use `-n USERNAME' (particularly with OS/2)\n"));
      DEBUG(0,("Some servers also insist on uppercase-only passwords\n"));
      if (was_null)
      {
        free(inbuf);
        free(outbuf);
      }
      return(False);
    }

    if (Protocol >= PROTOCOL_NT1)
    {
      char *domain,*os,*lanman;
      p = smb_buf(inbuf);
      os = p;
      lanman = skip_string(os,1);
      domain = skip_string(lanman,1);
      if (*domain || *os || *lanman)
      DEBUG(1,("Domain=[%s] OS=[%s] Server=[%s]\n",domain,os,lanman));
    }

    /* use the returned uid from now on */
    if (SVAL(inbuf,smb_uid) != vuid)
      DEBUG(3,("Server gave us a UID of %d. We gave %d\n",
    SVAL(inbuf,smb_uid),(int)vuid));
    opt.server_vuid = vuid = SVAL(inbuf,smb_uid);
  }

  if (opt.sec_mode & 1) {
	  if (SVAL(inbuf, smb_vwv2) & 1)
		  DEBUG(1,("connected as guest "));
	  DEBUG(1,("security=user\n"));
  } else {
	  DEBUG(1,("security=share\n"));
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
    fstrcpy(pword,pass);

    if (doencrypt && *pass) {
      passlen=24;
      SMBencrypt((uchar *)pass,(uchar *)cryptkey,(uchar *)pword);      
    }

    /* if in user level security then don't send a password now */
    if ((opt.sec_mode & 1)) {
      fstrcpy(pword, ""); passlen=1; 
    }

    if (Protocol <= PROTOCOL_COREPLUS) {
      set_message(outbuf,0,6 + strlen(service) + passlen + strlen(dev),True);
      CVAL(outbuf,smb_com) = SMBtcon;
      cli_setup_pkt(outbuf);

      p = smb_buf(outbuf);
      *p++ = 0x04;
      pstrcpy(p, service);
      p = skip_string(p,1);
      *p++ = 0x04;
      memcpy(p,pword,passlen);
      p += passlen;
      *p++ = 0x04;
      pstrcpy(p, dev);
    }
    else {
      set_message(outbuf,4,2 + strlen(service) + passlen + strlen(dev),True);
      CVAL(outbuf,smb_com) = SMBtconX;
      cli_setup_pkt(outbuf);
  
      SSVAL(outbuf,smb_vwv0,0xFF);
      SSVAL(outbuf,smb_vwv3,passlen);
  
      p = smb_buf(outbuf);
      memcpy(p,pword,passlen);
      p += passlen;
      pstrcpy(p,service);
      p = skip_string(p,1);
      pstrcpy(p,dev);
    }
  }

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  /* trying again with a blank password */
  if (CVAL(inbuf,smb_rcls) != 0 && 
      (int)strlen(pass) > 0 && 
      !doencrypt &&
      Protocol >= PROTOCOL_LANMAN1)
    {
      DEBUG(2,("first SMBtconX failed, trying again. %s\n",smb_errstr(inbuf)));
      pstrcpy(pass,"");
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
  

  if (Protocol <= PROTOCOL_COREPLUS) {
    max_xmit = SVAL(inbuf,smb_vwv0);

    cnum = SVAL(inbuf,smb_vwv1);
  }
  else {
    max_xmit = MIN(max_xmit,BUFFER_SIZE-4);
    if (max_xmit <= 0)
      max_xmit = BUFFER_SIZE - 4;

    cnum = SVAL(inbuf,smb_tid);
  }
  opt.max_xmit = max_xmit;
  opt.tid = cnum;

  DEBUG(3,("Connected with cnum=%d max_xmit=%d\n",cnum,max_xmit));

  if (was_null)
    {
      free(inbuf);
      free(outbuf);
    }

  if (options != NULL)
    {
      *options = opt;
    }

  return True;
}


/****************************************************************************
send a logout command
****************************************************************************/
void cli_send_logout(char *dum_in, char *dum_out)
{
  pstring inbuf,outbuf;

  DEBUG(5,("cli_send_logout\n"));

  bzero(outbuf,smb_size);
  set_message(outbuf,0,0,True);
  CVAL(outbuf,smb_com) = SMBtdis;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,SHORT_TIMEOUT);

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
open the client sockets
****************************************************************************/
BOOL cli_open_sockets(int port )
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
      pstrcpy(service2,service);
      host = strtok(service2,"\\/");
      if (!host) {
	DEBUG(0,("Badly formed host name\n"));
	return(False);
      }
      pstrcpy(desthost,host);
    }

  if (!(*global_myname)) {
      get_myname(global_myname,NULL);
  }
  strupper(global_myname);

  DEBUG(3,("Opening sockets\n"));

  if (!have_ip)
    {
      if(!resolve_name( host, &dest_ip, 0x20))
      {
	  DEBUG(0,("cli_open_sockets: Unknown host %s.\n",host));
	  return False;
      }
    }

  Client = open_socket_out(SOCK_STREAM, &dest_ip, port, LONG_CONNECT_TIMEOUT);
  if (Client == -1)
    return False;

  DEBUG(3,("Connected\n"));
  
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
  client_receive_smb(Client,inbuf,SHORT_TIMEOUT);

  close_sockets();
  if (!cli_open_sockets(0)) return(False);

  return(cli_send_login(inbuf,outbuf,True,True,NULL));
}

