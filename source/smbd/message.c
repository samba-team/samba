/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB messaging
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
/*
   This file handles the messaging system calls for winpopup style
   messages
*/


#include "includes.h"

/* look in server.c for some explanation of these variables */
extern int DEBUGLEVEL;


static char msgbuf[1600];
static int msgpos=0;
static fstring msgfrom="";
static fstring msgto="";

/****************************************************************************
deliver the message
****************************************************************************/
static void msg_deliver(void)
{
  pstring s;
  fstring name;
  int i;
  int fd;

  if (! (*lp_msg_command()))
    {
      DEBUG(1,("no messaging command specified\n"));
      msgpos = 0;
      return;
    }

  /* put it in a temporary file */
  slprintf(s,sizeof(s)-1, "%s/msg.XXXXXX",tmpdir());
  fstrcpy(name,(char *)mktemp(s));

  fd = open(name,O_WRONLY|O_CREAT|O_TRUNC|O_EXCL,0600);
  if (fd == -1) {
    DEBUG(1,("can't open message file %s\n",name));
    return;
  }

  for (i=0;i<msgpos;) {
    if (msgbuf[i]=='\r' && i<(msgpos-1) && msgbuf[i+1]=='\n') {
      i++; continue;      
    }
    write(fd,&msgbuf[i++],1);
  }
  close(fd);


  /* run the command */
  if (*lp_msg_command())
    {
      pstrcpy(s,lp_msg_command());
      string_sub(s,"%s",name);
      string_sub(s,"%f",msgfrom);
      string_sub(s,"%t",msgto);
      standard_sub(-1,s);
      smbrun(s,NULL,False);
    }

  msgpos = 0;
}



/****************************************************************************
  reply to a sends
****************************************************************************/
int reply_sends(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int len;
  char *orig,*dest,*msg;
  int outsize = 0;

  msgpos = 0;


  if (! (*lp_msg_command()))
    return(ERROR(ERRSRV,ERRmsgoff));

  outsize = set_message(outbuf,0,0,True);

  orig = smb_buf(inbuf)+1;
  dest = skip_string(orig,1)+1;
  msg = skip_string(dest,1)+1;

  fstrcpy(msgfrom,orig);
  fstrcpy(msgto,dest);

  len = SVAL(msg,0);
  len = MIN(len,1600-msgpos);

  memcpy(&msgbuf[msgpos],msg+2,len);
  msgpos += len;

  DEBUG(3,("%s SMBsends (from %s to %s)\n",timestring(),orig,dest));

  msg_deliver();

  return(outsize);
}


/****************************************************************************
  reply to a sendstrt
****************************************************************************/
int reply_sendstrt(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  char *orig,*dest;
  int outsize = 0;

  if (! (*lp_msg_command()))
    return(ERROR(ERRSRV,ERRmsgoff));

  outsize = set_message(outbuf,1,0,True);

  msgpos = 0;

  orig = smb_buf(inbuf)+1;
  dest = skip_string(orig,1)+1;

  fstrcpy(msgfrom,orig);
  fstrcpy(msgto,dest);

  DEBUG(3,("%s SMBsendstrt (from %s to %s)\n",timestring(),msgfrom,msgto));

  return(outsize);
}


/****************************************************************************
  reply to a sendtxt
****************************************************************************/
int reply_sendtxt(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int len;
  int outsize = 0;
  char *msg;

  if (! (*lp_msg_command()))
    return(ERROR(ERRSRV,ERRmsgoff));

  outsize = set_message(outbuf,0,0,True);

  msg = smb_buf(inbuf) + 1;

  len = SVAL(msg,0);
  len = MIN(len,1600-msgpos);

  memcpy(&msgbuf[msgpos],msg+2,len);
  msgpos += len;

  DEBUG(3,("%s SMBsendtxt\n",timestring()));

  return(outsize);
}


/****************************************************************************
  reply to a sendend
****************************************************************************/
int reply_sendend(char *inbuf,char *outbuf, int dum_size, int dum_buffsize)
{
  int outsize = 0;

  if (! (*lp_msg_command()))
    return(ERROR(ERRSRV,ERRmsgoff));

  outsize = set_message(outbuf,0,0,True);

  DEBUG(3,("%s SMBsendend\n",timestring()));

  msg_deliver();

  return(outsize);
}

