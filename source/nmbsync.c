/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines to synchronise browse lists
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

#include "includes.h"
#include "loadparm.h"
#include "nameserv.h"

extern int DEBUGLEVEL;

struct server_record *add_server_entry(char *name,int servertype,
				       int ttl,char *comment,BOOL replace);


/****************************************************************************
call a remote api
****************************************************************************/
static BOOL call_remote_api(int fd,int cnum,int uid,int timeout,
			    char *inbuf,char *outbuf,
			    int prcnt,int drcnt,
			    int mprcnt,int mdrcnt,
			    int *rprcnt,int *rdrcnt,
			    char *param,char *data,
			    char **rparam,char **rdata)
{
  char *p1,*p2;

  /* send a SMBtrans command */
  bzero(outbuf,smb_size);
  set_message(outbuf,14,0,True);
  CVAL(outbuf,smb_com) = SMBtrans;
  SSVAL(outbuf,smb_tid,cnum);
  SSVAL(outbuf,smb_uid,uid);

  p1 = smb_buf(outbuf);
  strcpy(p1,"\\PIPE\\LANMAN");
  p1 = skip_string(p1,1);
  p2 = p1 + prcnt;

  if (prcnt > 0)
    memcpy(p1,param,prcnt);
  if (drcnt > 0)
    memcpy(p2,data,drcnt);

  SSVAL(outbuf,smb_vwv0,prcnt); /* param count */
  SSVAL(outbuf,smb_vwv1,drcnt); /* data count */
  SSVAL(outbuf,smb_vwv2,mprcnt); /* mprcnt */
  SSVAL(outbuf,smb_vwv3,mdrcnt); /* mdrcnt */
  SSVAL(outbuf,smb_vwv4,0); /* msrcnt */
  SSVAL(outbuf,smb_vwv5,0); /* flags */
  SSVAL(outbuf,smb_vwv9,prcnt); /* pscnt */
  SSVAL(outbuf,smb_vwv10,smb_offset(p1,outbuf)); /* psoff */
  SSVAL(outbuf,smb_vwv11,drcnt); /* dscnt */
  SSVAL(outbuf,smb_vwv12,smb_offset(p2,outbuf)); /* dsoff */
  CVAL(outbuf,smb_vwv13) = 0; /* suwcnt */

  set_message(outbuf,14,PTR_DIFF(p2+drcnt,smb_buf(outbuf)),False);

  send_smb(fd,outbuf);
  
  if (receive_smb(fd,inbuf,timeout) &&
      CVAL(inbuf,smb_rcls) == 0)
    {
      if (rparam)
	*rparam = inbuf+4 + SVAL(inbuf,smb_vwv4);
      if (rdata)
	*rdata = inbuf+4 + SVAL(inbuf,smb_vwv7);
      if (rprcnt)
	*rprcnt = SVAL(inbuf,smb_vwv3);
      if (rdrcnt)
	*rdrcnt = SVAL(inbuf,smb_vwv6);
      return(True);
    }

  return(False);
}


/*******************************************************************
  synchronise browse lists with another browse server
  ******************************************************************/
void sync_browse_lists(char *name,int name_type,char *myname,
		       char *domain,struct in_addr ip)
{
  char *protocol = "LM1.2X002";
  char *service = "IPC$";
  char *dev = "IPC";
  int timeout=2000;
  char *inbuf=NULL;
  pstring outbuf;
  char *p;
  int len;
  uint32 sesskey;
  int cnum,uid;
  BOOL ret;

  int fd = open_socket_out(SOCK_STREAM, &ip, SMB_PORT);
  if (fd < 0) {
    DEBUG(3,("Failed to connect to %s at %s\n",name,inet_ntoa(ip)));
    return;
  }

  if (!(inbuf = (char *)malloc(0xFFFF+1024))) return;  

  /* put in the destination name */
  len = 4;
  p = outbuf+len;
  name_mangle(name,p,name_type);
  len += name_len(p);

  /* and my name */
  p = outbuf+len;
  name_mangle(myname,p,0x20);
  len += name_len(p);

  _smb_setlen(outbuf,len);
  CVAL(outbuf,0) = 0x81;

  send_smb(fd,outbuf);
  receive_smb(fd,inbuf,5000);
  
  bzero(outbuf,smb_size);

  /* setup the protocol string */
  set_message(outbuf,0,strlen(protocol)+2,True);
  p = smb_buf(outbuf);
  *p++ = 2;
  strcpy(p,protocol);

  CVAL(outbuf,smb_com) = SMBnegprot;
  CVAL(outbuf,smb_flg) = 0x8;
  SSVAL(outbuf,smb_flg2,0x1);

  send_smb(fd,outbuf);
  bzero(inbuf,smb_size);
  ret = receive_smb(fd,inbuf,timeout);
  
  if (!ret || CVAL(inbuf,smb_rcls) || SVAL(inbuf,smb_vwv0)) {
    DEBUG(3,("%s rejected the protocol\n",name));
    close(fd);
    if (inbuf) free(inbuf);
    return;
  }

  sesskey = IVAL(inbuf,smb_vwv6);

  bzero(outbuf,smb_size);
  set_message(outbuf,10,2,True);
  CVAL(outbuf,smb_com) = SMBsesssetupX;

  CVAL(outbuf,smb_vwv0) = 0xFF;
  SSVAL(outbuf,smb_vwv2,0xFFFF);
  SSVAL(outbuf,smb_vwv3,2);
  SSVAL(outbuf,smb_vwv4,1);
  SIVAL(outbuf,smb_vwv5,sesskey);
  SSVAL(outbuf,smb_vwv7,1);

  send_smb(fd,outbuf);
  bzero(inbuf,smb_size);
  ret = receive_smb(fd,inbuf,timeout);
  if (!ret || CVAL(inbuf,smb_rcls)) {
    DEBUG(3,("%s rejected session setup\n",name));
    close(fd);
    if (inbuf) free(inbuf);
    return;
  }

  uid = SVAL(inbuf,smb_uid);

  bzero(outbuf,smb_size);
  set_message(outbuf,4,2 + (2 + strlen(name) + 1 + strlen(service)) +
       1 + strlen(dev),True);
  CVAL(outbuf,smb_com) = SMBtconX;
  SSVAL(outbuf,smb_uid,uid);

  SSVAL(outbuf,smb_vwv0,0xFF);
  SSVAL(outbuf,smb_vwv3,1);

  p = smb_buf(outbuf) + 1;
  strcpy(p, "\\\\");
  strcat(p, name);
  strcat(p, "\\");
  strcat(p,service);
  p = skip_string(p,1);
  strcpy(p,dev);

  send_smb(fd,outbuf);
  bzero(inbuf,smb_size);
  ret = receive_smb(fd,inbuf,timeout);
  if (!ret || CVAL(inbuf,smb_rcls)) {
    DEBUG(3,("%s rejected IPC connect (%d,%d)\n",name,
	     CVAL(inbuf,smb_rcls),SVAL(inbuf,smb_err)));
    close(fd);
    if (inbuf) free(inbuf);
    return;
  }

  cnum = SVAL(inbuf,smb_tid);
  
  /* now I need to send a NetServerEnum */
  {
    fstring param;
    uint32 *typep;
    char *rparam,*rdata;

    p = param;
    SSVAL(p,0,0x68); /* api number */
    p += 2;
    strcpy(p,"WrLehDz");
    p = skip_string(p,1);

    strcpy(p,"B16BBDz");

    p = skip_string(p,1);
    SSVAL(p,0,1); /* level 1 */
    SSVAL(p,2,0xFFFF - 500); /* buf length */
    p += 4;
    typep = (uint32 *)p;
    p += 4;
    strcpy(p,domain);
    strupper(p);
    p = skip_string(p,1);

    SIVAL(typep,0,0x80000000); /* domain list */

    if (call_remote_api(fd,cnum,uid,timeout,inbuf,outbuf,
			PTR_DIFF(p,param),0,
			8,0xFFFF - 500,
			NULL,NULL,
			param,NULL,
			&rparam,&rdata) && SVAL(rparam,0)==0)
    {
      int converter=SVAL(rparam,2);
      int count=SVAL(rparam,4);
      int i;
      char *p2 = rdata;
      for (i=0;i<count;i++) {
	char *sname = p2;
	uint32 type = IVAL(p2,18);
	int comment_offset = IVAL(p2,22) & 0xFFFF;
	char *comment = comment_offset?(rdata+comment_offset-converter):"";

	add_server_entry(sname,type,lp_max_ttl(),comment,False);
	p2 += 26;
      }
    }

    SIVAL(typep,0,0xFFFFFFFF); /* server list */

    if (call_remote_api(fd,cnum,uid,timeout,inbuf,outbuf,
			PTR_DIFF(p,param),0,
			8,0xFFFF - 500,
			NULL,NULL,
			param,NULL,
			&rparam,&rdata) && SVAL(rparam,0)==0)
    {
      int converter=SVAL(rparam,2);
      int count=SVAL(rparam,4);
      int i;

      p = rdata;
      for (i=0;i<count;i++) {
	char *sname = p;
	uint32 type = IVAL(p,18);
	int comment_offset = IVAL(p,22) & 0xFFFF;
	char *comment = comment_offset?(rdata+comment_offset-converter):"";

	add_server_entry(sname,type,lp_max_ttl(),comment,False);
	p += 26;
      }
    }
  }

  /* close up */
  bzero(outbuf,smb_size);
  set_message(outbuf,0,0,True);
  CVAL(outbuf,smb_com) = SMBtdis;
  SSVAL(outbuf,smb_uid,uid);
  SSVAL(outbuf,smb_tid,cnum);
  send_smb(fd,outbuf);
  receive_smb(fd,inbuf,1000);
  
  close(fd);
  if (inbuf) free(inbuf);
}
