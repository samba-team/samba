/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1997
   
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
   
   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

*/

#include "includes.h"

extern int ClientDGRAM;

#define TEST_CODE /* want to debug unknown browse packets */

extern int DEBUGLEVEL;

extern pstring myname;


/****************************************************************************
   process a domain logon packet

   **************************************************************************/
void process_logon_packet(struct packet_struct *p,char *buf,int len)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  char *logname,*q;
  fstring reply_name;
  BOOL add_slashes = False;
  pstring outbuf;
  int code,reply_code;
  char   unknown_byte = 0;
  uint16 request_count = 0;
  uint16 token = 0;
  
  if (!lp_domain_logons())
    {
      DEBUG(3,("No domain logons\n"));
      return;
    }
  
 
  code = SVAL(buf,0);
  switch (code)
    {
    case 0:    
      {
	char *machine = buf+2;
	char *user = skip_string(machine,1);
	char *tmp;
	logname = skip_string(user,1);
	tmp = skip_string(logname,1);
	unknown_byte = CVAL(tmp,0);
	request_count = SVAL(tmp,1);
	token = SVAL(tmp,3);
	
	reply_code = 0x6;
	fstrcpy(reply_name,myname); 
	strupper(reply_name);
	add_slashes = True;
	DEBUG(3,("Domain login request from %s(%s) user=%s token=%x\n",
		 machine,inet_ntoa(p->ip),user,token));
	break;
      }
    case 7:    
      {
	char *machine = buf+2;
	logname = skip_string(machine,1);
	token = SVAL(skip_string(logname,1),0);
	
	fstrcpy(reply_name,lp_domain_controller()); 
	if (!*reply_name)
	  {
	    /* oo! no domain controller. must be us, then */
	    fstrcpy(reply_name,myname); 
	    reply_code = 0xC;
	  }
	else
	  {
	    /* refer logon request to the domain controller */
	    reply_code = 0x7;
	  }

	strupper(reply_name);
	DEBUG(3,("GETDC request from %s(%s), reporting %s 0x%x token=%x\n",
		 machine,inet_ntoa(p->ip), reply_name, reply_code,token));
	break;
      }
    default:
      {
	DEBUG(3,("Unknown domain request %d\n",code));
	return;
      }
    }
  
  bzero(outbuf,sizeof(outbuf));
  q = outbuf;
  SSVAL(q,0,reply_code);
  q += 2;
  
  if (token == 0xffff || /* LM 2.0 or later */
      token == 0xfffe) /* WfWg networking */
    {
      if (add_slashes)
	{
	  strcpy(q,"\\\\");
	  q += 2;
	}
      strcpy(q, reply_name); 
      strupper(q);
      q = skip_string(q,1);
      
      if (token == 0xffff) /* LM 2.0 or later */
	{
	  SSVAL(q,0,token);
	  q += 2;
	}
    }
  
  SSVAL(q,0,0xFFFF);
  q += 2;
  
  send_mailslot_reply(True, logname,ClientDGRAM,outbuf,PTR_DIFF(q,outbuf),
 		      myname,&dgram->source_name.name[0],0x20,0,p->ip,
		      *iface_ip(p->ip));  
}
