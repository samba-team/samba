/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
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

   08aug96 lkcl@pires.co.uk
   reply_code == 0xC courtesy of jim@oxfordcc.co.uk forwarded by
                                 lewis2@server.uwindsor.ca
   **************************************************************************/
void process_logon_packet(struct packet_struct *p,char *buf,int len)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  struct in_addr ip = dgram->header.source_ip;
  struct subnet_record *d = find_subnet(ip);
  char *logname,*q;
  fstring reply_name;
  BOOL add_slashes = False;
  pstring outbuf;
  int code,reply_code;
  struct work_record *work;
  
  if (!d) return;
  
  if (!(work = find_workgroupstruct(d,dgram->dest_name.name, False))) 
    return;
  
  if (!lp_domain_logons()) {
    DEBUG(3,("No domain logons\n"));
    return;
  }
  
  code = SVAL(buf,0);
  switch (code) {
  case 0:    
    {
      char *machine = buf+2;
      char *user = skip_string(machine,1);
      logname = skip_string(user,1);
      reply_code = 6;
      strcpy(reply_name,myname); 
      strupper(reply_name);
      add_slashes = True;
      DEBUG(3,("Domain login request from %s(%s) user=%s\n",
 	       machine,inet_ntoa(p->ip),user));
    }
    break;
  case 7:    
    {
      char *machine = buf+2;
      logname = skip_string(machine,1);
      reply_code = 7;
      strcpy(reply_name,lp_domain_controller()); 
      if (!*reply_name) {
	strcpy(reply_name,myname); 
        reply_code = 0xC;
      }
      strupper(reply_name);
      DEBUG(3,("GETDC request from %s(%s), reporting %s 0x%2x\n",
 	       machine,inet_ntoa(p->ip), reply_name, reply_code));
    }
    break;
  default:
    DEBUG(3,("Unknown domain request %d\n",code));
    return;
  }
  
  bzero(outbuf,sizeof(outbuf));
  q = outbuf;
  SSVAL(q,0,reply_code);
  q += 2;
  if (add_slashes) {
    strcpy(q,"\\\\");
    q += 2;
  }
  StrnCpy(q,reply_name,16);
  q = skip_string(q,1);

  if (reply_code == 0xC)
  {
   if ( PTR_DIFF (q,outbuf) & 1 )
   {
       q++;
   }

   PutUniCode(q,reply_name);
   q += 2*(strlen(reply_name) + 1);

   PutUniCode(q,lp_workgroup());
   q += 2*(strlen(lp_workgroup()) + 1);

   SIVAL(q,0,1);
   q += 4;
   SSVAL(q,0,0xFFFF);
   q += 2;
  }

  SSVAL(q,0,0xFFFF);
  q += 2;
  
  send_mailslot_reply(logname,ClientDGRAM,outbuf,PTR_DIFF(q,outbuf),
 		      myname,&dgram->source_name.name[0],0x20,0,p->ip,
		      *iface_ip(p->ip));  
}
