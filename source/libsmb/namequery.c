/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   name query routines
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

extern pstring scope;
extern int DEBUGLEVEL;


/****************************************************************************
interpret a node status response
****************************************************************************/
static void _interpret_node_status(char *p, char *master,char *rname)
{
  int level = (master||rname)?4:0;
  int numnames = CVAL(p,0);
  DEBUG(level,("received %d names\n",numnames));

  if (rname) *rname = 0;
  if (master) *master = 0;

  p += 1;
  while (numnames--)
    {
      char qname[17];
      int type;
      fstring flags;
      int i;
      *flags = 0;
      StrnCpy(qname,p,15);
      type = CVAL(p,15);
      p += 16;

      strcat(flags, (p[0] & 0x80) ? "<GROUP> " : "        ");
      if ((p[0] & 0x60) == 0x00) strcat(flags,"B ");
      if ((p[0] & 0x60) == 0x20) strcat(flags,"P ");
      if ((p[0] & 0x60) == 0x40) strcat(flags,"M ");
      if ((p[0] & 0x60) == 0x60) strcat(flags,"H ");
      if (p[0] & 0x10) strcat(flags,"<DEREGISTERING> ");
      if (p[0] & 0x08) strcat(flags,"<CONFLICT> ");
      if (p[0] & 0x04) strcat(flags,"<ACTIVE> ");
      if (p[0] & 0x02) strcat(flags,"<PERMANENT> ");

      if (master && !*master && type == 0x1d) {
	StrnCpy(master,qname,15);
	trim_string(master,NULL," ");
      }

      if (rname && !*rname && type == 0x20 && !(p[0]&0x80)) {
	StrnCpy(rname,qname,15);
	trim_string(rname,NULL," ");
      }
      
      for (i = strlen( qname) ; --i >= 0 ; ) {
	if (!isprint(qname[i])) qname[i] = '.';
      }
      DEBUG(level,("\t%-15s <%02x> - %s\n",qname,type,flags));
      p+=2;
    }
  DEBUG(level,("num_good_sends=%d num_good_receives=%d\n",
	       IVAL(p,20),IVAL(p,24)));
}


/****************************************************************************
  do a netbios name status query on a host

  the "master" parameter is a hack used for finding workgroups.
  **************************************************************************/
BOOL name_status(int fd,char *name,int name_type,BOOL recurse,
		 struct in_addr to_ip,char *master,char *rname,
		 void (*fn)())
{
  BOOL found=False;
  int retries = 2;
  int retry_time = 5000;
  struct timeval tval;
  struct packet_struct p;
  struct packet_struct *p2;
  struct nmb_packet *nmb = &p.packet.nmb;
  static int name_trn_id = 0;

  bzero((char *)&p,sizeof(p));

  if (!name_trn_id) name_trn_id = (time(NULL)%(unsigned)0x7FFF) + 
    (getpid()%(unsigned)100);
  name_trn_id = (name_trn_id+1) % (unsigned)0x7FFF;

  nmb->header.name_trn_id = name_trn_id;
  nmb->header.opcode = 0;
  nmb->header.response = False;
  nmb->header.nm_flags.bcast = False;
  nmb->header.nm_flags.recursion_available = False;
  nmb->header.nm_flags.recursion_desired = False;
  nmb->header.nm_flags.trunc = False;
  nmb->header.nm_flags.authoritative = False;
  nmb->header.rcode = 0;
  nmb->header.qdcount = 1;
  nmb->header.ancount = 0;
  nmb->header.nscount = 0;
  nmb->header.arcount = 0;

  make_nmb_name(&nmb->question.question_name,name,name_type,scope);

  nmb->question.question_type = 0x21;
  nmb->question.question_class = 0x1;

  p.ip = to_ip;
  p.port = NMB_PORT;
  p.fd = fd;
  p.timestamp = time(NULL);
  p.packet_type = NMB_PACKET;

  GetTimeOfDay(&tval);

  if (!send_packet(&p)) 
    return(False);

  retries--;

  while (1)
    {
      struct timeval tval2;
      GetTimeOfDay(&tval2);
      if (TvalDiff(&tval,&tval2) > retry_time) {
	if (!retries) break;
	if (!found && !send_packet(&p))
	  return False;
	GetTimeOfDay(&tval);
	retries--;
      }

      if ((p2=receive_packet(fd,NMB_PACKET,90)))
	{     
	  struct nmb_packet *nmb2 = &p2->packet.nmb;
      debug_nmb_packet(p2);

	  if (nmb->header.name_trn_id != nmb2->header.name_trn_id ||
	      !nmb2->header.response) {
	    /* its not for us - maybe deal with it later */
	    if (fn) 
	      fn(p2);
	    else
	      free_packet(p2);
	    continue;
	  }
	  
	  if (nmb2->header.opcode != 0 ||
	      nmb2->header.nm_flags.bcast ||
	      nmb2->header.rcode ||
	      !nmb2->header.ancount ||
	      nmb2->answers->rr_type != 0x21) {
	    /* XXXX what do we do with this? could be a redirect, but
	       we'll discard it for the moment */
	    free_packet(p2);
	    continue;
	  }

	  _interpret_node_status(&nmb2->answers->rdata[0], master,rname);
	  free_packet(p2);
	  return(True);
	}
    }
  

  DEBUG(0,("No status response (this is not unusual)\n"));

  return(False);
}


/****************************************************************************
  do a netbios name query to find someones IP
  ****************************************************************************/
BOOL name_query(int fd,char *name,int name_type, 
		BOOL bcast,BOOL recurse,
		struct in_addr to_ip, struct in_addr *ip,void (*fn)())
{
  BOOL found=False;
  int retries = 3;
  int retry_time = bcast?250:2000;
  struct timeval tval;
  struct packet_struct p;
  struct packet_struct *p2;
  struct nmb_packet *nmb = &p.packet.nmb;
  static int name_trn_id = 0;

  bzero((char *)&p,sizeof(p));

  if (!name_trn_id) name_trn_id = (time(NULL)%(unsigned)0x7FFF) + 
    (getpid()%(unsigned)100);
  name_trn_id = (name_trn_id+1) % (unsigned)0x7FFF;

  nmb->header.name_trn_id = name_trn_id;
  nmb->header.opcode = 0;
  nmb->header.response = False;
  nmb->header.nm_flags.bcast = bcast;
  nmb->header.nm_flags.recursion_available = False;
  nmb->header.nm_flags.recursion_desired = True;
  nmb->header.nm_flags.trunc = False;
  nmb->header.nm_flags.authoritative = False;
  nmb->header.rcode = 0;
  nmb->header.qdcount = 1;
  nmb->header.ancount = 0;
  nmb->header.nscount = 0;
  nmb->header.arcount = 0;

  make_nmb_name(&nmb->question.question_name,name,name_type,scope);

  nmb->question.question_type = 0x20;
  nmb->question.question_class = 0x1;

  p.ip = to_ip;
  p.port = NMB_PORT;
  p.fd = fd;
  p.timestamp = time(NULL);
  p.packet_type = NMB_PACKET;

  GetTimeOfDay(&tval);

  if (!send_packet(&p)) 
    return(False);

  retries--;

  while (1)
    {
      struct timeval tval2;
      GetTimeOfDay(&tval2);
      if (TvalDiff(&tval,&tval2) > retry_time) {
	if (!retries) break;
	if (!found && !send_packet(&p))
	  return False;
	GetTimeOfDay(&tval);
	retries--;
      }

      if ((p2=receive_packet(fd,NMB_PACKET,90)))
	{     
	  struct nmb_packet *nmb2 = &p2->packet.nmb;
      debug_nmb_packet(p2);

	  if (nmb->header.name_trn_id != nmb2->header.name_trn_id ||
	      !nmb2->header.response) {
	    /* its not for us - maybe deal with it later 
	       (put it on the queue?) */
	    if (fn) 
	      fn(p2);
	    else
	      free_packet(p2);
	    continue;
	  }
	  
	  if (nmb2->header.opcode != 0 ||
	      nmb2->header.nm_flags.bcast ||
	      nmb2->header.rcode ||
	      !nmb2->header.ancount) {
	    /* XXXX what do we do with this? could be a redirect, but
	       we'll discard it for the moment */
	    free_packet(p2);
	    continue;
	  }

	  if (ip) {
	    putip((char *)ip,&nmb2->answers->rdata[2]);
	    DEBUG(fn?3:2,("Got a positive name query response from %s",
			  inet_ntoa(p2->ip)));
	    DEBUG(fn?3:2,(" (%s)\n",inet_ntoa(*ip)));
	  }
	  found=True; retries=0;
	  free_packet(p2);
	  if (fn) break;
	}
    }

  return(found);
}
