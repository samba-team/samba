/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1996
   
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
   
   Module name: nameservreply.c

   Revision History:

   14 jan 96: lkcl@pires.co.uk
   added multiple workgroup domain master support

   04 jul 96: lkcl@pires.co.uk
   created module nameservreply containing NetBIOS reply functions

*/

#include "includes.h"

extern int ClientNMB;

extern int DEBUGLEVEL;

extern struct in_addr ipgrp;


/****************************************************************************
  add a netbios entry. respond to the (possibly new) owner.
  **************************************************************************/
void add_name_respond(struct subnet_record *d, int fd, struct in_addr from_ip,
				uint16 response_id,
				struct nmb_name *name,
				int nb_flags, int ttl, struct in_addr register_ip,
				BOOL new_owner, struct in_addr reply_to_ip)
{
	/* register the old or the new owners' ip */
	add_netbios_entry(d,name->name,name->name_type,
						nb_flags,ttl,REGISTER,register_ip,False,True);

	/* reply yes or no to the host that requested the name */
	send_name_response(fd,from_ip, response_id, NMB_REG,
				new_owner, True,
				name, nb_flags, ttl, reply_to_ip);
}

/****************************************************************************
send a registration / release response: pos/neg
**************************************************************************/
void send_name_response(int fd, struct in_addr from_ip,
				int name_trn_id, int opcode, BOOL success, BOOL recurse,
				struct nmb_name *reply_name, int nb_flags, int ttl,
				struct in_addr ip)
{
  char rdata[6];
  struct packet_struct p;

  int rcode = 0;  

  if (success == False)
  {
    /* NEGATIVE RESPONSE */
    rcode = 6;
  }
  else if (opcode == NMB_REG && recurse == False)
  {
    /* END-NODE CHALLENGE REGISTRATION RESPONSE */
	rcode = 0;
  }
  
  rdata[0] = nb_flags;
  rdata[1] = 0;
  putip(&rdata[2],(char *)&ip);
  
  p.ip = from_ip;
  p.port = NMB_PORT;
  p.fd = fd;
  p.timestamp = time(NULL);
  p.packet_type = NMB_PACKET;

  reply_netbios_packet(&p,name_trn_id,
		       rcode,opcode,opcode,recurse,
		       reply_name, 0x20, 0x1,
		       ttl, 
		       rdata, 6);
}


/****************************************************************************
reply to a name release
****************************************************************************/
void reply_name_release(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct in_addr ip;
  int nb_flags = nmb->additional->rdata[0];
  BOOL bcast = nmb->header.nm_flags.bcast;
  struct name_record *n;
  struct subnet_record *d = NULL;
  int search = 0;
  BOOL success = False;
  
  putip((char *)&ip,&nmb->additional->rdata[2]);  
  
  DEBUG(3,("Name release on name %s\n",
	   namestr(&nmb->question.question_name)));
  
  if (!(d = find_req_subnet(p->ip, bcast)))
  {
    DEBUG(3,("response packet: bcast %s not known\n",
			inet_ntoa(p->ip)));
    return;
  }

  if (bcast)
	search &= FIND_LOCAL;
  else
	search &= FIND_WINS;

  n = find_name_search(&d, &nmb->question.question_name, 
					search, ip);
  
  /* XXXX under what conditions should we reject the removal?? */
  if (n && n->ip_flgs[0].nb_flags == nb_flags)
  {
      success = True;
      
      remove_name(d,n);
      n = NULL;
  }
  
  if (bcast) return;
  
  /* Send a NAME RELEASE RESPONSE (pos/neg) see rfc1002.txt 4.2.10-11 */
  send_name_response(p->fd,p->ip, nmb->header.name_trn_id, NMB_REL,
						success, False,
						&nmb->question.question_name, nb_flags, 0, ip);
}


/****************************************************************************
reply to a reg request
**************************************************************************/
void reply_name_reg(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *question = &nmb->question.question_name;
  
  struct nmb_name *reply_name = question;

  char *qname      = question->name;
  int   qname_type = question->name_type;
 
  BOOL bcast = nmb->header.nm_flags.bcast;
  
  int ttl = GET_TTL(nmb->additional->ttl);
  int nb_flags = nmb->additional->rdata[0];
  BOOL group = NAME_GROUP(nb_flags);

  struct subnet_record *d = NULL;
  struct name_record *n = NULL;

  BOOL success = True;
  BOOL secured_redirect = False;

  struct in_addr ip, from_ip;
  int search = 0;
  
  putip((char *)&from_ip,&nmb->additional->rdata[2]);
  ip = from_ip;
  
  DEBUG(3,("Name registration for name %s at %s\n",
	           namestr(question),inet_ntoa(ip)));
  
  if (group)
    {
      /* apparently we should return 255.255.255.255 for group queries
	 (email from MS) */
      ip = ipgrp;
    }
  
  if (!(d = find_req_subnet(p->ip, bcast)))
  {
    DEBUG(3,("response packet: bcast %s not known\n",
				inet_ntoa(p->ip)));
    return;
  }

  if (bcast)
	search &= FIND_LOCAL;
  else
	search &= FIND_WINS;

  /* see if the name already exists */
  n = find_name_search(&d, question, search, from_ip);
  
  if (n)
  {
    if (!group) /* unique names */
	{
	  if (n->source == SELF || NAME_GROUP(n->ip_flgs[0].nb_flags))
	  {
	      /* no-one can register one of samba's names, nor can they
		 register a name that's a group name as a unique name */
	      
	      success = False;
	  }
	  else if(!ip_equal(ip, n->ip_flgs[0].ip))
	  {
	      /* XXXX rfc1001.txt says:
	       * if we are doing secured WINS, we must send a Wait-Acknowledge
	       * packet (WACK) to the person who wants the name, then do a
	       * name query on the person who currently owns the unique name.
	       * if the current owner still says they own it, the person who wants
		   * the name can't have it. if they do not, or are not alive, they can.
	       */

          secured_redirect = True;

	      reply_name = &n->name;
	  }
	  else
	  {
	      n->ip_flgs[0].ip = ip;
	      n->death_time = ttl?p->timestamp+ttl*3:0;
	      DEBUG(3,("%s owner: %s\n",namestr(&n->name),inet_ntoa(n->ip_flgs[0].ip)));
	  }
	}
    else
	{
	  /* refresh the name */
	  if (n->source != SELF)
	  {
	      n->death_time = ttl?p->timestamp + ttl*3:0;
	  }
	}

    /* XXXX bug reported by terryt@ren.pc.athabascau.ca */
    /* names that people have checked for and not found get DNSFAILed. 
       we need to update the name record if someone then registers */

    if (n->source == DNSFAIL)
      n->source = REGISTER;

  }
  else
  {
      /* add the name to our name/subnet, or WINS, database */
      n = add_netbios_entry(d,qname,qname_type,nb_flags,ttl,REGISTER,ip,
				True,!bcast);
  }
  
  /* if samba owns a unique name on a subnet, then it must respond and
     disallow the attempted registration. if the registration is
     successful by broadcast, only then is there no need to respond
     (implicit registration: see rfc1001.txt 15.2.1).
   */

  if (bcast && success) return;
  
  if (secured_redirect)
  {
    char rdata[2];

    /* XXXX i am confused. RSVAL or SSVAL? assume NMB byte ordering */
    RSSVAL(rdata,0,(nmb->header.opcode&0xf) + ((nb_flags&0xff) << 4));
  
    /* XXXX mistake in rfc1002.txt? 4.2.16: NULL is 0xa see 4.2.1.3 
       type  = 0x0a; see rfc1002.txt 4.2.1.3 
       class = 0x01; see rfc1002.txt 4.2.16
     */

    /* send WAIT ACKNOWLEDGEMENT see rfc1002.txt 4.2.16 */
    reply_netbios_packet(p,nmb->header.name_trn_id,
		       0,NMB_WAIT_ACK,NMB_WAIT_ACK,False,
		       reply_name, 0x0a, 0x01,
		       15*1000, /* 15 seconds long enough to wait? */
		       rdata, 2);

    /* initiate some enquiries to the current owner. */
	queue_netbios_packet(d,ClientNMB,NMB_QUERY,
						 NAME_REGISTER_CHALLENGE,
						 reply_name->name,reply_name->name_type,
	                     nb_flags,0,0,NULL,NULL,
						 False, False, n->ip_flgs[0].ip, p->ip);
  }
  else
  {
    /* Send a NAME REGISTRATION RESPONSE (pos/neg) see rfc1002.txt 4.2.13-14
       or an END-NODE CHALLENGE REGISTRATION RESPONSE see rfc1002.txt 4.2.7
     */

  	send_name_response(p->fd,p->ip, nmb->header.name_trn_id, NMB_REG,
						success, True,
						reply_name, nb_flags, ttl, ip);
  }
}

/* this is used to sort names for a name status into a sensible order
   we put our own names first, then in alphabetical order */
static int status_compare(char *n1,char *n2)
{
  extern pstring myname;
  int l1,l2,l3;

  /* its a bit tricky because the names are space padded */
  for (l1=0;l1<15 && n1[l1] && n1[l1] != ' ';l1++) ;
  for (l2=0;l2<15 && n2[l2] && n2[l2] != ' ';l2++) ;
  l3 = strlen(myname);

  if ((l1==l3) && strncmp(n1,myname,l3) == 0 && 
      (l2!=l3 || strncmp(n2,myname,l3) != 0))
    return -1;

  if ((l2==l3) && strncmp(n2,myname,l3) == 0 && 
      (l1!=l3 || strncmp(n1,myname,l3) != 0))
    return 1;

  return memcmp(n1,n2,18);
}


/****************************************************************************
  reply to a name status query

  combine the list of the local interface on which the query was made with
  the names registered via wins.
  ****************************************************************************/
void reply_name_status(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  char *qname   = nmb->question.question_name.name;
  int ques_type = nmb->question.question_name.name_type;
  char rdata[MAX_DGRAM_SIZE];
  char *countptr, *buf, *bufend, *buf0;
  int names_added,i;
  struct name_record *n;
  struct subnet_record *d = NULL;
  int search = FIND_SELF | FIND_WINS | FIND_LOCAL;

  /* NOTE: we always treat a name status lookup as a bcast */ 
  if (!(d = find_req_subnet(p->ip, True)))
  {
    DEBUG(3,("Name status req: bcast %s not known\n",
			inet_ntoa(p->ip)));
    return;
  }

  DEBUG(3,("Name status for name %s %s\n",
	   namestr(&nmb->question.question_name), 
	   inet_ntoa(p->ip)));

  n = find_name_search(&d, &nmb->question.question_name,
				search, p->ip);
  
  if (!n) return;
  
  /* XXXX hack, we should calculate exactly how many will fit */
  bufend = &rdata[MAX_DGRAM_SIZE] - 18;
  countptr = buf = rdata;
  buf += 1;
  buf0 = buf;

  names_added = 0;

  n = d->namelist;

  while (buf < bufend) 
  {
    if (n->source == SELF)
    {
      int name_type = n->name.name_type;
      
      /* check if we want to exclude other workgroup names
	     from the response. if we don't exclude them, windows clients
	     get confused and will respond with an error for NET VIEW */
      
      if (!strequal(n->name.name,"*") &&
	  !strequal(n->name.name,"__SAMBA__") &&
	  (name_type < 0x1b || name_type > 0x20 || 
	   ques_type < 0x1b || ques_type > 0x20 ||
	   strequal(qname, n->name.name)))
      {
        /* start with first bit of putting info in buffer: the name */
        bzero(buf,18);
	    sprintf(buf,"%-15.15s",n->name.name);
        strupper(buf);
        
        /* put name type and netbios flags in buffer */
        buf[15] = name_type;
        buf[16]  = n->ip_flgs[0].nb_flags;
        
        buf += 18;
      
        names_added++;
      }
    }

    /* remove duplicate names */
    qsort(buf0,names_added,18,QSORT_CAST status_compare);

    for (i=1;i<names_added;i++) {
      if (memcmp(buf0 + 18*i,buf0 + 18*(i-1),16) == 0) {
	names_added--;
	if (names_added == i) break;
	memmove(buf0 + 18*i,buf0 + 18*(i+1),18*(names_added-i));
	i--;
      }
    }

    buf = buf0 + 18*names_added;

    n = n->next;

    if (!n)
    {
      /* end of this name list: add wins names too? */
      struct subnet_record *w_d;

      if (!(w_d = find_subnet(ipgrp))) break;

      if (w_d != d)
      {
        d = w_d;
        n = d->namelist; /* start on the wins name list */
      }
	}
	if (!n) break;
  }
  
  SCVAL(countptr,0,names_added);
  
  /* XXXXXXX we should fill in more fields of the statistics structure */
  bzero(buf,64);
  {
    extern int num_good_sends,num_good_receives;
    SIVAL(buf,20,num_good_sends);
    SIVAL(buf,24,num_good_receives);
  }
  
  buf += 46;
  
  /* Send a POSITIVE NAME STATUS RESPONSE */
  reply_netbios_packet(p,nmb->header.name_trn_id,
			   0,NMB_STATUS,0,True,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       0,
		       rdata,PTR_DIFF(buf,rdata));
}


/***************************************************************************
reply to a name query.

with broadcast name queries:

	- only reply if the query is for one of YOUR names. all other machines on
	  the network will be doing the same thing (that is, only replying to a
	  broadcast query if they own it)
	  NOTE: broadcast name queries should only be sent out by a machine
	  if they HAVEN'T been configured to use WINS. this is generally bad news
	  in a wide area tcp/ip network and should be rectified by the systems
	  administrator. USE WINS! :-)
	- the exception to this is if the query is for a Primary Domain Controller
	  type name (0x1b), in which case, a reply is sent.

	- NEVER send a negative response to a broadcast query. no-one else will!

with directed name queries:

	- if you are the WINS server, you are expected to respond with either
      a negative response, a positive response, or a wait-for-acknowledgement
      packet, and then later on a pos/neg response.

****************************************************************************/
void reply_name_query(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  struct nmb_name *question = &nmb->question.question_name;
  int name_type = question->name_type;
  BOOL bcast = nmb->header.nm_flags.bcast;
  int ttl=0;
  int rcode = 0;
  int nb_flags = 0;
  struct in_addr retip;
  char rdata[6];
  struct subnet_record *d = NULL;
  BOOL success = True;
  struct name_record *n;

  /* directed queries are for WINS server: broadcasts are local SELF queries.
     the exception is Domain Master names.  */

  int search = bcast ? FIND_LOCAL | FIND_SELF : FIND_WINS;
  
  if (name_type == 0x1b)
  {
    search |= FIND_WINS;
  }

  if (search | FIND_LOCAL)
  {
    if (!(d = find_req_subnet(p->ip, bcast)))
    {
      DEBUG(3,("name query: bcast %s not known\n",
				    inet_ntoa(p->ip)));
      success = False;
    }
  }
  else
  {
    if (!(d = find_subnet(ipgrp)))
    {
      DEBUG(3,("name query: wins search %s not known\n",
				    inet_ntoa(p->ip)));
      success = False;
    }
  }

  DEBUG(3,("Name query "));
  
  if (search == 0)
  {
    /* eh? no criterion for searching database. help! */
    success = False;
  }

  if (!bcast && name_type == 0x1d)
  {
    /* see WINS manager HELP - 'How WINS Handles Special Names' */
    /* a WINS query (unicasted) for a 0x1d name must always return False */
    success = False;
  }

  if (success && (n = search_for_name(&d,question,p->ip,p->timestamp, search)))
  {
      /* don't respond to broadcast queries unless the query is for
         a name we own or it is for a Primary Domain Controller name */

      if (bcast && n->source != SELF && name_type != 0x1b) {
	    if (!lp_wins_proxy() || same_net(p->ip,n->ip_flgs[0].ip,*iface_nmask(p->ip))) {
	      /* never reply with a negative response to broadcast queries */
	      return;
	    }
	  }
      
      /* name is directed query, or it's self, or it's a Domain Master type
         name, or we're replying on behalf of a caller because they are on a
         different subnet and cannot hear the broadcast. XXXX lp_wins_proxy
         should be switched off in environments where broadcasts are forwarded
       */

      /* XXXX note: for proxy servers, we should forward the query on to
         another WINS server if the name is not in our database, or we are
         not a WINS server ourselves
       */
      ttl = n->death_time ? n->death_time - p->timestamp : GET_TTL(0);
      retip = n->ip_flgs[0].ip;
      nb_flags = n->ip_flgs[0].nb_flags;
  }
  else
  {
      if (bcast) return; /* never reply negative response to bcasts */
      success = False;
  }
  
  /* if the IP is 0 then substitute my IP */
  if (zero_ip(retip)) retip = *iface_ip(p->ip);

  if (success)
  {
      rcode = 0;
      DEBUG(3,("OK %s\n",inet_ntoa(retip)));      
  }
  else
  {
      rcode = 3;
      DEBUG(3,("UNKNOWN\n"));      
  }
  
  if (success)
  {
      rdata[0] = nb_flags;
      rdata[1] = 0;
      putip(&rdata[2],(char *)&retip);
  }
  
  reply_netbios_packet(p,nmb->header.name_trn_id,
			   rcode,NMB_QUERY,0,True,
		       &nmb->question.question_name,
		       nmb->question.question_type,
		       nmb->question.question_class,
		       ttl,
		       rdata, success ? 6 : 0);
}


