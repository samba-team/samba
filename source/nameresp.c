/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios library routines
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

extern int ClientNMB;
extern int ClientDGRAM;

extern struct subnet_record *subnetlist;

extern int DEBUGLEVEL;

static uint16 name_trn_id=0;
BOOL CanRecurse = True;
extern pstring scope;
extern pstring myname;
extern struct in_addr ipzero;
extern struct in_addr ipgrp;

int num_response_packets = 0;

/***************************************************************************
  updates the unique transaction identifier
  **************************************************************************/
static void update_name_trn_id(void)
{
  if (!name_trn_id)
  {
    name_trn_id = (time(NULL)%(unsigned)0x7FFF) + (getpid()%(unsigned)100);
  }
  name_trn_id = (name_trn_id+1) % (unsigned)0x7FFF;
}


/***************************************************************************
  add an initated name query  into the list
  **************************************************************************/
static void add_response_record(struct subnet_record *d,
				struct response_record *n)
{
  struct response_record *n2;

  if (!d) return;

  if (!d->responselist)
    {
      d->responselist = n;
      n->prev = NULL;
      n->next = NULL;
      return;
    }
  
  for (n2 = d->responselist; n2->next; n2 = n2->next) ;
  
  n2->next = n;
  n->next = NULL;
  n->prev = n2;
}


/***************************************************************************
  deals with an entry before it dies
  **************************************************************************/
static void dead_netbios_entry(struct subnet_record *d,
				struct response_record *n)
{
  DEBUG(3,("Removing dead netbios entry for %s %s (num_msgs=%d)\n",
	   inet_ntoa(n->to_ip), namestr(&n->name), n->num_msgs));

  switch (n->state)
  {
    case NAME_QUERY_CONFIRM:
    {
		if (!lp_wins_support()) return; /* only if we're a WINS server */

		if (n->num_msgs == 0)
        {
			/* oops. name query had no response. check that the name is
			   unique and then remove it from our WINS database */

			/* IMPORTANT: see query_refresh_names() */

			if ((!NAME_GROUP(n->nb_flags)))
			{
				struct subnet_record *d1 = find_subnet(ipgrp);
				if (d1)
				{
					/* remove the name that had been registered with us,
					   and we're now getting no response when challenging.
					   see rfc1001.txt 15.5.2
					 */
					remove_netbios_name(d1, n->name.name, n->name.name_type,
									REGISTER, n->to_ip);
				}
			}
		}
		break;
    }

	case NAME_QUERY_MST_CHK:
	{
	  /* if no response received, the master browser must have gone
		 down on that subnet, without telling anyone. */

	  /* IMPORTANT: see response_netbios_packet() */

	  if (n->num_msgs == 0)
		  browser_gone(n->name.name, n->to_ip);
	  break;
	}

	case NAME_RELEASE:
	{
	  /* if no response received, it must be OK for us to release the
		 name. nobody objected (including a potentially dead or deaf
		 WINS server) */

	  /* IMPORTANT: see response_name_release() */

	  if (ismyip(n->to_ip))
	  {
		remove_netbios_name(d,n->name.name,n->name.name_type,SELF,n->to_ip);
	  }
	  if (!n->bcast)
	  {
		 DEBUG(1,("WINS server did not respond to name release!\n"));
	  }
	  break;
	}

	case NAME_REGISTER:
	{
	  /* if no response received, and we are using a broadcast registration
		 method, it must be OK for us to register the name: nobody objected 
		 on that subnet. if we are using a WINS server, then the WINS
		 server must be dead or deaf.
	   */
	  if (n->bcast)
	  {
		/* broadcast method: implicit acceptance of the name registration
		   by not receiving any objections. */

		/* IMPORTANT: see response_name_reg() */

		enum name_source source = ismyip(n->to_ip) ? SELF : REGISTER;

		add_netbios_entry(d,n->name.name,n->name.name_type,
				n->nb_flags, n->ttl, source,n->to_ip, True,!n->bcast);
	  }
	  else
	  {
		/* XXXX oops. this is where i wish this code could retry DGRAM
		   packets. we directed a name registration at a WINS server, and
		   received no response. rfc1001.txt states that after retrying,
		   we should assume the WINS server is dead, and fall back to
		   broadcasting. */
		
		 DEBUG(1,("WINS server did not respond to name registration!\n"));
	  }
	  break;
	}

	default:
	{
	  /* nothing to do but delete the dead expected-response structure */
	  /* this is normal. */
	  break;
	}
  }
}


/****************************************************************************
  initiate a netbios packet
  ****************************************************************************/
static void initiate_netbios_packet(uint16 *id,
				int fd,int quest_type,char *name,int name_type,
			    int nb_flags,BOOL bcast,BOOL recurse,
			    struct in_addr to_ip)
{
  struct packet_struct p;
  struct nmb_packet *nmb = &p.packet.nmb;
  struct res_rec additional_rec;
  char *packet_type = "unknown";
  int opcode = -1;

  if (!id) return;

  if (quest_type == NMB_STATUS) { packet_type = "nmb_status"; opcode = 0; }
  if (quest_type == NMB_QUERY ) { packet_type = "nmb_query"; opcode = 0; }
  if (quest_type == NMB_REG   ) { packet_type = "nmb_reg"; opcode = 5; }
  if (quest_type == NMB_REL   ) { packet_type = "nmb_rel"; opcode = 6; }
  
  DEBUG(4,("initiating netbios packet: %s %s(%x) (bcast=%s) %s\n",
	   packet_type, name, name_type, BOOLSTR(bcast), inet_ntoa(to_ip)));

  if (opcode == -1) return;

  bzero((char *)&p,sizeof(p));

  update_name_trn_id();

  if (*id == 0xffff) *id = name_trn_id; /* allow resending with same id */

  nmb->header.name_trn_id = *id;
  nmb->header.opcode = opcode;
  nmb->header.response = False;
  nmb->header.nm_flags.bcast = bcast;
  nmb->header.nm_flags.recursion_available = CanRecurse;
  nmb->header.nm_flags.recursion_desired = recurse;
  nmb->header.nm_flags.trunc = False;
  nmb->header.nm_flags.authoritative = False;
  nmb->header.rcode = 0;
  nmb->header.qdcount = 1;
  nmb->header.ancount = 0;
  nmb->header.nscount = 0;
  nmb->header.arcount = (quest_type==NMB_REG || quest_type==NMB_REL) ? 1 : 0;
  
  make_nmb_name(&nmb->question.question_name,name,name_type,scope);
  
  nmb->question.question_type = quest_type;
  nmb->question.question_class = 0x1;
  
  if (quest_type == NMB_REG || quest_type == NMB_REL)
    {
      nmb->additional = &additional_rec;
      bzero((char *)nmb->additional,sizeof(*nmb->additional));
      
      nmb->additional->rr_name  = nmb->question.question_name;
      nmb->additional->rr_type  = nmb->question.question_type;
      nmb->additional->rr_class = nmb->question.question_class;
      
      nmb->additional->ttl = quest_type == NMB_REG ? lp_max_ttl() : 0;
      nmb->additional->rdlength = 6;
      nmb->additional->rdata[0] = nb_flags;
      putip(&nmb->additional->rdata[2],(char *)iface_ip(to_ip));
    }
  
  p.ip = to_ip;
  p.port = NMB_PORT;
  p.fd = fd;
  p.timestamp = time(NULL);
  p.packet_type = NMB_PACKET;
  
  if (!send_packet(&p)) *id = 0xffff;
  
  return;
}


/*******************************************************************
  remove old name response entries
  XXXX retry code needs to be added, including a retry wait period and a count
       see name_query() and name_status() for suggested implementation.
  ******************************************************************/
void expire_netbios_response_entries()
{
  struct response_record *n;
  struct response_record *nextn;
  struct subnet_record *d;

  for (d = subnetlist; d; d = d->next)
   for (n = d->responselist; n; n = nextn)
    {
      if (n->repeat_time < time(NULL))
	  {
		  if (n->repeat_count > 0)
		  {
			/* resend the entry */
  			initiate_netbios_packet(&n->response_id, n->fd, n->quest_type,
						n->name.name, n->name.name_type,
				      n->nb_flags, n->bcast, n->recurse, n->to_ip);

            n->repeat_time += n->repeat_interval; /* XXXX ms needed */
            n->repeat_count--;
		  }
		  else
		  {
			  dead_netbios_entry(d,n);

			  nextn = n->next;
			  
			  if (n->prev) n->prev->next = n->next;
			  if (n->next) n->next->prev = n->prev;
			  
			  if (d->responselist == n) d->responselist = n->next; 
			  
			  free(n);

			  num_response_packets--;

			  continue;
		   }
	  }
	  nextn = n->next;
    }
}


/****************************************************************************
  reply to a netbios name packet 
  ****************************************************************************/
void reply_netbios_packet(struct packet_struct *p1,int trn_id,
				int rcode,int opcode, BOOL recurse,
				struct nmb_name *rr_name,int rr_type,int rr_class,int ttl,
				char *data,int len)
{
  struct packet_struct p;
  struct nmb_packet *nmb = &p.packet.nmb;
  struct res_rec answers;
  char *packet_type = "unknown";
  
  p = *p1;

  if (rr_type == NMB_STATUS) packet_type = "nmb_status";
  if (rr_type == NMB_QUERY ) packet_type = "nmb_query";
  if (rr_type == NMB_REG   ) packet_type = "nmb_reg";
  if (rr_type == NMB_REL   ) packet_type = "nmb_rel";
  
  DEBUG(4,("replying netbios packet: %s %s\n",
	   packet_type, namestr(rr_name), inet_ntoa(p.ip)));

  nmb->header.name_trn_id = trn_id;
  nmb->header.opcode = opcode;
  nmb->header.response = True;
  nmb->header.nm_flags.bcast = False;
  nmb->header.nm_flags.recursion_available = recurse;
  nmb->header.nm_flags.recursion_desired = True;
  nmb->header.nm_flags.trunc = False;
  nmb->header.nm_flags.authoritative = True;
  
  nmb->header.qdcount = 0;
  nmb->header.ancount = 1;
  nmb->header.nscount = 0;
  nmb->header.arcount = 0;
  nmb->header.rcode = 0;
  
  bzero((char*)&nmb->question,sizeof(nmb->question));
  
  nmb->answers = &answers;
  bzero((char*)nmb->answers,sizeof(*nmb->answers));
  
  nmb->answers->rr_name  = *rr_name;
  nmb->answers->rr_type  = rr_type;
  nmb->answers->rr_class = rr_class;
  nmb->answers->ttl      = ttl;
  
  if (data && len)
    {
      nmb->answers->rdlength = len;
      memcpy(nmb->answers->rdata, data, len);
    }
  
  p.packet_type = NMB_PACKET;
  
  debug_nmb_packet(&p);
  
  send_packet(&p);
}


/****************************************************************************
  wrapper function to override a broadcast message and send it to the WINS
  name server instead, if it exists. if wins is false, and there has been no
  WINS server specified, the packet will NOT be sent.
  ****************************************************************************/
void queue_netbios_pkt_wins(struct subnet_record *d,
				int fd,int quest_type,enum state_type state,
			    char *name,int name_type,int nb_flags, time_t ttl,
			    BOOL bcast,BOOL recurse,struct in_addr to_ip)
{
  /* XXXX note: please see rfc1001.txt section 10 for details on this
     function: it is currently inappropriate to use this - it will do
     for now - once there is a clarification of B, M and P nodes and
     which one samba is supposed to be
   */

  if ((!lp_wins_support()) && (*lp_wins_server()))
    {
      /* samba is not a WINS server, and we are using a WINS server */
      struct in_addr wins_ip;
      wins_ip = *interpret_addr2(lp_wins_server());

      if (!zero_ip(wins_ip))
	{
	  bcast = False;
	  to_ip = wins_ip;
	}
      else
	{
	  /* oops. smb.conf's wins server parameter MUST be a host_name 
	     or an ip_address. */
	  DEBUG(0,("invalid smb.conf parameter 'wins server'\n"));
	}
    }

  if (zero_ip(to_ip)) return;

  queue_netbios_packet(d,fd, quest_type, state, 
		       name, name_type, nb_flags, ttl,
		       bcast, recurse, to_ip);
}

/****************************************************************************
  create a name query response record
  **************************************************************************/
static struct response_record *
make_response_queue_record(enum state_type state,int id,int fd,
				int quest_type, char *name,int type, int nb_flags, time_t ttl,
				BOOL bcast,BOOL recurse, struct in_addr ip)
{
  struct response_record *n;
	
  if (!name || !name[0]) return NULL;
	
  if (!(n = (struct response_record *)malloc(sizeof(*n)))) 
    return(NULL);

  n->response_id = id;
  n->state = state;
  n->fd = fd;
  n->quest_type = quest_type;
  make_nmb_name(&n->name, name, type, scope);
  n->nb_flags = nb_flags;
  n->ttl = ttl;
  n->bcast = bcast;
  n->recurse = recurse;
  n->to_ip = ip;

  n->repeat_interval = 1; /* XXXX should be in ms */
  n->repeat_count = 4;
  n->repeat_time = time(NULL) + n->repeat_interval;

  n->num_msgs = 0;

  num_response_packets++; /* count of total number of packets still around */

  return n;
}


/****************************************************************************
  initiate a netbios name query to find someone's or someones' IP
  this is intended to be used (not exclusively) for broadcasting to
  master browsers (WORKGROUP(1d or 1b) or __MSBROWSE__(1)) to get
  complete lists across a wide area network
  ****************************************************************************/
void queue_netbios_packet(struct subnet_record *d,
			int fd,int quest_type,enum state_type state,char *name,
			int name_type,int nb_flags, time_t ttl,
			BOOL bcast,BOOL recurse, struct in_addr to_ip)
{
  struct in_addr wins_ip = ipgrp;
  struct response_record *n;
  uint16 id = 0xffff;

  /* ha ha. no. do NOT broadcast to 255.255.255.255: it's a pseudo address */
  if (ip_equal(wins_ip, to_ip)) return;

  initiate_netbios_packet(&id, fd, quest_type, name, name_type,
				      nb_flags, bcast, recurse, to_ip);

  if (id == 0xffff) return;
  
  if ((n = make_response_queue_record(state,id,fd,
						quest_type,name,name_type,nb_flags,ttl,
						bcast,recurse,to_ip)))
    {
      add_response_record(d,n);
    }
}


/****************************************************************************
  find a response in a subnet's name query response list. 
  **************************************************************************/
struct response_record *find_response_record(struct subnet_record **d,
				uint16 id)
{  
  struct response_record *n;

  if (!d) return NULL;

  for ((*d) = subnetlist; (*d); (*d) = (*d)->next)
  {
    for (n = (*d)->responselist; n; n = n->next)
    {
      if (n->response_id == id) {
         return n;
      }
    }
  }

  *d = NULL;

  return NULL;
}


/*******************************************************************
  the global packet linked-list. incoming entries are added to the
  end of this list.  it is supposed to remain fairly short so we
  won't bother with an end pointer.
  ******************************************************************/
static struct packet_struct *packet_queue = NULL;

/*******************************************************************
  queue a packet into the packet queue
  ******************************************************************/
void queue_packet(struct packet_struct *packet)
{
  struct packet_struct *p;

  if (!packet_queue) {
    packet->prev = NULL;
    packet->next = NULL;
    packet_queue = packet;
    return;
  }
  
  /* find the bottom */
  for (p=packet_queue;p->next;p=p->next) ;

  p->next = packet;
  packet->next = NULL;
  packet->prev = p;
}

/*******************************************************************
  run elements off the packet queue till its empty
  ******************************************************************/
void run_packet_queue()
{
  struct packet_struct *p;

  while ((p=packet_queue))
    {
      switch (p->packet_type)
	{
	case NMB_PACKET:
	  process_nmb(p);
	  break;
	  
	case DGRAM_PACKET:
	  process_dgram(p);
	  break;
	}
      
      packet_queue = packet_queue->next;
      if (packet_queue) packet_queue->prev = NULL;
      free_packet(p);
    }
}

/****************************************************************************
  listens for NMB or DGRAM packets, and queues them
  ***************************************************************************/
void listen_for_packets(BOOL run_election)
{
  fd_set fds;
  int selrtn;
  struct timeval timeout;

  FD_ZERO(&fds);
  FD_SET(ClientNMB,&fds);
  FD_SET(ClientDGRAM,&fds);

  /* during elections and when expecting a netbios response packet we need
     to send election packets at one second intervals.
     XXXX actually, it needs to be the interval (in ms) between time now and the
     time we are expecting the next netbios packet */

  timeout.tv_sec = (run_election||num_response_packets) ? 1 : NMBD_SELECT_LOOP;
  timeout.tv_usec = 0;

  selrtn = sys_select(&fds,&timeout);

  if (FD_ISSET(ClientNMB,&fds))
    {
      struct packet_struct *packet = read_packet(ClientNMB, NMB_PACKET);
      if (packet) {
#if 1
	if (ismyip(packet->ip) &&
	    (packet->port == NMB_PORT || packet->port == DGRAM_PORT)) {
	  DEBUG(5,("discarding own packet from %s:%d\n",
		   inet_ntoa(packet->ip),packet->port));	  
	  free_packet(packet);
	} else 
#endif
	  {
	    queue_packet(packet);
	  }
      }
    }

  if (FD_ISSET(ClientDGRAM,&fds))
    {
      struct packet_struct *packet = read_packet(ClientDGRAM, DGRAM_PACKET);
      if (packet) {
#if 1
	if (ismyip(packet->ip) &&
	      (packet->port == NMB_PORT || packet->port == DGRAM_PORT)) {
	  DEBUG(5,("discarding own packet from %s:%d\n",
		   inet_ntoa(packet->ip),packet->port));	  
	  free_packet(packet);
	} else
#endif 
	  {
	    queue_packet(packet);
	  }
      }
    }
}



/****************************************************************************
interpret a node status response. this is pretty hacked: we need two bits of
info. a) the name of the workgroup b) the name of the server. it will also
add all the names it finds into the namelist.
****************************************************************************/
BOOL interpret_node_status(struct subnet_record *d,
				char *p, struct nmb_name *name,int t,
			   char *serv_name, struct in_addr ip, BOOL bcast)
{
  int level = t==0x20 ? 4 : 0;
  int numnames = CVAL(p,0);
  BOOL found = False;

  DEBUG(level,("received %d names\n",numnames));

  p += 1;

  if (serv_name) *serv_name = 0;

  while (numnames--)
    {
      char qname[17];
      int type;
      fstring flags;
      int nb_flags;
      
      BOOL group = False;
      BOOL add   = False;
      
      *flags = 0;
      
      StrnCpy(qname,p,15);
      type = CVAL(p,15);
      nb_flags = p[16];
      trim_string(qname,NULL," ");
      
      p += 18;
      
      if (NAME_GROUP    (nb_flags)) { strcat(flags,"<GROUP> "); group=True;}
      if (NAME_BFLAG    (nb_flags)) { strcat(flags,"B "); }
      if (NAME_PFLAG    (nb_flags)) { strcat(flags,"P "); }
      if (NAME_MFLAG    (nb_flags)) { strcat(flags,"M "); }
      if (NAME__FLAG    (nb_flags)) { strcat(flags,"_ "); }
      if (NAME_DEREG    (nb_flags)) { strcat(flags,"<DEREGISTERING> "); }
      if (NAME_CONFLICT (nb_flags)) { strcat(flags,"<CONFLICT> "); add=True;}
      if (NAME_ACTIVE   (nb_flags)) { strcat(flags,"<ACTIVE> "); add=True; }
      if (NAME_PERMANENT(nb_flags)) { strcat(flags,"<PERMANENT> "); add=True;}
      
      /* might as well update our namelist while we're at it */
      if (add)
	{
	  struct in_addr nameip;
	  enum name_source src;
	  
	  if (ismyip(ip)) {
	    nameip = ipzero;
	    src = SELF;
	  } else {
	    nameip = ip;
	    src = STATUS_QUERY;
	  }
	  add_netbios_entry(d,qname,type,nb_flags,2*60*60,src,nameip,True,bcast);
	} 

      /* we want the server name */
      if (serv_name && !*serv_name && !group && t == 0)
	{
	  StrnCpy(serv_name,qname,15);
	  serv_name[15] = 0;
	}
      
      /* looking for a name and type? */
      if (name && !found && (t == type))
	{
	  /* take a guess at some of the name types we're going to ask for.
	     evaluate whether they are group names or no... */
	  if (((t == 0x1b || t == 0x1d             ) && !group) ||
	      ((t == 0x20 || t == 0x1c || t == 0x1e) &&  group))
	    {
	      found = True;
	      make_nmb_name(name,qname,type,scope);
	    }
	}
      
      DEBUG(level,("\t%s(0x%x)\t%s\n",qname,type,flags));
    }
  DEBUG(level,("num_good_sends=%d num_good_receives=%d\n",
	       IVAL(p,20),IVAL(p,24)));
  return found;
}


/****************************************************************************
  construct and send a netbios DGRAM

  Note that this currently sends all answers to port 138. thats the
  wrong things to do! I should send to the requestors port. XXX
  **************************************************************************/
BOOL send_mailslot_reply(char *mailslot,int fd,char *buf,int len,char *srcname,
			 char *dstname,int src_type,int dest_type,
			 struct in_addr dest_ip,struct in_addr src_ip)
{
  struct packet_struct p;
  struct dgram_packet *dgram = &p.packet.dgram;
  struct in_addr wins_ip = ipgrp;
  char *ptr,*p2;
  char tmp[4];

  /* ha ha. no. do NOT send packets to 255.255.255.255: it's a pseudo address */
  if (ip_equal(wins_ip, dest_ip)) return False;

  bzero((char *)&p,sizeof(p));

  update_name_trn_id();

  dgram->header.msg_type = 0x11; /* DIRECT GROUP DATAGRAM */
  dgram->header.flags.node_type = M_NODE;
  dgram->header.flags.first = True;
  dgram->header.flags.more = False;
  dgram->header.dgm_id = name_trn_id;
  dgram->header.source_ip = src_ip;
  dgram->header.source_port = DGRAM_PORT;
  dgram->header.dgm_length = 0; /* let build_dgram() handle this */
  dgram->header.packet_offset = 0;
  
  make_nmb_name(&dgram->source_name,srcname,src_type,scope);
  make_nmb_name(&dgram->dest_name,dstname,dest_type,scope);

  ptr = &dgram->data[0];

  /* now setup the smb part */
  ptr -= 4; /* XXX ugliness because of handling of tcp SMB length */
  memcpy(tmp,ptr,4);
  set_message(ptr,17,17 + len,True);
  memcpy(ptr,tmp,4);

  CVAL(ptr,smb_com) = SMBtrans;
  SSVAL(ptr,smb_vwv1,len);
  SSVAL(ptr,smb_vwv11,len);
  SSVAL(ptr,smb_vwv12,70 + strlen(mailslot));
  SSVAL(ptr,smb_vwv13,3);
  SSVAL(ptr,smb_vwv14,1);
  SSVAL(ptr,smb_vwv15,1);
  SSVAL(ptr,smb_vwv16,2);
  p2 = smb_buf(ptr);
  strcpy(p2,mailslot);
  p2 = skip_string(p2,1);

  memcpy(p2,buf,len);
  p2 += len;

  dgram->datasize = PTR_DIFF(p2,ptr+4); /* +4 for tcp length */

  p.ip = dest_ip;
  p.port = DGRAM_PORT;
  p.fd = ClientDGRAM;
  p.timestamp = time(NULL);
  p.packet_type = DGRAM_PACKET;

  return(send_packet(&p));
}


