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
#include "loadparm.h"

extern int ClientNMB;
extern int ClientDGRAM;

/* this is our initiated name query response database */
struct name_response_record *nameresponselist = NULL;

extern int DEBUGLEVEL;

static uint16 name_trn_id=0;
BOOL CanRecurse = True;
extern pstring scope;
extern pstring myname;
extern struct in_addr ipzero;


/***************************************************************************
  add an initated name query  into the list
  **************************************************************************/
extern void add_response_record(struct name_response_record *n)
{
  struct name_response_record *n2;

  if (!nameresponselist)
    {
      nameresponselist = n;
      n->prev = NULL;
      n->next = NULL;
      return;
    }
  
  for (n2 = nameresponselist; n2->next; n2 = n2->next) ;
  
  n2->next = n;
  n->next = NULL;
  n->prev = n2;
}


/*******************************************************************
  remove old name response entries
  ******************************************************************/
void expire_netbios_response_entries(time_t t)
{
  struct name_response_record *n;
  struct name_response_record *nextn;

  for (n = nameresponselist; n; n = nextn)
    {
      if (n->start_time < t)
	{
	  DEBUG(3,("Removing dead name query for %s %s (num_msgs=%d)\n",
		   inet_ntoa(n->to_ip), namestr(&n->name), n->num_msgs));

	  if (n->cmd_type == CHECK_MASTER)
	    {
	      /* if no response received, the master browser must have gone */
	      if (n->num_msgs == 0)
		browser_gone(n->name.name, n->to_ip);
	    }
	  
	  nextn = n->next;
	  
	  if (n->prev) n->prev->next = n->next;
	  if (n->next) n->next->prev = n->prev;
	  
	  if (nameresponselist == n) nameresponselist = n->next; 
	  
	  free(n);
	}
      else
	{
	  nextn = n->next;
	}
    }
}


/****************************************************************************
  reply to a netbios name packet 
  ****************************************************************************/
void reply_netbios_packet(struct packet_struct *p1,int trn_id,int rcode,int opcode,
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
  nmb->header.nm_flags.recursion_available = True;
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
  initiate a netbios packet
  ****************************************************************************/
uint16 initiate_netbios_packet(int fd,int quest_type,char *name,int name_type,
			       int nb_flags,BOOL bcast,BOOL recurse,
			       struct in_addr to_ip)
{
  struct packet_struct p;
  struct nmb_packet *nmb = &p.packet.nmb;
  struct res_rec additional_rec;
  char *packet_type = "unknown";
  int opcode = -1;

  if (quest_type == NMB_STATUS) { packet_type = "nmb_status"; opcode = 0; }
  if (quest_type == NMB_QUERY ) { packet_type = "nmb_query"; opcode = 0; }
  if (quest_type == NMB_REG   ) { packet_type = "nmb_reg"; opcode = 5; }
  if (quest_type == NMB_REL   ) { packet_type = "nmb_rel"; opcode = 6; }
  
  DEBUG(4,("initiating netbios packet: %s %s(%x) (bcast=%s) %s\n",
	   packet_type, name, name_type, BOOLSTR(bcast), inet_ntoa(to_ip)));

  if (opcode == -1) return False;

  bzero((char *)&p,sizeof(p));

  if (!name_trn_id) name_trn_id = (time(NULL)%(unsigned)0x7FFF) + 
    (getpid()%(unsigned)100);
  name_trn_id = (name_trn_id+1) % (unsigned)0x7FFF;

  nmb->header.name_trn_id = name_trn_id;
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
  
  if (!send_packet(&p)) 
    return(0);
  
  return(name_trn_id);
}


/****************************************************************************
  wrapper function to override a broadcast message and send it to the WINS
  name server instead, if it exists. if wins is false, and there has been no
  WINS server specified, the packet will NOT be sent.
  ****************************************************************************/
void queue_netbios_pkt_wins(int fd,int quest_type,enum cmd_type cmd,
			    char *name,int name_type,int nb_flags,
			    BOOL bcast,BOOL recurse,struct in_addr to_ip)
{
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

  queue_netbios_packet(fd, quest_type, cmd, 
		       name, name_type, nb_flags,
		       bcast, recurse, to_ip);
}

/****************************************************************************
  create a name query response record
  **************************************************************************/
static struct name_response_record *make_name_query_record(
							   enum cmd_type cmd,int id,int fd,
							   char *name,int type,
							   BOOL bcast,BOOL recurse,
							   struct in_addr ip)
{
  struct name_response_record *n;
	
  if (!name || !name[0]) return NULL;
	
  if (!(n = (struct name_response_record *)malloc(sizeof(*n)))) 
    return(NULL);

  n->response_id = id;
  n->cmd_type = cmd;
  n->fd = fd;
  make_nmb_name(&n->name, name, type, scope);
  n->bcast = bcast;
  n->recurse = recurse;
  n->to_ip = ip;
  n->start_time = time(NULL);
  n->num_msgs = 0;

  return n;
}


/****************************************************************************
  initiate a netbios name query to find someone's or someones' IP
  this is intended to be used (not exclusively) for broadcasting to
  master browsers (WORKGROUP(1d or 1b) or __MSBROWSE__(1)) to get
  complete lists across a wide area network
  ****************************************************************************/
void queue_netbios_packet(int fd,int quest_type,enum cmd_type cmd,char *name,
			  int name_type,int nb_flags,BOOL bcast,BOOL recurse,
			  struct in_addr to_ip)
{
  uint16 id = initiate_netbios_packet(fd, quest_type, name, name_type,
				      nb_flags, bcast, recurse, to_ip);
  struct name_response_record *n;

  if (id == 0) return;
  
  if ((n = 
       make_name_query_record(cmd,id,fd,name,name_type,bcast,recurse,to_ip)))
    {
      add_response_record(n);
    }
}


/****************************************************************************
  find a response in the name query response list
  **************************************************************************/
struct name_response_record *find_name_query(uint16 id)
{   
  struct name_response_record *n;

  for (n = nameresponselist; n; n = n->next)
    {
      if (n->response_id == id)	{
	return n;
      }
    }

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

  /* during elections we need to send election packets at one
     second intervals */

  timeout.tv_sec = run_election ? 1 : NMBD_SELECT_LOOP;
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
BOOL interpret_node_status(char *p, struct nmb_name *name,int t,
			   char *serv_name, struct in_addr ip)
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
	  add_netbios_entry(qname,type,nb_flags,2*60*60,src,nameip,True);
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
  char *ptr,*p2;
  char tmp[4];

  bzero((char *)&p,sizeof(p));

  dgram->header.msg_type = 0x11; /* DIRECT GROUP DATAGRAM */
  dgram->header.flags.node_type = M_NODE;
  dgram->header.flags.first = True;
  dgram->header.flags.more = False;
  dgram->header.dgm_id = name_trn_id++;
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


