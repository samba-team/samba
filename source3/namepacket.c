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

extern int ClientNMB;
extern int ClientDGRAM;

extern int DEBUGLEVEL;

extern int num_response_packets;

BOOL CanRecurse = True;
extern pstring scope;
extern struct in_addr ipgrp;

static uint16 name_trn_id=0;


/***************************************************************************
  updates the unique transaction identifier
  **************************************************************************/
void debug_browse_data(char *outbuf, int len)
{
    int i,j;
    for (i = 0; i < len; i+= 16)
      {
	DEBUG(4, ("%3x char ", i));
	
	for (j = 0; j < 16; j++)
	  {
	    unsigned char x = outbuf[i+j];
	    if (x < 32 || x > 127) x = '.';
	    
	    if (i+j >= len) break;
	    DEBUG(4, ("%c", x));
	  }
	
	DEBUG(4, (" hex ", i));
	
	for (j = 0; j < 16; j++)
	  {
	    if (i+j >= len) break;
	    DEBUG(4, (" %02x", outbuf[i+j]));
	  }
	
	DEBUG(4, ("\n"));
      }
    
}


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


/****************************************************************************
  initiate a netbios packet
  ****************************************************************************/
void initiate_netbios_packet(uint16 *id,
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
  if (quest_type == NMB_REG_REFRESH ) { packet_type = "nmb_reg_refresh"; opcode = 9; }
  if (quest_type == NMB_REL   ) { packet_type = "nmb_rel"; opcode = 6; }
  
  DEBUG(4,("initiating netbios packet: %s %s(%x) (bcast=%s) %s\n",
	   packet_type, name, name_type, BOOLSTR(bcast), inet_ntoa(to_ip)));

  if (opcode == -1) return;

  bzero((char *)&p,sizeof(p));

  if (*id == 0xffff) {
    update_name_trn_id();
    *id = name_trn_id; /* allow resending with same id */
  }

  nmb->header.name_trn_id = *id;
  nmb->header.opcode = opcode;
  nmb->header.response = False;

  nmb->header.nm_flags.bcast = bcast;
  nmb->header.nm_flags.recursion_available = False;
  nmb->header.nm_flags.recursion_desired = recurse;
  nmb->header.nm_flags.trunc = False;
  nmb->header.nm_flags.authoritative = False;

  nmb->header.rcode = 0;
  nmb->header.qdcount = 1;
  nmb->header.ancount = 0;
  nmb->header.nscount = 0;
  nmb->header.arcount = (quest_type==NMB_REG || 
			 quest_type==NMB_REL ||
			 quest_type==NMB_REG_REFRESH) ? 1 : 0;
  
  make_nmb_name(&nmb->question.question_name,name,name_type,scope);
  
  nmb->question.question_type = quest_type;
  nmb->question.question_class = 0x1;
  
  if (quest_type == NMB_REG ||
      quest_type == NMB_REG_REFRESH ||
      quest_type == NMB_REL)
    {
      nmb->additional = &additional_rec;
      bzero((char *)nmb->additional,sizeof(*nmb->additional));
      
      nmb->additional->rr_name  = nmb->question.question_name;
      nmb->additional->rr_type  = nmb->question.question_type;
      nmb->additional->rr_class = nmb->question.question_class;
      
      if (quest_type == NMB_REG || quest_type == NMB_REG_REFRESH)
	nmb->additional->ttl = lp_max_ttl();
      else
	nmb->additional->ttl = 0;
      nmb->additional->rdlength = 6;
      nmb->additional->rdata[0] = nb_flags;
      putip(&nmb->additional->rdata[2],(char *)iface_ip(to_ip));
    }
  
  p.ip = to_ip;
  p.port = NMB_PORT;
  p.fd = fd;
  p.timestamp = time(NULL);
  p.packet_type = NMB_PACKET;
  
  if (!send_packet(&p)) {
    DEBUG(3,("send_packet to %s %d failed\n",inet_ntoa(p.ip),p.port));
    *id = 0xffff;
  }
  
  return;
}


/****************************************************************************
  reply to a netbios name packet 
  ****************************************************************************/
void reply_netbios_packet(struct packet_struct *p1,int trn_id,
				int rcode, int rcv_code, int opcode, BOOL recurse,
				struct nmb_name *rr_name,int rr_type,int rr_class,int ttl,
				char *data,int len)
{
  struct packet_struct p;
  struct nmb_packet *nmb = &p.packet.nmb;
  struct res_rec answers;
  char *packet_type = "unknown";
  BOOL recursion_desired = False;
  
  p = *p1;

  switch (rcv_code)
  {
    case NMB_STATUS:
	{
      packet_type = "nmb_status";
      recursion_desired = True;
      break;
    }
    case NMB_QUERY:
	{
      packet_type = "nmb_query";
      recursion_desired = True;
      break;
    }
    case NMB_REG:
	{
      packet_type = "nmb_reg";
      recursion_desired = True;
      break;
    }
    case NMB_REL:
	{
      packet_type = "nmb_rel";
      recursion_desired = False;
      break;
    }
    case NMB_WAIT_ACK:
	{
      packet_type = "nmb_wack";
      recursion_desired = False;
      break;
    }
    default:
    {
      DEBUG(1,("replying netbios packet: %s %s\n",
	            packet_type, namestr(rr_name), inet_ntoa(p.ip)));

      return;
    }
  }

  DEBUG(4,("replying netbios packet: %s %s\n",
	   packet_type, namestr(rr_name), inet_ntoa(p.ip)));

  nmb->header.name_trn_id = trn_id;
  nmb->header.opcode = opcode;
  nmb->header.response = True;
  nmb->header.nm_flags.bcast = False;
  nmb->header.nm_flags.recursion_available = recurse;
  nmb->header.nm_flags.recursion_desired = recursion_desired;
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

/****************************************************************************
  determine if a packet is for us. Note that to have any chance of
  being efficient we need to drop as many packets as possible at this
  stage as subsequent processing is expensive. 

  We also must make absolutely sure we don't tread on another machines
  property by answering a packet that is not for us.
  ****************************************************************************/
static BOOL listening(struct packet_struct *p,struct nmb_name *n)
{
  struct subnet_record *d;
  struct name_record *n1;

  d = find_subnet(p->ip);
  
  n1 = find_name_search(&d,n,FIND_LOCAL|FIND_WINS|FIND_SELF,p->ip);

  return (n1 != NULL);
}


/****************************************************************************
  process udp 138 datagrams
  ****************************************************************************/
static void process_dgram(struct packet_struct *p)
{
  char *buf;
  char *buf2;
  int len;
  struct dgram_packet *dgram = &p->packet.dgram;

  /* if we aren't listening to the destination name then ignore the packet */
  if (!listening(p,&dgram->dest_name))
    return;


  if (dgram->header.msg_type != 0x10 &&
      dgram->header.msg_type != 0x11 &&
      dgram->header.msg_type != 0x12) {
    /* don't process error packets etc yet */
    return;
  }

  buf = &dgram->data[0];
  buf -= 4; /* XXXX for the pseudo tcp length - 
	       someday I need to get rid of this */

  if (CVAL(buf,smb_com) != SMBtrans) return;

  len = SVAL(buf,smb_vwv11);
  buf2 = smb_base(buf) + SVAL(buf,smb_vwv12);

  DEBUG(4,("datagram from %s to %s for %s of type %d len=%d\n",
	   namestr(&dgram->source_name),namestr(&dgram->dest_name),
	   smb_buf(buf),CVAL(buf2,0),len));

 
  if (len <= 0) return;

   /* datagram packet received for the browser mailslot */
   if (strequal(smb_buf(buf),BROWSE_MAILSLOT)) {
     process_browse_packet(p,buf2,len);
     return;
   }

   /* datagram packet received for the domain log on mailslot */
   if (strequal(smb_buf(buf),NET_LOGON_MAILSLOT)) {
     process_logon_packet(p,buf2,len);
     return;
   }
}

/****************************************************************************
  process a nmb packet
  ****************************************************************************/
static void process_nmb(struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;

  debug_nmb_packet(p);

  switch (nmb->header.opcode) 
  {
    case 8: /* what is this?? */
    case NMB_REG:
    case NMB_REG_REFRESH:
    {
	if (nmb->header.qdcount==0 || nmb->header.arcount==0) break;
	if (nmb->header.response)
	  response_netbios_packet(p); /* response to registration dealt 
					 with here */
	else
	  reply_name_reg(p);
	break;
    }
      
    case 0:
    {
	  if (nmb->header.response)
	  {
	    switch (nmb->question.question_type)
	      {
	      case 0x0:
		{
		  response_netbios_packet(p);
		  break;
		}
	      }
	    return;
	  }
      else if (nmb->header.qdcount>0) 
	  {
	    switch (nmb->question.question_type)
	      {
	      case NMB_QUERY:
		{
		  reply_name_query(p);
		  break;
		}
	      case NMB_STATUS:
		{
		  reply_name_status(p);
		  break;
		}
	      }
	    return;
	  }
	break;
      }
      
    case NMB_REL:
    {
      if (nmb->header.qdcount==0 || nmb->header.arcount==0)
	  {
	    DEBUG(2,("netbios release packet rejected\n"));
	    break;
	  }
	
	if (nmb->header.response)
	  response_netbios_packet(p); /* response to reply dealt with 
					 in here */
	else
	  reply_name_release(p);
      break;
    }
  }
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

try_again:

  FD_ZERO(&fds);
  FD_SET(ClientNMB,&fds);
  FD_SET(ClientDGRAM,&fds);

  /* during elections and when expecting a netbios response packet we
     need to send election packets at tighter intervals 

     ideally it needs to be the interval (in ms) between time now and
     the time we are expecting the next netbios packet */

  timeout.tv_sec = (run_election||num_response_packets) ? 1 : NMBD_SELECT_LOOP;
  timeout.tv_usec = 0;

  selrtn = sys_select(&fds,&timeout);

  if (FD_ISSET(ClientNMB,&fds))
    {
      struct packet_struct *packet = read_packet(ClientNMB, NMB_PACKET);
      if (packet) {
	if (ismyip(packet->ip) &&
	    (packet->port == NMB_PORT || packet->port == DGRAM_PORT)) {
	  DEBUG(7,("discarding own packet from %s:%d\n",
		   inet_ntoa(packet->ip),packet->port));	  
	  free_packet(packet);
	  goto try_again;
	} else {
	  queue_packet(packet);
	}
      }
    }

  if (FD_ISSET(ClientDGRAM,&fds))
    {
      struct packet_struct *packet = read_packet(ClientDGRAM, DGRAM_PACKET);
      if (packet) {
	if (ismyip(packet->ip) &&
	      (packet->port == NMB_PORT || packet->port == DGRAM_PORT)) {
	  DEBUG(7,("discarding own packet from %s:%d\n",
		   inet_ntoa(packet->ip),packet->port));	  
	  free_packet(packet);
	  goto try_again;
	} else {
	  queue_packet(packet);
	}
      }
    }
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

  DEBUG(4,("send mailslot %s from %s %s", mailslot,
                    inet_ntoa(src_ip),namestr(&dgram->source_name)));
  DEBUG(4,("to %s %s\n", inet_ntoa(dest_ip),namestr(&dgram->dest_name)));

  return(send_packet(&p));
}
