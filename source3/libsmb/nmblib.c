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
#include "nameserv.h"

extern int DEBUGLEVEL;

int num_good_sends=0;
int  num_good_receives=0;
static uint16 name_trn_id = 0;
BOOL CanRecurse = True;
extern pstring scope;

/*******************************************************************
  handle "compressed" name pointers
  ******************************************************************/
static BOOL handle_name_ptrs(unsigned char *ubuf,int *offset,int length,
			     BOOL *got_pointer,int *ret)
{
  int loop_count=0;

  while ((ubuf[*offset] & 0xC0) == 0xC0) {
    if (!*got_pointer) (*ret) += 2;
    (*got_pointer)=True;
    (*offset) = ((ubuf[*offset] & ~0xC0)<<8) | ubuf[(*offset)+1];
    if (loop_count++ == 10 || (*offset) < 0 || (*offset)>(length-2)) {
      return(False);
    }
  }
  return(True);
}

/*******************************************************************
  parse a nmb name from "compressed" format to something readable
  return the space taken by the name, or 0 if the name is invalid
  ******************************************************************/
static int parse_nmb_name(char *inbuf,int offset,int length,
			  struct nmb_name *name)
{
  int m,n=0;
  unsigned char *ubuf = (unsigned char *)inbuf;
  int ret = 0;
  BOOL got_pointer=False;

  if (length - offset < 2) return(0);  

  /* handle initial name pointers */
  if (!handle_name_ptrs(ubuf,&offset,length,&got_pointer,&ret)) return(0);
  
  m = ubuf[offset];

  if (!m) return(0);
  if ((m & 0xC0) || offset+m+2 > length) return(0);

  bzero((char *)name,sizeof(*name));

  /* the "compressed" part */
  if (!got_pointer) ret += m + 2;
  offset++;
  while (m) {
    unsigned char c1,c2;
    c1 = ubuf[offset++]-'A';
    c2 = ubuf[offset++]-'A';
    if ((c1 & 0xF0) || (c2 & 0xF0)) return(0);
    name->name[n++] = (c1<<4) | c2;
    m -= 2;
  }
  name->name[n] = 0;

  if (n==16) {
    /* parse out the name type, 
       its always in the 16th byte of the name */
    name->name_type = name->name[15];
  
    /* remove trailing spaces */
    name->name[15] = 0;
    n = 14;
    while (n && name->name[n]==' ') name->name[n--] = 0;  
  }

  /* now the domain parts (if any) */
  n = 0;
  while ((m=ubuf[offset])) {
    /* we can have pointers within the domain part as well */
    if (!handle_name_ptrs(ubuf,&offset,length,&got_pointer,&ret)) return(0);

    if (!got_pointer) ret += m+1;
    if (n) name->scope[n++] = '.';
    if (m+2+offset>length || n+m+1>sizeof(name->scope)) return(0);
    offset++;
    while (m--) name->scope[n++] = (char)ubuf[offset++];
  }
  name->scope[n++] = 0;  

  return(ret);
}


/*******************************************************************
  put a compressed nmb name into a buffer. return the length of the
  compressed name

  compressed names are really weird. The "compression" doubles the
  size. The idea is that it also means that compressed names conform
  to the doman name system. See RFC1002.
  ******************************************************************/
static int put_nmb_name(char *buf,int offset,struct nmb_name *name)
{
  int ret,m;
  fstring buf1;
  char *p;

  if (name->name[0] == '*') {
    /* special case for wildcard name */
    bzero(buf1,20);
    buf1[0] = '*';
  } else {
    sprintf(buf1,"%-15.15s%c",name->name,name->name_type);
  }

  buf[offset] = 0x20;

  ret = 34;

  for (m=0;m<16;m++) {
    buf[offset+1+2*m] = 'A' + ((buf1[m]>>4)&0xF);
    buf[offset+2+2*m] = 'A' + (buf1[m]&0xF);
  }
  offset += 33;

  buf[offset] = 0;

  if (name->scope[0]) {
    /* XXXX this scope handling needs testing */
    ret += strlen(name->scope) + 1;
    strcpy(&buf[offset+1],name->scope);  
  
    p = &buf[offset+1];
    while ((p = strchr(p,'.'))) {
      buf[offset] = PTR_DIFF(p,&buf[offset]);
      offset += buf[offset];
      p = &buf[offset+1];
    }
    buf[offset] = strlen(&buf[offset+1]);
  }

  return(ret);
}

/*******************************************************************
  useful for debugging messages
  ******************************************************************/
char *namestr(struct nmb_name *n)
{
  static int i=0;
  static fstring ret[4];
  char *p = ret[i];

  if (!n->scope[0])
    sprintf(p,"%s(%x)",n->name,n->name_type);
  else
    sprintf(p,"%s(%x).%s",n->name,n->name_type,n->scope);

  i = (i+1)%4;
  return(p);
}

/*******************************************************************
  allocate are parse some resource records
  ******************************************************************/
static BOOL parse_alloc_res_rec(char *inbuf,int *offset,int length,
				struct res_rec **recs,
				int count)
{
  int i;
  *recs = (struct res_rec *)malloc(sizeof(**recs)*count);
  if (!*recs) return(False);

  bzero(*recs,sizeof(**recs)*count);

  for (i=0;i<count;i++) {
    int l = parse_nmb_name(inbuf,*offset,length,&(*recs)[i].rr_name);
    (*offset) += l;
    if (!l || (*offset)+10 > length) {
      free(*recs);
      return(False);
    }
    (*recs)[i].rr_type = RSVAL(inbuf,(*offset));
    (*recs)[i].rr_class = RSVAL(inbuf,(*offset)+2);
    (*recs)[i].ttl = RIVAL(inbuf,(*offset)+4);
    (*recs)[i].rdlength = RSVAL(inbuf,(*offset)+8);
    (*offset) += 10;
    if ((*recs)[i].rdlength>sizeof((*recs)[i].rdata) || 
	(*offset)+(*recs)[i].rdlength > length) {
      free(*recs);
      return(False);
    }
    memcpy((*recs)[i].rdata,inbuf+(*offset),(*recs)[i].rdlength);
    (*offset) += (*recs)[i].rdlength;    
  }
  return(True);
}

/*******************************************************************
  put a resource record into a packet
  ******************************************************************/
static int put_res_rec(char *buf,int offset,struct res_rec *recs,int count)
{
  int ret=0;
  int i;

  for (i=0;i<count;i++) {
    int l = put_nmb_name(buf,offset,&recs[i].rr_name);
    offset += l;
    ret += l;
    RSSVAL(buf,offset,recs[i].rr_type);
    RSSVAL(buf,offset+2,recs[i].rr_class);
    RSIVAL(buf,offset+4,recs[i].ttl);
    RSSVAL(buf,offset+8,recs[i].rdlength);
    memcpy(buf+offset+10,recs[i].rdata,recs[i].rdlength);
    offset += 10+recs[i].rdlength;
    ret += 10+recs[i].rdlength;
  }

  return(ret);
}

/*******************************************************************
  parse a dgram packet. Return False if the packet can't be parsed 
  or is invalid for some reason, True otherwise 

  this is documented in section 4.4.1 of RFC1002
  ******************************************************************/
static BOOL parse_dgram(char *inbuf,int length,struct dgram_packet *dgram)
{
  int offset;
  int flags;

  bzero((char *)dgram,sizeof(*dgram));

  if (length < 14) return(False);

  dgram->header.msg_type = CVAL(inbuf,0);
  flags = CVAL(inbuf,1);
  dgram->header.flags.node_type = (enum node_type)((flags>>2)&3);
  if (flags & 1) dgram->header.flags.more = True;
  if (flags & 2) dgram->header.flags.first = True;
  dgram->header.dgm_id = RSVAL(inbuf,2);
  putip((char *)&dgram->header.source_ip,inbuf+4);
  dgram->header.source_port = RSVAL(inbuf,8);
  dgram->header.dgm_length = RSVAL(inbuf,10);
  dgram->header.packet_offset = RSVAL(inbuf,12);

  offset = 14;

  if (dgram->header.msg_type == 0x10 ||
      dgram->header.msg_type == 0x11 ||
      dgram->header.msg_type == 0x12) {      
    offset += parse_nmb_name(inbuf,offset,length,&dgram->source_name);
    offset += parse_nmb_name(inbuf,offset,length,&dgram->dest_name);
  }

  if (offset >= length || (length-offset > sizeof(dgram->data))) 
    return(False);

  dgram->datasize = length-offset;
  memcpy(dgram->data,inbuf+offset,dgram->datasize);

  return(True);
}


/*******************************************************************
  parse a nmb packet. Return False if the packet can't be parsed 
  or is invalid for some reason, True otherwise 
  ******************************************************************/
static BOOL parse_nmb(char *inbuf,int length,struct nmb_packet *nmb)
{
  int nm_flags,offset;

  bzero((char *)nmb,sizeof(*nmb));

  if (length < 12) return(False);

  /* parse the header */
  nmb->header.name_trn_id = RSVAL(inbuf,0);
  nmb->header.opcode = (CVAL(inbuf,2) >> 3) & 0xF;
  nmb->header.response = ((CVAL(inbuf,2)>>7)&1)?True:False;
  nm_flags = ((CVAL(inbuf,2) & 0x7) << 4) + (CVAL(inbuf,3)>>4);
  nmb->header.nm_flags.bcast = (nm_flags&1)?True:False;
  nmb->header.nm_flags.recursion_available = (nm_flags&8)?True:False;
  nmb->header.nm_flags.recursion_desired = (nm_flags&0x10)?True:False;
  nmb->header.nm_flags.trunc = (nm_flags&0x20)?True:False;
  nmb->header.nm_flags.authoritative = (nm_flags&0x40)?True:False;
  nmb->header.rcode = CVAL(inbuf,3) & 0xF;
  nmb->header.qdcount = RSVAL(inbuf,4);
  nmb->header.ancount = RSVAL(inbuf,6);
  nmb->header.nscount = RSVAL(inbuf,8);
  nmb->header.arcount = RSVAL(inbuf,10);
  
  if (nmb->header.qdcount) {
    offset = parse_nmb_name(inbuf,12,length,&nmb->question.question_name);
    if (!offset) return(False);

    if (length - (12+offset) < 4) return(False);
    nmb->question.question_type = RSVAL(inbuf,12+offset);
    nmb->question.question_class = RSVAL(inbuf,12+offset+2);

    offset += 12+4;
  } else {
    offset = 12;
  }

  /* and any resource records */
  if (nmb->header.ancount && 
      !parse_alloc_res_rec(inbuf,&offset,length,&nmb->answers,
			   nmb->header.ancount))
    return(False);

  if (nmb->header.nscount && 
      !parse_alloc_res_rec(inbuf,&offset,length,&nmb->nsrecs,
			   nmb->header.nscount))
    return(False);
  
  if (nmb->header.arcount && 
      !parse_alloc_res_rec(inbuf,&offset,length,&nmb->additional,
			   nmb->header.arcount))
    return(False);

  return(True);
}

/*******************************************************************
  free up any resources associated with an nmb packet
  ******************************************************************/
void free_nmb_packet(struct nmb_packet *nmb)
{  
  if (nmb->answers) free(nmb->answers);
  if (nmb->nsrecs) free(nmb->nsrecs);
  if (nmb->additional) free(nmb->additional);
}

/*******************************************************************
  free up any resources associated with a packet
  ******************************************************************/
void free_packet(struct packet_struct *packet)
{  
  if (packet->packet_type == NMB_PACKET)
    free_nmb_packet(&packet->packet.nmb);
  free(packet);
}

/*******************************************************************
  read a packet from a socket and parse it, returning a packet ready
  to be used or put on the queue. This assumes a UDP socket
  ******************************************************************/
struct packet_struct *read_packet(int fd,enum packet_type packet_type)
{
  extern struct in_addr lastip;
  extern int lastport;
  struct packet_struct *packet;
  char buf[MAX_DGRAM_SIZE];
  int length;
  BOOL ok=False;

  length = read_udp_socket(fd,buf,sizeof(buf));
  if (length < MIN_DGRAM_SIZE) return(NULL);

  packet = (struct packet_struct *)malloc(sizeof(*packet));
  if (!packet) return(NULL);

  packet->next = NULL;
  packet->prev = NULL;
  packet->ip = lastip;
  packet->port = lastport;
  packet->fd = fd;
  packet->timestamp = time(NULL);
  packet->packet_type = packet_type;
  switch (packet_type) 
    {
    case NMB_PACKET:
      ok = parse_nmb(buf,length,&packet->packet.nmb);
      break;

    case DGRAM_PACKET:
      ok = parse_dgram(buf,length,&packet->packet.dgram);
      break;
    }
  if (!ok) {
    free(packet);
    return(NULL);
  }

  num_good_receives++;

  DEBUG(4,("%s received a packet of len %d from (%s) port %d\n",
	   timestring(),length,inet_ntoa(packet->ip),packet->port));

  return(packet);
}
					 

/*******************************************************************
  send a udp packet on a already open socket
  ******************************************************************/
static BOOL send_udp(int fd,char *buf,int len,struct in_addr ip,int port)
{
  BOOL ret;
  struct sockaddr_in sock_out;

  /* set the address and port */
  bzero((char *)&sock_out,sizeof(sock_out));
  putip((char *)&sock_out.sin_addr,(char *)&ip);
  sock_out.sin_port = htons( port );
  sock_out.sin_family = AF_INET;
  
  DEBUG(4,("%s sending a packet of len %d to (%s) on port %d\n",
	   timestring(),len,inet_ntoa(ip),port));
	
  ret = (sendto(fd,buf,len,0,(struct sockaddr *)&sock_out,
		sizeof(sock_out)) >= 0);

  if (!ret)
    DEBUG(0,("Packet send failed to %s(%d) ERRNO=%s\n",
	     inet_ntoa(ip),port,strerror(errno)));

  if (ret)
    num_good_sends++;

  return(ret);
}

/*******************************************************************
  build a dgram packet ready for sending

  XXXX This currently doesn't handle packets too big for one
  datagram. It should split them and use the packet_offset, more and
  first flags to handle the fragmentation. Yuck.
  ******************************************************************/
static int build_dgram(char *buf,struct packet_struct *p)
{
  struct dgram_packet *dgram = &p->packet.dgram;
  unsigned char *ubuf = (unsigned char *)buf;
  int offset=0;

  /* put in the header */
  ubuf[0] = dgram->header.msg_type;
  ubuf[1] = (((int)dgram->header.flags.node_type)<<2);
  if (dgram->header.flags.more) ubuf[1] |= 1;
  if (dgram->header.flags.first) ubuf[1] |= 2;
  RSSVAL(ubuf,2,dgram->header.dgm_id);
  putip(ubuf+4,(char *)&dgram->header.source_ip);
  RSSVAL(ubuf,8,dgram->header.source_port);
  RSSVAL(ubuf,12,dgram->header.packet_offset);

  offset = 14;

  if (dgram->header.msg_type == 0x10 ||
      dgram->header.msg_type == 0x11 ||
      dgram->header.msg_type == 0x12) {      
    offset += put_nmb_name((char *)ubuf,offset,&dgram->source_name);
    offset += put_nmb_name((char *)ubuf,offset,&dgram->dest_name);
  }

  memcpy(ubuf+offset,dgram->data,dgram->datasize);
  offset += dgram->datasize;

  /* automatically set the dgm_length */
  dgram->header.dgm_length = offset;
  RSSVAL(ubuf,10,dgram->header.dgm_length); 

  return(offset);
}

/*******************************************************************
  build a nmb name
  ******************************************************************/
void make_nmb_name(struct nmb_name *n,char *name,int type,char *this_scope)
{
  strcpy(n->name,name);
  strupper(n->name);
  n->name_type = type;
  strcpy(n->scope,this_scope);
}


/*******************************************************************
  build a nmb packet ready for sending

  XXXX this currently relies on not being passed something that expands
  to a packet too big for the buffer. Eventually this should be
  changed to set the trunc bit so the receiver can request the rest
  via tcp (when that becomes supported)
  ******************************************************************/
static int build_nmb(char *buf,struct packet_struct *p)
{
  struct nmb_packet *nmb = &p->packet.nmb;
  unsigned char *ubuf = (unsigned char *)buf;
  int offset=0;

  /* put in the header */
  RSSVAL(ubuf,offset,nmb->header.name_trn_id);
  ubuf[offset+2] = (nmb->header.opcode & 0xF) << 3;
  if (nmb->header.response) ubuf[offset+2] |= (1<<7);
  if (nmb->header.nm_flags.authoritative) ubuf[offset+2] |= 0x4;
  if (nmb->header.nm_flags.trunc) ubuf[offset+2] |= 0x2;
  if (nmb->header.nm_flags.recursion_desired) ubuf[offset+2] |= 0x1;
  if (nmb->header.nm_flags.recursion_available) ubuf[offset+3] |= 0x80;
  if (nmb->header.nm_flags.bcast) ubuf[offset+3] |= 0x10;
  ubuf[offset+3] |= (nmb->header.rcode & 0xF);
  RSSVAL(ubuf,offset+4,nmb->header.qdcount);
  RSSVAL(ubuf,offset+6,nmb->header.ancount);
  RSSVAL(ubuf,offset+8,nmb->header.nscount);
  RSSVAL(ubuf,offset+10,nmb->header.arcount);
  
  offset += 12;
  if (nmb->header.qdcount) {
    /* XXXX this doesn't handle a qdcount of > 1 */
    offset += put_nmb_name((char *)ubuf,offset,&nmb->question.question_name);
    RSSVAL(ubuf,offset,nmb->question.question_type);
    RSSVAL(ubuf,offset+2,nmb->question.question_class);
    offset += 4;
  }

  if (nmb->header.ancount)
    offset += put_res_rec((char *)ubuf,offset,nmb->answers,
			  nmb->header.ancount);

  if (nmb->header.nscount)
    offset += put_res_rec((char *)ubuf,offset,nmb->nsrecs,
			  nmb->header.nscount);

  if (nmb->header.arcount)
    offset += put_res_rec((char *)ubuf,offset,nmb->additional,
			  nmb->header.arcount);  

  return(offset);
}


/*******************************************************************
  send a packet_struct
  ******************************************************************/
BOOL send_packet(struct packet_struct *p)
{
  char buf[1024];
  int len=0;

  bzero(buf,sizeof(buf));

  switch (p->packet_type) 
    {
    case NMB_PACKET:
      len = build_nmb(buf,p);
      break;

    case DGRAM_PACKET:
      len = build_dgram(buf,p);
      break;
    }

  if (!len) return(False);

  return(send_udp(p->fd,buf,len,p->ip,p->port));
}

/****************************************************************************
  receive a packet with timeout on a open UDP filedescriptor
  The timeout is in milliseconds
  ***************************************************************************/
struct packet_struct *receive_packet(int fd,enum packet_type type,int t)
{
  fd_set fds;
  struct timeval timeout;

  FD_ZERO(&fds);
  FD_SET(fd,&fds);
  timeout.tv_sec = t/1000;
  timeout.tv_usec = 1000*(t%1000);

  sys_select(&fds,&timeout);

  if (FD_ISSET(fd,&fds)) 
    return(read_packet(fd,type));

  return(NULL);
}


/****************************************************************************
interpret a node status response
****************************************************************************/
static void interpret_node_status(char *p, char *master,char *rname)
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
      if ((p[0] & 0x60) == 0x60) strcat(flags,"_ ");
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

  bzero((char *)&p,sizeof(p));

  if (!name_trn_id) name_trn_id = (time(NULL)%(unsigned)0x7FFF) + 
    (getpid()%(unsigned)100);
  name_trn_id = (name_trn_id+1) % (unsigned)0x7FFF;

  nmb->header.name_trn_id = name_trn_id;
  nmb->header.opcode = 0;
  nmb->header.response = False;
  nmb->header.nm_flags.bcast = False;
  nmb->header.nm_flags.recursion_available = CanRecurse;
  nmb->header.nm_flags.recursion_desired = recurse;
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

	  interpret_node_status(&nmb2->answers->rdata[0], master,rname);
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

  bzero((char *)&p,sizeof(p));

  if (!name_trn_id) name_trn_id = (time(NULL)%(unsigned)0x7FFF) + 
    (getpid()%(unsigned)100);
  name_trn_id = (name_trn_id+1) % (unsigned)0x7FFF;

  nmb->header.name_trn_id = name_trn_id;
  nmb->header.opcode = 0;
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


/****************************************************************************
  construct and send a netbios DGRAM

  Note that this currently sends all answers to port 138. thats the
  wrong things to do! I should send to the requestors port. XXX
  **************************************************************************/
BOOL send_mailslot_reply(char *mailslot,int fd,char *buf,int len,
			 char *srcname,char *dstname,
			 int src_type,int dest_type,
			 struct in_addr dest_ip,
			 struct in_addr src_ip)
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
  p.fd = fd;
  p.timestamp = time(NULL);
  p.packet_type = DGRAM_PACKET;

  return(send_packet(&p));
}


