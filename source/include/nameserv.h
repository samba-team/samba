/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NBT netbios header - version 2
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

#define MAX_DGRAM_SIZE 576
#define MIN_DGRAM_SIZE 12

#define NMB_PORT 137
#define DGRAM_PORT 138
#define SMB_PORT 139

enum name_source {LMHOSTS, REGISTER, SELF, DNS, DNSFAIL};
enum node_type {B_NODE=0, P_NODE=1, M_NODE=2, NBDD_NODE=3};
enum packet_type {NMB_PACKET, DGRAM_PACKET};

/* a netbios name structure */
struct nmb_name {
  char name[17];
  char scope[64];
  int name_type;
};

/* this is the structure used for the local netbios name list */
struct name_record
{
  struct name_record *next;
  struct name_record *prev;
  struct nmb_name name;
  time_t death_time;
  struct in_addr ip;
  BOOL unique;
  enum name_source source;
};

/* this is used by the list of domains */
struct domain_record
{
  struct domain_record *next;
  struct domain_record *prev;
  fstring name;
  time_t lastannounce_time;
  int announce_interval;
  struct in_addr bcast_ip;
};

/* this is used to hold the list of servers in my domain */
struct server_record
{
  struct server_record *next;
  struct server_record *prev;
  fstring name;
  fstring comment;
  uint32 servertype;
  time_t death_time;  
};

/* a resource record */
struct res_rec {
  struct nmb_name rr_name;
  int rr_type;
  int rr_class;
  int ttl;
  int rdlength;
  char rdata[MAX_DGRAM_SIZE];
};

/* define a nmb packet. */
struct nmb_packet
{
  struct {
    int name_trn_id;
    int opcode;
    BOOL response;
    struct {
      BOOL bcast;
      BOOL recursion_available;
      BOOL recursion_desired;
      BOOL trunc;
      BOOL authoritative;
    } nm_flags;
    int rcode;
    int qdcount;
    int ancount;
    int nscount;
    int arcount;
  } header;

  struct {
    struct nmb_name question_name;
    int question_type;
    int question_class;
  } question;

  struct res_rec *answers;
  struct res_rec *nsrecs;
  struct res_rec *additional;
};


/* a datagram - this normally contains SMB data in the data[] array */
struct dgram_packet {
  struct {
    int msg_type;
    struct {
      enum node_type node_type;
      BOOL first;
      BOOL more;
    } flags;
    int dgm_id;
    struct in_addr source_ip;
    int source_port;
    int dgm_length;
    int packet_offset;
  } header;
  struct nmb_name source_name;
  struct nmb_name dest_name;
  int datasize;
  char data[MAX_DGRAM_SIZE];
};

/* define a structure used to queue packets. this will be a linked
 list of nmb packets */
struct packet_struct
{
  struct packet_struct *next;
  struct packet_struct *prev;
  struct in_addr ip;
  int port;
  int fd;
  time_t timestamp;
  enum packet_type packet_type;
  union {
    struct nmb_packet nmb;
    struct dgram_packet dgram;
  } packet;
};


/* this defines a list of network interfaces */
struct net_interface {
  struct net_interface *next;
  struct in_addr ip;
  struct in_addr bcast;
  struct in_addr netmask;
};


/* prototypes */
void free_nmb_packet(struct nmb_packet *nmb);
void free_packet(struct packet_struct *packet);
struct packet_struct *read_packet(int fd,enum packet_type packet_type);
BOOL send_packet(struct packet_struct *p);
struct packet_struct *receive_packet(int fd,enum packet_type type,int timeout);
void make_nmb_name(struct nmb_name *n,char *name,int type,char *this_scope);
BOOL name_query(int fd,char *name,int name_type,
		       BOOL bcast,BOOL recurse,
		       struct in_addr to_ip, struct in_addr *ip,void (*fn)());
BOOL name_status(int fd,char *name,int name_type,BOOL recurse,
		 struct in_addr to_ip,char *master,char *rname,
		 void (*fn)());
BOOL send_mailslot_reply(char *mailslot,int fd,char *buf,int len,
			 char *srcname,char *dstname,
			 int src_type,int dest_type,
			 struct in_addr dest_ip,
			 struct in_addr src_ip);
char *namestr(struct nmb_name *n);
