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

#define MAX_DGRAM_SIZE (80*18+64)
#define MIN_DGRAM_SIZE 12

#define NMB_QUERY  0x20
#define NMB_STATUS 0x21
#define NMB_REG    0x05
#define NMB_REL    0x06

#define NB_GROUP  0x80
#define NB_PERM   0x02
#define NB_ACTIVE 0x04
#define NB_CONFL  0x08
#define NB_DEREG  0x10
#define NB_BFLAG  0x00
#define NB_PFLAG  0x20
#define NB_MFLAG  0x40
#define NB__FLAG  0x60
#define NB_FLGMSK 0x60

#define NAME_PERMANENT(p) ((p) & NB_PERM)
#define NAME_ACTIVE(p)    ((p) & NB_ACTIVE)
#define NAME_CONFLICT(p)  ((p) & NB_CONFL)
#define NAME_DEREG(p)     ((p) & NB_DEREG)
#define NAME_GROUP(p)     ((p) & NB_GROUP)

#define NAME_BFLAG(p)     (((p) & NB_FLGMSK) == NB_BFLAG)
#define NAME_PFLAG(p)     (((p) & NB_FLGMSK) == NB_PFLAG)
#define NAME_MFLAG(p)     (((p) & NB_FLGMSK) == NB_MFLAG)
#define NAME__FLAG(p)     (((p) & NB_FLGMSK) == NB__FLAG)

enum name_source {STATUS_QUERY, LMHOSTS, REGISTER, SELF, DNS, DNSFAIL};
enum node_type {B_NODE=0, P_NODE=1, M_NODE=2, NBDD_NODE=3};
enum packet_type {NMB_PACKET, DGRAM_PACKET};
enum cmd_type
{
	NAME_STATUS_MASTER_CHECK,
	NAME_STATUS_CHECK,
	MASTER_SERVER_CHECK,
	SERVER_CHECK,
	FIND_MASTER,
	CHECK_MASTER,
	NAME_REGISTER,
	NAME_RELEASE,
	NAME_CONFIRM_QUERY
};

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
  int nb_flags;
  enum name_source source;
};

/* browse and backup server cache for synchronising browse list */
struct browse_cache_record
{
	struct browse_cache_record *next;
	struct browse_cache_record *prev;

	pstring name;
	int type;
	pstring group;
	struct in_addr ip;
	time_t sync_time;
	BOOL synced;
};

/* this is used to hold the list of servers in my domain, and is */
/* contained within lists of domains */
struct server_record
{
  struct server_record *next;
  struct server_record *prev;

  struct server_info_struct serv;
  time_t death_time;  
};

/* a workgroup structure. it contains a list of servers */
struct work_record
{
  struct work_record *next;
  struct work_record *prev;

  struct server_record *serverlist;

  /* work group info */
  fstring work_group;
  int     token;        /* used when communicating with backup browsers */
  int     ServerType;

  /* announce info */
  time_t lastannounce_time;
  int announce_interval;
  BOOL    needannounce;

  /* election info */
  BOOL    RunningElection;
  BOOL    needelection;
  int     ElectionCount;
  uint32  ElectionCriterion;
};

/* a domain structure. it contains a list of workgroups */
struct domain_record
{
  struct domain_record *next;
  struct domain_record *prev;

  struct work_record *workgrouplist;

  struct in_addr bcast_ip;
  struct in_addr mask_ip;
  struct in_addr myip;
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


/* initiated name queries recorded in this list to track any responses... */
struct name_response_record
{
  struct name_response_record *next;
  struct name_response_record *prev;

  uint16 response_id;
  enum cmd_type cmd_type;

  int fd;
  struct nmb_name name;
  BOOL bcast;
  BOOL recurse;
  struct in_addr to_ip;

  time_t start_time;
  int num_msgs;
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


