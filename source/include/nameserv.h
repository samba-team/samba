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

#define GET_TTL(ttl) ((ttl)?MIN(ttl,lp_max_ttl()):lp_max_ttl())

/* NTAS uses 2, NT uses 1, WfWg uses 0 */
#define MAINTAIN_LIST    2
#define ELECTION_VERSION 1

#define MAX_DGRAM_SIZE (576) /* tcp/ip datagram limit is 576 bytes */
#define MIN_DGRAM_SIZE 12

#define NMB_QUERY  0x20
#define NMB_STATUS 0x21

#define NMB_REG         0x05 /* see rfc1002.txt 4.2.2,3,5,6,7,8 */
#define NMB_REG_REFRESH 0x09 /* see rfc1002.txt 4.2.4 */
#define NMB_REL         0x06 /* see rfc1002.txt 4.2.9,10,11 */
#define NMB_WAIT_ACK    0x07 /* see rfc1002.txt 4.2.16 */
/* XXXX what about all the other types?? 0x1, 0x2, 0x3, 0x4, 0x8? */

#define FIND_SELF  0x01
#define FIND_WINS  0x02
#define FIND_LOCAL 0x04

/* NetBIOS flags */
#define NB_GROUP  0x80
#define NB_PERM   0x02
#define NB_ACTIVE 0x04
#define NB_CONFL  0x08
#define NB_DEREG  0x10
#define NB_BFLAG  0x00 /* broadcast node type */
#define NB_PFLAG  0x20 /* point-to-point node type */
#define NB_MFLAG  0x40 /* mixed bcast & p-p node type */
#define NB_HFLAG  0x60 /* microsoft 'hybrid' node type */
#define NB_FLGMSK 0x60

#define REFRESH_TIME (15*60)
#define NAME_POLL_REFRESH_TIME (5*60)
#define NAME_POLL_INTERVAL 15

/* NetBIOS flag identifier */
#define NAME_PERMANENT(p) ((p) & NB_PERM)
#define NAME_ACTIVE(p)    ((p) & NB_ACTIVE)
#define NAME_CONFLICT(p)  ((p) & NB_CONFL)
#define NAME_DEREG(p)     ((p) & NB_DEREG)
#define NAME_GROUP(p)     ((p) & NB_GROUP)

#define NAME_BFLAG(p)     (((p) & NB_FLGMSK) == NB_BFLAG)
#define NAME_PFLAG(p)     (((p) & NB_FLGMSK) == NB_PFLAG)
#define NAME_MFLAG(p)     (((p) & NB_FLGMSK) == NB_MFLAG)
#define NAME_HFLAG(p)     (((p) & NB_FLGMSK) == NB_HFLAG)

/* server type identifiers */
#define AM_MASTER(work) (work->ServerType & SV_TYPE_MASTER_BROWSER)
#define AM_BACKUP(work) (work->ServerType & SV_TYPE_BACKUP_BROWSER)
#define AM_DOMCTL(work) (work->ServerType & SV_TYPE_DOMAIN_CTRL)

/* microsoft browser NetBIOS name */
#define MSBROWSE "\001\002__MSBROWSE__\002"

/* mail slots */
#define BROWSE_MAILSLOT    "\\MAILSLOT\\BROWSE"
#define NET_LOGON_MAILSLOT "\\MAILSLOT\\NET\\NETLOGON"

enum name_source {STATUS_QUERY, LMHOSTS, REGISTER, SELF, DNS, DNSFAIL};
enum node_type {B_NODE=0, P_NODE=1, M_NODE=2, NBDD_NODE=3};
enum packet_type {NMB_PACKET, DGRAM_PACKET};
enum master_state
{
   MST_NONE,
   MST_WON,
   MST_MSB,
   MST_BROWSER,
   MST_DOMAIN_NONE,
   MST_DOMAIN_MEM,
   MST_DOMAIN_TST,
   MST_DOMAIN
};

enum state_type
{
	NAME_STATUS_DOM_SRV_CHK,
	NAME_STATUS_SRV_CHK,
	NAME_REGISTER_CHALLENGE,
	NAME_REGISTER,
	NAME_RELEASE,
	NAME_QUERY_CONFIRM,
	NAME_QUERY_ANNOUNCE_HOST,
	NAME_QUERY_SYNC_LOCAL,
	NAME_QUERY_SYNC_REMOTE,
	NAME_QUERY_DOM_SRV_CHK,
	NAME_QUERY_SRV_CHK,
	NAME_QUERY_FIND_MST,
	NAME_QUERY_MST_CHK
};

/* a netbios name structure */
struct nmb_name {
  char name[17];
  char scope[64];
  int name_type;
};

/* a netbios flags + ip address structure */
/* this is used for multi-homed systems and for internet group names */
struct nmb_ip
{
  struct in_addr ip; /* ip address of host that owns this name */
  uint16 nb_flags;      /* netbios flags */
};

/* this is the structure used for the local netbios name list */
struct name_record
{
  struct name_record *next;
  struct name_record *prev;

  struct nmb_name name;    /* the netbios name */
  struct nmb_ip *ip_flgs;  /* the ip + flags */
  int num_ips;             /* number of ip+flags entries */

  enum name_source source; /* where the name came from */

  time_t death_time; /* time record must be removed (do not remove if 0) */
  time_t refresh_time; /* time record should be refreshed */
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
	BOOL local;
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

  /* stage of development from non-master to master browser / domain master */
  enum master_state state;

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

/* initiated name queries recorded in this list to track any responses... */
/* sadly, we need to group everything together. i suppose that if this
   gets unwieldy, then a union ought to be considered. oh for c++... */
struct response_record
{
  struct response_record *next;
  struct response_record *prev;

  uint16 response_id;
  enum state_type state;

  int fd;
  int quest_type;
  struct nmb_name name;
  int nb_flags;
  time_t ttl;

  int server_type;
  fstring my_name;
  fstring my_comment;

  BOOL bcast;
  BOOL recurse;
  struct in_addr send_ip;
  struct in_addr reply_to_ip;

  int num_msgs;

  time_t repeat_time;
  time_t repeat_interval;
  int    repeat_count;
};

/* a subnet structure. it contains a list of workgroups and netbios names*/

/* note that a subnet of 255.255.255.255 contains all the WINS netbios names.
   all communication from such nodes are on a non-broadcast basis: they
   are point-to-point (P nodes) or mixed point-to-point and broadcast
   (M nodes). M nodes use point-to-point as a preference, and will use
   broadcasting for certain activities, or will resort to broadcasting as a
   last resort, if the WINS server fails (users of wfwg will notice that their
   machine often freezes for 30 seconds at a time intermittently, if the WINS
   server is down).

   B nodes will have their own, totally separate subnet record, with their
   own netbios name set. these do NOT interact with other subnet records'
   netbios names, INCLUDING the WINS one (with an ip "address", so called,
   of 255.255.255.255)

   there is a separate response list for each subnet record. in the case of
   the 255.255.255.255 subnet record (WINS), the WINS server will be able to
   use this to poll (infrequently!) each of its entries, to ensure that the
   names are still in use.
   XXXX this polling is a planned feature for a really over-cautious WINS server 
*/

struct subnet_record
{
  struct subnet_record *next;
  struct subnet_record *prev;

  struct work_record *workgrouplist; /* list of workgroups */
  struct name_record *namelist;      /* list of netbios names */
  struct response_record *responselist; /* list of responses expected */

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


/* ids for netbios packet types */
#define ANN_HostAnnouncement         1
#define ANN_AnnouncementRequest      2
#define ANN_Election                 8
#define ANN_GetBackupListReq         9
#define ANN_GetBackupListResp       10
#define ANN_BecomeBackup            11
#define ANN_DomainAnnouncement      12
#define ANN_MasterAnnouncement      13
#define ANN_ResetBrowserState       14
#define ANN_LocalMasterAnnouncement 15


/* broadcast packet announcement intervals, in minutes */

/* search for master browsers of workgroups samba knows about, 
   except default */
#define CHECK_TIME_MST_BROWSE       5 

/* request backup browser announcements from other servers */
#define CHECK_TIME_ANNOUNCE_BACKUP 15

/* request host announcements from other servers: min and max of interval */
#define CHECK_TIME_MIN_HOST_ANNCE   3
#define CHECK_TIME_MAX_HOST_ANNCE  12

/* announce as master to WINS server and any Primary Domain Controllers */
#define CHECK_TIME_MST_ANNOUNCE    15

/* do all remote announcements this often */
#define REMOTE_ANNOUNCE_INTERVAL 180

#define DFLT_SERVER_TYPE (SV_TYPE_WORKSTATION | SV_TYPE_SERVER | \
			  SV_TYPE_TIME_SOURCE | SV_TYPE_SERVER_UNIX | \
			  SV_TYPE_PRINTQ_SERVER | SV_TYPE_SERVER_NT | \
			  SV_TYPE_NT)

