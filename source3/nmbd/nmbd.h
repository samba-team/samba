/*
 *  Unix SMB/CIFS implementation.
 *  NBT netbios routines and daemon - version 2
 *
 *  Copyright (C) Guenther Deschner 2011
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _NMBD_NMBD_H_
#define _NMBD_NMBD_H_

#ifndef HAVE_PIPE
#define SYNC_DNS 1
#endif

#include "libsmb/nmblib.h"

#define INFO_VERSION	"INFO/version"
#define INFO_COUNT	"INFO/num_entries"
#define INFO_ID_HIGH	"INFO/id_high"
#define INFO_ID_LOW	"INFO/id_low"
#define ENTRY_PREFIX 	"ENTRY/"

#define PERMANENT_TTL 0

/* NTAS uses 2, NT uses 1, WfWg uses 0 */
#define MAINTAIN_LIST    2
#define ELECTION_VERSION 1

#define REFRESH_TIME (15*60)
#define NAME_POLL_REFRESH_TIME (5*60)
#define NAME_POLL_INTERVAL 15

/* Workgroup state identifiers. */
#define AM_POTENTIAL_MASTER_BROWSER(work) ((work)->mst_state == MST_POTENTIAL)
#define AM_LOCAL_MASTER_BROWSER(work) ((work)->mst_state == MST_BROWSER)
#define AM_DOMAIN_MASTER_BROWSER(work) ((work)->dom_state == DOMAIN_MST)
#define AM_DOMAIN_MEMBER(work) ((work)->log_state == LOGON_SRV)

/* Microsoft browser NetBIOS name. */
#define MSBROWSE "\001\002__MSBROWSE__\002"

/* Mail slots. */
#define BROWSE_MAILSLOT    "\\MAILSLOT\\BROWSE"
#define NET_LOGON_MAILSLOT "\\MAILSLOT\\NET\\NETLOGON"
#define NT_LOGON_MAILSLOT  "\\MAILSLOT\\NET\\NTLOGON"
#define LANMAN_MAILSLOT    "\\MAILSLOT\\LANMAN"

/* Samba definitions for find_name_on_subnet(). */
#define FIND_ANY_NAME   0
#define FIND_SELF_NAME  1

/*
 * The different name types that can be in namelists.
 *
 * SELF_NAME should only be on the broadcast and unicast subnets.
 * LMHOSTS_NAME should only be in the remote_broadcast_subnet.
 * REGISTER_NAME, DNS_NAME, DNSFAIL_NAME should only be in the wins_server_subnet.
 * WINS_PROXY_NAME should only be on the broadcast subnets.
 * PERMANENT_NAME can be on all subnets except remote_broadcast_subnet.
 *
 */

enum name_source {LMHOSTS_NAME, REGISTER_NAME, SELF_NAME, DNS_NAME,
                  DNSFAIL_NAME, PERMANENT_NAME, WINS_PROXY_NAME};

enum master_state {
	MST_NONE,
	MST_POTENTIAL,
	MST_BACKUP,
	MST_MSB,
	MST_BROWSER,
	MST_UNBECOMING_MASTER
};

enum domain_state {
	DOMAIN_NONE,
	DOMAIN_WAIT,
	DOMAIN_MST
};

enum logon_state {
	LOGON_NONE,
	LOGON_WAIT,
	LOGON_SRV
};

struct subnet_record;

struct nmb_data {
	uint16_t nb_flags;       /* Netbios flags. */
	int num_ips;             /* Number of ip entries. */
	struct in_addr *ip;      /* The ip list for this name. */

	enum name_source source; /* Where the name came from. */

	time_t death_time; /* The time the record must be removed (do not remove if 0). */
	time_t refresh_time; /* The time the record should be refreshed. */

	uint64_t id;		/* unique id */
	struct in_addr wins_ip;	/* the address of the wins server this record comes from */

	int wins_flags;		/* similar to the netbios flags but different ! */
};

/* This structure represents an entry in a local netbios name list. */
struct name_record {
	struct name_record *prev, *next;
	struct subnet_record *subnet;
	struct nmb_name       name;    /* The netbios name. */
	struct nmb_data       data;    /* The netbios data. */
};

/* Browser cache for synchronising browse lists. */
struct browse_cache_record {
	struct browse_cache_record *prev, *next;
	unstring        lmb_name;
	unstring        work_group;
	struct in_addr ip;
	time_t         sync_time;
	time_t         death_time; /* The time the record must be removed. */
};

/* used for server information: client, nameserv and ipc */
struct server_info_struct {
	fstring name;
	uint32_t type;
	fstring comment;
	fstring domain; /* used ONLY in ipc.c NOT namework.c */
	bool server_added; /* used ONLY in ipc.c NOT namework.c */
};

/* This is used to hold the list of servers in my domain, and is
   contained within lists of domains. */

struct server_record {
	struct server_record *next;
	struct server_record *prev;

	struct subnet_record *subnet;

	struct server_info_struct serv;
	time_t death_time;
};

/* A workgroup structure. It contains a list of servers. */
struct work_record {
	struct work_record *next;
	struct work_record *prev;

	struct subnet_record *subnet;

	struct server_record *serverlist;

	/* Stage of development from non-local-master up to local-master browser. */
	enum master_state mst_state;

	/* Stage of development from non-domain-master to domain-master browser. */
	enum domain_state dom_state;

	/* Stage of development from non-logon-server to logon server. */
	enum logon_state log_state;

	/* Work group info. */
	unstring work_group;
	int     token;        /* Used when communicating with backup browsers. */
	unstring local_master_browser_name;      /* Current local master browser. */

	/* Announce info. */
	time_t lastannounce_time;
	int announce_interval;
	bool    needannounce;

	/* Timeout time for this workgroup. 0 means permanent. */
	time_t death_time;

	/* Election info */
	bool    RunningElection;
	bool    needelection;
	int     ElectionCount;
	uint32_t  ElectionCriterion;

	/* Domain master browser info. Used for efficient syncs. */
	struct nmb_name dmb_name;
	struct in_addr dmb_addr;
};

/* typedefs needed to define copy & free functions for userdata. */
struct userdata_struct;

typedef struct userdata_struct * (*userdata_copy_fn)(struct userdata_struct *);
typedef void (*userdata_free_fn)(struct userdata_struct *);

/* Structure to define any userdata passed around. */

struct userdata_struct {
	userdata_copy_fn copy_fn;
	userdata_free_fn free_fn;
	unsigned int userdata_len;
	char data[16]; /* 16 is to ensure alignment/padding on all systems */
};

struct response_record;
struct packet_struct;
struct res_rec;

/* typedef to define the function called when this response packet comes in. */
typedef void (*response_function)(struct subnet_record *, struct response_record *,
                                  struct packet_struct *);

/* typedef to define the function called when this response record times out. */
typedef void (*timeout_response_function)(struct subnet_record *,
                                          struct response_record *);

/* typedef to define the function called when the request that caused this
   response record to be created is successful. */
typedef void (*success_function)(struct subnet_record *, struct userdata_struct *, ...);

/* typedef to define the function called when the request that caused this
   response record to be created is unsuccessful. */
typedef void (*fail_function)(struct subnet_record *, struct response_record *, ...);

/* List of typedefs for success and fail functions of the different query
   types. Used to catch any compile time prototype errors. */

typedef void (*register_name_success_function)( struct subnet_record *,
                                                struct userdata_struct *,
                                                struct nmb_name *,
                                                uint16_t,
                                                int,
                                                struct in_addr);
typedef void (*register_name_fail_function)( struct subnet_record *,
                                             struct response_record *,
                                             struct nmb_name *);

typedef void (*release_name_success_function)( struct subnet_record *,
                                               struct userdata_struct *,
                                               struct nmb_name *,
                                               struct in_addr);
typedef void (*release_name_fail_function)( struct subnet_record *,
                                            struct response_record *,
                                            struct nmb_name *);

typedef void (*refresh_name_success_function)( struct subnet_record *,
                                               struct userdata_struct *,
                                               struct nmb_name *,
                                               uint16_t,
                                               int,
                                               struct in_addr);
typedef void (*refresh_name_fail_function)( struct subnet_record *,
                                            struct response_record *,
                                            struct nmb_name *);

typedef void (*query_name_success_function)( struct subnet_record *,
                                             struct userdata_struct *,
                                             struct nmb_name *,
                                             struct in_addr,
                                             struct res_rec *answers);

typedef void (*query_name_fail_function)( struct subnet_record *,
                                          struct response_record *,
                                          struct nmb_name *,
                                          int);

typedef void (*node_status_success_function)( struct subnet_record *,
                                              struct userdata_struct *,
                                              struct res_rec *,
                                              struct in_addr);
typedef void (*node_status_fail_function)( struct subnet_record *,
                                           struct response_record *);

/* Initiated name queries are recorded in this list to track any responses. */

struct response_record {
	struct response_record *next;
	struct response_record *prev;

	uint16_t response_id;

	/* Callbacks for packets received or not. */
	response_function resp_fn;
	timeout_response_function timeout_fn;

	/* Callbacks for the request succeeding or not. */
	success_function success_fn;
	fail_function fail_fn;

	struct packet_struct *packet;

	struct userdata_struct *userdata;

	int num_msgs;

	time_t repeat_time;
	time_t repeat_interval;
	int    repeat_count;

	/* Recursion protection. */
	bool in_expiration_processing;
};

/* A subnet structure. It contains a list of workgroups and netbios names. */

/*
   B nodes will have their own, totally separate subnet record, with their
   own netbios name set. These do NOT interact with other subnet records'
   netbios names.
*/

enum subnet_type {
	NORMAL_SUBNET              = 0,  /* Subnet listed in interfaces list. */
	UNICAST_SUBNET             = 1,  /* Subnet for unicast packets. */
	REMOTE_BROADCAST_SUBNET    = 2,  /* Subnet for remote broadcasts. */
	WINS_SERVER_SUBNET         = 3   /* Only created if we are a WINS server. */
};

struct subnet_record {
	struct subnet_record *next;
	struct subnet_record *prev;

	char  *subnet_name;      /* For Debug identification. */
	enum subnet_type type;   /* To catagorize the subnet. */

	struct work_record     *workgrouplist; /* List of workgroups. */
	struct name_record     *namelist;   /* List of netbios names. */
	struct response_record *responselist;  /* List of responses expected. */

	bool namelist_changed;
	bool work_changed;

	struct in_addr bcast_ip;
	struct in_addr mask_ip;
	struct in_addr myip;
	int nmb_sock;               /* socket to listen for unicast 137. */
	int nmb_bcast;              /* socket to listen for broadcast 137. */
	int dgram_sock;             /* socket to listen for unicast 138. */
	int dgram_bcast;            /* socket to listen for broadcast 138. */
};

/* Broadcast packet announcement intervals, in minutes. */

/* Attempt to add domain logon and domain master names. */
#define CHECK_TIME_ADD_DOM_NAMES 5

/* Search for master browsers of workgroups samba knows about,
   except default. */
#define CHECK_TIME_MST_BROWSE       5

/* Request backup browser announcements from other servers. */
#define CHECK_TIME_ANNOUNCE_BACKUP 15

/* Request host announcements from other servers: min and max of interval. */
#define CHECK_TIME_MIN_HOST_ANNCE   3
#define CHECK_TIME_MAX_HOST_ANNCE  12

/* Announce as master to WINS server and any Primary Domain Controllers. */
#define CHECK_TIME_MST_ANNOUNCE    15

/* Time between syncs from domain master browser to local master browsers. */
#define CHECK_TIME_DMB_TO_LMB_SYNC    15

/* Do all remote announcements this often. */
#define REMOTE_ANNOUNCE_INTERVAL 180

/* what is the maximum period between name refreshes. Note that this only
   affects non-permanent self names (in seconds) */
#define MAX_REFRESH_TIME (60*20)

/* The Extinction interval: 4 days, time a node will stay in released state  */
#define EXTINCTION_INTERVAL (4*24*60*60)

/* The Extinction time-out: 1 day, time a node will stay in deleted state */
#define EXTINCTION_TIMEOUT (24*60*60)

/* Macro's to enumerate subnets either with or without
   the UNICAST subnet. */

extern struct subnet_record *subnetlist;
extern struct subnet_record *unicast_subnet;
extern struct subnet_record *wins_server_subnet;
extern struct subnet_record *remote_broadcast_subnet;

#define FIRST_SUBNET subnetlist
#define NEXT_SUBNET_EXCLUDING_UNICAST(x) ((x)->next)
#define NEXT_SUBNET_INCLUDING_UNICAST(x) (get_next_subnet_maybe_unicast((x)))

/* wins replication record used between nmbd and wrepld */
typedef struct _WINS_RECORD {
	char name[17];
	char type;
	int nb_flags;
	int wins_flags;
	uint64_t id;
	int num_ips;
	struct in_addr ip[25];
	struct in_addr wins_ip;
} WINS_RECORD;

#include "nmbd/nmbd_proto.h"

#define NMBD_WAIT_INTERFACES_TIME_USEC  (250 * 1000)

/****************************************************************************
true if two IPv4 addresses are equal
****************************************************************************/

#define ip_equal_v4(ip1,ip2) ((ip1).s_addr == (ip2).s_addr)

#endif /* _NMBD_NMBD_H_ */
