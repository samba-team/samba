/*
   ctdb database library

   Copyright (C) Andrew Tridgell  2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _CTDB_PROTOCOL_H
#define _CTDB_PROTOCOL_H

/* location of daemon socket */
#define CTDB_PATH	"/tmp/ctdb.socket"

/* default ctdb port number */
#define CTDB_PORT 4379

/* we must align packets to ensure ctdb works on all architectures (eg. sparc) */
#define CTDB_DS_ALIGNMENT 8


#define CTDB_NULL_FUNC                  0xFF000001
#define CTDB_FETCH_FUNC                 0xFF000002
#define CTDB_FETCH_WITH_HEADER_FUNC     0xFF000003


struct ctdb_call {
	int call_id;
	TDB_DATA key;
	TDB_DATA call_data;
	TDB_DATA reply_data;
	uint32_t status;
#define CTDB_IMMEDIATE_MIGRATION		0x00000001
#define CTDB_CALL_FLAG_VACUUM_MIGRATION		0x00000002
#define CTDB_WANT_READONLY			0x00000004
	uint32_t flags;
};

/*
  structure passed to a ctdb call backend function
*/
struct ctdb_call_info {
	TDB_DATA key;          /* record key */
	struct ctdb_ltdb_header *header;
	TDB_DATA record_data;  /* current data in the record */
	TDB_DATA *new_data;    /* optionally updated record data */
	TDB_DATA *call_data;   /* optionally passed from caller */
	TDB_DATA *reply_data;  /* optionally returned by function */
	uint32_t status;       /* optional reply status - defaults to zero */
};

#define CTDB_ERR_INVALID 1
#define CTDB_ERR_NOMEM 2

/*
  ctdb flags
*/
#define CTDB_FLAG_TORTURE      (1<<1)

/*
   a message handler ID meaning "give me all messages"
 */
#define CTDB_SRVID_ALL (~(uint64_t)0)

/*
  srvid type : RECOVERY
*/
#define CTDB_SRVID_RECOVERY	0xF100000000000000LL

/*
   a message handler ID meaning that the cluster has been reconfigured
 */
#define CTDB_SRVID_RECONFIGURE 0xF200000000000000LL

/*
   a message handler ID meaning that an IP address has been released
 */
#define CTDB_SRVID_RELEASE_IP 0xF300000000000000LL

/*
   a message handler ID meaning that an IP address has been taken
 */
#define CTDB_SRVID_TAKE_IP 0xF301000000000000LL

/*
   a message ID to set the node flags in the recovery daemon
 */
#define CTDB_SRVID_SET_NODE_FLAGS 0xF400000000000000LL

/*
   a message ID to ask the recovery daemon to update the expected node
   assignment for a public ip
 */
#define CTDB_SRVID_RECD_UPDATE_IP 0xF500000000000000LL

/*
  a message to tell the recovery daemon to fetch a set of records
 */
#define CTDB_SRVID_VACUUM_FETCH 0xF700000000000000LL

/*
  a message to tell the recovery daemon to write a talloc memdump
  to the log
 */
#define CTDB_SRVID_MEM_DUMP 0xF800000000000000LL

/*
   a message ID to get the recovery daemon to push the node flags out
 */
#define CTDB_SRVID_PUSH_NODE_FLAGS 0xF900000000000000LL

/*
   a message ID to get the recovery daemon to reload the nodes file
 */
#define CTDB_SRVID_RELOAD_NODES 0xFA00000000000000LL

/*
   a message ID to get the recovery daemon to perform a takeover run
 */
#define CTDB_SRVID_TAKEOVER_RUN 0xFB00000000000000LL

/* request recovery daemon to rebalance ips for a node.
   input is uint32_t for the node id.
*/
#define CTDB_SRVID_REBALANCE_NODE 0xFB01000000000000LL

/*
   a message handler ID meaning to ask recovery master to reload all ips
 */
#define CTDB_SRVID_RELOAD_ALL_IPS 0xFB02000000000000LL

/* A message id to ask the recovery daemon to temporarily disable the
   public ip checks
*/
#define CTDB_SRVID_DISABLE_IP_CHECK  0xFC00000000000000LL

/* A dummy port used for sending back ipreallocate resposnes to the main
   daemon
*/
#define CTDB_SRVID_TAKEOVER_RUN_RESPONSE  0xFD00000000000000LL

/* A range of ports reserved for registering a PID (top 8 bits)
 * All ports matching the 8 top bits are reserved for exclusive use by
 * registering a SRVID that matches the process-id of the requesting process
 */
#define CTDB_SRVID_PID_RANGE   0x0000000000000000LL

/* A range of ports reserved for samba (top 8 bits)
 * All ports matching the 8 top bits are reserved for exclusive use by
 * CIFS server
 */
#define CTDB_SRVID_SAMBA_NOTIFY  0xFE00000000000000LL
#define CTDB_SRVID_SAMBA_RANGE   0xFE00000000000000LL

/* A range of ports reserved for a CTDB NFS server (top 8 bits)
 * All ports matching the 8 top bits are reserved for exclusive use by
 * NFS server
 */
#define CTDB_SRVID_NFSD_RANGE  0xEE00000000000000LL

/* A range of ports reserved for a CTDB ISCSI server (top 8 bits)
 * All ports matching the 8 top bits are reserved for exclusive use by
 * ISCSI server
 */
#define CTDB_SRVID_ISCSID_RANGE  0xDE00000000000000LL

/* A range of ports reserved for testing (top 8 bits)
 * All ports matching the 8 top bits are reserved for exclusive use by
 * test applications
 */
#define CTDB_SRVID_TEST_RANGE  0xCE00000000000000LL

/* Range of ports reserved for traversals */
#define CTDB_SRVID_TRAVERSE_RANGE  0xBE00000000000000LL

/* used on the domain socket, send a pdu to the local daemon */
#define CTDB_CURRENT_NODE     0xF0000001
/* send a broadcast to all nodes in the cluster, active or not */
#define CTDB_BROADCAST_ALL    0xF0000002
/* send a broadcast to all nodes in the current vnn map */
#define CTDB_BROADCAST_VNNMAP 0xF0000003
/* send a broadcast to all connected nodes */
#define CTDB_BROADCAST_CONNECTED 0xF0000004
/* send a broadcast to selected connected nodes */
#define CTDB_MULTICAST 0xF0000005

/* the key used for transaction locking on persistent databases */
#define CTDB_TRANSACTION_LOCK_KEY "__transaction_lock__"

/* the key used to store persistent db sequence number */
#define CTDB_DB_SEQNUM_KEY "__db_sequence_number__"

#define MONITOR_SCRIPT_OK      0
#define MONITOR_SCRIPT_TIMEOUT 1

#define MAX_SCRIPT_NAME 31
#define MAX_SCRIPT_OUTPUT 511
struct ctdb_script_wire {
	char name[MAX_SCRIPT_NAME+1];
	struct timeval start;
	struct timeval finished;
	int32_t status;
	char output[MAX_SCRIPT_OUTPUT+1];
};

struct ctdb_scripts_wire {
	uint32_t num_scripts;
	struct ctdb_script_wire scripts[1];
};

/* different calls to event scripts. */
enum ctdb_eventscript_call {
	CTDB_EVENT_INIT,		/* CTDB starting up: no args */
	CTDB_EVENT_SETUP,		/* CTDB starting up after transport is readdy: no args. */
	CTDB_EVENT_STARTUP,		/* CTDB starting up after initial recovery: no args. */
	CTDB_EVENT_START_RECOVERY,	/* CTDB recovery starting: no args. */
	CTDB_EVENT_RECOVERED,		/* CTDB recovery finished: no args. */
	CTDB_EVENT_TAKE_IP,		/* IP taken: interface, IP address, netmask bits. */
	CTDB_EVENT_RELEASE_IP,		/* IP released: interface, IP address, netmask bits. */
	CTDB_EVENT_STOPPED,		/* This node is stopped: no args. */
	CTDB_EVENT_MONITOR,		/* Please check if service is healthy: no args. */
	CTDB_EVENT_STATUS,		/* Report service status: no args. */
	CTDB_EVENT_SHUTDOWN,		/* CTDB shutting down: no args. */
	CTDB_EVENT_RELOAD,		/* magic */
	CTDB_EVENT_UPDATE_IP,		/* IP updating: old interface, new interface, IP address, netmask bits. */
	CTDB_EVENT_IPREALLOCATED,	/* when a takeover_run() completes */
	CTDB_EVENT_MAX
};

/* Mapping from enum to names. */
extern const char *ctdb_eventscript_call_names[];

/*
  operation IDs
*/
enum ctdb_operation {
	CTDB_REQ_CALL           = 0,
	CTDB_REPLY_CALL         = 1,
	CTDB_REQ_DMASTER        = 2,
	CTDB_REPLY_DMASTER      = 3,
	CTDB_REPLY_ERROR        = 4,
	CTDB_REQ_MESSAGE        = 5,
	/* #6 removed */
	CTDB_REQ_CONTROL        = 7,
	CTDB_REPLY_CONTROL      = 8,
	CTDB_REQ_KEEPALIVE      = 9,
};

#define CTDB_MAGIC 0x43544442 /* CTDB */
#define CTDB_VERSION 1

enum ctdb_controls {CTDB_CONTROL_PROCESS_EXISTS          = 0,
		    CTDB_CONTROL_STATISTICS              = 1,
		    /* #2 removed */
		    CTDB_CONTROL_PING                    = 3,
		    CTDB_CONTROL_GETDBPATH               = 4,
		    CTDB_CONTROL_GETVNNMAP               = 5,
		    CTDB_CONTROL_SETVNNMAP               = 6,
		    CTDB_CONTROL_GET_DEBUG               = 7,
		    CTDB_CONTROL_SET_DEBUG               = 8,
		    CTDB_CONTROL_GET_DBMAP               = 9,
		    CTDB_CONTROL_GET_NODEMAPv4           = 10, /* obsolete */
		    CTDB_CONTROL_SET_DMASTER             = 11,
		    /* #12 removed */
		    CTDB_CONTROL_PULL_DB                 = 13,
		    CTDB_CONTROL_PUSH_DB                 = 14,
		    CTDB_CONTROL_GET_RECMODE             = 15,
		    CTDB_CONTROL_SET_RECMODE             = 16,
		    CTDB_CONTROL_STATISTICS_RESET        = 17,
		    CTDB_CONTROL_DB_ATTACH               = 18,
		    CTDB_CONTROL_SET_CALL                = 19,
		    CTDB_CONTROL_TRAVERSE_START          = 20,
		    CTDB_CONTROL_TRAVERSE_ALL            = 21,
		    CTDB_CONTROL_TRAVERSE_DATA           = 22,
		    CTDB_CONTROL_REGISTER_SRVID          = 23,
		    CTDB_CONTROL_DEREGISTER_SRVID        = 24,
		    CTDB_CONTROL_GET_DBNAME              = 25,
		    CTDB_CONTROL_ENABLE_SEQNUM           = 26,
		    CTDB_CONTROL_UPDATE_SEQNUM           = 27,
		    /* #28 removed */
		    CTDB_CONTROL_DUMP_MEMORY             = 29,
		    CTDB_CONTROL_GET_PID                 = 30,
		    CTDB_CONTROL_GET_RECMASTER           = 31,
		    CTDB_CONTROL_SET_RECMASTER           = 32,
		    CTDB_CONTROL_FREEZE                  = 33,
		    CTDB_CONTROL_THAW                    = 34,
		    CTDB_CONTROL_GET_PNN                 = 35,
		    CTDB_CONTROL_SHUTDOWN                = 36,
		    CTDB_CONTROL_GET_MONMODE             = 37,
		    /* #38 removed */
		    /* #39 removed */
		    /* #40 removed */
		    /* #41 removed */
		    CTDB_CONTROL_TAKEOVER_IPv4           = 42, /* obsolete */
		    CTDB_CONTROL_RELEASE_IPv4            = 43, /* obsolete */
		    CTDB_CONTROL_TCP_CLIENT              = 44,
		    CTDB_CONTROL_TCP_ADD                 = 45,
		    CTDB_CONTROL_TCP_REMOVE              = 46,
		    CTDB_CONTROL_STARTUP                 = 47,
		    CTDB_CONTROL_SET_TUNABLE             = 48,
		    CTDB_CONTROL_GET_TUNABLE             = 49,
		    CTDB_CONTROL_LIST_TUNABLES           = 50,
		    CTDB_CONTROL_GET_PUBLIC_IPSv4        = 51, /* obsolete */
		    CTDB_CONTROL_MODIFY_FLAGS            = 52,
		    CTDB_CONTROL_GET_ALL_TUNABLES        = 53,
		    CTDB_CONTROL_KILL_TCP                = 54,
		    CTDB_CONTROL_GET_TCP_TICKLE_LIST     = 55,
		    CTDB_CONTROL_SET_TCP_TICKLE_LIST     = 56,
		    CTDB_CONTROL_REGISTER_SERVER_ID	 = 57,
		    CTDB_CONTROL_UNREGISTER_SERVER_ID	 = 58,
		    CTDB_CONTROL_CHECK_SERVER_ID	 = 59,
		    CTDB_CONTROL_GET_SERVER_ID_LIST	 = 60,
		    CTDB_CONTROL_DB_ATTACH_PERSISTENT    = 61,
		    CTDB_CONTROL_PERSISTENT_STORE        = 62,
		    CTDB_CONTROL_UPDATE_RECORD           = 63,
		    CTDB_CONTROL_SEND_GRATIOUS_ARP       = 64,
		    CTDB_CONTROL_TRANSACTION_START       = 65,
		    CTDB_CONTROL_TRANSACTION_COMMIT      = 66,
		    CTDB_CONTROL_WIPE_DATABASE           = 67,
		    /* #68 removed */
		    CTDB_CONTROL_UPTIME                  = 69,
		    CTDB_CONTROL_START_RECOVERY          = 70,
		    CTDB_CONTROL_END_RECOVERY            = 71,
		    CTDB_CONTROL_RELOAD_NODES_FILE       = 72,
		    /* #73 removed */
		    CTDB_CONTROL_TRY_DELETE_RECORDS      = 74,
		    CTDB_CONTROL_ENABLE_MONITOR          = 75,
		    CTDB_CONTROL_DISABLE_MONITOR         = 76,
		    CTDB_CONTROL_ADD_PUBLIC_IP           = 77,
		    CTDB_CONTROL_DEL_PUBLIC_IP           = 78,
		    CTDB_CONTROL_RUN_EVENTSCRIPTS        = 79,
		    CTDB_CONTROL_GET_CAPABILITIES	 = 80,
		    CTDB_CONTROL_START_PERSISTENT_UPDATE = 81,
		    CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE= 82,
		    CTDB_CONTROL_TRANS2_COMMIT           = 83,
		    CTDB_CONTROL_TRANS2_FINISHED         = 84,
		    CTDB_CONTROL_TRANS2_ERROR            = 85,
		    CTDB_CONTROL_TRANS2_COMMIT_RETRY     = 86,
		    CTDB_CONTROL_RECD_PING		 = 87,
		    CTDB_CONTROL_RELEASE_IP              = 88,
		    CTDB_CONTROL_TAKEOVER_IP             = 89,
		    CTDB_CONTROL_GET_PUBLIC_IPS          = 90,
		    CTDB_CONTROL_GET_NODEMAP             = 91,
		    CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS = 96,
		    CTDB_CONTROL_TRAVERSE_KILL		 = 97,
		    CTDB_CONTROL_RECD_RECLOCK_LATENCY    = 98,
		    CTDB_CONTROL_GET_RECLOCK_FILE        = 99,
		    CTDB_CONTROL_SET_RECLOCK_FILE        = 100,
		    CTDB_CONTROL_STOP_NODE               = 101,
		    CTDB_CONTROL_CONTINUE_NODE           = 102,
		    CTDB_CONTROL_SET_NATGWSTATE          = 103,
		    CTDB_CONTROL_SET_LMASTERROLE         = 104,
		    CTDB_CONTROL_SET_RECMASTERROLE       = 105,
		    CTDB_CONTROL_ENABLE_SCRIPT           = 107,
		    CTDB_CONTROL_DISABLE_SCRIPT          = 108,
		    CTDB_CONTROL_SET_BAN_STATE           = 109,
		    CTDB_CONTROL_GET_BAN_STATE           = 110,
		    CTDB_CONTROL_SET_DB_PRIORITY         = 111,
		    CTDB_CONTROL_GET_DB_PRIORITY         = 112,
		    CTDB_CONTROL_TRANSACTION_CANCEL      = 113,
		    CTDB_CONTROL_REGISTER_NOTIFY         = 114,
		    CTDB_CONTROL_DEREGISTER_NOTIFY       = 115,
		    CTDB_CONTROL_TRANS2_ACTIVE           = 116,
		    CTDB_CONTROL_GET_LOG		 = 117,
		    CTDB_CONTROL_CLEAR_LOG		 = 118,
		    CTDB_CONTROL_TRANS3_COMMIT           = 119,
		    CTDB_CONTROL_GET_DB_SEQNUM           = 120,
		    CTDB_CONTROL_DB_SET_HEALTHY		 = 121,
		    CTDB_CONTROL_DB_GET_HEALTH		 = 122,
		    CTDB_CONTROL_GET_PUBLIC_IP_INFO	 = 123,
		    CTDB_CONTROL_GET_IFACES		 = 124,
		    CTDB_CONTROL_SET_IFACE_LINK_STATE	 = 125,
		    CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE  = 126,
		    CTDB_CONTROL_GET_STAT_HISTORY	 = 127,
		    CTDB_CONTROL_SCHEDULE_FOR_DELETION   = 128,
		    CTDB_CONTROL_SET_DB_READONLY	 = 129,
		    CTDB_CONTROL_CHECK_SRVIDS		 = 130,
		    CTDB_CONTROL_TRAVERSE_START_EXT	 = 131,
		    CTDB_CONTROL_GET_DB_STATISTICS	 = 132,
		    CTDB_CONTROL_SET_DB_STICKY		 = 133,
		    CTDB_CONTROL_RELOAD_PUBLIC_IPS	 = 134,
};

/*
  packet structures
*/
struct ctdb_req_header {
	uint32_t length;
	uint32_t ctdb_magic;
	uint32_t ctdb_version;
	uint32_t generation;
	uint32_t operation;
	uint32_t destnode;
	uint32_t srcnode;
	uint32_t reqid;
};

struct ctdb_req_call {
	struct ctdb_req_header hdr;
	uint32_t flags;
	uint32_t db_id;
	uint32_t callid;
	uint32_t hopcount;
	uint32_t keylen;
	uint32_t calldatalen;
	uint8_t data[1]; /* key[] followed by calldata[] */
};

struct ctdb_reply_call {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_error {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t msglen;
	uint8_t  msg[1];
};

struct ctdb_req_dmaster {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_dmaster {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_req_message {
	struct ctdb_req_header hdr;
	uint64_t srvid;
	uint32_t datalen;
	uint8_t data[1];
};

struct ctdb_req_getdbpath {
	struct ctdb_req_header hdr;
	uint32_t db_id;
};

struct ctdb_reply_getdbpath {
	struct ctdb_req_header hdr;
	uint32_t datalen;
	uint8_t data[1];
};

struct ctdb_req_control {
	struct ctdb_req_header hdr;
	uint32_t opcode;
	uint32_t pad;
	uint64_t srvid;
	uint32_t client_id;
#define CTDB_CTRL_FLAG_NOREPLY   1
#define CTDB_CTRL_FLAG_OPCODE_SPECIFIC   0xFFFF0000
	uint32_t flags;
	uint32_t datalen;
	uint8_t data[1];
};

struct ctdb_reply_control {
	struct ctdb_req_header hdr;
	int32_t  status;
	uint32_t datalen;
	uint32_t errorlen;
	uint8_t data[1];
};

struct ctdb_req_keepalive {
	struct ctdb_req_header hdr;
};


/* types of failures possible from TRANS2_COMMIT */
enum ctdb_trans2_commit_error {
	CTDB_TRANS2_COMMIT_SUCCESS=0, /* all nodes committed successfully */
	CTDB_TRANS2_COMMIT_TIMEOUT=1, /* at least one node timed out */
	CTDB_TRANS2_COMMIT_ALLFAIL=2, /* all nodes failed the commit */
	CTDB_TRANS2_COMMIT_SOMEFAIL=3 /* some nodes failed the commit, some allowed it */
};

/*
  the extended header for records in the ltdb
*/
struct ctdb_ltdb_header {
	uint64_t rsn;
	uint32_t dmaster;
	uint16_t laccessor;
	uint16_t lacount;
#define CTDB_REC_FLAG_DEFAULT			0x00000000
#define CTDB_REC_FLAG_MIGRATED_WITH_DATA	0x00010000
#define CTDB_REC_FLAG_VACUUM_MIGRATED		0x00020000
#define CTDB_REC_FLAG_AUTOMATIC			0x00040000
#define CTDB_REC_RO_HAVE_DELEGATIONS		0x01000000
#define CTDB_REC_RO_HAVE_READONLY		0x02000000
#define CTDB_REC_RO_REVOKING_READONLY		0x04000000
#define CTDB_REC_RO_REVOKE_COMPLETE		0x08000000
	uint32_t flags;
};


/*
  definitions for different socket structures
 */
typedef struct sockaddr_in ctdb_addr_in;
typedef struct sockaddr_in6 ctdb_addr_in6;
typedef union {
	struct sockaddr sa;
	ctdb_addr_in	ip;
	ctdb_addr_in6	ip6;
} ctdb_sock_addr;

/*
   A structure describing a single node, its flags and its address
*/
struct ctdb_node_and_flags {
	uint32_t pnn;
	uint32_t flags;
	ctdb_sock_addr addr;
};


/*
   Structure used for a nodemap. 
   The nodemap is the structure containing a list of all nodes
   known to the cluster and their associated flags.
*/
struct ctdb_node_map {
	uint32_t num;
	struct ctdb_node_and_flags nodes[1];
};

/*
 * Node flags
 */
#define NODE_FLAGS_DISCONNECTED		0x00000001 /* node isn't connected */
#define NODE_FLAGS_UNHEALTHY  		0x00000002 /* monitoring says node is unhealthy */
#define NODE_FLAGS_PERMANENTLY_DISABLED	0x00000004 /* administrator has disabled node */
#define NODE_FLAGS_BANNED		0x00000008 /* recovery daemon has banned the node */
#define NODE_FLAGS_DELETED		0x00000010 /* this node has been deleted */
#define NODE_FLAGS_STOPPED		0x00000020 /* this node has been stopped */
#define NODE_FLAGS_DISABLED		(NODE_FLAGS_UNHEALTHY|NODE_FLAGS_PERMANENTLY_DISABLED)
#define NODE_FLAGS_INACTIVE		(NODE_FLAGS_DELETED|NODE_FLAGS_DISCONNECTED|NODE_FLAGS_BANNED|NODE_FLAGS_STOPPED)

#define NODE_FLAGS_NOIPTAKEOVER		0x01000000 /* this node can takeover any new ip addresses, this flag is ONLY valid within the recovery daemon */


struct ctdb_public_ip {
	uint32_t pnn;
	ctdb_sock_addr addr;
};

struct ctdb_all_public_ips {
	uint32_t num;
	struct ctdb_public_ip ips[1];
};


struct latency_counter {
	int num;
	double min;
	double max;
	double total;
};

/*
  structure used to pass record data between the child and parent
 */
struct ctdb_rec_data {
	uint32_t length;
	uint32_t reqid;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_traverse_start {
	uint32_t db_id;
	uint32_t reqid;
	uint64_t srvid;
};

struct ctdb_traverse_start_ext {
	uint32_t db_id;
	uint32_t reqid;
	uint64_t srvid;
	bool withemptyrecords;
};

/*
  ctdb statistics information
 */
#define MAX_COUNT_BUCKETS 16
#define MAX_HOT_KEYS      10

struct ctdb_statistics {
	uint32_t num_clients;
	uint32_t frozen;
	uint32_t recovering;
	uint32_t client_packets_sent;
	uint32_t client_packets_recv;
	uint32_t node_packets_sent;
	uint32_t node_packets_recv;
	uint32_t keepalive_packets_sent;
	uint32_t keepalive_packets_recv;
	struct {
		uint32_t req_call;
		uint32_t reply_call;
		uint32_t req_dmaster;
		uint32_t reply_dmaster;
		uint32_t reply_error;
		uint32_t req_message;
		uint32_t req_control;
		uint32_t reply_control;
	} node;
	struct {
		uint32_t req_call;
		uint32_t req_message;
		uint32_t req_control;
	} client;
	struct {
		uint32_t call;
		uint32_t control;
		uint32_t traverse;
	} timeouts;
	struct {
		struct latency_counter ctdbd;
		struct latency_counter recd;
	} reclock;
	uint32_t total_calls;
	uint32_t pending_calls;
	uint32_t lockwait_calls;
	uint32_t pending_lockwait_calls;
	uint32_t childwrite_calls;
	uint32_t pending_childwrite_calls;
	uint32_t memory_used;
	uint32_t __last_counter; /* hack for control_statistics_all */
	uint32_t max_hop_count;
	uint32_t hop_count_bucket[MAX_COUNT_BUCKETS];
	struct latency_counter call_latency;
	struct latency_counter lockwait_latency;
	struct latency_counter childwrite_latency;
	uint32_t num_recoveries;
	struct timeval statistics_start_time;
	struct timeval statistics_current_time;
	uint32_t total_ro_delegations;
	uint32_t total_ro_revokes;
};

/*
 * wire format for statistics history
 */
struct ctdb_statistics_wire {
	uint32_t num;
	struct ctdb_statistics stats[1];
};

/*
 * db statistics
 */
struct ctdb_db_hot_key {
	uint32_t count;
	TDB_DATA key;
};
struct ctdb_db_statistics {
	uint32_t db_ro_delegations;
	uint32_t db_ro_revokes;
	uint32_t hop_count_bucket[MAX_COUNT_BUCKETS];
	uint32_t num_hot_keys;
	struct ctdb_db_hot_key hot_keys[MAX_HOT_KEYS];
};
struct ctdb_db_statistics_wire {
	uint32_t db_ro_delegations;
	uint32_t db_ro_revokes;
	uint32_t hop_count_bucket[MAX_COUNT_BUCKETS];
	uint32_t num_hot_keys;
	char hot_keys[1];
};

/*
 * wire format for interface list
 */
#ifdef IFNAMSIZ
#define CTDB_IFACE_SIZE IFNAMSIZ
#else
#define CTDB_IFACE_SIZE 16
#endif

struct ctdb_iface_info {
	char name[CTDB_IFACE_SIZE+2];
	uint16_t link_state;
	uint32_t references;
};

struct ctdb_ifaces_list {
	uint32_t num;
	struct ctdb_iface_info ifaces[1];
};

#define INVALID_GENERATION 1
/* table that contains the mapping between a hash value and lmaster
 */
struct ctdb_vnn_map {
	uint32_t generation;
	uint32_t size;
	uint32_t *map;
};

/* 
   a wire representation of the vnn map
 */
struct ctdb_vnn_map_wire {
	uint32_t generation;
	uint32_t size;
	uint32_t map[1];
};

#endif
