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

#include <sys/socket.h>

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
 * a message to tell recovery daemon to detach a database
 */
#define CTDB_SRVID_DETACH_DATABASE 0xF701000000000000LL
/*
  a message to tell the recovery daemon to write a talloc memdump
  to the log
 */
#define CTDB_SRVID_MEM_DUMP 0xF800000000000000LL

/* A message id used to ask the recover daemon to send logs
*/
#define CTDB_SRVID_GETLOG  0xF801000000000000LL

/* A message id used to ask the recover daemon to send logs
*/
#define CTDB_SRVID_CLEARLOG  0xF802000000000000LL

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

/* A message handler ID to stop takeover runs from occurring */
#define CTDB_SRVID_DISABLE_TAKEOVER_RUNS 0xFB03000000000000LL

/* A message handler ID to stop recoveries from occurring */
#define CTDB_SRVID_DISABLE_RECOVERIES 0xFB04000000000000LL

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
struct ctdb_script {
	char name[MAX_SCRIPT_NAME+1];
	struct timeval start;
	struct timeval finished;
	int32_t status;
	char output[MAX_SCRIPT_OUTPUT+1];
};

struct ctdb_script_list_old {
	uint32_t num_scripts;
	struct ctdb_script scripts[1];
};

/* different calls to event scripts. */
enum ctdb_event {
	CTDB_EVENT_INIT,		/* CTDB starting up: no args */
	CTDB_EVENT_SETUP,		/* CTDB starting up after transport is readdy: no args. */
	CTDB_EVENT_STARTUP,		/* CTDB starting up after initial recovery: no args. */
	CTDB_EVENT_START_RECOVERY,	/* CTDB recovery starting: no args. */
	CTDB_EVENT_RECOVERED,		/* CTDB recovery finished: no args. */
	CTDB_EVENT_TAKE_IP,		/* IP taken: interface, IP address, netmask bits. */
	CTDB_EVENT_RELEASE_IP,		/* IP released: interface, IP address, netmask bits. */
	CTDB_EVENT_STOPPED,		/* Deprecated, do not use. */
	CTDB_EVENT_MONITOR,		/* Please check if service is healthy: no args. */
	CTDB_EVENT_STATUS,		/* Deprecated, do not use. */
	CTDB_EVENT_SHUTDOWN,		/* CTDB shutting down: no args. */
	CTDB_EVENT_RELOAD,		/* Deprecated, do not use */
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
#define CTDB_PROTOCOL 1

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
		    CTDB_CONTROL_SET_DMASTER             = 11, /* obsolete */
		    /* #12 removed */
		    CTDB_CONTROL_PULL_DB                 = 13,
		    CTDB_CONTROL_PUSH_DB                 = 14,
		    CTDB_CONTROL_GET_RECMODE             = 15,
		    CTDB_CONTROL_SET_RECMODE             = 16,
		    CTDB_CONTROL_STATISTICS_RESET        = 17,
		    CTDB_CONTROL_DB_ATTACH               = 18,
		    CTDB_CONTROL_SET_CALL                = 19, /* obsolete */
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
		    CTDB_CONTROL_PERSISTENT_STORE        = 62, /* obsolete */
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
		    CTDB_CONTROL_TRANS2_COMMIT           = 83, /* obsolete */
		    CTDB_CONTROL_TRANS2_FINISHED         = 84, /* obsolete */
		    CTDB_CONTROL_TRANS2_ERROR            = 85, /* obsolete */
		    CTDB_CONTROL_TRANS2_COMMIT_RETRY     = 86, /* obsolete */
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
		    CTDB_CONTROL_TRANS2_ACTIVE           = 116, /* obsolete */
		    CTDB_CONTROL_GET_LOG		 = 117, /* obsolete */
		    CTDB_CONTROL_CLEAR_LOG		 = 118, /* obsolete */
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
		    CTDB_CONTROL_TRAVERSE_ALL_EXT	 = 135,
		    CTDB_CONTROL_RECEIVE_RECORDS	 = 136,
		    CTDB_CONTROL_IPREALLOCATED		 = 137,
		    CTDB_CONTROL_GET_RUNSTATE		 = 138,
		    CTDB_CONTROL_DB_DETACH		 = 139,
		    CTDB_CONTROL_GET_NODES_FILE		 = 140,
		    CTDB_CONTROL_DB_FREEZE		 = 141,
		    CTDB_CONTROL_DB_THAW		 = 142,
		    CTDB_CONTROL_DB_TRANSACTION_START	 = 143,
		    CTDB_CONTROL_DB_TRANSACTION_COMMIT	 = 144,
		    CTDB_CONTROL_DB_TRANSACTION_CANCEL	 = 145,
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

struct ctdb_req_call_old {
	struct ctdb_req_header hdr;
	uint32_t flags;
	uint32_t db_id;
	uint32_t callid;
	uint32_t hopcount;
	uint32_t keylen;
	uint32_t calldatalen;
	uint8_t data[1]; /* key[] followed by calldata[] */
};

struct ctdb_reply_call_old {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_error_old {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t msglen;
	uint8_t  msg[1];
};

struct ctdb_req_dmaster_old {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_dmaster_old {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_req_message_old {
	struct ctdb_req_header hdr;
	uint64_t srvid;
	uint32_t datalen;
	uint8_t data[1];
};

struct ctdb_req_control_old {
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

struct ctdb_reply_control_old {
	struct ctdb_req_header hdr;
	int32_t  status;
	uint32_t datalen;
	uint32_t errorlen;
	uint8_t data[1];
};

struct ctdb_req_keepalive_old {
	struct ctdb_req_header hdr;
};


/*
  the extended header for records in the ltdb
*/
struct ctdb_ltdb_header {
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t reserved1;
#define CTDB_REC_FLAG_DEFAULT			0x00000000
#define CTDB_REC_FLAG_MIGRATED_WITH_DATA	0x00010000
#define CTDB_REC_FLAG_VACUUM_MIGRATED		0x00020000
#define CTDB_REC_FLAG_AUTOMATIC			0x00040000
#define CTDB_REC_RO_HAVE_DELEGATIONS		0x01000000
#define CTDB_REC_RO_HAVE_READONLY		0x02000000
#define CTDB_REC_RO_REVOKING_READONLY		0x04000000
#define CTDB_REC_RO_REVOKE_COMPLETE		0x08000000
#define CTDB_REC_RO_FLAGS			(CTDB_REC_RO_HAVE_DELEGATIONS|\
						 CTDB_REC_RO_HAVE_READONLY|\
						 CTDB_REC_RO_REVOKING_READONLY|\
						 CTDB_REC_RO_REVOKE_COMPLETE)
	uint32_t flags;
};


/*
  definitions for different socket structures
 */
typedef union {
	struct sockaddr sa;
	struct sockaddr_in ip;
	struct sockaddr_in6 ip6;
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
struct ctdb_node_map_old {
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

/*
 * Node capabilities
 */
#define CTDB_CAP_RECMASTER		0x00000001
#define CTDB_CAP_LMASTER		0x00000002
/* This capability is set if CTDB_LVS_PUBLIC_IP is set */
#define CTDB_CAP_LVS			0x00000004
/* This capability is set if NATGW is enabled */
#define CTDB_CAP_NATGW			0x00000008

/*
 * Node features
 */
#define CTDB_CAP_PARALLEL_RECOVERY	0x00010000

#define CTDB_CAP_FEATURES		(CTDB_CAP_PARALLEL_RECOVERY)

#define CTDB_CAP_DEFAULT		(CTDB_CAP_RECMASTER | \
					 CTDB_CAP_LMASTER   | \
					 CTDB_CAP_FEATURES)

struct ctdb_public_ip {
	uint32_t pnn;
	ctdb_sock_addr addr;
};

struct ctdb_public_ip_list_old {
	uint32_t num;
	struct ctdb_public_ip ips[1];
};


struct ctdb_latency_counter {
	int num;
	double min;
	double max;
	double total;
};

/*
  structure used to pass record data between the child and parent
 */
struct ctdb_rec_data_old {
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
		struct ctdb_latency_counter ctdbd;
		struct ctdb_latency_counter recd;
	} reclock;
	struct {
		uint32_t num_calls;
		uint32_t num_current;
		uint32_t num_pending;
		uint32_t num_failed;
		struct ctdb_latency_counter latency;
		uint32_t buckets[MAX_COUNT_BUCKETS];
	} locks;
	uint32_t total_calls;
	uint32_t pending_calls;
	uint32_t childwrite_calls;
	uint32_t pending_childwrite_calls;
	uint32_t memory_used;
	uint32_t __last_counter; /* hack for control_statistics_all */
	uint32_t max_hop_count;
	uint32_t hop_count_bucket[MAX_COUNT_BUCKETS];
	struct ctdb_latency_counter call_latency;
	struct ctdb_latency_counter childwrite_latency;
	uint32_t num_recoveries;
	struct timeval statistics_start_time;
	struct timeval statistics_current_time;
	uint32_t total_ro_delegations;
	uint32_t total_ro_revokes;
};

/*
 * wire format for statistics history
 */
struct ctdb_statistics_list_old {
	uint32_t num;
	struct ctdb_statistics stats[1];
};

/*
 * db statistics
 */
struct ctdb_db_statistics_old {
	struct {
		uint32_t num_calls;
		uint32_t num_current;
		uint32_t num_pending;
		uint32_t num_failed;
		struct ctdb_latency_counter latency;
		uint32_t buckets[MAX_COUNT_BUCKETS];
	} locks;
	struct {
		struct ctdb_latency_counter latency;
	} vacuum;
	uint32_t db_ro_delegations;
	uint32_t db_ro_revokes;
	uint32_t hop_count_bucket[MAX_COUNT_BUCKETS];
	uint32_t num_hot_keys;
	struct {
		uint32_t count;
		TDB_DATA key;
	} hot_keys[MAX_HOT_KEYS];
	char hot_keys_wire[1];
};

/*
 * wire format for interface list
 */
#ifdef IFNAMSIZ
#define CTDB_IFACE_SIZE IFNAMSIZ
#else
#define CTDB_IFACE_SIZE 16
#endif

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

struct ctdb_notify_data_old {
	uint64_t srvid;
	uint32_t len;
	uint8_t notify_data[1];
};

/* table that contains a list of all dbids on a node
 */

struct ctdb_dbid {
	uint32_t db_id;
#define CTDB_DB_FLAGS_PERSISTENT	0x01
#define CTDB_DB_FLAGS_READONLY		0x02
#define CTDB_DB_FLAGS_STICKY		0x04
	uint8_t flags;
};

struct ctdb_dbid_map_old {
	uint32_t num;
	struct ctdb_dbid dbs[1];
};

#define CTDB_RECOVERY_NORMAL		0
#define CTDB_RECOVERY_ACTIVE		1

enum ctdb_client_id_type {
	SERVER_TYPE_SAMBA=1,
	SERVER_TYPE_NFSD=2,
	SERVER_TYPE_ISCSID=3
};

struct ctdb_client_id {
	enum ctdb_client_id_type type;
	uint32_t pnn;
	uint32_t server_id;
};

struct ctdb_client_id_list_old {
	uint32_t num;
	struct ctdb_client_id server_ids[1];
};

struct ctdb_uptime {
	struct timeval current_time;
	struct timeval ctdbd_start_time;
	struct timeval last_recovery_started;
	struct timeval last_recovery_finished;
};

struct ctdb_connection {
	ctdb_sock_addr src;
	ctdb_sock_addr dst;
};

struct ctdb_ban_state {
	uint32_t pnn;
	uint32_t time;
};

struct ctdb_db_priority {
	uint32_t db_id;
	uint32_t priority;
};

/*
 * Structures to support SRVID requests and replies
 */
struct ctdb_srvid_message {
	uint32_t pnn;
	uint64_t srvid;
};

struct ctdb_disable_message {
	uint32_t pnn;
	uint64_t srvid;
	uint32_t timeout;
};

/* the list of tcp tickles used by get/set tcp tickle list */
struct ctdb_tickle_list_old {
	ctdb_sock_addr addr;
	uint32_t num;
	struct ctdb_connection connections[1];
};

/* all tunable variables go in here */
struct ctdb_tunable_list {
	uint32_t max_redirect_count;
	uint32_t seqnum_interval; /* unit is ms */
	uint32_t control_timeout;
	uint32_t traverse_timeout;
	uint32_t keepalive_interval;
	uint32_t keepalive_limit;
	uint32_t recover_timeout;
	uint32_t recover_interval;
	uint32_t election_timeout;
	uint32_t takeover_timeout;
	uint32_t monitor_interval;
	uint32_t tickle_update_interval;
	uint32_t script_timeout;
	uint32_t script_timeout_count; /* allow dodgy scripts to hang this many times in a row before we mark the node unhealthy */
	uint32_t script_unhealthy_on_timeout; /* obsolete */
	uint32_t recovery_grace_period;
	uint32_t recovery_ban_period;
	uint32_t database_hash_size;
	uint32_t database_max_dead;
	uint32_t rerecovery_timeout;
	uint32_t enable_bans;
	uint32_t deterministic_public_ips;
	uint32_t reclock_ping_period;
	uint32_t no_ip_failback;
	uint32_t disable_ip_failover;
	uint32_t verbose_memory_names;
	uint32_t recd_ping_timeout;
	uint32_t recd_ping_failcount;
	uint32_t log_latency_ms;
	uint32_t reclock_latency_ms;
	uint32_t recovery_drop_all_ips;
	uint32_t verify_recovery_lock;
	uint32_t vacuum_interval;
	uint32_t vacuum_max_run_time;
	uint32_t repack_limit;
	uint32_t vacuum_limit;
	uint32_t max_queue_depth_drop_msg;
	uint32_t allow_unhealthy_db_read;
	uint32_t stat_history_interval;
	uint32_t deferred_attach_timeout;
	uint32_t vacuum_fast_path_count;
	uint32_t lcp2_public_ip_assignment;
	uint32_t allow_client_db_attach;
	uint32_t recover_pdb_by_seqnum;
	uint32_t deferred_rebalance_on_node_add;
	uint32_t fetch_collapse;
	uint32_t hopcount_make_sticky;
	uint32_t sticky_duration;
	uint32_t sticky_pindown;
	uint32_t no_ip_takeover;
	uint32_t db_record_count_warn;
	uint32_t db_record_size_warn;
	uint32_t db_size_warn;
	uint32_t pulldb_preallocation_size;
	uint32_t no_ip_host_on_all_disabled;
	uint32_t samba3_hack;
	uint32_t mutex_enabled;
	uint32_t lock_processes_per_db;
};

enum ctdb_runstate {
	CTDB_RUNSTATE_UNKNOWN,
	CTDB_RUNSTATE_INIT,
	CTDB_RUNSTATE_SETUP,
	CTDB_RUNSTATE_FIRST_RECOVERY,
	CTDB_RUNSTATE_STARTUP,
	CTDB_RUNSTATE_RUNNING,
	CTDB_RUNSTATE_SHUTDOWN,
};

#define CTDB_MONITORING_ACTIVE		0
#define CTDB_MONITORING_DISABLED	1

/*
  struct holding a ctdb_sock_addr and an interface name,
  used to add/remove public addresses and grat arp
 */
struct ctdb_addr_info_old {
	ctdb_sock_addr addr;
	uint32_t mask;
	uint32_t len;
	char iface[1];
};

/*
  structure used for CTDB_SRVID_NODE_FLAGS_CHANGED
 */
struct ctdb_node_flag_change {
	uint32_t pnn;
	uint32_t new_flags;
	uint32_t old_flags;
};

#define CTDB_LMASTER_ANY	0xffffffff

/* structure used for pulldb control */
struct ctdb_pulldb {
	uint32_t db_id;
	uint32_t lmaster;
};

/* structure used for sending lists of records */
struct ctdb_marshall_buffer {
	uint32_t db_id;
	uint32_t count;
	uint8_t data[1];
};

/*
  structure for setting a tunable
 */
struct ctdb_tunable_old {
	uint32_t value;
	uint32_t length;
	uint8_t  name[1];
};

/*
  structure for getting a tunable
 */
struct ctdb_control_get_tunable {
	uint32_t length;
	uint8_t  name[1];
};

/*
  structure for listing tunables
 */
struct ctdb_control_list_tunable {
	uint32_t length;
	/* returns a : separated list of tunable names */
	uint8_t  data[1];
};


struct ctdb_transdb {
	uint32_t db_id;
	uint32_t tid;
};

#define CTDB_PUBLIC_IP_FLAGS_ONLY_AVAILABLE 0x00010000

struct ctdb_control_iface_info {
	char name[CTDB_IFACE_SIZE+2];
	uint16_t link_state;
	uint32_t references;
};

struct ctdb_control_public_ip_info {
	struct ctdb_public_ip ip;
	uint32_t active_idx;
	uint32_t num;
	struct ctdb_control_iface_info ifaces[1];
};

struct ctdb_control_get_ifaces {
	uint32_t num;
	struct ctdb_control_iface_info ifaces[1];
};

/**
 * structure to pass to a schedule_for_deletion_control
 */
struct ctdb_control_schedule_for_deletion {
	uint32_t db_id;
	struct ctdb_ltdb_header hdr;
	uint32_t keylen;
	uint8_t key[1]; /* key[] */
};

#endif
