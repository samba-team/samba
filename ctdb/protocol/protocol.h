/*
   CTDB protocol marshalling

   Copyright (C) Amitay Isaacs  2015

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

#ifndef __CTDB_PROTOCOL_H__
#define __CTDB_PROTOCOL_H__

#include <tdb.h>

#define CTDB_MAGIC	0x43544442 /* CTDB */
#define CTDB_PROTOCOL	1

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
	CTDB_REQ_TUNNEL		= 10,
};

/* used on the domain socket, send a pdu to the local daemon */
#define CTDB_CURRENT_NODE     0xF0000001
/* send a broadcast to all nodes in the cluster, active or not */
#define CTDB_BROADCAST_ALL    0xF0000002
/* send a broadcast to all nodes in the current vnn map */
#define CTDB_BROADCAST_ACTIVE 0xF0000003
/* send a broadcast to all connected nodes */
#define CTDB_BROADCAST_CONNECTED 0xF0000004
/* send a broadcast to selected connected nodes */
#define CTDB_MULTICAST 0xF0000005

#define CTDB_UNKNOWN_PNN	0xFFFFFFFF

/* the key used to store persistent db sequence number */
#define CTDB_DB_SEQNUM_KEY "__db_sequence_number__"

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
	uint32_t flags;
	uint32_t db_id;
	uint32_t callid;
	uint32_t hopcount;
	TDB_DATA key;
	TDB_DATA calldata;
};

struct ctdb_reply_call {
	int32_t status;
	TDB_DATA data;
};

struct ctdb_reply_error {
	int32_t status;
	TDB_DATA msg;
};

struct ctdb_req_dmaster {
	uint32_t db_id;
	uint64_t rsn;
	uint32_t dmaster;
	TDB_DATA key;
	TDB_DATA data;
};

struct ctdb_reply_dmaster {
	uint32_t db_id;
	uint64_t rsn;
	TDB_DATA key;
	TDB_DATA data;
};

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

/* SRVID to catch all messages */
#define CTDB_SRVID_ALL (~(uint64_t)0)

/* SRVID prefix used during recovery for pulling and pushing databases */
#define CTDB_SRVID_RECOVERY	0xF001000000000000LL

/* SRVID to assign of banning credits */
#define CTDB_SRVID_BANNING	0xF002000000000000LL

/* SRVID to inform of election data */
#define CTDB_SRVID_ELECTION	0xF100000000000000LL

/* SRVID to inform clients that the cluster has been reconfigured */
#define CTDB_SRVID_RECONFIGURE 0xF200000000000000LL

/* SRVID to inform clients an IP address has been released */
#define CTDB_SRVID_RELEASE_IP 0xF300000000000000LL

/* SRVID to inform clients that an IP address has been taken over */
#define CTDB_SRVID_TAKE_IP 0xF301000000000000LL

/* SRVID to inform recovery daemon of the node flags - OBSOLETE */
#define CTDB_SRVID_SET_NODE_FLAGS 0xF400000000000000LL

/* SRVID to inform recovery daemon to update public ip assignment */
#define CTDB_SRVID_RECD_UPDATE_IP 0xF500000000000000LL

/* SRVID to inform recovery daemon to migrate a set of records */
#define CTDB_SRVID_VACUUM_FETCH 0xF700000000000000LL

/* SRVID to inform recovery daemon to detach a database */
#define CTDB_SRVID_DETACH_DATABASE 0xF701000000000000LL

/* SRVID to inform recovery daemon to dump talloc memdump to the log */
#define CTDB_SRVID_MEM_DUMP 0xF800000000000000LL

/* SRVID to inform recovery daemon to send logs */
#define CTDB_SRVID_GETLOG  0xF801000000000000LL

/* SRVID to inform recovery daemon to clear logs */
#define CTDB_SRVID_CLEARLOG  0xF802000000000000LL

/* SRVID to inform recovery daemon to push the node flags to other nodes */
#define CTDB_SRVID_PUSH_NODE_FLAGS 0xF900000000000000LL

/* SRVID to inform recovery daemon to reload the nodes file */
#define CTDB_SRVID_RELOAD_NODES 0xFA00000000000000LL

/* SRVID to inform recovery daemon to perform a takeover run */
#define CTDB_SRVID_TAKEOVER_RUN 0xFB00000000000000LL

/* SRVID to inform recovery daemon to rebalance ips for a node.  */
#define CTDB_SRVID_REBALANCE_NODE 0xFB01000000000000LL

/* SRVID to inform recovery daemon to stop takeover runs from occurring */
#define CTDB_SRVID_DISABLE_TAKEOVER_RUNS 0xFB03000000000000LL

/* SRVID to inform recovery daemon to stop recoveries from occurring */
#define CTDB_SRVID_DISABLE_RECOVERIES 0xFB04000000000000LL

/* SRVID to inform recovery daemon to disable the public ip checks */
#define CTDB_SRVID_DISABLE_IP_CHECK  0xFC00000000000000LL

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

/* A range of ports reserved for CTDB tool (top 8 bits)
 * All ports matching the 8 top bits are reserved for exclusive use by
 * CTDB tool
 */
#define CTDB_SRVID_TOOL_RANGE  0xCE00000000000000LL

/* A range of ports reserved by client (top 8 bits)
 * All ports matching the 8 top bits are reserved for exclusive use by
 * CTDB client code
 */
#define CTDB_SRVID_CLIENT_RANGE  0xBE00000000000000LL

/* Range of ports reserved for test applications (top 8 bits)
 * All ports matching the 8 top bits are reserved for exclusive use by
 * test applications
 */
#define CTDB_SRVID_TEST_RANGE  0xAE00000000000000LL


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
		    CTDB_CONTROL_THAW                    = 34, /* obsolete */
		    CTDB_CONTROL_GET_PNN                 = 35,
		    CTDB_CONTROL_SHUTDOWN                = 36,
		    CTDB_CONTROL_GET_MONMODE             = 37, /* obsolete */
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
		    CTDB_CONTROL_KILL_TCP                = 54, /* obsolete */
		    CTDB_CONTROL_GET_TCP_TICKLE_LIST     = 55,
		    CTDB_CONTROL_SET_TCP_TICKLE_LIST     = 56,
		    CTDB_CONTROL_REGISTER_SERVER_ID      = 57, /* obsolete */
		    CTDB_CONTROL_UNREGISTER_SERVER_ID    = 58, /* obsolete */
		    CTDB_CONTROL_CHECK_SERVER_ID         = 59, /* obsolete */
		    CTDB_CONTROL_GET_SERVER_ID_LIST      = 60, /* obsolete */
		    CTDB_CONTROL_DB_ATTACH_PERSISTENT    = 61,
		    CTDB_CONTROL_PERSISTENT_STORE        = 62, /* obsolete */
		    CTDB_CONTROL_UPDATE_RECORD           = 63,
		    CTDB_CONTROL_SEND_GRATUITOUS_ARP     = 64,
		    CTDB_CONTROL_TRANSACTION_START       = 65, /* obsolete */
		    CTDB_CONTROL_TRANSACTION_COMMIT      = 66, /* obsolete */
		    CTDB_CONTROL_WIPE_DATABASE           = 67,
		    /* #68 removed */
		    CTDB_CONTROL_UPTIME                  = 69,
		    CTDB_CONTROL_START_RECOVERY          = 70,
		    CTDB_CONTROL_END_RECOVERY            = 71,
		    CTDB_CONTROL_RELOAD_NODES_FILE       = 72,
		    /* #73 removed */
		    CTDB_CONTROL_TRY_DELETE_RECORDS      = 74,
		    CTDB_CONTROL_ENABLE_MONITOR          = 75, /* obsolete */
		    CTDB_CONTROL_DISABLE_MONITOR         = 76, /* obsolete */
		    CTDB_CONTROL_ADD_PUBLIC_IP           = 77,
		    CTDB_CONTROL_DEL_PUBLIC_IP           = 78,
		    CTDB_CONTROL_RUN_EVENTSCRIPTS        = 79, /* obsolete */
		    CTDB_CONTROL_GET_CAPABILITIES        = 80,
		    CTDB_CONTROL_START_PERSISTENT_UPDATE = 81, /* obsolete */
		    CTDB_CONTROL_CANCEL_PERSISTENT_UPDATE= 82, /* obsolete */
		    CTDB_CONTROL_TRANS2_COMMIT           = 83, /* obsolete */
		    CTDB_CONTROL_TRANS2_FINISHED         = 84, /* obsolete */
		    CTDB_CONTROL_TRANS2_ERROR            = 85, /* obsolete */
		    CTDB_CONTROL_TRANS2_COMMIT_RETRY     = 86, /* obsolete */
		    CTDB_CONTROL_RECD_PING               = 87,
		    CTDB_CONTROL_RELEASE_IP              = 88,
		    CTDB_CONTROL_TAKEOVER_IP             = 89,
		    CTDB_CONTROL_GET_PUBLIC_IPS          = 90,
		    CTDB_CONTROL_GET_NODEMAP             = 91,
		    /* missing */
		    CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS = 96, /* obsolete */
		    CTDB_CONTROL_TRAVERSE_KILL           = 97,
		    CTDB_CONTROL_RECD_RECLOCK_LATENCY    = 98,
		    CTDB_CONTROL_GET_RECLOCK_FILE        = 99,
		    CTDB_CONTROL_SET_RECLOCK_FILE        = 100, /* obsolete */
		    CTDB_CONTROL_STOP_NODE               = 101,
		    CTDB_CONTROL_CONTINUE_NODE           = 102,
		    CTDB_CONTROL_SET_NATGWSTATE          = 103, /* obsolete */
		    CTDB_CONTROL_SET_LMASTERROLE         = 104,
		    CTDB_CONTROL_SET_RECMASTERROLE       = 105,
		    CTDB_CONTROL_ENABLE_SCRIPT           = 107, /* obsolete */
		    CTDB_CONTROL_DISABLE_SCRIPT          = 108, /* obsolete */
		    CTDB_CONTROL_SET_BAN_STATE           = 109,
		    CTDB_CONTROL_GET_BAN_STATE           = 110,
		    CTDB_CONTROL_SET_DB_PRIORITY         = 111, /* obsolete */
		    CTDB_CONTROL_GET_DB_PRIORITY         = 112, /* obsolete */
		    CTDB_CONTROL_TRANSACTION_CANCEL      = 113, /* obsolete */
		    CTDB_CONTROL_REGISTER_NOTIFY         = 114,
		    CTDB_CONTROL_DEREGISTER_NOTIFY       = 115,
		    CTDB_CONTROL_TRANS2_ACTIVE           = 116, /* obsolete */
		    CTDB_CONTROL_GET_LOG                 = 117, /* obsolete */
		    CTDB_CONTROL_CLEAR_LOG               = 118, /* obsolete */
		    CTDB_CONTROL_TRANS3_COMMIT           = 119,
		    CTDB_CONTROL_GET_DB_SEQNUM           = 120,
		    CTDB_CONTROL_DB_SET_HEALTHY          = 121,
		    CTDB_CONTROL_DB_GET_HEALTH           = 122,
		    CTDB_CONTROL_GET_PUBLIC_IP_INFO      = 123,
		    CTDB_CONTROL_GET_IFACES              = 124,
		    CTDB_CONTROL_SET_IFACE_LINK_STATE    = 125,
		    CTDB_CONTROL_TCP_ADD_DELAYED_UPDATE  = 126,
		    CTDB_CONTROL_GET_STAT_HISTORY        = 127,
		    CTDB_CONTROL_SCHEDULE_FOR_DELETION   = 128,
		    CTDB_CONTROL_SET_DB_READONLY         = 129,
		    CTDB_CONTROL_CHECK_SRVIDS            = 130, /* obsolete */
		    CTDB_CONTROL_TRAVERSE_START_EXT      = 131,
		    CTDB_CONTROL_GET_DB_STATISTICS       = 132,
		    CTDB_CONTROL_SET_DB_STICKY           = 133,
		    CTDB_CONTROL_RELOAD_PUBLIC_IPS       = 134,
		    CTDB_CONTROL_TRAVERSE_ALL_EXT        = 135,
		    CTDB_CONTROL_RECEIVE_RECORDS         = 136, /* obsolete */
		    CTDB_CONTROL_IPREALLOCATED           = 137,
		    CTDB_CONTROL_GET_RUNSTATE            = 138,
		    CTDB_CONTROL_DB_DETACH               = 139,
		    CTDB_CONTROL_GET_NODES_FILE          = 140,
		    CTDB_CONTROL_DB_FREEZE               = 141,
		    CTDB_CONTROL_DB_THAW                 = 142,
		    CTDB_CONTROL_DB_TRANSACTION_START    = 143,
		    CTDB_CONTROL_DB_TRANSACTION_COMMIT   = 144,
		    CTDB_CONTROL_DB_TRANSACTION_CANCEL	 = 145,
		    CTDB_CONTROL_DB_PULL                 = 146,
		    CTDB_CONTROL_DB_PUSH_START           = 147,
		    CTDB_CONTROL_DB_PUSH_CONFIRM         = 148,
		    CTDB_CONTROL_DB_OPEN_FLAGS           = 149,
		    CTDB_CONTROL_DB_ATTACH_REPLICATED    = 150,
		    CTDB_CONTROL_CHECK_PID_SRVID         = 151,
		    CTDB_CONTROL_TUNNEL_REGISTER         = 152,
		    CTDB_CONTROL_TUNNEL_DEREGISTER       = 153,
		    CTDB_CONTROL_VACUUM_FETCH            = 154,
		    CTDB_CONTROL_DB_VACUUM               = 155,
		    CTDB_CONTROL_ECHO_DATA               = 156,
		    CTDB_CONTROL_DISABLE_NODE            = 157,
		    CTDB_CONTROL_ENABLE_NODE             = 158,
};

#define MAX_COUNT_BUCKETS 16
#define MAX_HOT_KEYS      10

struct ctdb_latency_counter {
	int num;
	double min;
	double max;
	double total;
};

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
		uint32_t req_tunnel;
	} node;
	struct {
		uint32_t req_call;
		uint32_t req_message;
		uint32_t req_control;
		uint32_t req_tunnel;
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
	uint32_t __last_counter; /* hack */
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

#define INVALID_GENERATION 1
/* table that contains the mapping between a hash value and lmaster
 */
struct ctdb_vnn_map {
	uint32_t generation;
	uint32_t size;
	uint32_t *map;
};

struct ctdb_dbid {
	uint32_t db_id;
#define CTDB_DB_FLAGS_PERSISTENT	0x01
#define CTDB_DB_FLAGS_READONLY		0x02
#define CTDB_DB_FLAGS_STICKY		0x04
#define CTDB_DB_FLAGS_REPLICATED	0x08
	uint8_t flags;
};

struct ctdb_dbid_map {
	uint32_t num;
	struct ctdb_dbid *dbs;
};

struct ctdb_pulldb {
	uint32_t db_id;
#define CTDB_LMASTER_ANY	0xffffffff
	uint32_t lmaster;
};

struct ctdb_pulldb_ext {
	uint32_t db_id;
	uint32_t lmaster;
	uint64_t srvid;
};

#define CTDB_RECOVERY_NORMAL		0
#define CTDB_RECOVERY_ACTIVE		1

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

struct ctdb_rec_data {
	uint32_t reqid;
	struct ctdb_ltdb_header *header;
	TDB_DATA key, data;
};

struct ctdb_rec_buffer {
	uint32_t db_id;
	uint32_t count;
	uint8_t *buf;
	size_t buflen;
};

typedef int (*ctdb_rec_parser_func_t)(uint32_t reqid,
				      struct ctdb_ltdb_header *header,
				      TDB_DATA key, TDB_DATA data,
				      void *private_data);

struct ctdb_traverse_start {
	uint32_t db_id;
	uint32_t reqid;
	uint64_t srvid;
};

struct ctdb_traverse_all {
	uint32_t db_id;
	uint32_t reqid;
	uint32_t pnn;
	uint32_t client_reqid;
	uint64_t srvid;
};

struct ctdb_traverse_start_ext {
	uint32_t db_id;
	uint32_t reqid;
	uint64_t srvid;
	bool withemptyrecords;
};

struct ctdb_traverse_all_ext {
	uint32_t db_id;
	uint32_t reqid;
	uint32_t pnn;
	uint32_t client_reqid;
	uint64_t srvid;
	bool withemptyrecords;
};

typedef union {
	struct sockaddr sa;
	struct sockaddr_in ip;
	struct sockaddr_in6 ip6;
} ctdb_sock_addr;

struct ctdb_connection {
	union {
		ctdb_sock_addr src;
		ctdb_sock_addr server;
	};
	union {
		ctdb_sock_addr dst;
		ctdb_sock_addr client;
	};
};

struct ctdb_connection_list {
	uint32_t num;
	struct ctdb_connection *conn;
};

struct ctdb_tunable {
	const char *name;
	uint32_t value;
};

struct ctdb_var_list {
	int count;
	const char **var;
};

struct ctdb_node_flag_change {
	uint32_t pnn;
	uint32_t new_flags;
	uint32_t old_flags;
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
	uint32_t monitor_timeout_count; /* allow dodgy scripts to hang this many times in a row before we mark the node unhealthy */
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
	uint32_t rec_buffer_size_limit;
	uint32_t queue_buffer_size;
	uint32_t ip_alloc_algorithm;
	uint32_t allow_mixed_versions;
};

struct ctdb_tickle_list {
	ctdb_sock_addr addr;
	uint32_t num;
	struct ctdb_connection *conn;
};

struct ctdb_addr_info {
	ctdb_sock_addr addr;
	uint32_t mask;
	const char *iface;
};

struct ctdb_transdb {
	uint32_t db_id;
	uint32_t tid;
};

struct ctdb_uptime {
	struct timeval current_time;
	struct timeval ctdbd_start_time;
	struct timeval last_recovery_started;
	struct timeval last_recovery_finished;
};

struct ctdb_public_ip {
	uint32_t pnn;
	ctdb_sock_addr addr;
};

struct ctdb_public_ip_list {
	uint32_t num;
	struct ctdb_public_ip *ip;
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
#define CTDB_CAP_LVS			0x00000004 /* obsolete */
#define CTDB_CAP_NATGW			0x00000008 /* obsolete */

/*
 * Node features
 */
#define CTDB_CAP_PARALLEL_RECOVERY	0x00010000
#define CTDB_CAP_FRAGMENTED_CONTROLS	0x00020000

#define CTDB_CAP_FEATURES		(CTDB_CAP_PARALLEL_RECOVERY | \
					 CTDB_CAP_FRAGMENTED_CONTROLS)

#define CTDB_CAP_DEFAULT		(CTDB_CAP_RECMASTER | \
					 CTDB_CAP_LMASTER   | \
					 CTDB_CAP_FEATURES)

struct ctdb_node_and_flags {
	uint32_t pnn;
	uint32_t flags;
	ctdb_sock_addr addr;
};

struct ctdb_node_map {
	uint32_t num;
	struct ctdb_node_and_flags *node;
};

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

#define MAX_SCRIPT_NAME 31
#define MAX_SCRIPT_OUTPUT 511

struct ctdb_script {
	char name[MAX_SCRIPT_NAME+1];
	struct timeval start;
	struct timeval finished;
	int32_t status;
	char output[MAX_SCRIPT_OUTPUT+1];
};

struct ctdb_script_list {
	uint32_t num_scripts;
	struct ctdb_script *script;
};

struct ctdb_ban_state {
	uint32_t pnn;
	uint32_t time;
};

struct ctdb_notify_data {
	uint64_t srvid;
	TDB_DATA data;
};

#ifdef IFNAMSIZ
#define CTDB_IFACE_SIZE IFNAMSIZ
#else
#define CTDB_IFACE_SIZE 16
#endif

struct ctdb_iface {
	char name[CTDB_IFACE_SIZE+2];
	uint16_t link_state;
	uint32_t references;
};

struct ctdb_iface_list {
	uint32_t num;
	struct ctdb_iface *iface;
};

struct ctdb_public_ip_info {
	struct ctdb_public_ip ip;
	uint32_t active_idx;
	struct ctdb_iface_list *ifaces;
};

struct ctdb_statistics_list {
	int num;
	struct ctdb_statistics *stats;
};

struct ctdb_key_data {
	uint32_t db_id;
	struct ctdb_ltdb_header header;
	TDB_DATA key;
};

struct ctdb_db_statistics {
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

struct ctdb_pid_srvid {
	pid_t pid;
	uint64_t srvid;
};

struct ctdb_db_vacuum {
	uint32_t db_id;
	bool full_vacuum_run;

};

struct ctdb_echo_data {
	uint32_t timeout;
	TDB_DATA buf;
};

struct ctdb_req_control_data {
	uint32_t opcode;
	union {
		pid_t pid;
		uint32_t db_id;
		struct ctdb_vnn_map *vnnmap;
		uint32_t loglevel;
		struct ctdb_pulldb *pulldb;
		struct ctdb_pulldb_ext *pulldb_ext;
		struct ctdb_rec_buffer *recbuf;
		uint32_t recmode;
		const char *db_name;
		struct ctdb_traverse_start *traverse_start;
		struct ctdb_traverse_all *traverse_all;
		struct ctdb_rec_data *rec_data;
		uint32_t recmaster;
		struct ctdb_connection *conn;
		struct ctdb_tunable *tunable;
		const char *tun_var;
		struct ctdb_node_flag_change *flag_change;
		ctdb_sock_addr *addr;
		struct ctdb_tickle_list *tickles;
		struct ctdb_client_id *cid;
		struct ctdb_addr_info *addr_info;
		struct ctdb_transdb *transdb;
		struct ctdb_public_ip *pubip;
		enum ctdb_event event;
		double reclock_latency;
		uint32_t role;
		struct ctdb_ban_state *ban_state;
		struct ctdb_notify_data *notify;
		uint64_t srvid;
		struct ctdb_iface *iface;
		struct ctdb_key_data *key;
		struct ctdb_traverse_start_ext *traverse_start_ext;
		struct ctdb_traverse_all_ext *traverse_all_ext;
		struct ctdb_pid_srvid *pid_srvid;
		struct ctdb_db_vacuum *db_vacuum;
		struct ctdb_echo_data *echo_data;
	} data;
};

struct ctdb_reply_control_data {
	uint32_t opcode;
	union {
		struct ctdb_statistics *stats;
		const char *db_path;
		struct ctdb_vnn_map *vnnmap;
		uint32_t loglevel;
		struct ctdb_dbid_map *dbmap;
		struct ctdb_rec_buffer *recbuf;
		uint32_t db_id;
		const char *db_name;
		const char *mem_str;
		uint32_t tun_value;
		struct ctdb_var_list *tun_var_list;
		struct ctdb_tunable_list *tun_list;
		struct ctdb_tickle_list *tickles;
		struct ctdb_client_id_map *cid_map;
		struct ctdb_uptime *uptime;
		uint32_t caps;
		struct ctdb_public_ip_list *pubip_list;
		struct ctdb_node_map *nodemap;
		const char *reclock_file;
		struct ctdb_ban_state *ban_state;
		uint64_t seqnum;
		const char *reason;
		struct ctdb_public_ip_info *ipinfo;
		struct ctdb_iface_list *iface_list;
		struct ctdb_statistics_list *stats_list;
		struct ctdb_db_statistics *dbstats;
		enum ctdb_runstate runstate;
		uint32_t num_records;
		int tdb_flags;
		struct ctdb_echo_data *echo_data;
	} data;
};

struct ctdb_req_control {
	uint32_t opcode;
	uint32_t pad;
	uint64_t srvid;
	uint32_t client_id;
#define CTDB_CTRL_FLAG_NOREPLY   1
#define CTDB_CTRL_FLAG_OPCODE_SPECIFIC   0xFFFF0000
/* Ugly overloading of this field... */
#define CTDB_PUBLIC_IP_FLAGS_ONLY_AVAILABLE 0x00010000
#define CTDB_CTRL_FLAG_ATTACH_RECOVERY      0x00020000
	uint32_t flags;
	struct ctdb_req_control_data rdata;
};

struct ctdb_reply_control {
	int32_t status;
	const char *errmsg;
	struct ctdb_reply_control_data rdata;
};

struct ctdb_election_message {
	uint32_t num_connected;
	struct timeval priority_time;
	uint32_t pnn;
	uint32_t node_flags;
};

struct ctdb_srvid_message {
	uint32_t pnn;
	uint64_t srvid;
};

struct ctdb_disable_message {
	uint32_t pnn;
	uint64_t srvid;
	uint32_t timeout;
};

union ctdb_message_data {
	/* SRVID_ELECTION */
	struct ctdb_election_message *election;
	/* SRVID_RELEASE_IP, SRVID_TAKE_IP */
	const char *ipaddr;
	/* SRVID_SET_NODE_FLAGS, SERVID_PUSH_NODE_FLAGS */
	struct ctdb_node_flag_change *flag_change;
	/* SRVID_RECD_UPDATE_IP */
	struct ctdb_public_ip *pubip;
	/* SRVID_VACUUM_FETCH */
	struct ctdb_rec_buffer *recbuf;
	/* SRVID_DETACH_DATABASE */
	uint32_t db_id;
	/* SRVID_MEM_DUMP, SRVID_TAKEOVER_RUN */
	struct ctdb_srvid_message *msg;
	/* SRVID_BANNING, SRVID_REBALANCE_NODE */
	uint32_t pnn;
	/* SRVID_DISABLE_TAKEOVER_RUNS, SRVID_DISABLE_RECOVERIES */
	struct ctdb_disable_message *disable;
	/* SRVID_DISABLE_IP_CHECK */
	uint32_t timeout;
	/* Other */
	TDB_DATA data;
};

struct ctdb_req_message {
	uint64_t srvid;
	union ctdb_message_data data;
};

struct ctdb_req_message_data {
	uint64_t srvid;
	TDB_DATA data;
};

struct ctdb_req_keepalive {
	uint32_t version;
	uint32_t uptime;
};

#define CTDB_TUNNEL_TEST	0xffffffff00000000

#define CTDB_TUNNEL_FLAG_REQUEST	0x00000001
#define CTDB_TUNNEL_FLAG_REPLY		0x00000002
#define CTDB_TUNNEL_FLAG_NOREPLY	0x00000010

struct ctdb_req_tunnel {
	uint64_t tunnel_id;
	uint32_t flags;
	TDB_DATA data;
};


/* This is equivalent to server_id */
struct ctdb_server_id {
	uint64_t pid;
	uint32_t task_id;
	uint32_t vnn;
	uint64_t unique_id;
};

enum ctdb_g_lock_type {
	CTDB_G_LOCK_READ = 0,
	CTDB_G_LOCK_WRITE = 1,
};

struct ctdb_g_lock {
	enum ctdb_g_lock_type type;
	struct ctdb_server_id sid;
};

struct ctdb_g_lock_list {
	unsigned int num;
	struct ctdb_g_lock *lock;
};

/*
 * Generic packet header
 */

struct sock_packet_header {
	uint32_t length;
	uint32_t reqid;
};

#endif /* __CTDB_PROTOCOL_H__ */
