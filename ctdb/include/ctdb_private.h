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

#ifndef _CTDB_PRIVATE_H
#define _CTDB_PRIVATE_H

#include "ctdb.h"
#include <sys/socket.h>

/* location of daemon socket */
#define CTDB_PATH	"/tmp/ctdb.socket"

/* default ctdb port number */
#define CTDB_PORT 4379

/* we must align packets to ensure ctdb works on all architectures (eg. sparc) */
#define CTDB_DS_ALIGNMENT 8


#define CTDB_NULL_FUNC      0xFF000001
#define CTDB_FETCH_FUNC     0xFF000002


/*
  recovery daemon memdump reply address
 */
struct rd_memdump_reply {
	uint32_t pnn;
	uint64_t srvid;
};

/*
  a tcp connection description
 */
struct ctdb_tcp_connection {
	ctdb_sock_addr src_addr;
	ctdb_sock_addr dst_addr;
};

/* the wire representation for a tcp tickle array */
struct ctdb_tcp_wire_array {
	uint32_t num;
	struct ctdb_tcp_connection connections[1];
};	

/* the list of tcp tickles used by get/set tcp tickle list */
struct ctdb_control_tcp_tickle_list {
	ctdb_sock_addr addr;
	struct ctdb_tcp_wire_array tickles;
};

/*
  array of tcp connections
 */
struct ctdb_tcp_array {
	uint32_t num;
	struct ctdb_tcp_connection *connections;
};	


/* all tunable variables go in here */
struct ctdb_tunable {
	uint32_t max_redirect_count;
	uint32_t seqnum_frequency;
	uint32_t control_timeout;
	uint32_t traverse_timeout;
	uint32_t keepalive_interval;
	uint32_t keepalive_limit;
	uint32_t max_lacount;
	uint32_t recover_timeout;
	uint32_t recover_interval;
	uint32_t election_timeout;
	uint32_t takeover_timeout;
	uint32_t monitor_interval;
	uint32_t tickle_update_interval;
	uint32_t script_timeout;
	uint32_t script_ban_count; /* ban after this many consec timeouts*/
	uint32_t recovery_grace_period;
	uint32_t recovery_ban_period;
	uint32_t database_hash_size;
	uint32_t database_max_dead;
	uint32_t rerecovery_timeout;
	uint32_t enable_bans;
	uint32_t deterministic_public_ips;
	uint32_t disable_when_unhealthy;
	uint32_t reclock_ping_period;
	uint32_t no_ip_failback;
	uint32_t verbose_memory_names;
	uint32_t recd_ping_timeout;
	uint32_t recd_ping_failcount;
	uint32_t log_latency_ms;
};

/*
  an installed ctdb remote call
*/
struct ctdb_registered_call {
	struct ctdb_registered_call *next, *prev;
	uint32_t id;
	ctdb_fn_t fn;
};

/*
  this address structure might need to be generalised later for some
  transports
*/
struct ctdb_address {
	const char *address;
	int port;
};

/*
  check that a pnn is valid
 */
#define ctdb_validate_pnn(ctdb, pnn) (((uint32_t)(pnn)) < (ctdb)->num_nodes)


/* called from the queue code when a packet comes in. Called with data==NULL
   on error */
typedef void (*ctdb_queue_cb_fn_t)(uint8_t *data, size_t length,
				   void *private_data);

/* used for callbacks in ctdb_control requests */
typedef void (*ctdb_control_callback_fn_t)(struct ctdb_context *,
					   int32_t status, TDB_DATA data, 
					   const char *errormsg,
					   void *private_data);

/*
  structure describing a connected client in the daemon
 */
struct ctdb_client {
	struct ctdb_context *ctdb;
	int fd;
	struct ctdb_queue *queue;
	uint32_t client_id;
	pid_t pid;
	struct ctdb_tcp_list *tcp_list;
	uint32_t num_persistent_updates;
};


/* state associated with a public ip address */
struct ctdb_vnn {
	struct ctdb_vnn *prev, *next;

	const char *iface;
	ctdb_sock_addr public_address;
	uint8_t public_netmask_bits;

	/* the node number that is serving this public address, if any. 
	   If no node serves this ip it is set to -1 */
	int32_t pnn;

	/* List of clients to tickle for this public address */
	struct ctdb_tcp_array *tcp_array;

	/* whether we need to update the other nodes with changes to our list
	   of connected clients */
	bool tcp_update_needed;

	/* a context to hang sending gratious arp events off */
	TALLOC_CTX *takeover_ctx;

	struct ctdb_kill_tcp *killtcp;
};

/*
  state associated with one node
*/
struct ctdb_node {
	struct ctdb_context *ctdb;
	struct ctdb_address address;
	const char *name; /* for debug messages */
	void *private_data; /* private to transport */
	uint32_t pnn;
#define NODE_FLAGS_DISCONNECTED		0x00000001 /* node isn't connected */
#define NODE_FLAGS_UNHEALTHY  		0x00000002 /* monitoring says node is unhealthy */
#define NODE_FLAGS_PERMANENTLY_DISABLED	0x00000004 /* administrator has disabled node */
#define NODE_FLAGS_BANNED		0x00000008 /* recovery daemon has banned the node */
#define NODE_FLAGS_DISABLED		(NODE_FLAGS_UNHEALTHY|NODE_FLAGS_PERMANENTLY_DISABLED)
#define NODE_FLAGS_INACTIVE		(NODE_FLAGS_DISCONNECTED|NODE_FLAGS_BANNED)
	uint32_t flags;

	/* used by the dead node monitoring */
	uint32_t dead_count;
	uint32_t rx_cnt;
	uint32_t tx_cnt;

	/* used to track node capabilities, is only valid/tracked inside the
	   recovery daemon.
	*/
	uint32_t capabilities;

	/* a list of controls pending to this node, so we can time them out quickly
	   if the node becomes disconnected */
	struct daemon_control_state *pending_controls;

	/* used by the recovery daemon when distributing ip addresses 
	   across the nodes.  it needs to know which public ip's can be handled
	   by each node.
	*/
	struct ctdb_all_public_ips *public_ips;
};

/*
  transport specific methods
*/
struct ctdb_methods {
	int (*initialise)(struct ctdb_context *); /* initialise transport structures */	
	int (*start)(struct ctdb_context *); /* start the transport */
	int (*add_node)(struct ctdb_node *); /* setup a new node */	
	int (*connect_node)(struct ctdb_node *); /* connect to node */
	int (*queue_pkt)(struct ctdb_node *, uint8_t *data, uint32_t length);
	void *(*allocate_pkt)(TALLOC_CTX *mem_ctx, size_t );
	void (*shutdown)(struct ctdb_context *); /* shutdown transport */
	void (*restart)(struct ctdb_node *); /* stop and restart the connection */
};

/*
  transport calls up to the ctdb layer
*/
struct ctdb_upcalls {
	/* recv_pkt is called when a packet comes in */
	void (*recv_pkt)(struct ctdb_context *, uint8_t *data, uint32_t length);

	/* node_dead is called when an attempt to send to a node fails */
	void (*node_dead)(struct ctdb_node *);

	/* node_connected is called when a connection to a node is established */
	void (*node_connected)(struct ctdb_node *);
};

/* list of message handlers - needs to be changed to a more efficient data
   structure so we can find a message handler given a srvid quickly */
struct ctdb_message_list {
	struct ctdb_context *ctdb;
	struct ctdb_message_list *next, *prev;
	uint64_t srvid;
	ctdb_message_fn_t message_handler;
	void *message_private;
};

/* additional data required for the daemon mode */
struct ctdb_daemon_data {
	int sd;
	char *name;
	struct ctdb_queue *queue;
};

/*
  ctdb status information
 */
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
	uint32_t total_calls;
	uint32_t pending_calls;
	uint32_t lockwait_calls;
	uint32_t pending_lockwait_calls;
	uint32_t childwrite_calls;
	uint32_t pending_childwrite_calls;
	uint32_t memory_used;
	uint32_t __last_counter; /* hack for control_statistics_all */
	uint32_t max_hop_count;
	double max_call_latency;
	double max_lockwait_latency;
	double max_childwrite_latency;
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

/* a structure that contains the elements required for the write record
   control
*/
struct ctdb_write_record {
	uint32_t dbid;
	uint32_t keylen;
	uint32_t datalen;
	unsigned char blob[1];
};

enum ctdb_freeze_mode {CTDB_FREEZE_NONE, CTDB_FREEZE_PENDING, CTDB_FREEZE_FROZEN};

#define CTDB_MONITORING_ACTIVE		0
#define CTDB_MONITORING_DISABLED	1

/* The different capabilities of the ctdb daemon. */
#define CTDB_CAP_RECMASTER		0x00000001
#define CTDB_CAP_LMASTER		0x00000002
/* This capability is set if CTDB_LVS_PUBLIC_IP is set */
#define CTDB_CAP_LVS			0x00000004

/* main state of the ctdb daemon */
struct ctdb_context {
	struct event_context *ev;
	struct timeval ctdbd_start_time;
	struct timeval last_recovery_started;
	struct timeval last_recovery_finished;
	uint32_t recovery_mode;
	TALLOC_CTX *tickle_update_context;
	TALLOC_CTX *keepalive_ctx;
	struct ctdb_tunable tunable;
	enum ctdb_freeze_mode freeze_mode;
	struct ctdb_freeze_handle *freeze_handle;
	struct ctdb_address address;
	const char *name;
	const char *db_directory;
	const char *db_directory_persistent;
	const char *transport;
	const char *logfile;
	char *node_list_file;
	char *recovery_lock_file;
	int recovery_lock_fd;
	uint32_t pnn; /* our own pnn */
	uint32_t num_nodes;
	uint32_t num_connected;
	unsigned flags;
	uint32_t capabilities;
	struct idr_context *idr;
	uint16_t idr_cnt;
	struct ctdb_node **nodes; /* array of nodes in the cluster - indexed by vnn */
	struct ctdb_vnn *vnn; /* list of public ip addresses and interfaces */
	struct ctdb_vnn *single_ip_vnn; /* a structure for the single ip */
	char *err_msg;
	const struct ctdb_methods *methods; /* transport methods */
	const struct ctdb_upcalls *upcalls; /* transport upcalls */
	void *private_data; /* private to transport */
	struct ctdb_db_context *db_list;
	struct ctdb_message_list *message_list;
	struct ctdb_daemon_data daemon;
	struct ctdb_statistics statistics;
	struct ctdb_vnn_map *vnn_map;
	uint32_t num_clients;
	uint32_t recovery_master;
	struct ctdb_call_state *pending_calls;
	struct ctdb_client_ip *client_ip_list;
	bool do_setsched;
	bool do_checkpublicip;
	void *saved_scheduler_param;
	struct _trbt_tree_t *server_ids;	
	const char *event_script_dir;
	const char *default_public_interface;
	pid_t ctdbd_pid;
	pid_t recoverd_pid;
	bool done_startup;
	const char *node_ip;
	struct ctdb_monitor_state *monitor;
	struct ctdb_log_state *log;
	int start_as_disabled;
	uint32_t event_script_timeouts; /* counting how many consecutive times an eventscript has timedout */
	TALLOC_CTX *eventscripts_ctx; /* a context to hold data for the RUN_EVENTSCRIPTS control */
	uint32_t *recd_ping_count;
	TALLOC_CTX *release_ips_ctx; /* a context used to automatically drop all IPs if we fail to recover the node */
	TALLOC_CTX *script_monitoring_ctx; /* a context where we store results while running the monitor event */
	TALLOC_CTX *last_monitoring_ctx; 
};

struct ctdb_db_context {
	struct ctdb_db_context *next, *prev;
	struct ctdb_context *ctdb;
	uint32_t db_id;
	bool persistent;
	const char *db_name;
	const char *db_path;
	struct tdb_wrap *ltdb;
	struct ctdb_registered_call *calls; /* list of registered calls */
	uint32_t seqnum;
	struct timed_event *te;
};


#define CTDB_NO_MEMORY(ctdb, p) do { if (!(p)) { \
          DEBUG(0,("Out of memory for %s at %s\n", #p, __location__)); \
          ctdb_set_error(ctdb, "Out of memory at %s:%d", __FILE__, __LINE__); \
	  return -1; }} while (0)

#define CTDB_NO_MEMORY_VOID(ctdb, p) do { if (!(p)) { \
          DEBUG(0,("Out of memory for %s at %s\n", #p, __location__)); \
          ctdb_set_error(ctdb, "Out of memory at %s:%d", __FILE__, __LINE__); \
	  return; }} while (0)

#define CTDB_NO_MEMORY_NULL(ctdb, p) do { if (!(p)) { \
          DEBUG(0,("Out of memory for %s at %s\n", #p, __location__)); \
          ctdb_set_error(ctdb, "Out of memory at %s:%d", __FILE__, __LINE__); \
	  return NULL; }} while (0)

#define CTDB_NO_MEMORY_FATAL(ctdb, p) do { if (!(p)) { \
          DEBUG(0,("Out of memory for %s at %s\n", #p, __location__)); \
          ctdb_fatal(ctdb, "Out of memory in " __location__ ); \
	  }} while (0)

/*
  the extended header for records in the ltdb
*/
struct ctdb_ltdb_header {
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t laccessor;
	uint32_t lacount;
};

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
		    CTDB_CONTROL_EVENT_SCRIPT_INIT       = 92,
		    CTDB_CONTROL_EVENT_SCRIPT_START      = 93,
		    CTDB_CONTROL_EVENT_SCRIPT_STOP       = 94,
		    CTDB_CONTROL_EVENT_SCRIPT_FINISHED   = 95,
		    CTDB_CONTROL_GET_EVENT_SCRIPT_STATUS = 96,
};	

/*
  structure passed in set_call control
 */
struct ctdb_control_set_call {
	uint32_t db_id;
	ctdb_fn_t fn;
	uint32_t id;
};

/*
  struct for kill_tcp control
 */
struct ctdb_control_killtcp {
	ctdb_sock_addr src_addr;
	ctdb_sock_addr dst_addr;
};

/*
  struct holding a ctdb_sock_addr and an interface name,
  used to add/remove public addresses
 */
struct ctdb_control_ip_iface {
	ctdb_sock_addr addr;
	uint32_t mask;
	uint32_t len;
	char iface[1];
};

/*
  struct holding a ctdb_sock_addr and an interface name,
  used for send_gratious_arp
 */
struct ctdb_control_gratious_arp {
	ctdb_sock_addr addr;
	uint32_t mask;
	uint32_t len;
	char iface[1];
};

/*
  struct for tcp_add and tcp_remove controls
 */
struct ctdb_control_tcp_vnn {
	ctdb_sock_addr src;
	ctdb_sock_addr dest;
};

/*
  persistent store control - update this record on all other nodes
 */
struct ctdb_control_persistent_store {
	uint32_t db_id;
	uint32_t len;
	uint8_t  data[1];
};

/*
  structure used for CTDB_SRVID_NODE_FLAGS_CHANGED
 */
struct ctdb_node_flag_change {
	uint32_t pnn;
	uint32_t new_flags;
	uint32_t old_flags;
};

/*
  struct for admin setting a ban
 */
struct ctdb_ban_info {
	uint32_t pnn;
	uint32_t ban_time;
};

enum call_state {CTDB_CALL_WAIT, CTDB_CALL_DONE, CTDB_CALL_ERROR};

#define CTDB_LMASTER_ANY	0xffffffff

/*
  state of a in-progress ctdb call
*/
struct ctdb_call_state {
	struct ctdb_call_state *next, *prev;
	enum call_state state;
	uint32_t reqid;
	struct ctdb_req_call *c;
	struct ctdb_db_context *ctdb_db;
	const char *errmsg;
	struct ctdb_call *call;
	uint32_t generation;
	struct {
		void (*fn)(struct ctdb_call_state *);
		void *private_data;
	} async;
};


/* used for fetch_lock */
struct ctdb_fetch_handle {
	struct ctdb_db_context *ctdb_db;
	TDB_DATA key;
	TDB_DATA *data;
	struct ctdb_ltdb_header header;
};

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
	uint64_t srvid;
	uint32_t client_id;
#define CTDB_CTRL_FLAG_NOREPLY   1
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


/* internal prototypes */
void ctdb_set_error(struct ctdb_context *ctdb, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);
void ctdb_fatal(struct ctdb_context *ctdb, const char *msg);
bool ctdb_same_address(struct ctdb_address *a1, struct ctdb_address *a2);
int ctdb_parse_address(struct ctdb_context *ctdb,
		       TALLOC_CTX *mem_ctx, const char *str,
		       struct ctdb_address *address);
bool ctdb_same_ip(const ctdb_sock_addr *ip1, const ctdb_sock_addr *ip2);
bool ctdb_same_sockaddr(const ctdb_sock_addr *ip1, const ctdb_sock_addr *ip2);
uint32_t ctdb_hash(const TDB_DATA *key);
uint32_t ctdb_hash_string(const char *str);
void ctdb_request_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_request_dmaster(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_request_message(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_dmaster(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_error(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);

uint32_t ctdb_lmaster(struct ctdb_context *ctdb, const TDB_DATA *key);
int ctdb_ltdb_fetch(struct ctdb_db_context *ctdb_db, 
		    TDB_DATA key, struct ctdb_ltdb_header *header, 
		    TALLOC_CTX *mem_ctx, TDB_DATA *data);
int ctdb_ltdb_store(struct ctdb_db_context *ctdb_db, TDB_DATA key, 
		    struct ctdb_ltdb_header *header, TDB_DATA data);
int32_t ctdb_control_start_persistent_update(struct ctdb_context *ctdb, 
			struct ctdb_req_control *c,
			TDB_DATA recdata);
int32_t ctdb_control_cancel_persistent_update(struct ctdb_context *ctdb, 
			struct ctdb_req_control *c,
			TDB_DATA recdata);
void ctdb_queue_packet(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_queue_packet_opcode(struct ctdb_context *ctdb, struct ctdb_req_header *hdr, unsigned opcode);
int ctdb_ltdb_lock_requeue(struct ctdb_db_context *ctdb_db, 
			   TDB_DATA key, struct ctdb_req_header *hdr,
			   void (*recv_pkt)(void *, struct ctdb_req_header *),
			   void *recv_context, bool ignore_generation);
int ctdb_ltdb_lock_fetch_requeue(struct ctdb_db_context *ctdb_db, 
				 TDB_DATA key, struct ctdb_ltdb_header *header, 
				 struct ctdb_req_header *hdr, TDB_DATA *data,
				 void (*recv_pkt)(void *, struct ctdb_req_header *),
				 void *recv_context, bool ignore_generation);
void ctdb_input_pkt(struct ctdb_context *ctdb, struct ctdb_req_header *);

struct ctdb_call_state *ctdb_call_local_send(struct ctdb_db_context *ctdb_db, 
					     struct ctdb_call *call,
					     struct ctdb_ltdb_header *header,
					     TDB_DATA *data);


int ctdbd_start(struct ctdb_context *ctdb);
struct ctdb_call_state *ctdbd_call_send(struct ctdb_db_context *ctdb_db, struct ctdb_call *call);
int ctdbd_call_recv(struct ctdb_call_state *state, struct ctdb_call *call);

/*
  queue a packet for sending
*/
int ctdb_queue_send(struct ctdb_queue *queue, uint8_t *data, uint32_t length);

/*
  setup the fd used by the queue
 */
int ctdb_queue_set_fd(struct ctdb_queue *queue, int fd);

/*
  setup a packet queue on a socket
 */
struct ctdb_queue *ctdb_queue_setup(struct ctdb_context *ctdb,
				    TALLOC_CTX *mem_ctx, int fd, int alignment,
				    
				    ctdb_queue_cb_fn_t callback,
				    void *private_data);

/*
  allocate a packet for use in client<->daemon communication
 */
struct ctdb_req_header *_ctdbd_allocate_pkt(struct ctdb_context *ctdb,
					    TALLOC_CTX *mem_ctx, 
					    enum ctdb_operation operation, 
					    size_t length, size_t slength,
					    const char *type);
#define ctdbd_allocate_pkt(ctdb, mem_ctx, operation, length, type) \
	(type *)_ctdbd_allocate_pkt(ctdb, mem_ctx, operation, length, sizeof(type), #type)

struct ctdb_req_header *_ctdb_transport_allocate(struct ctdb_context *ctdb,
						 TALLOC_CTX *mem_ctx, 
						 enum ctdb_operation operation, 
						 size_t length, size_t slength,
						 const char *type);
#define ctdb_transport_allocate(ctdb, mem_ctx, operation, length, type) \
	(type *)_ctdb_transport_allocate(ctdb, mem_ctx, operation, length, sizeof(type), #type)


/*
  lock a record in the ltdb, given a key
 */
int ctdb_ltdb_lock(struct ctdb_db_context *ctdb_db, TDB_DATA key);

/*
  unlock a record in the ltdb, given a key
 */
int ctdb_ltdb_unlock(struct ctdb_db_context *ctdb_db, TDB_DATA key);


/*
  make a ctdb call to the local daemon - async send. Called from client context.

  This constructs a ctdb_call request and queues it for processing. 
  This call never blocks.
*/
struct ctdb_call_state *ctdb_client_call_send(struct ctdb_db_context *ctdb_db, 
					      struct ctdb_call *call);

/*
  make a recv call to the local ctdb daemon - called from client context

  This is called when the program wants to wait for a ctdb_call to complete and get the 
  results. This call will block unless the call has already completed.
*/
int ctdb_client_call_recv(struct ctdb_call_state *state, struct ctdb_call *call);

int ctdb_daemon_set_message_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     ctdb_message_fn_t handler,
			     void *private_data);

int ctdb_client_send_message(struct ctdb_context *ctdb, uint32_t vnn,
			     uint64_t srvid, TDB_DATA data);

/*
  send a ctdb message
*/
int ctdb_daemon_send_message(struct ctdb_context *ctdb, uint32_t pnn,
			     uint64_t srvid, TDB_DATA data);


struct lockwait_handle *ctdb_lockwait(struct ctdb_db_context *ctdb_db,
				      TDB_DATA key,
				      void (*callback)(void *), void *private_data);

struct ctdb_call_state *ctdb_daemon_call_send(struct ctdb_db_context *ctdb_db, 
					      struct ctdb_call *call);

int ctdb_daemon_call_recv(struct ctdb_call_state *state, struct ctdb_call *call);

struct ctdb_call_state *ctdb_daemon_call_send_remote(struct ctdb_db_context *ctdb_db, 
						     struct ctdb_call *call, 
						     struct ctdb_ltdb_header *header);

int ctdb_call_local(struct ctdb_db_context *ctdb_db, struct ctdb_call *call,
		    struct ctdb_ltdb_header *header, TALLOC_CTX *mem_ctx, TDB_DATA *data,
		    uint32_t caller);

#define ctdb_reqid_find(ctdb, reqid, type)	(type *)_ctdb_reqid_find(ctdb, reqid, #type, __location__)

void ctdb_recv_raw_pkt(void *p, uint8_t *data, uint32_t length);

int ctdb_socket_connect(struct ctdb_context *ctdb);

void ctdb_latency(struct ctdb_db_context *ctdb_db, const char *name, double *latency, struct timeval t);

uint32_t ctdb_reqid_new(struct ctdb_context *ctdb, void *state);
void *_ctdb_reqid_find(struct ctdb_context *ctdb, uint32_t reqid, const char *type, const char *location);
void ctdb_reqid_remove(struct ctdb_context *ctdb, uint32_t reqid);

void ctdb_request_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);

int ctdb_daemon_send_control(struct ctdb_context *ctdb, uint32_t destnode,
			     uint64_t srvid, uint32_t opcode, uint32_t client_id, uint32_t flags,
			     TDB_DATA data,
			     ctdb_control_callback_fn_t callback,
			     void *private_data);

int32_t ctdb_control_db_attach(struct ctdb_context *ctdb, TDB_DATA indata, 
			       TDB_DATA *outdata, uint64_t tdb_flags, bool persistent);

int ctdb_daemon_set_call(struct ctdb_context *ctdb, uint32_t db_id,
			 ctdb_fn_t fn, int id);

int ctdb_control(struct ctdb_context *ctdb, uint32_t destnode, uint64_t srvid, 
		 uint32_t opcode, uint32_t flags, TDB_DATA data, 
		 TALLOC_CTX *mem_ctx, TDB_DATA *outdata, int32_t *status,
		 struct timeval *timeout, char **errormsg);
int ctdb_control_recv(struct ctdb_context *ctdb, 
		struct ctdb_client_control_state *state, 
		TALLOC_CTX *mem_ctx,
		TDB_DATA *outdata, int32_t *status, char **errormsg);

struct ctdb_client_control_state *
ctdb_control_send(struct ctdb_context *ctdb, 
		uint32_t destnode, uint64_t srvid, 
		uint32_t opcode, uint32_t flags, TDB_DATA data, 
		TALLOC_CTX *mem_ctx,
		struct timeval *timeout,
		char **errormsg);




#define CHECK_CONTROL_DATA_SIZE(size) do { \
 if (indata.dsize != size) { \
	 DEBUG(0,(__location__ " Invalid data size in opcode %u. Got %u expected %u\n", \
		  opcode, (unsigned)indata.dsize, (unsigned)size));	\
	 return -1; \
 } \
 } while (0)

int ctdb_control_getvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata);
int ctdb_control_setvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata);
int ctdb_control_getdbmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata);
int ctdb_control_getnodemapv4(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata);
int ctdb_control_getnodemap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata);
int ctdb_control_writerecord(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata);


struct ctdb_traverse_start {
	uint32_t db_id;
	uint32_t reqid;
	uint64_t srvid;
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
				   

/* structure used for pulldb control */
struct ctdb_control_pulldb {
	uint32_t db_id;
	uint32_t lmaster;
};

/* structure used for sending lists of records */
struct ctdb_marshall_buffer {
	uint32_t db_id;
	uint32_t count;
	uint8_t data[1];
};

/* set dmaster control structure */
struct ctdb_control_set_dmaster {
	uint32_t db_id;
	uint32_t dmaster;
};

/*
  structure for setting a tunable
 */
struct ctdb_control_set_tunable {
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


/* table that contains a list of all nodes a ctdb knows about and their 
   status
 */
struct ctdb_node_and_flags {
	uint32_t pnn;
	uint32_t flags;
	ctdb_sock_addr addr;
};

struct ctdb_node_map {
	uint32_t num;
	struct ctdb_node_and_flags nodes[1];
};

struct ctdb_node_and_flagsv4 {
	uint32_t pnn;
	uint32_t flags;
	struct sockaddr_in sin;
};

struct ctdb_node_mapv4 {
	uint32_t num;
	struct ctdb_node_and_flagsv4 nodes[1];
};

struct ctdb_control_wipe_database {
	uint32_t db_id;
	uint32_t transaction_id;
};

/*
  state of a in-progress ctdb call in client
*/
struct ctdb_client_call_state {
	enum call_state state;
	uint32_t reqid;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_call *call;
	struct {
		void (*fn)(struct ctdb_client_call_state *);
		void *private_data;
	} async;
};


int32_t ctdb_control_traverse_start(struct ctdb_context *ctdb, TDB_DATA indata, 
				    TDB_DATA *outdata, uint32_t srcnode);
int32_t ctdb_control_traverse_all(struct ctdb_context *ctdb, TDB_DATA data, TDB_DATA *outdata);
int32_t ctdb_control_traverse_data(struct ctdb_context *ctdb, TDB_DATA data, TDB_DATA *outdata);

int ctdb_dispatch_message(struct ctdb_context *ctdb, uint64_t srvid, TDB_DATA data);

int daemon_register_message_handler(struct ctdb_context *ctdb, uint32_t client_id, uint64_t srvid);
int ctdb_deregister_message_handler(struct ctdb_context *ctdb, uint64_t srvid, void *private_data);
int daemon_deregister_message_handler(struct ctdb_context *ctdb, uint32_t client_id, uint64_t srvid);

int32_t ctdb_ltdb_enable_seqnum(struct ctdb_context *ctdb, uint32_t db_id);
int32_t ctdb_ltdb_update_seqnum(struct ctdb_context *ctdb, uint32_t db_id, uint32_t srcnode);
int32_t ctdb_ltdb_set_seqnum_frequency(struct ctdb_context *ctdb, uint32_t frequency);

struct ctdb_rec_data *ctdb_marshall_record(TALLOC_CTX *mem_ctx, uint32_t reqid,	
					   TDB_DATA key, struct ctdb_ltdb_header *, TDB_DATA data);

struct ctdb_rec_data *ctdb_marshall_loop_next(struct ctdb_marshall_buffer *m, struct ctdb_rec_data *r,
					      uint32_t *reqid,
					      struct ctdb_ltdb_header *header,
					      TDB_DATA *key, TDB_DATA *data);

int32_t ctdb_control_pull_db(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata);
int32_t ctdb_control_push_db(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_set_dmaster(struct ctdb_context *ctdb, TDB_DATA indata);

int32_t ctdb_control_set_recmode(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 TDB_DATA indata, bool *async_reply,
				 const char **errormsg);
void ctdb_request_control_reply(struct ctdb_context *ctdb, struct ctdb_req_control *c,
				TDB_DATA *outdata, int32_t status, const char *errormsg);

int32_t ctdb_control_freeze(struct ctdb_context *ctdb, struct ctdb_req_control *c, bool *async_reply);
int32_t ctdb_control_thaw(struct ctdb_context *ctdb);

int ctdb_start_recoverd(struct ctdb_context *ctdb);
void ctdb_stop_recoverd(struct ctdb_context *ctdb);

uint32_t ctdb_get_num_active_nodes(struct ctdb_context *ctdb);

void ctdb_disable_monitoring(struct ctdb_context *ctdb);
void ctdb_enable_monitoring(struct ctdb_context *ctdb);
void ctdb_stop_monitoring(struct ctdb_context *ctdb);
void ctdb_start_monitoring(struct ctdb_context *ctdb);
void ctdb_start_tcp_tickle_update(struct ctdb_context *ctdb);
void ctdb_send_keepalive(struct ctdb_context *ctdb, uint32_t destnode);
void ctdb_start_keepalive(struct ctdb_context *ctdb);
void ctdb_stop_keepalive(struct ctdb_context *ctdb);
int32_t ctdb_run_eventscripts(struct ctdb_context *ctdb, struct ctdb_req_control *c, TDB_DATA data, bool *async_reply);


void ctdb_daemon_cancel_controls(struct ctdb_context *ctdb, struct ctdb_node *node);
void ctdb_call_resend_all(struct ctdb_context *ctdb);
void ctdb_node_dead(struct ctdb_node *node);
void ctdb_node_connected(struct ctdb_node *node);
bool ctdb_blocking_freeze(struct ctdb_context *ctdb);
void ctdb_set_scheduler(struct ctdb_context *ctdb);
void ctdb_restore_scheduler(struct ctdb_context *ctdb);
int32_t ctdb_control_takeover_ip(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 TDB_DATA indata, 
				 bool *async_reply);
int32_t ctdb_control_takeover_ipv4(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 TDB_DATA indata, 
				 bool *async_reply);
int32_t ctdb_control_release_ip(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 TDB_DATA indata, 
				 bool *async_reply);
int32_t ctdb_control_release_ipv4(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 TDB_DATA indata, 
				 bool *async_reply);
int32_t ctdb_control_start_recovery(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 bool *async_reply);
int32_t ctdb_control_end_recovery(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 bool *async_reply);

struct ctdb_public_ipv4 {
	uint32_t pnn;
	struct sockaddr_in sin;
};

struct ctdb_public_ip {
	uint32_t pnn;
	ctdb_sock_addr addr;
};
int ctdb_ctrl_takeover_ip(struct ctdb_context *ctdb, struct timeval timeout, 
			  uint32_t destnode, struct ctdb_public_ip *ip);
int ctdb_ctrl_release_ip(struct ctdb_context *ctdb, struct timeval timeout, 
			 uint32_t destnode, struct ctdb_public_ip *ip);

struct ctdb_all_public_ipsv4 {
	uint32_t num;
	struct ctdb_public_ipv4 ips[1];
};

struct ctdb_all_public_ips {
	uint32_t num;
	struct ctdb_public_ip ips[1];
};
int32_t ctdb_control_get_public_ipsv4(struct ctdb_context *ctdb, struct ctdb_req_control *c, TDB_DATA *outdata);
int32_t ctdb_control_get_public_ips(struct ctdb_context *ctdb, struct ctdb_req_control *c, TDB_DATA *outdata);
int ctdb_ctrl_get_public_ips(struct ctdb_context *ctdb, 
			struct timeval timeout, uint32_t destnode, 
			TALLOC_CTX *mem_ctx, struct ctdb_all_public_ips **ips);
int ctdb_ctrl_get_public_ipsv4(struct ctdb_context *ctdb, 
			struct timeval timeout, uint32_t destnode, 
			TALLOC_CTX *mem_ctx, struct ctdb_all_public_ips **ips);


/* from takeover/system.c */
int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface);
bool ctdb_sys_have_ip(ctdb_sock_addr *addr);
int ctdb_sys_send_tcp(const ctdb_sock_addr *dest, 
		      const ctdb_sock_addr *src,
		      uint32_t seq, uint32_t ack, int rst);

int ctdb_set_public_addresses(struct ctdb_context *ctdb, const char *alist);
int ctdb_set_event_script(struct ctdb_context *ctdb, const char *script);
int ctdb_set_event_script_dir(struct ctdb_context *ctdb, const char *script_dir);
int ctdb_takeover_run(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap);

int32_t ctdb_control_tcp_client(struct ctdb_context *ctdb, uint32_t client_id, 
				TDB_DATA indata);
int32_t ctdb_control_tcp_add(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_tcp_remove(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_startup(struct ctdb_context *ctdb, uint32_t vnn);
int32_t ctdb_control_kill_tcp(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_send_gratious_arp(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_get_tcp_tickle_list(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata);
int32_t ctdb_control_set_tcp_tickle_list(struct ctdb_context *ctdb, TDB_DATA indata);

void ctdb_takeover_client_destructor_hook(struct ctdb_client *client);
int ctdb_event_script(struct ctdb_context *ctdb, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);
int ctdb_event_script_callback(struct ctdb_context *ctdb, 
			       struct timeval timeout,
			       TALLOC_CTX *mem_ctx,
			       void (*callback)(struct ctdb_context *, int, void *),
			       void *private_data,
			       const char *fmt, ...) PRINTF_ATTRIBUTE(6,7);
void ctdb_release_all_ips(struct ctdb_context *ctdb);

void set_nonblocking(int fd);
void set_close_on_exec(int fd);

bool ctdb_recovery_lock(struct ctdb_context *ctdb, bool keep);

int ctdb_set_recovery_lock_file(struct ctdb_context *ctdb, const char *file);

int32_t ctdb_control_get_tunable(struct ctdb_context *ctdb, TDB_DATA indata, 
				 TDB_DATA *outdata);
int32_t ctdb_control_set_tunable(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_list_tunables(struct ctdb_context *ctdb, TDB_DATA *outdata);
int32_t ctdb_control_try_delete_records(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata);
int32_t ctdb_control_add_public_address(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_del_public_address(struct ctdb_context *ctdb, TDB_DATA indata);

void ctdb_tunables_set_defaults(struct ctdb_context *ctdb);

int32_t ctdb_control_modflags(struct ctdb_context *ctdb, TDB_DATA indata);

int ctdb_ctrl_get_all_tunables(struct ctdb_context *ctdb, 
			       struct timeval timeout, 
			       uint32_t destnode,
			       struct ctdb_tunable *tunables);

void ctdb_start_freeze(struct ctdb_context *ctdb);

bool parse_ip_mask(const char *s, const char *iface, ctdb_sock_addr *addr, unsigned *mask);
bool parse_ip_port(const char *s, ctdb_sock_addr *addr);
bool parse_ip(const char *s, const char *iface, ctdb_sock_addr *addr);
bool parse_ipv4(const char *s, unsigned port, struct sockaddr_in *sin);
 

int ctdb_sys_open_capture_socket(const char *iface, void **private_data);
int ctdb_sys_close_capture_socket(void *private_data);
int ctdb_sys_read_tcp_packet(int s, void *private_data, ctdb_sock_addr *src, ctdb_sock_addr *dst, uint32_t *ack_seq, uint32_t *seq);

int ctdb_ctrl_killtcp(struct ctdb_context *ctdb, 
		      struct timeval timeout, 
		      uint32_t destnode,
		      struct ctdb_control_killtcp *killtcp);

int ctdb_ctrl_add_public_ip(struct ctdb_context *ctdb, 
		      struct timeval timeout, 
		      uint32_t destnode,
		      struct ctdb_control_ip_iface *pub);

int ctdb_ctrl_del_public_ip(struct ctdb_context *ctdb, 
		      struct timeval timeout, 
		      uint32_t destnode,
		      struct ctdb_control_ip_iface *pub);

int ctdb_ctrl_gratious_arp(struct ctdb_context *ctdb, 
		      struct timeval timeout, 
		      uint32_t destnode,
		      ctdb_sock_addr *addr,
		      const char *ifname);

int ctdb_ctrl_get_tcp_tickles(struct ctdb_context *ctdb, 
		      struct timeval timeout, 
		      uint32_t destnode,
		      TALLOC_CTX *mem_ctx,
		      ctdb_sock_addr *addr,
		      struct ctdb_control_tcp_tickle_list **list);


int32_t ctdb_control_register_server_id(struct ctdb_context *ctdb, 
		      uint32_t client_id,
		      TDB_DATA indata);
int32_t ctdb_control_check_server_id(struct ctdb_context *ctdb, 
		      TDB_DATA indata);
int32_t ctdb_control_unregister_server_id(struct ctdb_context *ctdb, 
		      TDB_DATA indata);
int32_t ctdb_control_get_server_id_list(struct ctdb_context *ctdb, 
		      TDB_DATA *outdata);
int32_t ctdb_control_uptime(struct ctdb_context *ctdb, 
		      TDB_DATA *outdata);

int ctdb_attach_persistent(struct ctdb_context *ctdb);

int32_t ctdb_control_persistent_store(struct ctdb_context *ctdb, 
				      struct ctdb_req_control *c, 
				      TDB_DATA recdata, bool *async_reply);
int32_t ctdb_control_update_record(struct ctdb_context *ctdb, 
				   struct ctdb_req_control *c, TDB_DATA recdata, 
				   bool *async_reply);
int32_t ctdb_control_trans2_commit(struct ctdb_context *ctdb, 
				   struct ctdb_req_control *c, 
				   TDB_DATA recdata, bool *async_reply);

int32_t ctdb_control_transaction_start(struct ctdb_context *ctdb, uint32_t id);
int32_t ctdb_control_transaction_commit(struct ctdb_context *ctdb, uint32_t id);
int32_t ctdb_control_wipe_database(struct ctdb_context *ctdb, TDB_DATA indata);


int ctdb_vacuum(struct ctdb_context *ctdb, int argc, const char **argv);
int ctdb_repack(struct ctdb_context *ctdb, int argc, const char **argv);

void ctdb_block_signal(int signum);
void ctdb_unblock_signal(int signum);
int32_t ctdb_monitoring_mode(struct ctdb_context *ctdb);
int ctdb_set_child_logging(struct ctdb_context *ctdb);


typedef void (*client_async_callback)(struct ctdb_context *ctdb, uint32_t node_pnn, int32_t res, TDB_DATA outdata, void *callback_data);

struct client_async_data {
	enum ctdb_controls opcode;
	bool dont_log_errors;
	uint32_t count;
	uint32_t fail_count;
	client_async_callback callback;
	client_async_callback fail_callback;
	void *callback_data;
};
void ctdb_client_async_add(struct client_async_data *data, struct ctdb_client_control_state *state);
int ctdb_client_async_wait(struct ctdb_context *ctdb, struct client_async_data *data);
int ctdb_client_async_control(struct ctdb_context *ctdb,
				enum ctdb_controls opcode,
				uint32_t *nodes,
				struct timeval timeout,
				bool dont_log_errors,
				TDB_DATA data,
			      	client_async_callback client_callback,
			        client_async_callback fail_callback,
				void *callback_data);

void ctdb_load_nodes_file(struct ctdb_context *ctdb);

int ctdb_control_reload_nodes_file(struct ctdb_context *ctdb, uint32_t opcode);

int32_t ctdb_dump_memory(struct ctdb_context *ctdb, TDB_DATA *outdata);
int32_t ctdb_control_get_capabilities(struct ctdb_context *ctdb, TDB_DATA *outdata);

int32_t ctdb_control_trans2_finished(struct ctdb_context *ctdb, 
				     struct ctdb_req_control *c);
int32_t ctdb_control_trans2_error(struct ctdb_context *ctdb, 
				  struct ctdb_req_control *c);

char *ctdb_addr_to_str(ctdb_sock_addr *addr);
void ctdb_canonicalize_ip(const ctdb_sock_addr *ip, ctdb_sock_addr *cip);

int32_t ctdb_control_recd_ping(struct ctdb_context *ctdb);
int32_t ctdb_control_set_recmaster(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata);

extern int script_log_level;

int ctdb_ctrl_event_script_init(struct ctdb_context *ctdb);
int ctdb_ctrl_event_script_start(struct ctdb_context *ctdb, const char *name);
int ctdb_ctrl_event_script_stop(struct ctdb_context *ctdb, int32_t res);
int ctdb_ctrl_event_script_finished(struct ctdb_context *ctdb);

int32_t ctdb_control_event_script_init(struct ctdb_context *ctdb);
int32_t ctdb_control_event_script_start(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_event_script_stop(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_event_script_finished(struct ctdb_context *ctdb);


int32_t ctdb_control_get_event_script_status(struct ctdb_context *ctdb, TDB_DATA *outdata);

int ctdb_log_event_script_output(struct ctdb_context *ctdb, char *str, uint16_t len);

#endif
