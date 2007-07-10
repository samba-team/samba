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
#include <netinet/in.h>

/* location of daemon socket */
#define CTDB_PATH	"/tmp/ctdb.socket"

/* default ctdb port number */
#define CTDB_PORT 4379

/* we must align packets to ensure ctdb works on all architectures (eg. sparc) */
#define CTDB_DS_ALIGNMENT 8


#define CTDB_NULL_FUNC      0xFF000001
#define CTDB_FETCH_FUNC     0xFF000002

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
	uint32_t script_timeout;
	uint32_t recovery_grace_period;
	uint32_t recovery_ban_period;
	uint32_t database_hash_size;
	uint32_t rerecovery_timeout;
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
  check a vnn is valid
 */
#define ctdb_validate_vnn(ctdb, vnn) (((uint32_t)(vnn)) < (ctdb)->num_nodes)


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
};


/*
  state associated with one node
*/
struct ctdb_node {
	struct ctdb_context *ctdb;
	struct ctdb_address address;
	const char *name; /* for debug messages */
	void *private_data; /* private to transport */
	uint32_t vnn;
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

	/* a list of controls pending to this node, so we can time them out quickly
	   if the node becomes disconnected */
	struct daemon_control_state *pending_controls;

	/* the public address of this node, if known */
	const char *public_address;
	uint8_t public_netmask_bits;

	/* the node number that has taken over this nodes public address, if any. 
	   If not taken over, then set to -1 */
	int32_t takeover_vnn;
};

/*
  transport specific methods
*/
struct ctdb_methods {
	int (*initialise)(struct ctdb_context *); /* initialise transport structures */	
	int (*start)(struct ctdb_context *); /* start protocol processing */	
	int (*add_node)(struct ctdb_node *); /* setup a new node */	
	int (*queue_pkt)(struct ctdb_node *, uint8_t *data, uint32_t length);
	void *(*allocate_pkt)(TALLOC_CTX *mem_ctx, size_t );
	void (*shutdown)(struct ctdb_context *); /* shutdown transport */
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
	uint32_t memory_used;
	uint32_t __last_counter; /* hack for control_statistics_all */
	uint32_t max_hop_count;
	double max_call_latency;
	double max_lockwait_latency;
};

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

/* information about IP takeover */
struct ctdb_takeover {
	bool enabled;
	const char *interface;
	const char *event_script;
	TALLOC_CTX *last_ctx;
};

/* main state of the ctdb daemon */
struct ctdb_context {
	struct event_context *ev;
	uint32_t recovery_mode;
	uint32_t monitoring_mode;
	TALLOC_CTX *monitor_context;
	struct ctdb_tunable tunable;
	enum ctdb_freeze_mode freeze_mode;
	struct ctdb_freeze_handle *freeze_handle;
	struct ctdb_address address;
	const char *name;
	const char *db_directory;
	const char *transport;
	const char *logfile;
	char *node_list_file;
	char *recovery_lock_file;
	int recovery_lock_fd;
	uint32_t vnn; /* our own vnn */
	uint32_t num_nodes;
	uint32_t num_connected;
	unsigned flags;
	struct idr_context *idr;
	uint16_t idr_cnt;
	struct ctdb_node **nodes; /* array of nodes in the cluster - indexed by vnn */
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
	struct ctdb_takeover takeover;
	struct ctdb_tcp_list *tcp_list;
	struct ctdb_client_ip *client_ip_list;
};

struct ctdb_db_context {
	struct ctdb_db_context *next, *prev;
	struct ctdb_context *ctdb;
	uint32_t db_id;
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
	  }} while (0)

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
		    CTDB_CONTROL_GET_NODEMAP             = 10,
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
		    CTDB_CONTROL_GET_VNN                 = 35,
		    CTDB_CONTROL_SHUTDOWN                = 36,
		    CTDB_CONTROL_GET_MONMODE             = 37,
		    CTDB_CONTROL_SET_MONMODE             = 38,
		    CTDB_CONTROL_MAX_RSN                 = 39,
		    CTDB_CONTROL_SET_RSN_NONEMPTY        = 40,
		    CTDB_CONTROL_DELETE_LOW_RSN          = 41,
		    CTDB_CONTROL_TAKEOVER_IP             = 42,
		    CTDB_CONTROL_RELEASE_IP              = 43,
		    CTDB_CONTROL_TCP_CLIENT              = 44,
		    CTDB_CONTROL_TCP_ADD                 = 45,
		    CTDB_CONTROL_TCP_REMOVE              = 46,
		    CTDB_CONTROL_STARTUP                 = 47,
		    CTDB_CONTROL_SET_TUNABLE             = 48,
		    CTDB_CONTROL_GET_TUNABLE             = 49,
		    CTDB_CONTROL_LIST_TUNABLES           = 50,
		    CTDB_CONTROL_GET_PUBLIC_IPS          = 51,
		    CTDB_CONTROL_MODIFY_FLAGS            = 52,
		    CTDB_CONTROL_GET_ALL_TUNABLES        = 53,
};

/*
  structure passed in ctdb_control_set_rsn_nonempty
 */
struct ctdb_control_set_rsn_nonempty {
	uint32_t db_id;
	uint64_t rsn;
};

/*
  structure passed in ctdb_control_delete_low_rsn
 */
struct ctdb_control_delete_low_rsn {
	uint32_t db_id;
	uint64_t rsn;
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
  struct for tcp_client control
 */
struct ctdb_control_tcp {
	struct sockaddr_in src;
	struct sockaddr_in dest;
};

/*
  struct for tcp_add and tcp_remove controls
 */
struct ctdb_control_tcp_vnn {
	uint32_t vnn;
	struct sockaddr_in src;
	struct sockaddr_in dest;
};

/*
  structure used for CTDB_SRVID_NODE_FLAGS_CHANGED
 */
struct ctdb_node_flag_change {
	uint32_t vnn;
	uint32_t flags;
};

/*
  structure to change flags on a node
 */
struct ctdb_node_modflags {
	uint32_t set;
	uint32_t clear;
};

/*
  struct for admin setting a ban
 */
struct ctdb_ban_info {
	uint32_t vnn;
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
	struct ctdb_call call;
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

/* internal prototypes */
void ctdb_set_error(struct ctdb_context *ctdb, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);
void ctdb_fatal(struct ctdb_context *ctdb, const char *msg);
bool ctdb_same_address(struct ctdb_address *a1, struct ctdb_address *a2);
int ctdb_parse_address(struct ctdb_context *ctdb,
		       TALLOC_CTX *mem_ctx, const char *str,
		       struct ctdb_address *address);
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
void ctdb_queue_packet(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
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
int ctdb_daemon_send_message(struct ctdb_context *ctdb, uint32_t vnn,
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

void ctdb_latency(double *latency, struct timeval t);

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
			       TDB_DATA *outdata);

int ctdb_daemon_set_call(struct ctdb_context *ctdb, uint32_t db_id,
			 ctdb_fn_t fn, int id);

int ctdb_control(struct ctdb_context *ctdb, uint32_t destnode, uint64_t srvid, 
		 uint32_t opcode, uint32_t flags, TDB_DATA data, 
		 TALLOC_CTX *mem_ctx, TDB_DATA *outdata, int32_t *status,
		 struct timeval *timeout, char **errormsg);




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

/* structure used for pulldb control */
struct ctdb_control_pulldb_reply {
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
	uint32_t vnn;
	uint32_t flags;
	struct sockaddr_in sin;

};

struct ctdb_node_map {
	uint32_t num;
	struct ctdb_node_and_flags nodes[1];
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

struct ctdb_rec_data *ctdb_marshall_record(TALLOC_CTX *mem_ctx, uint32_t reqid,	TDB_DATA key, TDB_DATA data);

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

uint32_t ctdb_get_num_active_nodes(struct ctdb_context *ctdb);

void ctdb_stop_monitoring(struct ctdb_context *ctdb);
void ctdb_start_monitoring(struct ctdb_context *ctdb);
void ctdb_send_keepalive(struct ctdb_context *ctdb, uint32_t destnode);

void ctdb_daemon_cancel_controls(struct ctdb_context *ctdb, struct ctdb_node *node);
void ctdb_call_resend_all(struct ctdb_context *ctdb);
void ctdb_node_dead(struct ctdb_node *node);
void ctdb_node_connected(struct ctdb_node *node);
bool ctdb_blocking_freeze(struct ctdb_context *ctdb);
int32_t ctdb_control_max_rsn(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata);
int32_t ctdb_control_set_rsn_nonempty(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata);
int32_t ctdb_control_delete_low_rsn(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata);
int ctdb_ctrl_get_max_rsn(struct ctdb_context *ctdb, struct timeval timeout, 
			  uint32_t destnode, uint32_t db_id, uint64_t *max_rsn);
int ctdb_ctrl_set_rsn_nonempty(struct ctdb_context *ctdb, struct timeval timeout, 
			       uint32_t destnode, uint32_t db_id, uint64_t rsn);
int ctdb_ctrl_delete_low_rsn(struct ctdb_context *ctdb, struct timeval timeout, 
			     uint32_t destnode, uint32_t db_id, uint64_t rsn);
void ctdb_set_realtime(bool enable);
int32_t ctdb_control_takeover_ip(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 TDB_DATA indata, 
				 bool *async_reply);
int32_t ctdb_control_release_ip(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 TDB_DATA indata, 
				 bool *async_reply);

struct ctdb_public_ip {
	uint32_t vnn;
	uint32_t takeover_vnn;
	struct sockaddr_in sin;
};
int ctdb_ctrl_takeover_ip(struct ctdb_context *ctdb, struct timeval timeout, 
			  uint32_t destnode, struct ctdb_public_ip *ip);
int ctdb_ctrl_release_ip(struct ctdb_context *ctdb, struct timeval timeout, 
			 uint32_t destnode, struct ctdb_public_ip *ip);

struct ctdb_all_public_ips {
	uint32_t num;
	struct ctdb_public_ip ips[1];
};
int32_t ctdb_control_get_public_ips(struct ctdb_context *ctdb, struct ctdb_req_control *c, TDB_DATA *outdata);
int ctdb_ctrl_get_public_ips(struct ctdb_context *ctdb, 
			struct timeval timeout, uint32_t destnode, 
			TALLOC_CTX *mem_ctx, struct ctdb_all_public_ips **ips);


/* from takeover/system.c */
int ctdb_sys_send_arp(const struct sockaddr_in *saddr, const char *iface);
bool ctdb_sys_have_ip(const char *ip);
int ctdb_sys_send_tcp(const struct sockaddr_in *dest, 
		      const struct sockaddr_in *src,
		      uint32_t seq, uint32_t ack, int rst);
int ctdb_sys_kill_tcp(struct event_context *ev,
		      const struct sockaddr_in *dest, 
		      const struct sockaddr_in *src);

int ctdb_set_public_addresses(struct ctdb_context *ctdb, const char *alist);
int ctdb_set_event_script(struct ctdb_context *ctdb, const char *script);
int ctdb_takeover_run(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap);

int32_t ctdb_control_tcp_client(struct ctdb_context *ctdb, uint32_t client_id, 
				uint32_t srcnode, TDB_DATA indata);
int32_t ctdb_control_tcp_add(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_tcp_remove(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_startup(struct ctdb_context *ctdb, uint32_t vnn);

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

void ctdb_tunables_set_defaults(struct ctdb_context *ctdb);

int32_t ctdb_control_modflags(struct ctdb_context *ctdb, TDB_DATA indata);

int ctdb_ctrl_get_all_tunables(struct ctdb_context *ctdb, 
			       struct timeval timeout, 
			       uint32_t destnode,
			       struct ctdb_tunable *tunables);

void ctdb_start_freeze(struct ctdb_context *ctdb);

bool parse_ip_port(const char *s, struct sockaddr_in *ip);

#endif
