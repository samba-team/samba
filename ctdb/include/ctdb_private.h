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

#include "ctdb_client.h"
#include <sys/socket.h>

/*
  recovery daemon memdump reply address
 */
struct rd_memdump_reply {
	uint32_t pnn;
	uint64_t srvid;
};

/*
  description for a TAKEOVER_RUN message reply address
 */
struct takeover_run_reply {
	uint32_t pnn;
	uint64_t srvid;
};

/*
 * pid of the ctdbd daemon
 */
extern pid_t ctdbd_pid;

/*
  a tcp connection description
  also used by tcp_add and tcp_remove controls
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
	uint32_t vacuum_default_interval;
	uint32_t vacuum_max_run_time;
	uint32_t repack_limit;
	uint32_t vacuum_limit;
	uint32_t vacuum_min_interval;
	uint32_t vacuum_max_interval;
	uint32_t max_queue_depth_drop_msg;
	uint32_t use_status_events_for_monitoring;
	uint32_t allow_unhealthy_db_read;
	uint32_t stat_history_interval;
	uint32_t deferred_attach_timeout;
	uint32_t vacuum_fast_path_count;
	uint32_t lcp2_public_ip_assignment;
	uint32_t allow_client_db_attach;
	uint32_t recover_pdb_by_seqnum;
	uint32_t deferred_rebalance_on_node_add;
	uint32_t fetch_collapse;
	uint32_t max_lacount;
	uint32_t hopcount_make_sticky;
	uint32_t sticky_duration;
	uint32_t sticky_pindown;
	uint32_t no_ip_takeover;
	uint32_t db_record_count_warn;
	uint32_t db_record_size_warn;
	uint32_t db_size_warn;
	uint32_t pulldb_preallocation_size;
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
	uint32_t db_id;
	uint32_t num_persistent_updates;
	struct ctdb_client_notify_list *notify;
};

struct ctdb_iface;

/* state associated with a public ip address */
struct ctdb_vnn {
	struct ctdb_vnn *prev, *next;

	struct ctdb_iface *iface;
	const char **ifaces;
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
	struct ctdb_all_public_ips *known_public_ips;
	struct ctdb_all_public_ips *available_public_ips;
	/* used by the recovery dameon to track when a node should be banned */
	struct ctdb_banning_state *ban_state; 
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
	ctdb_msg_fn_t message_handler;
	void *message_private;
};

/* additional data required for the daemon mode */
struct ctdb_daemon_data {
	int sd;
	char *name;
	struct ctdb_queue *queue;
};


#define CTDB_UPDATE_STAT(ctdb, counter, value) \
	{										\
		if (value > ctdb->statistics.counter) {					\
			ctdb->statistics.counter = c->hopcount;				\
		}									\
		if (value > ctdb->statistics_current.counter) {				\
			ctdb->statistics_current.counter = c->hopcount;			\
		}									\
	}

#define CTDB_INCREMENT_STAT(ctdb, counter) \
	{										\
		ctdb->statistics.counter++;						\
		ctdb->statistics_current.counter++;					\
	}

#define CTDB_INCREMENT_DB_STAT(ctdb_db, counter) \
	{										\
		ctdb_db->statistics.counter++;						\
	}

#define CTDB_DECREMENT_STAT(ctdb, counter) \
	{										\
		if (ctdb->statistics.counter > 0)					\
			ctdb->statistics.counter--;					\
		if (ctdb->statistics_current.counter > 0)				\
			ctdb->statistics_current.counter--;				\
	}

#define CTDB_UPDATE_RECLOCK_LATENCY(ctdb, name, counter, value) \
	{										\
		if (value > ctdb->statistics.counter.max)					\
			ctdb->statistics.counter.max = value;				\
		if (value > ctdb->statistics_current.counter.max)				\
			ctdb->statistics_current.counter.max = value;			\
											\
		if (ctdb->statistics.counter.num == 0 || value < ctdb->statistics.counter.min)	\
			ctdb->statistics.counter.min = value;				\
		if (ctdb->statistics_current.counter.num == 0 || value < ctdb->statistics_current.counter.min)	\
			ctdb->statistics_current.counter.min = value;			\
											\
		ctdb->statistics.counter.total += value;					\
		ctdb->statistics_current.counter.total += value;				\
											\
		ctdb->statistics.counter.num++;						\
		ctdb->statistics_current.counter.num++;					\
											\
		if (ctdb->tunable.reclock_latency_ms != 0) {				\
			if (value*1000 > ctdb->tunable.reclock_latency_ms) {		\
				DEBUG(DEBUG_ERR, ("High RECLOCK latency %fs for operation %s\n", value, name));	\
			}								\
		}									\
	}


#define CTDB_UPDATE_LATENCY(ctdb, db, operation, counter, t) \
	{										\
		double l = timeval_elapsed(&t);						\
											\
		if (l > ctdb->statistics.counter.max)					\
			ctdb->statistics.counter.max = l;				\
		if (l > ctdb->statistics_current.counter.max)				\
			ctdb->statistics_current.counter.max = l;			\
											\
		if (ctdb->statistics.counter.num == 0 || l < ctdb->statistics.counter.min)	\
			ctdb->statistics.counter.min = l;				\
		if (ctdb->statistics_current.counter.num == 0 || l < ctdb->statistics_current.counter.min)	\
			ctdb->statistics_current.counter.min = l;			\
											\
		ctdb->statistics.counter.total += l;					\
		ctdb->statistics_current.counter.total += l;				\
											\
		ctdb->statistics.counter.num++;						\
		ctdb->statistics_current.counter.num++;					\
											\
		if (ctdb->tunable.log_latency_ms !=0) {					\
			if (l*1000 > ctdb->tunable.log_latency_ms) {			\
				DEBUG(DEBUG_WARNING, ("High latency %.6fs for operation %s on database %s\n", l, operation, db->db_name));\
			}								\
		}									\
	}



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
/* This capability is set if NATGW is enabled */
#define CTDB_CAP_NATGW			0x00000008

#define NUM_DB_PRIORITIES 3
/* main state of the ctdb daemon */
struct ctdb_context {
	struct tevent_context *ev;
	struct timeval ctdbd_start_time;
	struct timeval last_recovery_started;
	struct timeval last_recovery_finished;
	uint32_t recovery_mode;
	TALLOC_CTX *tickle_update_context;
	TALLOC_CTX *keepalive_ctx;
	TALLOC_CTX *check_public_ifaces_ctx;
	struct ctdb_tunable tunable;
	enum ctdb_freeze_mode freeze_mode[NUM_DB_PRIORITIES+1];
	struct ctdb_freeze_handle *freeze_handles[NUM_DB_PRIORITIES+1];
	bool freeze_transaction_started;
	uint32_t freeze_transaction_id;
	struct ctdb_address address;
	const char *name;
	const char *db_directory;
	const char *db_directory_persistent;
	const char *db_directory_state;
	struct tdb_wrap *db_persistent_health;
	uint32_t db_persistent_startup_generation;
	uint64_t db_persistent_check_errors;
	uint64_t max_persistent_check_errors;
	const char *transport;
	char *recovery_lock_file;
	int recovery_lock_fd;
	uint32_t pnn; /* our own pnn */
	uint32_t num_nodes;
	uint32_t num_connected;
	unsigned flags;
	uint32_t capabilities;
	struct idr_context *idr;
	int lastid;
	struct ctdb_node **nodes; /* array of nodes in the cluster - indexed by vnn */
	struct ctdb_vnn *vnn; /* list of public ip addresses and interfaces */
	struct ctdb_vnn *single_ip_vnn; /* a structure for the single ip */
	struct ctdb_iface *ifaces; /* list of local interfaces */
	char *err_msg;
	const struct ctdb_methods *methods; /* transport methods */
	const struct ctdb_upcalls *upcalls; /* transport upcalls */
	void *private_data; /* private to transport */
	struct ctdb_db_context *db_list;
	struct ctdb_message_list *message_list;
	struct ctdb_daemon_data daemon;
	struct ctdb_statistics statistics;
	struct ctdb_statistics statistics_current;
#define MAX_STAT_HISTORY 100
	struct ctdb_statistics statistics_history[MAX_STAT_HISTORY];
	struct ctdb_vnn_map *vnn_map;
	uint32_t num_clients;
	uint32_t recovery_master;
	struct ctdb_call_state *pending_calls;
	struct ctdb_client_ip *client_ip_list;
	bool do_checkpublicip;
	struct trbt_tree *server_ids; 
	bool do_setsched;
	void *saved_scheduler_param;
	const char *event_script_dir;
	const char *debug_hung_script;
	const char *notification_script;
	const char *default_public_interface;
	pid_t ctdbd_pid;
	pid_t recoverd_pid;
	pid_t syslogd_pid;
	bool done_startup;
	const char *node_ip;
	struct ctdb_monitor_state *monitor;
	struct ctdb_log_state *log;
	int start_as_disabled;
	int start_as_stopped;
	bool valgrinding;
	uint32_t event_script_timeouts; /* counting how many consecutive times an eventscript has timedout */
	uint32_t *recd_ping_count;
	TALLOC_CTX *release_ips_ctx; /* a context used to automatically drop all IPs if we fail to recover the node */

	TALLOC_CTX *event_script_ctx;

	struct ctdb_event_script_state *current_monitor;
	struct ctdb_scripts_wire *last_status[CTDB_EVENT_MAX];

	TALLOC_CTX *banning_ctx;

	struct ctdb_vacuum_child_context *vacuumers;

	/* mapping from pid to ctdb_client * */
	struct ctdb_client_pid_list *client_pids;

	/* used in the recovery daemon to remember the ip allocation */
	struct trbt_tree *ip_tree;

	/* Used to defer db attach requests while in recovery mode */
	struct ctdb_deferred_attach_context *deferred_attach;

	/* if we are a child process, do we have a domain socket to send controls on */
	bool can_send_controls;

	/* list of event script callback functions that are active */
	struct event_script_callback *script_callbacks;

	struct ctdb_reloadips_handle *reload_ips;

	const char *public_addresses_file;
	struct trbt_tree *child_processes; 
	TALLOC_CTX *debug_hung_script_ctx;
};

struct ctdb_db_context {
	struct ctdb_db_context *next, *prev;
	struct ctdb_context *ctdb;
	uint32_t db_id;
	uint32_t priority;
	bool persistent;
	bool readonly; /* Do we support read-only delegations ? */
	bool sticky; /* Do we support sticky records ? */
	const char *db_name;
	const char *db_path;
	struct tdb_wrap *ltdb;
	struct tdb_context *rottdb; /* ReadOnly tracking TDB */
	struct ctdb_registered_call *calls; /* list of registered calls */
	uint32_t seqnum;
	struct timed_event *seqnum_update;
	struct ctdb_traverse_local_handle *traverse;
	bool transaction_active;
	struct ctdb_vacuum_handle *vacuum_handle;
	char *unhealthy_reason;
	int pending_requests;
	struct lockwait_handle *lockwait_active;
	struct lockwait_handle *lockwait_overflow;
	struct revokechild_handle *revokechild_active;
	struct ctdb_persistent_state *persistent_state;
	struct trbt_tree *delete_queue;
	struct trbt_tree *sticky_records; 
	int (*ctdb_ltdb_store_fn)(struct ctdb_db_context *ctdb_db,
				  TDB_DATA key,
				  struct ctdb_ltdb_header *header,
				  TDB_DATA data);

	/* used to track which records we are currently fetching
	   so we can avoid sending duplicate fetch requests
	*/
	struct trbt_tree *deferred_fetch;

	struct ctdb_db_statistics statistics;
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
int ctdb_ltdb_delete(struct ctdb_db_context *ctdb_db, TDB_DATA key);
int ctdb_ltdb_fetch_with_header(struct ctdb_db_context *ctdb_db, 
		    TDB_DATA key, struct ctdb_ltdb_header *header, 
		    TALLOC_CTX *mem_ctx, TDB_DATA *data);
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
				    void *private_data, const char *fmt, ...)
	PRINTF_ATTRIBUTE(7,8);

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

int ctdb_queue_length(struct ctdb_queue *queue);

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
		    struct ctdb_ltdb_header *header, TALLOC_CTX *mem_ctx,
		    TDB_DATA *data, bool updatetdb, uint32_t caller);

#define ctdb_reqid_find(ctdb, reqid, type)	(type *)_ctdb_reqid_find(ctdb, reqid, #type, __location__)

void ctdb_recv_raw_pkt(void *p, uint8_t *data, uint32_t length);

int ctdb_socket_connect(struct ctdb_context *ctdb);
void ctdb_client_read_cb(uint8_t *data, size_t cnt, void *args);

#define CTDB_BAD_REQID ((uint32_t)-1)
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
			       TDB_DATA *outdata, uint64_t tdb_flags,
			       bool persistent, uint32_t client_id,
			       struct ctdb_req_control *c,
			       bool *async_reply);

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

#define CHECK_CONTROL_MIN_DATA_SIZE(size) do { \
 if (indata.dsize < size) { \
	 DEBUG(0,(__location__ " Invalid data size in opcode %u. Got %u expected >= %u\n", \
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


int32_t ctdb_control_traverse_start_ext(struct ctdb_context *ctdb,
					TDB_DATA indata,
					TDB_DATA *outdata,
					uint32_t srcnode,
					uint32_t client_id);
int32_t ctdb_control_traverse_start(struct ctdb_context *ctdb, TDB_DATA indata, 
				    TDB_DATA *outdata, uint32_t srcnode, uint32_t client_id);
int32_t ctdb_control_traverse_all(struct ctdb_context *ctdb, TDB_DATA data, TDB_DATA *outdata);
int32_t ctdb_control_traverse_data(struct ctdb_context *ctdb, TDB_DATA data, TDB_DATA *outdata);
int32_t ctdb_control_traverse_kill(struct ctdb_context *ctdb, TDB_DATA indata, 
				    TDB_DATA *outdata, uint32_t srcnode);

int ctdb_dispatch_message(struct ctdb_context *ctdb, uint64_t srvid, TDB_DATA data);

int daemon_register_message_handler(struct ctdb_context *ctdb, uint32_t client_id, uint64_t srvid);
int ctdb_deregister_message_handler(struct ctdb_context *ctdb, uint64_t srvid, void *private_data);
int daemon_deregister_message_handler(struct ctdb_context *ctdb, uint32_t client_id, uint64_t srvid);
int daemon_check_srvids(struct ctdb_context *ctdb, TDB_DATA indata,
			TDB_DATA *outdata);

int32_t ctdb_ltdb_enable_seqnum(struct ctdb_context *ctdb, uint32_t db_id);
int32_t ctdb_ltdb_update_seqnum(struct ctdb_context *ctdb, uint32_t db_id, uint32_t srcnode);

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
int32_t ctdb_control_thaw(struct ctdb_context *ctdb, uint32_t priority);

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

struct tevent_signal *ctdb_init_sigchld(struct ctdb_context *ctdb);
pid_t ctdb_fork(struct ctdb_context *ctdb);
int ctdb_kill(struct ctdb_context *ctdb, pid_t pid, int signum);

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

int ctdb_ctrl_takeover_ip(struct ctdb_context *ctdb, struct timeval timeout, 
			  uint32_t destnode, struct ctdb_public_ip *ip);
int ctdb_ctrl_release_ip(struct ctdb_context *ctdb, struct timeval timeout, 
			 uint32_t destnode, struct ctdb_public_ip *ip);

struct ctdb_all_public_ipsv4 {
	uint32_t num;
	struct ctdb_public_ipv4 ips[1];
};

int32_t ctdb_control_get_public_ipsv4(struct ctdb_context *ctdb, struct ctdb_req_control *c, TDB_DATA *outdata);
int32_t ctdb_control_get_public_ips(struct ctdb_context *ctdb, struct ctdb_req_control *c, TDB_DATA *outdata);
int ctdb_ctrl_get_public_ips(struct ctdb_context *ctdb, 
			     struct timeval timeout,
			     uint32_t destnode,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_all_public_ips **ips);
#define CTDB_PUBLIC_IP_FLAGS_ONLY_AVAILABLE 0x00010000
int ctdb_ctrl_get_public_ips_flags(struct ctdb_context *ctdb,
				   struct timeval timeout, uint32_t destnode,
				   TALLOC_CTX *mem_ctx,
				   uint32_t flags,
				   struct ctdb_all_public_ips **ips);
int ctdb_ctrl_get_public_ipsv4(struct ctdb_context *ctdb, 
			struct timeval timeout, uint32_t destnode, 
			TALLOC_CTX *mem_ctx, struct ctdb_all_public_ips **ips);

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

int32_t ctdb_control_get_public_ip_info(struct ctdb_context *ctdb,
					struct ctdb_req_control *c,
					TDB_DATA indata,
					TDB_DATA *outdata);
int32_t ctdb_control_get_ifaces(struct ctdb_context *ctdb,
				struct ctdb_req_control *c,
				TDB_DATA *outdata);
int32_t ctdb_control_set_iface_link(struct ctdb_context *ctdb,
				    struct ctdb_req_control *c,
				    TDB_DATA indata);
int ctdb_ctrl_get_public_ip_info(struct ctdb_context *ctdb,
				 struct timeval timeout, uint32_t destnode,
				 TALLOC_CTX *mem_ctx,
				 const ctdb_sock_addr *addr,
				 struct ctdb_control_public_ip_info **info);
int ctdb_ctrl_get_ifaces(struct ctdb_context *ctdb,
			 struct timeval timeout, uint32_t destnode,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_control_get_ifaces **ifaces);
int ctdb_ctrl_set_iface_link(struct ctdb_context *ctdb,
			     struct timeval timeout, uint32_t destnode,
			     TALLOC_CTX *mem_ctx,
			     const struct ctdb_control_iface_info *info);

/* from takeover/system.c */
uint32_t uint16_checksum(uint16_t *data, size_t n);
int ctdb_sys_send_arp(const ctdb_sock_addr *addr, const char *iface);
bool ctdb_sys_have_ip(ctdb_sock_addr *addr);
char *ctdb_sys_find_ifname(ctdb_sock_addr *addr);
bool ctdb_sys_check_iface_exists(const char *iface);
int ctdb_get_peer_pid(const int fd, pid_t *peer_pid);
int ctdb_sys_send_tcp(const ctdb_sock_addr *dest, 
		      const ctdb_sock_addr *src,
		      uint32_t seq, uint32_t ack, int rst);

int ctdb_set_public_addresses(struct ctdb_context *ctdb, bool check_addresses);
int ctdb_set_single_public_ip(struct ctdb_context *ctdb,
			      const char *iface,
			      const char *ip);
int ctdb_set_event_script(struct ctdb_context *ctdb, const char *script);
int ctdb_set_event_script_dir(struct ctdb_context *ctdb, const char *script_dir);
int ctdb_set_debug_hung_script(struct ctdb_context *ctdb, const char *script);
int ctdb_set_notification_script(struct ctdb_context *ctdb, const char *script);
void lcp2_forcerebalance(struct ctdb_context *ctdb, uint32_t pnn);
int ctdb_takeover_run(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap);

int32_t ctdb_control_tcp_client(struct ctdb_context *ctdb, uint32_t client_id, 
				TDB_DATA indata);
int32_t ctdb_control_tcp_add(struct ctdb_context *ctdb, TDB_DATA indata, bool tcp_update_needed);
int32_t ctdb_control_tcp_remove(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_startup(struct ctdb_context *ctdb, uint32_t vnn);
int32_t ctdb_control_kill_tcp(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_send_gratious_arp(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_get_tcp_tickle_list(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata);
int32_t ctdb_control_set_tcp_tickle_list(struct ctdb_context *ctdb, TDB_DATA indata);

void ctdb_takeover_client_destructor_hook(struct ctdb_client *client);
int ctdb_event_script(struct ctdb_context *ctdb, enum ctdb_eventscript_call call);
int ctdb_event_script_args(struct ctdb_context *ctdb, enum ctdb_eventscript_call call,
			   const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);
int ctdb_event_script_callback(struct ctdb_context *ctdb, 
			       TALLOC_CTX *mem_ctx,
			       void (*callback)(struct ctdb_context *, int, void *),
			       void *private_data,
			       bool from_user,
			       enum ctdb_eventscript_call call,
			       const char *fmt, ...) PRINTF_ATTRIBUTE(7,8);
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

int ctdb_start_freeze(struct ctdb_context *ctdb, uint32_t priority);

bool parse_ip_mask(const char *s, const char *iface, ctdb_sock_addr *addr, unsigned *mask);
bool parse_ip_port(const char *s, ctdb_sock_addr *addr);
bool parse_ip(const char *s, const char *iface, unsigned port, ctdb_sock_addr *addr);
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

int ctdb_attach_databases(struct ctdb_context *ctdb);

int32_t ctdb_control_persistent_store(struct ctdb_context *ctdb, 
				      struct ctdb_req_control *c, 
				      TDB_DATA recdata, bool *async_reply);
int32_t ctdb_control_update_record(struct ctdb_context *ctdb, 
				   struct ctdb_req_control *c, TDB_DATA recdata, 
				   bool *async_reply);
int32_t ctdb_control_trans2_commit(struct ctdb_context *ctdb, 
				   struct ctdb_req_control *c, 
				   TDB_DATA recdata, bool *async_reply);

int32_t ctdb_control_trans3_commit(struct ctdb_context *ctdb,
				   struct ctdb_req_control *c,
				   TDB_DATA recdata, bool *async_reply);

void ctdb_persistent_finish_trans3_commits(struct ctdb_context *ctdb);

int32_t ctdb_control_transaction_start(struct ctdb_context *ctdb, uint32_t id);
int32_t ctdb_control_transaction_commit(struct ctdb_context *ctdb, uint32_t id);
int32_t ctdb_control_transaction_cancel(struct ctdb_context *ctdb);
int32_t ctdb_control_wipe_database(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_db_set_healthy(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_db_get_health(struct ctdb_context *ctdb,
				   TDB_DATA indata,
				   TDB_DATA *outdata);


int ctdb_vacuum(struct ctdb_context *ctdb, int argc, const char **argv);
int ctdb_repack(struct ctdb_context *ctdb, int argc, const char **argv);

void ctdb_block_signal(int signum);
void ctdb_unblock_signal(int signum);
int32_t ctdb_monitoring_mode(struct ctdb_context *ctdb);
int ctdb_set_child_logging(struct ctdb_context *ctdb);
void ctdb_lockdown_memory(struct ctdb_context *ctdb);

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
			      	uint64_t srvid,
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
int32_t ctdb_control_trans2_active(struct ctdb_context *ctdb,
				   struct ctdb_req_control *c,
				   uint32_t db_id);

char *ctdb_addr_to_str(ctdb_sock_addr *addr);
unsigned ctdb_addr_to_port(ctdb_sock_addr *addr);
void ctdb_canonicalize_ip(const ctdb_sock_addr *ip, ctdb_sock_addr *cip);

int32_t ctdb_control_recd_ping(struct ctdb_context *ctdb);
int32_t ctdb_control_set_recmaster(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata);

extern int script_log_level;
extern bool fast_start;

int32_t ctdb_control_get_event_script_status(struct ctdb_context *ctdb,
					     uint32_t call_type,
					     TDB_DATA *outdata);

int ctdb_log_event_script_output(struct ctdb_context *ctdb, char *str, uint16_t len);
int ctdb_ctrl_report_recd_lock_latency(struct ctdb_context *ctdb, struct timeval timeout, double latency);

int32_t ctdb_control_stop_node(struct ctdb_context *ctdb, struct ctdb_req_control *c, bool *async_reply);
int32_t ctdb_control_continue_node(struct ctdb_context *ctdb);

void ctdb_stop_vacuuming(struct ctdb_context *ctdb);
int ctdb_vacuum_init(struct ctdb_db_context *ctdb_db);

int32_t ctdb_control_enable_script(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_disable_script(struct ctdb_context *ctdb, TDB_DATA indata);

int32_t ctdb_local_node_got_banned(struct ctdb_context *ctdb);
int32_t ctdb_control_set_ban_state(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_get_ban_state(struct ctdb_context *ctdb, TDB_DATA *outdata);
int32_t ctdb_control_set_db_priority(struct ctdb_context *ctdb, TDB_DATA indata);
void ctdb_ban_self(struct ctdb_context *ctdb);

int32_t ctdb_control_register_notify(struct ctdb_context *ctdb, uint32_t client_id, TDB_DATA indata);

int32_t ctdb_control_deregister_notify(struct ctdb_context *ctdb, uint32_t client_id, TDB_DATA indata);

int start_syslog_daemon(struct ctdb_context *ctdb);

/* Where to send the log messages back to */
struct ctdb_get_log_addr {
	uint32_t pnn;
	uint64_t srvid;
	int32_t level;
};

extern int log_ringbuf_size;

int32_t ctdb_control_get_log(struct ctdb_context *ctdb, TDB_DATA addr);
int32_t ctdb_control_clear_log(struct ctdb_context *ctdb);


struct ctdb_log_state *ctdb_fork_with_logging(TALLOC_CTX *mem_ctx,
					      struct ctdb_context *ctdb,
					      const char *log_prefix,
					      void (*logfn)(const char *, uint16_t, void *),
					      void *logfn_private, pid_t *pid);

int32_t ctdb_control_process_exists(struct ctdb_context *ctdb, pid_t pid);
struct ctdb_client *ctdb_find_client_by_pid(struct ctdb_context *ctdb, pid_t pid);

int32_t ctdb_control_get_db_seqnum(struct ctdb_context *ctdb,
				   TDB_DATA indata,
				   TDB_DATA *outdata);

int ctdb_load_persistent_health(struct ctdb_context *ctdb,
				struct ctdb_db_context *ctdb_db);
int ctdb_update_persistent_health(struct ctdb_context *ctdb,
				  struct ctdb_db_context *ctdb_db,
				  const char *reason,/* NULL means healthy */
				  int num_healthy_nodes);
int ctdb_recheck_persistent_health(struct ctdb_context *ctdb);

void ctdb_run_notification_script(struct ctdb_context *ctdb, const char *event);

void ctdb_fault_setup(void);

int verify_remote_ip_allocation(struct ctdb_context *ctdb, 
				struct ctdb_all_public_ips *ips);
int update_ip_assignment_tree(struct ctdb_context *ctdb,
				struct ctdb_public_ip *ip);

int ctdb_init_tevent_logging(struct ctdb_context *ctdb);

int ctdb_statistics_init(struct ctdb_context *ctdb);

int32_t ctdb_control_get_stat_history(struct ctdb_context *ctdb,
				      struct ctdb_req_control *c,
				      TDB_DATA *outdata);

int ctdb_deferred_drop_all_ips(struct ctdb_context *ctdb);

int ctdb_process_deferred_attach(struct ctdb_context *ctdb);

/**
 * structure to pass to a schedule_for_deletion_control
 */
struct ctdb_control_schedule_for_deletion {
	uint32_t db_id;
	struct ctdb_ltdb_header hdr;
	uint32_t keylen;
	uint8_t key[1]; /* key[] */
};

int32_t ctdb_control_schedule_for_deletion(struct ctdb_context *ctdb,
					   TDB_DATA indata);


int32_t ctdb_local_schedule_for_deletion(struct ctdb_db_context *ctdb_db,
					 const struct ctdb_ltdb_header *hdr,
					 TDB_DATA key);

void ctdb_local_remove_from_delete_queue(struct ctdb_db_context *ctdb_db,
					 const struct ctdb_ltdb_header *hdr,
					 const TDB_DATA key);

struct ctdb_ltdb_header *ctdb_header_from_record_handle(struct ctdb_record_handle *h);

/* For unit testing ctdb_transaction.c. */
struct ctdb_public_ip_list {
	struct ctdb_public_ip_list *next;
	uint32_t pnn;
	ctdb_sock_addr addr;
};
int ctdb_trackingdb_add_pnn(struct ctdb_context *ctdb, TDB_DATA *data, uint32_t pnn);

typedef void (*ctdb_trackingdb_cb)(struct ctdb_context *ctdb, uint32_t pnn, void *private_data);

void ctdb_trackingdb_traverse(struct ctdb_context *ctdb, TDB_DATA data, ctdb_trackingdb_cb cb, void *private_data);

int ctdb_start_revoke_ro_record(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA data);

typedef void (*deferred_requeue_fn)(void *call_context, struct ctdb_req_header *hdr);

int ctdb_add_revoke_deferred_call(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_req_header *hdr, deferred_requeue_fn fn, void *call_context);

int ctdb_set_db_readonly(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db);

int ctdb_null_func(struct ctdb_call_info *call);

int ctdb_fetch_func(struct ctdb_call_info *call);

int ctdb_fetch_with_header_func(struct ctdb_call_info *call);

int32_t ctdb_control_get_db_statistics(struct ctdb_context *ctdb,
				uint32_t db_id,
				TDB_DATA *outdata);

int ctdb_set_db_sticky(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db);

/*
  description for a message to reload all ips via recovery master/daemon
 */
struct reloadips_all_reply {
	uint32_t pnn;
	uint64_t srvid;
};

int32_t ctdb_control_reload_public_ips(struct ctdb_context *ctdb, struct ctdb_req_control *c, bool *async_reply);

int ctdb_start_monitoring_interfaces(struct ctdb_context *ctdb);

#endif
