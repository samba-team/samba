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

#include "common/db_hash.h"

/*
  array of tcp connections
 */
struct ctdb_tcp_array {
	uint32_t num;
	struct ctdb_connection *connections;
};

/*
  an installed ctdb remote call
*/
typedef int (*ctdb_fn_t)(struct ctdb_call_info *);

struct ctdb_registered_call {
	struct ctdb_registered_call *next, *prev;
	uint32_t id;
	ctdb_fn_t fn;
};

/*
  check that a pnn is valid
 */
#define ctdb_validate_pnn(ctdb, pnn) (((uint32_t)(pnn)) < (ctdb)->num_nodes)

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

/*
  state associated with one node
*/
struct ctdb_node {
	struct ctdb_context *ctdb;
	ctdb_sock_addr address;
	const char *name; /* for debug messages */
	void *transport_data; /* private to transport */
	uint32_t pnn;
	uint32_t flags;

	/* used by the dead node monitoring */
	uint32_t dead_count;
	uint32_t rx_cnt;
	uint32_t tx_cnt;

	/* a list of controls pending to this node, so we can time them out quickly
	   if the node becomes disconnected */
	struct daemon_control_state *pending_controls;

	/* used by the recovery daemon to track when a node should be banned */
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

/* additional data required for the daemon mode */
struct ctdb_daemon_data {
	int sd;
	char *name;
	struct ctdb_queue *queue;
};


#define CTDB_UPDATE_STAT(ctdb, counter, value) \
	{										\
		if (value > ctdb->statistics.counter) {					\
			ctdb->statistics.counter = value;				\
		}									\
		if (value > ctdb->statistics_current.counter) {				\
			ctdb->statistics_current.counter = value;			\
		}									\
	}

#define CTDB_INCREMENT_STAT(ctdb, counter) \
	{										\
		ctdb->statistics.counter++;						\
		ctdb->statistics_current.counter++;					\
	}

#define CTDB_DECREMENT_STAT(ctdb, counter) \
	{										\
		if (ctdb->statistics.counter > 0)					\
			ctdb->statistics.counter--;					\
		if (ctdb->statistics_current.counter > 0)				\
			ctdb->statistics_current.counter--;				\
	}

#define CTDB_INCREMENT_DB_STAT(ctdb_db, counter) \
	{										\
		ctdb_db->statistics.counter++;						\
	}

#define CTDB_DECREMENT_DB_STAT(ctdb_db, counter) \
	{										\
		if (ctdb_db->statistics.counter > 0)					\
			ctdb_db->statistics.counter--;					\
	}

#define CTDB_UPDATE_RECLOCK_LATENCY(ctdb, name, counter, value) \
	{										\
		if (value > ctdb->statistics.counter.max)				\
			ctdb->statistics.counter.max = value;				\
		if (value > ctdb->statistics_current.counter.max)			\
			ctdb->statistics_current.counter.max = value;			\
											\
		if (ctdb->statistics.counter.num == 0 ||				\
		    value < ctdb->statistics.counter.min)				\
			ctdb->statistics.counter.min = value;				\
		if (ctdb->statistics_current.counter.num == 0 ||			\
		    value < ctdb->statistics_current.counter.min)			\
			ctdb->statistics_current.counter.min = value;			\
											\
		ctdb->statistics.counter.total += value;				\
		ctdb->statistics_current.counter.total += value;			\
											\
		ctdb->statistics.counter.num++;						\
		ctdb->statistics_current.counter.num++;					\
											\
		if (ctdb->tunable.reclock_latency_ms != 0) {				\
			if (value*1000 > ctdb->tunable.reclock_latency_ms) {		\
				DEBUG(DEBUG_ERR,					\
				      ("High RECLOCK latency %fs for operation %s\n",	\
				       value, name));					\
			}								\
		}									\
	}

#define CTDB_UPDATE_DB_LATENCY(ctdb_db, operation, counter, value)			\
	{										\
		if (value > ctdb_db->statistics.counter.max)				\
			ctdb_db->statistics.counter.max = value;			\
		if (ctdb_db->statistics.counter.num == 0 || 				\
		    value < ctdb_db->statistics.counter.min)				\
			ctdb_db->statistics.counter.min = value;			\
											\
		ctdb_db->statistics.counter.total += value;				\
		ctdb_db->statistics.counter.num++;					\
											\
		if (ctdb_db->ctdb->tunable.log_latency_ms != 0) {			\
			if (value*1000 > ctdb_db->ctdb->tunable.log_latency_ms) {	\
				DEBUG(DEBUG_ERR,					\
				      ("High latency %.6fs for operation %s on database %s\n",\
				       value, operation, ctdb_db->db_name));		\
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
		if (ctdb->statistics.counter.num == 0 ||				\
		    l < ctdb->statistics.counter.min)					\
			ctdb->statistics.counter.min = l;				\
		if (ctdb->statistics_current.counter.num == 0 ||			\
		    l < ctdb->statistics_current.counter.min)				\
			ctdb->statistics_current.counter.min = l;			\
											\
		ctdb->statistics.counter.total += l;					\
		ctdb->statistics_current.counter.total += l;				\
											\
		ctdb->statistics.counter.num++;						\
		ctdb->statistics_current.counter.num++;					\
											\
		if (ctdb->tunable.log_latency_ms != 0) {				\
			if (l*1000 > ctdb->tunable.log_latency_ms) {			\
				DEBUG(DEBUG_WARNING,					\
				      ("High latency %.6fs for operation %s on database %s\n",\
				       l, operation, db->db_name));			\
			}								\
		}									\
	}


struct ctdb_cluster_mutex_handle;
struct eventd_context;

enum ctdb_freeze_mode {CTDB_FREEZE_NONE, CTDB_FREEZE_PENDING, CTDB_FREEZE_FROZEN};

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
	struct ctdb_tunable_list tunable;
	enum ctdb_freeze_mode freeze_mode;
	struct ctdb_freeze_handle *freeze_handle;
	bool freeze_transaction_started;
	uint32_t freeze_transaction_id;
	ctdb_sock_addr *address;
	const char *name;
	const char *db_directory;
	const char *db_directory_persistent;
	const char *db_directory_state;
	struct tdb_wrap *db_persistent_health;
	uint32_t db_persistent_startup_generation;
	uint64_t db_persistent_check_errors;
	uint64_t max_persistent_check_errors;
	const char *transport;
	const char *recovery_lock;
	uint32_t pnn; /* our own pnn */
	uint32_t num_nodes;
	uint32_t num_connected;
	unsigned flags;
	uint32_t capabilities;
	struct reqid_context *idr;
	struct ctdb_node **nodes; /* array of nodes in the cluster - indexed by vnn */
	struct ctdb_vnn *vnn; /* list of public ip addresses and interfaces */
	struct ctdb_interface *ifaces; /* list of local interfaces */
	char *err_msg;
	const struct ctdb_methods *methods; /* transport methods */
	const struct ctdb_upcalls *upcalls; /* transport upcalls */
	void *transport_data; /* private to transport */
	struct ctdb_db_context *db_list;
	struct srvid_context *srv;
	struct srvid_context *tunnels;
	struct ctdb_daemon_data daemon;
	struct ctdb_statistics statistics;
	struct ctdb_statistics statistics_current;
#define MAX_STAT_HISTORY 100
	struct ctdb_statistics statistics_history[MAX_STAT_HISTORY];
	struct ctdb_vnn_map *vnn_map;
	uint32_t num_clients;
	uint32_t recovery_master;
	struct ctdb_client_ip *client_ip_list;
	bool do_checkpublicip;
	bool do_setsched;
	const char *event_script_dir;
	const char *notification_script;
	pid_t ctdbd_pid;
	pid_t recoverd_pid;
	enum ctdb_runstate runstate;
	struct ctdb_monitor_state *monitor;
	int start_as_disabled;
	int start_as_stopped;
	bool valgrinding;
	uint32_t *recd_ping_count;
	TALLOC_CTX *recd_ctx; /* a context used to track recoverd monitoring events */
	TALLOC_CTX *release_ips_ctx; /* a context used to automatically drop all IPs if we fail to recover the node */

	struct eventd_context *ectx;

	TALLOC_CTX *banning_ctx;

	struct ctdb_vacuum_child_context *vacuumer;

	/* mapping from pid to ctdb_client * */
	struct ctdb_client_pid_list *client_pids;

	/* Used to defer db attach requests while in recovery mode */
	struct ctdb_deferred_attach_context *deferred_attach;

	/* if we are a child process, do we have a domain socket to send controls on */
	bool can_send_controls;

	struct ctdb_reloadips_handle *reload_ips;

	const char *nodes_file;
	const char *public_addresses_file;
	struct trbt_tree *child_processes; 

	/* Used for locking record/db/alldb */
	struct lock_context *lock_current;
	struct lock_context *lock_pending;
};

struct ctdb_db_hot_key {
	uint32_t count;
	TDB_DATA key;
	uint32_t last_logged_count;
};

struct ctdb_db_context {
	struct ctdb_db_context *next, *prev;
	struct ctdb_context *ctdb;
	uint32_t db_id;
	uint8_t db_flags;
	const char *db_name;
	const char *db_path;
	struct tdb_wrap *ltdb;
	struct tdb_context *rottdb; /* ReadOnly tracking TDB */
	struct ctdb_registered_call *calls; /* list of registered calls */
	uint32_t seqnum;
	struct tevent_timer *seqnum_update;
	struct ctdb_traverse_local_handle *traverse;
	struct ctdb_vacuum_handle *vacuum_handle;
	char *unhealthy_reason;
	int pending_requests;
	struct revokechild_handle *revokechild_active;
	struct ctdb_persistent_state *persistent_state;
	struct trbt_tree *delete_queue;
	struct trbt_tree *fetch_queue;
	struct trbt_tree *sticky_records; 
	int (*ctdb_ltdb_store_fn)(struct ctdb_db_context *ctdb_db,
				  TDB_DATA key,
				  struct ctdb_ltdb_header *header,
				  TDB_DATA data);

	/* used to track which records we are currently fetching
	   so we can avoid sending duplicate fetch requests
	*/
	struct trbt_tree *deferred_fetch;
	struct trbt_tree *defer_dmaster;

	struct ctdb_db_statistics_old statistics;
	struct ctdb_db_hot_key hot_keys[MAX_HOT_KEYS];

	struct lock_context *lock_current;
	struct lock_context *lock_pending;
	unsigned int lock_num_current;
	struct db_hash_context *lock_log;

	struct ctdb_call_state *pending_calls;

	enum ctdb_freeze_mode freeze_mode;
	struct ctdb_db_freeze_handle *freeze_handle;
	bool freeze_transaction_started;
	uint32_t freeze_transaction_id;
	uint32_t generation;

	bool invalid_records;
	bool push_started;
	void *push_state;

	struct hash_count_context *migratedb;
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


enum call_state {CTDB_CALL_WAIT, CTDB_CALL_DONE, CTDB_CALL_ERROR};

/*
  state of a in-progress ctdb call
*/
struct ctdb_call_state {
	struct ctdb_call_state *next, *prev;
	enum call_state state;
	uint32_t reqid;
	struct ctdb_req_call_old *c;
	struct ctdb_db_context *ctdb_db;
	const char *errmsg;
	struct ctdb_call *call;
	uint32_t generation;
	struct {
		void (*fn)(struct ctdb_call_state *);
		void *private_data;
	} async;
};

/* internal prototypes */

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

extern int script_log_level;
extern bool fast_start;
extern const char *ctdbd_pidfile;

typedef void (*deferred_requeue_fn)(void *call_context, struct ctdb_req_header *hdr);


/* from tcp/ and ib/ */

int ctdb_tcp_init(struct ctdb_context *ctdb);
int ctdb_ibw_init(struct ctdb_context *ctdb);

/* from ctdb_banning.c */

int32_t ctdb_control_set_ban_state(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_get_ban_state(struct ctdb_context *ctdb, TDB_DATA *outdata);
void ctdb_ban_self(struct ctdb_context *ctdb);

/* from ctdb_call.c */

struct ctdb_db_context *find_ctdb_db(struct ctdb_context *ctdb, uint32_t id);

void ctdb_request_dmaster(struct ctdb_context *ctdb,
			  struct ctdb_req_header *hdr);
void ctdb_reply_dmaster(struct ctdb_context *ctdb,
			struct ctdb_req_header *hdr);
void ctdb_request_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_error(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);

void ctdb_call_resend_db(struct ctdb_db_context *ctdb);
void ctdb_call_resend_all(struct ctdb_context *ctdb);

struct ctdb_call_state *ctdb_call_local_send(struct ctdb_db_context *ctdb_db,
					     struct ctdb_call *call,
					     struct ctdb_ltdb_header *header,
					     TDB_DATA *data);

struct ctdb_call_state *ctdb_daemon_call_send_remote(
					struct ctdb_db_context *ctdb_db,
					struct ctdb_call *call,
					struct ctdb_ltdb_header *header);
int ctdb_daemon_call_recv(struct ctdb_call_state *state,
			  struct ctdb_call *call);

int ctdb_start_revoke_ro_record(struct ctdb_context *ctdb,
				struct ctdb_db_context *ctdb_db,
				TDB_DATA key, struct ctdb_ltdb_header *header,
				TDB_DATA data);

int ctdb_add_revoke_deferred_call(struct ctdb_context *ctdb,
				  struct ctdb_db_context *ctdb_db,
				  TDB_DATA key, struct ctdb_req_header *hdr,
				  deferred_requeue_fn fn, void *call_context);

int ctdb_migration_init(struct ctdb_db_context *ctdb_db);

/* from server/ctdb_control.c */

int32_t ctdb_dump_memory(struct ctdb_context *ctdb, TDB_DATA *outdata);

void ctdb_request_control_reply(struct ctdb_context *ctdb,
				struct ctdb_req_control_old *c,
				TDB_DATA *outdata, int32_t status,
				const char *errormsg);

void ctdb_request_control(struct ctdb_context *ctdb,
			  struct ctdb_req_header *hdr);
void ctdb_reply_control(struct ctdb_context *ctdb,
			struct ctdb_req_header *hdr);

int ctdb_daemon_send_control(struct ctdb_context *ctdb, uint32_t destnode,
			     uint64_t srvid, uint32_t opcode,
			     uint32_t client_id, uint32_t flags,
			     TDB_DATA data,
			     ctdb_control_callback_fn_t callback,
			     void *private_data);

/* from server/ctdb_daemon.c */

int daemon_register_message_handler(struct ctdb_context *ctdb,
				    uint32_t client_id, uint64_t srvid);
int daemon_deregister_message_handler(struct ctdb_context *ctdb,
				      uint32_t client_id, uint64_t srvid);

void daemon_tunnel_handler(uint64_t tunnel_id, TDB_DATA data,
			   void *private_data);

struct ctdb_node *ctdb_find_node(struct ctdb_context *ctdb, uint32_t pnn);

int ctdb_start_daemon(struct ctdb_context *ctdb,
		      bool interactive,
		      bool test_mode_enabled);

struct ctdb_req_header *_ctdb_transport_allocate(struct ctdb_context *ctdb,
						 TALLOC_CTX *mem_ctx,
						 enum ctdb_operation operation,
						 size_t length, size_t slength,
						 const char *type);

#define ctdb_transport_allocate(ctdb, mem_ctx, operation, length, type) \
	(type *)_ctdb_transport_allocate(ctdb, mem_ctx, operation, length, \
					 sizeof(type), #type)

void ctdb_daemon_cancel_controls(struct ctdb_context *ctdb,
				 struct ctdb_node *node);

int ctdb_daemon_set_call(struct ctdb_context *ctdb, uint32_t db_id,
			 ctdb_fn_t fn, int id);

int ctdb_daemon_send_message(struct ctdb_context *ctdb, uint32_t pnn,
			     uint64_t srvid, TDB_DATA data);

int32_t ctdb_control_register_notify(struct ctdb_context *ctdb,
				     uint32_t client_id, TDB_DATA indata);
int32_t ctdb_control_deregister_notify(struct ctdb_context *ctdb,
				       uint32_t client_id, TDB_DATA indata);

struct ctdb_client *ctdb_find_client_by_pid(struct ctdb_context *ctdb,
					    pid_t pid);

int32_t ctdb_control_process_exists(struct ctdb_context *ctdb, pid_t pid);
int32_t ctdb_control_check_pid_srvid(struct ctdb_context *ctdb,
				     TDB_DATA indata);

int ctdb_control_getnodesfile(struct ctdb_context *ctdb, uint32_t opcode,
			      TDB_DATA indata, TDB_DATA *outdata);

void ctdb_shutdown_sequence(struct ctdb_context *ctdb, int exit_code);

int switch_from_server_to_client(struct ctdb_context *ctdb);

/* From server/ctdb_fork.c */

void ctdb_track_child(struct ctdb_context *ctdb, pid_t pid);

pid_t ctdb_fork(struct ctdb_context *ctdb);
pid_t ctdb_vfork_exec(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
		      const char *helper, int helper_argc,
		      const char **helper_argv);

struct tevent_signal *ctdb_init_sigchld(struct ctdb_context *ctdb);

int ctdb_kill(struct ctdb_context *ctdb, pid_t pid, int signum);

/* from server/ctdb_freeze.c */

int32_t ctdb_control_db_freeze(struct ctdb_context *ctdb,
			       struct ctdb_req_control_old *c,
			       uint32_t db_id, bool *async_reply);
int32_t ctdb_control_db_thaw(struct ctdb_context *ctdb, uint32_t db_id);

int32_t ctdb_control_freeze(struct ctdb_context *ctdb,
			    struct ctdb_req_control_old *c, bool *async_reply);
int32_t ctdb_control_thaw(struct ctdb_context *ctdb, bool check_recmode);

bool ctdb_blocking_freeze(struct ctdb_context *ctdb);

int32_t ctdb_control_db_transaction_start(struct ctdb_context *ctdb,
					  TDB_DATA indata);
int32_t ctdb_control_db_transaction_cancel(struct ctdb_context *ctdb,
					   TDB_DATA indata);
int32_t ctdb_control_db_transaction_commit(struct ctdb_context *ctdb,
					   TDB_DATA indata);

int32_t ctdb_control_wipe_database(struct ctdb_context *ctdb, TDB_DATA indata);

bool ctdb_db_frozen(struct ctdb_db_context *ctdb_db);
bool ctdb_db_all_frozen(struct ctdb_context *ctdb);
bool ctdb_db_allow_access(struct ctdb_db_context *ctdb_db);

/* from server/ctdb_keepalive.c */

void ctdb_start_keepalive(struct ctdb_context *ctdb);
void ctdb_stop_keepalive(struct ctdb_context *ctdb);

void ctdb_request_keepalive(struct ctdb_context *ctdb,
			    struct ctdb_req_header *hdr);

/* from server/ctdb_lock.c */

struct lock_request;

typedef int (*ctdb_db_handler_t)(struct ctdb_db_context *ctdb_db,
				 void *private_data);

int ctdb_db_iterator(struct ctdb_context *ctdb, ctdb_db_handler_t handler,
		     void *private_data);

int ctdb_lockdb_mark(struct ctdb_db_context *ctdb_db);

int ctdb_lockdb_unmark(struct ctdb_db_context *ctdb_db);

struct lock_request *ctdb_lock_record(TALLOC_CTX *mem_ctx,
				      struct ctdb_db_context *ctdb_db,
				      TDB_DATA key,
				      bool auto_mark,
				      void (*callback)(void *, bool),
				      void *private_data);

struct lock_request *ctdb_lock_db(TALLOC_CTX *mem_ctx,
				  struct ctdb_db_context *ctdb_db,
				  bool auto_mark,
				  void (*callback)(void *, bool),
				  void *private_data);

/* from ctdb_logging.c */

bool ctdb_logging_init(TALLOC_CTX *mem_ctx, const char *logging,
		       const char *debug_level);

int ctdb_set_child_logging(struct ctdb_context *ctdb);

/* from ctdb_logging_file.c */

void ctdb_log_init_file(void);

/* from ctdb_logging_syslog.c */

void ctdb_log_init_syslog(void);

/* from ctdb_ltdb_server.c */

int ctdb_ltdb_lock_requeue(struct ctdb_db_context *ctdb_db,
			   TDB_DATA key, struct ctdb_req_header *hdr,
			   void (*recv_pkt)(void *, struct ctdb_req_header *),
			   void *recv_context, bool ignore_generation);

int ctdb_ltdb_lock_fetch_requeue(struct ctdb_db_context *ctdb_db,
				 TDB_DATA key, struct ctdb_ltdb_header *header,
				 struct ctdb_req_header *hdr, TDB_DATA *data,
				 void (*recv_pkt)(void *, struct ctdb_req_header *),
				 void *recv_context, bool ignore_generation);

int ctdb_load_persistent_health(struct ctdb_context *ctdb,
				struct ctdb_db_context *ctdb_db);
int ctdb_update_persistent_health(struct ctdb_context *ctdb,
				  struct ctdb_db_context *ctdb_db,
				  const char *reason,/* NULL means healthy */
				  unsigned int num_healthy_nodes);
int ctdb_recheck_persistent_health(struct ctdb_context *ctdb);

int32_t ctdb_control_db_set_healthy(struct ctdb_context *ctdb,
				    TDB_DATA indata);
int32_t ctdb_control_db_get_health(struct ctdb_context *ctdb,
				   TDB_DATA indata, TDB_DATA *outdata);

int ctdb_set_db_readonly(struct ctdb_context *ctdb,
			 struct ctdb_db_context *ctdb_db);

int ctdb_process_deferred_attach(struct ctdb_context *ctdb);

int32_t ctdb_control_db_attach(struct ctdb_context *ctdb,
			       TDB_DATA indata,
			       TDB_DATA *outdata,
			       uint8_t db_flags,
			       uint32_t srcnode,
			       uint32_t client_id,
			       struct ctdb_req_control_old *c,
			       bool *async_reply);
int32_t ctdb_control_db_detach(struct ctdb_context *ctdb, TDB_DATA indata,
			       uint32_t client_id);

int ctdb_attach_databases(struct ctdb_context *ctdb);

int32_t ctdb_ltdb_update_seqnum(struct ctdb_context *ctdb, uint32_t db_id,
				uint32_t srcnode);
int32_t ctdb_ltdb_enable_seqnum(struct ctdb_context *ctdb, uint32_t db_id);

int ctdb_set_db_sticky(struct ctdb_context *ctdb,
		       struct ctdb_db_context *ctdb_db);

void ctdb_db_statistics_reset(struct ctdb_db_context *ctdb_db);

int32_t ctdb_control_get_db_statistics(struct ctdb_context *ctdb,
				       uint32_t db_id, TDB_DATA *outdata);

/* from ctdb_monitor.c */

void ctdb_run_notification_script(struct ctdb_context *ctdb, const char *event);

void ctdb_stop_monitoring(struct ctdb_context *ctdb);

void ctdb_wait_for_first_recovery(struct ctdb_context *ctdb);

int32_t ctdb_control_modflags(struct ctdb_context *ctdb, TDB_DATA indata);

/* from ctdb_persistent.c */

void ctdb_persistent_finish_trans3_commits(struct ctdb_context *ctdb);

int32_t ctdb_control_trans3_commit(struct ctdb_context *ctdb,
				   struct ctdb_req_control_old *c,
				   TDB_DATA recdata, bool *async_reply);

int32_t ctdb_control_start_persistent_update(struct ctdb_context *ctdb,
					     struct ctdb_req_control_old *c,
					     TDB_DATA recdata);
int32_t ctdb_control_cancel_persistent_update(struct ctdb_context *ctdb,
					      struct ctdb_req_control_old *c,
					      TDB_DATA recdata);

int32_t ctdb_control_get_db_seqnum(struct ctdb_context *ctdb,
				   TDB_DATA indata, TDB_DATA *outdata);

/* from ctdb_recover.c */

int ctdb_control_getvnnmap(struct ctdb_context *ctdb, uint32_t opcode,
			   TDB_DATA indata, TDB_DATA *outdata);
int ctdb_control_setvnnmap(struct ctdb_context *ctdb, uint32_t opcode,
			   TDB_DATA indata, TDB_DATA *outdata);

int ctdb_control_getdbmap(struct ctdb_context *ctdb, uint32_t opcode,
			  TDB_DATA indata, TDB_DATA *outdata);
int ctdb_control_getnodemap(struct ctdb_context *ctdb, uint32_t opcode,
			    TDB_DATA indata, TDB_DATA *outdata);

int ctdb_control_reload_nodes_file(struct ctdb_context *ctdb, uint32_t opcode);

int32_t ctdb_control_pull_db(struct ctdb_context *ctdb, TDB_DATA indata,
			     TDB_DATA *outdata);
int32_t ctdb_control_push_db(struct ctdb_context *ctdb, TDB_DATA indata);

int32_t ctdb_control_db_pull(struct ctdb_context *ctdb,
			     struct ctdb_req_control_old *c,
			     TDB_DATA indata, TDB_DATA *outdata);
int32_t ctdb_control_db_push_start(struct ctdb_context *ctdb,
				   TDB_DATA indata);
int32_t ctdb_control_db_push_confirm(struct ctdb_context *ctdb,
				     TDB_DATA indata, TDB_DATA *outdata);

int ctdb_deferred_drop_all_ips(struct ctdb_context *ctdb);

int32_t ctdb_control_set_recmode(struct ctdb_context *ctdb,
				 struct ctdb_req_control_old *c,
				 TDB_DATA indata, bool *async_reply,
				 const char **errormsg);

int32_t ctdb_control_end_recovery(struct ctdb_context *ctdb,
				 struct ctdb_req_control_old *c,
				 bool *async_reply);
int32_t ctdb_control_start_recovery(struct ctdb_context *ctdb,
				 struct ctdb_req_control_old *c,
				 bool *async_reply);

int32_t ctdb_control_try_delete_records(struct ctdb_context *ctdb,
					TDB_DATA indata, TDB_DATA *outdata);

int32_t ctdb_control_get_capabilities(struct ctdb_context *ctdb,
				      TDB_DATA *outdata);

int32_t ctdb_control_recd_ping(struct ctdb_context *ctdb);
int32_t ctdb_control_set_recmaster(struct ctdb_context *ctdb,
				   uint32_t opcode, TDB_DATA indata);

void ctdb_node_become_inactive(struct ctdb_context *ctdb);

int32_t ctdb_control_stop_node(struct ctdb_context *ctdb);
int32_t ctdb_control_continue_node(struct ctdb_context *ctdb);

/* from ctdb_recoverd.c */

int ctdb_start_recoverd(struct ctdb_context *ctdb);
void ctdb_stop_recoverd(struct ctdb_context *ctdb);

/* from ctdb_server.c */

int ctdb_set_transport(struct ctdb_context *ctdb, const char *transport);

struct ctdb_node *ctdb_ip_to_node(struct ctdb_context *ctdb,
				  const ctdb_sock_addr *nodeip);
uint32_t ctdb_ip_to_pnn(struct ctdb_context *ctdb,
			const ctdb_sock_addr *nodeip);

void ctdb_load_nodes_file(struct ctdb_context *ctdb);

int ctdb_set_address(struct ctdb_context *ctdb, const char *address);

uint32_t ctdb_get_num_active_nodes(struct ctdb_context *ctdb);

void ctdb_input_pkt(struct ctdb_context *ctdb, struct ctdb_req_header *);

void ctdb_node_dead(struct ctdb_node *node);
void ctdb_node_connected(struct ctdb_node *node);

void ctdb_queue_packet(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_queue_packet_opcode(struct ctdb_context *ctdb,
			      struct ctdb_req_header *hdr, unsigned opcode);

/* from ctdb_serverids.c */

int32_t ctdb_control_register_server_id(struct ctdb_context *ctdb,
					uint32_t client_id, TDB_DATA indata);
int32_t ctdb_control_check_server_id(struct ctdb_context *ctdb,
				     TDB_DATA indata);
int32_t ctdb_control_unregister_server_id(struct ctdb_context *ctdb,
					  TDB_DATA indata);
int32_t ctdb_control_get_server_id_list(struct ctdb_context *ctdb,
					TDB_DATA *outdata);

/* from ctdb_statistics.c */

int ctdb_statistics_init(struct ctdb_context *ctdb);

int32_t ctdb_control_get_stat_history(struct ctdb_context *ctdb,
				      struct ctdb_req_control_old *c,
				      TDB_DATA *outdata);

/* from ctdb_takeover.c */

int32_t ctdb_control_takeover_ip(struct ctdb_context *ctdb,
				 struct ctdb_req_control_old *c,
				 TDB_DATA indata,
				 bool *async_reply);
int32_t ctdb_control_release_ip(struct ctdb_context *ctdb,
				 struct ctdb_req_control_old *c,
				 TDB_DATA indata,
				 bool *async_reply);
int32_t ctdb_control_ipreallocated(struct ctdb_context *ctdb,
				 struct ctdb_req_control_old *c,
				 bool *async_reply);

int ctdb_set_public_addresses(struct ctdb_context *ctdb, bool check_addresses);

int32_t ctdb_control_tcp_client(struct ctdb_context *ctdb, uint32_t client_id,
				TDB_DATA indata);
int32_t ctdb_control_tcp_add(struct ctdb_context *ctdb, TDB_DATA indata,
			     bool tcp_update_needed);
int32_t ctdb_control_tcp_remove(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_startup(struct ctdb_context *ctdb, uint32_t vnn);

void ctdb_takeover_client_destructor_hook(struct ctdb_client *client);

void ctdb_release_all_ips(struct ctdb_context *ctdb);

int32_t ctdb_control_get_public_ips(struct ctdb_context *ctdb,
				    struct ctdb_req_control_old *c,
				    TDB_DATA *outdata);
int32_t ctdb_control_get_public_ip_info(struct ctdb_context *ctdb,
					struct ctdb_req_control_old *c,
					TDB_DATA indata, TDB_DATA *outdata);

int32_t ctdb_control_get_ifaces(struct ctdb_context *ctdb,
				struct ctdb_req_control_old *c,
				TDB_DATA *outdata);
int32_t ctdb_control_set_iface_link(struct ctdb_context *ctdb,
				    struct ctdb_req_control_old *c,
				    TDB_DATA indata);

int32_t ctdb_control_set_tcp_tickle_list(struct ctdb_context *ctdb,
					 TDB_DATA indata);
int32_t ctdb_control_get_tcp_tickle_list(struct ctdb_context *ctdb,
					 TDB_DATA indata, TDB_DATA *outdata);

void ctdb_start_tcp_tickle_update(struct ctdb_context *ctdb);

int32_t ctdb_control_send_gratious_arp(struct ctdb_context *ctdb,
				       TDB_DATA indata);

int32_t ctdb_control_add_public_address(struct ctdb_context *ctdb,
					TDB_DATA indata);
int32_t ctdb_control_del_public_address(struct ctdb_context *ctdb,
					TDB_DATA recdata);

int32_t ctdb_control_reload_public_ips(struct ctdb_context *ctdb,
				       struct ctdb_req_control_old *c,
				       bool *async_reply);

/* from ctdb_traverse.c */

int32_t ctdb_control_traverse_all_ext(struct ctdb_context *ctdb,
				      TDB_DATA data, TDB_DATA *outdata);
int32_t ctdb_control_traverse_all(struct ctdb_context *ctdb,
				  TDB_DATA data, TDB_DATA *outdata);
int32_t ctdb_control_traverse_data(struct ctdb_context *ctdb,
				   TDB_DATA data, TDB_DATA *outdata);
int32_t ctdb_control_traverse_kill(struct ctdb_context *ctdb, TDB_DATA indata,
				    TDB_DATA *outdata, uint32_t srcnode);

int32_t ctdb_control_traverse_start_ext(struct ctdb_context *ctdb,
					TDB_DATA indata, TDB_DATA *outdata,
					uint32_t srcnode, uint32_t client_id);
int32_t ctdb_control_traverse_start(struct ctdb_context *ctdb,
				    TDB_DATA indata, TDB_DATA *outdata,
				    uint32_t srcnode, uint32_t client_id);

/* from ctdb_tunables.c */

void ctdb_tunables_set_defaults(struct ctdb_context *ctdb);

int32_t ctdb_control_get_tunable(struct ctdb_context *ctdb, TDB_DATA indata,
				 TDB_DATA *outdata);
int32_t ctdb_control_set_tunable(struct ctdb_context *ctdb, TDB_DATA indata);
int32_t ctdb_control_list_tunables(struct ctdb_context *ctdb,
				   TDB_DATA *outdata);

/* from ctdb_tunnel.c */

int32_t ctdb_control_tunnel_register(struct ctdb_context *ctdb,
				     uint32_t client_id, uint64_t tunnel_id);
int32_t ctdb_control_tunnel_deregister(struct ctdb_context *ctdb,
				       uint32_t client_id, uint64_t tunnel_id);

int ctdb_daemon_send_tunnel(struct ctdb_context *ctdb, uint32_t destnode,
			    uint64_t tunnel_id, uint32_t client_id,
			    TDB_DATA data);

void ctdb_request_tunnel(struct ctdb_context *ctdb,
			 struct ctdb_req_header *hdr);

/* from ctdb_update_record.c */

int32_t ctdb_control_update_record(struct ctdb_context *ctdb,
				   struct ctdb_req_control_old *c,
				   TDB_DATA recdata, bool *async_reply);

/* from ctdb_uptime.c */

int32_t ctdb_control_uptime(struct ctdb_context *ctdb, TDB_DATA *outdata);

/* from ctdb_vacuum.c */

int32_t ctdb_control_db_vacuum(struct ctdb_context *ctdb,
			       struct ctdb_req_control_old *c,
			       TDB_DATA indata,
			       bool *async_reply);

void ctdb_stop_vacuuming(struct ctdb_context *ctdb);
int ctdb_vacuum_init(struct ctdb_db_context *ctdb_db);

int32_t ctdb_control_schedule_for_deletion(struct ctdb_context *ctdb,
					   TDB_DATA indata);
int32_t ctdb_local_schedule_for_deletion(struct ctdb_db_context *ctdb_db,
					 const struct ctdb_ltdb_header *hdr,
					 TDB_DATA key);

void ctdb_local_remove_from_delete_queue(struct ctdb_db_context *ctdb_db,
					 const struct ctdb_ltdb_header *hdr,
					 const TDB_DATA key);

int32_t ctdb_control_vacuum_fetch(struct ctdb_context *ctdb, TDB_DATA indata);

/* from eventscript.c */

int ctdb_start_eventd(struct ctdb_context *ctdb);
void ctdb_stop_eventd(struct ctdb_context *ctdb);

int ctdb_event_script_callback(struct ctdb_context *ctdb,
			       TALLOC_CTX *mem_ctx,
			       void (*callback)(struct ctdb_context *,
						int, void *),
			       void *private_data,
			       enum ctdb_event call,
			       const char *fmt, ...) PRINTF_ATTRIBUTE(6,7);

int ctdb_event_script_args(struct ctdb_context *ctdb,
			   enum ctdb_event call,
			   const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);

int ctdb_event_script(struct ctdb_context *ctdb,
		      enum ctdb_event call);

#endif
