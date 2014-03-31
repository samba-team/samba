/*
   ctdb database library: old client interface

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

#ifndef _CTDB_CLIENT_H
#define _CTDB_CLIENT_H
#include "ctdb_protocol.h"

enum control_state {CTDB_CONTROL_WAIT, CTDB_CONTROL_DONE, CTDB_CONTROL_ERROR, CTDB_CONTROL_TIMEOUT};

struct ctdb_client_control_state {
	struct ctdb_context *ctdb;
	uint32_t reqid;
	int32_t status;
	TDB_DATA outdata;
	enum control_state state;
	char *errormsg;
	struct ctdb_req_control *c;

	/* if we have a callback registered for the completion (or failure) of
	   this control
	   if a callback is used, it MUST talloc_free the cb_data passed to it
	*/
	struct {
		void (*fn)(struct ctdb_client_control_state *);
		void *private_data;
	} async;
};

struct ctdb_client_notify_register {
	uint64_t srvid;
	uint32_t len;
	uint8_t notify_data[1];
};

struct ctdb_client_notify_deregister {
	uint64_t srvid;
};

struct tevent_context;

/*
  initialise ctdb subsystem
*/
struct ctdb_context *ctdb_init(struct tevent_context *ev);

/*
  choose the transport
*/
int ctdb_set_transport(struct ctdb_context *ctdb, const char *transport);

/*
  set some flags
*/
void ctdb_set_flags(struct ctdb_context *ctdb, unsigned flags);

/*
  tell ctdb what address to listen on, in transport specific format
*/
int ctdb_set_address(struct ctdb_context *ctdb, const char *address);

int ctdb_set_socketname(struct ctdb_context *ctdb, const char *socketname);
const char *ctdb_get_socketname(struct ctdb_context *ctdb);

/*
  Check that a specific ip address exists in the node list and returns
  the id for the node or -1
*/
int ctdb_ip_to_nodeid(struct ctdb_context *ctdb, const char *nodeip);

/*
  start the ctdb protocol
*/
int ctdb_start(struct ctdb_context *ctdb);

/*
  attach to a ctdb database
*/
struct ctdb_db_context *ctdb_attach(struct ctdb_context *ctdb,
				    struct timeval timeout,
				    const char *name,
				    bool persistent,
				    uint32_t tdb_flags);

int ctdb_detach(struct ctdb_context *ctdb, uint32_t db_id);

/*
  find an attached ctdb_db handle given a name
 */
struct ctdb_db_context *ctdb_db_handle(struct ctdb_context *ctdb, const char *name);

/*
  error string for last ctdb error
*/
const char *ctdb_errstr(struct ctdb_context *);

/* a ctdb call function */
typedef int (*ctdb_fn_t)(struct ctdb_call_info *);

/*
  setup a ctdb call function
*/
int ctdb_set_call(struct ctdb_db_context *ctdb_db, ctdb_fn_t fn, uint32_t id);



/*
  make a ctdb call. The associated ctdb call function will be called on the DMASTER
  for the given record
*/
int ctdb_call(struct ctdb_db_context *ctdb_db, struct ctdb_call *call);

/*
  initiate an ordered ctdb cluster shutdown
  this function will never return
*/
void ctdb_shutdown(struct ctdb_context *ctdb);

/* return pnn of this node */
uint32_t ctdb_get_pnn(struct ctdb_context *ctdb);

/*
  return the number of nodes
*/
uint32_t ctdb_get_num_nodes(struct ctdb_context *ctdb);

/* setup a handler for ctdb messages */
typedef void (*ctdb_msg_fn_t)(struct ctdb_context *, uint64_t srvid,
				  TDB_DATA data, void *);
int ctdb_client_set_message_handler(struct ctdb_context *ctdb, uint64_t srvid,
			     ctdb_msg_fn_t handler,
			     void *private_data);
int ctdb_client_remove_message_handler(struct ctdb_context *ctdb,
				       uint64_t srvid, void *private_data);
int ctdb_client_check_message_handlers(struct ctdb_context *ctdb,
				       uint64_t *ids, uint32_t num,
				       uint8_t *result);

int ctdb_call(struct ctdb_db_context *ctdb_db, struct ctdb_call *call);
struct ctdb_client_call_state *ctdb_call_send(struct ctdb_db_context *ctdb_db, struct ctdb_call *call);
int ctdb_call_recv(struct ctdb_client_call_state *state, struct ctdb_call *call);

/* send a ctdb message */
int ctdb_client_send_message(struct ctdb_context *ctdb, uint32_t pnn,
		      uint64_t srvid, TDB_DATA data);


/*
   Fetch a ctdb record from a remote node
 . Underneath this will force the
   dmaster for the record to be moved to the local node.
*/
struct ctdb_record_handle *ctdb_fetch_lock(struct ctdb_db_context *ctdb_db, TALLOC_CTX *mem_ctx,
					   TDB_DATA key, TDB_DATA *data);

struct ctdb_record_handle *ctdb_fetch_readonly_lock(struct ctdb_db_context *ctdb_db, TALLOC_CTX *mem_ctx, TDB_DATA key, TDB_DATA *data, int read_only);

int ctdb_record_store(struct ctdb_record_handle *h, TDB_DATA data);

int ctdb_fetch(struct ctdb_db_context *ctdb_db, TALLOC_CTX *mem_ctx,
	       TDB_DATA key, TDB_DATA *data);

int ctdb_register_message_handler(struct ctdb_context *ctdb,
				  TALLOC_CTX *mem_ctx,
				  uint64_t srvid,
				  ctdb_msg_fn_t handler,
				  void *private_data);

struct ctdb_db_context *find_ctdb_db(struct ctdb_context *ctdb, uint32_t id);


struct ctdb_context *ctdb_cmdline_client(struct tevent_context *ev,
					 struct timeval req_timeout);

struct ctdb_statistics;
int ctdb_ctrl_statistics(struct ctdb_context *ctdb, uint32_t destnode, struct ctdb_statistics *status);
int ctdb_ctrl_dbstatistics(struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid,
			   TALLOC_CTX *mem_ctx, struct ctdb_db_statistics **dbstat);

int ctdb_ctrl_shutdown(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode);

struct ctdb_vnn_map;
int ctdb_ctrl_getvnnmap(struct ctdb_context *ctdb,
		struct timeval timeout, uint32_t destnode,
		TALLOC_CTX *mem_ctx, struct ctdb_vnn_map **vnnmap);
int ctdb_ctrl_setvnnmap(struct ctdb_context *ctdb,
		struct timeval timeout, uint32_t destnode,
		TALLOC_CTX *mem_ctx, struct ctdb_vnn_map *vnnmap);

/* table that contains a list of all dbids on a node
 */
struct ctdb_dbid_map {
	uint32_t num;
	struct ctdb_dbid {
		uint32_t dbid;
#define CTDB_DB_FLAGS_PERSISTENT	0x01
#define CTDB_DB_FLAGS_READONLY		0x02
#define CTDB_DB_FLAGS_STICKY		0x04
		uint8_t flags;
	} dbs[1];
};
int ctdb_ctrl_getdbmap(struct ctdb_context *ctdb,
	struct timeval timeout, uint32_t destnode,
	TALLOC_CTX *mem_ctx, struct ctdb_dbid_map **dbmap);


struct ctdb_node_map;

int ctdb_ctrl_getnodemap(struct ctdb_context *ctdb,
		    struct timeval timeout, uint32_t destnode,
		    TALLOC_CTX *mem_ctx, struct ctdb_node_map **nodemap);

int ctdb_ctrl_getnodemapv4(struct ctdb_context *ctdb,
		    struct timeval timeout, uint32_t destnode,
		    TALLOC_CTX *mem_ctx, struct ctdb_node_map **nodemap);

int ctdb_ctrl_reload_nodes_file(struct ctdb_context *ctdb,
		    struct timeval timeout, uint32_t destnode);

struct ctdb_key_list {
	uint32_t dbid;
	uint32_t num;
	TDB_DATA *keys;
	struct ctdb_ltdb_header *headers;
	TDB_DATA *data;
};

int ctdb_ctrl_pulldb(
       struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid,
       uint32_t lmaster, TALLOC_CTX *mem_ctx,
       struct timeval timeout, TDB_DATA *outdata);

struct ctdb_client_control_state *ctdb_ctrl_pulldb_send(
       struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid,
       uint32_t lmaster, TALLOC_CTX *mem_ctx, struct timeval timeout);

int ctdb_ctrl_pulldb_recv(
       struct ctdb_context *ctdb,
       TALLOC_CTX *mem_ctx, struct ctdb_client_control_state *state,
       TDB_DATA *outdata);

int ctdb_ctrl_pushdb(
       struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid,
       TALLOC_CTX *mem_ctx,
       struct timeval timeout, TDB_DATA indata);

struct ctdb_client_control_state *ctdb_ctrl_pushdb_send(
       struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid,
       TALLOC_CTX *mem_ctx, struct timeval timeout,
       TDB_DATA indata);

int ctdb_ctrl_pushdb_recv(
       struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
       struct ctdb_client_control_state *state);


int ctdb_ctrl_copydb(struct ctdb_context *ctdb,
	struct timeval timeout, uint32_t sourcenode,
	uint32_t destnode, uint32_t dbid, uint32_t lmaster,
	TALLOC_CTX *mem_ctx);

int ctdb_ctrl_getdbpath(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t dbid, TALLOC_CTX *mem_ctx, const char **path);
int ctdb_ctrl_getdbname(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t dbid, TALLOC_CTX *mem_ctx, const char **name);
int ctdb_ctrl_getdbhealth(struct ctdb_context *ctdb,
			  struct timeval timeout,
			  uint32_t destnode,
			  uint32_t dbid, TALLOC_CTX *mem_ctx,
			  const char **reason);
int ctdb_ctrl_getdbseqnum(struct ctdb_context *ctdb, struct timeval timeout,
			  uint32_t destnode, uint32_t dbid, uint64_t *seqnum);
int ctdb_ctrl_createdb(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, const char *name, bool persistent);

int ctdb_ctrl_process_exists(struct ctdb_context *ctdb, uint32_t destnode, pid_t pid);

int ctdb_ctrl_ping(struct ctdb_context *ctdb, uint32_t destnode);

int ctdb_ctrl_get_runstate(struct ctdb_context *ctdb, 
			   struct timeval timeout, 
			   uint32_t destnode,
			   uint32_t *runstate);

int ctdb_ctrl_get_config(struct ctdb_context *ctdb);

int ctdb_ctrl_get_debuglevel(struct ctdb_context *ctdb, uint32_t destnode, int32_t *level);
int ctdb_ctrl_set_debuglevel(struct ctdb_context *ctdb, uint32_t destnode, int32_t level);

/*
  change dmaster for all keys in the database to the new value
 */
int ctdb_ctrl_setdmaster(struct ctdb_context *ctdb,
	struct timeval timeout, uint32_t destnode,
	TALLOC_CTX *mem_ctx, uint32_t dbid, uint32_t dmaster);

/*
  write a record on a specific db (this implicitely updates dmaster of the record to locally be the vnn of the node where the control is executed on)
 */
int ctdb_ctrl_write_record(struct ctdb_context *ctdb, uint32_t destnode, TALLOC_CTX *mem_ctx, uint32_t dbid, TDB_DATA key, TDB_DATA data);

#define CTDB_RECOVERY_NORMAL		0
#define CTDB_RECOVERY_ACTIVE		1

/*
  get the recovery mode of a remote node
 */
int ctdb_ctrl_getrecmode(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, uint32_t *recmode);

struct ctdb_client_control_state *ctdb_ctrl_getrecmode_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_getrecmode_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct ctdb_client_control_state *state, uint32_t *recmode);


/*
  set the recovery mode of a remote node
 */
int ctdb_ctrl_setrecmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t recmode);
/*
  get the monitoring mode of a remote node
 */
int ctdb_ctrl_getmonmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *monmode);

/*
  set the monitoring mode of a remote node to active
 */
int ctdb_ctrl_enable_monmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode);

/*
  set the monitoring mode of a remote node to disabled
 */
int ctdb_ctrl_disable_monmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode);


/*
  get the recovery master of a remote node
 */
int ctdb_ctrl_getrecmaster(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, uint32_t *recmaster);

struct ctdb_client_control_state *ctdb_ctrl_getrecmaster_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_getrecmaster_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct ctdb_client_control_state *state, uint32_t *recmaster);



/*
  set the recovery master of a remote node
 */
int ctdb_ctrl_setrecmaster(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t recmaster);

uint32_t *ctdb_get_connected_nodes(struct ctdb_context *ctdb,
				   struct timeval timeout,
				   TALLOC_CTX *mem_ctx,
				   uint32_t *num_nodes);

int ctdb_statistics_reset(struct ctdb_context *ctdb, uint32_t destnode);

int ctdb_set_logfile(struct ctdb_context *ctdb, const char *logfile, bool use_syslog);

typedef int (*ctdb_traverse_func)(struct ctdb_context *, TDB_DATA, TDB_DATA, void *);
int ctdb_traverse(struct ctdb_db_context *ctdb_db, ctdb_traverse_func fn, void *private_data);

struct ctdb_dump_db_context {
	FILE *f;
	bool printemptyrecords;
	bool printdatasize;
	bool printlmaster;
	bool printhash;
	bool printrecordflags;
};

int ctdb_dumpdb_record(struct ctdb_context *ctdb, TDB_DATA key, TDB_DATA data, void *p);
int ctdb_dump_db(struct ctdb_db_context *ctdb_db,
		 struct ctdb_dump_db_context *ctx);

/*
  get the pid of a ctdb daemon
 */
int ctdb_ctrl_getpid(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *pid);

int ctdb_ctrl_freeze(struct ctdb_context *ctdb, struct timeval timeout,
			uint32_t destnode);
int ctdb_ctrl_freeze_priority(struct ctdb_context *ctdb, struct timeval timeout,
			      uint32_t destnode, uint32_t priority);

struct ctdb_client_control_state *
ctdb_ctrl_freeze_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
		      struct timeval timeout, uint32_t destnode,
		      uint32_t priority);

int ctdb_ctrl_freeze_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			struct ctdb_client_control_state *state);

int ctdb_ctrl_thaw_priority(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t priority);
int ctdb_ctrl_thaw(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_getpnn(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_get_tunable(struct ctdb_context *ctdb,
			  struct timeval timeout,
			  uint32_t destnode,
			  const char *name, uint32_t *value);

int ctdb_ctrl_set_tunable(struct ctdb_context *ctdb,
			  struct timeval timeout,
			  uint32_t destnode,
			  const char *name, uint32_t value);

int ctdb_ctrl_list_tunables(struct ctdb_context *ctdb,
			    struct timeval timeout,
			    uint32_t destnode,
			    TALLOC_CTX *mem_ctx,
			    const char ***list, uint32_t *count);

int ctdb_ctrl_modflags(struct ctdb_context *ctdb,
		       struct timeval timeout,
		       uint32_t destnode,
		       uint32_t set, uint32_t clear);

enum ctdb_server_id_type {
	SERVER_TYPE_SAMBA=1,
	SERVER_TYPE_NFSD=2,
	SERVER_TYPE_ISCSID=3
};

struct ctdb_server_id {
	enum ctdb_server_id_type type;
	uint32_t pnn;
	uint32_t server_id;
};

struct ctdb_server_id_list {
	uint32_t num;
	struct ctdb_server_id server_ids[1];
};


int ctdb_ctrl_register_server_id(struct ctdb_context *ctdb,
		struct timeval timeout,
		struct ctdb_server_id *id);
int ctdb_ctrl_unregister_server_id(struct ctdb_context *ctdb,
		struct timeval timeout,
		struct ctdb_server_id *id);
int ctdb_ctrl_check_server_id(struct ctdb_context *ctdb,
		struct timeval timeout, uint32_t destnode,
		struct ctdb_server_id *id, uint32_t *status);
int ctdb_ctrl_get_server_id_list(struct ctdb_context *ctdb,
		TALLOC_CTX *mem_ctx,
		struct timeval timeout, uint32_t destnode,
		struct ctdb_server_id_list **svid_list);

struct ctdb_uptime {
	struct timeval current_time;
	struct timeval ctdbd_start_time;
	struct timeval last_recovery_started;
	struct timeval last_recovery_finished;
};

/*
  struct for tcp_client control
  this is an ipv4 only version of this structure used by samba
  samba will later be migrated over to use the
  ctdb_control_tcp_addr structure instead
 */
struct ctdb_control_tcp {
	struct sockaddr_in src;  /* samba uses this */
	struct sockaddr_in dest; /* samba uses this */
};
/* new style structure */
struct ctdb_control_tcp_addr {
	ctdb_sock_addr src;
	ctdb_sock_addr dest;
};

int ctdb_socket_connect(struct ctdb_context *ctdb);

/*
  get the uptime of a remote node
 */
int ctdb_ctrl_uptime(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, struct ctdb_uptime **uptime);

struct ctdb_client_control_state *ctdb_ctrl_uptime_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_uptime_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct ctdb_client_control_state *state, struct ctdb_uptime **uptime);

int ctdb_ctrl_end_recovery(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_getreclock(struct ctdb_context *ctdb,
	struct timeval timeout, uint32_t destnode,
	TALLOC_CTX *mem_ctx, const char **reclock);
int ctdb_ctrl_setreclock(struct ctdb_context *ctdb,
	struct timeval timeout, uint32_t destnode,
	const char *reclock);


uint32_t *list_of_nodes(struct ctdb_context *ctdb,
			struct ctdb_node_map *node_map,
			TALLOC_CTX *mem_ctx,
			uint32_t mask,
			int exclude_pnn);
uint32_t *list_of_connected_nodes(struct ctdb_context *ctdb,
				struct ctdb_node_map *node_map,
				TALLOC_CTX *mem_ctx,
				bool include_self);
uint32_t *list_of_active_nodes(struct ctdb_context *ctdb,
				struct ctdb_node_map *node_map,
				TALLOC_CTX *mem_ctx,
				bool include_self);
uint32_t *list_of_vnnmap_nodes(struct ctdb_context *ctdb,
				struct ctdb_vnn_map *vnn_map,
				TALLOC_CTX *mem_ctx,
				bool include_self);

int ctdb_read_pnn_lock(int fd, int32_t pnn);

/*
  get capabilities of a remote node
 */
int ctdb_ctrl_getcapabilities(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *capabilities);

struct ctdb_client_control_state *ctdb_ctrl_getcapabilities_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_getcapabilities_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct ctdb_client_control_state *state, uint32_t *capabilities);

struct ctdb_marshall_buffer *ctdb_marshall_add(TALLOC_CTX *mem_ctx,
					       struct ctdb_marshall_buffer *m,
					       uint64_t db_id,
					       uint32_t reqid,
					       TDB_DATA key,
					       struct ctdb_ltdb_header *header,
					       TDB_DATA data);
TDB_DATA ctdb_marshall_finish(struct ctdb_marshall_buffer *m);

struct ctdb_transaction_handle *ctdb_transaction_start(struct ctdb_db_context *ctdb_db,
						       TALLOC_CTX *mem_ctx);
int ctdb_transaction_fetch(struct ctdb_transaction_handle *h,
			   TALLOC_CTX *mem_ctx,
			   TDB_DATA key, TDB_DATA *data);
int ctdb_transaction_store(struct ctdb_transaction_handle *h,
			   TDB_DATA key, TDB_DATA data);
int ctdb_transaction_commit(struct ctdb_transaction_handle *h);
int ctdb_transaction_cancel(struct ctdb_transaction_handle *h);

int ctdb_ctrl_recd_ping(struct ctdb_context *ctdb);

int switch_from_server_to_client(struct ctdb_context *ctdb, const char *fmt,
				 ...);

int ctdb_ctrl_getscriptstatus(struct ctdb_context *ctdb,
		    struct timeval timeout, uint32_t destnode,
		    TALLOC_CTX *mem_ctx, enum ctdb_eventscript_call type,
		    struct ctdb_scripts_wire **script_status);


struct debug_levels {
	int32_t	level;
	const char *description;
};
extern struct debug_levels debug_levels[];

const char *get_debug_by_level(int32_t level);
int32_t get_debug_by_desc(const char *desc);

int ctdb_ctrl_stop_node(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode);
int ctdb_ctrl_continue_node(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode);

int ctdb_ctrl_setnatgwstate(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t natgwstate);
int ctdb_ctrl_setlmasterrole(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t lmasterrole);
int ctdb_ctrl_setrecmasterrole(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t recmasterrole);

int ctdb_ctrl_enablescript(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, const char *script);
int ctdb_ctrl_disablescript(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, const char *script);

struct ctdb_ban_time {
	uint32_t pnn;
	uint32_t time;
};

int ctdb_ctrl_set_ban(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, struct ctdb_ban_time *bantime);
int ctdb_ctrl_get_ban(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, struct ctdb_ban_time **bantime);

struct ctdb_db_priority {
	uint32_t db_id;
	uint32_t priority;
};

int ctdb_ctrl_set_db_priority(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, struct ctdb_db_priority *db_prio);
int ctdb_ctrl_get_db_priority(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t db_id, uint32_t *priority);

int ctdb_ctrl_getstathistory(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, struct ctdb_statistics_wire **stats);



struct ctdb_client_control_state *
ctdb_ctrl_updaterecord_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA data);

int ctdb_ctrl_updaterecord_recv(struct ctdb_context *ctdb, struct ctdb_client_control_state *state);

int
ctdb_ctrl_updaterecord(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA data);


struct ctdb_client_control_state *
ctdb_ctrl_set_db_readonly_send(struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid);
int ctdb_ctrl_set_db_readonly_recv(struct ctdb_context *ctdb, struct ctdb_client_control_state *state);
int ctdb_ctrl_set_db_readonly(struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid);

struct ctdb_client_control_state *
ctdb_ctrl_set_db_sticky_send(struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid);
int ctdb_ctrl_set_db_sticky_recv(struct ctdb_context *ctdb, struct ctdb_client_control_state *state);
int ctdb_ctrl_set_db_sticky(struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid);

#endif /* _CTDB_CLIENT_H */
