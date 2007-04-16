/* 
   ctdb database library

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _CTDB_PRIVATE_H
#define _CTDB_PRIVATE_H

#include "ctdb.h"

/* location of daemon socket */
#define CTDB_PATH	"/tmp/ctdb.socket"

/* we must align packets to ensure ctdb works on all architectures (eg. sparc) */
#define CTDB_DS_ALIGNMENT 8



#define CTDB_FETCH_FUNC 0xf0000001
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


/* called from the queue code when a packet comes in. Called with data==NULL
   on error */
typedef void (*ctdb_queue_cb_fn_t)(uint8_t *data, size_t length,
				   void *private_data);


/*
  state associated with one node
*/
struct ctdb_node {
	struct ctdb_context *ctdb;
	struct ctdb_address address;
	const char *name; /* for debug messages */
	void *private_data; /* private to transport */
	uint32_t vnn;
};

struct ctdb_record_handle {
	struct ctdb_db_context *ctdb_db;
	TDB_DATA key;
	TDB_DATA *data;
};

/*
  transport specific methods
*/
struct ctdb_methods {
	int (*start)(struct ctdb_context *); /* start protocol processing */	
	int (*add_node)(struct ctdb_node *); /* setup a new node */	
	int (*queue_pkt)(struct ctdb_node *, uint8_t *data, uint32_t length);
	void *(*allocate_pkt)(struct ctdb_context *, size_t );
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
	uint32_t srvid;
	ctdb_message_fn_t message_handler;
	void *message_private;
};

/* additional data required for the daemon mode */
struct ctdb_daemon_data {
	int sd;
	char *name;
	struct ctdb_queue *queue;
};

/* main state of the ctdb daemon */
struct ctdb_context {
	struct event_context *ev;
	struct ctdb_address address;
	const char *name;
	uint32_t vnn; /* our own vnn */
	uint32_t num_nodes;
	uint32_t num_connected;
	unsigned flags;
	struct idr_context *idr;
	struct ctdb_node **nodes; /* array of nodes in the cluster - indexed by vnn */
	char *err_msg;
	const struct ctdb_methods *methods; /* transport methods */
	const struct ctdb_upcalls *upcalls; /* transport upcalls */
	void *private_data; /* private to transport */
	unsigned max_lacount;
	struct ctdb_db_context *db_list;
	struct ctdb_message_list *message_list;
	struct ctdb_daemon_data daemon;
};

struct ctdb_db_context {
	struct ctdb_db_context *next, *prev;
	struct ctdb_context *ctdb;
	uint32_t db_id;
	const char *db_name;
	struct tdb_wrap *ltdb;
	struct ctdb_registered_call *calls; /* list of registered calls */
};


#define CTDB_NO_MEMORY(ctdb, p) do { if (!(p)) { \
          ctdb_set_error(ctdb, "Out of memory at %s:%d", __FILE__, __LINE__); \
	  return -1; }} while (0)

#define CTDB_NO_MEMORY_NULL(ctdb, p) do { if (!(p)) { \
          ctdb_set_error(ctdb, "Out of memory at %s:%d", __FILE__, __LINE__); \
	  return NULL; }} while (0)

#define CTDB_NO_MEMORY_FATAL(ctdb, p) do { if (!(p)) { \
          ctdb_fatal(ctdb, "Out of memory in " __location__ ); \
	  }} while (0)

/* arbitrary maximum timeout for ctdb operations */
#define CTDB_REQ_TIMEOUT 10

/* max number of redirects before we ask the lmaster */
#define CTDB_MAX_REDIRECT 2

/* number of consecutive calls from the same node before we give them
   the record */
#define CTDB_DEFAULT_MAX_LACOUNT 7

/*
  the extended header for records in the ltdb
*/
struct ctdb_ltdb_header {
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t laccessor;
	uint32_t lacount;
};

enum call_state {CTDB_CALL_WAIT, CTDB_CALL_DONE, CTDB_CALL_ERROR};

/*
  state of a in-progress ctdb call
*/
struct ctdb_call_state {
	enum call_state state;
	struct ctdb_req_call *c;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_node *node;
	const char *errmsg;
	struct ctdb_call call;
	int redirect_count;
	struct ctdb_ltdb_header header;
	void *fetch_private;
	struct {
		void (*fn)(struct ctdb_call_state *);
		void *private_data;
	} async;
};


/*
  operation IDs
*/
enum ctdb_operation {
	CTDB_REQ_CALL           = 0,
	CTDB_REPLY_CALL         = 1,
	CTDB_REPLY_REDIRECT     = 2,
	CTDB_REQ_DMASTER        = 3,
	CTDB_REPLY_DMASTER      = 4,
	CTDB_REPLY_ERROR        = 5,
	CTDB_REQ_MESSAGE        = 6,
	
	/* only used on the domain socket */
	CTDB_REQ_REGISTER       = 1000,     
	CTDB_REQ_CONNECT_WAIT   = 1001,
	CTDB_REPLY_CONNECT_WAIT = 1002,
	CTDB_REQ_FETCH_LOCK     = 1003,
	CTDB_REPLY_FETCH_LOCK   = 1004,
	CTDB_REQ_STORE_UNLOCK   = 1005,
	CTDB_REPLY_STORE_UNLOCK = 1006
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

struct ctdb_reply_redirect {
	struct ctdb_req_header hdr;
	uint32_t dmaster;
};

struct ctdb_req_dmaster {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint32_t dmaster;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_dmaster {
	struct ctdb_req_header hdr;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_req_register {
	struct ctdb_req_header hdr;
	uint32_t srvid;
};

struct ctdb_req_message {
	struct ctdb_req_header hdr;
	uint32_t srvid;
	uint32_t datalen;
	uint8_t data[1];
};

struct ctdb_req_connect_wait {
	struct ctdb_req_header hdr;
};

struct ctdb_reply_connect_wait {
	struct ctdb_req_header hdr;
	uint32_t vnn;
	uint32_t num_connected;
};

struct ctdb_req_fetch_lock {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint32_t keylen;
	uint8_t key[1]; /* key[] */
};

struct ctdb_reply_fetch_lock {
	struct ctdb_req_header hdr;
	uint32_t state;
	uint32_t datalen;
	uint8_t data[1]; /* data[] */
};
struct ctdb_req_store_unlock {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint32_t keylen;	
	uint32_t datalen;
	uint8_t data[1]; /* key[] and data[] */
};

struct ctdb_reply_store_unlock {
	struct ctdb_req_header hdr;
	uint32_t state;
};

/* internal prototypes */
void ctdb_set_error(struct ctdb_context *ctdb, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);
void ctdb_fatal(struct ctdb_context *ctdb, const char *msg);
bool ctdb_same_address(struct ctdb_address *a1, struct ctdb_address *a2);
int ctdb_parse_address(struct ctdb_context *ctdb,
		       TALLOC_CTX *mem_ctx, const char *str,
		       struct ctdb_address *address);
uint32_t ctdb_hash(const TDB_DATA *key);
void ctdb_request_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_request_dmaster(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_request_message(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_dmaster(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_error(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);
void ctdb_reply_redirect(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);

uint32_t ctdb_lmaster(struct ctdb_context *ctdb, const TDB_DATA *key);
int ctdb_ltdb_fetch(struct ctdb_db_context *ctdb_db, 
		    TDB_DATA key, struct ctdb_ltdb_header *header, 
		    TALLOC_CTX *mem_ctx, TDB_DATA *data);
int ctdb_ltdb_store(struct ctdb_db_context *ctdb_db, TDB_DATA key, 
		    struct ctdb_ltdb_header *header, TDB_DATA data);
void ctdb_queue_packet(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);

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
void *ctdbd_allocate_pkt(struct ctdb_context *ctdb, size_t len);


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

int ctdb_daemon_set_message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
			     ctdb_message_fn_t handler,
			     void *private_data);

int ctdb_client_send_message(struct ctdb_context *ctdb, uint32_t vnn,
			     uint32_t srvid, TDB_DATA data);

/*
  send a ctdb message
*/
int ctdb_daemon_send_message(struct ctdb_context *ctdb, uint32_t vnn,
			     uint32_t srvid, TDB_DATA data);


/*
  wait for all nodes to be connected
*/
void ctdb_daemon_connect_wait(struct ctdb_context *ctdb);


/*
  do a fetch lock from a client to the local daemon
*/
struct ctdb_record_handle *ctdb_client_fetch_lock(struct ctdb_db_context *ctdb_db, 
						  TALLOC_CTX *mem_ctx, 
						  TDB_DATA key, TDB_DATA *data);

/*
  do a store unlock from a client to the local daemon
*/
int ctdb_client_store_unlock(struct ctdb_record_handle *rec, TDB_DATA data);

#endif
