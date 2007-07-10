/* 
   ctdb daemon code

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"
#include "lib/events/events.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"

/*
  structure describing a connected client in the daemon
 */
struct ctdb_client {
	struct ctdb_context *ctdb;
	int fd;
	struct ctdb_queue *queue;
};



static void daemon_incoming_packet(void *, uint8_t *, uint32_t );

static void ctdb_main_loop(struct ctdb_context *ctdb)
{
	ctdb->methods->start(ctdb);

	/* go into a wait loop to allow other nodes to complete */
	event_loop_wait(ctdb->ev);

	DEBUG(0,("event_loop_wait() returned. this should not happen\n"));
	exit(1);
}


static void set_non_blocking(int fd)
{
	unsigned v;
	v = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, v | O_NONBLOCK);
}

static void block_signal(int signum)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, signum);
	sigaction(signum, &act, NULL);
}


/*
  send a packet to a client
 */
static int daemon_queue_send(struct ctdb_client *client, struct ctdb_req_header *hdr)
{
	client->ctdb->status.client_packets_sent++;
	return ctdb_queue_send(client->queue, (uint8_t *)hdr, hdr->length);
}

/*
  message handler for when we are in daemon mode. This redirects the message
  to the right client
 */
static void daemon_message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
				    TDB_DATA data, void *private_data)
{
	struct ctdb_client *client = talloc_get_type(private_data, struct ctdb_client);
	struct ctdb_req_message *r;
	int len;

	/* construct a message to send to the client containing the data */
	len = offsetof(struct ctdb_req_message, data) + data.dsize;
	r = ctdbd_allocate_pkt(ctdb, len);

	talloc_set_name_const(r, "req_message packet");

	memset(r, 0, offsetof(struct ctdb_req_message, data));

	r->hdr.length    = len;
	r->hdr.ctdb_magic = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation = CTDB_REQ_MESSAGE;
	r->srvid         = srvid;
	r->datalen       = data.dsize;
	memcpy(&r->data[0], data.dptr, data.dsize);

	daemon_queue_send(client, &r->hdr);

	talloc_free(r);
}
					   

/*
  this is called when the ctdb daemon received a ctdb request to 
  set the srvid from the client
 */
static void daemon_request_register_message_handler(struct ctdb_client *client, 
						    struct ctdb_req_register *c)
{
	int res;
	res = ctdb_register_message_handler(client->ctdb, client, 
					    c->srvid, daemon_message_handler, 
					    client);
	if (res != 0) {
		DEBUG(0,(__location__ " Failed to register handler %u in daemon\n", 
			 c->srvid));
	} else {
		DEBUG(2,(__location__ " Registered message handler for srvid=%u\n", 
			 c->srvid));
	}
}


/*
  called when the daemon gets a shutdown request from a client
 */
static void daemon_request_shutdown(struct ctdb_client *client, 
				      struct ctdb_req_shutdown *f)
{
	struct ctdb_context *ctdb = talloc_get_type(client->ctdb, struct ctdb_context);
	int len;
	uint32_t node;

	/* we dont send to ourself so we can already count one daemon as
	   exiting */
	ctdb->num_finished++;


	/* loop over all nodes of the cluster */
	for (node=0; node<ctdb->num_nodes;node++) {
		struct ctdb_req_finished *rf;

		/* dont send a message to ourself */
		if (ctdb->vnn == node) {
			continue;
		}

		len = sizeof(struct ctdb_req_finished);
		rf = ctdb->methods->allocate_pkt(ctdb, len);
		CTDB_NO_MEMORY_FATAL(ctdb, rf);
		talloc_set_name_const(rf, "ctdb_req_finished packet");

		ZERO_STRUCT(*rf);
		rf->hdr.length    = len;
		rf->hdr.ctdb_magic = CTDB_MAGIC;
		rf->hdr.ctdb_version = CTDB_VERSION;
		rf->hdr.operation = CTDB_REQ_FINISHED;
		rf->hdr.destnode  = node;
		rf->hdr.srcnode   = ctdb->vnn;
		rf->hdr.reqid     = 0;

		ctdb_queue_packet(ctdb, &(rf->hdr));

		talloc_free(rf);
	}

	/* wait until all nodes have are prepared to shutdown */
	while (ctdb->num_finished != ctdb->num_nodes) {
		event_loop_once(ctdb->ev);
	}

	/* all daemons have requested to finish - we now exit */
	DEBUG(1,("All daemons finished - exiting\n"));
	_exit(0);
}



/*
  called when the daemon gets a connect wait request from a client
 */
static void daemon_request_connect_wait(struct ctdb_client *client, 
					struct ctdb_req_connect_wait *c)
{
	struct ctdb_reply_connect_wait r;
	int res;

	/* first wait - in the daemon */
	ctdb_daemon_connect_wait(client->ctdb);

	/* now send the reply */
	ZERO_STRUCT(r);

	r.hdr.length     = sizeof(r);
	r.hdr.ctdb_magic = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation = CTDB_REPLY_CONNECT_WAIT;
	r.vnn           = ctdb_get_vnn(client->ctdb);
	r.num_connected = client->ctdb->num_connected;
	
	res = daemon_queue_send(client, &r.hdr);
	if (res != 0) {
		DEBUG(0,(__location__ " Failed to queue a connect wait response\n"));
		return;
	}
}


/*
  called when the daemon gets a status request from a client
 */
static void daemon_request_status(struct ctdb_client *client, 
				  struct ctdb_req_status *c)
{
	struct ctdb_reply_status r;
	int res;

	/* now send the reply */
	ZERO_STRUCT(r);

	r.hdr.length     = sizeof(r);
	r.hdr.ctdb_magic = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation = CTDB_REPLY_STATUS;
	r.hdr.reqid = c->hdr.reqid;
	r.status = client->ctdb->status;
	
	res = daemon_queue_send(client, &r.hdr);
	if (res != 0) {
		DEBUG(0,(__location__ " Failed to queue a connect wait response\n"));
		return;
	}
}

/*
  destroy a ctdb_client
*/
static int ctdb_client_destructor(struct ctdb_client *client)
{
	close(client->fd);
	client->fd = -1;
	return 0;
}


/*
  this is called when the ctdb daemon received a ctdb request message
  from a local client over the unix domain socket
 */
static void daemon_request_message_from_client(struct ctdb_client *client, 
					       struct ctdb_req_message *c)
{
	TDB_DATA data;
	int res;

	/* maybe the message is for another client on this node */
	if (ctdb_get_vnn(client->ctdb)==c->hdr.destnode) {
		ctdb_request_message(client->ctdb, (struct ctdb_req_header *)c);
		return;
	}
	
	/* its for a remote node */
	data.dptr = &c->data[0];
	data.dsize = c->datalen;
	res = ctdb_daemon_send_message(client->ctdb, c->hdr.destnode,
				       c->srvid, data);
	if (res != 0) {
		DEBUG(0,(__location__ " Failed to send message to remote node %u\n",
			 c->hdr.destnode));
	}
}


struct daemon_call_state {
	struct ctdb_client *client;
	uint32_t reqid;
	struct ctdb_call *call;
	struct timeval start_time;
};

/* 
   complete a call from a client 
*/
static void daemon_call_from_client_callback(struct ctdb_call_state *state)
{
	struct daemon_call_state *dstate = talloc_get_type(state->async.private_data, 
							   struct daemon_call_state);
	struct ctdb_reply_call *r;
	int res;
	uint32_t length;
	struct ctdb_client *client = dstate->client;

	talloc_steal(client, dstate);
	talloc_steal(dstate, dstate->call);

	res = ctdb_daemon_call_recv(state, dstate->call);
	if (res != 0) {
		DEBUG(0, (__location__ " ctdbd_call_recv() returned error\n"));
		client->ctdb->status.pending_calls--;
		ctdb_latency(&client->ctdb->status.max_call_latency, dstate->start_time);
		return;
	}

	length = offsetof(struct ctdb_reply_call, data) + dstate->call->reply_data.dsize;
	r = ctdbd_allocate_pkt(dstate, length);
	if (r == NULL) {
		DEBUG(0, (__location__ " Failed to allocate reply_call in ctdb daemon\n"));
		client->ctdb->status.pending_calls--;
		ctdb_latency(&client->ctdb->status.max_call_latency, dstate->start_time);
		return;
	}
	memset(r, 0, offsetof(struct ctdb_reply_call, data));
	r->hdr.length       = length;
	r->hdr.ctdb_magic   = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation    = CTDB_REPLY_CALL;
	r->hdr.reqid        = dstate->reqid;
	r->datalen          = dstate->call->reply_data.dsize;
	memcpy(&r->data[0], dstate->call->reply_data.dptr, r->datalen);

	res = daemon_queue_send(client, &r->hdr);
	if (res != 0) {
		DEBUG(0, (__location__ "Failed to queue packet from daemon to client\n"));
	}
	ctdb_latency(&client->ctdb->status.max_call_latency, dstate->start_time);
	talloc_free(dstate);
	client->ctdb->status.pending_calls--;
}


/*
  this is called when the ctdb daemon received a ctdb request call
  from a local client over the unix domain socket
 */
static void daemon_request_call_from_client(struct ctdb_client *client, 
					    struct ctdb_req_call *c)
{
	struct ctdb_call_state *state;
	struct ctdb_db_context *ctdb_db;
	struct daemon_call_state *dstate;
	struct ctdb_call *call;
	struct ctdb_ltdb_header header;
	TDB_DATA key, data;
	int ret;
	struct ctdb_context *ctdb = client->ctdb;

	ctdb->status.total_calls++;
	ctdb->status.pending_calls++;

	ctdb_db = find_ctdb_db(client->ctdb, c->db_id);
	if (!ctdb_db) {
		DEBUG(0, (__location__ " Unknown database in request. db_id==0x%08x",
			  c->db_id));
		ctdb->status.pending_calls--;
		return;
	}

	key.dptr = c->data;
	key.dsize = c->keylen;

	ret = ctdb_ltdb_lock_fetch_requeue(ctdb_db, key, &header, 
					   (struct ctdb_req_header *)c, &data,
					   daemon_incoming_packet, client);
	if (ret == -2) {
		/* will retry later */
		ctdb->status.pending_calls--;
		return;
	}

	if (ret != 0) {
		DEBUG(0,(__location__ " Unable to fetch record\n"));
		ctdb->status.pending_calls--;
		return;
	}

	dstate = talloc(client, struct daemon_call_state);
	if (dstate == NULL) {
		ctdb_ltdb_unlock(ctdb_db, key);
		DEBUG(0,(__location__ " Unable to allocate dstate\n"));
		ctdb->status.pending_calls--;
		return;
	}
	dstate->start_time = timeval_current();
	dstate->client = client;
	dstate->reqid  = c->hdr.reqid;
	talloc_steal(dstate, data.dptr);

	call = dstate->call = talloc_zero(dstate, struct ctdb_call);
	if (call == NULL) {
		ctdb_ltdb_unlock(ctdb_db, key);
		DEBUG(0,(__location__ " Unable to allocate call\n"));
		ctdb->status.pending_calls--;
		ctdb_latency(&ctdb->status.max_call_latency, dstate->start_time);
		return;
	}

	call->call_id = c->callid;
	call->key = key;
	call->call_data.dptr = c->data + c->keylen;
	call->call_data.dsize = c->calldatalen;
	call->flags = c->flags;

	if (header.dmaster == ctdb->vnn && !(ctdb->flags & CTDB_FLAG_SELF_CONNECT)) {
		state = ctdb_call_local_send(ctdb_db, call, &header, &data);
	} else {
		state = ctdb_daemon_call_send_remote(ctdb_db, call, &header);
	}

	ctdb_ltdb_unlock(ctdb_db, key);

	if (state == NULL) {
		DEBUG(0,(__location__ " Unable to setup call send\n"));
		ctdb->status.pending_calls--;
		ctdb_latency(&ctdb->status.max_call_latency, dstate->start_time);
		return;
	}
	talloc_steal(state, dstate);
	talloc_steal(client, state);

	state->async.fn = daemon_call_from_client_callback;
	state->async.private_data = dstate;
}

/* data contains a packet from the client */
static void daemon_incoming_packet(void *p, uint8_t *data, uint32_t nread)
{
	struct ctdb_req_header *hdr = (struct ctdb_req_header *)data;
	struct ctdb_client *client = talloc_get_type(p, struct ctdb_client);
	TALLOC_CTX *tmp_ctx;
	struct ctdb_context *ctdb = client->ctdb;

	/* place the packet as a child of a tmp_ctx. We then use
	   talloc_free() below to free it. If any of the calls want
	   to keep it, then they will steal it somewhere else, and the
	   talloc_free() will be a no-op */
	tmp_ctx = talloc_new(client);
	talloc_steal(tmp_ctx, hdr);

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(client->ctdb, "Non CTDB packet rejected in daemon\n");
		goto done;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(client->ctdb, "Bad CTDB version 0x%x rejected in daemon\n", hdr->ctdb_version);
		goto done;
	}

	switch (hdr->operation) {
	case CTDB_REQ_CALL:
		ctdb->status.client.req_call++;
		daemon_request_call_from_client(client, (struct ctdb_req_call *)hdr);
		break;

	case CTDB_REQ_REGISTER:
		ctdb->status.client.req_register++;
		daemon_request_register_message_handler(client, 
							(struct ctdb_req_register *)hdr);
		break;
	case CTDB_REQ_MESSAGE:
		ctdb->status.client.req_message++;
		daemon_request_message_from_client(client, (struct ctdb_req_message *)hdr);
		break;

	case CTDB_REQ_CONNECT_WAIT:
		ctdb->status.client.req_connect_wait++;
		daemon_request_connect_wait(client, (struct ctdb_req_connect_wait *)hdr);
		break;

	case CTDB_REQ_SHUTDOWN:
		ctdb->status.client.req_shutdown++;
		daemon_request_shutdown(client, (struct ctdb_req_shutdown *)hdr);
		break;

	case CTDB_REQ_STATUS:
		ctdb->status.client.req_status++;
		daemon_request_status(client, (struct ctdb_req_status *)hdr);
		break;

	default:
		DEBUG(0,(__location__ " daemon: unrecognized operation %d\n",
			 hdr->operation));
	}

done:
	talloc_free(tmp_ctx);
}

/*
  called when the daemon gets a incoming packet
 */
static void ctdb_daemon_read_cb(uint8_t *data, size_t cnt, void *args)
{
	struct ctdb_client *client = talloc_get_type(args, struct ctdb_client);
	struct ctdb_req_header *hdr;

	if (cnt == 0) {
		talloc_free(client);
		return;
	}

	client->ctdb->status.client_packets_recv++;

	if (cnt < sizeof(*hdr)) {
		ctdb_set_error(client->ctdb, "Bad packet length %d in daemon\n", cnt);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (cnt != hdr->length) {
		ctdb_set_error(client->ctdb, "Bad header length %d expected %d\n in daemon", 
			       hdr->length, cnt);
		return;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(client->ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(client->ctdb, "Bad CTDB version 0x%x rejected in daemon\n", hdr->ctdb_version);
		return;
	}

	DEBUG(3,(__location__ " client request %d of type %d length %d from "
		 "node %d to %d\n", hdr->reqid, hdr->operation, hdr->length,
		 hdr->srcnode, hdr->destnode));

	/* it is the responsibility of the incoming packet function to free 'data' */
	daemon_incoming_packet(client, data, cnt);
}

static void ctdb_accept_client(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private_data)
{
	struct sockaddr_in addr;
	socklen_t len;
	int fd;
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	struct ctdb_client *client;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(ctdb->daemon.sd, (struct sockaddr *)&addr, &len);
	if (fd == -1) {
		return;
	}
	set_non_blocking(fd);

	client = talloc_zero(ctdb, struct ctdb_client);
	client->ctdb = ctdb;
	client->fd = fd;

	client->queue = ctdb_queue_setup(ctdb, client, fd, CTDB_DS_ALIGNMENT, 
					 ctdb_daemon_read_cb, client);

	talloc_set_destructor(client, ctdb_client_destructor);
}



static void ctdb_read_from_parent(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private_data)
{
	int *fd = private_data;
	int cnt;
	char buf;

	/* XXX this is a good place to try doing some cleaning up before exiting */
	cnt = read(*fd, &buf, 1);
	if (cnt==0) {
		DEBUG(2,(__location__ " parent process exited. filedescriptor dissappeared\n"));
		exit(1);
	} else {
		DEBUG(0,(__location__ " ctdb: did not expect data from parent process\n"));
		exit(1);
	}
}



/*
  create a unix domain socket and bind it
  return a file descriptor open on the socket 
*/
static int ux_socket_bind(struct ctdb_context *ctdb)
{
	struct sockaddr_un addr;

	ctdb->daemon.sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctdb->daemon.sd == -1) {
		ctdb->daemon.sd = -1;
		return -1;
	}

	set_non_blocking(ctdb->daemon.sd);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, ctdb->daemon.name, sizeof(addr.sun_path));

	if (bind(ctdb->daemon.sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(ctdb->daemon.sd);
		ctdb->daemon.sd = -1;
		return -1;
	}	
	listen(ctdb->daemon.sd, 1);

	return 0;
}

/*
  delete the socket on exit - called on destruction of autofree context
 */
static int unlink_destructor(const char *name)
{
	unlink(name);
	return 0;
}

/*
  start the protocol going
*/
int ctdb_start(struct ctdb_context *ctdb)
{
	pid_t pid;
	static int fd[2];
	int res;
	struct fd_event *fde;
	const char *domain_socket_name;

	/* generate a name to use for our local socket */
	ctdb->daemon.name = talloc_asprintf(ctdb, "%s.%s", CTDB_PATH, ctdb->address.address);
	/* get rid of any old sockets */
	unlink(ctdb->daemon.name);

	/* create a unix domain stream socket to listen to */
	res = ux_socket_bind(ctdb);
	if (res!=0) {
		DEBUG(0,(__location__ " Failed to open CTDB unix domain socket\n"));
		exit(10);
	}

	res = pipe(&fd[0]);
	if (res) {
		DEBUG(0,(__location__ " Failed to open pipe for CTDB\n"));
		exit(1);
	}
	pid = fork();
	if (pid==-1) {
		DEBUG(0,(__location__ " Failed to fork CTDB daemon\n"));
		exit(1);
	}

	if (pid) {
		close(fd[0]);
		close(ctdb->daemon.sd);
		ctdb->daemon.sd = -1;
		return 0;
	}

	block_signal(SIGPIPE);

	/* ensure the socket is deleted on exit of the daemon */
	domain_socket_name = talloc_strdup(talloc_autofree_context(), ctdb->daemon.name);
	talloc_set_destructor(domain_socket_name, unlink_destructor);	
	
	close(fd[1]);

	ctdb->ev = event_context_init(NULL);
	fde = event_add_fd(ctdb->ev, ctdb, fd[0], EVENT_FD_READ, ctdb_read_from_parent, &fd[0]);
	fde = event_add_fd(ctdb->ev, ctdb, ctdb->daemon.sd, EVENT_FD_READ, ctdb_accept_client, ctdb);
	ctdb_main_loop(ctdb);

	return 0;
}

/*
  allocate a packet for use in client<->daemon communication
 */
void *ctdbd_allocate_pkt(TALLOC_CTX *mem_ctx, size_t len)
{
	int size;

	size = (len+(CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);
	return talloc_size(mem_ctx, size);
}

/*
  called when a CTDB_REQ_FINISHED packet comes in
*/
void ctdb_request_finished(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	ctdb->num_finished++;
}
