/* 
   ctdb daemon code

   Copyright (C) Andrew Tridgell  2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

static void daemon_incoming_packet(void *, struct ctdb_req_header *);

/* called when the "startup" event script has finished */
static void ctdb_start_transport(struct ctdb_context *ctdb, int status, void *p)
{
	if (status != 0) {
		DEBUG(0,("startup event failed!\n"));
		ctdb_fatal(ctdb, "startup event script failed");		
	}

	/* start the transport running */
	if (ctdb->methods->start(ctdb) != 0) {
		DEBUG(0,("transport failed to start!\n"));
		ctdb_fatal(ctdb, "transport failed to start");
	}

	/* start the recovery daemon process */
	if (ctdb_start_recoverd(ctdb) != 0) {
		DEBUG(0,("Failed to start recovery daemon\n"));
		exit(11);
	}

	/* start monitoring for dead nodes */
	ctdb_start_monitoring(ctdb);
}

/* go into main ctdb loop */
static void ctdb_main_loop(struct ctdb_context *ctdb)
{
	int ret = -1;

	if (strcmp(ctdb->transport, "tcp") == 0) {
		int ctdb_tcp_init(struct ctdb_context *);
		ret = ctdb_tcp_init(ctdb);
	}
#ifdef USE_INFINIBAND
	if (strcmp(ctdb->transport, "ib") == 0) {
		int ctdb_ibw_init(struct ctdb_context *);
		ret = ctdb_ibw_init(ctdb);
	}
#endif
	if (ret != 0) {
		DEBUG(0,("Failed to initialise transport '%s'\n", ctdb->transport));
		return;
	}

	/* initialise the transport  */
	if (ctdb->methods->initialise(ctdb) != 0) {
		DEBUG(0,("transport failed to initialise!\n"));
		ctdb_fatal(ctdb, "transport failed to initialise");
	}

	/* tell all other nodes we've just started up */
	ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_ALL,
				 0, CTDB_CONTROL_STARTUP, 0,
				 CTDB_CTRL_FLAG_NOREPLY,
				 tdb_null, NULL, NULL);

	ret = ctdb_event_script_callback(ctdb, ctdb, 
					 ctdb_start_transport, NULL, "startup");
	if (ret != 0) {
		DEBUG(0,("Failed startup event script\n"));
		return;
	}

	/* go into a wait loop to allow other nodes to complete */
	event_loop_wait(ctdb->ev);

	DEBUG(0,("event_loop_wait() returned. this should not happen\n"));
	exit(1);
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
	client->ctdb->statistics.client_packets_sent++;
	return ctdb_queue_send(client->queue, (uint8_t *)hdr, hdr->length);
}

/*
  message handler for when we are in daemon mode. This redirects the message
  to the right client
 */
static void daemon_message_handler(struct ctdb_context *ctdb, uint64_t srvid, 
				    TDB_DATA data, void *private_data)
{
	struct ctdb_client *client = talloc_get_type(private_data, struct ctdb_client);
	struct ctdb_req_message *r;
	int len;

	/* construct a message to send to the client containing the data */
	len = offsetof(struct ctdb_req_message, data) + data.dsize;
	r = ctdbd_allocate_pkt(ctdb, ctdb, CTDB_REQ_MESSAGE, 
			       len, struct ctdb_req_message);
	CTDB_NO_MEMORY_VOID(ctdb, r);

	talloc_set_name_const(r, "req_message packet");

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
int daemon_register_message_handler(struct ctdb_context *ctdb, uint32_t client_id, uint64_t srvid)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
	int res;
	if (client == NULL) {
		DEBUG(0,("Bad client_id in daemon_request_register_message_handler\n"));
		return -1;
	}
	res = ctdb_register_message_handler(ctdb, client, srvid, daemon_message_handler, client);
	if (res != 0) {
		DEBUG(0,(__location__ " Failed to register handler %llu in daemon\n", 
			 (unsigned long long)srvid));
	} else {
		DEBUG(2,(__location__ " Registered message handler for srvid=%llu\n", 
			 (unsigned long long)srvid));
	}
	return res;
}

/*
  this is called when the ctdb daemon received a ctdb request to 
  remove a srvid from the client
 */
int daemon_deregister_message_handler(struct ctdb_context *ctdb, uint32_t client_id, uint64_t srvid)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
	if (client == NULL) {
		DEBUG(0,("Bad client_id in daemon_request_deregister_message_handler\n"));
		return -1;
	}
	return ctdb_deregister_message_handler(ctdb, srvid, client);
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
		rf = ctdb_transport_allocate(ctdb, ctdb, CTDB_REQ_FINISHED, len,
					     struct ctdb_req_finished);
		CTDB_NO_MEMORY_FATAL(ctdb, rf);

		rf->hdr.destnode  = node;

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
	struct ctdb_reply_connect_wait *r;
	int res;

	/* first wait - in the daemon */
	ctdb_daemon_connect_wait(client->ctdb);

	/* now send the reply */
	r = ctdbd_allocate_pkt(client->ctdb, client, CTDB_REPLY_CONNECT_WAIT, sizeof(*r), 
			       struct ctdb_reply_connect_wait);
	CTDB_NO_MEMORY_VOID(client->ctdb, r);
	r->vnn           = ctdb_get_vnn(client->ctdb);
	r->num_connected = client->ctdb->num_connected;
	
	res = daemon_queue_send(client, &r->hdr);
	talloc_free(r);
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
	ctdb_takeover_client_destructor_hook(client);
	ctdb_reqid_remove(client->ctdb, client->client_id);
	client->ctdb->statistics.num_clients--;
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
		client->ctdb->statistics.pending_calls--;
		ctdb_latency(&client->ctdb->statistics.max_call_latency, dstate->start_time);
		return;
	}

	length = offsetof(struct ctdb_reply_call, data) + dstate->call->reply_data.dsize;
	r = ctdbd_allocate_pkt(client->ctdb, dstate, CTDB_REPLY_CALL, 
			       length, struct ctdb_reply_call);
	if (r == NULL) {
		DEBUG(0, (__location__ " Failed to allocate reply_call in ctdb daemon\n"));
		client->ctdb->statistics.pending_calls--;
		ctdb_latency(&client->ctdb->statistics.max_call_latency, dstate->start_time);
		return;
	}
	r->hdr.reqid        = dstate->reqid;
	r->datalen          = dstate->call->reply_data.dsize;
	memcpy(&r->data[0], dstate->call->reply_data.dptr, r->datalen);

	res = daemon_queue_send(client, &r->hdr);
	if (res != 0) {
		DEBUG(0, (__location__ " Failed to queue packet from daemon to client\n"));
	}
	ctdb_latency(&client->ctdb->statistics.max_call_latency, dstate->start_time);
	talloc_free(dstate);
	client->ctdb->statistics.pending_calls--;
}


static void daemon_request_call_from_client(struct ctdb_client *client, 
					    struct ctdb_req_call *c);

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

	ctdb->statistics.total_calls++;
	ctdb->statistics.pending_calls++;

	ctdb_db = find_ctdb_db(client->ctdb, c->db_id);
	if (!ctdb_db) {
		DEBUG(0, (__location__ " Unknown database in request. db_id==0x%08x",
			  c->db_id));
		ctdb->statistics.pending_calls--;
		return;
	}

	key.dptr = c->data;
	key.dsize = c->keylen;

	ret = ctdb_ltdb_lock_fetch_requeue(ctdb_db, key, &header, 
					   (struct ctdb_req_header *)c, &data,
					   daemon_incoming_packet, client, True);
	if (ret == -2) {
		/* will retry later */
		ctdb->statistics.pending_calls--;
		return;
	}

	if (ret != 0) {
		DEBUG(0,(__location__ " Unable to fetch record\n"));
		ctdb->statistics.pending_calls--;
		return;
	}

	dstate = talloc(client, struct daemon_call_state);
	if (dstate == NULL) {
		ctdb_ltdb_unlock(ctdb_db, key);
		DEBUG(0,(__location__ " Unable to allocate dstate\n"));
		ctdb->statistics.pending_calls--;
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
		ctdb->statistics.pending_calls--;
		ctdb_latency(&ctdb->statistics.max_call_latency, dstate->start_time);
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
		ctdb->statistics.pending_calls--;
		ctdb_latency(&ctdb->statistics.max_call_latency, dstate->start_time);
		return;
	}
	talloc_steal(state, dstate);
	talloc_steal(client, state);

	state->async.fn = daemon_call_from_client_callback;
	state->async.private_data = dstate;
}


static void daemon_request_control_from_client(struct ctdb_client *client, 
					       struct ctdb_req_control *c);

/* data contains a packet from the client */
static void daemon_incoming_packet(void *p, struct ctdb_req_header *hdr)
{
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
		ctdb->statistics.client.req_call++;
		daemon_request_call_from_client(client, (struct ctdb_req_call *)hdr);
		break;

	case CTDB_REQ_MESSAGE:
		ctdb->statistics.client.req_message++;
		daemon_request_message_from_client(client, (struct ctdb_req_message *)hdr);
		break;

	case CTDB_REQ_CONNECT_WAIT:
		ctdb->statistics.client.req_connect_wait++;
		daemon_request_connect_wait(client, (struct ctdb_req_connect_wait *)hdr);
		break;

	case CTDB_REQ_SHUTDOWN:
		ctdb->statistics.client.req_shutdown++;
		daemon_request_shutdown(client, (struct ctdb_req_shutdown *)hdr);
		break;

	case CTDB_REQ_CONTROL:
		ctdb->statistics.client.req_control++;
		daemon_request_control_from_client(client, (struct ctdb_req_control *)hdr);
		break;

	default:
		DEBUG(0,(__location__ " daemon: unrecognized operation %u\n",
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

	client->ctdb->statistics.client_packets_recv++;

	if (cnt < sizeof(*hdr)) {
		ctdb_set_error(client->ctdb, "Bad packet length %u in daemon\n", 
			       (unsigned)cnt);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (cnt != hdr->length) {
		ctdb_set_error(client->ctdb, "Bad header length %u expected %u\n in daemon", 
			       (unsigned)hdr->length, (unsigned)cnt);
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

	DEBUG(3,(__location__ " client request %u of type %u length %u from "
		 "node %u to %u\n", hdr->reqid, hdr->operation, hdr->length,
		 hdr->srcnode, hdr->destnode));

	/* it is the responsibility of the incoming packet function to free 'data' */
	daemon_incoming_packet(client, hdr);
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

	set_nonblocking(fd);
	set_close_on_exec(fd);

	client = talloc_zero(ctdb, struct ctdb_client);
	client->ctdb = ctdb;
	client->fd = fd;
	client->client_id = ctdb_reqid_new(ctdb, client);
	ctdb->statistics.num_clients++;

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
		return -1;
	}

	set_nonblocking(ctdb->daemon.sd);
	set_close_on_exec(ctdb->daemon.sd);

#if 0
	/* AIX doesn't like this :( */
	if (fchown(ctdb->daemon.sd, geteuid(), getegid()) != 0 ||
	    fchmod(ctdb->daemon.sd, 0700) != 0) {
		DEBUG(0,("Unable to secure ctdb socket '%s', ctdb->daemon.name\n"));
		goto failed;
	}
#endif

	set_nonblocking(ctdb->daemon.sd);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, ctdb->daemon.name, sizeof(addr.sun_path));

	if (bind(ctdb->daemon.sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		DEBUG(0,("Unable to bind on ctdb socket '%s'\n", ctdb->daemon.name));
		goto failed;
	}	
	if (listen(ctdb->daemon.sd, 10) != 0) {
		DEBUG(0,("Unable to listen on ctdb socket '%s'\n", ctdb->daemon.name));
		goto failed;
	}

	return 0;

failed:
	close(ctdb->daemon.sd);
	ctdb->daemon.sd = -1;
	return -1;	
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
		ctdb->vnn = ctdb_ctrl_getvnn(ctdb, timeval_zero(), CTDB_CURRENT_NODE);
		if (ctdb->vnn == (uint32_t)-1) {
			DEBUG(0,(__location__ " Failed to get ctdb vnn\n"));
			return -1;
		}
		return 0;
	}

	block_signal(SIGPIPE);

	/* ensure the socket is deleted on exit of the daemon */
	domain_socket_name = talloc_strdup(talloc_autofree_context(), ctdb->daemon.name);
	talloc_set_destructor(domain_socket_name, unlink_destructor);	
	
	close(fd[1]);

	ctdb->ev = event_context_init(NULL);
	fde = event_add_fd(ctdb->ev, ctdb, fd[0], EVENT_FD_READ|EVENT_FD_AUTOCLOSE, ctdb_read_from_parent, &fd[0]);
	fde = event_add_fd(ctdb->ev, ctdb, ctdb->daemon.sd, EVENT_FD_READ|EVENT_FD_AUTOCLOSE, ctdb_accept_client, ctdb);
	ctdb_main_loop(ctdb);

	return 0;
}


/*
  start the protocol going as a daemon
*/
int ctdb_start_daemon(struct ctdb_context *ctdb, bool do_fork)
{
	int res;
	struct fd_event *fde;
	const char *domain_socket_name;

	/* get rid of any old sockets */
	unlink(ctdb->daemon.name);

	/* create a unix domain stream socket to listen to */
	res = ux_socket_bind(ctdb);
	if (res!=0) {
		DEBUG(0,(__location__ " Failed to open CTDB unix domain socket\n"));
		exit(10);
	}

	if (do_fork && fork()) {
		return 0;
	}

	tdb_reopen_all(False);

	if (do_fork) {
		setsid();
	}
	block_signal(SIGPIPE);

	/* try to set us up as realtime */
	ctdb_set_realtime(true);

	/* ensure the socket is deleted on exit of the daemon */
	domain_socket_name = talloc_strdup(talloc_autofree_context(), ctdb->daemon.name);
	talloc_set_destructor(domain_socket_name, unlink_destructor);	

	ctdb->ev = event_context_init(NULL);

	/* start frozen, then let the first election sort things out */
	if (!ctdb_blocking_freeze(ctdb)) {
		DEBUG(0,("Failed to get initial freeze\n"));
		exit(12);
	}

	/* force initial recovery for election */
	ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;

	/* now start accepting clients, only can do this once frozen */
	fde = event_add_fd(ctdb->ev, ctdb, ctdb->daemon.sd, 
			   EVENT_FD_READ|EVENT_FD_AUTOCLOSE, 
			   ctdb_accept_client, ctdb);

	ctdb_main_loop(ctdb);

	return 0;
}

/*
  allocate a packet for use in client<->daemon communication
 */
struct ctdb_req_header *_ctdbd_allocate_pkt(struct ctdb_context *ctdb,
					    TALLOC_CTX *mem_ctx, 
					    enum ctdb_operation operation, 
					    size_t length, size_t slength,
					    const char *type)
{
	int size;
	struct ctdb_req_header *hdr;

	length = MAX(length, slength);
	size = (length+(CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);

	hdr = (struct ctdb_req_header *)talloc_size(mem_ctx, size);
	if (hdr == NULL) {
		DEBUG(0,("Unable to allocate packet for operation %u of length %u\n",
			 operation, (unsigned)length));
		return NULL;
	}
	talloc_set_name_const(hdr, type);
	memset(hdr, 0, slength);
	hdr->length       = length;
	hdr->operation    = operation;
	hdr->ctdb_magic   = CTDB_MAGIC;
	hdr->ctdb_version = CTDB_VERSION;
	hdr->srcnode      = ctdb->vnn;
	if (ctdb->vnn_map) {
		hdr->generation = ctdb->vnn_map->generation;
	}

	return hdr;
}


/*
  allocate a packet for use in daemon<->daemon communication
 */
struct ctdb_req_header *_ctdb_transport_allocate(struct ctdb_context *ctdb,
						 TALLOC_CTX *mem_ctx, 
						 enum ctdb_operation operation, 
						 size_t length, size_t slength,
						 const char *type)
{
	int size;
	struct ctdb_req_header *hdr;

	length = MAX(length, slength);
	size = (length+(CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);

	hdr = (struct ctdb_req_header *)ctdb->methods->allocate_pkt(mem_ctx, size);
	if (hdr == NULL) {
		DEBUG(0,("Unable to allocate transport packet for operation %u of length %u\n",
			 operation, (unsigned)length));
		return NULL;
	}
	talloc_set_name_const(hdr, type);
	memset(hdr, 0, slength);
	hdr->length       = length;
	hdr->operation    = operation;
	hdr->ctdb_magic   = CTDB_MAGIC;
	hdr->ctdb_version = CTDB_VERSION;
	hdr->generation   = ctdb->vnn_map->generation;
	hdr->srcnode      = ctdb->vnn;

	return hdr;	
}

/*
  called when a CTDB_REQ_FINISHED packet comes in
*/
void ctdb_request_finished(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	ctdb->num_finished++;
}


struct daemon_control_state {
	struct daemon_control_state *next, *prev;
	struct ctdb_client *client;
	struct ctdb_req_control *c;
	uint32_t reqid;
	struct ctdb_node *node;
};

/*
  callback when a control reply comes in
 */
static void daemon_control_callback(struct ctdb_context *ctdb,
				    int32_t status, TDB_DATA data, 
				    const char *errormsg,
				    void *private_data)
{
	struct daemon_control_state *state = talloc_get_type(private_data, 
							     struct daemon_control_state);
	struct ctdb_client *client = state->client;
	struct ctdb_reply_control *r;
	size_t len;

	/* construct a message to send to the client containing the data */
	len = offsetof(struct ctdb_reply_control, data) + data.dsize;
	if (errormsg) {
		len += strlen(errormsg);
	}
	r = ctdbd_allocate_pkt(ctdb, state, CTDB_REPLY_CONTROL, len, 
			       struct ctdb_reply_control);
	CTDB_NO_MEMORY_VOID(ctdb, r);

	r->hdr.reqid     = state->reqid;
	r->status        = status;
	r->datalen       = data.dsize;
	r->errorlen = 0;
	memcpy(&r->data[0], data.dptr, data.dsize);
	if (errormsg) {
		r->errorlen = strlen(errormsg);
		memcpy(&r->data[r->datalen], errormsg, r->errorlen);
	}

	daemon_queue_send(client, &r->hdr);

	talloc_free(state);
}

/*
  fail all pending controls to a disconnected node
 */
void ctdb_daemon_cancel_controls(struct ctdb_context *ctdb, struct ctdb_node *node)
{
	struct daemon_control_state *state;
	while ((state = node->pending_controls)) {
		DLIST_REMOVE(node->pending_controls, state);
		daemon_control_callback(ctdb, (uint32_t)-1, tdb_null, 
					"node is disconnected", state);
	}
}

/*
  destroy a daemon_control_state
 */
static int daemon_control_destructor(struct daemon_control_state *state)
{
	if (state->node) {
		DLIST_REMOVE(state->node->pending_controls, state);
	}
	return 0;
}

/*
  this is called when the ctdb daemon received a ctdb request control
  from a local client over the unix domain socket
 */
static void daemon_request_control_from_client(struct ctdb_client *client, 
					       struct ctdb_req_control *c)
{
	TDB_DATA data;
	int res;
	struct daemon_control_state *state;

	if (c->hdr.destnode == CTDB_CURRENT_NODE) {
		c->hdr.destnode = client->ctdb->vnn;
	}

	state = talloc(client, struct daemon_control_state);
	CTDB_NO_MEMORY_VOID(client->ctdb, state);

	state->client = client;
	state->c = talloc_steal(state, c);
	state->reqid = c->hdr.reqid;
	if (ctdb_validate_vnn(client->ctdb, c->hdr.destnode)) {
		state->node = client->ctdb->nodes[c->hdr.destnode];
		DLIST_ADD(state->node->pending_controls, state);
	} else {
		state->node = NULL;
	}

	talloc_set_destructor(state, daemon_control_destructor);
	
	data.dptr = &c->data[0];
	data.dsize = c->datalen;
	res = ctdb_daemon_send_control(client->ctdb, c->hdr.destnode,
				       c->srvid, c->opcode, client->client_id,
				       c->flags,
				       data, daemon_control_callback,
				       state);
	if (res != 0) {
		DEBUG(0,(__location__ " Failed to send control to remote node %u\n",
			 c->hdr.destnode));
	}

	if (c->flags & CTDB_CTRL_FLAG_NOREPLY) {
		talloc_free(state);
	}
}

/*
  register a call function
*/
int ctdb_daemon_set_call(struct ctdb_context *ctdb, uint32_t db_id,
			 ctdb_fn_t fn, int id)
{
	struct ctdb_registered_call *call;
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (ctdb_db == NULL) {
		return -1;
	}

	call = talloc(ctdb_db, struct ctdb_registered_call);
	call->fn = fn;
	call->id = id;

	DLIST_ADD(ctdb_db->calls, call);	
	return 0;
}
