/* 
   ctdb daemon code

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

#include "includes.h"
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"
#include "lib/events/events.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"

#define CTDB_PATH	"/tmp/ctdb.socket"


static void ctdb_main_loop(struct ctdb_context *ctdb)
{
	ctdb->methods->start(ctdb);

	/* go into a wait loop to allow other nodes to complete */
	event_loop_wait(ctdb->ev);

	printf("event_loop_wait() returned. this should not happen\n");
	exit(1);
}


static void set_non_blocking(int fd)
{
	unsigned v;
	v = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, v | O_NONBLOCK);
}



struct ctdb_client {
	struct ctdb_context *ctdb;
	struct fd_event *fde;
	int fd;
	struct ctdb_partial partial;
};


/*
  destroy a ctdb_client
*/
static int ctdb_client_destructor(struct ctdb_client *client)
{
	close(client->fd);
	client->fd = -1;
	return 0;
}



static void client_request_call(struct ctdb_client *client, struct ctdb_req_call *c)
{
	struct ctdb_call_state *state;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_call call;
	struct ctdb_reply_call r;
	int res;

	for (ctdb_db=client->ctdb->db_list; ctdb_db; ctdb_db=ctdb_db->next) {
		if (ctdb_db->db_id == c->db_id) {
			break;
		}
	}
	if (!ctdb_db) {
		printf("Unknown database in request. db_id==0x%08x",c->db_id);
		return;
	}



	ZERO_STRUCT(call);
	call.call_id = c->callid;
	call.key.dptr = c->data;
	call.key.dsize = c->keylen;
	call.call_data.dptr = c->data + c->keylen;
	call.call_data.dsize = c->calldatalen;

	state = ctdb_call_send(ctdb_db, &call);

/* XXX this must be converted to fully async */
	res = ctdb_call_recv(state, &call);
	if (res != 0) {
		printf("ctdbd_call_recv() returned error\n");
		exit(1);
	}

	ZERO_STRUCT(r);
#if 0
	r.status =
#endif
	r.datalen          = call.reply_data.dsize;

	r.hdr.length       = offsetof(struct ctdb_reply_call, data) + r.datalen;
	r.hdr.ctdb_magic   = c->hdr.ctdb_magic;
	r.hdr.ctdb_version = c->hdr.ctdb_version;
	r.hdr.operation    = CTDB_REPLY_CALL;
#if 0
	r.hdr.destnode     =
	r.hdr.srcnode      =
#endif
	r.hdr.reqid        = c->hdr.reqid;
	
		
/*XXX need to handle the case of partial writes    logic for partial writes in tcp/ctdb_tcp_node_write */
	res = write(client->fd, &r, offsetof(struct ctdb_reply_call, data));
	if (r.datalen) {
		res = write(client->fd, call.reply_data.dptr, r.datalen);
	}
}


/* data contains a packet from the client */
static void client_incoming_packet(struct ctdb_client *client, void *data, size_t nread)
{
	struct ctdb_req_header *hdr = data;

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(client->ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(client->ctdb, "Bad CTDB version 0x%x rejected\n", hdr->ctdb_version);
		return;
	}

	switch (hdr->operation) {
	case CTDB_REQ_CALL:
		client_request_call(client, (struct ctdb_req_call *)hdr);
		break;

	}

	talloc_free(data);
}


static void ctdb_client_read(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private)
{
	struct ctdb_client *client = talloc_get_type(private, struct ctdb_client);
	int num_ready = 0;
	ssize_t nread;
	uint8_t *data, *data_base;

/*XXX replace this and all other similar code (tcp) with ctdb_io.c/ctdb_read_pdu */
	if (ioctl(client->fd, FIONREAD, &num_ready) != 0 ||
	    num_ready == 0) {
		/* we've lost the connection from a client client. */
		talloc_free(client);
		return;
	}

	client->partial.data = talloc_realloc_size(client, client->partial.data, 
					       num_ready + client->partial.length);
	if (client->partial.data == NULL) {
		/* not much we can do except drop the socket */
		talloc_free(client);
		return;
	}

	nread = read(client->fd, client->partial.data+client->partial.length, num_ready);
	if (nread <= 0) {
		/* the connection must be dead */
		talloc_free(client);
		return;
	}

	data = client->partial.data;
	nread += client->partial.length;

	client->partial.data = NULL;
	client->partial.length = 0;

	if (nread >= 4 && *(uint32_t *)data == nread) {
		/* it is the responsibility of the incoming packet function to free 'data' */
		client_incoming_packet(client, data, nread);
		return;
	}

	data_base = data;

	while (nread >= 4 && *(uint32_t *)data <= nread) {
		/* we have at least one packet */
		uint8_t *d2;
		uint32_t len;
		len = *(uint32_t *)data;
		d2 = talloc_memdup(client, data, len);
		if (d2 == NULL) {
			/* sigh */
			talloc_free(client);
			return;
		}
		client_incoming_packet(client, d2, len);
		data += len;
		nread -= len;		
	}

	if (nread > 0) {
		/* we have only part of a packet */
		if (data_base == data) {
			client->partial.data = data;
			client->partial.length = nread;
		} else {
			client->partial.data = talloc_memdup(client, data, nread);
			if (client->partial.data == NULL) {
				talloc_free(client);
				return;
			}
			client->partial.length = nread;
			talloc_free(data_base);
		}
		return;
	}

	talloc_free(data_base);
}


static void ctdb_accept_client(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private)
{
	struct sockaddr_in addr;
	socklen_t len;
	int fd;
	struct ctdb_context *ctdb = talloc_get_type(private, struct ctdb_context);
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

	event_add_fd(ctdb->ev, client, client->fd, EVENT_FD_READ, 
		     ctdb_client_read, client);	

	talloc_set_destructor(client, ctdb_client_destructor);
}



static void ctdb_read_from_parent(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private)
{
	int *fd = private;
	int cnt;
	char buf;

	/* XXX this is a good place to try doing some cleaning up before exiting */
	cnt = read(*fd, &buf, 1);
	if (cnt==0) {
		printf("parent process exited. filedescriptor dissappeared\n");
		exit(1);
	} else {
		printf("ctdb: did not expect data from parent process\n");
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
  start the protocol going
*/
int ctdbd_start(struct ctdb_context *ctdb)
{
	pid_t pid;
	static int fd[2];
	int res;
	struct fd_event *fde;

	/* generate a name to use for our local socket */
	ctdb->daemon.name = talloc_asprintf(ctdb, "%s.%s", CTDB_PATH, ctdb->address.address);
	/* get rid of any old sockets */
	unlink(ctdb->daemon.name);

	/* create a unix domain stream socket to listen to */
	res = ux_socket_bind(ctdb);
	if (res!=0) {
		printf("Failed to open CTDB unix domain socket\n");
		exit(10);
	}

	res = pipe(&fd[0]);
	if (res) {
		printf("Failed to open pipe for CTDB\n");
		exit(1);
	}
	pid = fork();
	if (pid==-1) {
		printf("Failed to fork CTDB daemon\n");
		exit(1);
	}

	if (pid) {
		close(fd[0]);
		close(ctdb->daemon.sd);
		ctdb->daemon.sd = -1;
		return 0;
	}

	
	close(fd[1]);
	ctdb_clear_flags(ctdb, CTDB_FLAG_DAEMON_MODE);
	ctdb->ev = event_context_init(NULL);
	fde = event_add_fd(ctdb->ev, ctdb, fd[0], EVENT_FD_READ, ctdb_read_from_parent, &fd[0]);
	fde = event_add_fd(ctdb->ev, ctdb, ctdb->daemon.sd, EVENT_FD_READ, ctdb_accept_client, ctdb);
	ctdb_main_loop(ctdb);

	return 0;
}


static void ctdb_daemon_read_cb(uint8_t *data, int cnt, void *args)
{
	struct ctdb_context *ctdb = talloc_get_type(args, struct ctdb_context);
	struct ctdb_req_header *hdr;

	if (cnt < sizeof(*hdr)) {
		ctdb_set_error(ctdb, "Bad packet length %d\n", cnt);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (cnt != hdr->length) {
		ctdb_set_error(ctdb, "Bad header length %d expected %d\n", 
			       hdr->length, cnt);
		return;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(ctdb, "Bad CTDB version 0x%x rejected\n", hdr->ctdb_version);
		return;
	}

	ctdb_reply_call(ctdb, hdr);
}



static void ctdb_daemon_io(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private)
{
	struct ctdb_context *ctdb = talloc_get_type(private, struct ctdb_context);


	if (flags&EVENT_FD_READ) {
		ctdb_read_pdu(ctdb->daemon.sd, ctdb, &ctdb->daemon.partial, ctdb_daemon_read_cb, ctdb);
	}
	if (flags&EVENT_FD_WRITE) {
		printf("socket is filled.   fix this   see tcp_io/ctdb_tcp_node_write how to do this\n");
/*		ctdb_daemon_write(ctdb);*/
	}
}

/*
  connect to a unix domain socket
*/
static int ux_socket_connect(struct ctdb_context *ctdb)
{
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, ctdb->daemon.name, sizeof(addr.sun_path));

	ctdb->daemon.sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctdb->daemon.sd == -1) {
		return -1;
	}
	
	if (connect(ctdb->daemon.sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(ctdb->daemon.sd);
		ctdb->daemon.sd = -1;
		return -1;
	}

	ctdb->daemon.fde = event_add_fd(ctdb->ev, ctdb, ctdb->daemon.sd, EVENT_FD_READ, 
		     ctdb_daemon_io, ctdb);	
	return 0;
}




static int ctdb_ltdb_lock(struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	return tdb_chainlock(ctdb_db->ltdb->tdb, key);
}

static int ctdb_ltdb_unlock(struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	return tdb_chainunlock(ctdb_db->ltdb->tdb, key);
}


#define CTDB_DS_ALIGNMENT 8
static void *ctdbd_allocate_pkt(struct ctdb_context *ctdb, size_t len)
{
	int size;

	size = (len+(CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);
	return talloc_size(ctdb, size);
}


struct ctdbd_queue_packet {
	struct ctdbd_queue_packet *next, *prev;
	uint8_t *data;
	uint32_t length;
};

/*
  queue a packet for sending
*/
int ctdbd_queue_pkt(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	uint8_t *data = (uint8_t *)hdr;
	uint32_t length = hdr->length;
	struct ctdbd_queue_packet *pkt;
	uint32_t length2;

	/* enforce the length and alignment rules from the tcp packet allocator */
	length2 = (length+(CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);
	*(uint32_t *)data = length2;

	if (length2 != length) {
		memset(data+length, 0, length2-length);
	}
	
	/* if the queue is empty then try an immediate write, avoiding
	   queue overhead. This relies on non-blocking sockets */
	if (ctdb->daemon.queue == NULL) {
		ssize_t n = write(ctdb->daemon.sd, data, length2);
		if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			printf("socket to ctdb daemon has died\n");
			return -1;
		}
		if (n > 0) {
			data += n;
			length2 -= n;
		}
		if (length2 == 0) return 0;
	}

	pkt = talloc(ctdb, struct ctdbd_queue_packet);
	CTDB_NO_MEMORY(ctdb, pkt);

	pkt->data = talloc_memdup(pkt, data, length2);
	CTDB_NO_MEMORY(ctdb, pkt->data);

	pkt->length = length2;

	if (ctdb->daemon.queue == NULL) {
		EVENT_FD_WRITEABLE(ctdb->daemon.fde);
	}

	DLIST_ADD_END(ctdb->daemon.queue, pkt, struct ctdbd_queue_packet *);

	return 0;
}


/*
  destroy a ctdb_call
*/
static int ctdbd_call_destructor(struct ctdb_call_state *state)
{
	idr_remove(state->node->ctdb->idr, state->c->hdr.reqid);
	return 0;
}

/*
  make a recv call to the local ctdb daemon

  This is called when the program wants to wait for a ctdb_call to complete and get the 
  results. This call will block unless the call has already completed.
*/
int ctdbd_call_recv(struct ctdb_call_state *state, struct ctdb_call *call)
{
	struct ctdb_record_handle *rec;

	while (state->state < CTDB_CALL_DONE) {
		event_loop_once(state->node->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		ctdb_set_error(state->node->ctdb, "%s", state->errmsg);
		talloc_free(state);
		return -1;
	}

	rec = state->fetch_private;

	/* ugly hack to manage forced migration */
	if (rec != NULL) {
		rec->data->dptr = talloc_steal(rec, state->call.reply_data.dptr);
		rec->data->dsize = state->call.reply_data.dsize;
		talloc_free(state);
		return 0;
	}

	if (state->call.reply_data.dsize) {
		call->reply_data.dptr = talloc_memdup(state->node->ctdb,
						      state->call.reply_data.dptr,
						      state->call.reply_data.dsize);
		call->reply_data.dsize = state->call.reply_data.dsize;
	} else {
		call->reply_data.dptr = NULL;
		call->reply_data.dsize = 0;
	}
	call->status = state->call.status;
	talloc_free(state);

	return 0;
}

/*
  make a ctdb call to the local daemon - async send

  This constructs a ctdb_call request and queues it for processing. 
  This call never blocks.
*/
struct ctdb_call_state *ctdbd_call_send(struct ctdb_db_context *ctdb_db, struct ctdb_call *call)
{
	struct ctdb_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_ltdb_header header;
	TDB_DATA data;
	int ret;
	size_t len;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ux_socket_connect(ctdb);
	}

	ret = ctdb_ltdb_lock(ctdb_db, call->key);
	if (ret != 0) {
		printf("failed to lock ltdb record\n");
		return NULL;
	}

	ret = ctdb_ltdb_fetch(ctdb_db, call->key, &header, ctdb_db, &data);
	if (ret != 0) {
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return NULL;
	}

#if 0
	if (header.dmaster == ctdb->vnn && !(ctdb->flags & CTDB_FLAG_SELF_CONNECT)) {
		state = ctdb_call_local_send(ctdb_db, call, &header, &data);
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return state;
	}
#endif

	state = talloc_zero(ctdb_db, struct ctdb_call_state);
	if (state == NULL) {
		printf("failed to allocate state\n");
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return NULL;
	}

	talloc_steal(state, data.dptr);

	len = offsetof(struct ctdb_req_call, data) + call->key.dsize + call->call_data.dsize;
	state->c = ctdbd_allocate_pkt(ctdb, len);
	if (state->c == NULL) {
		printf("failed to allocate packet\n");
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return NULL;
	}
	talloc_set_name_const(state->c, "ctdbd req_call packet");
	talloc_steal(state, state->c);

	state->c->hdr.length    = len;
	state->c->hdr.ctdb_magic = CTDB_MAGIC;
	state->c->hdr.ctdb_version = CTDB_VERSION;
	state->c->hdr.operation = CTDB_REQ_CALL;
	state->c->hdr.destnode  = header.dmaster;
	state->c->hdr.srcnode   = ctdb->vnn;
	/* this limits us to 16k outstanding messages - not unreasonable */
	state->c->hdr.reqid     = idr_get_new(ctdb->idr, state, 0xFFFF);
	state->c->flags         = call->flags;
	state->c->db_id         = ctdb_db->db_id;
	state->c->callid        = call->call_id;
	state->c->keylen        = call->key.dsize;
	state->c->calldatalen   = call->call_data.dsize;
	memcpy(&state->c->data[0], call->key.dptr, call->key.dsize);
	memcpy(&state->c->data[call->key.dsize], 
	       call->call_data.dptr, call->call_data.dsize);
	state->call                = *call;
	state->call.call_data.dptr = &state->c->data[call->key.dsize];
	state->call.key.dptr       = &state->c->data[0];

	state->node   = ctdb->nodes[header.dmaster];
	state->state  = CTDB_CALL_WAIT;
	state->header = header;
	state->ctdb_db = ctdb_db;

	talloc_set_destructor(state, ctdbd_call_destructor);

	ctdbd_queue_pkt(ctdb, &state->c->hdr);

/*XXX set up timeout to cleanup if server doesnt respond
	event_add_timed(ctdb->ev, state, timeval_current_ofs(CTDB_REQ_TIMEOUT, 0), 
			ctdb_call_timeout, state);
*/

	ctdb_ltdb_unlock(ctdb_db, call->key);
	return state;
}



