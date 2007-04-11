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


/*
  structure describing a connected client in the daemon
 */
struct ctdb_client {
	struct ctdb_context *ctdb;
	int fd;
	struct ctdb_queue *queue;
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


/*
  this is called when the ctdb daemon received a ctdb request call
  from a local client over the unix domain socket
 */
static void daemon_request_call_from_client(struct ctdb_client *client, 
					    struct ctdb_req_call *c)
{
	struct ctdb_call_state *state;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_call call;
	struct ctdb_reply_call *r;
	int res;
	uint32_t length;

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

	length = offsetof(struct ctdb_reply_call, data) + call.reply_data.dsize;
	r = ctdbd_allocate_pkt(client->ctdb, length);
	if (r == NULL) {
		printf("Failed to allocate reply_call in ctdb daemon\n");
		return;
	}
	ZERO_STRUCT(*r);
	r->hdr.length       = length;
	r->hdr.ctdb_magic   = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation    = CTDB_REPLY_CALL;
	r->hdr.reqid        = c->hdr.reqid;
	r->datalen          = call.reply_data.dsize;
	memcpy(&r->data[0], call.reply_data.dptr, r->datalen);

	res = ctdb_queue_send(client->queue, (uint8_t *)&r, r->hdr.length);
	if (res != 0) {
		printf("Failed to queue packet from daemon to client\n");
	}
	talloc_free(r);
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
		daemon_request_call_from_client(client, (struct ctdb_req_call *)hdr);
		break;

	}

	talloc_free(data);
}


static void ctdb_client_read_cb(uint8_t *data, size_t cnt, void *args)
{
	struct ctdb_client *client = talloc_get_type(args, struct ctdb_client);
	struct ctdb_req_header *hdr;

	if (cnt < sizeof(*hdr)) {
		ctdb_set_error(client->ctdb, "Bad packet length %d\n", cnt);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (cnt != hdr->length) {
		ctdb_set_error(client->ctdb, "Bad header length %d expected %d\n", 
			       hdr->length, cnt);
		return;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(client->ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(client->ctdb, "Bad CTDB version 0x%x rejected\n", hdr->ctdb_version);
		return;
	}

	/* it is the responsibility of the incoming packet function to free 'data' */
	client_incoming_packet(client, data, cnt);
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

	client->queue = ctdb_queue_setup(ctdb, client, fd, CTDB_DS_ALIGNMENT, 
					 ctdb_client_read_cb, client);

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
int ctdbd_start(struct ctdb_context *ctdb)
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

	/* ensure the socket is deleted on exit of the daemon */
	domain_socket_name = talloc_strdup(talloc_autofree_context(), ctdb->daemon.name);
	talloc_set_destructor(domain_socket_name, unlink_destructor);	
	
	close(fd[1]);
	ctdb_clear_flags(ctdb, CTDB_FLAG_DAEMON_MODE);
	ctdb->ev = event_context_init(NULL);
	fde = event_add_fd(ctdb->ev, ctdb, fd[0], EVENT_FD_READ, ctdb_read_from_parent, &fd[0]);
	fde = event_add_fd(ctdb->ev, ctdb, ctdb->daemon.sd, EVENT_FD_READ, ctdb_accept_client, ctdb);
	ctdb_main_loop(ctdb);

	return 0;
}

/*
  allocate a packet for use in client<->daemon communication
 */
void *ctdbd_allocate_pkt(struct ctdb_context *ctdb, size_t len)
{
	int size;

	size = (len+(CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);
	return talloc_size(ctdb, size);
}

