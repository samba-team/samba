/* 
   Unix SMB/CIFS implementation.
   Samba internal messaging functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001 by Martin Pool
   Copyright (C) 2002 by Jeremy Allison
   Copyright (C) 2005 by Volker Lendecke
   
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

/**
  @defgroup messages Internal messaging framework
  @{
  @file messages.c
  
  @brief  Module for internal messaging between Samba daemons. 

   The idea is that if a part of Samba wants to do communication with
   another Samba process then it will do a message_register() of a
   dispatch function, and use message_send_pid() to send messages to
   that process.

   The dispatch function is given the pid of the sender, and it can
   use that to reply by message_send_pid().  See ping_message() for a
   simple example.

   @caution Dispatch functions must be able to cope with incoming
   messages on an *odd* byte boundary.

   This system doesn't have any inherent size limitations but is not
   very efficient for large messages or when messages are sent in very
   quick succession.

*/

#include "includes.h"

#define CLUSTER_EXTENSION 1

static int connect_dispatch_daemon(void);

static struct process_id socket_pid;

struct data_container {
	DATA_BLOB *contents;
	size_t filled;
};
static int dgram_fd = -1;
static int stream_fd = -1;
static struct data_container *stream_container;

/* change the message version with any incompatible changes in the protocol */
#define MESSAGE_VERSION 1

static const char *dispatch_path(void);

struct message_rec {
	size_t len;
	int msg_version;
	int msg_type;
	BOOL duplicates;
	struct process_id dest;
	struct process_id src;
};

/* we have a linked list of dispatch handlers */
static struct dispatch_fns {
	struct dispatch_fns *next, *prev;
	int msg_type;
	void (*fn)(int msg_type, struct process_id pid, void *buf, size_t len);
} *dispatch_fns;


/****************************************************************************
 A useful function for testing the message system.
****************************************************************************/

static void ping_message(int msg_type, struct process_id src,
			 void *buf, size_t len)
{
	const char *msg = buf ? buf : "none";
	DEBUG(1,("INFO: Received PING message from PID %s [%s]\n",
		 procid_str_static(&src), msg));
	message_send_pid(src, MSG_PONG, buf, len, True);
}

/****************************************************************************
 Initialise the messaging functions. 
****************************************************************************/

static void shutdown_sockets(void)
{
	if (dgram_fd >= 0) {
		close(dgram_fd);
		dgram_fd = -1;
	}
	if (stream_fd >= 0) {
		close(stream_fd);
		stream_fd = -1;
	}
	if (procid_is_me(&socket_pid)) {
		char *path;
		asprintf(&path, "%s/%s", lock_path("messaging"),
			 procid_str_static(&socket_pid));
		if (path != NULL) {
			unlink(path);
			free(path);
		}
	}
}

static BOOL message_init_socket(void)
{
	struct message_rec hello;
	socket_pid = procid_self();

	SMB_ASSERT((dgram_fd == -1) && (stream_fd == -1));

	dgram_fd = create_dgram_sock(lock_path("messaging"),
				     procid_str_static(&socket_pid),
				     0700);
	if (dgram_fd < 0) {
		DEBUG(0, ("Could not create dgram socket: %s\n",
			  strerror(errno)));
		goto fail;
	}

	if (set_blocking(dgram_fd, False) < 0) {
		DEBUG(0, ("set_blocking failed: %s\n", strerror(errno)));
		goto fail;
	}

	stream_fd = connect_dispatch_daemon();
	if (stream_fd < 0) {
		DEBUG(5, ("Could not connect to dispatch daemon: %s\n",
			  strerror(errno)));
		goto fail;
	}

	hello.len = sizeof(hello);
	hello.msg_version = MESSAGE_VERSION;
	hello.msg_type = MSG_HELLO;
	hello.duplicates = False;
	hello.dest = procid_self();
	hello.src = hello.dest;

	if (write_data(stream_fd, (char *)&hello, sizeof(hello))
	    != sizeof(hello)) {
		DEBUG(0, ("Could not send hello message: %s\n",
			  strerror(errno)));
		goto fail;
	}

	return True;

 fail:
	shutdown_sockets();
	return False;
}

void message_reinit(void)
{
	if (dgram_fd < 0) {
		/* Never initialized messaging */
		return;
	}

	shutdown_sockets();
	message_init_socket();
}

BOOL message_init(void)
{
	if (!message_init_socket()) {
		DEBUG(0, ("Failed to init messaging socket\n"));
		return False;
	}

	message_register(MSG_PING, ping_message);

	/* Register some debugging related messages */

	register_msg_pool_usage();
	register_dmalloc_msgs();

	return True;
}

void message_end(void)
{
	shutdown_sockets();
}

void message_select_setup(int *maxfd, fd_set *rfds)
{
	if (dgram_fd < 0) {
		return;
	}
	FD_SET(dgram_fd, rfds);
	*maxfd = MAX(*maxfd, dgram_fd);
	FD_SET(stream_fd, rfds);
	*maxfd = MAX(*maxfd, stream_fd);
}

static const char *message_path(const struct process_id *pid)
{
	static pstring path;
	pstr_sprintf(path, "%s/%s", lock_path("messaging"),
		     procid_str_static(pid));
	return path;
}

BOOL message_send_pid(struct process_id pid, int msg_type,
		      const void *buf, size_t len, BOOL duplicates_allowed)
{
	DATA_BLOB packet;
	struct message_rec *hdr;
	struct sockaddr_un sunaddr;
	ssize_t sent;
	BOOL result = False;

	packet = data_blob(NULL, sizeof(struct message_rec) + len);
	if (packet.data == NULL) {
		DEBUG(0, ("malloc failed\n"));
		goto done;
	}

	hdr = (struct message_rec *)packet.data;
	hdr->len = packet.length;
	hdr->msg_version = MESSAGE_VERSION;
	hdr->msg_type = msg_type;
	hdr->duplicates = duplicates_allowed;
	hdr->src = procid_self();
	hdr->dest = pid;
	if (len > 0) {
		memcpy(packet.data + sizeof(struct message_rec), buf, len);
	}

	goto via_stream;
	if (!procid_is_local(&hdr->dest)) {
		goto via_stream;
	}

	ZERO_STRUCT(sunaddr);
	sunaddr.sun_family = AF_UNIX;
	strncpy(sunaddr.sun_path, message_path(&pid),
		sizeof(sunaddr.sun_path)-1);

	sent = sys_sendto(dgram_fd, packet.data, packet.length, 0,
			  (struct sockaddr *)&sunaddr, sizeof(sunaddr));

	if (sent == packet.length) {
		result = True;
		goto done;
	}

	if (sent > 0) {
		DEBUG(0, ("tried to send %d bytes, send returned %d ?? \n",
			  packet.length, sent));
		goto done;
	}

	if ((errno != EAGAIN) && (errno != EWOULDBLOCK) &&
	    (errno != EMSGSIZE)) {
		DEBUG(3, ("Could not send %d bytes to Unix domain "
			  "socket %s: %s\n", packet.length,
			  sunaddr.sun_path, strerror(errno)));
		goto done;
	}

	if (errno == EMSGSIZE) {
		DEBUG(10, ("message (%d bytes) too large, sending via "
			   "dispatcher\n", packet.length));
	} else {
		DEBUG(10, ("sending directly would block -- sending to "
			   "dispatcher in blocking mode\n"));
	}

 via_stream:

	sent = write_data(stream_fd, packet.data, packet.length);

	if (sent < packet.length) {
		DEBUG(5, ("Write failed: %s\n", strerror(errno)));
		close(stream_fd);
		stream_fd = -1;
		goto done;
	}

	result = True;

 done:

	SAFE_FREE(packet.data);
	return True;
}

static DATA_BLOB read_from_dgram_socket(int fd)
{
	int msglength;
	DATA_BLOB result;
	ssize_t received;

	if (ioctl(fd, FIONREAD, &msglength) < 0) {
		DEBUG(5, ("Could not get the message length\n"));
		msglength = 65536;
	}

	result = data_blob(NULL, msglength);
	if (result.data == NULL) {
		DEBUG(0, ("data_blob failed\n"));
		goto fail;
	}

	received = recv(fd, result.data, result.length, MSG_DONTWAIT);
	if (received != msglength) {
		DEBUG(0, ("Received different length (%d) than announced "
			  "(%d)\n", received, msglength));
		goto fail;
	}

	if (received < sizeof(struct message_rec)) {
		DEBUG(5, ("Message too short\n"));
		goto fail;
	}

	return result;

 fail:
	SAFE_FREE(result.data);
	result.length = 0;
	return result;
}

static BOOL container_full(const struct data_container *container)
{
	return ((container->filled != 0) &&
		(container->filled == container->contents->length));
}

static struct data_container *read_from_stream_socket(int fd,
						      TALLOC_CTX *mem_ctx,
						      struct data_container *c)
{
	struct data_container *cnt = c;
	size_t to_read;
	ssize_t nread;
	uint8_t *target;

	if ((cnt != NULL) && container_full(cnt)) {
		talloc_free(cnt);
		cnt = NULL;
	}

	if (cnt == NULL) {
		cnt = TALLOC_ZERO_P(mem_ctx, struct data_container);
	}

	if (cnt == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	if (cnt->contents == NULL) {
		cnt->contents = TALLOC_ZERO_P(cnt, DATA_BLOB);
	}

	if (cnt->contents == NULL) {
		DEBUG(0, ("talloc failed\n"));
		talloc_free(cnt);
		return NULL;
	}

	if ((cnt->contents->length == 0) ||
	    (cnt->filled < sizeof(cnt->contents->length))) {
		target = (uint8_t *)(&cnt->contents->length) + cnt->filled;
		to_read = sizeof(cnt->contents->length) - cnt->filled;
	} else {
		target = (uint8_t *)(cnt->contents->data) + cnt->filled;
		to_read = cnt->contents->length - cnt->filled;
	}

	DEBUG(5, ("reading %d bytes\n", to_read));

	nread = sys_read(fd, target, to_read);
	if (nread <= 0) {
		talloc_free(cnt);
		return NULL;
	}

	cnt->filled += nread;

	if (cnt->filled == sizeof(cnt->contents->length)) {
		DEBUG(5, ("Receiving msg of length %d\n",
			  cnt->contents->length));
		if (cnt->contents->length == 0) {
			DEBUG(2, ("received NULL message\n"));
			talloc_free(cnt);
			return NULL;
		}
		if (cnt->contents->length > MSG_MAXLEN) {
			DEBUG(2, ("Message too large: %d\n",
				  cnt->contents->length));
			talloc_free(cnt);
			return NULL;
		}
		cnt->contents->data = TALLOC_ARRAY(cnt, char,
						   cnt->contents->length);
		if (cnt->contents->data == NULL) {
			DEBUG(0, ("talloc failed\n"));
			talloc_free(cnt);
			return NULL;
		}
		{
			struct message_rec *msg =
				(struct message_rec *)cnt->contents->data;
			msg->len = cnt->contents->length;
		}
	}

	return cnt;
}

static struct message_rec *parse_message(const DATA_BLOB *blob)
{
	struct message_rec *result;

	if (blob->length < sizeof(struct message_rec)) {
		DEBUG(5, ("Message too short\n"));
		return NULL;
	}

	result = (struct message_rec *)blob->data;

	if (result->msg_version != MESSAGE_VERSION) {
		DEBUG(0,("message version %d received (expected %d)\n",
			 result->msg_version, MESSAGE_VERSION));
		return NULL;
	}

	if (result->len != blob->length) {
		DEBUG(5, ("Invalid message length received, got %d, "
			  "expected %d\n", result->len, blob->length));
		return NULL;
	}

	return result;
}

static int dispatch_one_message(struct message_rec *msg)
{
	struct dispatch_fns *dfn;
	int n_handled = 0;

	for (dfn = dispatch_fns; dfn; dfn = dfn->next) {
		uint8_t *user_buf;
		size_t user_len;
		if (dfn->msg_type != msg->msg_type) {
			continue;
		}
		DEBUG(10,("message_dispatch: processing message of "
			  "type %d.\n", msg->msg_type));

		user_len = msg->len - sizeof(struct message_rec);
		user_buf = (user_len == 0) ? NULL :
			((uint8_t *)msg)+sizeof(struct message_rec);
		dfn->fn(msg->msg_type, msg->src, user_buf, user_len);
		n_handled++;
	}

	if (n_handled == 0) {
		DEBUG(5,("message_dispatch: warning: no handlers registed for "
			 "msg_type %d in pid %u\n", msg->msg_type,
			 (unsigned int)sys_getpid()));
	}

	return n_handled;
}

BOOL message_dispatch(fd_set *rfds)
{
	DATA_BLOB dgram;
	struct message_rec *msg = NULL;
	BOOL result = False;

	ZERO_STRUCT(dgram);

	if (FD_ISSET(dgram_fd, rfds)) {
		dgram = read_from_dgram_socket(dgram_fd);
	}

	if (dgram.data != NULL) {
		msg = parse_message(&dgram);
	}

	if (msg != NULL) {
		dispatch_one_message(msg);
		SAFE_FREE(dgram.data);
		result = True;
	}

	if (FD_ISSET(stream_fd, rfds)) {
		stream_container =
			read_from_stream_socket(stream_fd, NULL,
						stream_container);
	}

	if ((stream_container == NULL) ||
	    (!container_full(stream_container))) {
		goto done;
	}

	msg = parse_message(stream_container->contents);

	if (msg != NULL) {
		dispatch_one_message(msg);
		result = True;
	}

 done:
	return result;
}

void message_select_dispatch(struct timeval *tv)
{
	fd_set rfds;
	int maxfd = 0;

	FD_ZERO(&rfds);
	message_select_setup(&maxfd, &rfds);
	if (sys_select(maxfd+1, &rfds, NULL, NULL, tv) > 0) {
		message_dispatch(&rfds);
	}
}

/****************************************************************************
 Register a dispatch function for a particular message type.
 *NOTE*: Dispatch functions must be able to cope with incoming
 messages on an *odd* byte boundary.
****************************************************************************/

void message_register(int msg_type, 
		      void (*fn)(int msg_type, struct process_id pid,
				 void *buf, size_t len))
{
	struct dispatch_fns *dfn;

	dfn = SMB_MALLOC_P(struct dispatch_fns);
	if (dfn == NULL) {
		DEBUG(0, ("malloc failed\n"));
		return;
	}

	ZERO_STRUCTPN(dfn);
	dfn->msg_type = msg_type;
	dfn->fn = fn;

	DLIST_ADD(dispatch_fns, dfn);
}

/****************************************************************************
 De-register the function for a particular message type.
****************************************************************************/

void message_deregister(int msg_type)
{
	struct dispatch_fns *dfn, *next;

	for (dfn = dispatch_fns; dfn; dfn = next) {
		next = dfn->next;
		if (dfn->msg_type == msg_type) {
			DLIST_REMOVE(dispatch_fns, dfn);
			SAFE_FREE(dfn);
		}
	}	
}

struct msg_all {
	int msg_type;
	uint32 msg_flag;
	const void *buf;
	size_t len;
	BOOL duplicates;
	int n_sent;
};

/****************************************************************************
 Send one of the messages for the broadcast.
****************************************************************************/

static int traverse_fn(TDB_CONTEXT *the_tdb, TDB_DATA kbuf, TDB_DATA dbuf,
		       void *state)
{
	struct connections_data crec;
	struct msg_all *msg_all = (struct msg_all *)state;

	if (dbuf.dsize != sizeof(crec))
		return 0;

	memcpy(&crec, dbuf.dptr, sizeof(crec));

	if (crec.cnum != -1)
		return 0;

	/* Don't send if the receiver hasn't registered an interest. */

	if(!(crec.bcast_msg_flags & msg_all->msg_flag))
		return 0;

	/* If the msg send fails because the pid was not found (i.e. smbd died), 
	 * the msg has already been deleted from the messages.tdb.*/

	if (!message_send_pid(crec.pid, msg_all->msg_type,
			      msg_all->buf, msg_all->len,
			      msg_all->duplicates)) {
		
		/* If the pid was not found delete the entry from connections.tdb */

		if (errno == ESRCH) {
			DEBUG(2,("pid %s doesn't exist - deleting connections %d [%s]\n",
				 procid_str_static(&crec.pid),
				 crec.cnum, crec.name));
			tdb_delete(the_tdb, kbuf);
		}
	}
	msg_all->n_sent++;
	return 0;
}

/**
 * Send a message to all smbd processes.
 *
 * It isn't very efficient, but should be OK for the sorts of
 * applications that use it. When we need efficient broadcast we can add
 * it.
 *
 * @param n_sent Set to the number of messages sent.  This should be
 * equal to the number of processes, but be careful for races.
 *
 * @retval True for success.
 **/
BOOL message_send_all(TDB_CONTEXT *conn_tdb, int msg_type,
		      const void *buf, size_t len,
		      BOOL duplicates_allowed,
		      int *n_sent)
{
	struct msg_all msg_all;

	msg_all.msg_type = msg_type;
	if (msg_type < 1000)
		msg_all.msg_flag = FLAG_MSG_GENERAL;
	else if (msg_type > 1000 && msg_type < 2000)
		msg_all.msg_flag = FLAG_MSG_NMBD;
	else if (msg_type > 2000 && msg_type < 2100)
		msg_all.msg_flag = FLAG_MSG_PRINT_NOTIFY;
	else if (msg_type > 2100 && msg_type < 3000)
		msg_all.msg_flag = FLAG_MSG_PRINT_GENERAL;
	else if (msg_type > 3000 && msg_type < 4000)
		msg_all.msg_flag = FLAG_MSG_SMBD;
	else
		return False;

	msg_all.buf = buf;
	msg_all.len = len;
	msg_all.duplicates = duplicates_allowed;
	msg_all.n_sent = 0;

	tdb_traverse(conn_tdb, traverse_fn, &msg_all);
	if (n_sent)
		*n_sent = msg_all.n_sent;
	return True;
}
/** @} **/

static const char *dispatch_path(void)
{
	static char *name = NULL;
	if (name == NULL) {
		asprintf(&name, "%s/%s:%s", lock_path("messaging"),
			 lp_socket_address(), "dispatch");
		SMB_ASSERT(name != NULL);
	}
	return name;
}

struct message {
	struct message *next, *prev;
	DATA_BLOB *data;
	size_t written;
};

struct messaging_client {
	struct messaging_client *next, *prev;
	struct process_id pid;
	int fd;
	BOOL connected;
	struct data_container *incoming;
	struct message *messages, *last_msg;
};

struct messaging_client *clients = NULL;

static struct messaging_client *find_client(struct messaging_client *c,
					    const struct process_id *pid)
{
	while (c != NULL) {
		if (procid_equal(&c->pid, pid))
			break;
		c = c->next;
	}
	return c;
}

static int messaging_client_destr(void *p)
{
	struct messaging_client *c =
		talloc_get_type_abort(p, struct messaging_client);

	if (close(c->fd) < 0) {
		DEBUG(0, ("close failed: %s\n", strerror(errno)));
		return -1;
	}
	return 0;
}

static void accept_tcp(int tcp_listener)
{
	struct messaging_client *c;
	int fd;
	struct sockaddr addr;
	struct sockaddr_in *in_addr = (struct sockaddr_in *)&addr;
	socklen_t addrlen = sizeof(addr);

	fd = sys_accept(tcp_listener, &addr, &addrlen);
	if (fd < 0) {
		DEBUG(5, ("accept failed: %s\n", strerror(errno)));
		return;
	}

	if (addr.sa_family != AF_INET) {
		DEBUG(5, ("Expected AF_INET(%d) in accept, got %d\n",
			  AF_INET, addr.sa_family));
		close(fd);
		return;
	}

	c = TALLOC_P(NULL, struct messaging_client);
	if (c == NULL) {
		DEBUG(0, ("talloc failed\n"));
		close(fd);
		return;
	}

	c->pid.ip = in_addr->sin_addr;
	c->pid.pid = MESSAGING_DISPATCHER_PID;
	c->fd = fd;
	c->connected = True;
	c->incoming = NULL;
	c->messages = NULL;
	c->last_msg = NULL;
	talloc_set_destructor(c, messaging_client_destr);

	DEBUG(10, ("Adding remote client %s\n", procid_str_static(&c->pid)));

	DLIST_ADD(clients, c);
}

static void accept_unix(int unix_listener)
{
	struct messaging_client *c;
	int fd;
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);

	fd = accept(unix_listener, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0) {
		DEBUG(5, ("accept failed: %s\n", strerror(errno)));
		return;
	}

	if (addr.sun_family != AF_UNIX) {
		DEBUG(5, ("Expected AF_UNIX(%d) in accept, got %d\n",
			  AF_UNIX, addr.sun_family));
		close(fd);
		return;
	}

	c = TALLOC_P(NULL, struct messaging_client);
	if (c == NULL) {
		DEBUG(0, ("talloc failed\n"));
		close(fd);
		return;
	}

	c->pid = procid_self();
	c->pid.pid = -1;
	c->fd = fd;
	c->connected = True;
	c->incoming = NULL;
	c->messages = NULL;
	c->last_msg = NULL;
	talloc_set_destructor(c, messaging_client_destr);

	DEBUG(10, ("Adding remote client %s\n", procid_str_static(&c->pid)));

	DLIST_ADD(clients, c);
}

static struct messaging_client *remote_connect(const struct process_id *pid)
{
	struct messaging_client *result;
	struct sockaddr_in sinaddr;

	result = TALLOC_P(NULL, struct messaging_client);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->pid = *pid;
	ZERO_STRUCT(result->incoming);
	result->messages = NULL;
	result->last_msg = NULL;
	result->connected = False;
	
	result->fd = socket(PF_INET, SOCK_STREAM, 0);
	if (result->fd < 0) {
		DEBUG(5, ("Could not create socket: %s\n", strerror(errno)));
		talloc_free(result);
		return NULL;
	}

	talloc_set_destructor(result, messaging_client_destr);

	if (set_blocking(result->fd, False) < 0) {
		DEBUG(1, ("set_blocking failed: %s\n", strerror(errno)));
		talloc_free(result);
		return NULL;
	}

	ZERO_STRUCT(sinaddr);
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_addr = pid->ip;
	sinaddr.sin_port = htons(MESSAGING_PORT);

	if (sys_connect(result->fd, (struct sockaddr *)&sinaddr,
			sizeof(sinaddr)) == 0) {
		result->connected = True;
		goto done;
	}

	if (errno == EINPROGRESS || errno == EALREADY || errno == EAGAIN) {
		/* Something is progressing */
		result->connected = False;
		goto done;
	}

	if (errno != 0) {
		DEBUG(0, ("connect failed: %s\n", strerror(errno)));
		talloc_free(result);
		return NULL;
	}

 done:
	DLIST_ADD(clients, result);
	return result;
}

static BOOL client_readable(struct messaging_client *c)
{
	struct messaging_client *dst;
	struct message_rec *msg_rec;
	struct message *msg;

	c->incoming = read_from_stream_socket(c->fd, c, c->incoming);
	if (c->incoming == NULL) {
		DEBUG(5, ("failed to read, killing client\n"));
		return False;
	}

	if (!container_full(c->incoming)) {
		return True;
	}

	msg_rec = parse_message(c->incoming->contents);
	if (msg_rec == NULL) {
		return False;
	}

	if (!procid_valid(&c->pid)) {
		if (msg_rec->msg_type != MSG_HELLO) {
			DEBUG(0, ("Client did not say hello\n"));
			return False;
		}
		DEBUG(10, ("Got hello from %s\n",
			   procid_str_static(&msg_rec->src)));
		c->pid = msg_rec->src;
		return True;
	}

	DEBUG(10, ("got message for %s\n", procid_str_static(&msg_rec->dest)));

	dst = find_client(clients, &msg_rec->dest);
	if ((dst == NULL) && (!procid_is_local(&msg_rec->dest))) {
		dst = remote_connect(&msg_rec->dest);
		return True;
	}

	if (dst == NULL) {
		DEBUG(10, ("Could not connect to pid %s, dropping message\n",
			   procid_str_static(&msg_rec->dest)));
		return True;
	}

	msg = TALLOC_P(dst, struct message);
	if (msg == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return True;
	}

	msg->data = TALLOC_P(msg, DATA_BLOB);
	if (msg->data == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return True;
	}

	msg->data->data = talloc_steal(msg, c->incoming->contents->data);
	msg->data->length = c->incoming->contents->length;
	msg->written = 0;

	if (dst->messages == NULL) {
		msg->prev = msg->next = NULL;
		dst->messages = dst->last_msg = msg;
		return True;
	}

	SMB_ASSERT(dst->last_msg->next == NULL);
	msg->prev = dst->last_msg;
	msg->next = NULL;
	dst->last_msg->next = msg;
	dst->last_msg = msg;
	return True;
}

static BOOL client_writeable(struct messaging_client *c)
{
	struct message *msg = c->messages;
	ssize_t sent;

	if (!c->connected) {
		c->connected = True;
		return True;
	}

	if (msg == NULL) {
		return True;
	}

	DEBUG(10, ("sending to client %s\n", procid_str_static(&c->pid)));

	sent = sys_write(c->fd, msg->data->data + msg->written,
			 msg->data->length - msg->written);

	if (sent < 0) {
		DEBUG(5, ("sending data failed, killing client: %s\n",
			  strerror(errno)));
		return False;
	}

	msg->written += sent;

	if (msg->written == msg->data->length) {
		DLIST_REMOVE(c->messages, msg);
		talloc_free(msg);
	}

	return True;
}

static void dispatch_loop(int *parent, int unix_listener, int tcp_listener)
{
	fd_set rfds, wfds;
	int maxfd = 0;
	struct messaging_client *client;
	int selret;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	if (*parent >= 0) {
		FD_SET(*parent, &rfds);
		maxfd = MAX(maxfd, *parent);
	}

	FD_SET(unix_listener, &rfds);
	maxfd = MAX(maxfd, unix_listener);

	FD_SET(tcp_listener, &rfds);
	maxfd = MAX(maxfd, tcp_listener);

	for (client = clients; client != NULL; client = client->next) {
		FD_SET(client->fd, &rfds);
		if (!client->connected || (client->messages != NULL)) {
			FD_SET(client->fd, &wfds);
		}
		maxfd = MAX(maxfd, client->fd);
	}

	selret = sys_select(maxfd+1, &rfds, &wfds, NULL, NULL);

	if (selret <= 0) {
		return;
	}

	if ((*parent > 0) && (FD_ISSET(*parent, &rfds))) {
		/* Parent died */
		close(*parent);
		*parent = -1;
	}

	if (FD_ISSET(tcp_listener, &rfds)) {
		accept_tcp(tcp_listener);
	}

	if (FD_ISSET(unix_listener, &rfds)) {
		accept_unix(unix_listener);
	}

	client = clients;
	while (client != NULL) {
		struct messaging_client *c;

		if (!client->connected && FD_ISSET(client->fd, &rfds) &&
		    FD_ISSET(client->fd, &wfds)) {
			DEBUG(5, ("Connect failed\n"));
			goto remove_client;
		}

		if (FD_ISSET(client->fd, &rfds) && !client_readable(client)) {
			goto remove_client;
		}

		if (FD_ISSET(client->fd, &wfds) && !client_writeable(client)) {
			goto remove_client;
		}
		client = client->next;
		continue;

	remove_client:

		c = client;
		client = client->next;
		DLIST_REMOVE(clients, c);
		talloc_free(c);
	}
}

#ifdef CLUSTER_EXTENSION
static int open_remote_listener(void)
{
	int result;

	result = open_socket_in(SOCK_STREAM, MESSAGING_PORT, 0,
				interpret_addr(lp_socket_address()), True);

	if (result < 0) {
		DEBUG(5, ("open_socket_in failed: %s\n", strerror(errno)));
		return result;
	}

	if (listen(result, 5) < 0) {
		DEBUG(0, ("listen() failed: %s\n", strerror(errno)));
		close(result);
		return -1;
	}
	return result;
}
#else
static int open_remote_listener(void)
{
	return -1;
}
#endif

static int dispatch_pidfile(void)
{
	char *path;
	int fd, ret;
	struct flock fl;

	asprintf(&path, "%s/%s", lock_path("messaging"), "dispatch.pid");
	if (path == NULL) {
		errno = ENOMEM;
		return -1;
	}

	fd = open(path, O_RDWR|O_CREAT, 0644);
	SAFE_FREE(path);

	if (fd < 0) {
		return -1;
	}

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 1;
	fl.l_pid = 0;

	do {
		ret = fcntl(fd, F_SETLKW, &fl);
	} while (ret == -1 && errno == EINTR);

	return fd;
}

static int dispatcher_child(int parent_pipe)
{
	int fd, tcp_fd;
	char *name;
	BOOL ok;

	asprintf(&name, "%s:dispatch", lp_socket_address());
	if (name == NULL) {
		smb_panic("asprintf failed\n");
	}
	fd = create_pipe_sock(lock_path("messaging"), name, 0700);
	SAFE_FREE(name);
	if (fd < 0) {
		smb_panic("Could not create dispatch socket\n");
	}
	tcp_fd = open_remote_listener();

	ok = True;
	write(parent_pipe, &ok, sizeof(ok));
	close(parent_pipe);

	while ((parent_pipe >= 0) || (clients != NULL)) {
		dispatch_loop(&parent_pipe, fd, tcp_fd);
	}
	exit(0);
}

static int connect_dispatch_daemon(void)
{
	int info_pipe[2];
	int sock, pidfile;
	pid_t child_pid;
	struct sockaddr_un sunaddr;
	BOOL ok;

	ZERO_STRUCT(sunaddr);
	sunaddr.sun_family = AF_UNIX;
	strncpy(sunaddr.sun_path, dispatch_path(), sizeof(sunaddr.sun_path)-1);

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		DEBUG(5, ("Could not create socket: %s\n", strerror(errno)));
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&sunaddr,
		    sizeof(sunaddr)) == 0) {
		return sock;
	}

	close(sock);

	pidfile = dispatch_pidfile();
	if (pidfile < 0) {
		DEBUG(5, ("Could not open pidfile: %s\n", strerror(errno)));
		return -1;
	}

	/* The pidfile is locked, because we can not atomically create a unix
	 * domain socket. Someone else might have found that no locking daemon
	 * is around and has created the socket for us. This second attempt to
	 * connect works around this race condition. */

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		DEBUG(5, ("Could not create socket: %s\n", strerror(errno)));
		close(pidfile);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&sunaddr,
		    sizeof(sunaddr)) == 0) {
		close(pidfile); /* Implictly release the lock */
		return sock;
	}

	close(sock);

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, info_pipe) != 0) {
		DEBUG(0, ("Could not create pipe: %s\n", strerror(errno)));
		close(pidfile);
		return -1;
	}

	child_pid = fork();
	if (child_pid < 0) {
		DEBUG(0, ("fork() failed: %s\n", strerror(errno)));
		close(pidfile);
		return -1;
	}

	if (child_pid == 0) {
		DEBUG(10, ("running message dispatcher child\n"));
		close(info_pipe[0]);
		dispatcher_child(info_pipe[1]); /* never returns */
	}

	close(info_pipe[1]);

	if (read(info_pipe[0], &ok, sizeof(ok)) != sizeof(ok)) {
		DEBUG(5, ("Reading from child failed: %s\n", strerror(errno)));
		close(pidfile);
		return -1;
	}

	if (!ok) {
		DEBUG(5, ("Child did not give ok to go\n"));
		close(pidfile);
		return -1;
	}

	/* info_pipe[0] is left open as an indication to the child that we're
	 * still around. */

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		DEBUG(5, ("Could not create socket: %s\n", strerror(errno)));
		close(pidfile);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&sunaddr,
		    sizeof(sunaddr)) == 0) {
		fstring pidstr;
		fstr_sprintf(pidstr, "%d\n", child_pid);
		sys_ftruncate(pidfile, 0);
		write(pidfile, pidstr, strlen(pidstr));
		close(pidfile); /* Implictly release the lock */
		return sock;
	}

	/* Ok, here we're really screwed. The child told us it's waiting for
	 * us, but apparently it isn't. */

	DEBUG(2, ("Starting dispatcher child failed\n"));
	close(pidfile);
	return -1;
}
