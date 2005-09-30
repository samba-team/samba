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

static struct process_id socket_pid;

struct data_container {
	DATA_BLOB *contents;
	size_t filled;
};
static int dgram_fd = -1;
static int listen_fd = -1;
static int stream_fd = -1;
static struct data_container *stream_container;



/* change the message version with any incompatible changes in the protocol */
#define MESSAGE_VERSION 1

static const char *dispatch_path(void);
static BOOL init_stream_socket(void);

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
	if (listen_fd >= 0) {
		close(listen_fd);
		listen_fd = -1;
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
		asprintf(&path, "%s/%ss", lock_path("messaging"),
			 procid_str_static(&socket_pid));
		if (path != NULL) {
			unlink(path);
			free(path);
		}
	}
}

static BOOL message_init_socket(void)
{
	socket_pid = procid_self();

	SMB_ASSERT((dgram_fd == -1) && (listen_fd == -1) &&
		   (stream_fd == -1));

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

	{
		char *stream_name;
		asprintf(&stream_name, "%ss", procid_str_static(&socket_pid));
		if (stream_name == NULL) {
			DEBUG(0, ("asprintf failed\n"));
			goto fail;
		}
		listen_fd = create_pipe_sock(lock_path("messaging"),
					     stream_name, 0700);
		if (listen_fd < 0) {
			DEBUG(0, ("Could not create pipe sock: %s\n",
				  strerror(errno)));
			goto fail;
		}
		SAFE_FREE(stream_name);
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

static BOOL init_stream_socket(void)
{
	struct sockaddr_un sunaddr;
	socklen_t addrlen = sizeof(sunaddr);
	struct message_rec msg;
	ssize_t ret;

	SMB_ASSERT(stream_fd < 0);

	msg.len = sizeof(struct message_rec);
	msg.msg_version = MESSAGE_VERSION;
	msg.msg_type = MSG_CALLME;
	msg.duplicates = False;
	msg.src = procid_self();
	msg.dest = procid_self();

	ZERO_STRUCT(sunaddr);
	sunaddr.sun_family = AF_UNIX;
	strncpy(sunaddr.sun_path, dispatch_path(), sizeof(sunaddr.sun_path)-1);

	if (set_blocking(dgram_fd, True) < 0) {
		DEBUG(5, ("Failed to set dgram socket to blocking: %s\n",
			  strerror(errno)));
		return False;
	}

	ret = sys_sendto(dgram_fd, &msg, sizeof(msg), 0,
			 (struct sockaddr *)&sunaddr, sizeof(sunaddr));

	set_blocking(dgram_fd, False);

	if (ret != sizeof(msg)) {
		DEBUG(5, ("Failed to send CALLME msg: %s\n", strerror(errno)));
		return False;
	}

	/* A deliberately blocking accept, we're waiting for the dispatch
	 * daemon to connect to us */

	stream_fd = accept(listen_fd, (struct sockaddr *)&sunaddr, &addrlen);
	if (stream_fd < 0) {
		DEBUG(0, ("Accept failed: %s\n", strerror(errno)));
		set_blocking(dgram_fd, True);
		return False;
	}

	talloc_free(stream_container);
	stream_container = NULL;

	return True;
}

void message_select_setup(int *maxfd, fd_set *rfds)
{
	if (dgram_fd < 0) {
		return;
	}

	FD_SET(dgram_fd, rfds);
	*maxfd = MAX(*maxfd, dgram_fd);
	FD_SET(listen_fd, rfds);
	*maxfd = MAX(*maxfd, listen_fd);

	if (stream_fd >= 0) {
		FD_SET(stream_fd, rfds);
		*maxfd = MAX(*maxfd, stream_fd);
	}
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
	if ((stream_fd < 0) && !init_stream_socket()) {
		DEBUG(5, ("No stream socket\n"));
		goto done;
	}

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

static DATA_BLOB *read_from_dgram_socket(TALLOC_CTX *mem_ctx, int fd)
{
	int msglength;
	DATA_BLOB *result;
	ssize_t received;

	if (ioctl(fd, FIONREAD, &msglength) < 0) {
		DEBUG(5, ("Could not get the message length\n"));
		msglength = 65536;
	}

	result = data_blob_talloc_p(mem_ctx, NULL, msglength);
	if (result == NULL) {
		return NULL;
	}

	received = recv(fd, result->data, result->length, MSG_DONTWAIT);
	if (received != msglength) {
		DEBUG(0, ("Received different length (%d) than announced "
			  "(%d)\n", received, msglength));
		talloc_free(result);
		return NULL;
	}

	if (received < sizeof(struct message_rec)) {
		DEBUG(5, ("Message too short\n"));
		talloc_free(result);
		return NULL;
	}

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

static struct message_rec *parse_message(DATA_BLOB *blob)
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
	DATA_BLOB *blob = NULL;
	struct message_rec *msg = NULL;
	BOOL result = False;
	TALLOC_CTX *mem_ctx = talloc_init("message_dispatch");

	if (mem_ctx == NULL) {
		DEBUG(0, ("talloc_init failed\n"));
		return False;
	}

	if (FD_ISSET(listen_fd, rfds)) {
		int new_fd;
		struct sockaddr addr;
		socklen_t addrlen = sizeof(addr);
		new_fd = sys_accept(listen_fd, &addr, &addrlen);
		if (new_fd < 0) {
			DEBUG(5, ("accept failed: %s\n", strerror(errno)));
		}
		if (stream_fd >= 0) {
			DEBUG(5, ("Already got a stream fd, closing new\n"));
			close(new_fd);
		} else {
			stream_fd = new_fd;
		}
	}

	if (FD_ISSET(dgram_fd, rfds)) {
		blob = read_from_dgram_socket(mem_ctx, dgram_fd);
	}

	if (blob != NULL) {
		msg = parse_message(blob);
	}

	if (msg != NULL) {
		dispatch_one_message(msg);
		result = True;
	}

	if (stream_fd < 0) {
		goto done;
	}

	if (FD_ISSET(stream_fd, rfds)) {
		stream_container = read_from_stream_socket(stream_fd,
							   NULL,
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
	talloc_free(mem_ctx);
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

	if (dfn != NULL) {

		ZERO_STRUCTPN(dfn);

		dfn->msg_type = msg_type;
		dfn->fn = fn;

		DLIST_ADD(dispatch_fns, dfn);
	}
	else {
	
		DEBUG(0,("message_register: Not enough memory. malloc failed!\n"));
	}
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

static struct messaging_client *new_client(const struct process_id *pid)
{
	struct messaging_client *result;
	struct sockaddr *addr;
	socklen_t addrlen;
	struct sockaddr_un sunaddr;
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
	
	result->fd = socket(procid_is_local(pid) ? PF_UNIX: PF_INET,
			    SOCK_STREAM, 0);
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

	if (procid_is_local(pid)) {
		char *path;
		asprintf(&path, "%s/%ss", lock_path("messaging"),
			 procid_str_static(pid));
		if (path == NULL) {
			DEBUG(0, ("asprintf failed\n"));
			return False;
		}
		DEBUG(10, ("Connecting to client %s, path %s\n",
			   procid_str_static(pid), path));

		ZERO_STRUCT(sunaddr);
		sunaddr.sun_family = AF_UNIX;
		strncpy(sunaddr.sun_path, path, sizeof(sunaddr.sun_path)-1);
		SAFE_FREE(path);

		addr = (struct sockaddr *)&sunaddr;
		addrlen = sizeof(sunaddr);

	} else {
		ZERO_STRUCT(sinaddr);
		sinaddr.sin_family = AF_INET;
		sinaddr.sin_addr = pid->ip;
		sinaddr.sin_port = htons(MESSAGING_PORT);

		addr = (struct sockaddr *)&sinaddr;
		addrlen = sizeof(sinaddr);
	}

	if (sys_connect(result->fd, addr, addrlen) == 0) {
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

	dst = find_client(clients, &msg_rec->dest);
	if (dst == NULL) {
		DEBUG(10, ("Connecting to pid %s\n",
			   procid_str_static(&msg_rec->dest)));
		dst = new_client(&msg_rec->dest);
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

static void dispatch_once(int parent_pipe, int receive_fd, int tcp_listener)
{
	fd_set rfds, wfds;
	int maxfd = 0;
	struct messaging_client *client;
	int selret;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	FD_SET(parent_pipe, &rfds);
	maxfd = MAX(maxfd, parent_pipe);

	FD_SET(receive_fd, &rfds);
	maxfd = MAX(maxfd, receive_fd);

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

	if (FD_ISSET(parent_pipe, &rfds)) {
		/* Parent died */
		exit(0);
	}

	if (FD_ISSET(tcp_listener, &rfds)) {
		accept_tcp(tcp_listener);
	}

	if (FD_ISSET(receive_fd, &rfds)) {
		DATA_BLOB *blob;
		struct message_rec *msg;
		blob = read_from_dgram_socket(NULL, receive_fd);
		if (blob == NULL) {
			DEBUG(5, ("read from dgram socket failed\n"));
			return;
		}
		msg = parse_message(blob);
		if (msg == NULL) {
			DEBUG(5, ("Got invalid message\n"));
			return;
		}
		if (msg->msg_type != MSG_CALLME) {
			DEBUG(5, ("Only expecting CALLME, got %d\n",
				  msg->msg_type));
			talloc_free(blob);
			return;
		}
		new_client(&msg->src);
		talloc_free(blob);
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

void message_dispatch_daemon(void)
{
	int parent_pipe[2];
	int fd, tcp_fd;
	char *name;

	if (pipe(parent_pipe) < 0) {
		return;
	}

	if (sys_fork() != 0) {
		close(parent_pipe[0]);
		/* Leave the writing end around, it is implicitly closed if
		 * the parent dies */
		return;
	}

	close(parent_pipe[1]);

	asprintf(&name, "%s:dispatch", lp_socket_address());
	if (name == NULL) {
		smb_panic("asprintf failed\n");
	}
	fd = create_dgram_sock(lock_path("messaging"), name, 0700);
	SAFE_FREE(name);
	if (fd < 0) {
		smb_panic("Could not create dispatch socket\n");
	}

	tcp_fd = open_remote_listener();

	while (1) {
		dispatch_once(parent_pipe[0], fd, tcp_fd);
	}
}
