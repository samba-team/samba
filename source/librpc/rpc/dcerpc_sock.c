/* 
   Unix SMB/CIFS implementation.

   dcerpc over standard sockets transport

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   
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

#define MIN_HDR_SIZE 16

struct sock_blob {
	struct sock_blob *next, *prev;
	DATA_BLOB data;
};

/* transport private information used by general socket pipe transports */
struct sock_private {
	struct event_context *event_ctx;
	struct fd_event *fde;
	int fd;
	char *server_name;
	uint32_t port;

	struct sock_blob *pending_send;

	struct {
		size_t received;
		DATA_BLOB data;
		uint_t pending_count;
	} recv;
};


/*
  mark the socket dead
*/
static void sock_dead(struct dcerpc_pipe *p, NTSTATUS status)
{
	struct sock_private *sock = p->transport.private;

	if (sock && sock->fd != -1) {
		close(sock->fd);
		sock->fd = -1;
	}

	/* wipe any pending sends */
	while (sock->pending_send) {
		struct sock_blob *blob = sock->pending_send;
		DLIST_REMOVE(sock->pending_send, blob);
		talloc_free(blob);
	}

	if (!NT_STATUS_IS_OK(status)) {
		p->transport.recv_data(p, NULL, status);
	}
}

/*
  process send requests
*/
static void sock_process_send(struct dcerpc_pipe *p)
{
	struct sock_private *sock = p->transport.private;

	while (sock->pending_send) {
		struct sock_blob *blob = sock->pending_send;
		ssize_t ret = write(sock->fd, blob->data.data, blob->data.length);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
			}
			break;
		}
		if (ret == 0) {
			sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
			break;
		}

		blob->data.data += ret;
		blob->data.length -= ret;

		if (blob->data.length != 0) {
			break;
		}

		DLIST_REMOVE(sock->pending_send, blob);
		talloc_free(blob);
	}

	if (sock->pending_send == NULL) {
		sock->fde->flags &= ~EVENT_FD_WRITE;
	}
}


/*
  process recv requests
*/
static void sock_process_recv(struct dcerpc_pipe *p)
{
	struct sock_private *sock = p->transport.private;
	ssize_t ret;

	if (sock->recv.data.data == NULL) {
		sock->recv.data = data_blob_talloc(sock, NULL, MIN_HDR_SIZE);
	}

	/* read in the base header to get the fragment length */
	if (sock->recv.received < MIN_HDR_SIZE) {
		uint32_t frag_length;

		ret = read(sock->fd, sock->recv.data.data, 
			   MIN_HDR_SIZE - sock->recv.received);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
			}
			return;
		}
		if (ret == 0) {
			sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
			return;
		}

		sock->recv.received += ret;

		if (sock->recv.received != MIN_HDR_SIZE) {
			return;
		}
		frag_length = dcerpc_get_frag_length(&sock->recv.data);

		sock->recv.data.data = talloc_realloc(sock, sock->recv.data.data,
						     frag_length);
		if (sock->recv.data.data == NULL) {
			sock_dead(p, NT_STATUS_NO_MEMORY);
			return;
		}
		sock->recv.data.length = frag_length;
	}

	/* read in the rest of the packet */
	ret = read(sock->fd, sock->recv.data.data + sock->recv.received,
		   sock->recv.data.length - sock->recv.received);
	if (ret == -1) {
		if (errno != EAGAIN && errno != EINTR) {
			sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
		}
		return;
	}
	if (ret == 0) {
		sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
		return;
	}

	sock->recv.received += ret;

	if (sock->recv.received != sock->recv.data.length) {
		return;
	}

	/* we have a full packet */
	p->transport.recv_data(p, &sock->recv.data, NT_STATUS_OK);
	talloc_free(sock->recv.data.data);
	sock->recv.data = data_blob(NULL, 0);
	sock->recv.received = 0;
	sock->recv.pending_count--;
	if (sock->recv.pending_count == 0) {
		sock->fde->flags &= ~EVENT_FD_READ;
	}
}

/*
  called when a IO is triggered by the events system
*/
static void sock_io_handler(struct event_context *ev, struct fd_event *fde, 
			   time_t t, uint16_t flags)
{
	struct dcerpc_pipe *p = fde->private;
	struct sock_private *sock = p->transport.private;

	if (flags & EVENT_FD_WRITE) {
		sock_process_send(p);
	}

	if (sock->fd == -1) {
		return;
	}

	if (flags & EVENT_FD_READ) {
		sock_process_recv(p);
	}
}

/* 
   initiate a read request 
*/
static NTSTATUS sock_send_read(struct dcerpc_pipe *p)
{
	struct sock_private *sock = p->transport.private;

	sock->recv.pending_count++;
	if (sock->recv.pending_count == 1) {
		sock->fde->flags |= EVENT_FD_READ;
	}
	return NT_STATUS_OK;
}

/* 
   send an initial pdu in a multi-pdu sequence
*/
static NTSTATUS sock_send_request(struct dcerpc_pipe *p, DATA_BLOB *data, BOOL trigger_read)
{
	struct sock_private *sock = p->transport.private;
	struct sock_blob *blob;

	blob = talloc_p(sock, struct sock_blob);
	if (blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	blob->data = data_blob_talloc(blob, data->data, data->length);
	if (blob->data.data == NULL) {
		talloc_free(blob);
		return NT_STATUS_NO_MEMORY;
	}

	DLIST_ADD_END(sock->pending_send, blob, struct sock_blob *);

	sock->fde->flags |= EVENT_FD_WRITE;

	if (trigger_read) {
		sock_send_read(p);
	}

	return NT_STATUS_OK;
}

/* 
   return the event context so the caller can process asynchronously
*/
static struct event_context *sock_event_context(struct dcerpc_pipe *p)
{
	struct sock_private *sock = p->transport.private;

	return sock->event_ctx;
}

/* 
   shutdown sock pipe connection
*/
static NTSTATUS sock_shutdown_pipe(struct dcerpc_pipe *p)
{
	sock_dead(p, NT_STATUS_OK);

	return NT_STATUS_OK;
}

/*
  return sock server name
*/
static const char *sock_peer_name(struct dcerpc_pipe *p)
{
	struct sock_private *sock = p->transport.private;
	return sock->server_name;
}

/* 
   open a rpc connection to a named pipe 
*/
NTSTATUS dcerpc_pipe_open_tcp(struct dcerpc_pipe **p, 
			      const char *server,
			      uint32_t port, 
				  int family)
{
	struct sock_private *sock;
	int fd, gai_err;
	struct fd_event fde;
	struct addrinfo hints, *res, *tmpres;
	char portname[16];

	if (port == 0) {
		port = EPMAPPER_PORT;
	}

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(portname, sizeof(portname)-1, "%d", port);
	
	gai_err = getaddrinfo(server, portname, &hints, &res);
	if (gai_err < 0) 
	{
		DEBUG(0, ("Unable to connect to %s:%d : %s\n", server, port, gai_strerror(gai_err)));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	tmpres = res;
	
	while (tmpres) {
		fd = socket(tmpres->ai_family, tmpres->ai_socktype, tmpres->ai_protocol);

		if(fd >= 0) {
			if (connect(fd, tmpres->ai_addr, tmpres->ai_addrlen) == 0)	
				break; 
			fd = -1;
		}

		tmpres = tmpres->ai_next;
	}

	freeaddrinfo(res);
	
	if (fd == -1) {
		return NT_STATUS_PORT_CONNECTION_REFUSED;
	}

	set_socket_options(fd, lp_socket_options());

	if (!(*p = dcerpc_pipe_init())) {
                return NT_STATUS_NO_MEMORY;
	}
 
	/*
	  fill in the transport methods
	*/
	(*p)->transport.transport = NCACN_IP_TCP;
	(*p)->transport.private = NULL;

	(*p)->transport.send_request = sock_send_request;
	(*p)->transport.send_read = sock_send_read;
	(*p)->transport.event_context = sock_event_context;
	(*p)->transport.recv_data = NULL;

	(*p)->transport.shutdown_pipe = sock_shutdown_pipe;
	(*p)->transport.peer_name = sock_peer_name;
	
	sock = talloc((*p), sizeof(*sock));
	if (!sock) {
		dcerpc_pipe_close(*p);
		return NT_STATUS_NO_MEMORY;
	}

	sock->fd = fd;
	sock->server_name = talloc_strdup((*p), server);
	sock->event_ctx = event_context_init(sock);
	sock->pending_send = NULL;
	sock->recv.received = 0;
	sock->recv.data = data_blob(NULL, 0);
	sock->recv.pending_count = 0;

	fde.fd = fd;
	fde.flags = 0;
	fde.handler = sock_io_handler;
	fde.private = *p;

	sock->fde = event_add_fd(sock->event_ctx, &fde);

	(*p)->transport.private = sock;

	/* ensure we don't get SIGPIPE */
	BlockSignals(True,SIGPIPE);

    return NT_STATUS_OK;
}

/* 
   open a rpc connection to a unix socket 
*/
NTSTATUS dcerpc_pipe_open_unix_stream(struct dcerpc_pipe **p, 
									  const char *path)
{
	struct sock_private *sock;
	int fd;
	struct fd_event fde;
	struct sockaddr_un sa;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);

	if (fd < 0) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, path, sizeof(sa.sun_path));

	if (connect(fd, &sa, sizeof(sa)) < 0) {
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	set_socket_options(fd, lp_socket_options());

	if (!(*p = dcerpc_pipe_init())) {
                return NT_STATUS_NO_MEMORY;
	}
 
	/*
	  fill in the transport methods
	*/
	(*p)->transport.transport = NCACN_UNIX_STREAM;
	(*p)->transport.private = NULL;

	(*p)->transport.send_request = sock_send_request;
	(*p)->transport.send_read = sock_send_read;
	(*p)->transport.event_context = sock_event_context;
	(*p)->transport.recv_data = NULL;

	(*p)->transport.shutdown_pipe = sock_shutdown_pipe;
	(*p)->transport.peer_name = sock_peer_name;
	
	sock = talloc((*p), sizeof(*sock));
	if (!sock) {
		dcerpc_pipe_close(*p);
		return NT_STATUS_NO_MEMORY;
	}

	sock->fd = fd;
	sock->server_name = talloc_strdup((*p), path);
	sock->event_ctx = event_context_init(sock);
	sock->pending_send = NULL;
	sock->recv.received = 0;
	sock->recv.data = data_blob(NULL, 0);
	sock->recv.pending_count = 0;

	fde.fd = fd;
	fde.flags = 0;
	fde.handler = sock_io_handler;
	fde.private = *p;

	sock->fde = event_add_fd(sock->event_ctx, &fde);

	(*p)->transport.private = sock;

	/* ensure we don't get SIGPIPE */
	BlockSignals(True,SIGPIPE);

    return NT_STATUS_OK;
}

/* 
   open a rpc connection to a named pipe 
*/
NTSTATUS dcerpc_pipe_open_pipe(struct dcerpc_pipe **p, 
									  const char *identifier)
{
	struct sock_private *sock;
	int fd;
	struct fd_event fde;
	struct sockaddr_un sa;
	char *canon, *full_path;

	if (!(*p = dcerpc_pipe_init())) {
                return NT_STATUS_NO_MEMORY;
	}

	canon = talloc_strdup(*p, identifier);

	string_replace(canon, '/', '\\');

	full_path = talloc_asprintf(*p, "%s/%s", lp_ncalrpc_dir(), canon);

	fd = socket(PF_UNIX, SOCK_STREAM, 0);

	if (fd < 0) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, full_path, sizeof(sa.sun_path));

	if (connect(fd, &sa, sizeof(sa)) < 0) {
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	set_socket_options(fd, lp_socket_options());
 
	/*
	  fill in the transport methods
	*/
	(*p)->transport.transport = NCALRPC;
	(*p)->transport.private = NULL;

	(*p)->transport.send_request = sock_send_request;
	(*p)->transport.send_read = sock_send_read;
	(*p)->transport.event_context = sock_event_context;
	(*p)->transport.recv_data = NULL;

	(*p)->transport.shutdown_pipe = sock_shutdown_pipe;
	(*p)->transport.peer_name = sock_peer_name;
	
	sock = talloc((*p), sizeof(*sock));
	if (!sock) {
		dcerpc_pipe_close(*p);
		return NT_STATUS_NO_MEMORY;
	}

	sock->fd = fd;
	sock->server_name = full_path;
	sock->event_ctx = event_context_init(sock);
	sock->pending_send = NULL;
	sock->recv.received = 0;
	sock->recv.data = data_blob(NULL, 0);
	sock->recv.pending_count = 0;

	fde.fd = fd;
	fde.flags = 0;
	fde.handler = sock_io_handler;
	fde.private = *p;

	sock->fde = event_add_fd(sock->event_ctx, &fde);

	(*p)->transport.private = sock;

	/* ensure we don't get SIGPIPE */
	BlockSignals(True,SIGPIPE);

    return NT_STATUS_OK;
}
