/* 
   Unix SMB/CIFS implementation.

   dcerpc over TCP transport

   Copyright (C) Andrew Tridgell 2003
   
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

struct tcp_blob {
	struct tcp_blob *next, *prev;
	DATA_BLOB data;
};

/* transport private information used by TCP pipe transport */
struct tcp_private {
	struct event_context *event_ctx;
	struct fd_event *fde;
	int fd;
	char *server_name;
	uint32_t port;

	struct tcp_blob *pending_send;

	struct {
		size_t received;
		DATA_BLOB data;
		uint_t pending_count;
	} recv;
};


/*
  mark the socket dead
*/
static void tcp_sock_dead(struct dcerpc_pipe *p, NTSTATUS status)
{
	struct tcp_private *tcp = p->transport.private;

	if (tcp && tcp->fd != -1) {
		close(tcp->fd);
		tcp->fd = -1;
	}

	/* wipe any pending sends */
	while (tcp->pending_send) {
		struct tcp_blob *blob = tcp->pending_send;
		DLIST_REMOVE(tcp->pending_send, blob);
		talloc_free(blob);
	}

	if (!NT_STATUS_IS_OK(status)) {
		p->transport.recv_data(p, NULL, status);
	}
}

/*
  process send requests
*/
static void tcp_process_send(struct dcerpc_pipe *p)
{
	struct tcp_private *tcp = p->transport.private;

	while (tcp->pending_send) {
		struct tcp_blob *blob = tcp->pending_send;
		ssize_t ret = write(tcp->fd, blob->data.data, blob->data.length);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				tcp_sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
			}
			break;
		}

		blob->data.data += ret;
		blob->data.length -= ret;

		if (blob->data.length != 0) {
			break;
		}

		DLIST_REMOVE(tcp->pending_send, blob);
		talloc_free(blob);
	}

	if (tcp->pending_send == NULL) {
		tcp->fde->flags &= ~EVENT_FD_WRITE;
	}
}


/*
  process recv requests
*/
static void tcp_process_recv(struct dcerpc_pipe *p)
{
	struct tcp_private *tcp = p->transport.private;
	ssize_t ret;

	/* read in the base header to get the fragment length */
	if (tcp->recv.received < MIN_HDR_SIZE) {
		uint32_t frag_length;

		ret = read(tcp->fd, tcp->recv.data.data, 
			   MIN_HDR_SIZE - tcp->recv.received);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				tcp_sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
			}
			return;
		}
		if (ret == 0) {
			tcp_sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
			return;
		}

		tcp->recv.received += ret;

		if (tcp->recv.received != MIN_HDR_SIZE) {
			return;
		}
		frag_length = dcerpc_get_frag_length(&tcp->recv.data);

		tcp->recv.data.data = talloc_realloc(tcp->recv.data.data,
						     frag_length);
		if (tcp->recv.data.data == NULL) {
			tcp_sock_dead(p, NT_STATUS_NO_MEMORY);
			return;
		}
		tcp->recv.data.length = frag_length;
	}

	/* read in the rest of the packet */
	ret = read(tcp->fd, tcp->recv.data.data + tcp->recv.received,
		   tcp->recv.data.length - tcp->recv.received);
	if (ret == -1) {
		if (errno != EAGAIN && errno != EINTR) {
			tcp_sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
		}
		return;
	}
	if (ret == 0) {
		tcp_sock_dead(p, NT_STATUS_NET_WRITE_FAULT);
		return;
	}

	tcp->recv.received += ret;

	if (tcp->recv.received != tcp->recv.data.length) {
		return;
	}

	/* we have a full packet */
	p->transport.recv_data(p, &tcp->recv.data, NT_STATUS_OK);

	tcp->recv.received = 0;
	tcp->recv.pending_count--;
	if (tcp->recv.pending_count == 0) {
		tcp->fde->flags &= ~EVENT_FD_READ;
	}
}

/*
  called when a IO is triggered by the events system
*/
static void tcp_io_handler(struct event_context *ev, struct fd_event *fde, 
			   time_t t, uint16_t flags)
{
	struct dcerpc_pipe *p = fde->private;
	struct tcp_private *tcp = p->transport.private;

	if (flags & EVENT_FD_WRITE) {
		tcp_process_send(p);
	}

	if (tcp->fd == -1) {
		return;
	}

	if (flags & EVENT_FD_READ) {
		tcp_process_recv(p);
	}
}

/* 
   send an initial pdu in a multi-pdu sequence
*/
static NTSTATUS tcp_send_request(struct dcerpc_pipe *p, 
				 DATA_BLOB *data)
{
	struct tcp_private *tcp = p->transport.private;
	struct tcp_blob *blob;

	blob = talloc_p(tcp, struct tcp_blob);
	if (blob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	blob->data = data_blob_talloc(blob, data->data, data->length);
	if (blob->data.data == NULL) {
		talloc_free(blob);
		return NT_STATUS_NO_MEMORY;
	}

	DLIST_ADD_END(tcp->pending_send, blob, struct tcp_blob *);

	tcp->fde->flags |= EVENT_FD_WRITE;

	return NT_STATUS_OK;
}

/* 
   initiate a read request 
*/
static NTSTATUS tcp_send_read(struct dcerpc_pipe *p)
{
	struct tcp_private *tcp = p->transport.private;

	tcp->recv.pending_count++;
	if (tcp->recv.pending_count == 1) {
		tcp->fde->flags |= EVENT_FD_READ;
	}
	return NT_STATUS_OK;
}

/* 
   return the event context so the caller can process asynchronously
*/
static struct event_context *tcp_event_context(struct dcerpc_pipe *p)
{
	struct tcp_private *tcp = p->transport.private;

	return tcp->event_ctx;
}

/* 
   shutdown TCP pipe connection
*/
static NTSTATUS tcp_shutdown_pipe(struct dcerpc_pipe *p)
{
	tcp_sock_dead(p, NT_STATUS_OK);

	return NT_STATUS_OK;
}

/*
  return TCP server name
*/
static const char *tcp_peer_name(struct dcerpc_pipe *p)
{
	struct tcp_private *tcp = p->transport.private;
	return tcp->server_name;
}


/* 
   open a rpc connection to a named pipe 
*/
NTSTATUS dcerpc_pipe_open_tcp(struct dcerpc_pipe **p, 
			      const char *server,
			      uint32_t port)
{
	struct tcp_private *tcp;
	int fd;
	struct in_addr addr;
	struct fd_event fde;

	if (port == 0) {
		port = EPMAPPER_PORT;
	}

	addr.s_addr = interpret_addr(server);
	if (addr.s_addr == 0) {
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	fd = open_socket_out(SOCK_STREAM, &addr, port, 30000);
	if (fd == -1) {
		return NT_STATUS_PORT_CONNECTION_REFUSED;
	}

	set_blocking(fd, False);

        if (!(*p = dcerpc_pipe_init())) {
                return NT_STATUS_NO_MEMORY;
	}
 
	/*
	  fill in the transport methods
	*/
	(*p)->transport.transport = NCACN_IP_TCP;
	(*p)->transport.private = NULL;

	(*p)->transport.send_request = tcp_send_request;
	(*p)->transport.send_read = tcp_send_read;
	(*p)->transport.event_context = tcp_event_context;
	(*p)->transport.recv_data = NULL;

	(*p)->transport.shutdown_pipe = tcp_shutdown_pipe;
	(*p)->transport.peer_name = tcp_peer_name;
	
	tcp = talloc((*p), sizeof(*tcp));
	if (!tcp) {
		dcerpc_pipe_close(*p);
		return NT_STATUS_NO_MEMORY;
	}

	tcp->fd = fd;
	tcp->server_name = talloc_strdup((*p), server);
	tcp->event_ctx = event_context_init();
	tcp->pending_send = NULL;
	tcp->recv.received = 0;
	tcp->recv.data = data_blob_talloc(tcp, NULL, MIN_HDR_SIZE);
	tcp->recv.pending_count = 0;

	fde.fd = fd;
	fde.flags = 0;
	fde.handler = tcp_io_handler;
	fde.private = *p;

	tcp->fde = event_add_fd(tcp->event_ctx, &fde);

	(*p)->transport.private = tcp;

        return NT_STATUS_OK;
}
