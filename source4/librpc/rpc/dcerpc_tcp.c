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

/* transport private information used by TCP pipe transport */
struct tcp_private {
	int fd;
	char *server_name;
	uint32_t port;
};


/*
  mark the socket dead
*/
static void tcp_sock_dead(struct tcp_private *tcp)
{
	if (tcp && tcp->fd != -1) {
		close(tcp->fd);
		tcp->fd = -1;
	}
}

static NTSTATUS tcp_raw_recv(struct dcerpc_pipe *p, 
			     TALLOC_CTX *mem_ctx,
			     DATA_BLOB *blob)
{
	struct tcp_private *tcp = p->transport.private;
	ssize_t ret;
	uint32_t frag_length;
	DATA_BLOB blob1;

	blob1 = data_blob_talloc(mem_ctx, NULL, 16);
	if (!blob1.data) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = read_data(tcp->fd, blob1.data, blob1.length);
	if (ret != blob1.length) {
		tcp_sock_dead(tcp);
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	/* this could be a ncacn_http endpoint - this doesn't work
	   yet, but it goes close */
	if (strncmp(blob1.data, "ncacn_http/1.0", 14) == 0) {
		memmove(blob1.data, blob1.data+14, 2);
		ret = read_data(tcp->fd, blob1.data+2, 14);
		if (ret != 14) {
			tcp_sock_dead(tcp);
			return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		}
	}

	/* we might have recieved a partial fragment, in which case we
	   need to pull the rest of it */
	frag_length = dcerpc_get_frag_length(&blob1);
	if (frag_length == blob1.length) {
		*blob = blob1;
		return NT_STATUS_OK;
	}

	*blob = data_blob_talloc(mem_ctx, NULL, frag_length);
	if (!blob->data) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(blob->data, blob1.data, blob1.length);

	ret = read_data(tcp->fd, blob->data + blob1.length, frag_length - blob1.length);
	if (ret != frag_length - blob1.length) {
		tcp_sock_dead(tcp);
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	return NT_STATUS_OK;
}

static NTSTATUS tcp_full_request(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *request_blob,
				 DATA_BLOB *reply_blob)
{
	struct tcp_private *tcp = p->transport.private;
	ssize_t ret;

	ret = write_data(tcp->fd, request_blob->data, request_blob->length);
	if (ret != request_blob->length) {
		tcp_sock_dead(tcp);
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	return tcp_raw_recv(p, mem_ctx, reply_blob);
}
	      

/* 
   retrieve a secondary pdu from a pipe 
*/
static NTSTATUS tcp_secondary_request(struct dcerpc_pipe *p, 
			       TALLOC_CTX *mem_ctx,
			       DATA_BLOB *blob)
{
	return tcp_raw_recv(p, mem_ctx, blob);
}


/* 
   send an initial pdu in a multi-pdu sequence
*/
static NTSTATUS tcp_initial_request(struct dcerpc_pipe *p, 
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *blob)
{
	struct tcp_private *tcp = p->transport.private;
	ssize_t ret;

	ret = write_data(tcp->fd, blob->data, blob->length);
	if (ret != blob->length) {
		tcp_sock_dead(tcp);
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	return NT_STATUS_OK;
}


/* 
   shutdown TCP pipe connection
*/
static NTSTATUS tcp_shutdown_pipe(struct dcerpc_pipe *p)
{
	struct tcp_private *tcp = p->transport.private;

	tcp_sock_dead(tcp);

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

        if (!(*p = dcerpc_pipe_init())) {
                return NT_STATUS_NO_MEMORY;
	}
 
	/*
	  fill in the transport methods
	*/
	(*p)->transport.transport = NCACN_IP_TCP;
	(*p)->transport.private = NULL;
	(*p)->transport.full_request = tcp_full_request;
	(*p)->transport.secondary_request = tcp_secondary_request;
	(*p)->transport.initial_request = tcp_initial_request;
	(*p)->transport.shutdown_pipe = tcp_shutdown_pipe;
	(*p)->transport.peer_name = tcp_peer_name;
	
	tcp = talloc((*p)->mem_ctx, sizeof(*tcp));
	if (!tcp) {
		dcerpc_pipe_close(*p);
		return NT_STATUS_NO_MEMORY;
	}

	tcp->fd = fd;
	tcp->server_name = talloc_strdup((*p)->mem_ctx, server);

	(*p)->transport.private = tcp;

        return NT_STATUS_OK;
}
