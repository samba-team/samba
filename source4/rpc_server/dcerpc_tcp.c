/* 
   Unix SMB/CIFS implementation.

   server side dcerpc over tcp code

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

struct rpc_server_context {
	struct dcesrv_endpoint *endpoint;
	const struct dcesrv_endpoint_ops *endpoint_ops;
	const struct model_ops *model_ops;
	struct dcesrv_state *dce;
	struct dcesrv_context dcesrv_context;
	int socket_fd;
	struct event_context *events;	
};

/*
  a callback from the process model termination routine 
*/
void rpc_server_terminate(void *rr)
{
	struct rpc_server_context *r = rr;

	dcesrv_endpoint_disconnect(r->dce);
	close(r->socket_fd);
	event_remove_fd_all(r->events, r->socket_fd);
	free(r);
}

/*
  called when a rpc session needs to be shutdown
*/
static void terminate_rpc_session(struct rpc_server_context *r, const char *reason)
{
	r->model_ops->terminate_rpc_connection(r, reason);
}

/*
  called when a RPC socket becomes writable
*/
static void dcerpc_write_handler(struct event_context *ev, struct fd_event *fde, 
				 time_t t, uint16 flags)
{
	struct rpc_server_context *r = fde->private;
	DATA_BLOB blob;
	NTSTATUS status;

	blob = data_blob(NULL, 0x4000);
	if (!blob.data) {
		terminate_rpc_session(r, "out of memory");
		return;
	}

	status = dcesrv_output(r->dce, &blob);

	if (NT_STATUS_IS_OK(status)) {
		write_data(fde->fd, blob.data, blob.length);
	}

	if (!r->dce->call_list || !r->dce->call_list->replies) {
		fde->flags &= ~EVENT_FD_WRITE;
	}

	data_blob_free(&blob);
}

/*
  called when a RPC socket becomes readable
*/
static void dcerpc_read_handler(struct event_context *ev, struct fd_event *fde, 
				time_t t, uint16 flags)
{
	struct rpc_server_context *r = fde->private;
	DATA_BLOB blob;
	ssize_t ret;

	blob = data_blob(NULL, 0x4000);
	if (!blob.data) {
		terminate_rpc_session(r, "out of memory");
		return;
	}

	ret = read(fde->fd, blob.data, blob.length);
	if (ret == 0 || (ret == -1 && errno != EINTR)) {
		terminate_rpc_session(r, "eof on socket");
		return;
	}
	if (ret == -1) {
		return;
	}

	dcesrv_input(r->dce, &blob);

	data_blob_free(&blob);

	if (r->dce->call_list && r->dce->call_list->replies) {
		fde->flags |= EVENT_FD_WRITE;
	}
}




/*
  called when a RPC socket becomes readable
*/
static void dcerpc_io_handler(struct event_context *ev, struct fd_event *fde, 
			      time_t t, uint16 flags)
{
	if (flags & EVENT_FD_WRITE) {
		dcerpc_write_handler(ev, fde, t, flags);
	}

	if (flags & EVENT_FD_READ) {
		dcerpc_read_handler(ev, fde, t, flags);
	}
}
	
/*
  initialise a server_context from a open socket and register a event handler
  for reading from that socket
*/
void init_rpc_session(struct event_context *ev, void *private, int fd)
{
	struct fd_event fde;
	struct rpc_server_context *r = private;

	r = memdup(r, sizeof(struct rpc_server_context));

	r->events = ev;
	r->socket_fd = fd;

	set_socket_options(fd,"SO_KEEPALIVE");
	set_socket_options(fd, lp_socket_options());

	dcesrv_endpoint_connect_ops(&r->dcesrv_context, r->endpoint, r->endpoint_ops, &r->dce);

	r->dce->dce = &r->dcesrv_context;

	set_blocking(fd, False);

	/* setup a event handler for this socket. We are initially
	   only interested in reading from the socket */
	fde.fd = fd;
	fde.handler = dcerpc_io_handler;
	fde.private = r;
	fde.flags = EVENT_FD_READ;

	event_add_fd(ev, &fde);
}


/*
  setup a single rpc listener
 */
static void setup_listen_rpc(struct event_context *events,
			     struct model_ops *model_ops, 
			     struct in_addr *ifip, uint32 *port,
			     struct rpc_server_context *r,
			     const struct dcesrv_endpoint_ops *endpoint_ops)
{
	struct fd_event fde;
	int i;

	if (*port == 0) {
		fde.fd = -1;
		for (i=DCERPC_TCP_LOW_PORT;i<= DCERPC_TCP_HIGH_PORT;i++) {
			fde.fd = open_socket_in(SOCK_STREAM, i, 0, ifip->s_addr, True);			
			if (fde.fd != -1) break;
		}
		if (fde.fd != -1) {
			*port = i;
		}
	} else {
		fde.fd = open_socket_in(SOCK_STREAM, *port, 0, ifip->s_addr, True);
	}

	if (fde.fd == -1) {
		DEBUG(0,("Failed to open socket on %s:%u - %s\n",
			 inet_ntoa(*ifip), *port, strerror(errno)));
		return;
	}

	/* each listening socket has separate state, so must use a different context */
	r = memdup(r, sizeof(struct rpc_server_context));
	if (!r) {
		smb_panic("out of memory");
	}

	r->endpoint_ops = endpoint_ops;

	r->endpoint = malloc(sizeof(struct dcesrv_endpoint));
	if (!r->endpoint) {
		smb_panic("out of memory");
	}
	r->endpoint->type = ENDPOINT_TCP;
	r->endpoint->info.tcp_port = *port;

	/* ready to listen */
	set_socket_options(fde.fd, "SO_KEEPALIVE"); 
	set_socket_options(fde.fd, lp_socket_options());
      
	if (listen(fde.fd, SMBD_LISTEN_BACKLOG) == -1) {
		DEBUG(0,("Failed to listen on %s:%d - %s\n",
			 inet_ntoa(*ifip), *port, strerror(errno)));
		close(fde.fd);
		return;
	}

	/* we are only interested in read events on the listen socket */
	fde.flags = EVENT_FD_READ;
	fde.private = r;
	fde.handler = model_ops->accept_rpc_connection;
	
	event_add_fd(events, &fde);
}

/*
  add a socket address to the list of events, one event per dcerpc endpoint
*/
static void add_socket_rpc(struct event_context *events, 
			   struct model_ops *model_ops, 
			   struct in_addr *ifip)
{
	struct dce_endpoint *e;
	struct rpc_server_context *r;

	r = malloc(sizeof(struct rpc_server_context));
	if (!r) {
		smb_panic("out of memory");
	}

	r->dcesrv_context.endpoint_list = NULL;
	dcesrv_init(&r->dcesrv_context);
	r->endpoint = NULL;
	r->model_ops = model_ops;
	r->dce = NULL;
	r->socket_fd = -1;
	r->events = NULL;
	
	for (e=r->dcesrv_context.endpoint_list;e;e=e->next) {
		if (e->endpoint.type == ENDPOINT_TCP) {
			setup_listen_rpc(events, model_ops, ifip, 
					 &e->endpoint.info.tcp_port, 
					 r, e->endpoint_ops);
		}
	}
}

/****************************************************************************
 Open the listening sockets for RPC over TCP
****************************************************************************/
void open_sockets_rpc(struct event_context *events,
		      struct model_ops *model_ops)
{
	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);
			if (ifip == NULL) {
				continue;
			}
			add_socket_rpc(events, model_ops, ifip);
		}
	} else {
		TALLOC_CTX *mem_ctx = talloc_init("open_sockets_smbd");		
		struct in_addr *ifip = interpret_addr2(mem_ctx, lp_socket_address());
		if (!mem_ctx) {
			smb_panic("No memory");
		}
		add_socket_rpc(events, model_ops, ifip);
		talloc_destroy(mem_ctx);
	} 
}
