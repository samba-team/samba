/* 
   Unix SMB/CIFS implementation.

   server side dcerpc over tcp code

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004   

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
	struct dcesrv_ep_description *ep_description;
	const struct dcesrv_endpoint *endpoint;
	const struct model_ops *model_ops;
	struct dcesrv_connection *dce_conn;
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

	dcesrv_endpoint_disconnect(r->dce_conn);
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
  write_fn callback for dcesrv_output()
*/
static ssize_t dcerpc_write_fn(void *private, const void *buf, size_t count)
{
	struct fd_event *fde = private;
	ssize_t ret;
	ret = write(fde->fd, buf, count);
	if (ret == -1 && errno == EINTR) {
		return 0;
	}
	return ret;
}

/*
  called when a RPC socket becomes writable
*/
static void dcerpc_write_handler(struct event_context *ev, struct fd_event *fde, 
				 time_t t, uint16_t flags)
{
	struct rpc_server_context *r = fde->private;
	NTSTATUS status;

	status = dcesrv_output(r->dce_conn, fde, dcerpc_write_fn);
	if (NT_STATUS_IS_ERR(status)) {
		/* TODO: destroy fd_event? */
	}

	if (!r->dce_conn->call_list || !r->dce_conn->call_list->replies) {
		fde->flags &= ~EVENT_FD_WRITE;
	}
}

/*
  called when a RPC socket becomes readable
*/
static void dcerpc_read_handler(struct event_context *ev, struct fd_event *fde, 
				time_t t, uint16_t flags)
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
		data_blob_free(&blob);
		terminate_rpc_session(r, "eof on socket");
		return;
	}
	if (ret == -1) {
		data_blob_free(&blob);
		return;
	}

	blob.length = ret;

	dcesrv_input(r->dce_conn, &blob);

	data_blob_free(&blob);

	if (r->dce_conn->call_list && r->dce_conn->call_list->replies) {
		fde->flags |= EVENT_FD_WRITE;
	}
}




/*
  called when a RPC socket becomes readable
*/
static void dcerpc_io_handler(struct event_context *ev, struct fd_event *fde, 
			      time_t t, uint16_t flags)
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
	NTSTATUS status;

	r = memdup(r, sizeof(struct rpc_server_context));

	r->events = ev;
	r->socket_fd = fd;

	set_socket_options(fd,"SO_KEEPALIVE");
	set_socket_options(fd, lp_socket_options());

	status = dcesrv_endpoint_connect(&r->dcesrv_context, r->endpoint, &r->dce_conn);
	if (!NT_STATUS_IS_OK(status)) {
		close(fd);
		free(r);
		DEBUG(0,("init_rpc_session: connection to endpoint failed: %s\n", 
			nt_errstr(status)));
		return;
	}

	r->dce_conn->dce_ctx = &r->dcesrv_context;

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
			     const struct model_ops *model_ops, 
			     struct in_addr *ifip, uint32_t *port,
			     struct rpc_server_context *r,
			     const struct dcesrv_endpoint *endpoint)
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

	r->ep_description = malloc(sizeof(struct dcesrv_ep_description));
	if (!r->ep_description) {
		smb_panic("out of memory");
	}
	r->ep_description->type = ENDPOINT_TCP;
	r->ep_description->info.tcp_port = *port;

	r->endpoint = endpoint;

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
			   const struct model_ops *model_ops, 
			   struct in_addr *ifip)
{
	struct dcesrv_endpoint *e;
	struct rpc_server_context *r;

	r = malloc(sizeof(struct rpc_server_context));
	if (!r) {
		smb_panic("out of memory");
	}

	r->dcesrv_context.endpoint_list = NULL;
	dcesrv_init_context(&r->dcesrv_context);
	r->ep_description = NULL;
	r->model_ops = model_ops;
	r->dce_conn = NULL;
	r->socket_fd = -1;
	r->events = NULL;
	
	for (e=r->dcesrv_context.endpoint_list;e;e=e->next) {
		if (e->ep_description.type == ENDPOINT_TCP) {
			setup_listen_rpc(events, model_ops, ifip, 
					 &e->ep_description.info.tcp_port, 
					 r, e);
		}
	}

	free(r);
}

/****************************************************************************
 Open the listening sockets for RPC over TCP
****************************************************************************/
void open_sockets_rpc(struct event_context *events,
		      const struct model_ops *model_ops)
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
