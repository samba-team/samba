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

struct rpc_listen {
	struct dce_endpoint *e;
	struct model_ops *model_ops;
};


/*
  called when a RPC socket becomes writable
*/
static void dcerpc_write_handler(struct event_context *ev, struct fd_event *fde, 
				 time_t t, uint16 flags)
{
	struct dcesrv_state *dce = fde->private;
	DATA_BLOB blob;
	NTSTATUS status;

	blob = data_blob(NULL, 0x4000);
	if (!blob.data) {
		smb_panic("out of memory in rpc write handler");
	}

	status = dcesrv_output(dce, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		fde->flags &= ~EVENT_FD_WRITE;
	} else {
		write_data(fde->fd, blob.data, blob.length);
	}

	data_blob_free(&blob);
}

/*
  called when a RPC socket becomes readable
*/
static void dcerpc_read_handler(struct event_context *ev, struct fd_event *fde, 
				time_t t, uint16 flags)
{
	struct dcesrv_state *dce = fde->private;
	DATA_BLOB blob;
	ssize_t ret;

	blob = data_blob(NULL, 0x4000);
	if (!blob.data) {
		smb_panic("out of memory in rpc read handler");
	}

	ret = read(fde->fd, blob.data, blob.length);
	if (ret == 0) {
		smb_panic("need a shutdown routine");
	}
	if (ret == -1 && errno != EINTR) {
		smb_panic("need a shutdown routine");
	}
	if (ret == -1) {
		return;
	}

	dcesrv_input(dce, &blob);

	data_blob_free(&blob);

	fde->flags |= EVENT_FD_WRITE;
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
	struct dcesrv_context context;
	struct dcesrv_state *dce;
	struct fd_event fde;
	struct rpc_listen *r = private;
	struct dcesrv_endpoint endpoint;

	set_socket_options(fd,"SO_KEEPALIVE");
	set_socket_options(fd, lp_socket_options());

	context.endpoint_list = NULL;
	dcesrv_init(&context);

	endpoint.type = ENDPOINT_TCP;
	endpoint.info.tcp_port = 0;

	dcesrv_endpoint_connect_ops(&context, &endpoint, r->e->endpoint_ops, &dce);

	dce->dce = talloc_p(dce->mem_ctx, struct dcesrv_context);
	*dce->dce = context;

	set_blocking(fd, False);

	/* setup a event handler for this socket. We are initially
	   only interested in reading from the socket */
	fde.fd = fd;
	fde.handler = dcerpc_io_handler;
	fde.private = dce;
	fde.flags = EVENT_FD_READ;

	event_add_fd(ev, &fde);
}


/*
  setup a single rpc listener
 */
static void setup_listen_rpc(struct event_context *events,
			     struct model_ops *model_ops, 
			     struct in_addr *ifip, unsigned port,
			     struct dce_endpoint *e)
{
	struct fd_event fde;
	struct rpc_listen *r;

	fde.fd = open_socket_in(SOCK_STREAM, port, 0, ifip->s_addr, True);
	if (fde.fd == -1) {
		DEBUG(0,("Failed to open socket on %s:%u - %s\n",
			 inet_ntoa(*ifip), port, strerror(errno)));
		return;
	}

	/* ready to listen */
	set_socket_options(fde.fd, "SO_KEEPALIVE"); 
	set_socket_options(fde.fd, lp_socket_options());
      
	if (listen(fde.fd, SMBD_LISTEN_BACKLOG) == -1) {
		DEBUG(0,("Failed to listen on %s:%d - %s\n",
			 inet_ntoa(*ifip), port, strerror(errno)));
		close(fde.fd);
		return;
	}

	r = malloc(sizeof(*r));
	if (!r) {
		return;
	}

	r->e = e;
	r->model_ops = model_ops;

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
	struct dcesrv_context dce;
	TALLOC_CTX *mem_ctx;
	
	mem_ctx = talloc_init("add_socket_rpc");
	if (!mem_ctx) {
		smb_panic("out of memory in add_socket_rpc");
	}
	
	dce.endpoint_list = NULL;

	dcesrv_init(&dce);

	while (dce.endpoint_list) {
		struct dce_endpoint *e = dce.endpoint_list;
		struct dcesrv_ep_iface *ifaces;
		int count, i;

		count = e->endpoint_ops->lookup_endpoints(mem_ctx, &ifaces);
		for (i=0;i<count;i++) {
			if (ifaces[i].endpoint.type == ENDPOINT_TCP) {
				setup_listen_rpc(events, model_ops, ifip, 
						 ifaces[i].endpoint.info.tcp_port,
						 e);
				break;
			}
		}

		DLIST_REMOVE(dce.endpoint_list, e);
	}

	talloc_destroy(mem_ctx);
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
