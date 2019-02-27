/*
 *  Unix SMB/CIFS implementation.
 *
 *  SMBD RPC service callbacks
 *
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _RPC_EP_SETUP_H
#define _RPC_EP_SETUP_H

#include "rpc_server/rpc_server.h"

struct pf_listen_fd;

NTSTATUS dcesrv_init(TALLOC_CTX *mem_ctx,
		     struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx,
		     struct dcesrv_context *dce_ctx);

NTSTATUS dcesrv_setup_endpoint_sockets(struct tevent_context *ev_ctx,
				       struct messaging_context *msg_ctx,
				       struct dcesrv_context *dce_ctx,
				       struct dcesrv_endpoint *e,
				       dcerpc_ncacn_termination_fn term_fn,
				       void *term_data);

NTSTATUS dcesrv_create_endpoint_sockets(struct tevent_context *ev_ctx,
					struct messaging_context *msg_ctx,
					struct dcesrv_context *dce_ctx,
					struct dcesrv_endpoint *e,
					struct pf_listen_fd *listen_fds,
					int *listen_fds_size);

NTSTATUS rpc_setup_embedded(struct tevent_context *ev_ctx,
			    struct messaging_context *msg_ctx,
			    struct dcesrv_context *dce_ctx,
			    const struct dcesrv_interface *iface);

#endif /* _RPC_EP_SETUP_H */

/* vim: set ts=8 sw=8 noet cindent ft=c.doxygen: */
