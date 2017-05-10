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

struct ndr_interface_table;
struct rpc_srv_callbacks;

bool dcesrv_ep_setup(struct tevent_context *ev_ctx,
		     struct messaging_context *msg_ctx);

bool rpc_setup_embedded(struct tevent_context *ev_ctx,
			struct messaging_context *msg_ctx,
			const struct ndr_interface_table *t,
			const char *pipe_name);

#endif /* _RPC_EP_SETUP_H */

/* vim: set ts=8 sw=8 noet cindent ft=c.doxygen: */
