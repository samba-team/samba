/*
 *  Unix SMB/CIFS implementation.
 *
 *  RPC Endpoint Registration
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

#ifndef _RPC_EP_REGISTER_H
#define _RPC_EP_REGISTER_H

struct dcerpc_binding_vector;

/**
 * @brief Register an endpoint at the endpoint mapper.
 *
 * This just sets up a register and monitor loop to try to regsiter the
 * endpoint at the endpoint mapper.
 *
 * @param[in] ev_ctx    The event context to setup the loop.
 *
 * @param[in] msg_ctx   The messaging context to use for the connnection.
 *
 * @param[in] iface     The interface table to register.
 *
 * @param[in] v         The binding vector to register.
 *
 * @return              NT_STATUS_OK on success or a corresponding error code.
 */
NTSTATUS rpc_ep_register(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 const struct ndr_interface_table *iface,
			 const struct dcerpc_binding_vector *v);

#endif /* _RPC_EP_REGISTER_H */

/* vim: set ts=8 sw=8 noet cindent ft=c.doxygen: */
