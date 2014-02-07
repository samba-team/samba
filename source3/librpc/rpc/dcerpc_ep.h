/*
 *  Endpoint Mapper Functions
 *  DCERPC local endpoint mapper client routines
 *  Copyright (c) 2010-2011 Andreas Schneider.
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

#ifndef _DCERPC_EP_H_
#define _DCERPC_EP_H_

struct dcerpc_binding_vector;

/**
 * @brief Allocate a new binding vector.
 *
 * @param[in]  mem_ctx  The memory context to allocate the vector.
 *
 * @param[out] pbvec    A pointer to store the binding vector.
 *
 * @return              An NTSTATUS error code.
 */
NTSTATUS dcerpc_binding_vector_new(TALLOC_CTX *mem_ctx,
				   struct dcerpc_binding_vector **pbvec);

/**
 * @brief Add default named pipes to the binding vector.
 *
 * @param[in] iface     The rpc interface to add.
 *
 * @param[in] bvec      The binding vector to add the interface.
 *
 * @return              An NTSTATUS error code.
 */
NTSTATUS dcerpc_binding_vector_add_np_default(const struct ndr_interface_table *iface,
					      struct dcerpc_binding_vector *bvec);

/**
 * @brief Add a tcpip port to a binding vector.
 *
 * @param[in] iface     The rpc interface to add.
 *
 * @param[in] bvec      The binding vector to add the intface, host and port.
 *
 * @param[in] host      The ip address of the network inteface bound.
 *
 * @param[in] port      The port bound.
 *
 * @return              An NTSTATUS error code.
 */
NTSTATUS dcerpc_binding_vector_add_port(const struct ndr_interface_table *iface,
					struct dcerpc_binding_vector *bvec,
					const char *host,
					uint16_t port);

/**
 * @brief Add a unix socket (ncalrpc) to a binding vector.
 *
 * @param[in] iface     The rpc interface to add.
 *
 * @param[in] bvec      The binding vector to add the intface, host and port.
 *
 * @param[in] name      The name of the unix socket.
 *
 * @return              An NTSTATUS error code.
 */
NTSTATUS dcerpc_binding_vector_add_unix(const struct ndr_interface_table *iface,
					struct dcerpc_binding_vector *bvec,
					const char *name);

/**
 * @brief Duplicate a dcerpc_binding_vector.
 *
 * @param[in] mem_ctx   The memory context to create the duplicate on.
 *
 * @param[in] bvec      The binding vector to duplicate.
 *
 * @return              The duplicated binding vector or NULL on error.
 */
struct dcerpc_binding_vector *dcerpc_binding_vector_dup(TALLOC_CTX *mem_ctx,
							const struct dcerpc_binding_vector *bvec);

/**
 * @brief Replace the interface of the bindings in the vector.
 *
 * @param[in] iface     The new interface identifier to use.
 *
 * @param[in] v         The binding vector to change.
 *
 * @return              An NTSTATUS error code.
 */
NTSTATUS dcerpc_binding_vector_replace_iface(const struct ndr_interface_table *iface,
					     struct dcerpc_binding_vector *v);

/**
 * @brief Adds server address information in the local endpoint map.
 *
 * @param[in]  mem_ctx  The memory context to use for the binding handle.
 *
 * @param[in]  iface    The interface specification to register with the local
 *                      endpoint map.
 *
 * @param[in]  binding  The server binding handles over which the server can
 *                      receive remote procedure calls.
 *
 * @param[in]  object_guid The object GUID that the server offers. The server
 *                         application constructs this vector.
 *
 * @param[in]  annotation  Defines a character string comment applied to the
 *                         element added to the local endpoint map. The string
 *                         can be up to 64 characters long, including the null
 *                         terminating character. Strings longer than 64
 *                         characters are truncated. The application supplies
 *                         the value NULL or the string "" to indicate an empty
 *                         annotation string.
 *
 *                         When replacing elements, the annotation string
 *                         supplied, including an empty annotation string,
 *                         replaces any existing annotation string.
 *
 * @param[out] ph          A pointer to store the binding handle. The memory
 *                         context will be the give one. If you free this handle
 *                         then the connection will be closed.
 *
 * @return                 An NTSTATUS error code.
 */
NTSTATUS dcerpc_ep_register(TALLOC_CTX *mem_ctx,
			    struct messaging_context *msg_ctx,
			    const struct ndr_interface_table *iface,
			    const struct dcerpc_binding_vector *bind_vec,
			    const struct GUID *object_guid,
			    const char *annotation,
			    struct dcerpc_binding_handle **ph);

NTSTATUS dcerpc_ep_register_noreplace(TALLOC_CTX *mem_ctx,
				      struct messaging_context *msg_ctx,
				      const struct ndr_interface_table *iface,
				      const struct dcerpc_binding_vector *bind_vec,
				      const struct GUID *object_guid,
				      const char *annotation,
				      struct dcerpc_binding_handle **ph);

NTSTATUS dcerpc_ep_unregister(struct messaging_context *msg_ctx,
			      const struct ndr_interface_table *iface,
			      const struct dcerpc_binding_vector *bind_vec,
			      const struct GUID *object_guid);

#endif /* _DCERPC_EP_H_ */
