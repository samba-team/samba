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

struct dcesrv_context;
struct dcesrv_interface;

/**
 * @brief Adds server address information in the local endpoint map.
 *
 * @param[in]  mem_ctx  The memory context to use for the binding handle.
 *
 * @param[in]  dce_ctx  The dcerpc server context
 *
 * @param[in]  iface  The interface to register in the endpoint mapper
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
			    struct dcesrv_context *dce_ctx,
			    const struct dcesrv_interface *iface,
			    const struct GUID *object_guid,
			    const char *annotation,
			    struct dcerpc_binding_handle **ph);

NTSTATUS dcerpc_ep_register_noreplace(TALLOC_CTX *mem_ctx,
				      struct messaging_context *msg_ctx,
				      struct dcesrv_context *dce_ctx,
				      const struct dcesrv_interface *iface,
				      const struct GUID *object_guid,
				      const char *annotation,
				      struct dcerpc_binding_handle **ph);

NTSTATUS dcerpc_ep_unregister(struct messaging_context *msg_ctx,
			      struct dcesrv_context *dce_ctx,
			      const struct dcesrv_interface *iface,
			      const struct GUID *object_guid);

#endif /* _DCERPC_EP_H_ */
