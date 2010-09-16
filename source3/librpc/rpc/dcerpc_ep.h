/*
 *  Endpoint Mapper Functions
 *  DCERPC local endpoint mapper client routines
 *  Copyright (c) 2010      Andreas Schneider.
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

struct dcerpc_binding_vector {
    struct dcerpc_binding *bindings;
    uint32_t count;
};

NTSTATUS dcerpc_binding_vector_create(TALLOC_CTX *mem_ctx,
				      const struct ndr_interface_table *iface,
				      struct dcerpc_binding_vector **pbvec);

/**
 * @brief Adds server address information in the local endpoint map.
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
 * @return                 An NTSTATUS error code.
 */
NTSTATUS dcerpc_ep_register(const struct ndr_interface_table *iface,
			    const struct dcerpc_binding_vector *bind_vec,
			    const struct GUID *object_guid,
			    const char *annotation);

NTSTATUS dcerpc_ep_register_noreplace(const struct ndr_interface_table *iface,
				      const struct dcerpc_binding_vector *bind_vec,
				      const struct GUID *object_guid,
				      const char *annotation);

NTSTATUS dcerpc_ep_unregister(const struct ndr_interface_table *iface,
			      const struct dcerpc_binding_vector *bind_vec,
			      const struct GUID *object_guid);

#endif /* _DCERPC_EP_H_ */
