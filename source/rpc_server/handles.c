/* 
   Unix SMB/CIFS implementation.

   server side dcerpc handle code

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

/*
  allocate a new rpc handle
*/
struct dcesrv_handle *dcesrv_handle_new(struct dcesrv_connection *dce_conn, 
					uint8_t handle_type)
{
	TALLOC_CTX *mem_ctx;
	struct dcesrv_handle *h;

	mem_ctx = talloc_init("rpc handle type %d\n", handle_type);
	if (!mem_ctx) {
		return NULL;
	}
	h = talloc(mem_ctx, sizeof(*h));
	if (!h) {
		talloc_destroy(mem_ctx);
		return NULL;
	}
	h->mem_ctx = mem_ctx;
	h->data = NULL;
	h->destroy = NULL;

	h->wire_handle.handle_type = handle_type;
	uuid_generate_random(&h->wire_handle.uuid);
	
	DLIST_ADD(dce_conn->handles, h);

	return h;
}

/*
  destroy a rpc handle
*/
void dcesrv_handle_destroy(struct dcesrv_connection *dce_conn, 
			   struct dcesrv_handle *h)
{
	if (h->destroy) {
		h->destroy(dce_conn, h);
	}
	DLIST_REMOVE(dce_conn->handles, h);
	talloc_destroy(h->mem_ctx);
}


/*
  find an internal handle given a wire handle. If the wire handle is NULL then
  allocate a new handle
*/
struct dcesrv_handle *dcesrv_handle_fetch(struct dcesrv_connection *dce_conn, 
					  struct policy_handle *p,
					  uint8_t handle_type)
{
	struct dcesrv_handle *h;

	if (policy_handle_empty(p)) {
		return dcesrv_handle_new(dce_conn, handle_type);
	}

	for (h=dce_conn->handles; h; h=h->next) {
		if (h->wire_handle.handle_type == p->handle_type &&
		    uuid_equal(&p->uuid, &h->wire_handle.uuid)) {
			if (handle_type != DCESRV_HANDLE_ANY &&
			    p->handle_type != handle_type) {
				DEBUG(0,("client gave us the wrong handle type (%d should be %d)\n",
					 p->handle_type, handle_type));
				return NULL;
			}
			return h;
		}
	}

	return NULL;
}
