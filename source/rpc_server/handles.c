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
struct dcesrv_handle *dcesrv_handle_new(struct dcesrv_state *dce, 
					uint8 handle_type)
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

	memset(h->wire_handle.data, 'H', sizeof(h->wire_handle.data));
	strncpy(h->wire_handle.data, dce->ndr->name, 11);
	h->wire_handle.data[11] = handle_type;
	
	/* TODO: check for wraparound here */
	SIVAL(&h->wire_handle.data, 12, random());
	dce->next_handle++;	
	SIVAL(&h->wire_handle.data, 16, dce->next_handle);

	DLIST_ADD(dce->handles, h);

	return h;
}

/*
  destroy a rpc handle
*/
void dcesrv_handle_destroy(struct dcesrv_state *dce, 
			   struct dcesrv_handle *h)
{
	DLIST_REMOVE(dce->handles, h);
	talloc_destroy(h->mem_ctx);
}


/*
  find an internal handle given a wire handle. If the wire handle is NULL then
  allocate a new handle
*/
struct dcesrv_handle *dcesrv_handle_fetch(struct dcesrv_state *dce, 
					  struct policy_handle *p,
					  uint8 handle_type)
{
	struct dcesrv_handle *h;

	if (all_zero(p->data, sizeof(p->data))) {
		return dcesrv_handle_new(dce, handle_type);
	}

	for (h=dce->handles; h; h=h->next) {
		if (memcmp(h->wire_handle.data, p->data, sizeof(p->data)) == 0) {
			return h;
		}
	}

	return NULL;
}
