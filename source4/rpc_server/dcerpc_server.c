/* 
   Unix SMB/CIFS implementation.

   server side dcerpc core code

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
  find the set of endpoint operations for an endpoint server
*/
static const struct dcesrv_endpoint_ops *find_endpoint(struct server_context *smb,
						       const struct dcesrv_endpoint *endpoint)
{
	struct dce_endpoint *ep;
	for (ep=smb->dcesrv.endpoint_list; ep; ep=ep->next) {
		if (ep->endpoint_ops->query(endpoint)) {
			return ep->endpoint_ops;
		}
	}
	return NULL;
}


/*
  register an endpoint server
*/
BOOL dcesrv_endpoint_register(struct server_context *smb, 
			      const struct dcesrv_endpoint_ops *ops)
{
	struct dce_endpoint *ep;
	ep = malloc(sizeof(*ep));
	if (!ep) {
		return False;
	}
	ep->endpoint_ops = ops;
	DLIST_ADD(smb->dcesrv.endpoint_list, ep);
	return True;
}

/*
  connect to a dcerpc endpoint
*/
NTSTATUS dcesrv_endpoint_connect(struct server_context *smb,
				 const struct dcesrv_endpoint *endpoint,
				 struct dcesrv_state **p)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	const struct dcesrv_endpoint_ops *ops;

	/* make sure this endpoint exists */
	ops = find_endpoint(smb, endpoint);
	if (!ops) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	mem_ctx = talloc_init("dcesrv_endpoint_connect");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	*p = talloc(mem_ctx, sizeof(struct dcesrv_state));
	if (! *p) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	(*p)->mem_ctx = mem_ctx;
	(*p)->endpoint = *endpoint;
	(*p)->ops = ops;
	(*p)->private = NULL;

	/* make sure the endpoint server likes the connection */
	status = ops->connect(*p);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}
	
	return NT_STATUS_OK;
}


/*
  disconnect a link to an endpoint
*/
void dcesrv_endpoint_disconnect(struct dcesrv_state *p)
{
	p->ops->disconnect(p);
	talloc_destroy(p->mem_ctx);
}


/*
  provide some input to a dcerpc endpoint server. This passes data
  from a dcerpc client into the server
*/
NTSTATUS dcesrv_input(struct dcesrv_state *p, const DATA_BLOB *data)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  retrieve some output from a dcerpc server. The amount of data that
  is wanted is in data->length
*/
NTSTATUS dcesrv_output(struct dcesrv_state *p, DATA_BLOB *data)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  a useful function for implementing the query endpoint op
 */
BOOL dcesrv_table_query(const struct dcerpc_interface_table *table,
			const struct dcesrv_endpoint *ep)
{
	int i;
	const struct dcerpc_endpoint_list *endpoints = table->endpoints;

	if (ep->type != ENDPOINT_SMB) {
		return False;
	}

	for (i=0;i<endpoints->count;i++) {
		if (strcasecmp(ep->info.smb_pipe, endpoints->names[i]) == 0) {
			return True;
		}
	}
	return False;
}


/*
  initialise the dcerpc server subsystem
*/
BOOL dcesrv_init(struct server_context *smb)
{
	rpc_echo_init(smb);
	return True;
}
