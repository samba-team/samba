/* 
   Unix SMB/CIFS implementation.

   endpoint server for the echo pipe

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


static NTSTATUS echo_AddOne(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, struct echo_AddOne *r)
{
	*r->out.v = *r->in.v + 1;
	return NT_STATUS_OK;
}

static NTSTATUS echo_EchoData(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, struct echo_EchoData *r)
{
	memcpy(r->out.out_data, r->in.in_data, r->in.len);

	return NT_STATUS_OK;
}

static NTSTATUS echo_SinkData(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, struct echo_SinkData *r)
{
	return NT_STATUS_OK;
}

static NTSTATUS echo_SourceData(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, struct echo_SourceData *r)
{
	int i;
	for (i=0;i<r->in.len;i++) {
		r->out.data[i] = i;
	}

	return NT_STATUS_OK;
}

static NTSTATUS echo_TestCall(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, struct TestCall *r)
{
	return NT_STATUS_BAD_NETWORK_NAME;
}

static NTSTATUS echo_TestCall2(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, struct TestCall2 *r)
{
	return NT_STATUS_BAD_NETWORK_NAME;
}




/**************************************************************************
  all the code below this point is boilerplate that will be auto-generated
***************************************************************************/

static const dcesrv_dispatch_fn_t dispatch_table[] = {
	(dcesrv_dispatch_fn_t)echo_AddOne,
	(dcesrv_dispatch_fn_t)echo_EchoData,
	(dcesrv_dispatch_fn_t)echo_SinkData,
	(dcesrv_dispatch_fn_t)echo_SourceData,
	(dcesrv_dispatch_fn_t)echo_TestCall,
	(dcesrv_dispatch_fn_t)echo_TestCall2
};


/*
  return True if we want to handle the given endpoint
*/
static BOOL op_query_endpoint(const struct dcesrv_endpoint *ep)
{
	return dcesrv_table_query(&dcerpc_table_rpcecho, ep);
}

/*
  setup for a particular rpc interface
*/
static BOOL op_set_interface(struct dcesrv_state *dce, const char *uuid, uint32 if_version)
{
	if (strcasecmp(uuid, dcerpc_table_rpcecho.uuid) != 0 ||
	    if_version != dcerpc_table_rpcecho.if_version) {
		DEBUG(2,("Attempt to use unknown interface %s/%d\n", uuid, if_version));
		return False;
	}

	dce->ndr = &dcerpc_table_rpcecho;
	dce->dispatch = dispatch_table;

	return True;
}


/* op_connect is called when a connection is made to an endpoint */
static NTSTATUS op_connect(struct dcesrv_state *dce)
{
	return NT_STATUS_OK;
}

static void op_disconnect(struct dcesrv_state *dce)
{
	/* nothing to do */
}


static const struct dcesrv_endpoint_ops rpc_echo_ops = {
	op_query_endpoint,
	op_set_interface,
	op_connect,
	op_disconnect
};

/*
  register with the dcerpc server
*/
void rpc_echo_init(struct server_context *smb)
{
	if (!dcesrv_endpoint_register(smb, &rpc_echo_ops)) {
		DEBUG(1,("Failed to register rpcecho endpoint\n"));
	}
}
