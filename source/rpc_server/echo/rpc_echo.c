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
	r->out.out_data = talloc(mem_ctx, r->in.len);
	if (!r->out.out_data) {
		return NT_STATUS_NO_MEMORY;
	}
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
	r->out.s2 = "this is a test string";
	
	return NT_STATUS_OK;
}

static NTSTATUS echo_TestCall2(struct dcesrv_state *dce, TALLOC_CTX *mem_ctx, struct TestCall2 *r)
{
	r->out.info = talloc(mem_ctx, sizeof(*r->out.info));
	if (!r->out.info) {
		r->out.result = NT_STATUS_NO_MEMORY;
		return NT_STATUS_OK;
	}

	r->out.result = NT_STATUS_OK;

	switch (r->in.level) {
	case 1:
		r->out.info->info1.v = 10;
		break;
	case 2:
		r->out.info->info2.v = 20;
		break;
	case 3:
		r->out.info->info3.v = 30;
		break;
	case 4:
		r->out.info->info4.v.low = 40;
		r->out.info->info4.v.high = 0;
		break;
	case 5:
		r->out.info->info5.v1 = 50;
		r->out.info->info5.v2.low = 60;
		r->out.info->info5.v2.high = 0;
		break;
	case 6:
		r->out.info->info6.v1 = 70;
		r->out.info->info6.info1.v= 80;
		break;
	case 7:
		r->out.info->info7.v1 = 80;
		r->out.info->info7.info4.v.low = 90;
		r->out.info->info7.info4.v.high = 0;
		break;
	default:
		r->out.result = NT_STATUS_INVALID_LEVEL;
		break;
	}

	return NT_STATUS_OK;
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


static int op_lookup_endpoints(TALLOC_CTX *mem_ctx, struct dcesrv_ep_iface **e)
{
	return dcesrv_lookup_endpoints(&dcerpc_table_rpcecho, mem_ctx, e);
}

static const struct dcesrv_endpoint_ops rpc_echo_ops = {
	op_query_endpoint,
	op_set_interface,
	op_connect,
	op_disconnect,
	op_lookup_endpoints
};

/*
  register with the dcerpc server
*/
void rpc_echo_init(struct dcesrv_context *dce)
{
	if (!dcesrv_endpoint_register(dce, &rpc_echo_ops, &dcerpc_table_rpcecho)) {
		DEBUG(1,("Failed to register rpcecho endpoint\n"));
	}
}
