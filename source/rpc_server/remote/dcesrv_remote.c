/* 
   Unix SMB/CIFS implementation.
   remote dcerpc operations

   Copyright (C) Stefan (metze) Metzmacher 2004
   
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
#include "rpc_server/dcerpc_server.h"

struct dcesrv_remote_private {
	struct dcerpc_pipe *c_pipe;
};

static NTSTATUS remote_op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface)
{
        NTSTATUS status;
        struct dcesrv_remote_private *private;
	const char *binding = lp_parm_string(-1, "dcerpc_remote", "binding");

	if (!binding) {
		DEBUG(0,("You must specify a ncacn binding string\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	private = talloc_p(dce_call->conn, struct dcesrv_remote_private);
	if (!private) {
		return NT_STATUS_NO_MEMORY;	
	}

	status = dcerpc_pipe_connect(&(private->c_pipe), binding, iface->uuid, iface->if_version,
				     lp_workgroup(), 
				     lp_parm_string(-1, "dcerpc_remote", "username"),
				     lp_parm_string(-1, "dcerpc_remote", "password"));
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dce_call->conn->private = private;

	return NT_STATUS_OK;	
}

static void remote_op_unbind(struct dcesrv_connection *dce_conn, const struct dcesrv_interface *iface)
{
	struct dcesrv_remote_private *private = dce_conn->private;

	dcerpc_pipe_close(private->c_pipe);

	return;	
}

static NTSTATUS remote_op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	NTSTATUS status;
	const struct dcerpc_interface_table *table = dce_call->conn->iface->private;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= table->num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc(mem_ctx, table->calls[opnum].struct_size);
	if (!*r) {
		return NT_STATUS_NO_MEMORY;
	}

        /* unravel the NDR for the packet */
	status = table->calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NT_STATUS_IS_OK(status)) {
		dcerpc_log_packet(table, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS remote_op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	struct dcesrv_remote_private *private = dce_call->conn->private;
	uint16_t opnum = dce_call->pkt.u.request.opnum;
	const struct dcerpc_interface_table *table = dce_call->conn->iface->private;
	const struct dcerpc_interface_call *call;
	const char *name;

	name = table->calls[opnum].name;
	call = &table->calls[opnum];

	if (private->c_pipe->flags & DCERPC_DEBUG_PRINT_IN) {
		ndr_print_function_debug(call->ndr_print, name, NDR_IN | NDR_SET_VALUES, r);		
	}

	/* we didn't use the return code of this function as we only check the last_fault_code */
	dcerpc_ndr_request(private->c_pipe, NULL, table, opnum, mem_ctx,r);

	dce_call->fault_code = private->c_pipe->last_fault_code;
	if (dce_call->fault_code != 0) {
		DEBUG(0,("dcesrv_remote: call[%s] failed with: %s!\n",name, dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		return NT_STATUS_NET_WRITE_FAULT;
	}

	if ((dce_call->fault_code == 0) && (private->c_pipe->flags & DCERPC_DEBUG_PRINT_OUT)) {
		ndr_print_function_debug(call->ndr_print, name, NDR_OUT, r);		
	}

	return NT_STATUS_OK;
}

static NTSTATUS remote_op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, void *r)
{
	NTSTATUS status;
	const struct dcerpc_interface_table *table = dce_call->conn->iface->private;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

        /* unravel the NDR for the packet */
	status = table->calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NT_STATUS_IS_OK(status)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS remote_register_one_iface(struct dcesrv_context *dce_ctx, const struct dcesrv_interface *iface)
{
	int i;
	const struct dcerpc_interface_table *table = iface->private;

	for (i=0;i<table->endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = table->endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, iface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,("remote_op_init_server: failed to register endpoint '%s'\n",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS remote_op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;
	char **ifaces = str_list_make(lp_parm_string(-1,"dcerpc_remote","interfaces"),NULL);

	if (!ifaces) {
		DEBUG(3,("remote_op_init_server: no interfaces configured\n"));
		return NT_STATUS_OK;
	}

	for (i=0;ifaces[i];i++) {
		NTSTATUS ret;
		struct dcesrv_interface iface;
		
		if (!ep_server->interface_by_name(&iface, ifaces[i])) {
			DEBUG(0,("remote_op_init_server: failed to find interface = '%s'\n", ifaces[i]));
			str_list_free(&ifaces);
			return NT_STATUS_UNSUCCESSFUL;
		}

		ret = remote_register_one_iface(dce_ctx, &iface);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(0,("remote_op_init_server: failed to register interface = '%s'\n", ifaces[i]));
			str_list_free(&ifaces);
			return ret;
		}
	}

	str_list_free(&ifaces);
	return NT_STATUS_OK;
}

static BOOL remote_fill_interface(struct dcesrv_interface *iface, const struct dcerpc_interface_table *if_tabl)
{
	iface->name = if_tabl->name;
	iface->uuid = if_tabl->uuid;
	iface->if_version = if_tabl->if_version;
	
	iface->bind = remote_op_bind;
	iface->unbind = remote_op_unbind;

	iface->ndr_pull = remote_op_ndr_pull;
	iface->dispatch = remote_op_dispatch;
	iface->ndr_push = remote_op_ndr_push;

	iface->private = if_tabl;

	return True;
}

static BOOL remote_op_interface_by_uuid(struct dcesrv_interface *iface, const char *uuid, uint32_t if_version)
{
	struct dcerpc_interface_list *l;

	for (l=dcerpc_pipes;l;l=l->next) {
		if (l->table->if_version == if_version &&
			strcmp(l->table->uuid, uuid)==0) {
			return remote_fill_interface(iface, l->table);
		}
	}

	return False;	
}

static BOOL remote_op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	struct dcerpc_interface_list *l;

	for (l=dcerpc_pipes;l;l=l->next) {
		if (strcmp(l->table->name, name)==0) {
			return remote_fill_interface(iface, l->table);
		}
	}

	return False;	
}

NTSTATUS dcerpc_server_remote_init(void)
{
	NTSTATUS ret;
	struct dcesrv_endpoint_server ep_server;

	ZERO_STRUCT(ep_server);

	/* fill in our name */
	ep_server.name = "remote";

	/* fill in all the operations */
	ep_server.init_server = remote_op_init_server;

	ep_server.interface_by_uuid = remote_op_interface_by_uuid;
	ep_server.interface_by_name = remote_op_interface_by_name;

	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'remote' endpoint server!\n"));
		return ret;
	}

	return ret;
}
