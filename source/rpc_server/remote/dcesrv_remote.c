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
	void *private;	
};

static NTSTATUS remote_op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface)
{
        NTSTATUS status;
        struct dcesrv_remote_private *private;
	const char *binding = lp_parm_string(-1, "dcerpc_remote", "binding");

	if (!binding) {
		printf("You must specify a ncacn binding string\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	private = talloc_p(dce_call->conn, struct dcesrv_remote_private);
	if (!private) {
		return NT_STATUS_NO_MEMORY;	
	}

	status = dcerpc_pipe_connect(&(private->c_pipe), binding, iface->ndr->uuid, iface->ndr->if_version,
				     lp_workgroup(), 
				     lp_parm_string(-1, "dcerpc_remote", "username"),
				     lp_parm_string(-1, "dcerpc_remote", "password"));

	dce_call->conn->private = private;

	return NT_STATUS_OK;	
}

static void remote_op_unbind(struct dcesrv_connection *dce_conn, const struct dcesrv_interface *iface)
{
	struct dcesrv_remote_private *private = dce_conn->private;

	dcerpc_pipe_close(private->c_pipe);

	return;	
}

static NTSTATUS remote_op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	struct dcesrv_remote_private *private = dce_call->conn->private;
	NTSTATUS status;
	uint16_t opnum = dce_call->pkt.u.request.opnum;
	const char *name = dce_call->conn->iface->ndr->calls[opnum].name;
	ndr_push_flags_fn_t ndr_push_fn = dce_call->conn->iface->ndr->calls[opnum].ndr_push;
	ndr_pull_flags_fn_t ndr_pull_fn = dce_call->conn->iface->ndr->calls[opnum].ndr_pull;
	ndr_print_function_t ndr_print_fn = dce_call->conn->iface->ndr->calls[opnum].ndr_print;
	size_t struct_size = dce_call->conn->iface->ndr->calls[opnum].struct_size;

	if (private->c_pipe->flags & DCERPC_DEBUG_PRINT_IN) {
		ndr_print_function_debug(ndr_print_fn, name, NDR_IN | NDR_SET_VALUES, r);		
	}

	status = dcerpc_ndr_request(private->c_pipe, opnum, mem_ctx,
				    (ndr_push_flags_fn_t) ndr_push_fn,
				    (ndr_pull_flags_fn_t) ndr_pull_fn,
				    r, struct_size);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("dcesrv_remote: call[%s] failed with: %s!\n",name, nt_errstr(status)));
		return status;
	}

	if (NT_STATUS_IS_OK(status) && (private->c_pipe->flags & DCERPC_DEBUG_PRINT_OUT)) {
		ndr_print_function_debug(ndr_print_fn, name, NDR_OUT, r);		
	}

	return status;
}

static NTSTATUS remote_register_one_iface(struct dcesrv_context *dce_ctx, const struct dcesrv_interface *iface)
{
	int i;

	for (i=0;i<iface->ndr->endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = iface->ndr->endpoints->names[i];

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
	iface->ndr = if_tabl;

	iface->bind = remote_op_bind;
	iface->unbind = remote_op_unbind;
	iface->dispatch = remote_op_dispatch;

	return True;
}

static BOOL remote_op_interface_by_uuid(struct dcesrv_interface *iface, const char *uuid, uint32_t if_version)
{
	int i;

	for (i=0;dcerpc_pipes[i];i++) {
		if (dcerpc_pipes[i]->if_version == if_version &&
			strcmp(dcerpc_pipes[i]->uuid, uuid)==0) {
			return remote_fill_interface(iface, dcerpc_pipes[i]);
		}
	}

	return False;	
}

static BOOL remote_op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	int i;

	for (i=0;dcerpc_pipes[i];i++) {
		if (strcmp(dcerpc_pipes[i]->name, name)==0) {
			return remote_fill_interface(iface, dcerpc_pipes[i]);
		}
	}

	return False;	
}

NTSTATUS dcerpc_remote_init(void)
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
	ret = register_backend("dcerpc", &ep_server);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'remote' endpoint server!\n"));
		return ret;
	}

	return ret;
}
