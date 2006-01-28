/* 
   Unix SMB/CIFS implementation.
   DCE/RPC over named pipes support (glue between dcerpc and smb servers)

   Copyright (C) Jelmer Vernooij 2005

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
#include "lib/socket/socket.h"
#include "lib/events/events.h"
#include "rpc_server/dcerpc_server.h"
#include "ntvfs/ipc/ipc.h"

static NTSTATUS dcesrv_pipe_open (void *context_data, const char *path, struct auth_session_info *session_info, struct stream_connection *srv_conn, TALLOC_CTX *mem_ctx, void **private_data)
{
	NTSTATUS status;
	struct dcerpc_binding *ep_description;
	struct dcesrv_connection *dce_conn;

	ep_description = talloc(mem_ctx, struct dcerpc_binding);
	NT_STATUS_HAVE_NO_MEMORY(ep_description);

	/*
	  we're all set, now ask the dcerpc server subsystem to open the 
	  endpoint. At this stage the pipe isn't bound, so we don't
	  know what interface the user actually wants, just that they want
	  one of the interfaces attached to this pipe endpoint.
	*/
	ep_description->transport = NCACN_NP;
	ep_description->endpoint = talloc_reference(ep_description, path);

	/* The session info is refcount-increased in the 
	 * dcesrv_endpoint_search_connect() function
	 */
	status = dcesrv_endpoint_search_connect(context_data,
						mem_ctx,
						ep_description, 
						session_info,
						srv_conn,
						&dce_conn);
	talloc_free(ep_description);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*private_data = dce_conn;

	return NT_STATUS_OK;
}

static NTSTATUS ipc_trans_dcesrv_output(void *private_data, DATA_BLOB *out, size_t *nwritten)
{
	NTSTATUS status = NT_STATUS_OK;
	DATA_BLOB *blob = private_data;

	if (out->length > blob->length) {
		status = STATUS_BUFFER_OVERFLOW;
	}

	if (out->length < blob->length) {
		blob->length = out->length;
	}
	memcpy(blob->data, out->data, blob->length);
	*nwritten = blob->length;
	return status;
}


static NTSTATUS dcesrv_pipe_trans(void *private_data, DATA_BLOB *in, DATA_BLOB *out)
{
	struct dcesrv_connection *dce_conn = private_data;
	NTSTATUS status;

	/* pass the data to the dcerpc server. Note that we don't
	   expect this to fail, and things like NDR faults are not
	   reported at this stage. Those sorts of errors happen in the
	   dcesrv_output stage */
	status = dcesrv_input(dce_conn, in);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	  now ask the dcerpc system for some output. This doesn't yet handle
	  async calls. Again, we only expect NT_STATUS_OK. If the call fails then
	  the error is encoded at the dcerpc level
	*/
	status = dcesrv_output(dce_conn, out, ipc_trans_dcesrv_output);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	return status;
}

static NTSTATUS dcesrv_pipe_write(void *private_data, DATA_BLOB *out)
{
	struct dcesrv_connection *dce_conn = private_data;
	NTSTATUS status;
	
	status = dcesrv_input(dce_conn, out);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return status;
}

static NTSTATUS ipc_readx_dcesrv_output(void *private_data, DATA_BLOB *out, size_t *nwritten)
{
	DATA_BLOB *blob = private_data;

	if (out->length < blob->length) {
		blob->length = out->length;
	}
	memcpy(blob->data, out->data, blob->length);
	*nwritten = blob->length;
	return NT_STATUS_OK;
}

		
static NTSTATUS dcesrv_pipe_read(void *private_data, DATA_BLOB *in)
{
	struct dcesrv_connection *dce_conn = private_data;
	NTSTATUS status;
	
	status = dcesrv_output(dce_conn, in, ipc_readx_dcesrv_output);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	return status;
}

const struct named_pipe_ops dce_pipe_ops = {
	.open = dcesrv_pipe_open,
	.write = dcesrv_pipe_write,
	.read = dcesrv_pipe_read,
	.trans = dcesrv_pipe_trans
};

/* Add named pipe endpoint */
NTSTATUS dcesrv_add_ep_np(struct dcesrv_context *dce_ctx, struct dcesrv_endpoint *e, struct event_context *event_ctx, const struct model_ops *model_ops)
{
	NTSTATUS status;

	status = named_pipe_listen(e->ep_description->endpoint, &dce_pipe_ops, dce_ctx);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	return NT_STATUS_OK;
}
