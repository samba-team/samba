/* 
   Unix SMB/CIFS implementation.

   provide interfaces to rpc calls from ejs scripts

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "scripting/ejs/smbcalls.h"
#include "lib/appweb/ejs/ejs.h"
#include "librpc/gen_ndr/echo.h"
#include "lib/cmdline/popt_common.h"
#include "lib/messaging/irpc.h"
#include "scripting/ejs/ejsrpc.h"
#include "lib/util/dlinklist.h"
#include "lib/events/events.h"
#include "librpc/rpc/dcerpc_table.h"
#include "auth/credentials/credentials.h"
#include "librpc/rpc/dcerpc.h"
#include "cluster/cluster.h"

/*
  state of a irpc 'connection'
*/
struct ejs_irpc_connection {
	const char *server_name;
	struct server_id *dest_ids;
	struct messaging_context *msg_ctx;
};

/*
  messaging clients need server IDs as well ...
 */
#define EJS_ID_BASE 0x30000000

/*
  setup a context for talking to a irpc server
     example: 
        status = irpc.connect("smb_server");
*/
static int ejs_irpc_connect(MprVarHandle eid, int argc, char **argv)
{
	NTSTATUS status;
	int i;
	struct event_context *ev;
	struct ejs_irpc_connection *p;
	struct MprVar *this = mprGetProperty(ejsGetLocalObject(eid), "this", 0);

	/* validate arguments */
	if (argc != 1) {
		ejsSetErrorMsg(eid, "rpc_connect invalid arguments");
		return -1;
	}

	p = talloc(this, struct ejs_irpc_connection);
	if (p == NULL) {
		return -1;
	}

	p->server_name = argv[0];

	ev = event_context_find(p);

	/* create a messaging context, looping as we have no way to
	   allocate temporary server ids automatically */
	for (i=0;i<10000;i++) {
		p->msg_ctx = messaging_init(p, cluster_id(EJS_ID_BASE + i), ev);
		if (p->msg_ctx) break;
	}
	if (p->msg_ctx == NULL) {
		ejsSetErrorMsg(eid, "irpc_connect unable to create a messaging context");
		talloc_free(p);
		return -1;
	}

	p->dest_ids = irpc_servers_byname(p->msg_ctx, p, p->server_name);
	if (p->dest_ids == NULL || p->dest_ids[0].id == 0) {
		talloc_free(p);
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	} else {
		mprSetPtrChild(this, "irpc", p);
		status = NT_STATUS_OK;
	}

	mpr_Return(eid, mprNTSTATUS(status));
	return 0;
}


/*
  connect to an rpc server
     examples: 
        status = rpc.connect("ncacn_ip_tcp:localhost");
        status = rpc.connect("ncacn_ip_tcp:localhost", "pipe_name");
*/
static int ejs_rpc_connect(MprVarHandle eid, int argc, char **argv)
{
	const char *binding, *pipe_name;
	const struct dcerpc_interface_table *iface;
	NTSTATUS status;
	struct dcerpc_pipe *p;
	struct cli_credentials *creds;
	struct event_context *ev;
	struct MprVar *this = mprGetProperty(ejsGetLocalObject(eid), "this", 0);
	struct MprVar *credentials;

	/* validate arguments */
	if (argc < 1) {
		ejsSetErrorMsg(eid, "rpc_connect invalid arguments");
		return -1;
	}

	binding    = argv[0];
	if (strchr(binding, ':') == NULL) {
		/* its an irpc connect */
		return ejs_irpc_connect(eid, argc, argv);
	}

	if (argc > 1) {
		pipe_name = argv[1];
	} else {
		pipe_name = mprToString(mprGetProperty(this, "pipe_name", NULL));
	}

	iface = idl_iface_by_name(pipe_name);
	if (iface == NULL) {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto done;
	}

	credentials = mprGetProperty(this, "credentials", NULL);
	if (credentials) {
		creds = mprGetPtr(credentials, "creds");
	} else {
		creds = cmdline_credentials;
	}
	if (creds == NULL) {
		creds = cli_credentials_init(mprMemCtx());
		cli_credentials_guess(creds);
		cli_credentials_set_anonymous(creds);
	}

	ev = event_context_find(mprMemCtx());

	status = dcerpc_pipe_connect(this, &p, binding, iface, creds, ev);
	if (!NT_STATUS_IS_OK(status)) goto done;

	/* callers don't allocate ref vars in the ejs interface */
	p->conn->flags |= DCERPC_NDR_REF_ALLOC;

	/* by making the pipe a child of the connection variable, it will
	   auto close when it goes out of scope in the script */
	mprSetPtrChild(this, "pipe", p);

done:
	mpr_Return(eid, mprNTSTATUS(status));
	return 0;
}


/*
  make an irpc call - called via the same interface as rpc
*/
static int ejs_irpc_call(int eid, struct MprVar *io, 
			 const struct dcerpc_interface_table *iface, int callnum,
			 ejs_pull_function_t ejs_pull, ejs_push_function_t ejs_push)
{
	NTSTATUS status;
	void *ptr;
	struct ejs_rpc *ejs;
	const struct dcerpc_interface_call *call;
	struct ejs_irpc_connection *p;
	struct irpc_request **reqs;
	int i, count;
	struct MprVar *results;

	p = mprGetThisPtr(eid, "irpc");

	ejs = talloc(mprMemCtx(), struct ejs_rpc);
	if (ejs == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	call = &iface->calls[callnum];

	ejs->eid = eid;
	ejs->callname = call->name;

	/* allocate the C structure */
	ptr = talloc_zero_size(ejs, call->struct_size);
	if (ptr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* convert the mpr object into a C structure */
	status = ejs_pull(ejs, io, ptr);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	for (count=0;p->dest_ids[count].id;count++) /* noop */ ;

	/* we need to make a call per server */
	reqs = talloc_array(ejs, struct irpc_request *, count);
	if (reqs == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* make the actual calls */
	for (i=0;i<count;i++) {
		reqs[i] = irpc_call_send(p->msg_ctx, p->dest_ids[i], 
					 iface, callnum, ptr, ptr);
		if (reqs[i] == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		talloc_steal(reqs, reqs[i]);
	}
	
	mprSetVar(io, "results", mprObject("results"));
	results = mprGetProperty(io, "results", NULL);

	/* and receive the results, placing them in io.results[i] */
	for (i=0;i<count;i++) {
		struct MprVar *output;

		status = irpc_call_recv(reqs[i]);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		status = ejs_push(ejs, io, ptr);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}

		/* add to the results array */
		output = mprGetProperty(io, "output", NULL);
		if (output) {
			char idx[16];
			mprItoa(i, idx, sizeof(idx));
			mprSetProperty(results, idx, output);
			mprDeleteProperty(io, "output");
		}
	}
	mprSetVar(results, "length", mprCreateIntegerVar(i));

done:
	talloc_free(ejs);
	mpr_Return(eid, mprNTSTATUS(status));
	if (NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR)) {
		return -1;
	}
	return 0;
}


/*
  backend code for making an rpc call - this is called from the pidl generated ejs
  code
*/
 int ejs_rpc_call(int eid, int argc, struct MprVar **argv,
		  const struct dcerpc_interface_table *iface, int callnum,
		  ejs_pull_function_t ejs_pull, ejs_push_function_t ejs_push)
{
	struct MprVar *io;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	void *ptr;
	struct rpc_request *req;
	struct ejs_rpc *ejs;
	const struct dcerpc_interface_call *call;

	if (argc != 1 || argv[0]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "rpc_call invalid arguments");
		return -1;
	}
	    
	io       = argv[0];

	if (mprGetThisPtr(eid, "irpc")) {
		/* its an irpc call */
		return ejs_irpc_call(eid, io, iface, callnum, ejs_pull, ejs_push);
	}

	/* get the pipe info */
	p = mprGetThisPtr(eid, "pipe");
	if (p == NULL) {
		ejsSetErrorMsg(eid, "rpc_call invalid pipe");
		return -1;
	}

	ejs = talloc(mprMemCtx(), struct ejs_rpc);
	if (ejs == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	call = &iface->calls[callnum];

	ejs->eid = eid;
	ejs->callname = call->name;

	/* allocate the C structure */
	ptr = talloc_zero_size(ejs, call->struct_size);
	if (ptr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* convert the mpr object into a C structure */
	status = ejs_pull(ejs, io, ptr);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* make the actual call */
	req = dcerpc_ndr_request_send(p, NULL, iface, callnum, ptr, ptr);

	/* if requested, print the structure */
	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		ndr_print_function_debug(call->ndr_print, call->name, NDR_IN, ptr);
	}

	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = dcerpc_ndr_request_recv(req);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* print the 'out' structure, if needed */
	if (p->conn->flags & DCERPC_DEBUG_PRINT_OUT) {
		ndr_print_function_debug(call->ndr_print, call->name, NDR_OUT, ptr);
	}

	status = ejs_push(ejs, io, ptr);

done:
	talloc_free(ejs);
	mpr_Return(eid, mprNTSTATUS(status));
	if (NT_STATUS_EQUAL(status, NT_STATUS_INTERNAL_ERROR)) {
		return -1;
	}
	return 0;
}

/*
  hook called by generated RPC interfaces at the end of their init routines
  used to add generic operations on the pipe
*/
int ejs_rpc_init(struct MprVar *obj, const char *name)
{
	dcerpc_table_init();

	mprSetStringCFunction(obj, "connect", ejs_rpc_connect);
	if (mprGetProperty(obj, "pipe_name", NULL) == NULL) {
		mprSetVar(obj, "pipe_name", mprString(name));
	}
	return 0;
}
