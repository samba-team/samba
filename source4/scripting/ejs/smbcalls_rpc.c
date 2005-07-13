/* 
   Unix SMB/CIFS implementation.

   provide interfaces to rpc calls from ejs scripts

   Copyright (C) Andrew Tridgell 2005
   
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
#include "scripting/ejs/smbcalls.h"
#include "lib/appweb/ejs/ejs.h"
#include "librpc/gen_ndr/ndr_echo.h"
#include "lib/cmdline/popt_common.h"
#include "lib/messaging/irpc.h"
#include "scripting/ejs/ejsrpc.h"
#include "dlinklist.h"

/*
  state of a irpc 'connection'
*/
struct ejs_irpc_connection {
	const char *server_name;
	uint32_t *dest_ids;
	struct messaging_context *msg_ctx;
};

/*
  messaging clients need server IDs as well ...
 */
#define EJS_ID_BASE 0x30000000

/*
  setup a context for talking to a irpc server
     example: 
        var conn = new Object();
        status = irpc_connect(conn, "smb_server");
*/
static int ejs_irpc_connect(MprVarHandle eid, int argc, struct MprVar **argv)
{
	NTSTATUS status;
	int i;
	struct MprVar *conn;
	struct event_context *ev;
	struct ejs_irpc_connection *p;

	/* validate arguments */
	if (argc != 2 ||
	    argv[0]->type != MPR_TYPE_OBJECT ||
	    argv[1]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "rpc_connect invalid arguments");
		return -1;
	}

	conn           = argv[0];

	p = talloc(conn, struct ejs_irpc_connection);
	if (p == NULL) {
		return -1;
	}

	p->server_name = mprToString(argv[1]);

	ev = talloc_find_parent_bytype(mprMemCtx(), struct event_context);

	/* create a messaging context, looping as we have no way to
	   allocate temporary server ids automatically */
	for (i=0;i<10000;i++) {
		p->msg_ctx = messaging_init(p, EJS_ID_BASE + i, ev);
		if (p->msg_ctx) break;
	}
	if (p->msg_ctx == NULL) {
		ejsSetErrorMsg(eid, "irpc_connect unable to create a messaging context");
		talloc_free(p);
		return -1;
	}

	p->dest_ids = irpc_servers_byname(p->msg_ctx, p->server_name);
	if (p->dest_ids == NULL || p->dest_ids[0] == 0) {
		talloc_free(p);
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	} else {
		mprSetPtrChild(conn, "irpc", p);
		status = NT_STATUS_OK;
	}

	mpr_Return(eid, mprNTSTATUS(status));
	return 0;
}


/*
  connect to an rpc server
     example: 
        var conn = new Object();
        status = rpc_connect(conn, "ncacn_ip_tcp:localhost", "rpcecho");
*/
static int ejs_rpc_connect(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const char *binding, *pipe_name;
	const struct dcerpc_interface_table *iface;
	NTSTATUS status;
	struct dcerpc_pipe *p;
	struct MprVar *conn;
	struct cli_credentials *creds = cmdline_credentials;
	struct event_context *ev;

	/* validate arguments */
	if (argc != 3 ||
	    argv[0]->type != MPR_TYPE_OBJECT ||
	    argv[1]->type != MPR_TYPE_STRING ||
	    argv[2]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "rpc_connect invalid arguments");
		return -1;
	}

	conn       = argv[0];
	binding    = mprToString(argv[1]);
	pipe_name  = mprToString(argv[2]);

	iface = idl_iface_by_name(pipe_name);
	if (iface == NULL) {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto done;
	}

	if (creds == NULL) {
		creds = cli_credentials_init(mprMemCtx());
		cli_credentials_guess(creds);
		cli_credentials_set_username(creds, "", CRED_GUESSED);
		cli_credentials_set_password(creds, "", CRED_GUESSED);
	}

	ev = talloc_find_parent_bytype(mprMemCtx(), struct event_context);

	status = dcerpc_pipe_connect(conn, &p, binding, 
				     iface->uuid, iface->if_version, 
				     creds, ev);
	if (!NT_STATUS_IS_OK(status)) goto done;

	/* callers don't allocate ref vars in the ejs interface */
	p->conn->flags |= DCERPC_NDR_REF_ALLOC;

	/* by making the pipe a child of the connection variable, it will
	   auto close when it goes out of scope in the script */
	mprSetPtrChild(conn, "pipe", p);
	mprSetPtr(conn, "iface", iface);

done:
	mpr_Return(eid, mprNTSTATUS(status));
	return 0;
}


/*
  make an irpc call - called via the same interface as rpc
*/
static int ejs_irpc_call(int eid, struct MprVar *conn, struct MprVar *io, 
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

	p = mprGetPtr(conn, "irpc");

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

	for (count=0;p->dest_ids[count];count++) /* noop */ ;

	/* we need to make a call per server */
	reqs = talloc_array(ejs, struct irpc_request *, count);
	if (reqs == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* make the actual calls */
	for (i=0;i<count;i++) {
		reqs[i] = irpc_call_send(p->msg_ctx, p->dest_ids[i], 
					 iface, callnum, ptr);
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
		talloc_free(reqs[i]);

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
	struct MprVar *conn, *io;
	struct dcerpc_pipe *p;
	NTSTATUS status;
	void *ptr;
	struct rpc_request *req;
	struct ejs_rpc *ejs;
	const struct dcerpc_interface_call *call;

	if (argc != 2 ||
	    argv[0]->type != MPR_TYPE_OBJECT ||
	    argv[1]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "rpc_call invalid arguments");
		return -1;
	}
	    
	conn     = argv[0];
	io       = argv[1];

	if (mprGetPtr(conn, "irpc")) {
		/* its an irpc call */
		return ejs_irpc_call(eid, conn, io, iface, callnum, ejs_pull, ejs_push);
	}

	/* get the pipe info */
	p = mprGetPtr(conn, "pipe");
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

	/* if requested, print the structure */
	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		ndr_print_function_debug(call->ndr_print, call->name, NDR_IN, ptr);
	}

	/* make the actual call */
	req = dcerpc_ndr_request_send(p, NULL, iface, callnum, ptr, ptr);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	status = dcerpc_ndr_request_recv(req);

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


/* a list of registered ejs rpc modules */
static struct ejs_register {
	struct ejs_register *next, *prev;
	const char *name;
	ejs_setup_t setup;
	ejs_constants_t constants;
} *ejs_registered;

/*
  register a generated ejs module
*/
 NTSTATUS smbcalls_register_ejs(const char *name, 
				ejs_setup_t setup,
				ejs_constants_t constants)
{
	struct ejs_register *r;
	void *ctx = ejs_registered;
	if (ctx == NULL) {
		ctx = talloc_autofree_context();
	}
	r = talloc(ctx, struct ejs_register);
	NT_STATUS_HAVE_NO_MEMORY(r);
	r->name = name;
	r->setup = setup;
	r->constants = constants;
	DLIST_ADD(ejs_registered, r);
	return NT_STATUS_OK;
}

/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_rpc(void)
{
	struct ejs_register *r;

	ejsDefineCFunction(-1, "rpc_connect", ejs_rpc_connect, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "irpc_connect", ejs_irpc_connect, NULL, MPR_VAR_SCRIPT_HANDLE);
	for (r=ejs_registered;r;r=r->next) {
		r->setup();
	}
}

/*
  setup constants for rpc calls
*/
void smb_setup_ejs_rpc_constants(int eid)
{
	struct ejs_register *r;
	struct MprVar v;

	for (r=ejs_registered;r;r=r->next) {
		r->constants(eid);
	}

	v = mprCreatePtrVar(NULL);
	mprSetProperty(ejsGetGlobalObject(eid), "NULL", &v);
}


