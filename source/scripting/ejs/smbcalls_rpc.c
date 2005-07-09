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
#include "lib/ejs/ejs.h"
#include "librpc/gen_ndr/ndr_echo.h"
#include "lib/cmdline/popt_common.h"
#include "scripting/ejs/ejsrpc.h"
#include "dlinklist.h"

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

	status = dcerpc_pipe_connect(mprMemCtx(), &p, binding, 
				     iface->uuid, iface->if_version, 
				     creds, ev);
	if (!NT_STATUS_IS_OK(status)) goto done;

	/* callers don't allocate ref vars in the ejs interface */
	p->conn->flags |= DCERPC_NDR_REF_ALLOC;

	mprSetPtr(conn, "pipe", p);
	mprSetPtr(conn, "iface", iface);

done:
	ejsSetReturnValue(eid, mprNTSTATUS(status));
	return 0;
}


/*
  make an rpc call
     example:
            status = rpc_call(conn, "echo_AddOne", io);
*/
 int ejs_rpc_call(int eid, int argc, struct MprVar **argv,
		  const char *callname,
		  ejs_pull_function_t ejs_pull, ejs_push_function_t ejs_push)
{
	struct MprVar *conn, *io;
	const struct dcerpc_interface_table *iface;
	struct dcerpc_pipe *p;
	const struct dcerpc_interface_call *call;
	NTSTATUS status;
	void *ptr;
	struct rpc_request *req;
	int callnum;

	if (argc != 2 ||
	    argv[0]->type != MPR_TYPE_OBJECT ||
	    argv[1]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "rpc_call invalid arguments");
		return -1;
	}
	    
	conn     = argv[0];
	io       = argv[1];

	/* get the pipe info */
	p = mprGetPtr(conn, "pipe");
	iface = mprGetPtr(conn, "iface");
	if (p == NULL || iface == NULL) {
		ejsSetErrorMsg(eid, "rpc_call invalid pipe");
		return -1;
	}

	/* find the call by name */
	call = dcerpc_iface_find_call(iface, callname);
	if (call == NULL) {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto done;
	}
	callnum = call - iface->calls;

	/* allocate the C structure */
	ptr = talloc_zero_size(mprMemCtx(), call->struct_size);
	if (ptr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* convert the mpr object into a C structure */
	status = ejs_pull_rpc(eid, callname, io, ptr, ejs_pull);
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
		talloc_free(ptr);
		goto done;
	}
	status = dcerpc_ndr_request_recv(req);

	/* print the 'out' structure, if needed */
	if (p->conn->flags & DCERPC_DEBUG_PRINT_OUT) {
		ndr_print_function_debug(call->ndr_print, call->name, NDR_OUT, ptr);
	}

	status = ejs_push_rpc(eid, callname, io, ptr, ejs_push);

	talloc_free(ptr);
done:
	ejsSetReturnValue(eid, mprNTSTATUS(status));
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

	v = mprCreatePtrVar(NULL, "NULL");
	mprSetProperty(ejsGetGlobalObject(eid), "NULL", &v);
}


