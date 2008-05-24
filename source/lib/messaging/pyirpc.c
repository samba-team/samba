/* 
   Unix SMB/CIFS implementation.
   Copyright © Jelmer Vernooij <jelmer@samba.org> 2008

   Based on the equivalent for EJS:
   Copyright © Andrew Tridgell <tridge@samba.org> 2005
   
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
#include <Python.h>
#include "lib/messaging/irpc.h"

/*
  messaging clients need server IDs as well ...
 */
#define EJS_ID_BASE 0x30000000

/*
  state of a irpc 'connection'
*/
struct ejs_irpc_connection {
	const char *server_name;
	struct server_id *dest_ids;
	struct messaging_context *msg_ctx;
};

/*
  setup a context for talking to a irpc server
     example: 
        status = irpc.connect("smb_server");
*/

PyObject *py_irpc_connect(PyObject *args, PyObjet *kwargs)
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

	ev = mprEventCtx();

	/* create a messaging context, looping as we have no way to
	   allocate temporary server ids automatically */
	for (i=0;i<10000;i++) {
		p->msg_ctx = messaging_init(p, 
					    lp_messaging_path(p, mprLpCtx()),
					    cluster_id(EJS_ID_BASE, i), 
				            lp_iconv_convenience(mprLpCtx()),
					    ev);
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
  make an irpc call - called via the same interface as rpc
*/
static int ejs_irpc_call(int eid, struct MprVar *io, 
			 const struct ndr_interface_table *iface, int callnum,
			 ejs_pull_function_t ejs_pull, ejs_push_function_t ejs_push)
{
	NTSTATUS status;
	void *ptr;
	struct ejs_rpc *ejs;
	const struct ndr_interface_call *call;
	struct ejs_irpc_connection *p;
	struct irpc_request **reqs;
	int i, count;
	struct MprVar *results;

	p = (struct ejs_irpc_connection *)mprGetThisPtr(eid, "irpc");

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



static void initirpc(void)
{

}
