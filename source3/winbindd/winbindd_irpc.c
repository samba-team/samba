/*
   Unix SMB/CIFS implementation.
   async implementation of commands submitted over IRPC
   Copyright (C) Volker Lendecke 2009
   Copyright (C) Guenther Deschner 2009
   Copyright (C) Andrew Bartlett 2014
   Copyright (C) Andrew Tridgell 2009

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
#include "winbindd.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "source4/lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winbind.h"

struct wb_irpc_forward_state {
	struct irpc_message *msg;
	struct winbind_DsrUpdateReadOnlyServerDnsRecords *req;

	const char *opname;
	struct dcesrv_call_state *dce_call;
};

/*
  called when the forwarded rpc request is finished
 */
static void wb_irpc_forward_callback(struct tevent_req *subreq)
{
	struct wb_irpc_forward_state *st =
		tevent_req_callback_data(subreq,
		struct wb_irpc_forward_state);
	const char *opname = st->opname;
	NTSTATUS status;

	status = dcerpc_binding_handle_call_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("RPC callback failed for %s - %s\n",
			 opname, nt_errstr(status)));
		irpc_send_reply(st->msg, status);
		return;
	}

	irpc_send_reply(st->msg, status);
}



/**
 * Forward a RPC call using IRPC to another task
 */

static NTSTATUS wb_irpc_forward_rpc_call(struct irpc_message *msg, TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 void *r, uint32_t callid,
					 const char *opname,
					 struct winbindd_domain *domain,
					 uint32_t timeout)
{
	struct wb_irpc_forward_state *st;
	struct dcerpc_binding_handle *binding_handle;
	struct tevent_req *subreq;

	st = talloc(mem_ctx, struct wb_irpc_forward_state);
	if (st == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	st->msg = msg;
	st->opname   = opname;

	binding_handle =  dom_child_handle(domain);
	if (binding_handle == NULL) {
		DEBUG(0,("%s: Failed to forward request to winbind handler for %s\n",
			 opname, domain->name));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* reset timeout for the handle */
	dcerpc_binding_handle_set_timeout(binding_handle, timeout);

	/* forward the call */
	subreq = dcerpc_binding_handle_call_send(st, ev,
						 binding_handle,
						 NULL, &ndr_table_winbind,
						 callid,
						 msg, r);
	if (subreq == NULL) {
		DEBUG(0,("%s: Failed to forward request to winbind handler for %s\n",
			 opname, domain->name));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* mark the request as replied async */
	msg->defer_reply = true;

	/* setup the callback */
	tevent_req_set_callback(subreq, wb_irpc_forward_callback, st);
	return NT_STATUS_OK;
}

static NTSTATUS wb_irpc_DsrUpdateReadOnlyServerDnsRecords(struct irpc_message *msg,
						   struct winbind_DsrUpdateReadOnlyServerDnsRecords *req)
{
	struct winbindd_domain *domain = find_our_domain();
	if (domain == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	DEBUG(5, ("wb_irpc_DsrUpdateReadOnlyServerDnsRecords called\n"));

	return wb_irpc_forward_rpc_call(msg, msg,
					winbind_event_context(),
					req, NDR_WINBIND_DSRUPDATEREADONLYSERVERDNSRECORDS,
					"winbind_DsrUpdateReadOnlyServerDnsRecords",
					domain, IRPC_CALL_TIMEOUT);
}

static NTSTATUS wb_irpc_SamLogon(struct irpc_message *msg,
				 struct winbind_SamLogon *req)
{
	struct winbindd_domain *domain;
	const char *target_domain_name;
	if (req->in.logon.network == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}
	target_domain_name = req->in.logon.network->identity_info.domain_name.string;

	domain = find_auth_domain(0, target_domain_name);
	if (domain == NULL) {
		return NT_STATUS_NO_SUCH_USER;
	}

	DEBUG(5, ("wb_irpc_SamLogon called\n"));

	return wb_irpc_forward_rpc_call(msg, msg,
					winbind_event_context(),
					req, NDR_WINBIND_SAMLOGON,
					"winbind_SamLogon",
					domain, IRPC_CALL_TIMEOUT);
}

NTSTATUS wb_irpc_register(void)
{
	NTSTATUS status;
	status = IRPC_REGISTER(winbind_imessaging_context(), winbind, WINBIND_DSRUPDATEREADONLYSERVERDNSRECORDS,
			       wb_irpc_DsrUpdateReadOnlyServerDnsRecords, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = IRPC_REGISTER(winbind_imessaging_context(), winbind, WINBIND_SAMLOGON,
			       wb_irpc_SamLogon, NULL);
	return status;
}
