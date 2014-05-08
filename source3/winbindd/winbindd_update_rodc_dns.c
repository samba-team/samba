/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_CHANGE_MACHINE_ACCT
   Copyright (C) Volker Lendecke 2009
   Copyright (C) Guenther Deschner 2009

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

struct wb_irpc_DsrUpdateReadOnlyServerDnsRecords_state {
	struct irpc_message *msg;
	struct winbind_DsrUpdateReadOnlyServerDnsRecords *req;
};

static void wb_irpc_DsrUpdateReadOnlyServerDnsRecords_callback(struct tevent_req *subreq);

NTSTATUS wb_irpc_DsrUpdateReadOnlyServerDnsRecords(struct irpc_message *msg,
				 struct winbind_DsrUpdateReadOnlyServerDnsRecords *req)
{
	struct wb_irpc_DsrUpdateReadOnlyServerDnsRecords_state *s;
	struct tevent_req *subreq;
	struct winbindd_domain *domain;

	DEBUG(5, ("wb_irpc_DsrUpdateReadOnlyServerDnsRecords called\n"));

	s = talloc(msg, struct wb_irpc_DsrUpdateReadOnlyServerDnsRecords_state);
	NT_STATUS_HAVE_NO_MEMORY(s);

	s->msg = msg;
	s->req = req;

	domain = find_our_domain();
	if (domain == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	subreq = dcerpc_winbind_DsrUpdateReadOnlyServerDnsRecords_send(s, winbind_event_context(),
								     dom_child_handle(domain),
								     req->in.site_name,
								     req->in.dns_ttl,
								     req->in.dns_names);
	if (!subreq) {
		return NT_STATUS_NO_MEMORY;
	}

	tevent_req_set_callback(subreq,
				wb_irpc_DsrUpdateReadOnlyServerDnsRecords_callback,
				s);

	msg->defer_reply = true;
	return NT_STATUS_OK;
}

static void wb_irpc_DsrUpdateReadOnlyServerDnsRecords_callback(struct tevent_req *subreq)
{
	struct wb_irpc_DsrUpdateReadOnlyServerDnsRecords_state *s =
		tevent_req_callback_data(subreq,
		struct wb_irpc_DsrUpdateReadOnlyServerDnsRecords_state);
	NTSTATUS status, result;

	DEBUG(5, ("wb_irpc_DsrUpdateReadOnlyServerDnsRecords_callback called\n"));

	status = dcerpc_winbind_DsrUpdateReadOnlyServerDnsRecords_recv(subreq, s, &result);
	any_nt_status_not_ok(status, result, &status);
	TALLOC_FREE(subreq);

	irpc_send_reply(s->msg, status);
}
