/*
   Unix SMB/CIFS implementation.

   a composite API for finding a DC and its name via CLDAP

   Copyright (C) Andrew Tridgell 2010
   Copyright (C) Andrew Bartlett 2010

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

#include "include/includes.h"
#include <tevent.h>
#include "libcli/resolve/resolve.h"
#include "lib/messaging/messaging.h"
#include "libcli/libcli.h"
#include "libcli/cldap/cldap.h"
#include "libcli/finddcs.h"
#include "libcli/security/dom_sid.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/composite/composite.h"

struct finddcs_cldap_state {
	struct tevent_context *ev;
	struct tevent_req *req;
	const char *dns_domain_name;
	struct dom_sid *domain_sid;
	const char **srv_addresses;
	uint32_t minimum_dc_flags;
	uint32_t srv_address_index;
	struct cldap_socket *cldap;
	struct cldap_netlogon *netlogon;
};

static void finddcs_cldap_srv_resolved(struct composite_context *ctx);
static void finddcs_cldap_netlogon_replied(struct tevent_req *req);


/*
 * find a list of DCs via DNS/CLDAP
 *
 */
struct tevent_req *finddcs_cldap_send(TALLOC_CTX *mem_ctx,
				      struct finddcs *io,
				      struct resolve_context *resolve_ctx,
				      struct tevent_context *event_ctx)
{
	struct finddcs_cldap_state *state;
	struct tevent_req *req;
	const char *srv_name;
	struct composite_context *creq;
	struct nbt_name name;

	req = tevent_req_create(mem_ctx, &state, struct finddcs_cldap_state);
	if (req == NULL) {
		return NULL;
	}

	state->req = req;
	state->ev = event_ctx;
	state->minimum_dc_flags = io->in.minimum_dc_flags;
	state->dns_domain_name = talloc_strdup(state, io->in.dns_domain_name);
	if (tevent_req_nomem(state->dns_domain_name, req)) {
		return tevent_req_post(req, event_ctx);
	}

	if (io->in.domain_sid) {
		state->domain_sid = dom_sid_dup(state, io->in.domain_sid);
		if (tevent_req_nomem(state->domain_sid, req)) {
			return tevent_req_post(req, event_ctx);
		}
	} else {
		state->domain_sid = NULL;
	}

	/* step1: lookup _ldap._tcp.* */
	if (io->in.site_name) {
		srv_name = talloc_asprintf(state, "_ldap._tcp.%s._sites.%s",
					   io->in.site_name, io->in.dns_domain_name);
	} else {
		srv_name = talloc_asprintf(state, "_ldap._tcp.%s", io->in.dns_domain_name);
	}

	make_nbt_name(&name, srv_name, 0);

	creq = resolve_name_ex_send(resolve_ctx, state,
				    RESOLVE_NAME_FLAG_FORCE_DNS | RESOLVE_NAME_FLAG_DNS_SRV,
				    0, &name, event_ctx);
	if (tevent_req_nomem(creq, req)) {
		return tevent_req_post(req, event_ctx);
	}
	creq->async.fn = finddcs_cldap_srv_resolved;
	creq->async.private_data = state;

	return req;
}


/*
  fire off a CLDAP query to the next server
 */
static void finddcs_cldap_next_server(struct finddcs_cldap_state *state)
{
	struct tevent_req *subreq;

	if (state->srv_addresses[state->srv_address_index] == NULL) {
		tevent_req_nterror(state->req, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		return;
	}

	state->netlogon = talloc_zero(state, struct cldap_netlogon);
	if (tevent_req_nomem(state->netlogon, state->req)) {
		return;
	}

	state->netlogon->in.dest_address = state->srv_addresses[state->srv_address_index];
	/* we should get the port from the SRV response */
	state->netlogon->in.dest_port = 389;
	state->netlogon->in.realm = state->dns_domain_name;
	if (state->domain_sid) {
		state->netlogon->in.domain_sid = dom_sid_string(state, state->domain_sid);
		if (tevent_req_nomem(state->netlogon->in.domain_sid, state->req)) {
			return;
		}
	}
	state->netlogon->in.acct_control = -1;
	state->netlogon->in.version =
		NETLOGON_NT_VERSION_5 |
		NETLOGON_NT_VERSION_5EX |
		NETLOGON_NT_VERSION_IP;
	state->netlogon->in.map_response = true;

	subreq = cldap_netlogon_send(state, state->cldap, state->netlogon);
	if (tevent_req_nomem(subreq, state->req)) {
		return;
	}

	tevent_req_set_callback(subreq, finddcs_cldap_netlogon_replied, state);
}


/*
  we have a response from a CLDAP server for a netlogon request
 */
static void finddcs_cldap_netlogon_replied(struct tevent_req *subreq)
{
	struct finddcs_cldap_state *state;
	NTSTATUS status;

	state = tevent_req_callback_data(subreq, struct finddcs_cldap_state);

	status = cldap_netlogon_recv(subreq, state->netlogon, state->netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		state->srv_address_index++;
		finddcs_cldap_next_server(state);
		return;
	}
	if (state->minimum_dc_flags !=
	    (state->minimum_dc_flags & state->netlogon->out.netlogon.data.nt5_ex.server_type)) {
		/* the server didn't match the minimum requirements */
		DEBUG(4,(__location__ ": Skipping DC %s with server_type=0x%08x\n",
			 state->srv_addresses[state->srv_address_index],
			 state->netlogon->out.netlogon.data.nt5_ex.server_type));
		state->srv_address_index++;
		finddcs_cldap_next_server(state);
		return;
	}

	talloc_free(subreq);
	tevent_req_done(state->req);
}


/*
 * Having got a DNS SRV answer, fire off the first CLDAP request
 */
static void finddcs_cldap_srv_resolved(struct composite_context *ctx)
{
	struct finddcs_cldap_state *state =
		talloc_get_type(ctx->async.private_data, struct finddcs_cldap_state);
	NTSTATUS status;

	status = resolve_name_multiple_recv(ctx, state, &state->srv_addresses);
	if (tevent_req_nterror(state->req, status)) {
		return;
	}

	state->srv_address_index = 0;

	status = cldap_socket_init(state, state->ev, NULL, NULL, &state->cldap);
	if (tevent_req_nterror(state->req, status)) {
		return;
	}

	finddcs_cldap_next_server(state);
}


NTSTATUS finddcs_cldap_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx, struct finddcs *io)
{
	struct finddcs_cldap_state *state = tevent_req_data(req, struct finddcs_cldap_state);
	bool ok;
	NTSTATUS status;

	ok = tevent_req_poll(req, state->ev);
	if (!ok) {
		talloc_free(req);
		return NT_STATUS_INTERNAL_ERROR;
	}
	status = tevent_req_simple_recv_ntstatus(req);
	if (NT_STATUS_IS_OK(status)) {
		talloc_steal(mem_ctx, state->netlogon);
		io->out.netlogon = state->netlogon->out.netlogon;
		io->out.address = talloc_steal(mem_ctx, state->srv_addresses[state->srv_address_index]);
	}
	tevent_req_received(req);
	return status;
}

NTSTATUS finddcs_cldap(TALLOC_CTX *mem_ctx,
		       struct finddcs *io,
		       struct resolve_context *resolve_ctx,
		       struct tevent_context *event_ctx)
{
	NTSTATUS status;
	struct tevent_req *req = finddcs_cldap_send(mem_ctx,
						    io,
						    resolve_ctx,
						    event_ctx);
	status = finddcs_cldap_recv(req, mem_ctx, io);
	talloc_free(req);
	return status;
}
