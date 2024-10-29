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
#include "libcli/cldap/cldap.h"
#include "libcli/finddc.h"
#include "libcli/security/security.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/composite/composite.h"
#include "lib/util/util_net.h"
#include "source3/libads/netlogon_ping.h"

struct finddcs_cldap_state {
	struct tevent_context *ev;
	struct tevent_req *req;
	const char *domain_name;
	struct dom_sid *domain_sid;
	const char *srv_name;
	const char **srv_addresses;
	uint32_t minimum_dc_flags;
	enum client_netlogon_ping_protocol proto;
	uint32_t srv_address_index;
	struct netlogon_samlogon_response *response;
	NTSTATUS status;
};

static void finddcs_cldap_srv_resolved(struct composite_context *ctx);
static void finddcs_cldap_netlogon_replied(struct tevent_req *req);
static bool finddcs_cldap_srv_lookup(struct finddcs_cldap_state *state,
				     struct finddcs *io,
				     struct resolve_context *resolve_ctx,
				     struct tevent_context *event_ctx);
static bool finddcs_cldap_nbt_lookup(struct finddcs_cldap_state *state,
				     struct finddcs *io,
				     struct resolve_context *resolve_ctx,
				     struct tevent_context *event_ctx);
static void finddcs_cldap_nbt_resolved(struct composite_context *ctx);
static bool finddcs_cldap_name_lookup(struct finddcs_cldap_state *state,
				      struct finddcs *io,
				      struct resolve_context *resolve_ctx,
				      struct tevent_context *event_ctx);
static void finddcs_cldap_name_resolved(struct composite_context *ctx);
static void finddcs_cldap_next_server(struct finddcs_cldap_state *state);
static bool finddcs_cldap_ipaddress(struct finddcs_cldap_state *state, struct finddcs *io);


/*
 * find a list of DCs via DNS/CLDAP
 */
struct tevent_req *finddcs_cldap_send(TALLOC_CTX *mem_ctx,
				      struct finddcs *io,
				      struct resolve_context *resolve_ctx,
				      struct tevent_context *event_ctx)
{
	struct finddcs_cldap_state *state;
	struct tevent_req *req;

	req = tevent_req_create(mem_ctx, &state, struct finddcs_cldap_state);
	if (req == NULL) {
		return NULL;
	}

	state->req = req;
	state->ev = event_ctx;
	state->minimum_dc_flags = io->in.minimum_dc_flags;
	state->proto = io->in.proto;

	if (io->in.domain_name) {
		state->domain_name = talloc_strdup(state, io->in.domain_name);
		if (tevent_req_nomem(state->domain_name, req)) {
			return tevent_req_post(req, event_ctx);
		}
	} else {
		state->domain_name = NULL;
	}

	if (io->in.domain_sid) {
		state->domain_sid = dom_sid_dup(state, io->in.domain_sid);
		if (tevent_req_nomem(state->domain_sid, req)) {
			return tevent_req_post(req, event_ctx);
		}
	} else {
		state->domain_sid = NULL;
	}

	if (io->in.server_address) {
		if (is_ipaddress(io->in.server_address)) {
			DEBUG(4,("finddcs: searching for a DC by IP %s\n",
				 io->in.server_address));
			if (!finddcs_cldap_ipaddress(state, io)) {
				return tevent_req_post(req, event_ctx);
			}
		} else {
			if (!finddcs_cldap_name_lookup(state, io, resolve_ctx,
						       event_ctx)) {
				return tevent_req_post(req, event_ctx);
			}
		}
	} else if (io->in.domain_name) {
		if (strchr(state->domain_name, '.')) {
			/* looks like a DNS name */
			DEBUG(4,("finddcs: searching for a DC by DNS domain %s\n", state->domain_name));
			if (!finddcs_cldap_srv_lookup(state, io, resolve_ctx,
						      event_ctx)) {
				return tevent_req_post(req, event_ctx);
			}
		} else {
			DEBUG(4,("finddcs: searching for a DC by NBT lookup %s\n", state->domain_name));
			if (!finddcs_cldap_nbt_lookup(state, io, resolve_ctx,
						      event_ctx)) {
				return tevent_req_post(req, event_ctx);
			}
		}
	} else {
		/* either we have the domain name or the IP address */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		DEBUG(2,("finddcs: Please specify at least the domain name or the IP address! \n"));
		return tevent_req_post(req, event_ctx);
	}

	return req;
}


/*
  we've been told the IP of the server, bypass name
  resolution and go straight to CLDAP
*/
static bool finddcs_cldap_ipaddress(struct finddcs_cldap_state *state, struct finddcs *io)
{
	NTSTATUS status;

	state->srv_addresses = talloc_array(state, const char *, 2);
	if (tevent_req_nomem(state->srv_addresses, state->req)) {
		return false;
	}
	state->srv_addresses[0] = talloc_strdup(state->srv_addresses, io->in.server_address);
	if (tevent_req_nomem(state->srv_addresses[0], state->req)) {
		return false;
	}
	state->srv_addresses[1] = NULL;
	state->srv_address_index = 0;

	finddcs_cldap_next_server(state);
	return tevent_req_is_nterror(state->req, &status);
}

/*
  start a SRV DNS lookup
 */
static bool finddcs_cldap_srv_lookup(struct finddcs_cldap_state *state,
				     struct finddcs *io,
				     struct resolve_context *resolve_ctx,
				     struct tevent_context *event_ctx)
{
	struct composite_context *creq;
	struct nbt_name name;

	if (io->in.site_name) {
		state->srv_name = talloc_asprintf(state, "_ldap._tcp.%s._sites.%s",
					   io->in.site_name, io->in.domain_name);
	} else {
		state->srv_name = talloc_asprintf(state, "_ldap._tcp.%s", io->in.domain_name);
	}

	DEBUG(4,("finddcs: looking for SRV records for %s\n", state->srv_name));

	make_nbt_name(&name, state->srv_name, 0);

	creq = resolve_name_ex_send(resolve_ctx, state,
				    RESOLVE_NAME_FLAG_FORCE_DNS | RESOLVE_NAME_FLAG_DNS_SRV,
				    0, &name, event_ctx);
	if (tevent_req_nomem(creq, state->req)) {
		return false;
	}
	creq->async.fn = finddcs_cldap_srv_resolved;
	creq->async.private_data = state;

	return true;
}

/*
  start a NBT name lookup for domain<1C>
 */
static bool finddcs_cldap_nbt_lookup(struct finddcs_cldap_state *state,
				     struct finddcs *io,
				     struct resolve_context *resolve_ctx,
				     struct tevent_context *event_ctx)
{
	struct composite_context *creq;
	struct nbt_name name;

	make_nbt_name(&name, state->domain_name, NBT_NAME_LOGON);
	creq = resolve_name_send(resolve_ctx, state, &name, event_ctx);
	if (tevent_req_nomem(creq, state->req)) {
		return false;
	}
	creq->async.fn = finddcs_cldap_nbt_resolved;
	creq->async.private_data = state;
	return true;
}

static bool finddcs_cldap_name_lookup(struct finddcs_cldap_state *state,
				      struct finddcs *io,
				      struct resolve_context *resolve_ctx,
				      struct tevent_context *event_ctx)
{
	struct composite_context *creq;
	struct nbt_name name;

	make_nbt_name(&name, io->in.server_address, NBT_NAME_SERVER);
	creq = resolve_name_send(resolve_ctx, state, &name, event_ctx);
	if (tevent_req_nomem(creq, state->req)) {
		return false;
	}
	creq->async.fn = finddcs_cldap_name_resolved;
	creq->async.private_data = state;
	return true;
}

/*
  fire off a CLDAP query to the next server
 */
static void finddcs_cldap_next_server(struct finddcs_cldap_state *state)
{
	struct tevent_req *subreq;
	struct tsocket_address **servers = NULL;
	const char *realm = NULL;
	size_t i, num_servers;
	int ret;

	num_servers = str_list_length(state->srv_addresses);

	servers = talloc_array(state, struct tsocket_address *, num_servers);
	if (tevent_req_nomem(servers, state->req)) {
		return;
	}

	for (i = 0; i < num_servers; i++) {
		ret = tsocket_address_inet_from_strings(
			servers,
			"ip",
			state->srv_addresses[i],
			389,
			&servers[i]);
		if (ret == -1) {
			NTSTATUS status = map_nt_error_from_unix_common(errno);
			tevent_req_nterror(state->req, status);
			return;
		}
	}

	if ((state->domain_name != NULL) && (strchr(state->domain_name, '.'))) {
		realm = state->domain_name;
	}

	subreq = netlogon_pings_send(
		state,
		state->ev,
		state->proto,
		servers,
		num_servers,
		(struct netlogon_ping_filter){
			.ntversion = NETLOGON_NT_VERSION_5 |
				     NETLOGON_NT_VERSION_5EX |
				     NETLOGON_NT_VERSION_IP,

			.acct_ctrl = -1,
			.domain = realm,
			.domain_sid = state->domain_sid,
			.required_flags = state->minimum_dc_flags,
		},
		1, /* min_servers */
		tevent_timeval_current_ofs(2, 0));
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
	struct netlogon_samlogon_response **responses = NULL;
	size_t i, num_responses;
	NTSTATUS status;

	state = tevent_req_callback_data(subreq, struct finddcs_cldap_state);

	status = netlogon_pings_recv(subreq, state, &responses);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(state->req, status)) {
		return;
	}

	num_responses = talloc_array_length(responses);

	for (i = 0; i < num_responses; i++) {
		if (responses[i] != NULL) {
			state->srv_address_index = i;
			state->response = responses[i];
		}
	}

	if (state->response == NULL) {
		tevent_req_nterror(state->req,
				   NT_STATUS_OBJECT_NAME_NOT_FOUND);
		return;
	}

	map_netlogon_samlogon_response(state->response);

	DEBUG(4,("finddcs: Found matching DC %s with server_type=0x%08x\n",
		 state->srv_addresses[state->srv_address_index],
		 state->response->data.nt5_ex.server_type));

	tevent_req_done(state->req);
}

static void finddcs_cldap_name_resolved(struct composite_context *ctx)
{
	struct finddcs_cldap_state *state =
		talloc_get_type(ctx->async.private_data, struct finddcs_cldap_state);
	NTSTATUS status;
	unsigned i;

	status = resolve_name_multiple_recv(ctx, state, &state->srv_addresses);
	if (tevent_req_nterror(state->req, status)) {
		DEBUG(2,("finddcs: No matching server found\n"));
		return;
	}

	for (i=0; state->srv_addresses[i]; i++) {
		DEBUG(4,("finddcs: response %u at '%s'\n",
		         i, state->srv_addresses[i]));
	}

	state->srv_address_index = 0;

	state->status = NT_STATUS_OK;
	finddcs_cldap_next_server(state);
}

/*
   handle NBT name lookup reply
 */
static void finddcs_cldap_nbt_resolved(struct composite_context *ctx)
{
	struct finddcs_cldap_state *state =
		talloc_get_type(ctx->async.private_data, struct finddcs_cldap_state);
	NTSTATUS status;
	unsigned i;

	status = resolve_name_multiple_recv(ctx, state, &state->srv_addresses);
	if (tevent_req_nterror(state->req, status)) {
		DEBUG(2,("finddcs: No matching NBT <1c> server found\n"));
		return;
	}

	for (i=0; state->srv_addresses[i]; i++) {
		DEBUG(4,("finddcs: NBT <1c> response %u at '%s'\n",
		         i, state->srv_addresses[i]));
	}

	state->srv_address_index = 0;

	finddcs_cldap_next_server(state);
}


/*
 * Having got a DNS SRV answer, fire off the first CLDAP request
 */
static void finddcs_cldap_srv_resolved(struct composite_context *ctx)
{
	struct finddcs_cldap_state *state =
		talloc_get_type(ctx->async.private_data, struct finddcs_cldap_state);
	NTSTATUS status;
	unsigned i;

	status = resolve_name_multiple_recv(ctx, state, &state->srv_addresses);
	if (tevent_req_nterror(state->req, status)) {
		DEBUG(2,("finddcs: Failed to find SRV record for %s\n", state->srv_name));
		return;
	}

	for (i=0; state->srv_addresses[i]; i++) {
		DEBUG(4,("finddcs: DNS SRV response %u at '%s'\n", i, state->srv_addresses[i]));
	}

	state->srv_address_index = 0;

	state->status = NT_STATUS_OK;
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
	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	io->out.netlogon = talloc_move(mem_ctx, &state->response);
	io->out.address = talloc_steal(
		mem_ctx, state->srv_addresses[state->srv_address_index]);

	tevent_req_received(req);
	return NT_STATUS_OK;
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
