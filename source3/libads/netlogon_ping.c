/*
 * Samba Unix/Linux SMB client library
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include <tevent.h>
#include "netlogon_ping.h"
#include "libcli/netlogon/netlogon_proto.h"
#include "libcli/ldap/ldap_ndr.h"
#include "libcli/ldap/ldap_message.h"
#include "libcli/cldap/cldap.h"
#include "source3/include/tldap.h"
#include "source3/include/tldap_util.h"
#include "source3/lib/tldap_tls_connect.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "source4/lib/tls/tls.h"
#include "source3/libads/cldap.h"
#include "librpc/gen_ndr/netlogon.h"

#define RETURN_ON_FALSE(x) \
	if (!(x))          \
		return false;

bool check_cldap_reply_required_flags(uint32_t ret_flags, uint32_t req_flags)
{
	if (req_flags == 0) {
		return true;
	}

	if (req_flags & DS_PDC_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_PDC);

	if (req_flags & DS_GC_SERVER_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_GC);

	if (req_flags & DS_ONLY_LDAP_NEEDED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_LDAP);

	if ((req_flags & DS_DIRECTORY_SERVICE_REQUIRED) ||
	    (req_flags & DS_DIRECTORY_SERVICE_PREFERRED))
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_DS);

	if (req_flags & DS_KDC_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_KDC);

	if (req_flags & DS_TIMESERV_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_TIMESERV);

	if (req_flags & DS_WEB_SERVICE_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_ADS_WEB_SERVICE);

	if (req_flags & DS_WRITABLE_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_WRITABLE);

	if (req_flags & DS_DIRECTORY_SERVICE_6_REQUIRED)
		RETURN_ON_FALSE(ret_flags &
				(NBT_SERVER_SELECT_SECRET_DOMAIN_6 |
				 NBT_SERVER_FULL_SECRET_DOMAIN_6));

	if (req_flags & DS_DIRECTORY_SERVICE_8_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_DS_8);

	if (req_flags & DS_DIRECTORY_SERVICE_9_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_DS_9);

	if (req_flags & DS_DIRECTORY_SERVICE_10_REQUIRED)
		RETURN_ON_FALSE(ret_flags & NBT_SERVER_DS_10);

	return true;
}

struct ldap_netlogon_state {
	struct tevent_context *ev;
	struct tsocket_address *local;
	struct tsocket_address *remote;
	enum client_netlogon_ping_protocol proto;
	const char *filter;

	struct tstream_context *plain;
	struct tldap_context *tldap;
	struct tstream_tls_params *tls_params;

	struct netlogon_samlogon_response *response;
};

static void ldap_netlogon_connected(struct tevent_req *subreq);
static void ldap_netlogon_starttls_done(struct tevent_req *subreq);
static void ldap_netlogon_tls_set_up(struct tevent_req *subreq);
static void ldap_netlogon_search(struct tevent_req *req);
static void ldap_netlogon_searched(struct tevent_req *subreq);

static struct tevent_req *ldap_netlogon_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	const struct tsocket_address *server,
	enum client_netlogon_ping_protocol proto,
	const char *filter)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct ldap_netlogon_state *state = NULL;
	uint16_t port;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct ldap_netlogon_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->filter = filter;
	state->proto = proto;

	state->remote = tsocket_address_copy(server, state);
	if (tevent_req_nomem(state->remote, req)) {
		return tevent_req_post(req, ev);
	}

	port = (proto == CLIENT_NETLOGON_PING_LDAPS) ? 636 : 389;

	ret = tsocket_address_inet_set_port(state->remote, port);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(errno));
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_from_strings(
		state, "ip", NULL, 0, &state->local);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(errno));
		return tevent_req_post(req, ev);
	}

	subreq = tstream_inet_tcp_connect_send(state,
					       state->ev,
					       state->local,
					       state->remote);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ldap_netlogon_connected, req);

	return req;
}

static void ldap_netlogon_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct ldap_netlogon_state *state = tevent_req_data(
		req, struct ldap_netlogon_state);
	int ret, err;
	NTSTATUS status;

	ret = tstream_inet_tcp_connect_recv(
		subreq, &err, state, &state->plain, NULL);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(err));
		return;
	}

	state->tldap = tldap_context_create_from_plain_stream(
		state, &state->plain);
	if (tevent_req_nomem(state->tldap, req)) {
		return;
	}

	if (state->proto == CLIENT_NETLOGON_PING_LDAP) {
		ldap_netlogon_search(req);
		return;
	}

	status = tstream_tls_params_client(state,
					   false,
					   NULL,
					   NULL,
					   NULL,
					   "NORMAL",
					   TLS_VERIFY_PEER_NO_CHECK,
					   NULL,
					   &state->tls_params);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("tstream_tls_params_client(NO_CHECK): %s\n",
			nt_errstr(status));
		return;
	}

	if (state->proto == CLIENT_NETLOGON_PING_STARTTLS) {
		subreq = tldap_extended_send(state,
					     state->ev,
					     state->tldap,
					     LDB_EXTENDED_START_TLS_OID,
					     NULL,
					     NULL,
					     0,
					     NULL,
					     0);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					ldap_netlogon_starttls_done,
					req);
		return;
	}

	subreq = tldap_tls_connect_send(state,
					state->ev,
					state->tldap,
					state->tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ldap_netlogon_tls_set_up, req);
}

static void ldap_netlogon_starttls_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct ldap_netlogon_state *state = tevent_req_data(
		req, struct ldap_netlogon_state);
	TLDAPRC rc;

	rc = tldap_extended_recv(subreq, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		tevent_req_nterror(req, NT_STATUS_LDAP(TLDAP_RC_V(rc)));
		return;
	}

	subreq = tldap_tls_connect_send(state,
					state->ev,
					state->tldap,
					state->tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ldap_netlogon_tls_set_up, req);
}

static void ldap_netlogon_tls_set_up(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	TLDAPRC rc;

	rc = tldap_tls_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		tevent_req_nterror(req, NT_STATUS_LDAP(TLDAP_RC_V(rc)));
		return;
	}

	ldap_netlogon_search(req);
}

static void ldap_netlogon_search(struct tevent_req *req)
{
	struct ldap_netlogon_state *state = tevent_req_data(
		req, struct ldap_netlogon_state);
	static const char *attrs[] = {"netlogon"};
	struct tevent_req *subreq = NULL;

	subreq = tldap_search_all_send(state,
				       state->ev,
				       state->tldap,
				       "",
				       TLDAP_SCOPE_BASE,
				       state->filter,
				       attrs,
				       ARRAY_SIZE(attrs),
				       0,
				       NULL,
				       0,
				       NULL,
				       0,
				       0,
				       0,
				       0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ldap_netlogon_searched, req);
}

static void ldap_netlogon_searched(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct ldap_netlogon_state *state = tevent_req_data(
		req, struct ldap_netlogon_state);
	struct tldap_message **msgs = NULL;
	DATA_BLOB blob = {.data = NULL};
	NTSTATUS status;
	TLDAPRC rc;
	bool ok;

	rc = tldap_search_all_recv(subreq, state, &msgs, NULL);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		tevent_req_nterror(req, NT_STATUS_LDAP(TLDAP_RC_V(rc)));
		return;
	}

	if (talloc_array_length(msgs) != 1) {
		tevent_req_nterror(req,
				   NT_STATUS_LDAP(TLDAP_RC_V(
					   TLDAP_NO_RESULTS_RETURNED)));
		return;
	}

	ok = tldap_get_single_valueblob(msgs[0], "netlogon", &blob);
	if (!ok) {
		tevent_req_nterror(req,
				   NT_STATUS_LDAP(TLDAP_RC_V(
					   TLDAP_NO_RESULTS_RETURNED)));
		return;
	}

	state->response = talloc(state, struct netlogon_samlogon_response);
	if (tevent_req_nomem(state->response, req)) {
		return;
	}

	status = pull_netlogon_samlogon_response(&blob,
						 state->response,
						 state->response);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS ldap_netlogon_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct netlogon_samlogon_response **response)
{
	struct ldap_netlogon_state *state = tevent_req_data(
		req, struct ldap_netlogon_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*response = talloc_move(mem_ctx, &state->response);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct cldap_netlogon_ping_state {
	struct cldap_socket *sock;
	struct cldap_search search;
	struct netlogon_samlogon_response *response;
};

static void cldap_netlogon_ping_done(struct tevent_req *subreq);

static struct tevent_req *cldap_netlogon_ping_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	const struct tsocket_address *server,
	const char *filter)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cldap_netlogon_ping_state *state = NULL;
	struct tsocket_address *server_389 = NULL;
	static const char *const attr[] = {"NetLogon", NULL};
	int ret;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx,
				&state,
				struct cldap_netlogon_ping_state);
	if (req == NULL) {
		return NULL;
	}

	server_389 = tsocket_address_copy(server, state);
	if (tevent_req_nomem(server_389, req)) {
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_inet_set_port(server_389, 389);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(errno));
		return tevent_req_post(req, ev);
	}

	status = cldap_socket_init(state, NULL, server_389, &state->sock);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->search = (struct cldap_search){
		.in.filter = filter,
		.in.attributes = attr,
		.in.timeout = 2,
		.in.retries = 2,
	};

	subreq = cldap_search_send(state, ev, state->sock, &state->search);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cldap_netlogon_ping_done, req);
	return req;
}

static void cldap_netlogon_ping_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct cldap_netlogon_ping_state *state = tevent_req_data(
		req, struct cldap_netlogon_ping_state);
	struct ldap_SearchResEntry *resp = NULL;
	NTSTATUS status;

	status = cldap_search_recv(subreq, state, &state->search);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	TALLOC_FREE(state->sock);

	resp = state->search.out.response;

	if (resp == NULL) {
		tevent_req_nterror(req, NT_STATUS_NOT_FOUND);
		return;
	}

	if (resp->num_attributes != 1 ||
	    !strequal(resp->attributes[0].name, "netlogon") ||
	    resp->attributes[0].num_values != 1 ||
	    resp->attributes[0].values->length < 2)
	{
		tevent_req_nterror(req, NT_STATUS_UNEXPECTED_NETWORK_ERROR);
		return;
	}

	state->response = talloc(state, struct netlogon_samlogon_response);
	if (tevent_req_nomem(state->response, req)) {
		return;
	}

	status = pull_netlogon_samlogon_response(resp->attributes[0].values,
						 state->response,
						 state->response);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS cldap_netlogon_ping_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct netlogon_samlogon_response **response)
{
	struct cldap_netlogon_ping_state *state = tevent_req_data(
		req, struct cldap_netlogon_ping_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*response = talloc_move(mem_ctx, &state->response);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct netlogon_ping_state {
	struct netlogon_samlogon_response *response;
};

static void netlogon_ping_done_cldap(struct tevent_req *subreq);
static void netlogon_ping_done_ldaps(struct tevent_req *subreq);

static struct tevent_req *netlogon_ping_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct tsocket_address *server,
	enum client_netlogon_ping_protocol proto,
	const char *filter,
	struct timeval timeout)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct netlogon_ping_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct netlogon_ping_state);
	if (req == NULL) {
		return NULL;
	}

	switch (proto) {
	case CLIENT_NETLOGON_PING_CLDAP:
		subreq = cldap_netlogon_ping_send(state, ev, server, filter);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, netlogon_ping_done_cldap, req);
		break;
	case CLIENT_NETLOGON_PING_LDAP:
	case CLIENT_NETLOGON_PING_LDAPS:
	case CLIENT_NETLOGON_PING_STARTTLS:
		subreq = ldap_netlogon_send(state, ev, server, proto, filter);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, netlogon_ping_done_ldaps, req);
		break;
	default:
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
		break;
	}

	return req;
}

static void netlogon_ping_done_cldap(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct netlogon_ping_state *state = tevent_req_data(
		req, struct netlogon_ping_state);
	NTSTATUS status;

	status = cldap_netlogon_ping_recv(subreq, state, &state->response);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static void netlogon_ping_done_ldaps(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct netlogon_ping_state *state = tevent_req_data(
		req, struct netlogon_ping_state);
	NTSTATUS status;

	status = ldap_netlogon_recv(subreq, state, &state->response);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS netlogon_ping_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct netlogon_samlogon_response **response)
{
	struct netlogon_ping_state *state = tevent_req_data(
		req, struct netlogon_ping_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*response = talloc_move(mem_ctx, &state->response);
	return NT_STATUS_OK;
}

struct netlogon_pings_state {
	struct tevent_context *ev;

	struct tsocket_address **servers;
	size_t num_servers;
	size_t wanted_servers;
	struct timeval timeout;
	enum client_netlogon_ping_protocol proto;
	uint32_t required_flags;

	char *filter;
	size_t num_sent;
	size_t num_received;
	size_t num_good_received;
	struct tevent_req **reqs;
	struct netlogon_samlogon_response **responses;
};

static void netlogon_pings_next(struct tevent_req *subreq);
static void netlogon_pings_done(struct tevent_req *subreq);

struct tevent_req *netlogon_pings_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       enum client_netlogon_ping_protocol proto,
				       struct tsocket_address **servers,
				       size_t num_servers,
				       struct netlogon_ping_filter filter,
				       size_t wanted_servers,
				       struct timeval timeout)
{
	struct tevent_req *req = NULL;
	struct netlogon_pings_state *state = NULL;
	char *filter_str = NULL;
	size_t i;

	req = tevent_req_create(mem_ctx, &state, struct netlogon_pings_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->proto = proto;
	state->servers = servers;
	state->num_servers = num_servers;
	state->wanted_servers = wanted_servers;
	state->timeout = timeout;
	state->required_flags = filter.required_flags;

	state->reqs = talloc_zero_array(state,
					struct tevent_req *,
					num_servers);
	if (tevent_req_nomem(state->reqs, req)) {
		return tevent_req_post(req, ev);
	}

	state->responses = talloc_zero_array(
		state, struct netlogon_samlogon_response *, num_servers);
	if (tevent_req_nomem(state->responses, req)) {
		return tevent_req_post(req, ev);
	}

	filter_str = talloc_asprintf(state,
				     "(&(NtVer=%s)",
				     ldap_encode_ndr_uint32(state,
							    filter.ntversion));
	if (filter.domain != NULL) {
		talloc_asprintf_addbuf(&filter_str,
				       "(DnsDomain=%s)",
				       filter.domain);
	}
	if (filter.acct_ctrl != -1) {
		talloc_asprintf_addbuf(
			&filter_str,
			"(AAC=%s)",
			ldap_encode_ndr_uint32(mem_ctx, filter.acct_ctrl));
	}
	if (filter.domain_sid != NULL) {
		talloc_asprintf_addbuf(
			&filter_str,
			"(domainSid=%s)",
			ldap_encode_ndr_dom_sid(mem_ctx, filter.domain_sid));
	}
	if (filter.domain_guid != NULL) {
		talloc_asprintf_addbuf(
			&filter_str,
			"(DomainGuid=%s)",
			ldap_encode_ndr_GUID(mem_ctx, filter.domain_guid));
	}
	if (filter.hostname != NULL) {
		talloc_asprintf_addbuf(&filter_str,
				       "(Host=%s)",
				       filter.hostname);
	}
	if (filter.user != NULL) {
		talloc_asprintf_addbuf(&filter_str, "(User=%s)", filter.user);
	}
	talloc_asprintf_addbuf(&filter_str, ")");

	if (tevent_req_nomem(filter_str, req)) {
		return tevent_req_post(req, ev);
	}
	state->filter = filter_str;

	for (i = 0; i < wanted_servers; i++) {
		state->reqs[i] = netlogon_ping_send(state->reqs,
						    state->ev,
						    state->servers[i],
						    state->proto,
						    state->filter,
						    state->timeout);
		if (tevent_req_nomem(state->reqs[i], req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(state->reqs[i],
					netlogon_pings_done,
					req);
	}
	state->num_sent = wanted_servers;
	if (state->num_sent < state->num_servers) {
		/*
		 * After 100 milliseconds fire the next one
		 */
		struct tevent_req *subreq = tevent_wakeup_send(
			state, state->ev, timeval_current_ofs(0, 100000));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, netlogon_pings_next, req);
	}

	return req;
}

static void netlogon_pings_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct netlogon_pings_state *state = tevent_req_data(
		req, struct netlogon_pings_state);
	bool ret;

	ret = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	subreq = netlogon_ping_send(state->reqs,
				    state->ev,
				    state->servers[state->num_sent],
				    state->proto,
				    state->filter,
				    state->timeout);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, netlogon_pings_done, req);
	state->reqs[state->num_sent] = subreq;
	state->num_sent += 1;

	if (state->num_sent < state->num_servers) {
		/*
		 * After 100 milliseconds fire the next one
		 */
		subreq = tevent_wakeup_send(state,
					    state->ev,
					    timeval_current_ofs(0, 100000));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, netlogon_pings_next, req);
	}
}

static void netlogon_pings_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct netlogon_pings_state *state = tevent_req_data(
		req, struct netlogon_pings_state);
	struct netlogon_samlogon_response *response = NULL;
	NTSTATUS status;
	size_t i;

	for (i = 0; i < state->num_sent; i++) {
		if (state->reqs[i] == subreq) {
			break;
		}
	}

	if (i == state->num_sent) {
		/*
		 * Got a response we did not fire...
		 */
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	state->reqs[i] = NULL;

	status = netlogon_ping_recv(subreq, state, &response);
	TALLOC_FREE(subreq);
	state->num_received += 1;

	if (NT_STATUS_IS_OK(status)) {
		enum netlogon_command cmd;
		uint32_t ret_flags;
		bool ok = true;

		switch (response->ntver) {
		case NETLOGON_NT_VERSION_5EX:
			ret_flags = response->data.nt5_ex.server_type;
			cmd = response->data.nt5_ex.command;
			ok &= !(cmd == LOGON_SAM_LOGON_PAUSE_RESPONSE ||
				cmd == LOGON_SAM_LOGON_PAUSE_RESPONSE_EX);
			break;
		case NETLOGON_NT_VERSION_5:
			ret_flags = response->data.nt5.server_type;
			cmd = response->data.nt5.command;
			ok &= !(cmd == LOGON_SAM_LOGON_PAUSE_RESPONSE ||
				cmd == LOGON_SAM_LOGON_PAUSE_RESPONSE_EX);
			break;
		default:
			ret_flags = 0;
			break;
		}

		ok &= check_cldap_reply_required_flags(ret_flags,
						       state->required_flags);
		if (ok) {
			state->responses[i] = talloc_move(state->responses,
							  &response);
			state->num_good_received += 1;
		}
	}

	if (state->num_good_received >= state->wanted_servers) {
		tevent_req_done(req);
		return;
	}
	if (state->num_received < state->num_servers) {
		/*
		 * Wait for more answers
		 */
		return;
	}
	if (state->num_good_received == 1) {
		/* We require at least one DC */
		tevent_req_done(req);
		return;
	}
	/*
	 * Everybody replied, but we did not get a single good
	 * answers (see above)
	 */
	tevent_req_nterror(req, NT_STATUS_NOT_FOUND);
	return;
}

NTSTATUS netlogon_pings_recv(struct tevent_req *req,
			     TALLOC_CTX *mem_ctx,
			     struct netlogon_samlogon_response ***responses)
{
	struct netlogon_pings_state *state = tevent_req_data(
		req, struct netlogon_pings_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*responses = talloc_move(mem_ctx, &state->responses);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS netlogon_pings(TALLOC_CTX *mem_ctx,
			enum client_netlogon_ping_protocol proto,
			struct tsocket_address **servers,
			int num_servers,
			struct netlogon_ping_filter filter,
			int wanted_servers,
			struct timeval timeout,
			struct netlogon_samlogon_response ***responses)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = netlogon_pings_send(frame,
				  ev,
				  proto,
				  servers,
				  num_servers,
				  filter,
				  wanted_servers,
				  timeout);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = netlogon_pings_recv(req, mem_ctx, responses);
 fail:
	TALLOC_FREE(frame);
	return status;
}
