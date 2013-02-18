/* 
   Samba Unix/Linux SMB client library 
   net ads cldap functions 
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2003 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2008 Guenther Deschner (gd@samba.org)
   Copyright (C) 2009 Stefan Metzmacher (metze@samba.org)

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
#include "../libcli/cldap/cldap.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_ntstatus.h"
#include "libads/cldap.h"

struct cldap_multi_netlogon_state {
	struct tevent_context *ev;
	const struct tsocket_address * const *servers;
	int num_servers;
	const char *domain;
	const char *hostname;
	unsigned ntversion;
	int min_servers;

	struct cldap_socket **cldap;
	struct tevent_req **subreqs;
	int num_sent;
	int num_received;
	int num_good_received;
	struct cldap_netlogon *ios;
	struct netlogon_samlogon_response **responses;
};

static void cldap_multi_netlogon_done(struct tevent_req *subreq);
static void cldap_multi_netlogon_next(struct tevent_req *subreq);

/*
 * Do a parallel cldap ping to the servers. The first "min_servers"
 * are fired directly, the remaining ones in 100msec intervals. If
 * "min_servers" responses came in successfully, we immediately reply,
 * not waiting for the remaining ones.
 */

struct tevent_req *cldap_multi_netlogon_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const struct tsocket_address * const *servers, int num_servers,
	const char *domain, const char *hostname, unsigned ntversion,
	int min_servers)
{
	struct tevent_req *req, *subreq;
	struct cldap_multi_netlogon_state *state;
	int i;

	req = tevent_req_create(mem_ctx, &state,
				struct cldap_multi_netlogon_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->servers = servers;
	state->num_servers = num_servers;
	state->domain = domain;
	state->hostname = hostname;
	state->ntversion = ntversion;
	state->min_servers = min_servers;

	if (min_servers > num_servers) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->subreqs = talloc_zero_array(state,
					   struct tevent_req *,
					   num_servers);
	if (tevent_req_nomem(state->subreqs, req)) {
		return tevent_req_post(req, ev);
	}

	state->cldap = talloc_zero_array(state,
					 struct cldap_socket *,
					 num_servers);
	if (tevent_req_nomem(state->cldap, req)) {
		return tevent_req_post(req, ev);
	}

	state->responses = talloc_zero_array(state,
				struct netlogon_samlogon_response *,
				num_servers);
	if (tevent_req_nomem(state->responses, req)) {
		return tevent_req_post(req, ev);
	}

	state->ios = talloc_zero_array(state->responses,
				       struct cldap_netlogon,
				       num_servers);
	if (tevent_req_nomem(state->ios, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_servers; i++) {
		NTSTATUS status;

		status = cldap_socket_init(state->cldap,
					   NULL, /* local_addr */
					   state->servers[i],
					   &state->cldap[i]);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		state->ios[i].in.dest_address	= NULL;
		state->ios[i].in.dest_port	= 0;
		state->ios[i].in.realm		= domain;
		state->ios[i].in.host		= NULL;
		state->ios[i].in.user		= NULL;
		state->ios[i].in.domain_guid	= NULL;
		state->ios[i].in.domain_sid	= NULL;
		state->ios[i].in.acct_control	= 0;
		state->ios[i].in.version	= ntversion;
		state->ios[i].in.map_response	= false;
	}

	for (i=0; i<min_servers; i++) {
		state->subreqs[i] = cldap_netlogon_send(state->subreqs,
							state->ev,
							state->cldap[i],
							&state->ios[i]);
		if (tevent_req_nomem(state->subreqs[i], req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			state->subreqs[i], cldap_multi_netlogon_done, req);
	}
	state->num_sent = min_servers;

	if (state->num_sent < state->num_servers) {
		/*
		 * After 100 milliseconds fire the next one
		 */
		subreq = tevent_wakeup_send(state, state->ev,
					    timeval_current_ofs(0, 100000));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cldap_multi_netlogon_next,
					req);
	}

	return req;
}

static void cldap_multi_netlogon_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cldap_multi_netlogon_state *state = tevent_req_data(
		req, struct cldap_multi_netlogon_state);
	NTSTATUS status;
	struct netlogon_samlogon_response *response;
	int i;

	for (i=0; i<state->num_sent; i++) {
		if (state->subreqs[i] == subreq) {
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
	state->subreqs[i] = NULL;

	response = talloc_zero(state, struct netlogon_samlogon_response);
	if (tevent_req_nomem(response, req)) {
		return;
	}

	status = cldap_netlogon_recv(subreq, response,
				     &state->ios[i]);
	TALLOC_FREE(subreq);
	state->num_received += 1;

	if (NT_STATUS_IS_OK(status)) {
		*response = state->ios[i].out.netlogon;
		state->responses[i] = talloc_move(state->responses,
						  &response);
		state->num_good_received += 1;
	}

	if ((state->num_received == state->num_servers) ||
	    (state->num_good_received >= state->min_servers)) {
		tevent_req_done(req);
		return;
	}
}

static void cldap_multi_netlogon_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cldap_multi_netlogon_state *state = tevent_req_data(
		req, struct cldap_multi_netlogon_state);
	bool ret;

	ret = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	subreq = cldap_netlogon_send(state->subreqs,
				     state->ev,
				     state->cldap[state->num_sent],
				     &state->ios[state->num_sent]);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cldap_multi_netlogon_done, req);
	state->subreqs[state->num_sent] = subreq;
	state->num_sent += 1;

	if (state->num_sent < state->num_servers) {
		/*
		 * After 100 milliseconds fire the next one
		 */
		subreq = tevent_wakeup_send(state, state->ev,
					    timeval_current_ofs(0, 100000));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, cldap_multi_netlogon_next,
					req);
	}
}

NTSTATUS cldap_multi_netlogon_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx,
	struct netlogon_samlogon_response ***responses)
{
	struct cldap_multi_netlogon_state *state = tevent_req_data(
		req, struct cldap_multi_netlogon_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		return status;
	}
	/*
	 * If we timeout, give back what we have so far
	 */
	*responses = talloc_move(mem_ctx, &state->responses);
	return NT_STATUS_OK;
}

NTSTATUS cldap_multi_netlogon(
	TALLOC_CTX *mem_ctx,
	const struct tsocket_address * const *servers,
	int num_servers,
	const char *domain, const char *hostname, unsigned ntversion,
	int min_servers, struct timeval timeout,
	struct netlogon_samlogon_response ***responses)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = cldap_multi_netlogon_send(
		ev, ev, servers, num_servers, domain, hostname, ntversion,
		min_servers);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_set_endtime(req, ev, timeout)) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cldap_multi_netlogon_recv(req, mem_ctx, responses);
fail:
	TALLOC_FREE(ev);
	return status;
}

/*******************************************************************
  do a cldap netlogon query.  Always 389/udp
*******************************************************************/

bool ads_cldap_netlogon(TALLOC_CTX *mem_ctx,
			struct sockaddr_storage *ss,
			const char *realm,
			uint32_t nt_version,
			struct netlogon_samlogon_response **_reply)
{
	NTSTATUS status;
	char addrstr[INET6_ADDRSTRLEN];
	const char *dest_str;
	struct tsocket_address *dest_addr;
	const struct tsocket_address * const *dest_addrs;
	struct netlogon_samlogon_response **responses = NULL;
	int ret;

	dest_str = print_sockaddr(addrstr, sizeof(addrstr), ss);

	ret = tsocket_address_inet_from_strings(mem_ctx, "ip",
						dest_str, LDAP_PORT,
						&dest_addr);
	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
		DEBUG(2,("Failed to create cldap tsocket_address for %s - %s\n",
			 dest_str, nt_errstr(status)));
		return false;
	}

	dest_addrs = (const struct tsocket_address * const *)&dest_addr;

	status = cldap_multi_netlogon(talloc_tos(),
				dest_addrs, 1,
				realm, NULL,
				nt_version, 1,
				timeval_current_ofs(MAX(3,lp_ldap_timeout()/2), 0),
				&responses);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("ads_cldap_netlogon: cldap_multi_netlogon "
			  "failed: %s\n", nt_errstr(status)));
		return false;
	}
	if (responses[0] == NULL) {
		DEBUG(2, ("ads_cldap_netlogon: did not get a reply\n"));
		TALLOC_FREE(responses);
		return false;
	}
	*_reply = talloc_move(mem_ctx, &responses[0]);

	return true;
}

/*******************************************************************
  do a cldap netlogon query.  Always 389/udp
*******************************************************************/

bool ads_cldap_netlogon_5(TALLOC_CTX *mem_ctx,
			  struct sockaddr_storage *ss,
			  const char *realm,
			  struct NETLOGON_SAM_LOGON_RESPONSE_EX *reply5)
{
	uint32_t nt_version = NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX;
	struct netlogon_samlogon_response *reply = NULL;
	bool ret;

	ret = ads_cldap_netlogon(mem_ctx, ss, realm, nt_version, &reply);
	if (!ret) {
		return false;
	}

	if (reply->ntver != NETLOGON_NT_VERSION_5EX) {
		DEBUG(0,("ads_cldap_netlogon_5: nt_version mismatch: 0x%08x\n",
			reply->ntver));
		return false;
	}

	*reply5 = reply->data.nt5_ex;

	return true;
}
