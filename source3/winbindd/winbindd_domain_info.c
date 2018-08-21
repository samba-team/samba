/*
 * Unix SMB/CIFS implementation.
 * async implementation of WINBINDD_DOMAIN_INFO
 * Copyright (C) Volker Lendecke 2018
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

#include "includes.h"
#include "winbindd.h"

struct winbindd_domain_info_state {
	struct winbindd_domain *domain;
	struct winbindd_request ping_request;
};

static void winbindd_domain_info_done(struct tevent_req *subreq);

struct tevent_req *winbindd_domain_info_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct winbindd_cli_state *cli,
	struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_domain_info_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_domain_info_state);
	if (req == NULL) {
		return NULL;
	}

	DEBUG(3, ("[%5lu]: domain_info [%s]\n", (unsigned long)cli->pid,
		  cli->request->domain_name));

	state->domain = find_domain_from_name_noinit(
		cli->request->domain_name);

	if (state->domain == NULL) {
		DEBUG(3, ("Did not find domain [%s]\n",
			  cli->request->domain_name));
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_DOMAIN);
		return tevent_req_post(req, ev);
	}

	if (state->domain->initialized) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	state->ping_request.cmd = WINBINDD_PING;

	/*
	 * Send a ping down. This implicitly initializes the domain.
	 */

	subreq = wb_domain_request_send(state, global_event_context(),
					state->domain, &state->ping_request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_domain_info_done, req);

	return req;
}

static void winbindd_domain_info_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_domain_info_state *state = tevent_req_data(
		req, struct winbindd_domain_info_state);
	struct winbindd_response *response;
	int ret, err;

	ret = wb_domain_request_recv(subreq, state, &response, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		DBG_DEBUG("wb_domain_request failed: %s\n", strerror(err));
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	if (!state->domain->initialized) {
		DBG_INFO("wb_domain_request did not initialize domain %s\n",
			 state->domain->name);
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS winbindd_domain_info_recv(struct tevent_req *req,
				   struct winbindd_response *response)
{
	struct winbindd_domain_info_state *state = tevent_req_data(
		req, struct winbindd_domain_info_state);
	struct winbindd_domain *domain = state->domain;
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DBG_DEBUG("winbindd_domain_info failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	fstrcpy(response->data.domain_info.name, domain->name);
	fstrcpy(response->data.domain_info.alt_name, domain->alt_name);
	sid_to_fstring(response->data.domain_info.sid, &domain->sid);

	response->data.domain_info.native_mode = domain->native_mode;
	response->data.domain_info.active_directory = domain->active_directory;
	response->data.domain_info.primary = domain->primary;

	return NT_STATUS_OK;
}
