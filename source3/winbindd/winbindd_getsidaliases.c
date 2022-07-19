/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_GETSIDALIASES
   Copyright (C) Volker Lendecke 2009

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
#include "../libcli/security/security.h"

struct winbindd_getsidaliases_state {
	struct dom_sid sid;
	uint32_t num_aliases;
	uint32_t *aliases;
};

static void winbindd_getsidaliases_done(struct tevent_req *subreq);

struct tevent_req *winbindd_getsidaliases_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct winbindd_cli_state *cli,
					       struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_getsidaliases_state *state;
	struct winbindd_domain *domain;
	uint32_t num_sids, i;
	struct dom_sid *sids;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_getsidaliases_state);
	if (req == NULL) {
		return NULL;
	}

	/* Ensure null termination */
	request->data.sid[sizeof(request->data.sid)-1]='\0';

	if (!string_to_sid(&state->sid, request->data.sid)) {
		D_WARNING("Could not get convert sid %s from string\n",
			  request->data.sid);
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	domain = find_domain_from_sid_noinit(&state->sid);
	if (domain == NULL) {
		D_WARNING("could not find domain entry for sid %s\n",
			 request->data.sid);
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_DOMAIN);
		return tevent_req_post(req, ev);
	}

	num_sids = 0;
	sids = NULL;

	if (request->extra_data.data != NULL) {
		if (request->extra_data.data[request->extra_len-1] != '\0') {
			D_WARNING("Got non-NULL terminated sidlist\n");
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		if (!parse_sidlist(state, request->extra_data.data,
				   &sids, &num_sids)) {
			D_WARNING("Could not parse SID list: %s\n",
				  request->extra_data.data);
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
	}

	D_NOTICE("[%s (%u)] Winbind external command GETSIDALIASES start.\n"
		 "sid=%s\n",
		 cli->client_name,
		 (unsigned int)cli->pid,
		 request->data.sid);
	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		for (i = 0; i < num_sids; i++) {
			struct dom_sid_buf sidstr;
			D_NOTICE("%"PRIu32": %s\n",
				 i, dom_sid_str_buf(&sids[i], &sidstr));
		}
	}

	subreq = wb_lookupuseraliases_send(state, ev, domain, num_sids, sids);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_getsidaliases_done, req);
	return req;
}

static void winbindd_getsidaliases_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_getsidaliases_state *state = tevent_req_data(
		req, struct winbindd_getsidaliases_state);
	NTSTATUS status;

	status = wb_lookupuseraliases_recv(subreq, state, &state->num_aliases,
					   &state->aliases);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS winbindd_getsidaliases_recv(struct tevent_req *req,
				     struct winbindd_response *response)
{
	struct winbindd_getsidaliases_state *state = tevent_req_data(
		req, struct winbindd_getsidaliases_state);
	NTSTATUS status;
	uint32_t i;
	char *sidlist;

	if (tevent_req_is_nterror(req, &status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		return status;
	}

	sidlist = talloc_strdup(response, "");

	D_NOTICE("Winbind external command GETSIDALIASES end.\n"
		 "Received %"PRIu32" alias(es).\n",
		 state->num_aliases);
	for (i=0; i<state->num_aliases; i++) {
		struct dom_sid sid;
		struct dom_sid_buf tmp;
		sid_compose(&sid, &state->sid, state->aliases[i]);

		talloc_asprintf_addbuf(
			&sidlist, "%s\n", dom_sid_str_buf(&sid, &tmp));
		D_NOTICE("%"PRIu32": %s\n", i, dom_sid_str_buf(&sid, &tmp));
	}

	if (sidlist == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	response->extra_data.data = sidlist;
	response->length += talloc_get_size(sidlist);
	response->data.num_entries = state->num_aliases;
	return NT_STATUS_OK;
}
