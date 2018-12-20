/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_LIST_USERS
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
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "lib/util/strv.h"

struct winbindd_list_users_domstate {
	struct tevent_req *subreq;
	struct winbindd_domain *domain;
	char *users;
};

struct winbindd_list_users_state {
        size_t num_received;
	/* All domains */
	size_t num_domains;
	struct winbindd_list_users_domstate *domains;
};

static void winbindd_list_users_done(struct tevent_req *subreq);

struct tevent_req *winbindd_list_users_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct winbindd_cli_state *cli,
					    struct winbindd_request *request)
{
	struct tevent_req *req;
	struct winbindd_list_users_state *state;
	struct winbindd_domain *domain;
	size_t i;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_list_users_state);
	if (req == NULL) {
		return NULL;
	}

	if (request->wb_flags & WBFLAG_FROM_NSS && !lp_winbind_enum_users()) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	/* Ensure null termination */
	request->domain_name[sizeof(request->domain_name)-1]='\0';

	DEBUG(3, ("list_users %s\n", request->domain_name));

	if (request->domain_name[0] != '\0') {
		state->num_domains = 1;
	} else {
		state->num_domains = 0;
		for (domain = domain_list(); domain; domain = domain->next) {
			state->num_domains += 1;
		}
	}

	state->domains = talloc_array(state,
				      struct winbindd_list_users_domstate,
				      state->num_domains);
	if (tevent_req_nomem(state->domains, req)) {
		return tevent_req_post(req, ev);
	}

	if (request->domain_name[0] != '\0') {
		state->domains[0].domain = find_domain_from_name_noinit(
			request->domain_name);
		if (state->domains[0].domain == NULL) {
			tevent_req_nterror(req, NT_STATUS_NO_SUCH_DOMAIN);
			return tevent_req_post(req, ev);
		}
	} else {
		i = 0;
		for (domain = domain_list(); domain; domain = domain->next) {
			state->domains[i++].domain = domain;
		}
	}

	for (i=0; i<state->num_domains; i++) {
		struct winbindd_list_users_domstate *d = &state->domains[i];

		d->subreq = wb_query_user_list_send(
			state->domains, ev, d->domain);
		if (tevent_req_nomem(d->subreq, req)) {
			TALLOC_FREE(state->domains);
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(d->subreq, winbindd_list_users_done,
					req);
	}
	state->num_received = 0;
	return req;
}

static void winbindd_list_users_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_list_users_state *state = tevent_req_data(
		req, struct winbindd_list_users_state);
	struct winbindd_list_users_domstate *d;
	NTSTATUS status;
	size_t i;

	for (i=0; i<state->num_domains; i++) {
		if (subreq == state->domains[i].subreq) {
			break;
		}
	}
	if (i == state->num_domains) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	d = &state->domains[i];

	status = wb_query_user_list_recv(subreq, state->domains,
					 &d->users);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Just skip this domain
		 */
		d->users = NULL;
	}

	state->num_received += 1;

	if (state->num_received >= state->num_domains) {
		tevent_req_done(req);
	}
}

NTSTATUS winbindd_list_users_recv(struct tevent_req *req,
				  struct winbindd_response *response)
{
	struct winbindd_list_users_state *state = tevent_req_data(
		req, struct winbindd_list_users_state);
	NTSTATUS status;
	char *result;
	size_t i, len;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	result = NULL;

	for (i=0; i<state->num_domains; i++) {
		struct winbindd_list_users_domstate *d = &state->domains[i];
		int ret;

		if (d->users == NULL) {
			continue;
		}

		ret = strv_append(state, &result, d->users);
		if (ret != 0) {
			return map_nt_error_from_unix(ret);
		}
	}

	len = talloc_get_size(result);

	response->extra_data.data = talloc_steal(response, result);
	response->length += len;
	response->data.num_entries = 0;

	if (result != NULL && len >= 1) {
		len -= 1;
		response->data.num_entries = 1;

		for (i=0; i<len; i++) {
			if (result[i] == '\0') {
				result[i] = ',';
				response->data.num_entries += 1;
			}
		}
	}

	return NT_STATUS_OK;
}
