/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_WINS_BYNAME
   Copyright (C) Volker Lendecke 2011

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
#include "librpc/gen_ndr/ndr_wbint_c.h"
#include "libsmb/nmblib.h"
#include "lib/util/string_wrappers.h"

struct winbindd_wins_byname_state {
	struct tevent_context *ev;
	struct winbindd_request *request;
	struct sockaddr_storage *addrs;
	int num_addrs;
};

static void winbindd_wins_byname_wins_done(struct tevent_req *subreq);
static void winbindd_wins_byname_bcast_done(struct tevent_req *subreq);

struct tevent_req *winbindd_wins_byname_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct winbindd_cli_state *cli,
					     struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_wins_byname_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_wins_byname_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->request = request;

	/* Ensure null termination */
	request->data.winsreq[sizeof(request->data.winsreq)-1]='\0';

	DEBUG(3, ("[%5lu]: wins_byname %s\n", (unsigned long)cli->pid,
		  request->data.winsreq));

	subreq = resolve_wins_send(state, ev, state->request->data.winsreq,
				   0x20);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_wins_byname_wins_done, req);
	return req;
}

static void winbindd_wins_byname_wins_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_wins_byname_state *state = tevent_req_data(
		req, struct winbindd_wins_byname_state);
	NTSTATUS status;

	status = resolve_wins_recv(subreq, talloc_tos(), &state->addrs,
				   &state->num_addrs, NULL);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return;
	}
	subreq = name_resolve_bcast_send(state, state->ev,
					 state->request->data.winsreq, 0x20);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, winbindd_wins_byname_bcast_done, req);
}

static void winbindd_wins_byname_bcast_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_wins_byname_state *state = tevent_req_data(
		req, struct winbindd_wins_byname_state);
	NTSTATUS status;

	status = name_resolve_bcast_recv(subreq, talloc_tos(), &state->addrs,
					 &state->num_addrs);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS winbindd_wins_byname_recv(struct tevent_req *req,
				   struct winbindd_response *presp)
{
	struct winbindd_wins_byname_state *state = tevent_req_data(
		req, struct winbindd_wins_byname_state);
	char *response;
	NTSTATUS status;
	int i;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	response = talloc_strdup(talloc_tos(), "");
	if (response == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<state->num_addrs; i++) {
		char addr[INET6_ADDRSTRLEN];
		print_sockaddr(addr, sizeof(addr), &state->addrs[i]);

		response = talloc_asprintf_append_buffer(
			response, "%s%s", addr,
			i < (state->num_addrs-1) ? " " : "");
		if (response == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	response = talloc_asprintf_append_buffer(
		response, "\t%s\n", state->request->data.winsreq);
	if (response == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (talloc_get_size(response) > sizeof(presp->data.winsresp)) {
		TALLOC_FREE(response);
		return NT_STATUS_MARSHALL_OVERFLOW;
	}
	fstrcpy(presp->data.winsresp, response);
	TALLOC_FREE(response);
	return NT_STATUS_OK;
}
