/*
   Unix SMB/CIFS implementation.
   async implementation of WINBINDD_WINS_BYIP
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

struct winbindd_wins_byip_state {
	struct nmb_name star;
	struct sockaddr_storage addr;
	fstring response;
};

static void winbindd_wins_byip_done(struct tevent_req *subreq);

struct tevent_req *winbindd_wins_byip_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct winbindd_cli_state *cli,
					   struct winbindd_request *request)
{
	struct tevent_req *req, *subreq;
	struct winbindd_wins_byip_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct winbindd_wins_byip_state);
	if (req == NULL) {
		return NULL;
	}

	/* Ensure null termination */
	request->data.winsreq[sizeof(request->data.winsreq)-1]='\0';

	fstr_sprintf(state->response, "%s\t", request->data.winsreq);

	DEBUG(3, ("[%5lu]: wins_byip %s\n", (unsigned long)cli->pid,
		  request->data.winsreq));

	make_nmb_name(&state->star, "*", 0);

	if (!interpret_string_addr(&state->addr, request->data.winsreq,
				   AI_NUMERICHOST)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	subreq = node_status_query_send(state, ev, &state->star,
					&state->addr);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, winbindd_wins_byip_done, req);
	return req;
}

static void winbindd_wins_byip_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct winbindd_wins_byip_state *state = tevent_req_data(
		req, struct winbindd_wins_byip_state);
	struct node_status *names;
	int i, num_names;
	NTSTATUS status;

	status = node_status_query_recv(subreq, talloc_tos(), &names,
					&num_names, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	for (i=0; i<num_names; i++) {
		size_t size;
		/*
		 * ignore group names
		 */
		if (names[i].flags & 0x80) {
			continue;
		}
		/*
		 * Only report 0x20
		 */
		if (names[i].type != 0x20) {
			continue;
		}

		DEBUG(10, ("got name %s\n", names[i].name));

		size = strlen(names[i].name + strlen(state->response));
		if (size > sizeof(state->response) - 1) {
			DEBUG(10, ("To much data\n"));
			tevent_req_nterror(req, STATUS_BUFFER_OVERFLOW);
			return;
		}
		fstrcat(state->response, names[i].name);
		fstrcat(state->response, " ");
	}
	state->response[strlen(state->response)-1] = '\n';

	DEBUG(10, ("response: %s", state->response));

	TALLOC_FREE(names);
	tevent_req_done(req);
}

NTSTATUS winbindd_wins_byip_recv(struct tevent_req *req,
				 struct winbindd_response *presp)
{
	struct winbindd_wins_byip_state *state = tevent_req_data(
		req, struct winbindd_wins_byip_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	fstrcpy(presp->data.winsresp, state->response);
	return NT_STATUS_OK;
}
