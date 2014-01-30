/*
 *  Unix SMB/CIFS implementation.
 *
 *  RPC Endpoint Registration
 *
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "ntdomain.h"

#include "../librpc/gen_ndr/ndr_epmapper_c.h"

#include "librpc/rpc/dcerpc_ep.h"
#include "rpc_server/rpc_ep_register.h"

static void rpc_ep_register_loop(struct tevent_req *subreq);
static NTSTATUS rpc_ep_try_register(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev_ctx,
				    struct messaging_context *msg_ctx,
				    const struct ndr_interface_table *iface,
				    const struct dcerpc_binding_vector *v,
				    struct dcerpc_binding_handle **pbh);

struct rpc_ep_register_state {
	struct dcerpc_binding_handle *h;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;

	const struct ndr_interface_table *iface;
	const struct dcerpc_binding_vector *vector;

	uint32_t wait_time;
};

NTSTATUS rpc_ep_register(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 const struct ndr_interface_table *iface,
			 const struct dcerpc_binding_vector *v)
{
	struct rpc_ep_register_state *state;
	struct tevent_req *req;

	state = talloc(ev_ctx, struct rpc_ep_register_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->wait_time = 1;
	state->ev_ctx = ev_ctx;
	state->msg_ctx = msg_ctx;
	state->iface = iface;
	state->vector = dcerpc_binding_vector_dup(state, v);
	if (state->vector == NULL) {
		talloc_free(state);
		return NT_STATUS_NO_MEMORY;
	}

	req = tevent_wakeup_send(state,
				 state->ev_ctx,
				 timeval_current_ofs(1, 0));
	if (req == NULL) {
		talloc_free(state);
		return NT_STATUS_NO_MEMORY;
	}

	tevent_req_set_callback(req, rpc_ep_register_loop, state);

	return NT_STATUS_OK;
}

#define MONITOR_WAIT_TIME 30
static void rpc_ep_monitor_loop(struct tevent_req *subreq);

static void rpc_ep_register_loop(struct tevent_req *subreq)
{
	struct rpc_ep_register_state *state =
		tevent_req_callback_data(subreq, struct rpc_ep_register_state);
	NTSTATUS status;
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		talloc_free(state);
		return;
	}

	status = rpc_ep_try_register(state,
				     state->ev_ctx,
				     state->msg_ctx,
				     state->iface,
				     state->vector,
				     &state->h);
	if (NT_STATUS_IS_OK(status)) {
		/* endpoint registered, monitor the connnection. */
		subreq = tevent_wakeup_send(state,
					    state->ev_ctx,
					    timeval_current_ofs(MONITOR_WAIT_TIME, 0));
		if (subreq == NULL) {
			talloc_free(state);
			return;
		}

		tevent_req_set_callback(subreq, rpc_ep_monitor_loop, state);
		return;
	}

	state->wait_time = state->wait_time * 2;
	if (state->wait_time > 16) {
		DEBUG(0, ("Failed to register endpoint '%s'!\n",
			   state->iface->name));
		state->wait_time = 16;
	}

	subreq = tevent_wakeup_send(state,
				    state->ev_ctx,
				    timeval_current_ofs(state->wait_time, 0));
	if (subreq == NULL) {
		talloc_free(state);
		return;
	}

	tevent_req_set_callback(subreq, rpc_ep_register_loop, state);
	return;
}

static NTSTATUS rpc_ep_try_register(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev_ctx,
				    struct messaging_context *msg_ctx,
				    const struct ndr_interface_table *iface,
				    const struct dcerpc_binding_vector *v,
				    struct dcerpc_binding_handle **pbh)
{
	NTSTATUS status;

	status = dcerpc_ep_register(mem_ctx,
				    msg_ctx,
				    iface,
				    v,
				    &iface->syntax_id.uuid,
				    iface->name,
				    pbh);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return status;
}

/*
 * Monitor the connection to the endpoint mapper and if it goes away, try to
 * register the endpoint.
 */
static void rpc_ep_monitor_loop(struct tevent_req *subreq)
{
	struct rpc_ep_register_state *state =
		tevent_req_callback_data(subreq, struct rpc_ep_register_state);
	struct policy_handle entry_handle;
	struct dcerpc_binding *map_binding;
	struct epm_twr_p_t towers[10];
	struct epm_twr_t *map_tower;
	uint32_t num_towers = 0;
	struct GUID object;
	NTSTATUS status;
	uint32_t result = EPMAPPER_STATUS_CANT_PERFORM_OP;
	TALLOC_CTX *tmp_ctx;
	bool ok;

	ZERO_STRUCT(object);
	ZERO_STRUCT(entry_handle);

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		talloc_free(state);
		return;
	}

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		talloc_free(tmp_ctx);
		talloc_free(state);
		return;
	}

	/* Create map tower */
	status = dcerpc_parse_binding(tmp_ctx, "ncacn_np:", &map_binding);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		talloc_free(state);
		return;
	}

	status = dcerpc_binding_set_abstract_syntax(map_binding,
						&state->iface->syntax_id);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		talloc_free(state);
		return;
	}

	map_tower = talloc_zero(tmp_ctx, struct epm_twr_t);
	if (map_tower == NULL) {
		talloc_free(tmp_ctx);
		talloc_free(state);
		return;
	}

	status = dcerpc_binding_build_tower(map_tower, map_binding,
					    &map_tower->tower);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		talloc_free(state);
		return;
	}

	ok = false;
	status = dcerpc_epm_Map(state->h,
				tmp_ctx,
				&object,
				map_tower,
				&entry_handle,
				10,
				&num_towers,
				towers,
				&result);
	if (NT_STATUS_IS_OK(status)) {
		ok = true;
	}
	if (result == EPMAPPER_STATUS_OK ||
	    result == EPMAPPER_STATUS_NO_MORE_ENTRIES) {
		ok = true;
	}
	if (num_towers == 0) {
		ok = false;
	}

	dcerpc_epm_LookupHandleFree(state->h,
				    tmp_ctx,
				    &entry_handle,
				    &result);
	talloc_free(tmp_ctx);

	subreq = tevent_wakeup_send(state,
				    state->ev_ctx,
				    timeval_current_ofs(MONITOR_WAIT_TIME, 0));
	if (subreq == NULL) {
		talloc_free(state);
		return;
	}

	if (ok) {
		tevent_req_set_callback(subreq, rpc_ep_monitor_loop, state);
	} else {
		TALLOC_FREE(state->h);
		state->wait_time = 1;

		tevent_req_set_callback(subreq, rpc_ep_register_loop, state);
	}

	return;
}
