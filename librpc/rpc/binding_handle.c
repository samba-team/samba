/*
   Unix SMB/CIFS implementation.

   dcerpc binding handle functions

   Copyright (C) Stefan Metzmacher 2010

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
#include <tevent.h>
#include "../lib/util/tevent_ntstatus.h"
#include "librpc/rpc/dcerpc.h"
#include "rpc_common.h"

struct dcerpc_binding_handle {
	void *private_data;
	const struct dcerpc_binding_handle_ops *ops;
	const char *location;
	const struct GUID *object;
	const struct ndr_interface_table *table;
	struct tevent_context *sync_ev;
};

static int dcerpc_binding_handle_destructor(struct dcerpc_binding_handle *b)
{
	return 0;
}

struct dcerpc_binding_handle *_dcerpc_binding_handle_create(TALLOC_CTX *mem_ctx,
					const struct dcerpc_binding_handle_ops *ops,
					const struct GUID *object,
					const struct ndr_interface_table *table,
					void *pstate,
					size_t psize,
					const char *type,
					const char *location)
{
	struct dcerpc_binding_handle *h;
	void **ppstate = (void **)pstate;
	void *state;

	h = talloc_zero(mem_ctx, struct dcerpc_binding_handle);
	if (h == NULL) {
		return NULL;
	}
	h->ops		= ops;
	h->location	= location;
	h->object	= object;
	h->table	= table;

	state = talloc_zero_size(h, psize);
	if (state == NULL) {
		talloc_free(h);
		return NULL;
	}
	talloc_set_name_const(state, type);

	h->private_data = state;

	talloc_set_destructor(h, dcerpc_binding_handle_destructor);

	*ppstate = state;
	return h;
}

void *_dcerpc_binding_handle_data(struct dcerpc_binding_handle *h)
{
	return h->private_data;
}

void dcerpc_binding_handle_set_sync_ev(struct dcerpc_binding_handle *h,
				       struct tevent_context *ev)
{
	h->sync_ev = ev;
}

bool dcerpc_binding_handle_is_connected(struct dcerpc_binding_handle *h)
{
	return h->ops->is_connected(h);
}

uint32_t dcerpc_binding_handle_set_timeout(struct dcerpc_binding_handle *h,
					   uint32_t timeout)
{
	return h->ops->set_timeout(h, timeout);
}

void dcerpc_binding_handle_auth_info(struct dcerpc_binding_handle *h,
				     enum dcerpc_AuthType *auth_type,
				     enum dcerpc_AuthLevel *auth_level)
{
	enum dcerpc_AuthType _auth_type;
	enum dcerpc_AuthLevel _auth_level;

	if (auth_type == NULL) {
		auth_type = &_auth_type;
	}

	if (auth_level == NULL) {
		auth_level = &_auth_level;
	}

	*auth_type = DCERPC_AUTH_TYPE_NONE;
	*auth_level = DCERPC_AUTH_LEVEL_NONE;

	if (h->ops->auth_info == NULL) {
		return;
	}

	h->ops->auth_info(h, auth_type, auth_level);
}

struct dcerpc_binding_handle_raw_call_state {
	const struct dcerpc_binding_handle_ops *ops;
	uint8_t *out_data;
	size_t out_length;
	uint32_t out_flags;
};

static void dcerpc_binding_handle_raw_call_done(struct tevent_req *subreq);

struct tevent_req *dcerpc_binding_handle_raw_call_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h,
						const struct GUID *object,
						uint32_t opnum,
						uint32_t in_flags,
						const uint8_t *in_data,
						size_t in_length)
{
	struct tevent_req *req;
	struct dcerpc_binding_handle_raw_call_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct dcerpc_binding_handle_raw_call_state);
	if (req == NULL) {
		return NULL;
	}
	state->ops = h->ops;
	state->out_data = NULL;
	state->out_length = 0;
	state->out_flags = 0;

	if (h->object != NULL) {
		/*
		 * If an object is set on the binding handle,
		 * per request object passing is not allowed.
		 */
		if (object != NULL) {
			tevent_req_nterror(req, NT_STATUS_INVALID_HANDLE);
			return tevent_req_post(req, ev);
		}

		/*
		 * We use the object from the binding handle
		 */
		object = h->object;
	}

	subreq = state->ops->raw_call_send(state, ev, h,
					   object, opnum,
					   in_flags, in_data, in_length);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dcerpc_binding_handle_raw_call_done, req);

	return req;
}

static void dcerpc_binding_handle_raw_call_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct dcerpc_binding_handle_raw_call_state *state =
		tevent_req_data(req,
		struct dcerpc_binding_handle_raw_call_state);
	NTSTATUS error;

	error = state->ops->raw_call_recv(subreq, state,
					  &state->out_data,
					  &state->out_length,
					  &state->out_flags);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, error)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS dcerpc_binding_handle_raw_call_recv(struct tevent_req *req,
					     TALLOC_CTX *mem_ctx,
					     uint8_t **out_data,
					     size_t *out_length,
					     uint32_t *out_flags)
{
	struct dcerpc_binding_handle_raw_call_state *state =
		tevent_req_data(req,
		struct dcerpc_binding_handle_raw_call_state);
	NTSTATUS error;

	if (tevent_req_is_nterror(req, &error)) {
		tevent_req_received(req);
		return error;
	}

	*out_data = talloc_move(mem_ctx, &state->out_data);
	*out_length = state->out_length;
	*out_flags = state->out_flags;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS dcerpc_binding_handle_raw_call(struct dcerpc_binding_handle *h,
					const struct GUID *object,
					uint32_t opnum,
					uint32_t in_flags,
					const uint8_t *in_data,
					size_t in_length,
					TALLOC_CTX *mem_ctx,
					uint8_t **out_data,
					size_t *out_length,
					uint32_t *out_flags)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *subreq;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	/*
	 * TODO: allow only one sync call
	 */

	if (h->sync_ev) {
		ev = h->sync_ev;
	} else {
		ev = samba_tevent_context_init(frame);
	}
	if (ev == NULL) {
		goto fail;
	}

	subreq = dcerpc_binding_handle_raw_call_send(frame, ev,
						     h, object, opnum,
						     in_flags,
						     in_data,
						     in_length);
	if (subreq == NULL) {
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(subreq, ev, &status)) {
		goto fail;
	}

	status = dcerpc_binding_handle_raw_call_recv(subreq,
						     mem_ctx,
						     out_data,
						     out_length,
						     out_flags);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct dcerpc_binding_handle_disconnect_state {
	const struct dcerpc_binding_handle_ops *ops;
};

static void dcerpc_binding_handle_disconnect_done(struct tevent_req *subreq);

struct tevent_req *dcerpc_binding_handle_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h)
{
	struct tevent_req *req;
	struct dcerpc_binding_handle_disconnect_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct dcerpc_binding_handle_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	state->ops = h->ops;

	subreq = state->ops->disconnect_send(state, ev, h);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dcerpc_binding_handle_disconnect_done, req);

	return req;
}

static void dcerpc_binding_handle_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct dcerpc_binding_handle_disconnect_state *state =
		tevent_req_data(req,
		struct dcerpc_binding_handle_disconnect_state);
	NTSTATUS error;

	error = state->ops->disconnect_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, error)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS dcerpc_binding_handle_disconnect_recv(struct tevent_req *req)
{
	NTSTATUS error;

	if (tevent_req_is_nterror(req, &error)) {
		tevent_req_received(req);
		return error;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct dcerpc_binding_handle_call_state {
	struct dcerpc_binding_handle *h;
	const struct ndr_interface_call *call;
	TALLOC_CTX *r_mem;
	void *r_ptr;
	struct ndr_push *push;
	DATA_BLOB request;
	DATA_BLOB response;
	struct ndr_pull *pull;
};

static void dcerpc_binding_handle_call_done(struct tevent_req *subreq);

struct tevent_req *dcerpc_binding_handle_call_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct dcerpc_binding_handle *h,
					const struct GUID *object,
					const struct ndr_interface_table *table,
					uint32_t opnum,
					TALLOC_CTX *r_mem,
					void *r_ptr)
{
	struct tevent_req *req;
	struct dcerpc_binding_handle_call_state *state;
	struct tevent_req *subreq;
	enum ndr_err_code ndr_err;

	req = tevent_req_create(mem_ctx, &state,
				struct dcerpc_binding_handle_call_state);
	if (req == NULL) {
		return NULL;
	}

	if (table != h->table) {
		tevent_req_nterror(req, NT_STATUS_INVALID_HANDLE);
		return tevent_req_post(req, ev);
	}

	if (opnum >= table->num_calls) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	state->h = h;
	state->call = &table->calls[opnum];

	state->r_mem = r_mem;
	state->r_ptr = r_ptr;

	/* setup for a ndr_push_* call */
	state->push = ndr_push_init_ctx(state);
	if (tevent_req_nomem(state->push, req)) {
		return tevent_req_post(req, ev);
	}

	if (h->ops->ref_alloc && h->ops->ref_alloc(h)) {
		state->push->flags |= LIBNDR_FLAG_REF_ALLOC;
	}

	if (h->ops->push_bigendian && h->ops->push_bigendian(h)) {
		state->push->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	if (h->ops->use_ndr64 && h->ops->use_ndr64(h)) {
		state->push->flags |= LIBNDR_FLAG_NDR64;
	}

	if (h->ops->do_ndr_print) {
		h->ops->do_ndr_print(h, NDR_IN | NDR_SET_VALUES,
				     state->r_ptr, state->call);
	}

	/* push the structure into a blob */
	ndr_err = state->call->ndr_push(state->push, NDR_IN, state->r_ptr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS error;
		error = ndr_map_error2ntstatus(ndr_err);
		if (h->ops->ndr_push_failed) {
			h->ops->ndr_push_failed(h, error,
						state->r_ptr,
						state->call);
		}
		tevent_req_nterror(req, error);
		return tevent_req_post(req, ev);
	}

	/* retrieve the blob */
	state->request = ndr_push_blob(state->push);

	if (h->ops->ndr_validate_in) {
		NTSTATUS error;
		error = h->ops->ndr_validate_in(h, state,
						&state->request,
						state->call);
		if (!NT_STATUS_IS_OK(error)) {
			tevent_req_nterror(req, error);
			return tevent_req_post(req, ev);
		}
	}

	subreq = dcerpc_binding_handle_raw_call_send(state, ev,
						     h, object, opnum,
						     state->push->flags,
						     state->request.data,
						     state->request.length);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dcerpc_binding_handle_call_done, req);

	return req;
}

static void dcerpc_binding_handle_call_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct dcerpc_binding_handle_call_state *state =
		tevent_req_data(req,
		struct dcerpc_binding_handle_call_state);
	struct dcerpc_binding_handle *h = state->h;
	NTSTATUS error;
	uint32_t out_flags = 0;
	enum ndr_err_code ndr_err;

	error = dcerpc_binding_handle_raw_call_recv(subreq, state,
						    &state->response.data,
						    &state->response.length,
						    &out_flags);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, error)) {
		return;
	}

	state->pull = ndr_pull_init_blob(&state->response, state);
	if (tevent_req_nomem(state->pull, req)) {
		return;
	}
	state->pull->flags = state->push->flags;

	if (out_flags & LIBNDR_FLAG_BIGENDIAN) {
		state->pull->flags |= LIBNDR_FLAG_BIGENDIAN;
	} else {
		state->pull->flags &= ~LIBNDR_FLAG_BIGENDIAN;
	}

	state->pull->current_mem_ctx = state->r_mem;

	/* pull the structure from the blob */
	ndr_err = state->call->ndr_pull(state->pull, NDR_OUT, state->r_ptr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		error = ndr_map_error2ntstatus(ndr_err);
		if (h->ops->ndr_pull_failed) {
			h->ops->ndr_pull_failed(h, error,
						&state->response,
						state->call);
		}
		tevent_req_nterror(req, error);
		return;
	}

	if (h->ops->do_ndr_print) {
		h->ops->do_ndr_print(h, NDR_OUT,
				     state->r_ptr, state->call);
	}

	if (h->ops->ndr_validate_out) {
		error = h->ops->ndr_validate_out(h,
						 state->pull,
						 state->r_ptr,
						 state->call);
		if (!NT_STATUS_IS_OK(error)) {
			tevent_req_nterror(req, error);
			return;
		}
	}

	tevent_req_done(req);
}

NTSTATUS dcerpc_binding_handle_call_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS dcerpc_binding_handle_call(struct dcerpc_binding_handle *h,
				    const struct GUID *object,
				    const struct ndr_interface_table *table,
				    uint32_t opnum,
				    TALLOC_CTX *r_mem,
				    void *r_ptr)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *subreq;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	/*
	 * TODO: allow only one sync call
	 */

	if (h->sync_ev) {
		ev = h->sync_ev;
	} else {
		ev = samba_tevent_context_init(frame);
	}
	if (ev == NULL) {
		goto fail;
	}

	subreq = dcerpc_binding_handle_call_send(frame, ev,
						 h, object, table,
						 opnum, r_mem, r_ptr);
	if (subreq == NULL) {
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(subreq, ev, &status)) {
		goto fail;
	}

	status = dcerpc_binding_handle_call_recv(subreq);
fail:
	TALLOC_FREE(frame);
	return status;
}
