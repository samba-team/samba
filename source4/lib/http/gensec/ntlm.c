/*
   Unix SMB/CIFS implementation.

   HTTP library - NTLM authentication mechanism gensec module

   Copyright (C) 2014 Samuel Cabrero <samuelcabrero@kernevil.me>

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
#include "lib/util/tevent_ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "lib/util/base64.h"

_PUBLIC_ NTSTATUS gensec_http_ntlm_init(TALLOC_CTX *);

struct gensec_http_ntlm_state {
	struct gensec_security *sub;
};

static NTSTATUS gensec_http_ntlm_client_start(struct gensec_security *gensec)
{
	NTSTATUS status;
	struct gensec_http_ntlm_state *state;

	state = talloc_zero(gensec, struct gensec_http_ntlm_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	gensec->private_data = state;

	status = gensec_subcontext_start(state, gensec, &state->sub);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return gensec_start_mech_by_oid(state->sub, GENSEC_OID_NTLMSSP);
}

struct gensec_http_ntlm_update_state {
	DATA_BLOB ntlm_in;
	NTSTATUS status;
	DATA_BLOB out;
};

static void gensec_http_ntlm_update_done(struct tevent_req *subreq);

static struct tevent_req *gensec_http_ntlm_update_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct gensec_security *gensec_ctx,
						    const DATA_BLOB in)
{
	struct gensec_http_ntlm_state *http_ntlm =
		talloc_get_type_abort(gensec_ctx->private_data,
				      struct gensec_http_ntlm_state);
	struct tevent_req *req = NULL;
	struct gensec_http_ntlm_update_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_http_ntlm_update_state);
	if (req == NULL) {
		return NULL;
	}

	if (in.length) {
		if (strncasecmp((char *)in.data, "NTLM ", 5) != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		state->ntlm_in = base64_decode_data_blob_talloc(state,
							(char *)&in.data[5]);
	}

	subreq = gensec_update_send(state, ev,
				    http_ntlm->sub,
				    state->ntlm_in);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, gensec_http_ntlm_update_done, req);

	return req;
}

static void gensec_http_ntlm_update_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct gensec_http_ntlm_update_state *state =
		tevent_req_data(req,
		struct gensec_http_ntlm_update_state);
	NTSTATUS status;
	DATA_BLOB ntlm_out;
	char *b64 = NULL;
	char *str = NULL;

	status = gensec_update_recv(subreq, state, &ntlm_out);
	TALLOC_FREE(subreq);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	b64 = base64_encode_data_blob(state, ntlm_out);
	data_blob_free(&ntlm_out);
	if (tevent_req_nomem(b64, req)) {
		return;
	}

	str = talloc_asprintf(state, "NTLM %s", b64);
	TALLOC_FREE(b64);
	if (tevent_req_nomem(str, req)) {
		return;
	}

	state->out = data_blob_string_const(str);
	tevent_req_done(req);
}

static NTSTATUS gensec_http_ntlm_update_recv(struct tevent_req *req,
					     TALLOC_CTX *out_mem_ctx,
					     DATA_BLOB *out)
{
	struct gensec_http_ntlm_update_state *state =
		tevent_req_data(req,
		struct gensec_http_ntlm_update_state);
	NTSTATUS status;

	*out = data_blob_null;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out = state->out;
	talloc_steal(out_mem_ctx, state->out.data);
	status = state->status;
	tevent_req_received(req);
	return status;
}

static const struct gensec_security_ops gensec_http_ntlm_security_ops = {
	.name           = "http_ntlm",
	.auth_type      = 0,
	.client_start   = gensec_http_ntlm_client_start,
	.update_send    = gensec_http_ntlm_update_send,
	.update_recv    = gensec_http_ntlm_update_recv,
	.enabled        = true,
	.priority       = GENSEC_EXTERNAL,
};

_PUBLIC_ NTSTATUS gensec_http_ntlm_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = gensec_register(ctx, &gensec_http_ntlm_security_ops);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register '%s' gensec backend!\n",
				gensec_http_ntlm_security_ops.name));
		return status;
	}

	return status;
}
