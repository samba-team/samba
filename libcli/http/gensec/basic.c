/*
   Unix SMB/CIFS implementation.

   HTTP library - Basic authentication mechanism gensec module

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
#include "auth/credentials/credentials.h"
#include "lib/util/base64.h"

_PUBLIC_ NTSTATUS gensec_http_basic_init(TALLOC_CTX *);

struct gensec_http_basic_state {
	enum {
		GENSEC_HTTP_BASIC_START,
		GENSEC_HTTP_BASIC_DONE,
		GENSEC_HTTP_BASIC_ERROR,
	} step;
};

static NTSTATUS gensec_http_basic_client_start(struct gensec_security *gensec)
{
	struct gensec_http_basic_state *state;

	state = talloc_zero(gensec, struct gensec_http_basic_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	gensec->private_data = state;

	state->step = GENSEC_HTTP_BASIC_START;

	return NT_STATUS_OK;
}

struct gensec_http_basic_update_state {
	NTSTATUS status;
	DATA_BLOB out;
};

static NTSTATUS gensec_http_basic_update_internal(struct gensec_security *gensec_ctx,
						  TALLOC_CTX *mem_ctx,
						  const DATA_BLOB in,
						  DATA_BLOB *out);

static struct tevent_req *gensec_http_basic_update_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct gensec_security *gensec_security,
						    const DATA_BLOB in)
{
	struct tevent_req *req = NULL;
	struct gensec_http_basic_update_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_http_basic_update_state);
	if (req == NULL) {
		return NULL;
	}

	status = gensec_http_basic_update_internal(gensec_security,
						   state, in,
						   &state->out);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS gensec_http_basic_update_internal(struct gensec_security *gensec_ctx,
						  TALLOC_CTX *mem_ctx,
						  const DATA_BLOB in,
						  DATA_BLOB *out)
{
	struct gensec_http_basic_state *state;
	struct cli_credentials *creds;
	char *tmp, *b64;

	state = talloc_get_type_abort(gensec_ctx->private_data,
				      struct gensec_http_basic_state);
	creds = gensec_get_credentials(gensec_ctx);

	switch (gensec_ctx->gensec_role) {
	case GENSEC_CLIENT:
		switch (state->step) {
		case GENSEC_HTTP_BASIC_START:
			tmp = talloc_asprintf(mem_ctx, "%s\\%s:%s",
					cli_credentials_get_domain(creds),
					cli_credentials_get_username(creds),
					cli_credentials_get_password(creds));
			if (tmp == NULL) {
				state->step = GENSEC_HTTP_BASIC_ERROR;
				return NT_STATUS_NO_MEMORY;
			}
			*out = data_blob_string_const(tmp);

			b64 = base64_encode_data_blob(mem_ctx, *out);
			if (b64 == NULL) {
				state->step = GENSEC_HTTP_BASIC_ERROR;
				return NT_STATUS_NO_MEMORY;
			}
			TALLOC_FREE(tmp);

			tmp = talloc_asprintf(mem_ctx, "Basic %s", b64);
			if (tmp == NULL) {
				state->step = GENSEC_HTTP_BASIC_ERROR;
				return NT_STATUS_NO_MEMORY;
			}
			TALLOC_FREE(b64);

			*out = data_blob_string_const(tmp);
			state->step = GENSEC_HTTP_BASIC_DONE;
			return NT_STATUS_OK;

		case GENSEC_HTTP_BASIC_DONE:
		case GENSEC_HTTP_BASIC_ERROR:
		default:
			break;
		}
		state->step = GENSEC_HTTP_BASIC_ERROR;
		return NT_STATUS_INTERNAL_ERROR;

	case GENSEC_SERVER:
		state->step = GENSEC_HTTP_BASIC_ERROR;
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	state->step = GENSEC_HTTP_BASIC_ERROR;
	return NT_STATUS_INTERNAL_ERROR;
}

static NTSTATUS gensec_http_basic_update_recv(struct tevent_req *req,
					      TALLOC_CTX *out_mem_ctx,
					      DATA_BLOB *out)
{
	struct gensec_http_basic_update_state *state =
		tevent_req_data(req,
		struct gensec_http_basic_update_state);
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

static const struct gensec_security_ops gensec_http_basic_security_ops = {
	.name           = "http_basic",
	.auth_type      = 0,
	.client_start   = gensec_http_basic_client_start,
	.update_send    = gensec_http_basic_update_send,
	.update_recv    = gensec_http_basic_update_recv,
	.enabled        = true,
	.priority       = GENSEC_EXTERNAL,
};

_PUBLIC_ NTSTATUS gensec_http_basic_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = gensec_register(ctx, &gensec_http_basic_security_ops);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register '%s' gensec backend!\n",
				gensec_http_basic_security_ops.name));
		return status;
	}

	return status;
}
