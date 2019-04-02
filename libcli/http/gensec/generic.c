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

_PUBLIC_ NTSTATUS gensec_http_generic_init(TALLOC_CTX *);

struct gensec_http_generic_state {
	struct gensec_security *sub;
	DATA_BLOB prefix;
};

static NTSTATUS gensec_http_generic_client_start(struct gensec_security *gensec,
						 const char *prefix_str,
						 const char *mech_oid)
{
	NTSTATUS status;
	struct gensec_http_generic_state *state;

	state = talloc_zero(gensec, struct gensec_http_generic_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	gensec->private_data = state;

	state->prefix = data_blob_string_const(prefix_str);

	status = gensec_subcontext_start(state, gensec, &state->sub);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return gensec_start_mech_by_oid(state->sub, mech_oid);
}

static NTSTATUS gensec_http_ntlm_client_start(struct gensec_security *gensec)
{
	return gensec_http_generic_client_start(gensec, "NTLM",
						GENSEC_OID_NTLMSSP);
}

static NTSTATUS gensec_http_negotiate_client_start(struct gensec_security *gensec)
{
	return gensec_http_generic_client_start(gensec, "Negotiate",
						GENSEC_OID_SPNEGO);
}

struct gensec_http_generic_update_state {
	struct gensec_security *gensec;
	DATA_BLOB sub_in;
	NTSTATUS status;
	DATA_BLOB out;
};

static void gensec_http_generic_update_done(struct tevent_req *subreq);

static struct tevent_req *gensec_http_generic_update_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct gensec_security *gensec_ctx,
						    const DATA_BLOB in)
{
	struct gensec_http_generic_state *http_generic =
		talloc_get_type_abort(gensec_ctx->private_data,
				      struct gensec_http_generic_state);
	struct tevent_req *req = NULL;
	struct gensec_http_generic_update_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct gensec_http_generic_update_state);
	if (req == NULL) {
		return NULL;
	}
	state->gensec = gensec_ctx;

	if (in.length) {
		int cmp;
		DATA_BLOB b64b;
		size_t skip = 0;

		if (in.length < http_generic->prefix.length) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		cmp = strncasecmp((const char *)in.data,
				  (const char *)http_generic->prefix.data,
				  http_generic->prefix.length);
		if (cmp != 0) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}

		if (in.length == http_generic->prefix.length) {
			/*
			 * We expect more data, but the
			 * server just sent the prefix without
			 * a space prefixing base64 data.
			 *
			 * It means the server rejects
			 * the request with.
			 */
			tevent_req_nterror(req, NT_STATUS_LOGON_FAILURE);
			return tevent_req_post(req, ev);
		}

		if (in.data[http_generic->prefix.length] != ' ') {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		skip = http_generic->prefix.length + 1;

		b64b = data_blob_const(in.data + skip, in.length - skip);
		if (b64b.length != 0) {
			char *b64 = NULL;

			/*
			 * ensure it's terminated with \0' before
			 * passing to base64_decode_data_blob_talloc().
			 */
			b64 = talloc_strndup(state, (const char *)b64b.data,
					     b64b.length);
			if (tevent_req_nomem(b64, req)) {
				return tevent_req_post(req, ev);
			}

			state->sub_in = base64_decode_data_blob_talloc(state,
								       b64);
			TALLOC_FREE(b64);
			if (tevent_req_nomem(state->sub_in.data, req)) {
				return tevent_req_post(req, ev);
			}
		}
	}

	subreq = gensec_update_send(state, ev,
				    http_generic->sub,
				    state->sub_in);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, gensec_http_generic_update_done, req);

	return req;
}

static void gensec_http_generic_update_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct gensec_http_generic_update_state *state =
		tevent_req_data(req,
		struct gensec_http_generic_update_state);
	struct gensec_http_generic_state *http_generic =
		talloc_get_type_abort(state->gensec->private_data,
		struct gensec_http_generic_state);
	NTSTATUS status;
	DATA_BLOB sub_out = data_blob_null;
	char *b64 = NULL;
	char *str = NULL;
	int prefix_length;

	status = gensec_update_recv(subreq, state, &sub_out);
	TALLOC_FREE(subreq);
	state->status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (sub_out.length == 0) {
		tevent_req_done(req);
		return;
	}

	b64 = base64_encode_data_blob(state, sub_out);
	data_blob_free(&sub_out);
	if (tevent_req_nomem(b64, req)) {
		return;
	}

	prefix_length = http_generic->prefix.length;
	str = talloc_asprintf(state, "%*.*s %s", prefix_length, prefix_length,
			      (const char *)http_generic->prefix.data, b64);
	TALLOC_FREE(b64);
	if (tevent_req_nomem(str, req)) {
		return;
	}

	state->out = data_blob_string_const(str);
	tevent_req_done(req);
}

static NTSTATUS gensec_http_generic_update_recv(struct tevent_req *req,
					     TALLOC_CTX *out_mem_ctx,
					     DATA_BLOB *out)
{
	struct gensec_http_generic_update_state *state =
		tevent_req_data(req,
		struct gensec_http_generic_update_state);
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
	.update_send    = gensec_http_generic_update_send,
	.update_recv    = gensec_http_generic_update_recv,
	.enabled        = true,
	.priority       = GENSEC_EXTERNAL,
};

static const struct gensec_security_ops gensec_http_negotiate_security_ops = {
	.name           = "http_negotiate",
	.auth_type      = 0,
	.client_start   = gensec_http_negotiate_client_start,
	.update_send    = gensec_http_generic_update_send,
	.update_recv    = gensec_http_generic_update_recv,
	.enabled        = true,
	.priority       = GENSEC_EXTERNAL,
	.glue           = true,
};

_PUBLIC_ NTSTATUS gensec_http_generic_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = gensec_register(ctx, &gensec_http_ntlm_security_ops);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register '%s' gensec backend!\n",
				gensec_http_ntlm_security_ops.name));
		return status;
	}

	status = gensec_register(ctx, &gensec_http_negotiate_security_ops);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to register '%s' gensec backend!\n",
			  gensec_http_negotiate_security_ops.name));
		return status;
	}

	return status;
}
