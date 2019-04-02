/*
   Unix SMB/CIFS implementation.

   HTTP library

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
#include "http.h"
#include "http_internal.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/param/param.h"
#include "tevent.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "lib/util/data_blob.h"

/**
 * Copy the request headers from src to dst
 */
static NTSTATUS http_copy_header(const struct http_request *src,
				 struct http_request *dst)
{
	struct http_header *h;

	dst->type = src->type;
	dst->major = src->major;
	dst->minor = src->minor;
	dst->uri = talloc_strdup(dst, src->uri);

	for (h = src->headers; h != NULL; h = h->next) {
		http_add_header(dst, &dst->headers, h->key, h->value);
	}
	dst->headers_size = src->headers_size;

	return NT_STATUS_OK;
}

/*
 * Retrieve the WWW-Authenticate header from server response based on the
 * authentication scheme being used.
 */
static NTSTATUS http_parse_auth_response(const DATA_BLOB prefix,
					 struct http_request *auth_response,
					 DATA_BLOB *in)
{
	struct http_header *h;

	for (h = auth_response->headers; h != NULL; h = h->next) {
		int cmp;

		cmp = strcasecmp(h->key, "WWW-Authenticate");
		if (cmp != 0) {
			continue;
		}

		cmp = strncasecmp(h->value,
				  (const char *)prefix.data,
				  prefix.length);
		if (cmp != 0) {
			continue;
		}

		*in = data_blob_string_const(h->value);
		return NT_STATUS_OK;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

struct http_auth_state {
	struct tevent_context *ev;

	struct http_conn *http_conn;

	enum http_auth_method auth;
	DATA_BLOB prefix;

	struct gensec_security *gensec_ctx;
	NTSTATUS gensec_status;

	const struct http_request *original_request;
	struct http_request *next_request;
	struct http_request *auth_response;
};


static void http_send_auth_request_gensec_done(struct tevent_req *subreq);
static void http_send_auth_request_http_req_done(struct tevent_req *subreq);
static void http_send_auth_request_http_rep_done(struct tevent_req *subreq);

struct tevent_req *http_send_auth_request_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct http_conn *http_conn,
					       const struct http_request *original_request,
					       struct cli_credentials *credentials,
					       struct loadparm_context *lp_ctx,
					       enum http_auth_method auth)
{
	struct tevent_req *req = NULL;
	struct http_auth_state *state = NULL;
	struct tevent_req *subreq = NULL;
	DATA_BLOB gensec_in = data_blob_null;
	NTSTATUS status;
	struct http_header *h = NULL;
	const char *mech_name = NULL;

	req = tevent_req_create(mem_ctx, &state, struct http_auth_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->http_conn = http_conn;
	state->auth = auth;
	state->original_request = original_request;

	status = gensec_init();
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = gensec_client_start(state, &state->gensec_ctx,
			             lpcfg_gensec_settings(state, lp_ctx));
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = gensec_set_credentials(state->gensec_ctx, credentials);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	for (h = original_request->headers; h != NULL; h = h->next) {
		int cmp;

		cmp = strcasecmp(h->key, "Host");
		if (cmp != 0) {
			continue;
		}

		status = gensec_set_target_service(state->gensec_ctx, "http");
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		status = gensec_set_target_hostname(state->gensec_ctx, h->value);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
		break;
	}

	switch (state->auth) {
	case HTTP_AUTH_BASIC:
		mech_name = "http_basic";
		state->prefix = data_blob_string_const("Basic");
		break;
	case HTTP_AUTH_NTLM:
		mech_name = "http_ntlm";
		state->prefix = data_blob_string_const("NTLM");
		break;
	case HTTP_AUTH_NEGOTIATE:
		mech_name = "http_negotiate";
		state->prefix = data_blob_string_const("Negotiate");
		break;
	default:
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	status = gensec_start_mech_by_name(state->gensec_ctx, mech_name);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	subreq = gensec_update_send(state, state->ev,
				    state->gensec_ctx,
				    gensec_in);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, http_send_auth_request_gensec_done, req);

	return req;
}

static void http_send_auth_request_gensec_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct http_auth_state *state =
		tevent_req_data(req,
		struct http_auth_state);
	DATA_BLOB gensec_out = data_blob_null;
	NTSTATUS status;
	int ret;

	TALLOC_FREE(state->auth_response);

	status = gensec_update_recv(subreq, state, &gensec_out);
	TALLOC_FREE(subreq);
	state->gensec_status = status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->next_request = talloc_zero(state, struct http_request);
	if (tevent_req_nomem(state->next_request, req)) {
		return;
	}

	status = http_copy_header(state->original_request, state->next_request);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (!NT_STATUS_IS_OK(state->gensec_status)) {
		/*
		 * More preprocessing required before we
		 * can include the content.
		 */
		ret = http_replace_header(state->next_request,
					  &state->next_request->headers,
					  "Content-Length", "0");
		if (ret != 0) {
			tevent_req_oom(req);
			return;
		}
	} else {
		state->next_request->body = state->original_request->body;
	}

	if (gensec_out.length > 0) {
		ret = http_add_header(state->next_request,
				      &state->next_request->headers,
				      "Authorization",
				      (char *)gensec_out.data);
		if (ret != 0) {
			tevent_req_oom(req);
			return;
		}
		data_blob_free(&gensec_out);
	}

	subreq = http_send_request_send(state, state->ev,
					state->http_conn,
					state->next_request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				http_send_auth_request_http_req_done,
				req);
}

static void http_send_auth_request_http_req_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct http_auth_state *state =
		tevent_req_data(req,
		struct http_auth_state);
	NTSTATUS status;

	TALLOC_FREE(state->next_request);

	status = http_send_request_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * If no more processing required, it is done
	 *
	 * The caller will use http_read_response_send/recv
	 * in order to get the high level response.
	 */
	if (NT_STATUS_IS_OK(state->gensec_status)) {
		tevent_req_done(req);
		return;
	}

	/*
	 * If more processing required, read the response from server
	 *
	 * We may get an empty RPCH Echo packet from the server
	 * on the "RPC_OUT_DATA" path. We need to consume this
	 * from the socket, but for now we just ignore the bytes.
	 */
	subreq = http_read_response_send(state, state->ev,
					 state->http_conn,
					 UINT16_MAX);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				http_send_auth_request_http_rep_done,
				req);
}

static void http_send_auth_request_http_rep_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct http_auth_state *state =
		tevent_req_data(req,
		struct http_auth_state);
	DATA_BLOB gensec_in = data_blob_null;
	NTSTATUS status;

	status = http_read_response_recv(subreq, state,
					 &state->auth_response);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * We we asked for up to UINT16_MAX bytes of
	 * content, we don't expect
	 * state->auth_response->remaining_content_length
	 * to be set.
	 *
	 * For now we just ignore any bytes in
	 * state->auth_response->body.
	 */
	if (state->auth_response->remaining_content_length != 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	status = http_parse_auth_response(state->prefix,
					  state->auth_response,
					  &gensec_in);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = gensec_update_send(state, state->ev,
				    state->gensec_ctx,
				    gensec_in);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, http_send_auth_request_gensec_done, req);
}

NTSTATUS http_send_auth_request_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	tevent_req_received(req);

	return NT_STATUS_OK;
}
