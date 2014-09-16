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
static NTSTATUS http_copy_header(struct http_request *src,
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
static NTSTATUS http_parse_auth_response(enum http_auth_method auth,
					 struct http_request *auth_response,
					 DATA_BLOB *in)
{
	struct http_header *h;

	for (h = auth_response->headers; h != NULL; h = h->next) {
		if (strncasecmp(h->key, "WWW-Authenticate", 16) == 0) {
			switch (auth) {
			case HTTP_AUTH_NTLM:
				if (strncasecmp(h->value, "NTLM ", 5) == 0) {
					*in = data_blob_string_const(h->value);
					return NT_STATUS_OK;
				}
				break;
			default:
				break;
			}
		}
	}

	return NT_STATUS_NOT_SUPPORTED;
}

/*
 * Create the next authentication request to send to server if authentication
 * is not completed. If it is completed, attachs the 'Authorization' header
 * to the original request.
 */
static NTSTATUS http_create_auth_request(TALLOC_CTX *mem_ctx,
					 struct gensec_security *gensec_ctx,
					 struct tevent_context *ev,
					 enum http_auth_method auth,
					 struct http_request *original_request,
					 struct http_request *auth_response,
					 struct http_request **auth_request)
{
	NTSTATUS status;
	DATA_BLOB in, out;

	if (auth_response) {
		status = http_parse_auth_response(auth, auth_response, &in);
	} else {
		in = data_blob_null;
	}

	status = gensec_update_ev(gensec_ctx, mem_ctx, ev, in, &out);
	if (NT_STATUS_IS_OK(status)) {
		if (out.length) {
			http_add_header(original_request,
					&original_request->headers,
					"Authorization", (char*)out.data);
		}
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		NTSTATUS status2;

		*auth_request = talloc_zero(mem_ctx, struct http_request);
		if (*auth_request == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status2 = http_copy_header(original_request, *auth_request);
		if (!NT_STATUS_IS_OK(status2)) {
			talloc_free(*auth_request);
			return status2;
		}

		http_replace_header(*auth_request, &((*auth_request)->headers),
				    "Content-Length", "0");
		if (out.length) {
			http_add_header(*auth_request,
					&((*auth_request)->headers),
					"Authorization", (char*)out.data);
		}
	}

	return status;
}

struct http_auth_state
{
	struct loadparm_context	*lp_ctx;
	struct tevent_context	*ev;
	struct tstream_context	*stream;
	struct tevent_queue	*send_queue;
	struct cli_credentials  *credentials;
	struct http_request	*original_request;
	struct gensec_security	*gensec_ctx;
	NTSTATUS		gensec_status;
	enum http_auth_method	auth;

	int			sys_errno;
	int			nwritten;
};


static void http_send_auth_request_done(struct tevent_req *);
struct tevent_req *http_send_auth_request_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct tstream_context *stream,
					       struct tevent_queue *send_queue,
					       struct http_request *original_request,
					       struct cli_credentials *credentials,
					       struct loadparm_context *lp_ctx,
					       enum http_auth_method auth)
{
	struct tevent_req *req;
	struct tevent_req *subreq;
	struct http_auth_state *state;
	NTSTATUS status;
	struct http_request *auth_request;
	struct http_request *request_to_send;

	req = tevent_req_create(mem_ctx, &state, struct http_auth_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->stream = stream;
	state->send_queue = send_queue;
	state->original_request = original_request;
	state->credentials = credentials;
	state->lp_ctx = lp_ctx;
	state->auth = auth;

	status = gensec_init();
	if (!NT_STATUS_IS_OK(status)) {
		goto post_status;
	}
	status = gensec_client_start(state, &state->gensec_ctx,
			             lpcfg_gensec_settings(state, lp_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		goto post_status;
	}
	status = gensec_set_credentials(state->gensec_ctx, credentials);
	if (!NT_STATUS_IS_OK(status)) {
		goto post_status;
	}

	switch (state->auth) {
	case HTTP_AUTH_BASIC:
		status = gensec_start_mech_by_name(state->gensec_ctx,
						   "http_basic");
		if (!NT_STATUS_IS_OK(status)) {
			goto post_status;
		}
		break;
	case HTTP_AUTH_NTLM:
		status = gensec_start_mech_by_name(state->gensec_ctx,
						   "http_ntlm");
		if (!NT_STATUS_IS_OK(status)) {
			goto post_status;
		}
		break;
	default:
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	/*
	 * Store the gensec status to read the server response on callback
	 * if more processing is required
	*/
	state->gensec_status = http_create_auth_request(state,
							state->gensec_ctx,
							state->ev,
							state->auth,
							state->original_request,
							NULL,
							&auth_request);
	if (!NT_STATUS_IS_OK(state->gensec_status) &&
	    !NT_STATUS_EQUAL(state->gensec_status,
			     NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto post_status;
	}

	/*
	 * If no more processing is necessary, the http_create_auth_request
	 * function will attach the authentication header to the original
	 * request
	 */
	request_to_send = NT_STATUS_IS_OK(state->gensec_status) ?
				state->original_request : auth_request;

	subreq = http_send_request_send(state, ev, stream, send_queue,
					request_to_send);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, http_send_auth_request_done, req);
	return req;
post_status:
	tevent_req_nterror(req, status);
	return tevent_req_post(req, ev);
}

static void http_send_auth_request_done2(struct tevent_req *subreq);
static void http_send_auth_request_done(struct tevent_req *subreq)
{
	NTSTATUS		status;
	struct tevent_req	*req;
	struct http_auth_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct http_auth_state);

	status = http_send_request_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* If no more processing required, it is done */
	if (NT_STATUS_IS_OK(state->gensec_status)) {
		tevent_req_done(req);
		return;
	}

	/* If more processing required, read the response from server */
	if (NT_STATUS_EQUAL(state->gensec_status,
			    NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		subreq = http_read_response_send(state, state->ev,
						 state->stream);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, http_send_auth_request_done2,
					req);
		return;
	}

	/*
	 * If gensec status is not NT_STATUS_OK neither
	 * NT_STATUS_MORE_PROCESSING_REQUIRED , it is an error
	 */
	tevent_req_nterror(req, state->gensec_status);
}

static void http_send_auth_request_done2(struct tevent_req *subreq)
{
	NTSTATUS status;
	struct tevent_req	*req;
	struct http_auth_state	*state;
	struct http_request *auth_response;
	struct http_request *auth_request;
	struct http_request *request_to_send;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct http_auth_state);

	status = http_read_response_recv(subreq, state, &auth_response);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->gensec_status = http_create_auth_request(state,
							state->gensec_ctx,
							state->ev,
							state->auth,
							state->original_request,
							auth_response,
							&auth_request);
	if (!NT_STATUS_IS_OK(state->gensec_status) &&
	    !NT_STATUS_EQUAL(state->gensec_status,
			     NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}

	/*
	 * If no more processing is necessary, the http_create_auth_request
	 * function will attach the authentication header to the original
	 * request
	 */
	request_to_send = NT_STATUS_IS_OK(state->gensec_status) ?
				state->original_request : auth_request;

	subreq = http_send_request_send(state,
					state->ev,
					state->stream,
					state->send_queue,
					request_to_send);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, http_send_auth_request_done, req);
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
