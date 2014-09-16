/*
   Unix SMB/CIFS implementation.

   HTTP library

   Copyright (C) 2013 Samuel Cabrero <samuelcabrero@kernevil.me>

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
#include <talloc_dict.h>
#include "lib/util/tevent_ntstatus.h"
#include "http.h"
#include "http_internal.h"
#include "util/tevent_werror.h"
#include "lib/util/dlinklist.h"


/**
 * Determines if a response should have a body.
 * Follows the rules in RFC 2616 section 4.3.
 * @return 1 if the response MUST have a body; 0 if the response MUST NOT have
 *     a body. Returns -1 on error.
 */
static int http_response_needs_body(struct http_request *req)
{
	if (!req) return -1;

	/* If response code is 503, the body contains the error description
	 * (2.1.2.1.3)
	 */
	if (req->response_code == 503)
		return 1;

	return 0;
}


/**
 * Parses the HTTP headers
 */
static enum http_read_status http_parse_headers(struct http_read_response_state *state)
{
	enum http_read_status	status = HTTP_ALL_DATA_READ;
	char			*ptr = NULL;
	char			*line = NULL;
	char			*key = NULL;
	char			*value = NULL;
	int			n = 0;
	int			ret;

	/* Sanity checks */
	if (!state || !state->response) {
		DEBUG(0, ("%s: Invalid Parameter\n", __func__));
		return HTTP_DATA_CORRUPTED;
	}

	if (state->buffer.length > state->max_headers_size) {
		DEBUG(0, ("%s: Headers too long: %zi, maximum length is %zi\n", __func__,
			  state->buffer.length, state->max_headers_size));
		return HTTP_DATA_TOO_LONG;
	}

	line = talloc_strndup(state, (char *)state->buffer.data, state->buffer.length);
	if (!line) {
		DEBUG(0, ("%s: Memory error\n", __func__));
		return HTTP_DATA_CORRUPTED;
	}

	ptr = strstr(line, "\r\n");
	if (ptr == NULL) {
		TALLOC_FREE(line);
		return HTTP_MORE_DATA_EXPECTED;
	}

	state->response->headers_size += state->buffer.length;

	if (strncmp(line, "\r\n", 2) == 0) {
		DEBUG(11,("%s: All headers read\n", __func__));

		ret = http_response_needs_body(state->response);
		switch (ret) {
		case 0:
			DEBUG(11, ("%s: Skipping body for code %d\n", __func__,
				   state->response->response_code));
			state->parser_state = HTTP_READING_DONE;
			break;
		case 1:
			DEBUG(11, ("%s: Start of read body\n", __func__));
			state->parser_state = HTTP_READING_BODY;
			break;
		case -1:
			DEBUG(0, ("%s_: Error in http_response_needs_body\n", __func__));
			TALLOC_FREE(line);
			return HTTP_DATA_CORRUPTED;
			break;
		}

		TALLOC_FREE(line);
		return HTTP_ALL_DATA_READ;
	}

	n = sscanf(line, "%a[^:]: %a[^\r\n]\r\n", &key, &value);
	if (n != 2) {
		DEBUG(0, ("%s: Error parsing header '%s'\n", __func__, line));
		status = HTTP_DATA_CORRUPTED;
		goto error;
	}

	if (http_add_header(state->response, &state->response->headers, key, value) == -1) {
		DEBUG(0, ("%s: Error adding header\n", __func__));
		status = HTTP_DATA_CORRUPTED;
		goto error;
	}

error:
	free(key);
	free(value);
	TALLOC_FREE(line);
	return status;
}

/**
 * Parses the first line of a HTTP response
 */
static bool http_parse_response_line(struct http_read_response_state *state)
{
	bool	status = true;
	char	*protocol;
	char	*msg = NULL;
	char	major;
	char	minor;
	int	code;
	char	*line = NULL;
	int	n;

	/* Sanity checks */
	if (!state) {
		DEBUG(0, ("%s: Input parameter is NULL\n", __func__));
		return false;
	}

	line = talloc_strndup(state, (char*)state->buffer.data, state->buffer.length);
	if (!line) {
		DEBUG(0, ("%s: Memory error\n", __func__));
		return false;
	}

	n = sscanf(line, "%a[^/]/%c.%c %d %a[^\r\n]\r\n",
		   &protocol, &major, &minor, &code, &msg);

	DEBUG(11, ("%s: Header parsed(%i): protocol->%s, major->%c, minor->%c, "
		   "code->%d, message->%s\n", __func__, n, protocol, major, minor,
		   code, msg));

	if (n != 5) {
		DEBUG(0, ("%s: Error parsing header\n",	__func__));
		status = false;
		goto error;
	}

	if (major != '1') {
		DEBUG(0, ("%s: Bad HTTP major number '%c'\n", __func__, major));
		status = false;
		goto error;
	}

	if (code == 0) {
		DEBUG(0, ("%s: Bad response code '%d'", __func__, code));
		status = false;
		goto error;
	}

	if (msg == NULL) {
		DEBUG(0, ("%s: Error parsing HTTP data\n", __func__));
		status = false;
		goto error;
	}

	state->response->major = major;
	state->response->minor = minor;
	state->response->response_code = code;
	state->response->response_code_line = talloc_strndup(state->response,
							     msg, strlen(msg));

error:
	free(protocol);
	free(msg);
	TALLOC_FREE(line);
	return status;
}

/*
 * Parses header lines from a request or a response into the specified
 * request object given a buffer.
 *
 * Returns
 *   HTTP_DATA_CORRUPTED		on error
 *   HTTP_MORE_DATA_EXPECTED	when we need to read more headers
 *   HTTP_DATA_TOO_LONG			on error
 *   HTTP_ALL_DATA_READ			when all headers have been read
 */
static enum http_read_status http_parse_firstline(struct http_read_response_state *state)
{
	enum http_read_status	status = HTTP_ALL_DATA_READ;
	char			*ptr = NULL;
	char			*line;

	/* Sanity checks */
	if (!state) {
		DEBUG(0, ("%s: Invalid Parameter\n", __func__));
		return HTTP_DATA_CORRUPTED;
	}

	if (state->buffer.length > state->max_headers_size) {
		DEBUG(0, ("%s: Headers too long: %zi, maximum length is %zi\n", __func__,
			  state->buffer.length, state->max_headers_size));
		return HTTP_DATA_TOO_LONG;
	}

	line = talloc_strndup(state, (char *)state->buffer.data, state->buffer.length);
	if (!line) {
		DEBUG(0, ("%s: Not enough memory\n", __func__));
		return HTTP_DATA_CORRUPTED;
	}

	ptr = strstr(line, "\r\n");
	if (ptr == NULL) {
		TALLOC_FREE(line);
		return HTTP_MORE_DATA_EXPECTED;
	}

	state->response->headers_size = state->buffer.length;
	if (!http_parse_response_line(state)) {
		status = HTTP_DATA_CORRUPTED;
	}

	/* Next state, read HTTP headers */
	state->parser_state = HTTP_READING_HEADERS;

	TALLOC_FREE(line);
	return status;
}

static enum http_read_status http_read_body(struct http_read_response_state *state)
{
	enum http_read_status status = HTTP_DATA_CORRUPTED;
	/* TODO */
	return status;
}

static enum http_read_status http_read_trailer(struct http_read_response_state *state)
{
	enum http_read_status status = HTTP_DATA_CORRUPTED;
	/* TODO */
	return status;
}

static enum http_read_status http_parse_buffer(struct http_read_response_state *state)
{
	if (!state) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return HTTP_DATA_CORRUPTED;
	}

	switch (state->parser_state) {
		case HTTP_READING_FIRSTLINE:
			return http_parse_firstline(state);
		case HTTP_READING_HEADERS:
			return http_parse_headers(state);
		case HTTP_READING_BODY:
			return http_read_body(state);
			break;
		case HTTP_READING_TRAILER:
			return http_read_trailer(state);
			break;
		case HTTP_READING_DONE:
			/* All read */
			return HTTP_ALL_DATA_READ;
		default:
			DEBUG(0, ("%s: Illegal parser state %d", __func__,
				  state->parser_state));
			break;
	}
	return HTTP_DATA_CORRUPTED;
}

static int http_header_is_valid_value(const char *value)
{
	const char	*p = NULL;

	/* Sanity checks */
	if (!value) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return -1;
	}
	p = value;

	while ((p = strpbrk(p, "\r\n")) != NULL) {
		/* Expect only one new line */
		p += strspn(p, "\r\n");
		/* Expect a space or tab for continuation */
		if (*p != ' ' && *p != '\t')
			return (0);
	}
	return 1;
}

static int http_add_header_internal(TALLOC_CTX *mem_ctx,
				    struct http_header **headers,
				    const char *key, const char *value,
				    bool replace)
{
	struct http_header *tail = NULL;
	struct http_header *h = NULL;

	/* Sanity checks */
	if (!headers || !key || !value) {
		DEBUG(0, ("Invalid parameter\n"));
		return -1;
	}



	if (replace) {
		for (h = *headers; h != NULL; h = h->next) {
			if (strcasecmp(key, h->key) == 0) {
				break;
			}
		}

		if (h != NULL) {
			/* Replace header value */
			if (h->value) {
				talloc_free(h->value);
			}
			h->value = talloc_strdup(h, value);
			DEBUG(11, ("%s: Replaced HTTP header: key '%s', value '%s'\n",
					__func__, h->key, h->value));
			return 0;
		}
	}

	/* Add new header */
	h = talloc(mem_ctx, struct http_header);
	h->key = talloc_strdup(h, key);
	h->value = talloc_strdup(h, value);
	DLIST_ADD_END(*headers, h, NULL);
	tail = DLIST_TAIL(*headers);
	if (tail != h) {
		DEBUG(0, ("%s: Error adding header\n", __func__));
		return -1;
	}
	DEBUG(11, ("%s: Added HTTP header: key '%s', value '%s'\n",
			__func__, h->key, h->value));
	return 0;
}

int http_add_header(TALLOC_CTX *mem_ctx,
		    struct http_header **headers,
		    const char *key, const char *value)
{
	if (strchr(key, '\r') != NULL || strchr(key, '\n') != NULL) {
		DEBUG(0, ("%s: Dropping illegal header key\n", __func__));
		return -1;
	}

	if (!http_header_is_valid_value(value)) {
		DEBUG(0, ("%s: Dropping illegal header value\n", __func__));
		return -1;
	}

	return (http_add_header_internal(mem_ctx, headers, key, value, false));
}

int http_replace_header(TALLOC_CTX *mem_ctx,
		    struct http_header **headers,
		    const char *key, const char *value)
{
	if (strchr(key, '\r') != NULL || strchr(key, '\n') != NULL) {
		DEBUG(0, ("%s: Dropping illegal header key\n", __func__));
		return -1;
	}

	if (!http_header_is_valid_value(value)) {
		DEBUG(0, ("%s: Dropping illegal header value\n", __func__));
		return -1;
	}

	return (http_add_header_internal(mem_ctx, headers, key, value, true));
}

/**
 * Remove a header from the headers list.
 *
 * Returns 0,  if the header was successfully removed.
 * Returns -1, if the header could not be found.
 */
int http_remove_header(struct http_header **headers, const char *key)
{
	struct http_header *header;

	/* Sanity checks */
	if (!headers || !key) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return -1;
	}

	for(header = *headers; header != NULL; header = header->next) {
		if (strcmp(key, header->key) == 0) {
			DLIST_REMOVE(*headers, header);
			return 0;
		}
	}
	return -1;
}

static int http_read_response_next_vector(struct tstream_context *stream,
					  void *private_data,
					  TALLOC_CTX *mem_ctx,
					  struct iovec **_vector,
					  size_t *_count)
{
	struct http_read_response_state	*state;
	struct iovec			*vector;

	/* Sanity checks */
	if (!stream || !private_data || !_vector || !_count) {
		DEBUG(0, ("%s: Invalid Parameter\n", __func__));
	}

	state =	talloc_get_type_abort(private_data, struct http_read_response_state);
	vector = talloc_array(mem_ctx, struct iovec, 1);
	if (!vector) {
		DEBUG(0, ("%s: No more memory\n", __func__));
		return -1;
	}

	if (state->buffer.data == NULL) {
		/* Allocate buffer */
		state->buffer.data = talloc_zero_array(state, uint8_t, 1);
		if (!state->buffer.data) {
			DEBUG(0, ("%s: No more memory\n", __func__));
			return -1;
		}
		state->buffer.length = 1;

		/* Return now, nothing to parse yet */
		vector[0].iov_base = (void *)(state->buffer.data);
		vector[0].iov_len = 1;
		*_vector = vector;
		*_count = 1;
		return 0;
	}

	switch (http_parse_buffer(state)) {
		case HTTP_ALL_DATA_READ:
			if (state->parser_state == HTTP_READING_DONE) {
				/* Full request or response parsed */
				*_vector = NULL;
				*_count = 0;
			} else {
				/* Free current buffer and allocate new one */
				TALLOC_FREE(state->buffer.data);
				state->buffer.data = talloc_zero_array(state, uint8_t, 1);
				if (!state->buffer.data) {
					return -1;
				}
				state->buffer.length = 1;

				vector[0].iov_base = (void *)(state->buffer.data);
				vector[0].iov_len = 1;
				*_vector = vector;
				*_count = 1;
			}
			break;
		case HTTP_MORE_DATA_EXPECTED:
			/* TODO Optimize, allocating byte by byte */
			state->buffer.data = talloc_realloc(state, state->buffer.data,
							    uint8_t, state->buffer.length + 1);
			if (!state->buffer.data) {
				return -1;
			}
			state->buffer.length++;
			vector[0].iov_base = (void *)(state->buffer.data +
						      state->buffer.length - 1);
			vector[0].iov_len = 1;
			*_vector = vector;
			*_count = 1;
			break;
		case HTTP_DATA_CORRUPTED:
		case HTTP_REQUEST_CANCELED:
		case HTTP_DATA_TOO_LONG:
			return -1;
			break;
		default:
			DEBUG(0, ("%s: Unexpected status\n", __func__));
			break;
	}
	return 0;
}


/**
 * Reads a HTTP response
 */
static void http_read_response_done(struct tevent_req *);
struct tevent_req *http_read_response_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct tstream_context *stream)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct http_read_response_state *state;

	DEBUG(11, ("%s: Reading HTTP response\n", __func__));

	/* Sanity checks */
	if (!ev || !stream) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state, struct http_read_response_state);
	if (req == NULL) {
		return NULL;
	}

	state->max_headers_size = HTTP_MAX_HEADER_SIZE;
	state->parser_state = HTTP_READING_FIRSTLINE;
	state->response = talloc_zero(state, struct http_request);
	if (tevent_req_nomem(state->response, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = tstream_readv_pdu_send(state, ev, stream,
					http_read_response_next_vector,
					state);
	if (tevent_req_nomem(subreq,req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, http_read_response_done, req);

	return req;
}

static void http_read_response_done(struct tevent_req *subreq)
{
	NTSTATUS			status;
	struct tevent_req		*req;
	int				ret;
	int				sys_errno;

	if (!subreq) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return;
	}

	req = tevent_req_callback_data(subreq, struct tevent_req);

	ret = tstream_readv_pdu_recv(subreq, &sys_errno);
	DEBUG(11, ("%s: HTTP response read (%d bytes)\n", __func__, ret));
	TALLOC_FREE(subreq);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(sys_errno);
		DEBUG(0, ("%s: Failed to read HTTP response: %s\n",
			  __func__, nt_errstr(status)));
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS http_read_response_recv(struct tevent_req *req,
				 TALLOC_CTX *mem_ctx,
				 struct http_request **response)
{
	NTSTATUS status;
	struct http_read_response_state *state;

	if (!mem_ctx || !response || !req) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	state = tevent_req_data(req, struct http_read_response_state);
	*response = state->response;
	talloc_steal(mem_ctx, state->response);

	tevent_req_received(req);

	return NT_STATUS_OK;
}

static const char *http_method_str(enum http_cmd_type type)
{
	const char *method;

	switch (type) {
	case HTTP_REQ_RPC_IN_DATA:
		method = "RPC_IN_DATA";
		break;
	case HTTP_REQ_RPC_OUT_DATA:
		method = "RPC_OUT_DATA";
		break;
	default:
		method = NULL;
		break;
	}

	return method;
}

static NTSTATUS http_push_request_line(TALLOC_CTX *mem_ctx,
				       DATA_BLOB *buffer,
				       const struct http_request *req)
{
	const char	*method;
	char		*str;

	/* Sanity checks */
	if (!buffer || !req) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return NT_STATUS_INVALID_PARAMETER;
	}

	method = http_method_str(req->type);
	if (method == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	str = talloc_asprintf(mem_ctx, "%s %s HTTP/%c.%c\r\n", method,
			      req->uri, req->major, req->minor);
	if (str == NULL)
		return NT_STATUS_NO_MEMORY;

	if (!data_blob_append(mem_ctx, buffer, str, strlen(str))) {
		talloc_free(str);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_free(str);
	return NT_STATUS_OK;
}

static NTSTATUS http_push_headers(TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct http_request *req)
{
	struct http_header	*header = NULL;
	char			*header_str = NULL;
	size_t			len;

	/* Sanity checks */
	if (!blob || !req) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (header = req->headers; header != NULL; header = header->next) {
		header_str = talloc_asprintf(mem_ctx, "%s: %s\r\n",
					     header->key, header->value);
		if (header_str == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		len = strlen(header_str);
		if (!data_blob_append(mem_ctx, blob, header_str, len)) {
			talloc_free(header_str);
			return NT_STATUS_NO_MEMORY;
		}
		talloc_free(header_str);
	}

	if (!data_blob_append(mem_ctx, blob, "\r\n",2)) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}


static NTSTATUS http_push_body(TALLOC_CTX *mem_ctx,
			       DATA_BLOB *blob,
			       struct http_request *req)
{
	/* Sanity checks */
	if (!blob || !req) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (req->body.length) {
		if (!data_blob_append(mem_ctx, blob, req->body.data,
				req->body.length)) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	return NT_STATUS_OK;
}

/**
 * Sends and HTTP request
 */
static void http_send_request_done(struct tevent_req *);
struct tevent_req *http_send_request_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tstream_context *stream,
					  struct tevent_queue *send_queue,
					  struct http_request *request)
{
	struct tevent_req		*req;
	struct tevent_req		*subreq;
	struct http_send_request_state	*state = NULL;
	NTSTATUS			status;

	DEBUG(11, ("%s: Sending HTTP request\n", __func__));

	/* Sanity checks */
	if (!ev || !stream || !send_queue || !request) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state, struct http_send_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->stream = stream;
	state->send_queue = send_queue;
	state->request = request;

	/* Push the request line */
	status = http_push_request_line(state, &state->buffer, state->request);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	/* Push the headers */
	status = http_push_headers(mem_ctx, &state->buffer, request);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	/* Push the body */
	status = http_push_body(mem_ctx, &state->buffer, request);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	state->iov.iov_base = (char *) state->buffer.data;
	state->iov.iov_len = state->buffer.length;
	subreq = tstream_writev_queue_send(state, ev, stream, send_queue,
					   &state->iov, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, http_send_request_done, req);

	return req;
}

static void http_send_request_done(struct tevent_req *subreq)
{
	NTSTATUS			status;
	struct tevent_req		*req;
	struct http_send_request_state	*state;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct http_send_request_state);

	state->nwritten = tstream_writev_queue_recv(subreq, &state->sys_errno);
	TALLOC_FREE(subreq);
	if (state->nwritten == -1 && state->sys_errno != 0) {
		status = map_nt_error_from_unix_common(state->sys_errno);
		DEBUG(0, ("%s: Failed to send HTTP request: %s\n",
			  __func__, nt_errstr(status)));
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS http_send_request_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (!req) {
		DEBUG(0, ("%s: Invalid parameter\n", __func__));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);

	return NT_STATUS_OK;
}
