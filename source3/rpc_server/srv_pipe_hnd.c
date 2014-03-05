/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Largely re-written : 2005
 *  Copyright (C) Jeremy Allison		1998 - 2005
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
#include "fake_file.h"
#include "rpc_dce.h"
#include "ntdomain.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "rpc_server/srv_pipe.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_config.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_ntstatus.h"
#include "librpc/ndr/ndr_table.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

bool fsp_is_np(struct files_struct *fsp)
{
	enum FAKE_FILE_TYPE type;

	if ((fsp == NULL) || (fsp->fake_file_handle == NULL)) {
		return false;
	}

	type = fsp->fake_file_handle->type;

	return (type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY);
}

NTSTATUS np_open(TALLOC_CTX *mem_ctx, const char *name,
		 const struct tsocket_address *local_address,
		 const struct tsocket_address *remote_address,
		 struct auth_session_info *session_info,
		 struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx,
		 struct fake_file_handle **phandle)
{
	enum rpc_service_mode_e pipe_mode;
	const char **proxy_list;
	struct fake_file_handle *handle;
	struct ndr_syntax_id syntax;
	struct npa_state *npa = NULL;
	NTSTATUS status;
	bool ok;

	proxy_list = lp_parm_string_list(-1, "np", "proxy", NULL);

	handle = talloc(mem_ctx, struct fake_file_handle);
	if (handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Check what is the server type for this pipe.
	   Defaults to "embedded" */
	pipe_mode = rpc_service_mode(name);

	/* Still support the old method for defining external servers */
	if ((proxy_list != NULL) && str_list_check_ci(proxy_list, name)) {
		pipe_mode = RPC_SERVICE_MODE_EXTERNAL;
	}

	switch (pipe_mode) {
	case RPC_SERVICE_MODE_EXTERNAL:
		status = make_external_rpc_pipe(handle,
						name,
						local_address,
						remote_address,
						session_info,
						&npa);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(handle);
			return status;
		}

		handle->private_data = (void *)npa;
		handle->type = FAKE_FILE_TYPE_NAMED_PIPE_PROXY;

		break;
	case RPC_SERVICE_MODE_EMBEDDED:
		/* Check if we handle this pipe internally */
		ok = is_known_pipename(name, &syntax);
		if (!ok) {
			DEBUG(2, ("'%s' is not a registered pipe!\n", name));
			talloc_free(handle);
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		status = make_internal_rpc_pipe_socketpair(handle,
							   ev_ctx,
							   msg_ctx,
							   name,
							   &syntax,
							   remote_address,
							   session_info,
							   &npa);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(handle);
			return status;
		}

		handle->private_data = (void *)npa;
		handle->type = FAKE_FILE_TYPE_NAMED_PIPE_PROXY;

		break;
	case RPC_SERVICE_MODE_DISABLED:
		talloc_free(handle);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	*phandle = handle;

	return NT_STATUS_OK;
}

bool np_read_in_progress(struct fake_file_handle *handle)
{
	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		struct npa_state *p =
			talloc_get_type_abort(handle->private_data,
					      struct npa_state);
		size_t read_count;

		read_count = tevent_queue_length(p->read_queue);
		if (read_count > 0) {
			return true;
		}

		return false;
	}

	return false;
}

struct np_write_state {
	struct tevent_context *ev;
	struct npa_state *p;
	struct iovec iov;
	ssize_t nwritten;
};

static void np_write_done(struct tevent_req *subreq);

struct tevent_req *np_write_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				 struct fake_file_handle *handle,
				 const uint8_t *data, size_t len)
{
	struct tevent_req *req;
	struct np_write_state *state;
	NTSTATUS status;

	DEBUG(6, ("np_write_send: len: %d\n", (int)len));
	dump_data(50, data, len);

	req = tevent_req_create(mem_ctx, &state, struct np_write_state);
	if (req == NULL) {
		return NULL;
	}

	if (len == 0) {
		state->nwritten = 0;
		status = NT_STATUS_OK;
		goto post_status;
	}

	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		struct npa_state *p = talloc_get_type_abort(
			handle->private_data, struct npa_state);
		struct tevent_req *subreq;

		state->ev = ev;
		state->p = p;
		state->iov.iov_base = discard_const_p(void, data);
		state->iov.iov_len = len;

		subreq = tstream_writev_queue_send(state, ev,
						   p->stream,
						   p->write_queue,
						   &state->iov, 1);
		if (subreq == NULL) {
			goto fail;
		}
		tevent_req_set_callback(subreq, np_write_done, req);
		return req;
	}

	status = NT_STATUS_INVALID_HANDLE;
 post_status:
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
	} else {
		tevent_req_nterror(req, status);
	}
	return tevent_req_post(req, ev);
 fail:
	TALLOC_FREE(req);
	return NULL;
}

static void np_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_write_state *state = tevent_req_data(
		req, struct np_write_state);
	ssize_t received;
	int err;

	received = tstream_writev_queue_recv(subreq, &err);
	if (received < 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}
	state->nwritten = received;
	tevent_req_done(req);
}

NTSTATUS np_write_recv(struct tevent_req *req, ssize_t *pnwritten)
{
	struct np_write_state *state = tevent_req_data(
		req, struct np_write_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pnwritten = state->nwritten;
	return NT_STATUS_OK;
}

struct np_ipc_readv_next_vector_state {
	uint8_t *buf;
	size_t len;
	off_t ofs;
	size_t remaining;
};

static void np_ipc_readv_next_vector_init(struct np_ipc_readv_next_vector_state *s,
					  uint8_t *buf, size_t len)
{
	ZERO_STRUCTP(s);

	s->buf = buf;
	s->len = MIN(len, UINT16_MAX);
}

static int np_ipc_readv_next_vector(struct tstream_context *stream,
				    void *private_data,
				    TALLOC_CTX *mem_ctx,
				    struct iovec **_vector,
				    size_t *count)
{
	struct np_ipc_readv_next_vector_state *state =
		(struct np_ipc_readv_next_vector_state *)private_data;
	struct iovec *vector;
	ssize_t pending;
	size_t wanted;

	if (state->ofs == state->len) {
		*_vector = NULL;
		*count = 0;
		return 0;
	}

	pending = tstream_pending_bytes(stream);
	if (pending == -1) {
		return -1;
	}

	if (pending == 0 && state->ofs != 0) {
		/* return a short read */
		*_vector = NULL;
		*count = 0;
		return 0;
	}

	if (pending == 0) {
		/* we want at least one byte and recheck again */
		wanted = 1;
	} else {
		size_t missing = state->len - state->ofs;
		if (pending > missing) {
			/* there's more available */
			state->remaining = pending - missing;
			wanted = missing;
		} else {
			/* read what we can get and recheck in the next cycle */
			wanted = pending;
		}
	}

	vector = talloc_array(mem_ctx, struct iovec, 1);
	if (!vector) {
		return -1;
	}

	vector[0].iov_base = state->buf + state->ofs;
	vector[0].iov_len = wanted;

	state->ofs += wanted;

	*_vector = vector;
	*count = 1;
	return 0;
}

struct np_read_state {
	struct npa_state *p;
	struct np_ipc_readv_next_vector_state next_vector;

	ssize_t nread;
	bool is_data_outstanding;
};

static void np_read_done(struct tevent_req *subreq);

struct tevent_req *np_read_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct fake_file_handle *handle,
				uint8_t *data, size_t len)
{
	struct tevent_req *req;
	struct np_read_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct np_read_state);
	if (req == NULL) {
		return NULL;
	}

	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		struct npa_state *p = talloc_get_type_abort(
			handle->private_data, struct npa_state);
		struct tevent_req *subreq;

		np_ipc_readv_next_vector_init(&state->next_vector,
					      data, len);

		subreq = tstream_readv_pdu_queue_send(state,
						      ev,
						      p->stream,
						      p->read_queue,
						      np_ipc_readv_next_vector,
						      &state->next_vector);
		if (subreq == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto post_status;
		}
		tevent_req_set_callback(subreq, np_read_done, req);
		return req;
	}

	status = NT_STATUS_INVALID_HANDLE;
 post_status:
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
	} else {
		tevent_req_nterror(req, status);
	}
	return tevent_req_post(req, ev);
}

static void np_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_read_state *state = tevent_req_data(
		req, struct np_read_state);
	ssize_t ret;
	int err;

	ret = tstream_readv_pdu_queue_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	state->nread = ret;
	state->is_data_outstanding = (state->next_vector.remaining > 0);

	tevent_req_done(req);
	return;
}

NTSTATUS np_read_recv(struct tevent_req *req, ssize_t *nread,
		      bool *is_data_outstanding)
{
	struct np_read_state *state = tevent_req_data(
		req, struct np_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	DEBUG(10, ("Received %d bytes. There is %smore data outstanding\n",
		   (int)state->nread, state->is_data_outstanding?"":"no "));

	*nread = state->nread;
	*is_data_outstanding = state->is_data_outstanding;
	return NT_STATUS_OK;
}
