/*
 *  Unix SMB/CIFS implementation.
 *
 *  Simple Named Pipe Echo service
 *
 *  Copyright (C) Stefan Metzmacher 2026
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
#include "lib/global_contexts.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util/tevent_unix.h"
#include "rpc_server/rpc_worker_nps.h"

static const struct nps_interface npsd_echo_msg8_iface = {
	.pipe_name		= "nps_echo_msg8",
	.file_type		= FILE_TYPE_MESSAGE_MODE_PIPE,
	.device_state		= 0xff | 0x0400 | 0x0100,
	.allocation_size	= UINT8_MAX,
};

static const struct nps_interface npsd_echo_msg16_iface = {
	.pipe_name		= "nps_echo_msg16",
	.file_type		= FILE_TYPE_MESSAGE_MODE_PIPE,
	.device_state		= 0xff | 0x0400 | 0x0100,
	.allocation_size	= UINT16_MAX,
};

static size_t npsd_echo_get_interfaces(const struct nps_interface ***pifaces,
				       void *private_data)
{
	static const struct nps_interface *ifaces[] = {
		&npsd_echo_msg8_iface,
		&npsd_echo_msg16_iface,
	};

	*pifaces = ifaces;
	return ARRAY_SIZE(ifaces);
}

static NTSTATUS npsd_echo_setup_servers(struct rpc_worker *worker,
					void *private_data)
{
	DBG_NOTICE("Started (%d)\n", getpid());
	return NT_STATUS_OK;
}

struct npsd_echo_connection {
	struct tevent_context *ev;
	struct rpc_worker_connection *worker_conn;
	struct auth_session_info *session_info;
	struct tstream_context *tstream;
	struct tsocket_address *remote_client_addr;
	struct tsocket_address *local_server_addr;
	size_t max_size;

	struct tevent_req *error_subreq;
	struct tevent_req *in_subreq;
	DATA_BLOB blob;
	struct iovec out_vec;
	struct tevent_req *out_subreq;
};

static int npsd_echo_connection_destructor(
		struct npsd_echo_connection *echo_conn)
{
	/*
	 * First cleanup all subreqs
	 */
	TALLOC_FREE(echo_conn->error_subreq);
	TALLOC_FREE(echo_conn->in_subreq);
	TALLOC_FREE(echo_conn->out_subreq);

	/*
	 * Disconnect the connection
	 */
	TALLOC_FREE(echo_conn->tstream);

	/*
	 * This lets the rpc_worker_connection_destructor
	 * to call rpc_worker_report_status()...
	 */
	TALLOC_FREE(echo_conn->worker_conn);
	return 0;
}

static void npsd_echo_connection_error(struct tevent_req *subreq);
static int npsd_echo_connection_next_vector(struct tstream_context *stream,
					     void *private_data,
					     TALLOC_CTX *mem_ctx,
					     struct iovec **_vector,
					     size_t *_count);
static void npsd_echo_connection_in_done(struct tevent_req *subreq);
static void npsd_echo_connection_out_done(struct tevent_req *subreq);

static NTSTATUS npsd_echo_accept_client(
		struct rpc_worker *worker,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **transport_session_info,
		const char *pipe_name,
		const struct named_pipe_auth_rep_info8 *np_info,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr)
{
	struct tevent_context *ev_ctx = global_event_context();
	struct npsd_echo_connection *echo_conn = NULL;
	struct tevent_req *subreq = NULL;
	size_t max_size;

	if (strcmp(npsd_echo_msg8_iface.pipe_name, pipe_name) == 0) {
		max_size = npsd_echo_msg8_iface.allocation_size;
	} else if (strcmp(npsd_echo_msg16_iface.pipe_name, pipe_name) == 0) {
		max_size = npsd_echo_msg16_iface.allocation_size;
	} else {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	echo_conn = talloc_zero(worker_conn, struct npsd_echo_connection);
	if (echo_conn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	echo_conn->ev = ev_ctx;
	echo_conn->worker_conn = worker_conn;
	echo_conn->session_info = talloc_move(echo_conn, transport_session_info);
	echo_conn->tstream = talloc_move(echo_conn, tstream);
	echo_conn->remote_client_addr = talloc_move(echo_conn, remote_client_addr);
	echo_conn->local_server_addr = talloc_move(echo_conn, local_server_addr);
	echo_conn->max_size = max_size;

	DBG_NOTICE("starting echo server loop max_size=%zu\n", max_size);

	subreq = tstream_monitor_send(echo_conn,
				      echo_conn->ev,
				      echo_conn->tstream);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	echo_conn->error_subreq = subreq;
	tevent_req_set_callback(echo_conn->error_subreq,
				npsd_echo_connection_error,
				echo_conn);

	subreq = tstream_readv_pdu_send(echo_conn,
					echo_conn->ev,
					echo_conn->tstream,
					npsd_echo_connection_next_vector,
					echo_conn);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	echo_conn->in_subreq = subreq;
	tevent_req_set_callback(echo_conn->in_subreq,
				npsd_echo_connection_in_done,
				echo_conn);

	talloc_set_destructor(echo_conn, npsd_echo_connection_destructor);

	return NT_STATUS_OK;
}

static void npsd_echo_connection_error(struct tevent_req *subreq)
{
	struct npsd_echo_connection *echo_conn =
		tevent_req_callback_data(subreq,
		struct npsd_echo_connection);
	int ret;
	int err;

	SMB_ASSERT(echo_conn->error_subreq == subreq);
	echo_conn->error_subreq = NULL;

	ret = tstream_monitor_recv(subreq, &err);
	TALLOC_FREE(subreq);

	DBG_NOTICE("Error: ret=%d err=%d (%s)\n", ret, err, strerror(err));
	TALLOC_FREE(echo_conn);
}

static int npsd_echo_connection_next_vector(struct tstream_context *stream,
					    void *private_data,
					    TALLOC_CTX *mem_ctx,
					    struct iovec **_vector,
					    size_t *_count)
{
	struct npsd_echo_connection *echo_conn =
		talloc_get_type_abort(private_data,
		struct npsd_echo_connection);
	struct iovec *vector = NULL;
	size_t ofs = echo_conn->blob.length;
	ssize_t pending;

	pending = tstream_pending_bytes(stream);
	if (pending < 0) {
		return pending;
	}

	if (pending == 0) {
		if (ofs != 0) {
			return 0;
		}

		echo_conn->blob = data_blob_talloc(echo_conn,
						   NULL,
						   1);
		if (echo_conn->blob.length == 0) {
			return -ENOMEM;
		}
	} else {
		size_t max_size = MIN(UINT16_MAX, echo_conn->max_size);
		size_t full_length;
		bool ok;

		if (pending > max_size) {
			return -EPROTO;
		}
		if (ofs > max_size) {
			return -EPROTO;
		}
		full_length = ofs + pending;
		if (full_length > max_size) {
			return -EPROTO;
		}

		ok = data_blob_realloc(echo_conn,
				       &echo_conn->blob,
				       full_length);
		if (!ok) {
			return -ENOMEM;
		}
	}

	vector = talloc(mem_ctx, struct iovec);
	if (vector == NULL) {
		return -ENOMEM;
	}
	vector->iov_base = echo_conn->blob.data + ofs;
	vector->iov_len = echo_conn->blob.length - ofs;

	*_vector = vector;
	*_count = 1;
	return 0;
}

static void npsd_echo_connection_in_done(struct tevent_req *subreq)
{
	struct npsd_echo_connection *echo_conn =
		tevent_req_callback_data(subreq,
		struct npsd_echo_connection);
	int ret;
	int err;

	SMB_ASSERT(echo_conn->in_subreq == subreq);
	echo_conn->in_subreq = NULL;

	ret = tstream_readv_pdu_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		DBG_ERR("tstream_readv_pdu_recv() ret=%d err=%d (%s)\n",
			ret, err, strerror(err));
		TALLOC_FREE(echo_conn);
		return;
	}

	echo_conn->out_vec.iov_base = echo_conn->blob.data;
	echo_conn->out_vec.iov_len = echo_conn->blob.length;

	subreq = tstream_writev_send(echo_conn,
				     echo_conn->ev,
				     echo_conn->tstream,
				     &echo_conn->out_vec,
				     1);
	if (subreq == NULL) {
		DBG_ERR("tstream_writev_send() failed\n");
		TALLOC_FREE(echo_conn);
		return;
	}
	echo_conn->out_subreq = subreq;
	tevent_req_set_callback(echo_conn->out_subreq,
				npsd_echo_connection_out_done,
				echo_conn);
	return;
}

static void npsd_echo_connection_out_done(struct tevent_req *subreq)
{
	struct npsd_echo_connection *echo_conn =
		tevent_req_callback_data(subreq,
		struct npsd_echo_connection);
	int ret;
	int err;

	SMB_ASSERT(echo_conn->out_subreq == subreq);
	echo_conn->out_subreq = NULL;

	echo_conn->out_vec = (struct iovec) { .iov_len = 0, };
	data_blob_free(&echo_conn->blob);

	ret = tstream_writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		DBG_ERR("tstream_writev_recv() ret=%d err=%d (%s)\n",
			ret, err, strerror(err));
		TALLOC_FREE(echo_conn);
		return;
	}

	subreq = tstream_readv_pdu_send(echo_conn,
					echo_conn->ev,
					echo_conn->tstream,
					npsd_echo_connection_next_vector,
					echo_conn);
	if (subreq == NULL) {
		DBG_ERR("tstream_readv_pdu_send() failed\n");
		TALLOC_FREE(echo_conn);
		return;
	}
	echo_conn->in_subreq = subreq;
	tevent_req_set_callback(echo_conn->in_subreq,
				npsd_echo_connection_in_done,
				echo_conn);
	return;
}

static NTSTATUS npsd_echo_shutdown_servers(struct rpc_worker *worker,
					   void *private_data)
{
	DBG_DEBUG("server exiting\n");
	return NT_STATUS_OK;
}

int main(int argc, const char *argv[])
{
	return nps_worker_main(
		argc,
		argv,
		"npsd_echo_server",
		5,
		60,
		npsd_echo_get_interfaces,
		npsd_echo_setup_servers,
		npsd_echo_accept_client,
		npsd_echo_shutdown_servers,
		NULL);
}
