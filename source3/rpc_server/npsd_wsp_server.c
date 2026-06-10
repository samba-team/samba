/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c)  Stefan Metzmacher
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
#include "messages.h"
#include "lib/global_contexts.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "rpc_server/rpc_worker_nps.h"
#include "rpc_server/wsp/wsp_gss.h"
#include "librpc/gen_ndr/ndr_wsp.h"
#include "smbd/proto.h"

#ifdef HAVE_WSP_BACKEND_ES
void init_elastic_wsp_abs_interace(void);
#endif

struct wsp_server_worker {
	struct wsp_gss_state *wsp_gss_state;
};

static const struct nps_interface nps_msftewds = {
	.pipe_name		= "msftewds",
	.file_type		= FILE_TYPE_MESSAGE_MODE_PIPE,
	.device_state		= 0xff | 0x0400 | 0x0100,
	.allocation_size	= 3072,
};

static size_t wsp_server_get_interfaces(
		const struct nps_interface ***pifaces,
		void *private_data)
{
	static const struct nps_interface *ifaces[] = {
		&nps_msftewds,
	};

	if (lp_wsp_backend() != WSP_BACKEND_NONE) {
		*pifaces = ifaces;
		return ARRAY_SIZE(ifaces);
	}

	*pifaces = NULL;
	return 0;
}

static NTSTATUS wsp_server_setup_servers(
		struct rpc_worker *worker,
		void *private_data)
{
	struct wsp_server_worker *wworker =
		(struct wsp_server_worker *)private_data;
	struct messaging_context *msg_ctx = global_messaging_context();
	struct tevent_context *ev_ctx = messaging_tevent_context(msg_ctx);
	struct wsp_gss_state *wsp_gss_state = NULL;

	/* load smb.conf */
	lp_load_with_shares(get_dyn_CONFIGFILE());

	/*
	 * #TODO In the future we probably need to think about bundling
	 *       backend specifics in their own library, loaded dynamically
	 *       and then initialise. For the moment we emulate that type
	 *       of mechanism and manually call the backend initialisation.
	 */
#ifdef HAVE_WSP_BACKEND_ES
	init_elastic_wsp_abs_interace();
#endif
	mangle_reset_cache();

	wsp_gss_state = wsp_gss_state_create(ev_ctx);
	if (wsp_gss_state == NULL) {
		DBG_ERR("failed to create GSS state\n");
		return NT_STATUS_NO_MEMORY;
	}

	if (!wsp_gss_init(wsp_gss_state)) {
		DBG_ERR("Failed to initialise the gss\n");
		return NT_STATUS_FAILED_DRIVER_ENTRY;
	}

	wworker->wsp_gss_state = wsp_gss_state;

	DBG_NOTICE("WSP Worker Started (%d)\n", getpid());
	return NT_STATUS_OK;
}

struct wsp_server_connection {
	struct tevent_context *ev;
	struct rpc_worker_connection *worker_conn;
	struct auth_session_info *session_info;
	struct tstream_context *tstream;
	struct tsocket_address *remote_client_addr;
	struct tsocket_address *local_server_addr;

	struct wspd_client_state *client_state;

	struct tevent_req *error_subreq;
	DATA_BLOB in_blob;
	struct tevent_req *in_subreq;
	struct tevent_req *request_subreq;
	DATA_BLOB out_blob;
	struct iovec out_vec;
	struct tevent_req *out_subreq;
};

static int wsp_server_connection_destructor(
				struct wsp_server_connection *wsp_conn)
{
	/*
	 * First cleanup all subreqs
	 */
	TALLOC_FREE(wsp_conn->error_subreq);
	TALLOC_FREE(wsp_conn->in_subreq);
	TALLOC_FREE(wsp_conn->request_subreq);
	TALLOC_FREE(wsp_conn->out_subreq);

	/*
	 * Disconnect the connection
	 */
	TALLOC_FREE(wsp_conn->tstream);

	if (wsp_conn->client_state != NULL) {
		/*
		 * We passed wsp_conn->session_info to
		 * create_client_state() and client_disconnected()
		 * goes async, so we make sure wsp_conn->session_info
		 * stays...
		 */
		talloc_steal(wsp_conn->client_state, wsp_conn->session_info);
		wsp_gss_client_state_destroy(wsp_conn->client_state,
					     wsp_conn->ev);
	}

	/*
	 * This lets the rpc_worker_connection_destructor
	 * to call rpc_worker_report_status()...
	 */
	TALLOC_FREE(wsp_conn->worker_conn);
	return 0;
}

static void wsp_server_connection_error(struct tevent_req *subreq);
static int wsp_server_connection_next_vector(struct tstream_context *stream,
					     void *private_data,
					     TALLOC_CTX *mem_ctx,
					     struct iovec **_vector,
					     size_t *_count);
static void wsp_server_connection_in_done(struct tevent_req *subreq);
static void wsp_server_connection_request_done(struct tevent_req *subreq);
static void wsp_server_connection_out_done(struct tevent_req *subreq);

static NTSTATUS wsp_server_accept_client(
		struct rpc_worker *worker,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **transport_session_info,
		const char *pipe_name,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr)
{
	struct messaging_context *msg_ctx = global_messaging_context();
	struct tevent_context *ev_ctx = messaging_tevent_context(msg_ctx);
	struct wsp_server_worker *wworker =
		(struct wsp_server_worker *)private_data;
	struct wsp_gss_state *wsp_gss_state =
		talloc_get_type_abort(wworker->wsp_gss_state,
		struct wsp_gss_state);
	struct wsp_server_connection *wsp_conn = NULL;
	struct tevent_req *subreq = NULL;

	if (strcmp(nps_msftewds.pipe_name, pipe_name) != 0) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	wsp_conn = talloc_zero(worker_conn, struct wsp_server_connection);
	if (wsp_conn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	wsp_conn->ev = ev_ctx;
	wsp_conn->worker_conn = worker_conn;
	wsp_conn->session_info = talloc_move(wsp_conn, transport_session_info);
	wsp_conn->tstream = talloc_move(wsp_conn, tstream);
	wsp_conn->remote_client_addr = talloc_move(wsp_conn, remote_client_addr);
	wsp_conn->local_server_addr = talloc_move(wsp_conn, local_server_addr);

	wsp_conn->client_state = wsp_gss_client_state_create(
		wsp_conn->session_info,
		wsp_gss_state);
	if (wsp_conn->client_state == NULL) {
		DBG_ERR("Failed to create client state\n");
		return NT_STATUS_NO_MEMORY;
	}

	DBG_NOTICE("starting wsp server loop \n");

	subreq = tstream_monitor_send(wsp_conn,
				      wsp_conn->ev,
				      wsp_conn->tstream);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	wsp_conn->error_subreq = subreq;
	tevent_req_set_callback(wsp_conn->error_subreq,
				wsp_server_connection_error,
				wsp_conn);

	subreq = tstream_readv_pdu_send(wsp_conn,
					wsp_conn->ev,
					wsp_conn->tstream,
					wsp_server_connection_next_vector,
					wsp_conn);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	wsp_conn->in_subreq = subreq;
	tevent_req_set_callback(wsp_conn->in_subreq,
				wsp_server_connection_in_done,
				wsp_conn);

	talloc_set_destructor(wsp_conn, wsp_server_connection_destructor);

	return NT_STATUS_OK;
}

static void wsp_server_connection_error(struct tevent_req *subreq)
{
	struct wsp_server_connection *wsp_conn =
		tevent_req_callback_data(subreq,
		struct wsp_server_connection);
	int ret;
	int err;

	SMB_ASSERT(wsp_conn->error_subreq == subreq);
	wsp_conn->error_subreq = NULL;

	ret = tstream_monitor_recv(subreq, &err);
	TALLOC_FREE(subreq);

	DBG_NOTICE("tstream_monitor_recv: ret=%d err=%d (%s)\n",
		   ret, err, strerror(err));
	TALLOC_FREE(wsp_conn);
}

static int wsp_server_connection_next_vector(struct tstream_context *stream,
					     void *private_data,
					     TALLOC_CTX *mem_ctx,
					     struct iovec **_vector,
					     size_t *_count)
{
	struct wsp_server_connection *wsp_conn =
		talloc_get_type_abort(private_data,
		struct wsp_server_connection);
	struct iovec *vector = NULL;
	size_t ofs = wsp_conn->in_blob.length;
	ssize_t pending;

	pending = tstream_pending_bytes(stream);
	if (pending < 0) {
		return pending;
	}

	if (pending == 0) {
		if (ofs != 0) {
			return 0;
		}

		wsp_conn->in_blob = data_blob_talloc(wsp_conn,
						     NULL,
						     1);
		if (wsp_conn->in_blob.length == 0) {
			return -ENOMEM;
		}
	} else {
		size_t full_length;
		bool ok;

		if (pending > UINT16_MAX) {
			return -EPROTO;
		}
		if (ofs > UINT16_MAX) {
			return -EPROTO;
		}
		full_length = ofs + pending;
		if (full_length > UINT16_MAX) {
			return -EPROTO;
		}

		ok = data_blob_realloc(wsp_conn,
				       &wsp_conn->in_blob,
				       full_length);
		if (!ok) {
			return -ENOMEM;
		}
	}

	vector = talloc(mem_ctx, struct iovec);
	if (vector == NULL) {
		return -ENOMEM;
	}
	vector->iov_base = wsp_conn->in_blob.data + ofs;
	vector->iov_len = wsp_conn->in_blob.length - ofs;

	*_vector = vector;
	*_count = 1;
	return 0;
}

static void wsp_server_connection_in_done(struct tevent_req *subreq)
{
	struct wsp_server_connection *wsp_conn =
		tevent_req_callback_data(subreq,
		struct wsp_server_connection);
	int ret;
	int err;

	SMB_ASSERT(wsp_conn->in_subreq == subreq);
	wsp_conn->in_subreq = NULL;

	ret = tstream_readv_pdu_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		DBG_NOTICE("tstream_readv_pdu_recv failed ret=%d err=%d (%s)\n",
			   ret, err, strerror(err));
		TALLOC_FREE(wsp_conn);
		return;
	}

	subreq = wsp_request_send(wsp_conn->client_state,
				  wsp_conn->ev,
				  wsp_conn->client_state,
				  &wsp_conn->in_blob);
	if (subreq == NULL) {
		TALLOC_FREE(wsp_conn);
		return;
	}
	wsp_conn->request_subreq = subreq;
	tevent_req_set_callback(wsp_conn->request_subreq,
				wsp_server_connection_request_done,
				wsp_conn);
	return;
}

static void wsp_server_connection_request_done(struct tevent_req *subreq)
{
	struct wsp_server_connection *wsp_conn =
		tevent_req_callback_data(subreq,
		struct wsp_server_connection);
	NTSTATUS status;

	SMB_ASSERT(wsp_conn->request_subreq == subreq);
	wsp_conn->request_subreq = NULL;

	data_blob_free(&wsp_conn->in_blob);

	status = wsp_request_recv(subreq, wsp_conn, &wsp_conn->out_blob);
	TALLOC_FREE(subreq);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("wsp_request_recv: %s\n", nt_errstr(status));
		TALLOC_FREE(wsp_conn);
		return;
	}
	wsp_conn->out_vec.iov_base = wsp_conn->out_blob.data;
	wsp_conn->out_vec.iov_len = wsp_conn->out_blob.length;

	subreq = tstream_writev_send(wsp_conn,
				     wsp_conn->ev,
				     wsp_conn->tstream,
				     &wsp_conn->out_vec,
				     1);
	if (subreq == NULL) {
		TALLOC_FREE(wsp_conn);
		return;
	}
	wsp_conn->out_subreq = subreq;
	tevent_req_set_callback(wsp_conn->out_subreq,
				wsp_server_connection_out_done,
				wsp_conn);
	return;
}

static void wsp_server_connection_out_done(struct tevent_req *subreq)
{
	struct wsp_server_connection *wsp_conn =
		tevent_req_callback_data(subreq,
		struct wsp_server_connection);
	int ret;
	int err;

	SMB_ASSERT(wsp_conn->out_subreq == subreq);
	wsp_conn->out_subreq = NULL;

	wsp_conn->out_vec = (struct iovec) { .iov_len = 0, };
	data_blob_free(&wsp_conn->out_blob);

	ret = tstream_writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		DBG_NOTICE("tstream_writev_recv: ret=%d err=%d (%s)\n",
			   ret, err, strerror(err));
		TALLOC_FREE(wsp_conn);
		return;
	}

	subreq = tstream_readv_pdu_send(wsp_conn,
					wsp_conn->ev,
					wsp_conn->tstream,
					wsp_server_connection_next_vector,
					wsp_conn);
	if (subreq == NULL) {
		TALLOC_FREE(wsp_conn);
		return;
	}
	wsp_conn->in_subreq = subreq;
	tevent_req_set_callback(wsp_conn->in_subreq,
				wsp_server_connection_in_done,
				wsp_conn);
	return;
}

static NTSTATUS wsp_server_shutdown_servers(
		struct rpc_worker *worker,
		void *private_data)
{
	struct wsp_server_worker *wworker =
		(struct wsp_server_worker *)private_data;
	DBG_DEBUG("server exiting\n");
	TALLOC_FREE(wworker->wsp_gss_state);
	return NT_STATUS_OK;
}

int main(int argc, const char *argv[])
{
	struct wsp_server_worker wworker = { .wsp_gss_state = NULL, };

	return nps_worker_main(
		argc,
		argv,
		"npsd_wsp_server",
		1,
		60,
		wsp_server_get_interfaces,
		wsp_server_setup_servers,
		wsp_server_accept_client,
		wsp_server_shutdown_servers,
		&wworker);
}
