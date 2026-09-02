/*
 *  Unix SMB/CIFS implementation.
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

#include "source3/include/includes.h"
#include "rpc_worker_internal.h"
#include "rpc_worker_nps.h"
#include "librpc/rpc/rpc_common.h"

struct rpc_worker_nps_state {
	size_t (*get_interfaces)(
		const struct nps_interface ***ifaces,
		void *private_data);
	NTSTATUS (*setup_servers)(
		struct rpc_worker *worker,
		void *private_data);
	NTSTATUS (*accept_client)(
		struct rpc_worker *worker,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **transport_session_info,
		const char *pipe_name,
		const struct named_pipe_auth_rep_info8 *np_info,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr);
	NTSTATUS (*shutdown_servers)(
		struct rpc_worker *worker,
		void *private_data);
	void *private_data;
};

static NTSTATUS rpc_worker_nps_get_interfaces(void *private_data,
					      TALLOC_CTX *mem_ctx,
					      char **_ifaces)
{
	struct rpc_worker_nps_state *nworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_nps_state);
	const struct nps_interface **ifaces = NULL;
	size_t num_ifaces;
	size_t idx_ifaces;
	char *str = NULL;

	num_ifaces = nworker->get_interfaces(&ifaces,
					     nworker->private_data);

	str = talloc_strdup(mem_ctx, "");

	for (idx_ifaces = 0; idx_ifaces < num_ifaces; idx_ifaces++) {
		const struct nps_interface *iface = ifaces[idx_ifaces];

		talloc_asprintf_addbuf(&str,
				       "\\pipe\\%s %" PRIu16 " %" PRIu16
				       " %" PRIu64 "\n",
				       iface->pipe_name,
				       iface->file_type,
				       iface->device_state,
				       iface->allocation_size);
	}

	if (str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*_ifaces = str;
	return NT_STATUS_OK;
}

static NTSTATUS rpc_worker_nps_setup_servers(struct rpc_worker *worker,
					     void *private_data)
{
	struct rpc_worker_nps_state *nworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_nps_state);

	worker->is_npsd = true;
	return nworker->setup_servers(worker, nworker->private_data);
}

static NTSTATUS rpc_worker_nps_accept_client(
		struct rpc_worker *worker,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **transport_session_info,
		struct dcerpc_binding **_b,
		uint8_t _effective_transport,
		const struct named_pipe_auth_rep_info8 *np_info,
		DATA_BLOB *first_pdu,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr)
{
	struct rpc_worker_nps_state *nworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_nps_state);
	const struct dcerpc_binding *b = talloc_move(worker_conn, _b);
	enum dcerpc_transport_t transport;
	const char *pipe_name = NULL;
	struct security_token *token = NULL;
	uint32_t npa_flags;
	bool npa_found;

	transport = dcerpc_binding_get_transport(b);
	if (transport != NCACN_NP) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}
	if (_effective_transport != transport) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}
	pipe_name = dcerpc_binding_get_string_option(b, "endpoint");
	if (pipe_name == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}
	if (strncmp(pipe_name, "\\pipe\\", 6) != 0) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}
	pipe_name += 6;
	if (pipe_name[0] == '\0') {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}
	if (first_pdu->length != 0) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	token = (*transport_session_info)->security_token;
	npa_found = security_token_find_npa_flags(token, &npa_flags);
	if (npa_found) {
		/*
		 * We don't want to pass these along
		 */
		security_token_del_npa_flags(token);
	}

	return nworker->accept_client(worker,
				      nworker->private_data,
				      worker_conn,
				      transport_session_info,
				      pipe_name,
				      np_info,
				      tstream,
				      remote_client_addr,
				      local_server_addr);
}

static NTSTATUS rpc_worker_nps_shutdown_servers(struct rpc_worker *worker,
					        void *private_data)
{
	struct rpc_worker_nps_state *nworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_nps_state);

	return nworker->shutdown_servers(worker, nworker->private_data);
}

/**
 * @brief Main function for Named Pipe server implementations
 *
 * This function provides all that is necessary to run a
 * Named Pipe server inside the samba-dcerpcd framework.
 *
 * The get_interfaces() callback provides the information that is
 * passed to samba-dcerpcd via --list-interfaces, it should not do any
 * real server initialization work. Quickly after this function is
 * called by nps_worker_main, the process exits again. It should
 * return the number of interfaces provided.
 *
 * setup_servers() is called when the process is about to do the real
 * work. So more heavy-weight initialization should happen here. It
 * should return NT_STATUS_OK.
 *
 * accept_client() is called when a new connection arrived:
 *
 *   1. Implementations should
 *   allocate their own per connection
 *   state as talloc child of worker_conn.
 *
 *   2. If it wants to keep any of the
 *   arguments which are passed as
 *   pointers to pointers (also
 *   first_pdu->data) after the
 *   call to this function it should
 *   use talloc_move().
 *
 *   3. Within this function call worker_conn
 *   should not be free'ed, that's done
 *   by the caller on error, which means
 *   the allocations of 1. can be leaked
 *   on error and cleaned up by the caller.
 *
 *   4. It should start the async processing
 *   for the connection.
 *
 *   5. When a connection is terminated
 *   after the async processing started and
 *   the accept_client returned NT_STATUS_OK,
 *   talloc_free(worker_conn) should be
 *   called to cleanup all connection state,
 *   which also means rpc_worker_connection_destructor()
 *   and rpc_worker_report_status() are called.
 *
 * shutdown_servers() is called when the process is about to exit.
 * So the state created by setup_servers() should be removed again.
 *
 * @param[in] argc argc from main()
 * @param[in] argv argv from main()
 * @param[in] get_interfaces List all interfaces that this server provides
 * @param[in] setup_servers Initialize the service before accepting connections
 * @param[in] accept_client A function called when a new connection arrived
 * @param[in] shutdown_servers Shutdown the service global state
 * @param[in] private_data Passed to the callback functions
 * @return 0 It should never return except on successful process exit
 */
int nps_worker_main(
	int argc,
	const char *argv[],
	const char *daemon_config_name,
	int num_workers,
	int idle_seconds,
	size_t (*get_interfaces)(
		const struct nps_interface ***ifaces,
		void *private_data),
	NTSTATUS (*setup_servers)(
		struct rpc_worker *worker,
		void *private_data),
	NTSTATUS (*accept_client)(
		struct rpc_worker *worker,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **transport_session_info,
		const char *pipe_name,
		const struct named_pipe_auth_rep_info8 *np_info,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr),
	NTSTATUS (*shutdown_servers)(
		struct rpc_worker *worker,
		void *private_data),
	void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_worker_nps_state *nworker = NULL;
	int ret;

	nworker = talloc_zero(frame, struct rpc_worker_nps_state);
	if (nworker == NULL) {
		DBG_ERR("talloc_zero(struct rpc_worker_nps_state) failed\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	*nworker = (struct rpc_worker_nps_state) {
		.get_interfaces = get_interfaces,
		.setup_servers = setup_servers,
		.accept_client = accept_client,
		.shutdown_servers = shutdown_servers,
		.private_data = private_data,
	};

	ret = rpc_worker_internal(argc,
				  argv,
				  daemon_config_name,
				  num_workers,
				  idle_seconds,
				  rpc_worker_nps_get_interfaces,
				  rpc_worker_nps_setup_servers,
				  rpc_worker_nps_accept_client,
				  rpc_worker_nps_shutdown_servers,
				  nworker);

	TALLOC_FREE(frame);
	return ret;
}
