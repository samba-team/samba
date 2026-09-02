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

#ifndef RPC_WORKER_INTERNAL_H
#define RPC_WORKER_INTERNAL_H

#include "librpc/gen_ndr/ndr_rpc_host.h"

struct auth_session_info;
struct dcerpc_binding;
struct tstream_context;
struct tsocket_address;

struct rpc_worker_connection {
	struct rpc_worker_connection *prev, *next;
	struct rpc_worker *worker;

	const char *endpoint;

	char *remote_client_name;
	char *remote_client_addr;
	char *local_server_name;
	struct timeval tv;

	struct tstream_context *tstream;
};

struct rpc_worker {
	struct server_id rpc_host_pid;
	struct messaging_context *msg_ctx;

	struct rpc_worker_status status;

	bool done;
	struct timeval last_connect;
	struct timeval last_disconnect;

	bool is_npsd;
	struct rpc_worker_connection *conns;

	/*
	 * 1. Implementations should
	 * allocate their own per connection
	 * state as talloc child of worker_conn.
	 *
	 * 2. If it wants to keep any of the
	 * arguments which are passed as
	 * pointers to pointers (also
	 * first_pdu->data) after the
	 * call to this function it should
	 * use talloc_move().
	 *
	 * 3. Within this function call worker_conn
	 * should not be free'ed, that's done
	 * by the caller on error, which means
	 * the allocations of 1. can be leaked
	 * on error and cleaned up by the caller.
	 *
	 * 4. It should start the async processing
	 * for the connection.
	 *
	 * 5. When a connection is terminated
	 * after the async processing started and
	 * the accept_client returned NT_STATUS_OK,
	 * talloc_free(worker_conn) should be
	 * called to cleanup all connection state,
	 * which also means rpc_worker_connection_destructor()
	 * and rpc_worker_report_status() are called.
	 */
	NTSTATUS (*accept_client)(
		struct rpc_worker *w,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **transport_session_info,
		struct dcerpc_binding **binding,
		uint8_t _effective_transport,
		const struct named_pipe_auth_rep_info8 *np_info,
		DATA_BLOB *first_pdu,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr);
	void *private_data;
};

int rpc_worker_internal(
	int argc,
	const char *argv[],
	const char *daemon_config_name,
	int num_workers,
	int idle_seconds,
	NTSTATUS (*get_interfaces)(
		void *private_data,
		TALLOC_CTX *mem_ctx,
		char **ifaces),
	NTSTATUS (*setup_servers)(
		struct rpc_worker *worker,
		void *private_data),
	NTSTATUS (*accept_client)(
		struct rpc_worker *worker,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **transport_session_info,
		struct dcerpc_binding **binding,
		uint8_t _effective_transport,
		const struct named_pipe_auth_rep_info8 *np_info,
		DATA_BLOB *first_pdu,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr),
	NTSTATUS (*shutdown_servers)(
		struct rpc_worker *worker,
		void *private_data),
	void *private_data);

#endif /* RPC_WORKER_INTERNAL_H */
