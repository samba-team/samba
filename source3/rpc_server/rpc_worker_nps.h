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

#ifndef __RPC_WORKER_NPS_H__
#define __RPC_WORKER_NPS_H__

#include "replace.h"

struct rpc_worker;
struct rpc_worker_connection;

struct auth_session_info;
struct tstream_context;
struct tsocket_address;

struct nps_interface {
	const char *pipe_name;
	uint16_t file_type;
	uint16_t device_state;
	uint64_t allocation_size;
};

struct named_pipe_auth_rep_info8;

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
	void *private_data);

#endif /* __RPC_WORKER_H__ */
