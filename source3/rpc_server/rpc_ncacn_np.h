/*
   Unix SMB/Netbios implementation.
   RPC Server Headers
   Copyright (C) Simo Sorce 2010

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

#ifndef _RPC_NCACN_NP_H_
#define _RPC_NCACN_NP_H_

struct dcerpc_binding_handle;
struct ndr_interface_table;
struct tsocket_address;
struct dcesrv_context;
struct dcesrv_endpoint;

struct npa_state {
	struct tstream_context *stream;

	struct tevent_queue *read_queue;
	struct tevent_queue *write_queue;

	uint64_t allocation_size;
	uint16_t device_state;
	uint16_t file_type;

	void *private_data;
};

NTSTATUS make_external_rpc_pipe(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct tsocket_address *remote_client_address,
				const struct tsocket_address *local_server_address,
				const struct auth_session_info *session_info,
				struct npa_state **pnpa);

NTSTATUS make_internal_rpc_pipe_socketpair(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev_ctx,
	struct messaging_context *msg_ctx,
	struct dcesrv_context *dce_ctx,
	struct dcesrv_endpoint *endpoint,
	const struct tsocket_address *remote_address,
	const struct tsocket_address *local_address,
	const struct auth_session_info *session_info,
	struct npa_state **pnpa);

NTSTATUS rpcint_binding_handle(TALLOC_CTX *mem_ctx,
			       const struct ndr_interface_table *ndr_table,
			       const struct tsocket_address *remote_address,
			       const struct tsocket_address *local_address,
			       const struct auth_session_info *session_info,
			       struct messaging_context *msg_ctx,
			       struct dcerpc_binding_handle **binding_handle);
NTSTATUS rpc_pipe_open_interface(TALLOC_CTX *mem_ctx,
				 const struct ndr_interface_table *table,
				 const struct auth_session_info *session_info,
				 const struct tsocket_address *remote_address,
				 const struct tsocket_address *local_address,
				 struct messaging_context *msg_ctx,
				 struct rpc_pipe_client **cli_pipe);

NTSTATUS rpc_pipe_open_internal(TALLOC_CTX *mem_ctx,
				const struct ndr_interface_table *ndr_table,
				const struct auth_session_info *session_info,
				const struct tsocket_address *remote_address,
				const struct tsocket_address *local_address,
				struct messaging_context *msg_ctx,
				struct rpc_pipe_client **presult);

#endif /* _RPC_NCACN_NP_H_ */
