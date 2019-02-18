/*
 *  RPC Server helper headers
 *  Almost completely rewritten by (C) Jeremy Allison 2005 - 2010
 *  Copyright (C) Simo Sorce <idra@samba.org> - 2010
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

#ifndef _RPC_SERVER_H_
#define _RPC_SERVER_H_

#include "librpc/rpc/rpc_common.h" /* For enum dcerpc_transport_t */

struct pipes_struct;
struct auth_session_info;

typedef bool (*dcerpc_ncacn_disconnect_fn)(struct pipes_struct *p);
typedef void (*named_pipe_termination_fn)(void *private_data);
typedef void (*dcerpc_ncacn_termination_fn)(void *private_data);

struct dcerpc_ncacn_conn {
	enum dcerpc_transport_t transport;

	const char *name;
	int sock;

	struct pipes_struct *p;
	dcerpc_ncacn_disconnect_fn disconnect_fn;
	dcerpc_ncacn_termination_fn termination_fn;
	void *termination_data;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;

	struct tstream_context *tstream;
	struct tevent_queue *send_queue;

	struct tsocket_address *remote_client_addr;
	char *remote_client_name;
	struct tsocket_address *local_server_addr;
	char *local_server_name;
	struct auth_session_info *session_info;

	struct iovec *iov;
	size_t count;
};

struct named_pipe_client {
	const char *pipe_name;

	struct tevent_context *ev;
	struct messaging_context *msg_ctx;

	uint16_t file_type;
	uint16_t device_state;
	uint64_t allocation_size;

	struct tstream_context *tstream;

	struct tsocket_address *remote_client_addr;
	char *remote_client_name;
	struct tsocket_address *local_server_addr;
	char *local_server_name;

	struct auth_session_info *session_info;

	struct pipes_struct *p;

	struct tevent_queue *write_queue;

	struct iovec *iov;
	size_t count;

	named_pipe_termination_fn term_fn;
	void *private_data;
};

struct named_pipe_client *named_pipe_client_init(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev_ctx,
						 struct messaging_context *msg_ctx,
						 const char *pipe_name,
						 named_pipe_termination_fn term_fn,
						 uint16_t file_type,
						 uint16_t device_state,
						 uint64_t allocation_size,
						 void *private_data);

NTSTATUS dcerpc_ncacn_conn_init(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev_ctx,
				struct messaging_context *msg_ctx,
				enum dcerpc_transport_t transport,
				const char *name,
				dcerpc_ncacn_disconnect_fn disconnect_fn,
				dcerpc_ncacn_termination_fn term_fn,
				void *termination_data,
				struct dcerpc_ncacn_conn **out);

int make_server_pipes_struct(TALLOC_CTX *mem_ctx,
			     struct messaging_context *msg_ctx,
			     const char *pipe_name,
			     enum dcerpc_transport_t transport,
			     const struct tsocket_address *remote_address,
			     const struct tsocket_address *local_address,
			     struct auth_session_info **session_info,
			     struct pipes_struct **_p,
			     int *perrno);

void set_incoming_fault(struct pipes_struct *p);
void process_complete_pdu(struct pipes_struct *p, struct ncacn_packet *pkt);
NTSTATUS dcesrv_create_ncacn_np_socket(const char *pipe_name, int *out_fd);
NTSTATUS dcesrv_setup_ncacn_np_socket(const char *pipe_name,
				      struct tevent_context *ev_ctx,
				      struct messaging_context *msg_ctx);
void named_pipe_accept_function(struct tevent_context *ev_ctx,
			        struct messaging_context *msg_ctx,
				const char *pipe_name, int fd,
				named_pipe_termination_fn term_fn,
				void *private_data);
void named_pipe_packet_process(struct tevent_req *subreq);

NTSTATUS dcesrv_create_ncacn_ip_tcp_socket(const struct sockaddr_storage *ifss,
					   uint16_t *port,
					   int *out_fd);
NTSTATUS dcesrv_setup_ncacn_ip_tcp_socket(struct tevent_context *ev_ctx,
					  struct messaging_context *msg_ctx,
					  const struct sockaddr_storage *ifss,
					  uint16_t *port);

NTSTATUS dcesrv_create_ncalrpc_socket(const char *name, int *out_fd);
NTSTATUS dcesrv_setup_ncalrpc_socket(struct tevent_context *ev_ctx,
				     struct messaging_context *msg_ctx,
				     const char *name,
				     dcerpc_ncacn_disconnect_fn fn);

void dcerpc_ncacn_accept(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 enum dcerpc_transport_t transport,
			 const char *name,
			 struct tsocket_address *cli_addr,
			 struct tsocket_address *srv_addr,
			 int s,
			 dcerpc_ncacn_disconnect_fn disconnect_fn,
			 dcerpc_ncacn_termination_fn termination_fn,
			 void *termination_data);

#endif /* _PRC_SERVER_H_ */
