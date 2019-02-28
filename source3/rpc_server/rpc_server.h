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

#include "librpc/rpc/dcesrv_core.h"

struct pipes_struct;
struct auth_session_info;
struct cli_credentials;

typedef void (*dcerpc_ncacn_termination_fn)(struct dcesrv_connection *,
					    void *);

struct dcerpc_ncacn_conn {
	int sock;

	struct pipes_struct *p;
	dcerpc_ncacn_termination_fn termination_fn;
	void *termination_data;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx;
	struct dcesrv_endpoint *endpoint;

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

NTSTATUS dcerpc_ncacn_conn_init(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev_ctx,
				struct messaging_context *msg_ctx,
				struct dcesrv_context *dce_ctx,
				struct dcesrv_endpoint *endpoint,
				dcerpc_ncacn_termination_fn term_fn,
				void *termination_data,
				struct dcerpc_ncacn_conn **out);

int make_server_pipes_struct(TALLOC_CTX *mem_ctx,
			     struct messaging_context *msg_ctx,
			     const char *pipe_name,
			     enum dcerpc_transport_t transport,
			     const struct tsocket_address *remote_address,
			     const struct tsocket_address *local_address,
			     struct pipes_struct **_p,
			     int *perrno);

void set_incoming_fault(struct pipes_struct *p);
void process_complete_pdu(struct pipes_struct *p, struct ncacn_packet *pkt);
NTSTATUS dcesrv_create_ncacn_np_socket(struct dcesrv_endpoint *e, int *out_fd);
NTSTATUS dcesrv_setup_ncacn_np_socket(struct tevent_context *ev_ctx,
				      struct messaging_context *msg_ctx,
				      struct dcesrv_context *dce_ctx,
				      struct dcesrv_endpoint *e,
				      dcerpc_ncacn_termination_fn term_fn,
				      void *term_data);

NTSTATUS dcesrv_create_ncacn_ip_tcp_socket(const struct sockaddr_storage *ifss,
					   uint16_t *port,
					   int *out_fd);
NTSTATUS dcesrv_setup_ncacn_ip_tcp_socket(struct tevent_context *ev_ctx,
					  struct messaging_context *msg_ctx,
					  struct dcesrv_context *dce_ctx,
					  struct dcesrv_endpoint *e,
					  const struct sockaddr_storage *ifss,
					  dcerpc_ncacn_termination_fn term_fn,
					  void *term_data);

NTSTATUS dcesrv_create_ncalrpc_socket(struct dcesrv_endpoint *e, int *fd);
NTSTATUS dcesrv_setup_ncalrpc_socket(struct tevent_context *ev_ctx,
				     struct messaging_context *msg_ctx,
				     struct dcesrv_context *dce_ctx,
				     struct dcesrv_endpoint *e,
				     dcerpc_ncacn_termination_fn term_fn,
				     void *termination_data);

void dcerpc_ncacn_accept(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 struct dcesrv_context *dce_ctx,
			 struct dcesrv_endpoint *e,
			 struct tsocket_address *cli_addr,
			 struct tsocket_address *srv_addr,
			 int s,
			 dcerpc_ncacn_termination_fn termination_fn,
			 void *termination_data);

NTSTATUS dcesrv_auth_gensec_prepare(TALLOC_CTX *mem_ctx,
				    struct dcesrv_call_state *call,
				    struct gensec_security **out);
void dcesrv_log_successful_authz(struct dcesrv_call_state *call);
NTSTATUS dcesrv_assoc_group_find(struct dcesrv_call_state *call);

NTSTATUS dcesrv_endpoint_by_ncacn_np_name(struct dcesrv_context *dce_ctx,
					  const char *endpoint,
					  struct dcesrv_endpoint **out);

struct pipes_struct *dcesrv_get_pipes_struct(struct dcesrv_connection *conn);

void dcesrv_transport_terminate_connection(struct dcesrv_connection *dce_conn,
					   const char *reason);

#endif /* _PRC_SERVER_H_ */
