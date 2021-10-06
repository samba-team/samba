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
#include "rpc_pipes.h"

struct auth_session_info;
struct cli_credentials;

typedef void (*dcerpc_ncacn_termination_fn)(struct dcesrv_connection *,
					    void *);

struct dcerpc_ncacn_conn {
	struct dcerpc_ncacn_conn *prev, *next;
	int sock;

	struct pipes_struct p;
	dcerpc_ncacn_termination_fn termination_fn;
	void *termination_data;

	struct dcesrv_endpoint *endpoint;

	char *remote_client_name;
	char *local_server_name;
};

void set_incoming_fault(struct pipes_struct *p);
void process_complete_pdu(struct pipes_struct *p, struct ncacn_packet *pkt);

NTSTATUS dcesrv_auth_gensec_prepare(
	TALLOC_CTX *mem_ctx,
	struct dcesrv_call_state *call,
	struct gensec_security **out,
	void *private_data);
void dcesrv_log_successful_authz(
	struct dcesrv_call_state *call,
	void *private_data);
NTSTATUS dcesrv_assoc_group_find(
	struct dcesrv_call_state *call,
	void *private_data);

NTSTATUS dcesrv_endpoint_by_ncacn_np_name(struct dcesrv_context *dce_ctx,
					  const char *endpoint,
					  struct dcesrv_endpoint **out);

struct pipes_struct *dcesrv_get_pipes_struct(struct dcesrv_connection *conn);

void dcesrv_transport_terminate_connection(struct dcesrv_connection *dce_conn,
					   const char *reason);

#endif /* _PRC_SERVER_H_ */
