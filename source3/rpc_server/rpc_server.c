/*
   Unix SMB/Netbios implementation.
   Generic infrstructure for RPC Daemons
   Copyright (C) Simo Sorce 2010
   Copyright (C) Andrew Bartlett 2011
   Copyright (C) Andreas Schneider 2011

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

#include "includes.h"
#include "librpc/rpc/dcesrv_core.h"
#include "rpc_server/rpc_pipes.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_config.h"
#include "rpc_dce.h"
#include "librpc/gen_ndr/netlogon.h"
#include "librpc/gen_ndr/auth.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/named_pipe_auth/npa_tstream.h"
#include "../auth/auth_sam_reply.h"
#include "auth.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "lib/util/idtree_random.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/* Start listening on the appropriate unix socket and setup all is needed to
 * dispatch requests to the pipes rpc implementation */

struct dcerpc_ncacn_listen_state {
	int fd;

	struct tevent_context *ev_ctx;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx;
	struct dcesrv_endpoint *endpoint;
	dcerpc_ncacn_termination_fn termination_fn;
	void *termination_data;
};

static void ncacn_terminate_connection(struct dcerpc_ncacn_conn *conn,
				       const char *reason);

NTSTATUS dcesrv_auth_gensec_prepare(
	TALLOC_CTX *mem_ctx,
	struct dcesrv_call_state *call,
	struct gensec_security **out,
	void *private_data)
{
	struct gensec_security *gensec = NULL;
	NTSTATUS status;

	if (out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = auth_generic_prepare(mem_ctx,
				      call->conn->remote_address,
				      call->conn->local_address,
				      "DCE/RPC",
				      &gensec);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to prepare gensec: %s\n", nt_errstr(status));
		return status;
	}

	*out = gensec;

	return NT_STATUS_OK;
}

void dcesrv_log_successful_authz(
	struct dcesrv_call_state *call,
	void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct auth4_context *auth4_context = NULL;
	struct dcesrv_auth *auth = call->auth_state;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(
			call->conn->endpoint->ep_description);
	const char *auth_type = derpc_transport_string_by_transport(transport);
	const char *transport_protection = AUTHZ_TRANSPORT_PROTECTION_NONE;
	NTSTATUS status;

	if (frame == NULL) {
		DBG_ERR("No memory\n");
		return;
	}

	if (transport == NCACN_NP) {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_SMB;
	}

	become_root();
	status = make_auth4_context(frame, &auth4_context);
	unbecome_root();
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Unable to make auth context for authz log.\n");
		TALLOC_FREE(frame);
		return;
	}

	/*
	 * Log the authorization to this RPC interface.  This
	 * covered ncacn_np pass-through auth, and anonymous
	 * DCE/RPC (eg epmapper, netlogon etc)
	 */
	log_successful_authz_event(auth4_context->msg_ctx,
				   auth4_context->lp_ctx,
				   call->conn->remote_address,
				   call->conn->local_address,
				   "DCE/RPC",
				   auth_type,
				   transport_protection,
				   auth->session_info,
				   NULL /* client_audit_info */,
				   NULL /* server_audit_info */);

	auth->auth_audited = true;

	TALLOC_FREE(frame);
}

static int dcesrv_assoc_group_destructor(struct dcesrv_assoc_group *assoc_group)
{
	int ret;

	dcesrv_assoc_group_common_destructor(assoc_group);

	ret = idr_remove(assoc_group->dce_ctx->assoc_groups_idr,
			 assoc_group->id);
	if (ret != 0) {
		DBG_ERR("Failed to remove assoc_group 0x%08x\n",
			assoc_group->id);
	}
	return 0;
}

static NTSTATUS dcesrv_assoc_group_new(struct dcesrv_call_state *call)
{
	struct dcesrv_connection *conn = call->conn;
	struct dcesrv_context *dce_ctx = conn->dce_ctx;
	const struct dcesrv_endpoint *endpoint = conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct dcesrv_assoc_group *assoc_group = NULL;
	int id;

	assoc_group = talloc_zero(conn, struct dcesrv_assoc_group);
	if (assoc_group == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	id = idr_get_new_random(dce_ctx->assoc_groups_idr,
				assoc_group,
				1,
				UINT16_MAX);
	if (id == -1) {
		TALLOC_FREE(assoc_group);
		DBG_ERR("Out of association groups!\n");
		return NT_STATUS_RPC_OUT_OF_RESOURCES;
	}

	assoc_group->transport = transport;
	assoc_group->id = id;
	assoc_group->dce_ctx = dce_ctx;

	call->conn->assoc_group = assoc_group;

	talloc_set_destructor(assoc_group, dcesrv_assoc_group_destructor);

	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_assoc_group_reference(struct dcesrv_call_state *call,
					     uint32_t assoc_group_id)
{
	struct dcesrv_connection *conn = call->conn;
	const struct dcesrv_endpoint *endpoint = conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct dcesrv_assoc_group *assoc_group = NULL;
	void *id_ptr = NULL;

	/* find an association group given a assoc_group_id */
	id_ptr = idr_find(conn->dce_ctx->assoc_groups_idr, assoc_group_id);
	if (id_ptr == NULL) {
		/*
		 * FIXME If the association group is not found it has
		 * been created in other process (preforking daemons).
		 * Until this is properly fixed we just create a new
		 * association group in this process
		 */
		DBG_NOTICE("Failed to find assoc_group 0x%08x in this "
			   "server process, creating a new one\n",
			   assoc_group_id);
		return dcesrv_assoc_group_new(call);
	}
	assoc_group = talloc_get_type_abort(id_ptr, struct dcesrv_assoc_group);

	if (assoc_group->transport != transport) {
		const char *at =
			derpc_transport_string_by_transport(
				assoc_group->transport);
		const char *ct =
			derpc_transport_string_by_transport(
				transport);

		DBG_NOTICE("assoc_group 0x%08x (transport %s) "
			   "is not available on transport %s\n",
			   assoc_group_id, at, ct);
		return NT_STATUS_UNSUCCESSFUL;
	}

	conn->assoc_group = talloc_reference(conn, assoc_group);
	return NT_STATUS_OK;
}

NTSTATUS dcesrv_assoc_group_find(
	struct dcesrv_call_state *call,
	void *private_data)
{
	uint32_t assoc_group_id = call->pkt.u.bind.assoc_group_id;

	if (assoc_group_id != 0) {
		return dcesrv_assoc_group_reference(call, assoc_group_id);
	}

	/* If not requested by client create a new association group */
	return dcesrv_assoc_group_new(call);
}

void dcesrv_transport_terminate_connection(struct dcesrv_connection *dce_conn,
					   const char *reason)
{
       struct dcerpc_ncacn_conn *ncacn_conn = talloc_get_type_abort(
                       dce_conn->transport.private_data,
                       struct dcerpc_ncacn_conn);

       ncacn_terminate_connection(ncacn_conn, reason);
}

static void ncacn_terminate_connection(struct dcerpc_ncacn_conn *conn,
				       const char *reason)
{
       if (reason == NULL) {
               reason = "Unknown reason";
       }

       DBG_NOTICE("Terminating connection - '%s'\n", reason);

       talloc_free(conn);
}

NTSTATUS dcesrv_endpoint_by_ncacn_np_name(struct dcesrv_context *dce_ctx,
					  const char *pipe_name,
					  struct dcesrv_endpoint **out)
{
	struct dcesrv_endpoint *e = NULL;

	for (e = dce_ctx->endpoint_list; e; e = e->next) {
		enum dcerpc_transport_t transport =
			dcerpc_binding_get_transport(e->ep_description);
		const char *endpoint = NULL;

		if (transport != NCACN_NP) {
			continue;
		}

		endpoint = dcerpc_binding_get_string_option(e->ep_description,
							    "endpoint");
		if (endpoint == NULL) {
			continue;
		}

		if (strncmp(endpoint, "\\pipe\\", 6) == 0) {
			endpoint += 6;
		}

		if (strequal(endpoint, pipe_name)) {
			*out = e;
			return NT_STATUS_OK;
		}
	}

	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

struct pipes_struct *dcesrv_get_pipes_struct(struct dcesrv_connection *conn)
{
	struct dcerpc_ncacn_conn *ncacn_conn = talloc_get_type_abort(
			conn->transport.private_data,
			struct dcerpc_ncacn_conn);

	return &ncacn_conn->p;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
