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
#include "rpc_worker_dcerpc.h"
#include "rpc_config.h"
#include "rpc_server.h"
#include "librpc/rpc/dcerpc_util.h"
#include "lib/util/debug.h"
#include "source3/lib/global_contexts.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util/idtree_random.h"
#include "libcli/security/dom_sid.h"

/*
 * This is the generic code that becomes the
 * template that all rpcd_* instances that
 * serve DCERPC can use to provide services to samba-dcerpcd.
 *
 * The external entry point is:
 * rpc_worker_main() which takes an argc/argv list
 * and two functions:
 *
 * get_interfaces() - List all interfaces that this server provides
 * get_servers() - Provide the RPC server implementations
 *
 * Each rpcd_* service needs only to provide
 * the implementations of get_interfaces() and get_servers()
 * and call rpc_worker_main() from their main() function
 * to provide services that can be connected to from samba-dcerpcd.
 */

struct rpc_worker_dcerpc_state {
	struct rpc_worker *worker;

	size_t (*get_interfaces)(
		const struct ndr_interface_table ***ifaces,
		void *private_data);
	NTSTATUS (*get_servers)(
		struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server ***ep_servers,
		size_t *num_ep_servers,
		void *private_data);
	void *private_data;

	struct dcesrv_context *dce_ctx;
	struct dcesrv_context_callbacks cb;
};

static int dcesrv_connection_destructor(struct dcesrv_connection *conn)
{
	struct dcesrv_context *dce_ctx = conn->dce_ctx;
	struct dcerpc_ncacn_conn *ncacn_conn =
		talloc_get_type_abort(conn->transport.private_data,
		struct dcerpc_ncacn_conn);
	struct rpc_worker_connection *worker_conn =
		talloc_get_type_abort(ncacn_conn->private_data,
		struct rpc_worker_connection);
	struct rpc_worker *worker = worker_conn->worker;

	/*
	 * We need to drop the association group reference
	 * explicitly here in order to avoid the order given
	 * by the destructors. rpc_worker_report_status()
	 * in rpc_worker_connection_destructor()
	 * expects worker->status.num_association_groups to be updated
	 * already.
	 */
	if (conn->assoc_group != NULL) {
		talloc_unlink(conn, conn->assoc_group);
		conn->assoc_group = NULL;
	}
	worker->status.num_association_groups = dce_ctx->assoc_groups_num;

	return 0;
}

static int dcerpc_ncacn_conn_destructor(struct dcerpc_ncacn_conn *ncacn_conn)
{
	/*
	 * This triggers dcesrv_connection_destructor()
	 * updating worker->status.num_association_groups
	 */
	TALLOC_FREE(ncacn_conn->dcesrv_conn);

	/*
	 * This triggers rpc_worker_connection_destructor()
	 * that calls rpc_worker_report_status().
	 */
	TALLOC_FREE(ncacn_conn->private_data);
	return 0;
}

/*
 * A new client has been passed to us from samba-dcerpcd.
 */
static NTSTATUS rpc_worker_dcerpc_accept_client(
		struct rpc_worker *worker,
		void *private_data,
		struct rpc_worker_connection *worker_conn,
		struct auth_session_info **_transport_session_info,
		struct dcerpc_binding **binding,
		uint8_t _effective_transport,
		const struct named_pipe_auth_rep_info8 *np_info,
		DATA_BLOB *first_pdu,
		struct tstream_context **tstream,
		struct tsocket_address **remote_client_addr,
		struct tsocket_address **local_server_addr)
{
	struct rpc_worker_dcerpc_state *dworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_dcerpc_state);
	struct dcesrv_context *dce_ctx = dworker->dce_ctx;
	enum dcerpc_transport_t effective_transport = _effective_transport;
	enum dcerpc_transport_t transport;
	struct auth_session_info *transport_session_info = NULL;
	const struct dcerpc_binding *b = *binding;
	struct dcesrv_endpoint *ep = NULL;
	struct dcerpc_ncacn_conn *ncacn_conn = NULL;
	struct dcesrv_connection *dcesrv_conn = NULL;
	DATA_BLOB buffer = { .length = 0, };
	struct ncacn_packet *pkt = NULL;
	struct security_token *token = NULL;
	uint32_t npa_flags, state_flags;
	bool found_npa_flags;
	NTSTATUS status;

	/* we don't have "int" in IDL, make sure we don't overflow */
	SMB_ASSERT(effective_transport == _effective_transport);

	transport = dcerpc_binding_get_transport(b);

	status = dcesrv_find_endpoint(dce_ctx, b, &ep);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND) &&
	    ((transport == NCACN_IP_TCP) || (transport == NCALRPC)) &&
	    (dcerpc_binding_get_string_option(b, "endpoint") != NULL)) {
		/*
		 * We have two kinds of servers: Those who explicitly
		 * bind to a port (e.g. 135 for epmapper) and those
		 * who just specify a transport. The client specified
		 * a port (or socket name), but we did not find this
		 * in the list of servers having specified a
		 * port. Retry just matching for the transport,
		 * catching the servers that did not explicitly
		 * specify a port.
		 *
		 * This is not fully correct, what we should do is
		 * that once the port the server listens on has been
		 * finalized we should mark this in the server list,
		 * but for now it works. We don't have the same RPC
		 * interface listening twice on different ports.
		 */
		struct dcerpc_binding *b_without_port = dcerpc_binding_dup(
			worker_conn, b);
		if (b_without_port == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = dcerpc_binding_set_string_option(
			b_without_port, "endpoint", NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Could not delete endpoint: %s\n",
				  nt_errstr(status));
			TALLOC_FREE(b_without_port);
			return status;
		}

		status = dcesrv_find_endpoint(dce_ctx, b_without_port, &ep);

		TALLOC_FREE(b_without_port);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Could not find endpoint for %s: %s\n",
			  worker_conn->endpoint,
			  nt_errstr(status));
		return status;
	}

	ncacn_conn = talloc(worker_conn, struct dcerpc_ncacn_conn);
	if (ncacn_conn == NULL) {
		DBG_DEBUG("talloc failed\n");
		return NT_STATUS_NO_MEMORY;
	}
	*ncacn_conn = (struct dcerpc_ncacn_conn) {
		.private_data = worker_conn,
	};

	transport_session_info = talloc_move(ncacn_conn, _transport_session_info);
	token = transport_session_info->security_token;

	state_flags = DCESRV_CALL_STATE_FLAG_MAY_ASYNC;

	found_npa_flags = security_token_find_npa_flags(token, &npa_flags);
	if (found_npa_flags) {
		if (npa_flags & SAMBA_NPA_FLAGS_WINBIND_OFF) {
			state_flags |=
				DCESRV_CALL_STATE_FLAG_WINBIND_OFF;
		}

		/*
		 * Delete the flags so that we don't bail in
		 * local_np_connect_send() on subsequent
		 * connects. Once we connect to another RPC service, a
		 * new flags sid will be added if required.
		 */
		security_token_del_npa_flags(token);
	}

	ncacn_conn->p.msg_ctx = global_messaging_context();
	ncacn_conn->p.transport = effective_transport;

	status = dcesrv_endpoint_connect(dce_ctx,
					 ncacn_conn,
					 ep,
					 transport_session_info,
					 global_event_context(),
					 state_flags,
					 &dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Failed to connect to endpoint: %s\n",
			  nt_errstr(status));
		return status;
	}

	ncacn_conn->dcesrv_conn = dcesrv_conn;
	talloc_set_destructor(dcesrv_conn, dcesrv_connection_destructor);

	dcesrv_conn->transport.private_data = ncacn_conn;
	dcesrv_conn->transport.report_output_data =
		dcesrv_sock_report_output_data;
	dcesrv_conn->transport.terminate_connection =
		dcesrv_transport_terminate_connection;

	dcesrv_conn->send_queue = tevent_queue_create(
		dcesrv_conn, "dcesrv send queue");
	if (dcesrv_conn->send_queue == NULL) {
		DBG_DEBUG("tevent_queue_create failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	dcesrv_conn->stream = talloc_move(dcesrv_conn, tstream);
	dcesrv_conn->local_address =
		talloc_move(dcesrv_conn, local_server_addr);
	dcesrv_conn->remote_address =
		talloc_move(dcesrv_conn, remote_client_addr);

	if (first_pdu->length == 0) {
		DBG_DEBUG("Expected bind packet\n");
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	buffer = (DATA_BLOB) {
		.data = talloc_move(dcesrv_conn, &first_pdu->data),
		.length = first_pdu->length,
	};

	pkt = talloc(dcesrv_conn, struct ncacn_packet);
	if (pkt == NULL) {
		DBG_DEBUG("talloc failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_pull_ncacn_packet(pkt, &buffer, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_pull_ncacn_packet failed: %s\n",
			  nt_errstr(status));
		return status;
	}

	talloc_set_destructor(ncacn_conn, dcerpc_ncacn_conn_destructor);

	dcesrv_loop_next_packet(dcesrv_conn, pkt, buffer);

	return NT_STATUS_OK;
}

/*
  take a reference to an existing association group
 */
static struct dcesrv_assoc_group *rpc_worker_assoc_group_reference(
	struct dcesrv_connection *conn,
	uint32_t id)
{
	const struct dcesrv_endpoint *endpoint = conn->endpoint;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(
		endpoint->ep_description);
	struct dcesrv_assoc_group *assoc_group = NULL;
	void *id_ptr = NULL;

	/* find an association group given a assoc_group_id */
	id_ptr = idr_find(conn->dce_ctx->assoc_groups_idr, id & UINT16_MAX);
	if (id_ptr == NULL) {
		DBG_NOTICE("Failed to find assoc_group 0x%08x\n", id);
		return NULL;
	}
	assoc_group = talloc_get_type_abort(id_ptr, struct dcesrv_assoc_group);

	if (assoc_group->transport != transport) {
		const char *at = derpc_transport_string_by_transport(
			assoc_group->transport);
		const char *ct = derpc_transport_string_by_transport(
			transport);

		DBG_NOTICE("assoc_group 0x%08x (transport %s) "
			   "is not available on transport %s\n",
			   id, at, ct);
		return NULL;
	}

	/*
	 * Yes, this is a talloc_reference: The assoc group must be
	 * removed when all connections go. This should be replaced by
	 * adding a linked list of dcesrv_connection structs to the
	 * assoc group.
	 */
	return talloc_reference(conn, assoc_group);
}

static int rpc_worker_assoc_group_destructor(
	struct dcesrv_assoc_group *assoc_group)
{
	int ret;

	dcesrv_assoc_group_common_destructor(assoc_group);

	ret = idr_remove(
		assoc_group->dce_ctx->assoc_groups_idr,
		assoc_group->id & UINT16_MAX);
	if (ret != 0) {
		DBG_WARNING("Failed to remove assoc_group 0x%08x\n",
			    assoc_group->id);
	}

	SMB_ASSERT(assoc_group->dce_ctx->assoc_groups_num > 0);
	assoc_group->dce_ctx->assoc_groups_num -= 1;
	return 0;
}

/*
  allocate a new association group
 */
static struct dcesrv_assoc_group *rpc_worker_assoc_group_new(
	struct dcesrv_connection *conn, uint16_t worker_index)
{
	struct dcesrv_context *dce_ctx = conn->dce_ctx;
	const struct dcesrv_endpoint *endpoint = conn->endpoint;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(
		endpoint->ep_description);
	struct dcesrv_assoc_group *assoc_group = NULL;
	int id;

	assoc_group = talloc_zero(conn, struct dcesrv_assoc_group);
	if (assoc_group == NULL) {
		return NULL;
	}

	/*
	 * We use 16-bit to encode the worker index,
	 * have 16-bits left within the worker to form a
	 * 32-bit association group id.
	 */
	id = idr_get_new_random(
		dce_ctx->assoc_groups_idr, assoc_group, 1, UINT16_MAX);
	if (id == -1) {
		talloc_free(assoc_group);
		DBG_WARNING("Out of association groups!\n");
		return NULL;
	}
	assoc_group->id = (((uint32_t)worker_index) << 16) | id;
	assoc_group->transport = transport;
	assoc_group->dce_ctx = dce_ctx;

	talloc_set_destructor(assoc_group, rpc_worker_assoc_group_destructor);

	SMB_ASSERT(dce_ctx->assoc_groups_num < UINT16_MAX);
	dce_ctx->assoc_groups_num += 1;

	return assoc_group;
}

static NTSTATUS rpc_worker_assoc_group_find(
	struct dcesrv_call_state *call,
	void *private_data)
{
	struct rpc_worker_dcerpc_state *dworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_dcerpc_state);
	struct rpc_worker *w = dworker->worker;
	uint32_t assoc_group_id = call->pkt.u.bind.assoc_group_id;

	if (assoc_group_id != 0) {
		uint16_t worker_index = (assoc_group_id & 0xffff0000) >> 16;
		if (worker_index != w->status.worker_index) {
			DBG_DEBUG("Wrong worker id %"PRIu16", "
				  "expected %"PRIu32"\n",
				  worker_index,
				  w->status.worker_index);
			return NT_STATUS_NOT_FOUND;
		}
		call->conn->assoc_group = rpc_worker_assoc_group_reference(
			call->conn, assoc_group_id);
	} else {
		call->conn->assoc_group = rpc_worker_assoc_group_new(
			call->conn, w->status.worker_index);
	}

	if (call->conn->assoc_group == NULL) {
		/* TODO Return correct status */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

static NTSTATUS register_ep_server(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server *ep_server)
{
	NTSTATUS status;

	DBG_DEBUG("Registering server %s\n", ep_server->name);

	status = dcerpc_register_ep_server(ep_server);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
		DBG_ERR("Failed to register '%s' endpoint server: %s\n",
			ep_server->name,
			nt_errstr(status));
		return status;
	}

	status = dcesrv_init_ep_server(dce_ctx, ep_server->name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dcesrv_init_ep_server(%s) failed: %s\n",
			ep_server->name,
			nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_worker_dcerpc_get_interfaces(void *private_data,
						 TALLOC_CTX *mem_ctx,
						 char **_ifaces)
{
	struct rpc_worker_dcerpc_state *dworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_dcerpc_state);
	const struct ndr_interface_table **ifaces = NULL;
	size_t num_ifaces;
	size_t idx_ifaces;
	char *str = NULL;

	num_ifaces = dworker->get_interfaces(&ifaces,
					     dworker->private_data);

	str = talloc_strdup(mem_ctx, "");

	for (idx_ifaces = 0; idx_ifaces < num_ifaces; idx_ifaces++) {
		const struct ndr_interface_table *t = ifaces[idx_ifaces];
		const struct ndr_interface_string_array *eps = t->endpoints;
		struct ndr_syntax_id_buf id_buf;
		uint32_t idx_eps;

		str = talloc_asprintf_append_buffer(str,
			"%s %s\n",
			ndr_syntax_id_buf_string(&t->syntax_id, &id_buf),
			t->name);

		for (idx_eps = 0; idx_eps < eps->count; idx_eps++) {
			str = talloc_asprintf_append_buffer(str,
					" %s\n",
					eps->names[idx_eps]);
		}
	}

	if (str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*_ifaces = str;
	return NT_STATUS_OK;
}

static NTSTATUS rpc_worker_dcerpc_setup_servers(struct rpc_worker *worker,
						void *private_data)
{
	struct rpc_worker_dcerpc_state *dworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_dcerpc_state);
	const struct dcesrv_endpoint_server **ep_servers = NULL;
	size_t i, num_servers;
	NTSTATUS status;

	dworker->worker = worker;

	dworker->cb = (struct dcesrv_context_callbacks) {
		.log.successful_authz = dcesrv_log_successful_authz,
		.auth.gensec_prepare = dcesrv_auth_gensec_prepare,
		.auth.become_root = become_root,
		.auth.unbecome_root = unbecome_root,
		.assoc_group.find = rpc_worker_assoc_group_find,
		.assoc_group.private_data = dworker,
	};

	dworker->dce_ctx = global_dcesrv_context();
	if (dworker->dce_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	dcesrv_context_set_callbacks(dworker->dce_ctx, &dworker->cb);

	DBG_INFO("Initializing DCE/RPC registered endpoint servers\n");

	status = dworker->get_servers(dworker->dce_ctx,
				      &ep_servers,
				      &num_servers,
				      dworker->private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("get_servers failed: %s\n", nt_errstr(status));
		return status;
	}

	DBG_DEBUG("get_servers() returned %zu servers\n", num_servers);

	for (i = 0; i < num_servers; i++) {
		status = register_ep_server(dworker->dce_ctx, ep_servers[i]);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("register_ep_server failed: %s\n",
				nt_errstr(status));
			return status;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS rpc_worker_dcerpc_shutdown_servers(struct rpc_worker *worker,
						   void *private_data)
{
	struct rpc_worker_dcerpc_state *dworker =
		talloc_get_type_abort(private_data,
		struct rpc_worker_dcerpc_state);
	NTSTATUS status;

	status = dcesrv_shutdown_registered_ep_servers(dworker->dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Shutdown failed with: %s\n",
			nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

/**
 * @brief Main function for RPC server implementations
 *
 * This function provides all that is necessary to run a RPC server
 * inside the samba-dcerpcd framework. Just pass argv and argc on to
 * this function.
 *
 * The get_interfaces() callback provides the information that is
 * passed to samba-dcerpcd via --list-interfaces, it should not do any
 * real RPC server initialization work. Quickly after this function is
 * called by rpc_worker_main, the process exits again. It should
 * return the number of interfaces provided.
 *
 * get_servers() is called when the process is about to do the real
 * work. So more heavy-weight initialization should happen here. It
 * should return NT_STATUS_OK and the number of server implementations provided.
 *
 * @param[in] argc argc from main()
 * @param[in] argv argv from main()
 * @param[in] get_interfaces List all interfaces that this server provides
 * @param[in] get_servers Provide the RPC server implementations
 * @param[in] private_data Passed to the callback functions
 * @return 0 It should never return except on successful process exit
 */
int rpc_worker_main(
	int argc,
	const char *argv[],
	const char *daemon_config_name,
	int num_workers,
	int idle_seconds,
	size_t (*get_interfaces)(
		const struct ndr_interface_table ***ifaces,
		void *private_data),
	NTSTATUS (*get_servers)(
		struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server ***ep_servers,
		size_t *num_ep_servers,
		void *private_data),
	void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct rpc_worker_dcerpc_state *dworker = NULL;
	int ret;

	dworker = talloc_zero(frame, struct rpc_worker_dcerpc_state);
	if (dworker == NULL) {
		DBG_ERR("talloc_zero(struct rpc_worker_dcerpc_state)  failed\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	*dworker = (struct rpc_worker_dcerpc_state) {
		.get_interfaces = get_interfaces,
		.get_servers = get_servers,
		.private_data = private_data,
	};

	ret = rpc_worker_internal(argc,
				  argv,
				  daemon_config_name,
				  num_workers,
				  idle_seconds,
				  rpc_worker_dcerpc_get_interfaces,
				  rpc_worker_dcerpc_setup_servers,
				  rpc_worker_dcerpc_accept_client,
				  rpc_worker_dcerpc_shutdown_servers,
				  dworker);

	TALLOC_FREE(frame);
	return ret;
}
