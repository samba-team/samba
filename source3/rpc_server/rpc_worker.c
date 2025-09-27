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
#include "lib/cmdline/cmdline.h"
#include "rpc_worker.h"
#include "rpc_config.h"
#include "librpc/rpc/dcesrv_core.h"
#include "librpc/rpc/dcerpc_util.h"
#include "source3/librpc/gen_ndr/ndr_rpc_host.h"
#include "lib/util/debug.h"
#include "lib/util/fault.h"
#include "lib/util/util_file.h"
#include "rpc_server.h"
#include "rpc_pipes.h"
#include "source3/smbd/proto.h"
#include "source3/lib/smbd_shim.h"
#include "source3/lib/global_contexts.h"
#include "source3/lib/util_procid.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/named_pipe_auth/npa_tstream.h"
#include "libcli/smb/smb_constants.h"
#include "lib/param/param.h"
#include "lib/util/idtree_random.h"
#include "lib/util/tevent_unix.h"
#include "lib/async_req/async_sock.h"
#include "lib/util/dlinklist.h"
#include "source3/include/auth.h"
#include "nsswitch/winbind_client.h"
#include "source3/include/messages.h"
#include "libcli/security/security_token.h"
#include "libcli/security/dom_sid.h"
#include "source3/include/proto.h"
#include "source3/lib/substitute.h"

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

struct rpc_worker {
	struct dcerpc_ncacn_conn *conns;
	struct server_id rpc_host_pid;
	struct messaging_context *msg_ctx;
	struct dcesrv_context *dce_ctx;

	struct dcesrv_context_callbacks cb;

	struct rpc_worker_status status;

	bool done;
};

static void rpc_worker_print_interface(
	FILE *f, const struct ndr_interface_table *t)
{
	const struct ndr_interface_string_array *endpoints = t->endpoints;
	uint32_t i;
	struct ndr_syntax_id_buf id_buf;

	fprintf(f,
		"%s %s\n",
		ndr_syntax_id_buf_string(&t->syntax_id, &id_buf),
		t->name);

	for (i=0; i<endpoints->count; i++) {
		fprintf(f, " %s\n", endpoints->names[i]);
	}
}

static NTSTATUS rpc_worker_report_status(struct rpc_worker *worker)
{
	uint8_t buf[16];
	DATA_BLOB blob = { .data = buf, .length = sizeof(buf), };
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	worker->status.num_association_groups = worker->dce_ctx->assoc_groups_num;

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(rpc_worker_status, &worker->status);
	}

	ndr_err = ndr_push_struct_into_fixed_blob(
		&blob,
		&worker->status,
		(ndr_push_flags_fn_t)ndr_push_rpc_worker_status);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

	status = messaging_send(
		worker->msg_ctx,
		worker->rpc_host_pid,
		MSG_RPC_WORKER_STATUS,
		&blob);
	return status;
}

static void rpc_worker_connection_terminated(
	struct dcesrv_connection *conn, void *private_data)
{
	struct rpc_worker *worker = talloc_get_type_abort(
		private_data, struct rpc_worker);
	struct dcerpc_ncacn_conn *ncacn_conn = talloc_get_type_abort(
		conn->transport.private_data, struct dcerpc_ncacn_conn);
	struct dcerpc_ncacn_conn *w = NULL;
	NTSTATUS status;
	bool found = false;

	/*
	 * We need to drop the association group reference
	 * explicitly here in order to avoid the order given
	 * by the destructors. rpc_worker_report_status() below,
	 * expects worker->dce_ctx->assoc_groups_num to be updated
	 * already.
	 */
	if (conn->assoc_group != NULL) {
		talloc_unlink(conn, conn->assoc_group);
		conn->assoc_group = NULL;
	}

	SMB_ASSERT(worker->status.num_connections > 0);

	for (w = worker->conns; w != NULL; w = w->next) {
		if (w == ncacn_conn) {
			found = true;
			break;
		}
	}
	SMB_ASSERT(found);

	DLIST_REMOVE(worker->conns, ncacn_conn);

	worker->status.num_connections -= 1;

	status = rpc_worker_report_status(worker);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_worker_report_status returned %s\n",
			  nt_errstr(status));
	}
}

static int dcesrv_connection_destructor(struct dcesrv_connection *conn)
{
	struct dcerpc_ncacn_conn *ncacn_conn = talloc_get_type_abort(
			conn->transport.private_data,
			struct dcerpc_ncacn_conn);

	if (ncacn_conn->termination_fn != NULL) {
		ncacn_conn->termination_fn(conn, ncacn_conn->termination_data);
	}

	return 0;
}

/*
 * A new client has been passed to us from samba-dcerpcd.
 */
static void rpc_worker_new_client(
	struct rpc_worker *worker,
	struct rpc_host_client *client,
	int sock)
{
	struct dcesrv_context *dce_ctx = worker->dce_ctx;
	struct named_pipe_auth_req_info8 *info8 = client->npa_info8;
	struct tsocket_address *remote_client_addr = NULL;
	struct tsocket_address *local_server_addr = NULL;
	struct dcerpc_binding *b = NULL;
	enum dcerpc_transport_t transport;
	struct dcesrv_endpoint *ep = NULL;
	struct tstream_context *tstream = NULL;
	struct dcerpc_ncacn_conn *ncacn_conn = NULL;
	struct dcesrv_connection *dcesrv_conn = NULL;
	DATA_BLOB buffer = { .data = NULL };
	struct ncacn_packet *pkt = NULL;
	struct security_token *token = NULL;
	uint32_t npa_flags, state_flags;
	bool found_npa_flags;
	NTSTATUS status;
	int ret;

	DBG_DEBUG("Got new conn sock %d for binding %s\n",
		  sock,
		  client->binding);

	status = dcerpc_parse_binding(client, client->binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_parse_binding(%s) failed: %s\n",
			  client->binding,
			  nt_errstr(status));
		goto fail;
	}
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
			client, b);
		if (b_without_port == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		status = dcerpc_binding_set_string_option(
			b_without_port, "endpoint", NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("Could not delete endpoint: %s\n",
				  nt_errstr(status));
			TALLOC_FREE(b_without_port);
			goto fail;
		}

		status = dcesrv_find_endpoint(dce_ctx, b_without_port, &ep);

		TALLOC_FREE(b_without_port);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Could not find endpoint for %s: %s\n",
			  client->binding,
			  nt_errstr(status));
		goto fail;
	}

	ncacn_conn = talloc(dce_ctx, struct dcerpc_ncacn_conn);
	if (ncacn_conn == NULL) {
		DBG_DEBUG("talloc failed\n");
		goto fail;
	}
	*ncacn_conn = (struct dcerpc_ncacn_conn) {
		.endpoint = ep,
		.sock = sock,
		.termination_fn = rpc_worker_connection_terminated,
		.termination_data = worker,
	};

	if (transport == NCALRPC) {
		ret = tsocket_address_unix_from_path(ncacn_conn,
						     info8->remote_client_addr,
						     &remote_client_addr);
		if (ret == -1) {
			DBG_DEBUG("tsocket_address_unix_from_path"
				  "(%s) failed: %s\n",
				  info8->remote_client_addr,
				  strerror(errno));
			goto fail;
		}

		ncacn_conn->remote_client_name =
			talloc_strdup(ncacn_conn, info8->remote_client_name);
		if (ncacn_conn->remote_client_name == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->remote_client_name);
			goto fail;
		}

		ret = tsocket_address_unix_from_path(ncacn_conn,
						     info8->local_server_addr,
						     &local_server_addr);
		if (ret == -1) {
			DBG_DEBUG("tsocket_address_unix_from_path"
				  "(%s) failed: %s\n",
				  info8->local_server_addr,
				  strerror(errno));
			goto fail;
		}

		ncacn_conn->local_server_name =
			talloc_strdup(ncacn_conn, info8->local_server_name);
		if (ncacn_conn->local_server_name == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->local_server_name);
			goto fail;
		}
	} else {
		ret = tsocket_address_inet_from_strings(
			ncacn_conn,
			"ip",
			info8->remote_client_addr,
			info8->remote_client_port,
			&remote_client_addr);
		if (ret == -1) {
			DBG_DEBUG("tsocket_address_inet_from_strings"
				  "(%s, %" PRIu16 ") failed: %s\n",
				  info8->remote_client_addr,
				  info8->remote_client_port,
				  strerror(errno));
			goto fail;
		}
		ncacn_conn->remote_client_name =
			talloc_strdup(ncacn_conn, info8->remote_client_name);
		if (ncacn_conn->remote_client_name == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->remote_client_name);
			goto fail;
		}

		ret = tsocket_address_inet_from_strings(
			ncacn_conn,
			"ip",
			info8->local_server_addr,
			info8->local_server_port,
			&local_server_addr);
		if (ret == -1) {
			DBG_DEBUG("tsocket_address_inet_from_strings"
				  "(%s, %" PRIu16 ") failed: %s\n",
				  info8->local_server_addr,
				  info8->local_server_port,
				  strerror(errno));
			goto fail;
		}
		ncacn_conn->local_server_name =
			talloc_strdup(ncacn_conn, info8->local_server_name);
		if (ncacn_conn->local_server_name == NULL) {
			DBG_DEBUG("talloc_strdup(%s) failed\n",
				  info8->local_server_name);
			goto fail;
		}
	}

	if (transport == NCACN_NP) {
		ret = tstream_npa_existing_socket(
			ncacn_conn,
			sock,
			FILE_TYPE_MESSAGE_MODE_PIPE,
			&tstream);
		if (ret == -1) {
			DBG_DEBUG("tstream_npa_existing_socket failed: %s\n",
				  strerror(errno));
			goto fail;
		}

		/*
		 * "transport" so far is implicitly assigned by the
		 * socket that the client connected to, passed in from
		 * samba-dcerpcd via the binding. For NCACN_NP (root
		 * only by unix permissions) we got a
		 * named_pipe_auth_req_info8 where the transport can
		 * be overridden.
		 */
		transport = info8->transport;
	} else {
		ret = tstream_bsd_existing_socket(
			ncacn_conn, sock, &tstream);
		if (ret == -1) {
			DBG_DEBUG("tstream_bsd_existing_socket failed: %s\n",
				  strerror(errno));
			goto fail;
		}
		/* as server we want to fail early */
		tstream_bsd_fail_readv_first_error(tstream, true);
	}
	sock = -1;

	token = info8->session_info->session_info->security_token;

	if (security_token_is_system(token) && (transport != NCALRPC)) {
		DBG_DEBUG("System token only allowed on NCALRPC\n");
		goto fail;
	}

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
	ncacn_conn->p.transport = transport;

	status = dcesrv_endpoint_connect(dce_ctx,
					 ncacn_conn,
					 ep,
					 info8->session_info->session_info,
					 global_event_context(),
					 state_flags,
					 &dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Failed to connect to endpoint: %s\n",
			  nt_errstr(status));
		goto fail;
	}

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
		goto fail;
	}

	dcesrv_conn->stream = talloc_move(dcesrv_conn, &tstream);
	dcesrv_conn->local_address =
		talloc_move(dcesrv_conn, &local_server_addr);
	dcesrv_conn->remote_address =
		talloc_move(dcesrv_conn, &remote_client_addr);

	if (client->bind_packet.length == 0) {
		DBG_DEBUG("Expected bind packet\n");
		goto fail;
	}

	buffer = (DATA_BLOB) {
		.data = talloc_move(dcesrv_conn, &client->bind_packet.data),
		.length = client->bind_packet.length,
	};

	pkt = talloc(dcesrv_conn, struct ncacn_packet);
	if (pkt == NULL) {
		DBG_DEBUG("talloc failed\n");
		goto fail;
	}

	status = dcerpc_pull_ncacn_packet(pkt, &buffer, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("dcerpc_pull_ncacn_packet failed: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	TALLOC_FREE(client);

	DLIST_ADD(worker->conns, ncacn_conn);
	worker->status.num_connections += 1;

	dcesrv_loop_next_packet(dcesrv_conn, pkt, buffer);

	return;
fail:
	TALLOC_FREE(ncacn_conn);
	TALLOC_FREE(dcesrv_conn);
	TALLOC_FREE(client);
	if (sock != -1) {
		close(sock);
	}

	/*
	 * Parent thinks it successfully sent us a client. Tell it
	 * that we declined.
	 */
	status = rpc_worker_report_status(worker);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("rpc_worker_report_status returned %s\n",
			  nt_errstr(status));
	}
}

/*
 * New client message processing.
 */
static bool rpc_worker_new_client_filter(
	struct messaging_rec *rec, void *private_data)
{
	struct rpc_worker *worker = talloc_get_type_abort(
		private_data, struct rpc_worker);
	struct dcesrv_context *dce_ctx = worker->dce_ctx;
	struct rpc_host_client *client = NULL;
	enum ndr_err_code ndr_err;
	int sock;

	if (rec->msg_type != MSG_RPC_HOST_NEW_CLIENT) {
		return false;
	}

	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %"PRIu8" fds\n", rec->num_fds);
		return false;
	}

	client = talloc(dce_ctx, struct rpc_host_client);
	if (client == NULL) {
		DBG_DEBUG("talloc failed\n");
		return false;
	}

	ndr_err = ndr_pull_struct_blob_all(
		&rec->buf,
		client,
		client,
		(ndr_pull_flags_fn_t)ndr_pull_rpc_host_client);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("ndr_pull_rpc_host_client failed: %s\n",
			  ndr_errstr(ndr_err));
		TALLOC_FREE(client);
		return false;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(rpc_host_client, client);
	}

	sock = rec->fds[0];
	rec->fds[0] = -1;

	rpc_worker_new_client(worker, client, sock);

	return false;
}

/*
 * Return your status message processing.
 */
static bool rpc_worker_status_filter(
	struct messaging_rec *rec, void *private_data)
{
	struct rpc_worker *worker = talloc_get_type_abort(
		private_data, struct rpc_worker);
	struct dcerpc_ncacn_conn *conn = NULL;
	FILE *f = NULL;

	if (rec->msg_type != MSG_RPC_DUMP_STATUS) {
		return false;
	}

	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %"PRIu8" fds\n", rec->num_fds);
		return false;
	}

	f = fdopen_keepfd(rec->fds[0], "w");
	if (f == NULL) {
		DBG_DEBUG("fdopen_keepfd failed: %s\n", strerror(errno));
		return false;
	}

	for (conn = worker->conns; conn != NULL; conn = conn->next) {
		char *endpoint = NULL;

		endpoint = dcerpc_binding_string(
			conn, conn->endpoint->ep_description);

		fprintf(f,
			"endpoint=%s client=%s server=%s\n",
			endpoint ? endpoint : "UNKNOWN",
			conn->remote_client_name,
			conn->local_server_name);
		TALLOC_FREE(endpoint);
	}

	fclose(f);

	return false;
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
	struct rpc_worker *w = talloc_get_type_abort(
		private_data, struct rpc_worker);
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

static struct rpc_worker *rpc_worker_new(
	TALLOC_CTX *mem_ctx,
	struct messaging_context *msg_ctx)
{
	struct rpc_worker *worker = NULL;

	worker = talloc_zero(mem_ctx, struct rpc_worker);
	if (worker == NULL) {
		return NULL;
	}

	worker->rpc_host_pid = (struct server_id) { .pid = 0 };
	worker->msg_ctx = msg_ctx;

	worker->cb = (struct dcesrv_context_callbacks) {
		.log.successful_authz = dcesrv_log_successful_authz,
		.auth.gensec_prepare = dcesrv_auth_gensec_prepare,
		.auth.become_root = become_root,
		.auth.unbecome_root = unbecome_root,
		.assoc_group.find = rpc_worker_assoc_group_find,
		.assoc_group.private_data = worker,
	};

	worker->dce_ctx = global_dcesrv_context();
	if (worker->dce_ctx == NULL) {
		goto fail;
	}
	dcesrv_context_set_callbacks(worker->dce_ctx, &worker->cb);

	return worker;
fail:
	TALLOC_FREE(worker);
	return NULL;
}

static struct dcesrv_context *rpc_worker_dce_ctx(struct rpc_worker *w)
{
	return w->dce_ctx;
}

struct rpc_worker_state {
	struct tevent_context *ev;
	struct rpc_worker *w;
	struct tevent_req *new_client_req;
	struct tevent_req *status_req;
	struct tevent_req *finish_req;
};

static void rpc_worker_done(struct tevent_req *subreq);
static void rpc_worker_shutdown(
	struct messaging_context *msg,
	void *private_data,
	uint32_t msg_type,
	struct server_id server_id,
	DATA_BLOB *data);

static struct tevent_req *rpc_worker_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct rpc_worker *w,
	pid_t rpc_host_pid,
	int server_index,
	int worker_index)
{
	struct tevent_req *req = NULL;
	struct rpc_worker_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct rpc_worker_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->w = w;

	if ((server_index < 0) || ((unsigned)server_index > UINT32_MAX)) {
		DBG_ERR("Invalid server index %d\n", server_index);
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}
	if ((worker_index < 0) || ((unsigned)worker_index > UINT16_MAX)) {
		DBG_ERR("Invalid worker index %d\n", worker_index);
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}
	w->rpc_host_pid = pid_to_procid(rpc_host_pid);

	w->status = (struct rpc_worker_status) {
		.server_index = server_index,
		.worker_index = worker_index,
	};

	/* Wait for new client messages. */
	state->new_client_req = messaging_filtered_read_send(
		w,
		messaging_tevent_context(w->msg_ctx),
		w->msg_ctx,
		rpc_worker_new_client_filter,
		w);
	if (tevent_req_nomem(state->new_client_req, req)) {
		return tevent_req_post(req, ev);
	}

	/* Wait for report your status messages. */
	state->status_req = messaging_filtered_read_send(
		w,
		messaging_tevent_context(w->msg_ctx),
		w->msg_ctx,
		rpc_worker_status_filter,
		w);
	if (tevent_req_nomem(state->status_req, req)) {
		return tevent_req_post(req, ev);
	}

	/* Wait for shutdown messages. */
	status = messaging_register(
		w->msg_ctx, req, MSG_SHUTDOWN, rpc_worker_shutdown);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_register failed: %s\n",
			  nt_errstr(status));
		tevent_req_error(req, map_errno_from_nt_status(status));
		return tevent_req_post(req, ev);
	}

	state->finish_req = wait_for_read_send(state, ev, 0, false);
	if (tevent_req_nomem(state->finish_req, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->finish_req, rpc_worker_done, req);

	rpc_worker_report_status(w);

	return req;
}

static void rpc_worker_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int err = 0;
	bool ok;

	ok = wait_for_read_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

static void rpc_worker_shutdown(
	struct messaging_context *msg,
	void *private_data,
	uint32_t msg_type,
	struct server_id server_id,
	DATA_BLOB *data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	tevent_req_done(req);
}

static int rpc_worker_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

static void sig_term_handler(
	struct tevent_context *ev,
	struct tevent_signal *se,
	int signum,
	int count,
	void *siginfo,
	void *private_data)
{
	exit(0);
}

static void sig_hup_handler(
	struct tevent_context *ev,
	struct tevent_signal *se,
	int signum,
	int count,
	void *siginfo,
	void *private_data)
{
	change_to_root_user();
	lp_load_with_shares(get_dyn_CONFIGFILE());
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
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *progname = getprogname();
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev_ctx = NULL;
	struct tevent_req *req = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct dcesrv_context *dce_ctx = NULL;
	struct tevent_signal *se = NULL;
	poptContext pc;
	int opt;
	NTSTATUS status;
	int ret;
	int worker_group = -1;
	int worker_index = -1;
	bool log_stdout;
	int list_interfaces = 0;
	struct rpc_worker *worker = NULL;
	const struct dcesrv_endpoint_server **ep_servers;
	size_t i, num_servers;
	bool ok;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "list-interfaces",
			.argInfo    = POPT_ARG_NONE,
			.arg        = &list_interfaces,
			.descrip    = "List the interfaces provided",
		},
		{
			.longName   = "worker-group",
			.argInfo    = POPT_ARG_INT,
			.arg        = &worker_group,
			.descrip    = "Group index in status message",
		},
		{
			.longName   = "worker-index",
			.argInfo    = POPT_ARG_INT,
			.arg        = &worker_index,
			.descrip    = "Worker index in status message",
		},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	static const struct smbd_shim smbd_shim_fns = {
		.become_authenticated_pipe_user =
		smbd_become_authenticated_pipe_user,
		.unbecome_authenticated_pipe_user =
		smbd_unbecome_authenticated_pipe_user,
		.become_root = smbd_become_root,
		.unbecome_root = smbd_unbecome_root,
	};

	closefrom(3);
	talloc_enable_null_tracking();
	frame = talloc_stackframe();
	umask(0);
	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_SERVER,
				true /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(ENOMEM);
	}

	pc = samba_popt_get_context(progname, argc, argv, long_options, 0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		d_fprintf(stderr,
			  "\nInvalid option %s: %s\n\n",
			  poptBadOption(pc, 0),
			  poptStrerror(opt));
		poptPrintUsage(pc, stderr, 0);
		TALLOC_FREE(frame);
		exit(1);
	};
	poptFreeContext(pc);

	if (list_interfaces != 0) {
		const struct ndr_interface_table **ifaces = NULL;
		size_t num_ifaces;

		num_workers = lp_parm_int(
			-1, daemon_config_name, "num_workers", num_workers);
		idle_seconds = lp_parm_int(
			-1, daemon_config_name, "idle_seconds", idle_seconds);

		DBG_DEBUG("daemon=%s, num_workers=%d, idle_seconds=%d\n",
			  daemon_config_name,
			  num_workers,
			  idle_seconds);

		fprintf(stdout, "%d\n%d\n", num_workers, idle_seconds);

		num_ifaces = get_interfaces(&ifaces, private_data);

		for (i=0; i<num_ifaces; i++) {
			rpc_worker_print_interface(stdout, ifaces[i]);
		}

		TALLOC_FREE(frame);
		exit(0);
	}

	log_stdout = (debug_get_log_type() == DEBUG_STDOUT);
	if (log_stdout != 0) {
		setup_logging(argv[0], DEBUG_STDOUT);
	} else {
		setup_logging(argv[0], DEBUG_FILE);
	}

	set_smbd_shim(&smbd_shim_fns);

	dump_core_setup(progname, lp_logfile(talloc_tos(), lp_sub));

	/* POSIX demands that signals are inherited. If the invoking
	 * process has these signals masked, we will have problems, as
	 * we won't receive them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGTERM);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif
	/* We no longer use USR2... */
#if defined(SIGUSR2)
	BlockSignals(True, SIGUSR2);
#endif
	/* Ignore children - no zombies. */
	CatchChild();

	set_remote_machine_name(progname, false);

	reopen_logs();

	DBG_STARTUP_NOTICE("%s version %s started.\n%s\n",
			   progname,
			   samba_version_string(),
			   samba_copyright_string());

	msg_ctx = global_messaging_context();
	if (msg_ctx == NULL) {
		DBG_ERR("global_messaging_context() failed\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	ev_ctx = messaging_tevent_context(msg_ctx);

	worker = rpc_worker_new(ev_ctx, msg_ctx);
	if (worker == NULL) {
		DBG_ERR("rpc_worker_new failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}
	dce_ctx = rpc_worker_dce_ctx(worker);

	se = tevent_add_signal(
		ev_ctx, ev_ctx, SIGTERM, 0, sig_term_handler, NULL);
	if (se == NULL) {
		DBG_ERR("tevent_add_signal failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}
	BlockSignals(false, SIGTERM);

	se = tevent_add_signal(
		ev_ctx, ev_ctx, SIGHUP, 0, sig_hup_handler, NULL);
	if (se == NULL) {
		DBG_ERR("tevent_add_signal failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}
	BlockSignals(false, SIGHUP);

	(void)winbind_off();
	ok = init_guest_session_info(NULL);
	(void)winbind_on();
	if (!ok) {
		DBG_WARNING("init_guest_session_info failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	status = init_system_session_info(NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("init_system_session_info failed: %s\n",
			    nt_errstr(status));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	DBG_INFO("Initializing DCE/RPC registered endpoint servers\n");

	status = get_servers(dce_ctx,
			     &ep_servers,
			     &num_servers,
			     private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("get_servers failed: %s\n", nt_errstr(status));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	DBG_DEBUG("get_servers() returned %zu servers\n", num_servers);

	for (i=0; i<num_servers; i++) {
		status = register_ep_server(dce_ctx, ep_servers[i]);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("register_ep_server failed: %s\n",
				nt_errstr(status));
			global_messaging_context_free();
			TALLOC_FREE(frame);
			exit(1);
		}
	}

	req = rpc_worker_send(
		ev_ctx, ev_ctx, worker, getppid(), worker_group, worker_index);
	if (req == NULL) {
		DBG_ERR("rpc_worker_send failed\n");
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	DBG_DEBUG("%s worker running\n", progname);

	while (tevent_req_is_in_progress(req)) {
		TALLOC_CTX *loop_frame = NULL;

		loop_frame = talloc_stackframe();

		ret = tevent_loop_once(ev_ctx);

		TALLOC_FREE(loop_frame);

		if (ret != 0) {
			DBG_WARNING("tevent_req_once() failed: %s\n",
				    strerror(errno));
			global_messaging_context_free();
			TALLOC_FREE(frame);
			exit(1);
		}
	}

	status = dcesrv_shutdown_registered_ep_servers(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Shutdown failed with: %s\n",
			nt_errstr(status));
	}

	ret = rpc_worker_recv(req);
	if (ret != 0) {
		DBG_DEBUG("rpc_worker_recv returned %s\n", strerror(ret));
		global_messaging_context_free();
		TALLOC_FREE(frame);
		exit(1);
	}

	TALLOC_FREE(frame);
	return 0;
}
