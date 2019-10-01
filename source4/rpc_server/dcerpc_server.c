/* 
   Unix SMB/CIFS implementation.

   server side dcerpc core code

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher 2004-2005
   
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
#include "auth/auth.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/dcerpc_server_proto.h"
#include "param/param.h"
#include "smbd/service_stream.h"
#include "lib/tsocket/tsocket.h"
#include "lib/socket/socket.h"
#include "smbd/process_model.h"
#include "lib/util/samba_modules.h"
#include "lib/util/tevent_ntstatus.h"

/*
  take a reference to an existing association group
 */
static struct dcesrv_assoc_group *dcesrv_assoc_group_reference(struct dcesrv_connection *conn,
							       uint32_t id)
{
	const struct dcesrv_endpoint *endpoint = conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct dcesrv_assoc_group *assoc_group;
	void *id_ptr = NULL;

	/* find an association group given a assoc_group_id */
	id_ptr = idr_find(conn->dce_ctx->assoc_groups_idr, id);
	if (id_ptr == NULL) {
		DBG_NOTICE("Failed to find assoc_group 0x%08x\n", id);
		return NULL;
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
			   "is not available on transport %s",
			   id, at, ct);
		return NULL;
	}

	return talloc_reference(conn, assoc_group);
}

static int dcesrv_assoc_group_destructor(struct dcesrv_assoc_group *assoc_group)
{
	int ret;
	ret = idr_remove(assoc_group->dce_ctx->assoc_groups_idr, assoc_group->id);
	if (ret != 0) {
		DEBUG(0,(__location__ ": Failed to remove assoc_group 0x%08x\n",
			 assoc_group->id));
	}
	return 0;
}

/*
  allocate a new association group
 */
static struct dcesrv_assoc_group *dcesrv_assoc_group_new(struct dcesrv_connection *conn)
{
	struct dcesrv_context *dce_ctx = conn->dce_ctx;
	const struct dcesrv_endpoint *endpoint = conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct dcesrv_assoc_group *assoc_group;
	int id;

	assoc_group = talloc_zero(conn, struct dcesrv_assoc_group);
	if (assoc_group == NULL) {
		return NULL;
	}

	id = idr_get_new_random(dce_ctx->assoc_groups_idr, assoc_group, UINT16_MAX);
	if (id == -1) {
		talloc_free(assoc_group);
		DEBUG(0,(__location__ ": Out of association groups!\n"));
		return NULL;
	}

	assoc_group->transport = transport;
	assoc_group->id = id;
	assoc_group->dce_ctx = dce_ctx;

	talloc_set_destructor(assoc_group, dcesrv_assoc_group_destructor);

	return assoc_group;
}

NTSTATUS dcesrv_assoc_group_find(struct dcesrv_call_state *call)
{
	/*
	  if provided, check the assoc_group is valid
	 */
	if (call->pkt.u.bind.assoc_group_id != 0) {
		call->conn->assoc_group =
			dcesrv_assoc_group_reference(call->conn,
					call->pkt.u.bind.assoc_group_id);
	} else {
		call->conn->assoc_group = dcesrv_assoc_group_new(call->conn);
	}

	/*
	 * The NETLOGON server does not use handles and so
	 * there is no need to support association groups, but
	 * we need to give back a number regardless.
	 *
	 * We have to do this when it is not run as a single process,
	 * because then it can't see the other valid association
	 * groups.  We handle this genericly for all endpoints not
	 * running in single process mode.
	 *
	 * We know which endpoint we are on even before checking the
	 * iface UUID, so for simplicity we enforce the same policy
	 * for all interfaces on the endpoint.
	 *
	 * This means that where NETLOGON
	 * shares an endpoint (such as ncalrpc or of 'lsa over
	 * netlogon' is set) we will still check association groups.
	 *
	 */

	if (call->conn->assoc_group == NULL &&
	    !call->conn->endpoint->use_single_process) {
		call->conn->assoc_group
			= dcesrv_assoc_group_new(call->conn);
	}

	if (call->conn->assoc_group == NULL) {
		/* TODO Return correct status */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

void dcerpc_server_init(struct loadparm_context *lp_ctx)
{
	static bool initialized;
#define _MODULE_PROTO(init) extern NTSTATUS init(TALLOC_CTX *);
	STATIC_dcerpc_server_MODULES_PROTO;
	init_module_fn static_init[] = { STATIC_dcerpc_server_MODULES };
	init_module_fn *shared_init;

	if (initialized) {
		return;
	}
	initialized = true;

	shared_init = load_samba_modules(NULL, "dcerpc_server");

	run_init_functions(NULL, static_init);
	run_init_functions(NULL, shared_init);

	talloc_free(shared_init);
}

struct dcesrv_socket_context {
	const struct dcesrv_endpoint *endpoint;
	struct dcesrv_context *dcesrv_ctx;
};

static void dcesrv_sock_accept(struct stream_connection *srv_conn)
{
	NTSTATUS status;
	struct dcesrv_socket_context *dcesrv_sock = 
		talloc_get_type(srv_conn->private_data, struct dcesrv_socket_context);
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dcesrv_sock->endpoint->ep_description);
	struct dcesrv_connection *dcesrv_conn = NULL;
	int ret;
	struct loadparm_context *lp_ctx = dcesrv_sock->dcesrv_ctx->lp_ctx;

	dcesrv_cleanup_broken_connections(dcesrv_sock->dcesrv_ctx);

	if (!srv_conn->session_info) {
		status = auth_anonymous_session_info(srv_conn,
						     lp_ctx,
						     &srv_conn->session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("dcesrv_sock_accept: auth_anonymous_session_info failed: %s\n",
				nt_errstr(status)));
			stream_terminate_connection(srv_conn, nt_errstr(status));
			return;
		}
	}

	/*
	 * This fills in dcesrv_conn->endpoint with the endpoint
	 * associated with the socket.  From this point on we know
	 * which (group of) services we are handling, but not the
	 * specific interface.
	 */

	status = dcesrv_endpoint_connect(dcesrv_sock->dcesrv_ctx,
					 srv_conn,
					 dcesrv_sock->endpoint,
					 srv_conn->session_info,
					 srv_conn->event.ctx,
					 DCESRV_CALL_STATE_FLAG_MAY_ASYNC,
					 &dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("dcesrv_sock_accept: dcesrv_endpoint_connect failed: %s\n", 
			nt_errstr(status)));
		stream_terminate_connection(srv_conn, nt_errstr(status));
		return;
	}

	dcesrv_conn->transport.private_data		= srv_conn;
	dcesrv_conn->transport.report_output_data	= dcesrv_sock_report_output_data;
	dcesrv_conn->transport.terminate_connection	= dcesrv_transport_terminate_connection;

	TALLOC_FREE(srv_conn->event.fde);

	dcesrv_conn->send_queue = tevent_queue_create(dcesrv_conn, "dcesrv send queue");
	if (!dcesrv_conn->send_queue) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0,("dcesrv_sock_accept: tevent_queue_create(%s)\n",
			nt_errstr(status)));
		stream_terminate_connection(srv_conn, nt_errstr(status));
		return;
	}

	if (transport == NCACN_NP) {
		dcesrv_conn->stream = talloc_move(dcesrv_conn,
						  &srv_conn->tstream);
	} else {
		ret = tstream_bsd_existing_socket(dcesrv_conn,
						  socket_get_fd(srv_conn->socket),
						  &dcesrv_conn->stream);
		if (ret == -1) {
			status = map_nt_error_from_unix_common(errno);
			DEBUG(0, ("dcesrv_sock_accept: "
				  "failed to setup tstream: %s\n",
				  nt_errstr(status)));
			stream_terminate_connection(srv_conn, nt_errstr(status));
			return;
		}
		socket_set_flags(srv_conn->socket, SOCKET_FLAG_NOCLOSE);
	}

	dcesrv_conn->local_address = srv_conn->local_address;
	dcesrv_conn->remote_address = srv_conn->remote_address;

	if (transport == NCALRPC) {
		uid_t uid;
		gid_t gid;
		int sock_fd;

		sock_fd = socket_get_fd(srv_conn->socket);
		if (sock_fd == -1) {
			stream_terminate_connection(
				srv_conn, "socket_get_fd failed\n");
			return;
		}

		ret = getpeereid(sock_fd, &uid, &gid);
		if (ret == -1) {
			status = map_nt_error_from_unix_common(errno);
			DEBUG(0, ("dcesrv_sock_accept: "
				  "getpeereid() failed for NCALRPC: %s\n",
				  nt_errstr(status)));
			stream_terminate_connection(srv_conn, nt_errstr(status));
			return;
		}
		if (uid == dcesrv_conn->dce_ctx->initial_euid) {
			struct tsocket_address *r = NULL;

			ret = tsocket_address_unix_from_path(dcesrv_conn,
							     AS_SYSTEM_MAGIC_PATH_TOKEN,
							     &r);
			if (ret == -1) {
				status = map_nt_error_from_unix_common(errno);
				DEBUG(0, ("dcesrv_sock_accept: "
					  "tsocket_address_unix_from_path() failed for NCALRPC: %s\n",
					  nt_errstr(status)));
				stream_terminate_connection(srv_conn, nt_errstr(status));
				return;
			}
			dcesrv_conn->remote_address = r;
		}
	}

	srv_conn->private_data = dcesrv_conn;

	status = dcesrv_connection_loop_start(dcesrv_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("dcesrv_sock_accept: dcerpc_read_fragment_buffer_send(%s)\n",
			nt_errstr(status)));
		stream_terminate_connection(srv_conn, nt_errstr(status));
		return;
	}

	return;
}

static void dcesrv_sock_recv(struct stream_connection *conn, uint16_t flags)
{
	struct dcesrv_connection *dce_conn = talloc_get_type(conn->private_data,
					     struct dcesrv_connection);
	dcesrv_terminate_connection(dce_conn, "dcesrv_sock_recv triggered");
}

static void dcesrv_sock_send(struct stream_connection *conn, uint16_t flags)
{
	struct dcesrv_connection *dce_conn = talloc_get_type(conn->private_data,
					     struct dcesrv_connection);
	dcesrv_terminate_connection(dce_conn, "dcesrv_sock_send triggered");
}


static const struct stream_server_ops dcesrv_stream_ops = {
	.name			= "rpc",
	.accept_connection	= dcesrv_sock_accept,
	.recv_handler		= dcesrv_sock_recv,
	.send_handler		= dcesrv_sock_send,
};

static NTSTATUS dcesrv_add_ep_unix(struct dcesrv_context *dce_ctx, 
				   struct loadparm_context *lp_ctx,
				   struct dcesrv_endpoint *e,
				   struct tevent_context *event_ctx,
				   const struct model_ops *model_ops,
				   void *process_context)
{
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 1;
	NTSTATUS status;
	const char *endpoint;

	dcesrv_sock = talloc_zero(event_ctx, struct dcesrv_socket_context);
	NT_STATUS_HAVE_NO_MEMORY(dcesrv_sock);

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= talloc_reference(dcesrv_sock, dce_ctx);

	endpoint = dcerpc_binding_get_string_option(e->ep_description, "endpoint");

	status = stream_setup_socket(dcesrv_sock, event_ctx, lp_ctx,
				     model_ops, &dcesrv_stream_ops, 
				     "unix", endpoint, &port,
				     lpcfg_socket_options(lp_ctx),
				     dcesrv_sock, process_context);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(path=%s) failed - %s\n",
			 endpoint, nt_errstr(status)));
	}

	return status;
}

static NTSTATUS dcesrv_add_ep_ncalrpc(struct dcesrv_context *dce_ctx, 
				      struct loadparm_context *lp_ctx,
				      struct dcesrv_endpoint *e,
				      struct tevent_context *event_ctx,
				      const struct model_ops *model_ops,
				      void *process_context)
{
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 1;
	char *full_path;
	NTSTATUS status;
	const char *endpoint;

	endpoint = dcerpc_binding_get_string_option(e->ep_description, "endpoint");

	if (endpoint == NULL) {
		/*
		 * No identifier specified: use DEFAULT.
		 *
		 * TODO: DO NOT hardcode this value anywhere else. Rather, specify
		 * no endpoint and let the epmapper worry about it.
		 */
		endpoint = "DEFAULT";
		status = dcerpc_binding_set_string_option(e->ep_description,
							  "endpoint",
							  endpoint);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("dcerpc_binding_set_string_option() failed - %s\n",
				  nt_errstr(status)));
			return status;
		}
	}

	full_path = talloc_asprintf(dce_ctx, "%s/%s", lpcfg_ncalrpc_dir(lp_ctx),
				    endpoint);

	dcesrv_sock = talloc_zero(event_ctx, struct dcesrv_socket_context);
	NT_STATUS_HAVE_NO_MEMORY(dcesrv_sock);

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= talloc_reference(dcesrv_sock, dce_ctx);

	status = stream_setup_socket(dcesrv_sock, event_ctx, lp_ctx,
				     model_ops, &dcesrv_stream_ops, 
				     "unix", full_path, &port, 
				     lpcfg_socket_options(lp_ctx),
				     dcesrv_sock, process_context);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(identifier=%s,path=%s) failed - %s\n",
			 endpoint, full_path, nt_errstr(status)));
	}
	return status;
}

static NTSTATUS dcesrv_add_ep_np(struct dcesrv_context *dce_ctx,
				 struct loadparm_context *lp_ctx,
				 struct dcesrv_endpoint *e,
				 struct tevent_context *event_ctx,
				 const struct model_ops *model_ops,
				 void *process_context)
{
	struct dcesrv_socket_context *dcesrv_sock;
	NTSTATUS status;
	const char *endpoint;

	endpoint = dcerpc_binding_get_string_option(e->ep_description, "endpoint");
	if (endpoint == NULL) {
		DEBUG(0, ("Endpoint mandatory for named pipes\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	dcesrv_sock = talloc_zero(event_ctx, struct dcesrv_socket_context);
	NT_STATUS_HAVE_NO_MEMORY(dcesrv_sock);

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= talloc_reference(dcesrv_sock, dce_ctx);

	status = tstream_setup_named_pipe(dce_ctx, event_ctx, lp_ctx,
					  model_ops, &dcesrv_stream_ops,
					  endpoint,
					  dcesrv_sock, process_context);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("stream_setup_named_pipe(pipe=%s) failed - %s\n",
			 endpoint, nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

/*
  add a socket address to the list of events, one event per dcerpc endpoint
*/
static NTSTATUS add_socket_rpc_tcp_iface(struct dcesrv_context *dce_ctx,
					 struct dcesrv_endpoint *e,
					 struct tevent_context *event_ctx,
					 const struct model_ops *model_ops,
					 const char *address,
					 void *process_context)
{
	struct dcesrv_socket_context *dcesrv_sock;
	uint16_t port = 0;
	NTSTATUS status;
	const char *endpoint;
	char port_str[6];

	endpoint = dcerpc_binding_get_string_option(e->ep_description, "endpoint");
	if (endpoint != NULL) {
		port = atoi(endpoint);
	}

	dcesrv_sock = talloc_zero(event_ctx, struct dcesrv_socket_context);
	NT_STATUS_HAVE_NO_MEMORY(dcesrv_sock);

	/* remember the endpoint of this socket */
	dcesrv_sock->endpoint		= e;
	dcesrv_sock->dcesrv_ctx		= talloc_reference(dcesrv_sock, dce_ctx);

	status = stream_setup_socket(dcesrv_sock, event_ctx, dce_ctx->lp_ctx,
				     model_ops, &dcesrv_stream_ops, 
				     "ip", address, &port,
				     lpcfg_socket_options(dce_ctx->lp_ctx),
				     dcesrv_sock, process_context);
	if (!NT_STATUS_IS_OK(status)) {
		struct dcesrv_if_list *iface;
		DEBUG(0,("service_setup_stream_socket(address=%s,port=%u) for ",
			 address, port));
		for (iface = e->interface_list; iface; iface = iface->next) {
			DEBUGADD(0, ("%s ", iface->iface->name));
		}
		DEBUGADD(0, ("failed - %s\n",
			     nt_errstr(status)));
		return status;
	}

	snprintf(port_str, sizeof(port_str), "%u", port);

	status = dcerpc_binding_set_string_option(e->ep_description,
						  "endpoint", port_str);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("dcerpc_binding_set_string_option(endpoint, %s) failed - %s\n",
			 port_str, nt_errstr(status)));
		return status;
	} else {
		struct dcesrv_if_list *iface;
		DEBUG(4,("Successfully listening on ncacn_ip_tcp endpoint [%s]:[%s] for ",
			 address, port_str));
		for (iface = e->interface_list; iface; iface = iface->next) {
			DEBUGADD(4, ("%s ", iface->iface->name));
		}
		DEBUGADD(4, ("\n"));
	}

	return NT_STATUS_OK;
}

#include "lib/socket/netif.h" /* Included here to work around the fact that socket_wrapper redefines bind() */

static NTSTATUS dcesrv_add_ep_tcp(struct dcesrv_context *dce_ctx, 
				  struct loadparm_context *lp_ctx,
				  struct dcesrv_endpoint *e,
				  struct tevent_context *event_ctx,
				  const struct model_ops *model_ops,
				  void *process_context)
{
	NTSTATUS status;

	/* Add TCP/IP sockets */
	if (lpcfg_interfaces(lp_ctx) && lpcfg_bind_interfaces_only(lp_ctx)) {
		int num_interfaces;
		int i;
		struct interface *ifaces;

		load_interface_list(dce_ctx, lp_ctx, &ifaces);

		num_interfaces = iface_list_count(ifaces);
		for(i = 0; i < num_interfaces; i++) {
			const char *address = iface_list_n_ip(ifaces, i);
			status = add_socket_rpc_tcp_iface(dce_ctx, e, event_ctx,
					                  model_ops, address,
							  process_context);
			NT_STATUS_NOT_OK_RETURN(status);
		}
	} else {
		char **wcard;
		size_t i;
		size_t num_binds = 0;
		wcard = iface_list_wildcard(dce_ctx);
		NT_STATUS_HAVE_NO_MEMORY(wcard);
		for (i=0; wcard[i]; i++) {
			status = add_socket_rpc_tcp_iface(dce_ctx, e, event_ctx,
							  model_ops, wcard[i],
							  process_context);
			if (NT_STATUS_IS_OK(status)) {
				num_binds++;
			}
		}
		talloc_free(wcard);
		if (num_binds == 0) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS dcesrv_add_ep(struct dcesrv_context *dce_ctx,
		       struct loadparm_context *lp_ctx,
		       struct dcesrv_endpoint *e,
		       struct tevent_context *event_ctx,
		       const struct model_ops *model_ops,
		       void *process_context)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(e->ep_description);

	switch (transport) {
	case NCACN_UNIX_STREAM:
		return dcesrv_add_ep_unix(dce_ctx, lp_ctx, e, event_ctx,
					  model_ops, process_context);

	case NCALRPC:
		return dcesrv_add_ep_ncalrpc(dce_ctx, lp_ctx, e, event_ctx,
					     model_ops, process_context);

	case NCACN_IP_TCP:
		return dcesrv_add_ep_tcp(dce_ctx, lp_ctx, e, event_ctx,
					 model_ops, process_context);

	case NCACN_NP:
		return dcesrv_add_ep_np(dce_ctx, lp_ctx, e, event_ctx,
					model_ops, process_context);

	default:
		return NT_STATUS_NOT_SUPPORTED;
	}
}

_PUBLIC_ struct imessaging_context *dcesrv_imessaging_context(
					struct dcesrv_connection *conn)
{
	struct stream_connection *srv_conn =
		talloc_get_type_abort(conn->transport.private_data,
				      struct stream_connection);
	return srv_conn->msg_ctx;
}

_PUBLIC_ struct server_id dcesrv_server_id(struct dcesrv_connection *conn)
{
	struct stream_connection *srv_conn =
		talloc_get_type_abort(conn->transport.private_data,
				struct stream_connection);
	return srv_conn->server_id;
}

void log_successful_dcesrv_authz_event(struct dcesrv_call_state *call)
{
	struct dcesrv_auth *auth = call->auth_state;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(call->conn->endpoint->ep_description);
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(call->conn);
	const char *auth_type = derpc_transport_string_by_transport(transport);
	const char *transport_protection = AUTHZ_TRANSPORT_PROTECTION_NONE;

	if (transport == NCACN_NP) {
		transport_protection = AUTHZ_TRANSPORT_PROTECTION_SMB;
	}

	/*
	 * Log the authorization to this RPC interface.  This
	 * covered ncacn_np pass-through auth, and anonymous
	 * DCE/RPC (eg epmapper, netlogon etc)
	 */
	log_successful_authz_event(imsg_ctx,
				   call->conn->dce_ctx->lp_ctx,
				   call->conn->remote_address,
				   call->conn->local_address,
				   "DCE/RPC",
				   auth_type,
				   transport_protection,
				   auth->session_info);

	auth->auth_audited = true;
}

NTSTATUS dcesrv_gensec_prepare(TALLOC_CTX *mem_ctx,
			       struct dcesrv_call_state *call,
			       struct gensec_security **out)
{
	struct cli_credentials *server_creds = NULL;
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(call->conn);
	NTSTATUS status;

	server_creds = cli_credentials_init(call->auth_state);
	if (!server_creds) {
		DEBUG(1, ("Failed to init server credentials\n"));
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_set_conf(server_creds, call->conn->dce_ctx->lp_ctx);

	status = cli_credentials_set_machine_account(server_creds,
						call->conn->dce_ctx->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to obtain server credentials: %s\n",
			  nt_errstr(status)));
		talloc_free(server_creds);
		return status;
	}

	return samba_server_gensec_start(mem_ctx,
					 call->event_ctx,
					 imsg_ctx,
					 call->conn->dce_ctx->lp_ctx,
					 server_creds,
					 NULL,
					 out);
}

void dcesrv_transport_terminate_connection(struct dcesrv_connection *dce_conn,
					   const char *reason)
{
	struct stream_connection *srv_conn =
		talloc_get_type_abort(dce_conn->transport.private_data,
				      struct stream_connection);
	stream_terminate_connection(srv_conn, reason);
}
