/*
   Unix SMB/CIFS implementation.

   server side dcerpc core code

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher 2004-2005
   Copyright (C) Samuel Cabrero <scabrero@samba.org> 2019

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
#include "librpc/rpc/dcesrv_core_proto.h"
#include "librpc/gen_ndr/auth.h"
#include "auth/gensec/gensec.h"
#include "lib/util/dlinklist.h"
#include "libcli/security/security.h"
#include "param/param.h"
#include "lib/tsocket/tsocket.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "lib/util/tevent_ntstatus.h"


#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static NTSTATUS dcesrv_negotiate_contexts(struct dcesrv_call_state *call,
				const struct dcerpc_bind *b,
				struct dcerpc_ack_ctx *ack_ctx_list);

/*
  see if two endpoints match
*/
static bool endpoints_match(const struct dcerpc_binding *ep1,
			    const struct dcerpc_binding *ep2)
{
	enum dcerpc_transport_t t1;
	enum dcerpc_transport_t t2;
	const char *e1;
	const char *e2;

	t1 = dcerpc_binding_get_transport(ep1);
	t2 = dcerpc_binding_get_transport(ep2);

	e1 = dcerpc_binding_get_string_option(ep1, "endpoint");
	e2 = dcerpc_binding_get_string_option(ep2, "endpoint");

	if (t1 != t2) {
		return false;
	}

	if (!e1 || !e2) {
		return e1 == e2;
	}

	if (strcasecmp(e1, e2) != 0) {
		return false;
	}

	return true;
}

/*
  find an endpoint in the dcesrv_context
*/
_PUBLIC_ NTSTATUS dcesrv_find_endpoint(struct dcesrv_context *dce_ctx,
				const struct dcerpc_binding *ep_description,
				struct dcesrv_endpoint **_out)
{
	struct dcesrv_endpoint *ep = NULL;
	for (ep=dce_ctx->endpoint_list; ep; ep=ep->next) {
		if (endpoints_match(ep->ep_description, ep_description)) {
			*_out = ep;
			return NT_STATUS_OK;
		}
	}
	return NT_STATUS_NOT_FOUND;
}

/*
  find a registered context_id from a bind or alter_context
*/
static struct dcesrv_connection_context *dcesrv_find_context(struct dcesrv_connection *conn,
							     uint16_t context_id)
{
	struct dcesrv_connection_context *c;
	for (c=conn->contexts;c;c=c->next) {
		if (c->context_id == context_id) return c;
	}
	return NULL;
}

/*
  see if a uuid and if_version match to an interface
*/
static bool interface_match(const struct dcesrv_interface *if1,
							const struct dcesrv_interface *if2)
{
	return (if1->syntax_id.if_version == if2->syntax_id.if_version &&
			GUID_equal(&if1->syntax_id.uuid, &if2->syntax_id.uuid));
}

/*
  find the interface operations on any endpoint with this binding
*/
static const struct dcesrv_interface *find_interface_by_binding(struct dcesrv_context *dce_ctx,
								struct dcerpc_binding *binding,
								const struct dcesrv_interface *iface)
{
	struct dcesrv_endpoint *ep;
	for (ep=dce_ctx->endpoint_list; ep; ep=ep->next) {
		if (endpoints_match(ep->ep_description, binding)) {
			struct dcesrv_if_list *ifl;
			for (ifl=ep->interface_list; ifl; ifl=ifl->next) {
				if (interface_match(ifl->iface, iface)) {
					return ifl->iface;
				}
			}
		}
	}
	return NULL;
}

/*
  see if a uuid and if_version match to an interface
*/
static bool interface_match_by_uuid(const struct dcesrv_interface *iface,
				    const struct GUID *uuid, uint32_t if_version)
{
	return (iface->syntax_id.if_version == if_version &&
			GUID_equal(&iface->syntax_id.uuid, uuid));
}

/*
  find the interface operations on an endpoint by uuid
*/
_PUBLIC_ const struct dcesrv_interface *find_interface_by_uuid(const struct dcesrv_endpoint *endpoint,
						      const struct GUID *uuid, uint32_t if_version)
{
	struct dcesrv_if_list *ifl;
	for (ifl=endpoint->interface_list; ifl; ifl=ifl->next) {
		if (interface_match_by_uuid(ifl->iface, uuid, if_version)) {
			return ifl->iface;
		}
	}
	return NULL;
}

/*
  find the earlier parts of a fragmented call awaiting reassembily
*/
static struct dcesrv_call_state *dcesrv_find_fragmented_call(struct dcesrv_connection *dce_conn, uint32_t call_id)
{
	struct dcesrv_call_state *c;
	for (c=dce_conn->incoming_fragmented_call_list;c;c=c->next) {
		if (c->pkt.call_id == call_id) {
			return c;
		}
	}
	return NULL;
}

/*
  register an interface on an endpoint

  An endpoint is one unix domain socket (for ncalrpc), one TCP port
  (for ncacn_ip_tcp) or one (forwarded) named pipe (for ncacn_np).

  Each endpoint can have many interfaces such as netlogon, lsa or
  samr.  Some have essentially the full set.

  This is driven from the set of interfaces listed in each IDL file
  via the PIDL generated *__op_init_server() functions.
*/
_PUBLIC_ NTSTATUS dcesrv_interface_register(struct dcesrv_context *dce_ctx,
				   const char *ep_name,
				   const char *ncacn_np_secondary_endpoint,
				   const struct dcesrv_interface *iface,
				   const struct security_descriptor *sd)
{
	struct dcesrv_endpoint *ep;
	struct dcesrv_if_list *ifl;
	struct dcerpc_binding *binding;
	struct dcerpc_binding *binding2 = NULL;
	bool add_ep = false;
	NTSTATUS status;
	enum dcerpc_transport_t transport;
	char *ep_string = NULL;
	bool use_single_process = true;
	const char *ep_process_string;

	/*
	 * If we are not using handles, there is no need for force
	 * this service into using a single process.
	 *
	 * However, due to the way we listen for RPC packets, we can
	 * only do this if we have a single service per pipe or TCP
	 * port, so we still force a single combined process for
	 * ncalrpc.
	 */
	if (iface->flags & DCESRV_INTERFACE_FLAGS_HANDLES_NOT_USED) {
		use_single_process = false;
	}

	status = dcerpc_parse_binding(dce_ctx, ep_name, &binding);

	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Trouble parsing binding string '%s'\n", ep_name));
		return status;
	}

	transport = dcerpc_binding_get_transport(binding);
	if (transport == NCACN_IP_TCP) {
		int port;
		char port_str[6];

		/*
		 * First check if there is already a port specified, eg
		 * for epmapper on ncacn_ip_tcp:[135]
		 */
		const char *endpoint
			= dcerpc_binding_get_string_option(binding,
							   "endpoint");
		if (endpoint == NULL) {
			port = lpcfg_parm_int(dce_ctx->lp_ctx, NULL,
					      "rpc server port", iface->name, 0);

			/*
			 * For RPC services that are not set to use a single
			 * process, we do not default to using the 'rpc server
			 * port' because that would cause a double-bind on
			 * that port.
			 */
			if (port == 0 && !use_single_process) {
				port = lpcfg_rpc_server_port(dce_ctx->lp_ctx);
			}
			if (port != 0) {
				snprintf(port_str, sizeof(port_str), "%u", port);
				status = dcerpc_binding_set_string_option(binding,
									  "endpoint",
									  port_str);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
		}
	}

	if (transport == NCACN_NP && ncacn_np_secondary_endpoint != NULL) {
		enum dcerpc_transport_t transport2;

		status = dcerpc_parse_binding(dce_ctx,
					      ncacn_np_secondary_endpoint,
					      &binding2);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Trouble parsing 2nd binding string '%s'\n",
				  ncacn_np_secondary_endpoint));
			return status;
		}

		transport2 = dcerpc_binding_get_transport(binding2);
		SMB_ASSERT(transport2 == transport);
	}

	/* see if the interface is already registered on the endpoint */
	if (find_interface_by_binding(dce_ctx, binding, iface)!=NULL) {
		DEBUG(0,("dcesrv_interface_register: interface '%s' already registered on endpoint '%s'\n",
			 iface->name, ep_name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	/* check if this endpoint exists
	 */
	status = dcesrv_find_endpoint(dce_ctx, binding, &ep);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * We want a new port on ncacn_ip_tcp for NETLOGON, so
		 * it can be multi-process.  Other processes can also
		 * listen on distinct ports, if they have one forced
		 * in the code above with eg 'rpc server port:drsuapi = 1027'
		 *
		 * If we have mulitiple endpoints on port 0, they each
		 * get an epemeral port (currently by walking up from
		 * 1024).
		 *
		 * Because one endpoint can only have one process
		 * model, we add a new IP_TCP endpoint for each model.
		 *
		 * This works in conjunction with the forced overwrite
		 * of ep->use_single_process below.
		 */
		if (ep->use_single_process != use_single_process
		    && transport == NCACN_IP_TCP) {
			add_ep = true;
		}
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND) || add_ep) {
		ep = talloc_zero(dce_ctx, struct dcesrv_endpoint);
		if (!ep) {
			return NT_STATUS_NO_MEMORY;
		}
		ZERO_STRUCTP(ep);
		ep->ep_description = talloc_move(ep, &binding);
		ep->ep_2nd_description = talloc_move(ep, &binding2);
		add_ep = true;

		/* add mgmt interface */
		ifl = talloc_zero(ep, struct dcesrv_if_list);
		if (!ifl) {
			return NT_STATUS_NO_MEMORY;
		}

		ifl->iface = talloc_memdup(ifl,
					   dcesrv_get_mgmt_interface(),
					   sizeof(struct dcesrv_interface));
		if (ifl->iface == NULL) {
			talloc_free(ep);
			return NT_STATUS_NO_MEMORY;
		}

		DLIST_ADD(ep->interface_list, ifl);
	} else if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Failed to find endpoint: %s\n", nt_errstr(status));
		return status;
	}

	/*
	 * By default don't force into a single process, but if any
	 * interface on this endpoint on this service uses handles
	 * (most do), then we must force into single process mode
	 *
	 * By overwriting this each time a new interface is added to
	 * this endpoint, we end up with the most restrictive setting.
	 */
	if (use_single_process) {
		ep->use_single_process = true;
	}

	/* talloc a new interface list element */
	ifl = talloc_zero(ep, struct dcesrv_if_list);
	if (!ifl) {
		return NT_STATUS_NO_MEMORY;
	}

	/* copy the given interface struct to the one on the endpoints interface list */
	ifl->iface = talloc_memdup(ifl,
				   iface,
				   sizeof(struct dcesrv_interface));
	if (ifl->iface == NULL) {
		talloc_free(ep);
		return NT_STATUS_NO_MEMORY;
	}

	/* if we have a security descriptor given,
	 * we should see if we can set it up on the endpoint
	 */
	if (sd != NULL) {
		/* if there's currently no security descriptor given on the endpoint
		 * we try to set it
		 */
		if (ep->sd == NULL) {
			ep->sd = security_descriptor_copy(ep, sd);
		}

		/* if now there's no security descriptor given on the endpoint
		 * something goes wrong, either we failed to copy the security descriptor
		 * or there was already one on the endpoint
		 */
		if (ep->sd != NULL) {
			DEBUG(0,("dcesrv_interface_register: interface '%s' failed to setup a security descriptor\n"
			         "                           on endpoint '%s'\n",
				iface->name, ep_name));
			if (add_ep) free(ep);
			free(ifl);
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
	}

	/* finally add the interface on the endpoint */
	DLIST_ADD(ep->interface_list, ifl);

	/* if it's a new endpoint add it to the dcesrv_context */
	if (add_ep) {
		DLIST_ADD(dce_ctx->endpoint_list, ep);
	}

	/* Re-get the string as we may have set a port */
	ep_string = dcerpc_binding_string(dce_ctx, ep->ep_description);

	if (use_single_process) {
		ep_process_string = "single process required";
	} else {
		ep_process_string = "multi process compatible";
	}

	DBG_INFO("Interface '%s' registered on endpoint '%s' (%s)\n",
		 iface->name, ep_string, ep_process_string);
	TALLOC_FREE(ep_string);

	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_session_info_session_key(struct dcesrv_auth *auth,
						DATA_BLOB *session_key)
{
	if (auth->session_info == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (auth->session_info->session_key.length == 0) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	*session_key = auth->session_info->session_key;
	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_remote_session_key(struct dcesrv_auth *auth,
					  DATA_BLOB *session_key)
{
	if (auth->auth_type != DCERPC_AUTH_TYPE_NONE) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	return dcesrv_session_info_session_key(auth, session_key);
}

static NTSTATUS dcesrv_local_fixed_session_key(struct dcesrv_auth *auth,
					       DATA_BLOB *session_key)
{
	return dcerpc_generic_session_key(session_key);
}

/*
 * Fetch the authentication session key if available.
 *
 * This is the key generated by a gensec authentication.
 *
 */
_PUBLIC_ NTSTATUS dcesrv_auth_session_key(struct dcesrv_call_state *call,
					  DATA_BLOB *session_key)
{
	struct dcesrv_auth *auth = call->auth_state;
	SMB_ASSERT(auth->auth_finished);
	return dcesrv_session_info_session_key(auth, session_key);
}

/*
 * Fetch the transport session key if available.
 * Typically this is the SMB session key
 * or a fixed key for local transports.
 *
 * The key is always truncated to 16 bytes.
*/
_PUBLIC_ NTSTATUS dcesrv_transport_session_key(struct dcesrv_call_state *call,
					       DATA_BLOB *session_key)
{
	struct dcesrv_auth *auth = call->auth_state;
	NTSTATUS status;

	SMB_ASSERT(auth->auth_finished);

	if (auth->session_key_fn == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	status = auth->session_key_fn(auth, session_key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	session_key->length = MIN(session_key->length, 16);

	return NT_STATUS_OK;
}

static struct dcesrv_auth *dcesrv_auth_create(struct dcesrv_connection *conn)
{
	const struct dcesrv_endpoint *ep = conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(ep->ep_description);
	struct dcesrv_auth *auth = NULL;

	auth = talloc_zero(conn, struct dcesrv_auth);
	if (auth == NULL) {
		return NULL;
	}

	switch (transport) {
	case NCACN_NP:
		auth->session_key_fn = dcesrv_remote_session_key;
		break;
	case NCALRPC:
	case NCACN_UNIX_STREAM:
		auth->session_key_fn = dcesrv_local_fixed_session_key;
		break;
	default:
		/*
		 * All other's get a NULL pointer, which
		 * results in NT_STATUS_NO_USER_SESSION_KEY
		 */
		break;
	}

	return auth;
}

/*
  connect to a dcerpc endpoint
*/
_PUBLIC_ NTSTATUS dcesrv_endpoint_connect(struct dcesrv_context *dce_ctx,
				TALLOC_CTX *mem_ctx,
				const struct dcesrv_endpoint *ep,
				struct auth_session_info *session_info,
				struct tevent_context *event_ctx,
				uint32_t state_flags,
				struct dcesrv_connection **_p)
{
	struct dcesrv_auth *auth = NULL;
	struct dcesrv_connection *p;

	if (!session_info) {
		return NT_STATUS_ACCESS_DENIED;
	}

	p = talloc_zero(mem_ctx, struct dcesrv_connection);
	NT_STATUS_HAVE_NO_MEMORY(p);

	p->dce_ctx = dce_ctx;
	p->endpoint = ep;
	p->packet_log_dir = lpcfg_parm_string(dce_ctx->lp_ctx,
					      NULL,
					      "dcesrv",
					      "stubs directory");
	p->event_ctx = event_ctx;
	p->state_flags = state_flags;
	p->allow_bind = true;
	p->max_recv_frag = 5840;
	p->max_xmit_frag = 5840;
	p->max_total_request_size = DCERPC_NCACN_REQUEST_DEFAULT_MAX_SIZE;

	p->support_hdr_signing = lpcfg_parm_bool(dce_ctx->lp_ctx,
						 NULL,
						 "dcesrv",
						 "header signing",
						 true);
	p->max_auth_states = lpcfg_parm_ulong(dce_ctx->lp_ctx,
					      NULL,
					      "dcesrv",
					      "max auth states",
					      2049);

	auth = dcesrv_auth_create(p);
	if (auth == NULL) {
		talloc_free(p);
		return NT_STATUS_NO_MEMORY;
	}

	auth->session_info = talloc_reference(auth, session_info);
	if (auth->session_info == NULL) {
		talloc_free(p);
		return NT_STATUS_NO_MEMORY;
	}

	p->default_auth_state = auth;

	/*
	 * For now we only support NDR32.
	 */
	p->preferred_transfer = &ndr_transfer_syntax_ndr;

	*_p = p;
	return NT_STATUS_OK;
}

/*
  move a call from an existing linked list to the specified list. This
  prevents bugs where we forget to remove the call from a previous
  list when moving it.
 */
static void dcesrv_call_set_list(struct dcesrv_call_state *call,
				 enum dcesrv_call_list list)
{
	switch (call->list) {
	case DCESRV_LIST_NONE:
		break;
	case DCESRV_LIST_CALL_LIST:
		DLIST_REMOVE(call->conn->call_list, call);
		break;
	case DCESRV_LIST_FRAGMENTED_CALL_LIST:
		DLIST_REMOVE(call->conn->incoming_fragmented_call_list, call);
		break;
	case DCESRV_LIST_PENDING_CALL_LIST:
		DLIST_REMOVE(call->conn->pending_call_list, call);
		break;
	}
	call->list = list;
	switch (list) {
	case DCESRV_LIST_NONE:
		break;
	case DCESRV_LIST_CALL_LIST:
		DLIST_ADD_END(call->conn->call_list, call);
		break;
	case DCESRV_LIST_FRAGMENTED_CALL_LIST:
		DLIST_ADD_END(call->conn->incoming_fragmented_call_list, call);
		break;
	case DCESRV_LIST_PENDING_CALL_LIST:
		DLIST_ADD_END(call->conn->pending_call_list, call);
		break;
	}
}

static void dcesrv_call_disconnect_after(struct dcesrv_call_state *call,
					 const char *reason)
{
	struct dcesrv_auth *a = NULL;

	if (call->conn->terminate != NULL) {
		return;
	}

	call->conn->allow_bind = false;
	call->conn->allow_alter = false;

	call->conn->default_auth_state->auth_invalid = true;

	for (a = call->conn->auth_states; a != NULL; a = a->next) {
		a->auth_invalid = true;
	}

	call->terminate_reason = talloc_strdup(call, reason);
	if (call->terminate_reason == NULL) {
		call->terminate_reason = __location__;
	}
}

/*
  return a dcerpc bind_nak
*/
static NTSTATUS dcesrv_bind_nak(struct dcesrv_call_state *call, uint32_t reason)
{
	struct ncacn_packet pkt;
	struct dcerpc_bind_nak_version version;
	struct data_blob_list_item *rep;
	NTSTATUS status;
	static const uint8_t _pad[3] = { 0, };

	/*
	 * We add the call to the pending_call_list
	 * in order to defer the termination.
	 */
	dcesrv_call_disconnect_after(call, "dcesrv_bind_nak");

	/* setup a bind_nak */
	dcesrv_init_hdr(&pkt, lpcfg_rpc_big_endian(call->conn->dce_ctx->lp_ctx));
	pkt.auth_length = 0;
	pkt.call_id = call->pkt.call_id;
	pkt.ptype = DCERPC_PKT_BIND_NAK;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.u.bind_nak.reject_reason = reason;
	version.rpc_vers = 5;
	version.rpc_vers_minor = 0;
	pkt.u.bind_nak.num_versions = 1;
	pkt.u.bind_nak.versions = &version;
	pkt.u.bind_nak._pad = data_blob_const(_pad, sizeof(_pad));

	rep = talloc_zero(call, struct data_blob_list_item);
	if (!rep) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_ncacn_push_auth(&rep->blob, call, &pkt, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dcerpc_set_frag_length(&rep->blob, rep->blob.length);

	DLIST_ADD_END(call->replies, rep);
	dcesrv_call_set_list(call, DCESRV_LIST_CALL_LIST);

	if (call->conn->call_list && call->conn->call_list->replies) {
		if (call->conn->transport.report_output_data) {
			call->conn->transport.report_output_data(call->conn);
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_fault_disconnect(struct dcesrv_call_state *call,
				 uint32_t fault_code)
{
	/*
	 * We add the call to the pending_call_list
	 * in order to defer the termination.
	 */
	dcesrv_call_disconnect_after(call, "dcesrv_fault_disconnect");

	return dcesrv_fault_with_flags(call, fault_code,
				       DCERPC_PFC_FLAG_DID_NOT_EXECUTE);
}

static int dcesrv_connection_context_destructor(struct dcesrv_connection_context *c)
{
	DLIST_REMOVE(c->conn->contexts, c);

	if (c->iface && c->iface->unbind) {
		c->iface->unbind(c, c->iface);
		c->iface = NULL;
	}

	return 0;
}

static void dcesrv_prepare_context_auth(struct dcesrv_call_state *dce_call)
{
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	const struct dcesrv_endpoint *endpoint = dce_call->conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct dcesrv_connection_context *context = dce_call->context;
	const struct dcesrv_interface *iface = context->iface;

	context->min_auth_level = DCERPC_AUTH_LEVEL_NONE;

	if (transport == NCALRPC) {
		context->allow_connect = true;
		return;
	}

	/*
	 * allow overwrite per interface
	 * allow dcerpc auth level connect:<interface>
	 */
	context->allow_connect = lpcfg_allow_dcerpc_auth_level_connect(lp_ctx);
	context->allow_connect = lpcfg_parm_bool(lp_ctx, NULL,
					"allow dcerpc auth level connect",
					iface->name,
					context->allow_connect);
}

NTSTATUS dcesrv_interface_bind_require_integrity(struct dcesrv_connection_context *context,
						 const struct dcesrv_interface *iface)
{
	/*
	 * For connection oriented DCERPC DCERPC_AUTH_LEVEL_PACKET (4)
	 * has the same behavior as DCERPC_AUTH_LEVEL_INTEGRITY (5).
	 */
	context->min_auth_level = DCERPC_AUTH_LEVEL_PACKET;
	return NT_STATUS_OK;
}

NTSTATUS dcesrv_interface_bind_require_privacy(struct dcesrv_connection_context *context,
					       const struct dcesrv_interface *iface)
{
	context->min_auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcesrv_interface_bind_reject_connect(struct dcesrv_connection_context *context,
						       const struct dcesrv_interface *iface)
{
	struct loadparm_context *lp_ctx = context->conn->dce_ctx->lp_ctx;
	const struct dcesrv_endpoint *endpoint = context->conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);

	if (transport == NCALRPC) {
		context->allow_connect = true;
		return NT_STATUS_OK;
	}

	/*
	 * allow overwrite per interface
	 * allow dcerpc auth level connect:<interface>
	 */
	context->allow_connect = false;
	context->allow_connect = lpcfg_parm_bool(lp_ctx, NULL,
					"allow dcerpc auth level connect",
					iface->name,
					context->allow_connect);
	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcesrv_interface_bind_allow_connect(struct dcesrv_connection_context *context,
						      const struct dcesrv_interface *iface)
{
	struct loadparm_context *lp_ctx = context->conn->dce_ctx->lp_ctx;
	const struct dcesrv_endpoint *endpoint = context->conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);

	if (transport == NCALRPC) {
		context->allow_connect = true;
		return NT_STATUS_OK;
	}

	/*
	 * allow overwrite per interface
	 * allow dcerpc auth level connect:<interface>
	 */
	context->allow_connect = true;
	context->allow_connect = lpcfg_parm_bool(lp_ctx, NULL,
					"allow dcerpc auth level connect",
					iface->name,
					context->allow_connect);
	return NT_STATUS_OK;
}

struct dcesrv_conn_auth_wait_context {
	struct tevent_req *req;
	bool done;
	NTSTATUS status;
};

struct dcesrv_conn_auth_wait_state {
	uint8_t dummy;
};

static struct tevent_req *dcesrv_conn_auth_wait_send(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev,
						     void *private_data)
{
	struct dcesrv_conn_auth_wait_context *auth_wait =
		talloc_get_type_abort(private_data,
		struct dcesrv_conn_auth_wait_context);
	struct tevent_req *req = NULL;
	struct dcesrv_conn_auth_wait_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct dcesrv_conn_auth_wait_state);
	if (req == NULL) {
		return NULL;
	}
	auth_wait->req = req;

	tevent_req_defer_callback(req, ev);

	if (!auth_wait->done) {
		return req;
	}

	if (tevent_req_nterror(req, auth_wait->status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS dcesrv_conn_auth_wait_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS dcesrv_conn_auth_wait_setup(struct dcesrv_connection *conn)
{
	struct dcesrv_conn_auth_wait_context *auth_wait = NULL;

	if (conn->wait_send != NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	auth_wait = talloc_zero(conn, struct dcesrv_conn_auth_wait_context);
	if (auth_wait == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	conn->wait_private = auth_wait;
	conn->wait_send = dcesrv_conn_auth_wait_send;
	conn->wait_recv = dcesrv_conn_auth_wait_recv;
	return NT_STATUS_OK;
}

static void dcesrv_conn_auth_wait_finished(struct dcesrv_connection *conn,
					   NTSTATUS status)
{
	struct dcesrv_conn_auth_wait_context *auth_wait =
		talloc_get_type_abort(conn->wait_private,
		struct dcesrv_conn_auth_wait_context);

	auth_wait->done = true;
	auth_wait->status = status;

	if (auth_wait->req == NULL) {
		return;
	}

	if (tevent_req_nterror(auth_wait->req, status)) {
		return;
	}

	tevent_req_done(auth_wait->req);
}

static NTSTATUS dcesrv_auth_reply(struct dcesrv_call_state *call);

static void dcesrv_bind_done(struct tevent_req *subreq);

/*
  handle a bind request
*/
static NTSTATUS dcesrv_bind(struct dcesrv_call_state *call)
{
	struct dcesrv_connection *conn = call->conn;
	struct ncacn_packet *pkt = &call->ack_pkt;
	NTSTATUS status;
	uint32_t extra_flags = 0;
	uint16_t max_req = 0;
	uint16_t max_rep = 0;
	struct dcerpc_binding *ep_2nd_description = NULL;
	const char *endpoint = NULL;
	struct dcesrv_auth *auth = call->auth_state;
	struct dcerpc_ack_ctx *ack_ctx_list = NULL;
	struct dcerpc_ack_ctx *ack_features = NULL;
	struct tevent_req *subreq = NULL;
	size_t i;

	status = dcerpc_verify_ncacn_packet_header(&call->pkt,
			DCERPC_PKT_BIND,
			call->pkt.u.bind.auth_info.length,
			0, /* required flags */
			DCERPC_PFC_FLAG_FIRST |
			DCERPC_PFC_FLAG_LAST |
			DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
			0x08 | /* this is not defined, but should be ignored */
			DCERPC_PFC_FLAG_CONC_MPX |
			DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
			DCERPC_PFC_FLAG_MAYBE |
			DCERPC_PFC_FLAG_OBJECT_UUID);
	if (!NT_STATUS_IS_OK(status)) {
		return dcesrv_bind_nak(call,
			DCERPC_BIND_NAK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED);
	}

	/* max_recv_frag and max_xmit_frag result always in the same value! */
	max_req = MIN(call->pkt.u.bind.max_xmit_frag,
		      call->pkt.u.bind.max_recv_frag);
	/*
	 * The values are between 2048 and 5840 tested against Windows 2012R2
	 * via ncacn_ip_tcp on port 135.
	 */
	max_req = MAX(2048, max_req);
	max_rep = MIN(max_req, call->conn->max_recv_frag);
	/* They are truncated to an 8 byte boundary. */
	max_rep &= 0xFFF8;

	/* max_recv_frag and max_xmit_frag result always in the same value! */
	call->conn->max_recv_frag = max_rep;
	call->conn->max_xmit_frag = max_rep;

	status = call->conn->dce_ctx->callbacks.assoc_group.find(call);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Failed to find assoc_group 0x%08x: %s\n",
			   call->pkt.u.bind.assoc_group_id, nt_errstr(status));
		return dcesrv_bind_nak(call, 0);
	}

	if (call->pkt.u.bind.num_contexts < 1) {
		return dcesrv_bind_nak(call, 0);
	}

	ack_ctx_list = talloc_zero_array(call, struct dcerpc_ack_ctx,
					 call->pkt.u.bind.num_contexts);
	if (ack_ctx_list == NULL) {
		return dcesrv_bind_nak(call, 0);
	}

	/*
	 * Set some sane defaults (required by dcesrv_negotiate_contexts()/
	 * dcesrv_check_or_create_context()) and do some protocol validation
	 * and set sane defaults.
	 */
	for (i = 0; i < call->pkt.u.bind.num_contexts; i++) {
		const struct dcerpc_ctx_list *c = &call->pkt.u.bind.ctx_list[i];
		struct dcerpc_ack_ctx *a = &ack_ctx_list[i];
		bool is_feature = false;
		uint64_t features = 0;

		if (c->num_transfer_syntaxes == 0) {
			return dcesrv_bind_nak(call, 0);
		}

		a->result = DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
		a->reason.value = DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;

		/*
		 * It's only treated as bind time feature request, if the first
		 * transfer_syntax matches, all others are ignored.
		 */
		is_feature = dcerpc_extract_bind_time_features(c->transfer_syntaxes[0],
							       &features);
		if (!is_feature) {
			continue;
		}

		if (ack_features != NULL) {
			/*
			 * Only one bind time feature context is allowed.
			 */
			return dcesrv_bind_nak(call, 0);
		}
		ack_features = a;

		a->result = DCERPC_BIND_ACK_RESULT_NEGOTIATE_ACK;
		a->reason.negotiate = 0;
		if (features & DCERPC_BIND_TIME_SECURITY_CONTEXT_MULTIPLEXING) {
			if (call->conn->max_auth_states != 0) {
				a->reason.negotiate |=
				DCERPC_BIND_TIME_SECURITY_CONTEXT_MULTIPLEXING;
			}
		}
		if (features & DCERPC_BIND_TIME_KEEP_CONNECTION_ON_ORPHAN) {
			a->reason.negotiate |=
				DCERPC_BIND_TIME_KEEP_CONNECTION_ON_ORPHAN;
		}

		call->conn->assoc_group->bind_time_features = a->reason.negotiate;
	}

	/*
	 * Try to negotiate one new presentation context.
	 *
	 * Deep in here we locate the iface (by uuid) that the client
	 * requested, from the list of interfaces on the
	 * call->conn->endpoint, and call iface->bind() on that iface.
	 *
	 * call->conn was set up at the accept() of the socket, and
	 * call->conn->endpoint has a list of interfaces restricted to
	 * this port or pipe.
	 */
	status = dcesrv_negotiate_contexts(call, &call->pkt.u.bind, ack_ctx_list);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTOCOL_ERROR)) {
		return dcesrv_bind_nak(call, 0);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * At this point we still don't know which interface (eg
	 * netlogon, lsa, drsuapi) the caller requested in this bind!
	 * The most recently added context is available as the first
	 * element in the linked list at call->conn->contexts, that is
	 * call->conn->contexts->iface, but they may not have
	 * requested one at all!
	 */

	if ((call->pkt.pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) &&
	    (call->state_flags & DCESRV_CALL_STATE_FLAG_MULTIPLEXED)) {
		call->conn->state_flags |= DCESRV_CALL_STATE_FLAG_MULTIPLEXED;
		extra_flags |= DCERPC_PFC_FLAG_CONC_MPX;
	}

	if (call->state_flags & DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL) {
		call->conn->state_flags |= DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL;
	}

	/*
	 * After finding the interface and setting up the NDR
	 * transport negotiation etc, handle any authentication that
	 * is being requested.
	 */
	if (!dcesrv_auth_bind(call)) {

		if (auth->auth_level == DCERPC_AUTH_LEVEL_NONE) {
			/*
			 * With DCERPC_AUTH_LEVEL_NONE, we get the
			 * reject_reason in auth->auth_context_id.
			 */
			return dcesrv_bind_nak(call, auth->auth_context_id);
		}

		/*
		 * This must a be a temporary failure e.g. talloc or invalid
		 * configuration, e.g. no machine account.
		 */
		return dcesrv_bind_nak(call,
				DCERPC_BIND_NAK_REASON_TEMPORARY_CONGESTION);
	}

	/* setup a bind_ack */
	dcesrv_init_hdr(pkt, lpcfg_rpc_big_endian(call->conn->dce_ctx->lp_ctx));
	pkt->auth_length = 0;
	pkt->call_id = call->pkt.call_id;
	pkt->ptype = DCERPC_PKT_BIND_ACK;
	pkt->pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt->u.bind_ack.max_xmit_frag = call->conn->max_xmit_frag;
	pkt->u.bind_ack.max_recv_frag = call->conn->max_recv_frag;
	pkt->u.bind_ack.assoc_group_id = call->conn->assoc_group->id;

	ep_2nd_description = call->conn->endpoint->ep_2nd_description;
	if (ep_2nd_description == NULL) {
		ep_2nd_description = call->conn->endpoint->ep_description;
	}

	endpoint = dcerpc_binding_get_string_option(
				ep_2nd_description,
				"endpoint");
	if (endpoint == NULL) {
		endpoint = "";
	}

	pkt->u.bind_ack.secondary_address = endpoint;
	pkt->u.bind_ack.num_results = call->pkt.u.bind.num_contexts;
	pkt->u.bind_ack.ctx_list = ack_ctx_list;
	pkt->u.bind_ack.auth_info = data_blob_null;

	status = dcesrv_auth_prepare_bind_ack(call, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return dcesrv_bind_nak(call, 0);
	}

	if (auth->auth_finished) {
		return dcesrv_auth_reply(call);
	}

	subreq = gensec_update_send(call, call->event_ctx,
				    auth->gensec_security,
				    call->in_auth_info.credentials);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, dcesrv_bind_done, call);

	return dcesrv_conn_auth_wait_setup(conn);
}

static void dcesrv_bind_done(struct tevent_req *subreq)
{
	struct dcesrv_call_state *call =
		tevent_req_callback_data(subreq,
		struct dcesrv_call_state);
	struct dcesrv_connection *conn = call->conn;
	NTSTATUS status;

	status = gensec_update_recv(subreq, call,
				    &call->out_auth_info->credentials);
	TALLOC_FREE(subreq);

	status = dcesrv_auth_complete(call, status);
	if (!NT_STATUS_IS_OK(status)) {
		status = dcesrv_bind_nak(call, 0);
		dcesrv_conn_auth_wait_finished(conn, status);
		return;
	}

	status = dcesrv_auth_reply(call);
	dcesrv_conn_auth_wait_finished(conn, status);
	return;
}

static NTSTATUS dcesrv_auth_reply(struct dcesrv_call_state *call)
{
	struct ncacn_packet *pkt = &call->ack_pkt;
	struct data_blob_list_item *rep = NULL;
	NTSTATUS status;

	rep = talloc_zero(call, struct data_blob_list_item);
	if (!rep) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_ncacn_push_auth(&rep->blob,
					call,
					pkt,
					call->out_auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dcerpc_set_frag_length(&rep->blob, rep->blob.length);

	DLIST_ADD_END(call->replies, rep);
	dcesrv_call_set_list(call, DCESRV_LIST_CALL_LIST);

	if (call->conn->call_list && call->conn->call_list->replies) {
		if (call->conn->transport.report_output_data) {
			call->conn->transport.report_output_data(call->conn);
		}
	}

	return NT_STATUS_OK;
}


static void dcesrv_auth3_done(struct tevent_req *subreq);

/*
  handle a auth3 request
*/
static NTSTATUS dcesrv_auth3(struct dcesrv_call_state *call)
{
	struct dcesrv_connection *conn = call->conn;
	struct dcesrv_auth *auth = call->auth_state;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;

	if (!auth->auth_started) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	if (auth->auth_finished) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	status = dcerpc_verify_ncacn_packet_header(&call->pkt,
			DCERPC_PKT_AUTH3,
			call->pkt.u.auth3.auth_info.length,
			0, /* required flags */
			DCERPC_PFC_FLAG_FIRST |
			DCERPC_PFC_FLAG_LAST |
			DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
			0x08 | /* this is not defined, but should be ignored */
			DCERPC_PFC_FLAG_CONC_MPX |
			DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
			DCERPC_PFC_FLAG_MAYBE |
			DCERPC_PFC_FLAG_OBJECT_UUID);
	if (!NT_STATUS_IS_OK(status)) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	/* handle the auth3 in the auth code */
	if (!dcesrv_auth_prepare_auth3(call)) {
		/*
		 * we don't send a reply to a auth3 request,
		 * except by a fault.
		 *
		 * In anycase we mark the connection as
		 * invalid.
		 */
		auth->auth_invalid = true;
		if (call->fault_code != 0) {
			return dcesrv_fault_disconnect(call, call->fault_code);
		}
		TALLOC_FREE(call);
		return NT_STATUS_OK;
	}

	subreq = gensec_update_send(call, call->event_ctx,
				    auth->gensec_security,
				    call->in_auth_info.credentials);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, dcesrv_auth3_done, call);

	return dcesrv_conn_auth_wait_setup(conn);
}

static void dcesrv_auth3_done(struct tevent_req *subreq)
{
	struct dcesrv_call_state *call =
		tevent_req_callback_data(subreq,
		struct dcesrv_call_state);
	struct dcesrv_connection *conn = call->conn;
	struct dcesrv_auth *auth = call->auth_state;
	NTSTATUS status;

	status = gensec_update_recv(subreq, call,
				    &call->out_auth_info->credentials);
	TALLOC_FREE(subreq);

	status = dcesrv_auth_complete(call, status);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * we don't send a reply to a auth3 request,
		 * except by a fault.
		 *
		 * In anycase we mark the connection as
		 * invalid.
		 */
		auth->auth_invalid = true;
		if (call->fault_code != 0) {
			status = dcesrv_fault_disconnect(call, call->fault_code);
			dcesrv_conn_auth_wait_finished(conn, status);
			return;
		}
		TALLOC_FREE(call);
		dcesrv_conn_auth_wait_finished(conn, NT_STATUS_OK);
		return;
	}

	/*
	 * we don't send a reply to a auth3 request.
	 */
	TALLOC_FREE(call);
	dcesrv_conn_auth_wait_finished(conn, NT_STATUS_OK);
	return;
}


static NTSTATUS dcesrv_check_or_create_context(struct dcesrv_call_state *call,
				const struct dcerpc_bind *b,
				const struct dcerpc_ctx_list *ctx,
				struct dcerpc_ack_ctx *ack,
				bool validate_only,
				const struct ndr_syntax_id *supported_transfer)
{
	uint32_t if_version;
	struct dcesrv_connection_context *context;
	const struct dcesrv_interface *iface;
	struct GUID uuid;
	NTSTATUS status;
	const struct ndr_syntax_id *selected_transfer = NULL;
	size_t i;
	bool ok;

	if (b == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	if (ctx == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	if (ctx->num_transfer_syntaxes < 1) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	if (ack == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	if (supported_transfer == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	switch (ack->result) {
	case DCERPC_BIND_ACK_RESULT_ACCEPTANCE:
	case DCERPC_BIND_ACK_RESULT_NEGOTIATE_ACK:
		/*
		 * We is already completed.
		 */
		return NT_STATUS_OK;
	default:
		break;
	}

	ack->result = DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
	ack->reason.value = DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;

	if_version = ctx->abstract_syntax.if_version;
	uuid = ctx->abstract_syntax.uuid;

	iface = find_interface_by_uuid(call->conn->endpoint, &uuid, if_version);
	if (iface == NULL) {
		char *uuid_str = GUID_string(call, &uuid);
		DEBUG(2,("Request for unknown dcerpc interface %s/%d\n", uuid_str, if_version));
		talloc_free(uuid_str);
		/*
		 * We report this only via ack->result
		 */
		return NT_STATUS_OK;
	}

	ack->result = DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
	ack->reason.value = DCERPC_BIND_ACK_REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED;

	if (validate_only) {
		/*
		 * We report this only via ack->result
		 */
		return NT_STATUS_OK;
	}

	for (i = 0; i < ctx->num_transfer_syntaxes; i++) {
		/*
		 * we only do NDR encoded dcerpc for now.
		 */
		ok = ndr_syntax_id_equal(&ctx->transfer_syntaxes[i],
					 supported_transfer);
		if (ok) {
			selected_transfer = supported_transfer;
			break;
		}
	}

	context = dcesrv_find_context(call->conn, ctx->context_id);
	if (context != NULL) {
		ok = ndr_syntax_id_equal(&context->iface->syntax_id,
					 &ctx->abstract_syntax);
		if (!ok) {
			return NT_STATUS_RPC_PROTOCOL_ERROR;
		}

		if (selected_transfer != NULL) {
			ok = ndr_syntax_id_equal(&context->transfer_syntax,
						 selected_transfer);
			if (!ok) {
				return NT_STATUS_RPC_PROTOCOL_ERROR;
			}

			ack->result = DCERPC_BIND_ACK_RESULT_ACCEPTANCE;
			ack->reason.value = DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
			ack->syntax = context->transfer_syntax;
		}

		/*
		 * We report this only via ack->result
		 */
		return NT_STATUS_OK;
	}

	if (selected_transfer == NULL) {
		/*
		 * We report this only via ack->result
		 */
		return NT_STATUS_OK;
	}

	ack->result = DCERPC_BIND_ACK_RESULT_USER_REJECTION;
	ack->reason.value = DCERPC_BIND_ACK_REASON_LOCAL_LIMIT_EXCEEDED;

	/* add this context to the list of available context_ids */
	context = talloc_zero(call->conn, struct dcesrv_connection_context);
	if (context == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	context->conn = call->conn;
	context->context_id = ctx->context_id;
	context->iface = iface;
	context->transfer_syntax = *selected_transfer;
	DLIST_ADD(call->conn->contexts, context);
	call->context = context;
	talloc_set_destructor(context, dcesrv_connection_context_destructor);

	dcesrv_prepare_context_auth(call);

	/*
	 * Multiplex is supported by default
	 */
	call->state_flags |= DCESRV_CALL_STATE_FLAG_MULTIPLEXED;

	status = iface->bind(context, iface);
	call->context = NULL;
	if (!NT_STATUS_IS_OK(status)) {
		/* we don't want to trigger the iface->unbind() hook */
		context->iface = NULL;
		talloc_free(context);
		/*
		 * We report this only via ack->result
		 */
		return NT_STATUS_OK;
	}

	ack->result = DCERPC_BIND_ACK_RESULT_ACCEPTANCE;
	ack->reason.value = DCERPC_BIND_ACK_REASON_NOT_SPECIFIED;
	ack->syntax = context->transfer_syntax;
	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_negotiate_contexts(struct dcesrv_call_state *call,
				const struct dcerpc_bind *b,
				struct dcerpc_ack_ctx *ack_ctx_list)
{
	NTSTATUS status;
	size_t i;
	bool validate_only = false;
	bool preferred_ndr32;

	/*
	 * Try to negotiate one new presentation context,
	 * using our preferred transfer syntax.
	 */
	for (i = 0; i < b->num_contexts; i++) {
		const struct dcerpc_ctx_list *c = &b->ctx_list[i];
		struct dcerpc_ack_ctx *a = &ack_ctx_list[i];

		status = dcesrv_check_or_create_context(call, b, c, a,
						validate_only,
						call->conn->preferred_transfer);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (a->result == DCERPC_BIND_ACK_RESULT_ACCEPTANCE) {
			/*
			 * We managed to negotiate one context.
			 *
			 * => we're done.
			 */
			validate_only = true;
		}
	}

	preferred_ndr32 = ndr_syntax_id_equal(&ndr_transfer_syntax_ndr,
					call->conn->preferred_transfer);
	if (preferred_ndr32) {
		/*
		 * We're done.
		 */
		return NT_STATUS_OK;
	}

	/*
	 * Try to negotiate one new presentation context,
	 * using NDR 32 as fallback.
	 */
	for (i = 0; i < b->num_contexts; i++) {
		const struct dcerpc_ctx_list *c = &b->ctx_list[i];
		struct dcerpc_ack_ctx *a = &ack_ctx_list[i];

		status = dcesrv_check_or_create_context(call, b, c, a,
						validate_only,
						&ndr_transfer_syntax_ndr);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (a->result == DCERPC_BIND_ACK_RESULT_ACCEPTANCE) {
			/*
			 * We managed to negotiate one context.
			 *
			 * => we're done.
			 */
			validate_only = true;
		}
	}

	return NT_STATUS_OK;
}

static void dcesrv_alter_done(struct tevent_req *subreq);

/*
  handle a alter context request
*/
static NTSTATUS dcesrv_alter(struct dcesrv_call_state *call)
{
	struct dcesrv_connection *conn = call->conn;
	NTSTATUS status;
	bool auth_ok = false;
	struct ncacn_packet *pkt = &call->ack_pkt;
	uint32_t extra_flags = 0;
	struct dcesrv_auth *auth = call->auth_state;
	struct dcerpc_ack_ctx *ack_ctx_list = NULL;
	struct tevent_req *subreq = NULL;
	size_t i;

	if (!call->conn->allow_alter) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	status = dcerpc_verify_ncacn_packet_header(&call->pkt,
			DCERPC_PKT_ALTER,
			call->pkt.u.alter.auth_info.length,
			0, /* required flags */
			DCERPC_PFC_FLAG_FIRST |
			DCERPC_PFC_FLAG_LAST |
			DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN |
			0x08 | /* this is not defined, but should be ignored */
			DCERPC_PFC_FLAG_CONC_MPX |
			DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
			DCERPC_PFC_FLAG_MAYBE |
			DCERPC_PFC_FLAG_OBJECT_UUID);
	if (!NT_STATUS_IS_OK(status)) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	auth_ok = dcesrv_auth_alter(call);
	if (!auth_ok) {
		if (call->fault_code != 0) {
			return dcesrv_fault_disconnect(call, call->fault_code);
		}
	}

	if (call->pkt.u.alter.num_contexts < 1) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	ack_ctx_list = talloc_zero_array(call, struct dcerpc_ack_ctx,
					 call->pkt.u.alter.num_contexts);
	if (ack_ctx_list == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Set some sane defaults (required by dcesrv_negotiate_contexts()/
	 * dcesrv_check_or_create_context()) and do some protocol validation
	 * and set sane defaults.
	 */
	for (i = 0; i < call->pkt.u.alter.num_contexts; i++) {
		const struct dcerpc_ctx_list *c = &call->pkt.u.alter.ctx_list[i];
		struct dcerpc_ack_ctx *a = &ack_ctx_list[i];

		if (c->num_transfer_syntaxes == 0) {
			return dcesrv_fault_disconnect(call,
					DCERPC_NCA_S_PROTO_ERROR);
		}

		a->result = DCERPC_BIND_ACK_RESULT_PROVIDER_REJECTION;
		a->reason.value = DCERPC_BIND_ACK_REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED;
	}

	/*
	 * Try to negotiate one new presentation context.
	 */
	status = dcesrv_negotiate_contexts(call, &call->pkt.u.alter, ack_ctx_list);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTOCOL_ERROR)) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((call->pkt.pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) &&
	    (call->state_flags & DCESRV_CALL_STATE_FLAG_MULTIPLEXED)) {
		call->conn->state_flags |= DCESRV_CALL_STATE_FLAG_MULTIPLEXED;
		extra_flags |= DCERPC_PFC_FLAG_CONC_MPX;
	}

	if (call->state_flags & DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL) {
		call->conn->state_flags |= DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL;
	}

	/* handle any authentication that is being requested */
	if (!auth_ok) {
		if (call->in_auth_info.auth_type != auth->auth_type) {
			return dcesrv_fault_disconnect(call,
					DCERPC_FAULT_SEC_PKG_ERROR);
		}
		return dcesrv_fault_disconnect(call, DCERPC_FAULT_ACCESS_DENIED);
	}

	dcesrv_init_hdr(pkt, lpcfg_rpc_big_endian(call->conn->dce_ctx->lp_ctx));
	pkt->auth_length = 0;
	pkt->call_id = call->pkt.call_id;
	pkt->ptype = DCERPC_PKT_ALTER_RESP;
	pkt->pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt->u.alter_resp.max_xmit_frag = call->conn->max_xmit_frag;
	pkt->u.alter_resp.max_recv_frag = call->conn->max_recv_frag;
	pkt->u.alter_resp.assoc_group_id = call->conn->assoc_group->id;
	pkt->u.alter_resp.secondary_address = "";
	pkt->u.alter_resp.num_results = call->pkt.u.alter.num_contexts;
	pkt->u.alter_resp.ctx_list = ack_ctx_list;
	pkt->u.alter_resp.auth_info = data_blob_null;

	status = dcesrv_auth_prepare_alter_ack(call, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return dcesrv_fault_disconnect(call, DCERPC_FAULT_SEC_PKG_ERROR);
	}

	if (auth->auth_finished) {
		return dcesrv_auth_reply(call);
	}

	subreq = gensec_update_send(call, call->event_ctx,
				    auth->gensec_security,
				    call->in_auth_info.credentials);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, dcesrv_alter_done, call);

	return dcesrv_conn_auth_wait_setup(conn);
}

static void dcesrv_alter_done(struct tevent_req *subreq)
{
	struct dcesrv_call_state *call =
		tevent_req_callback_data(subreq,
		struct dcesrv_call_state);
	struct dcesrv_connection *conn = call->conn;
	NTSTATUS status;

	status = gensec_update_recv(subreq, call,
				    &call->out_auth_info->credentials);
	TALLOC_FREE(subreq);

	status = dcesrv_auth_complete(call, status);
	if (!NT_STATUS_IS_OK(status)) {
		status = dcesrv_fault_disconnect(call, DCERPC_FAULT_SEC_PKG_ERROR);
		dcesrv_conn_auth_wait_finished(conn, status);
		return;
	}

	status = dcesrv_auth_reply(call);
	dcesrv_conn_auth_wait_finished(conn, status);
	return;
}

/*
  possibly save the call for inspection with ndrdump
 */
static void dcesrv_save_call(struct dcesrv_call_state *call, const char *why)
{
#ifdef DEVELOPER
	dcerpc_log_packet(call->conn->packet_log_dir,
			  call->context->iface->name,
			  call->pkt.u.request.opnum,
			  NDR_IN,
			  &call->pkt.u.request.stub_and_verifier,
			  why);
#endif
}

#ifdef DEVELOPER
/*
  Save the call for use as a seed for fuzzing.

  This is only enabled in a developer build, and only has effect if the
  "dcesrv fuzz directory" param is set.
*/
void _dcesrv_save_ndr_fuzz_seed(DATA_BLOB call_blob,
				struct dcesrv_call_state *call,
				int flags)
{
	const char *dump_dir = lpcfg_parm_string(call->conn->dce_ctx->lp_ctx,
						 NULL,
						 "dcesrv", "fuzz directory");

	dcerpc_save_ndr_fuzz_seed(call,
				  call_blob,
				  dump_dir,
				  call->context->iface->name,
				  flags,
				  call->pkt.u.request.opnum,
				  call->ndr_pull->flags & LIBNDR_FLAG_NDR64);
}
#endif /*if DEVELOPER, enveloping _dcesrv_save_ndr_fuzz_seed() */


static NTSTATUS dcesrv_check_verification_trailer(struct dcesrv_call_state *call)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const uint32_t bitmask1 = call->conn->client_hdr_signing ?
		DCERPC_SEC_VT_CLIENT_SUPPORTS_HEADER_SIGNING : 0;
	const struct dcerpc_sec_vt_pcontext pcontext = {
		.abstract_syntax = call->context->iface->syntax_id,
		.transfer_syntax = call->context->transfer_syntax,
	};
	const struct dcerpc_sec_vt_header2 header2 =
		dcerpc_sec_vt_header2_from_ncacn_packet(&call->pkt);
	enum ndr_err_code ndr_err;
	struct dcerpc_sec_verification_trailer *vt = NULL;
	NTSTATUS status = NT_STATUS_OK;
	bool ok;

	SMB_ASSERT(call->pkt.ptype == DCERPC_PKT_REQUEST);

	ndr_err = ndr_pop_dcerpc_sec_verification_trailer(call->ndr_pull,
							  frame, &vt);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		goto done;
	}

	ok = dcerpc_sec_verification_trailer_check(vt, &bitmask1,
						   &pcontext, &header2);
	if (!ok) {
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}
done:
	TALLOC_FREE(frame);
	return status;
}

/*
  handle a dcerpc request packet
*/
static NTSTATUS dcesrv_request(struct dcesrv_call_state *call)
{
	const struct dcesrv_endpoint *endpoint = call->conn->endpoint;
	struct dcesrv_auth *auth = call->auth_state;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct ndr_pull *pull;
	NTSTATUS status;

	if (!auth->auth_finished) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	/* if authenticated, and the mech we use can't do async replies, don't use them... */
	if (auth->gensec_security != NULL &&
	    !gensec_have_feature(auth->gensec_security, GENSEC_FEATURE_ASYNC_REPLIES)) {
		call->state_flags &= ~DCESRV_CALL_STATE_FLAG_MAY_ASYNC;
	}

	if (call->context == NULL) {
		return dcesrv_fault_with_flags(call, DCERPC_NCA_S_UNKNOWN_IF,
					DCERPC_PFC_FLAG_DID_NOT_EXECUTE);
	}

	switch (auth->auth_level) {
	case DCERPC_AUTH_LEVEL_NONE:
	case DCERPC_AUTH_LEVEL_PACKET:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PRIVACY:
		break;
	default:
		if (!call->context->allow_connect) {
			char *addr;

			addr = tsocket_address_string(call->conn->remote_address,
						      call);

			DEBUG(2, ("%s: restrict auth_level_connect access "
				  "to [%s] with auth[type=0x%x,level=0x%x] "
				  "on [%s] from [%s]\n",
				  __func__, call->context->iface->name,
				  auth->auth_type,
				  auth->auth_level,
				  derpc_transport_string_by_transport(transport),
				  addr));
			return dcesrv_fault(call, DCERPC_FAULT_ACCESS_DENIED);
		}
		break;
	}

	if (auth->auth_level < call->context->min_auth_level) {
		char *addr;

		addr = tsocket_address_string(call->conn->remote_address, call);

		DEBUG(2, ("%s: restrict access by min_auth_level[0x%x] "
			  "to [%s] with auth[type=0x%x,level=0x%x] "
			  "on [%s] from [%s]\n",
			  __func__,
			  call->context->min_auth_level,
			  call->context->iface->name,
			  auth->auth_type,
			  auth->auth_level,
			  derpc_transport_string_by_transport(transport),
			  addr));
		return dcesrv_fault(call, DCERPC_FAULT_ACCESS_DENIED);
	}

	pull = ndr_pull_init_blob(&call->pkt.u.request.stub_and_verifier, call);
	NT_STATUS_HAVE_NO_MEMORY(pull);

	pull->flags |= LIBNDR_FLAG_REF_ALLOC;

	call->ndr_pull	= pull;

	if (!(call->pkt.drep[0] & DCERPC_DREP_LE)) {
		pull->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	status = dcesrv_check_verification_trailer(call);
	if (!NT_STATUS_IS_OK(status)) {
		uint32_t faultcode = DCERPC_FAULT_OTHER;
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			faultcode = DCERPC_FAULT_ACCESS_DENIED;
		}
		DEBUG(10, ("dcesrv_check_verification_trailer failed: %s\n",
			   nt_errstr(status)));
		return dcesrv_fault(call, faultcode);
	}

	/* unravel the NDR for the packet */
	status = call->context->iface->ndr_pull(call, call, pull, &call->r);
	if (!NT_STATUS_IS_OK(status)) {
		uint8_t extra_flags = 0;
		if (call->fault_code == DCERPC_FAULT_OP_RNG_ERROR) {
			/* we got an unknown call */
			DEBUG(3,(__location__ ": Unknown RPC call %u on %s\n",
				 call->pkt.u.request.opnum,
				 call->context->iface->name));
			dcesrv_save_call(call, "unknown");
			extra_flags |= DCERPC_PFC_FLAG_DID_NOT_EXECUTE;
		} else {
			dcesrv_save_call(call, "pullfail");
		}

		return dcesrv_fault_with_flags(call, call->fault_code, extra_flags);
	}

	dcesrv_save_ndr_fuzz_seed(call->pkt.u.request.stub_and_verifier,
				  call,
				  NDR_IN);

	if (pull->offset != pull->data_size) {
		dcesrv_save_call(call, "extrabytes");
		DEBUG(3,("Warning: %d extra bytes in incoming RPC request\n",
			 pull->data_size - pull->offset));
	}

	/* call the dispatch function */
	status = call->context->iface->dispatch(call, call, call->r);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("dcerpc fault in call %s:%02x - %s\n",
			 call->context->iface->name,
			 call->pkt.u.request.opnum,
			 dcerpc_errstr(pull, call->fault_code)));
		return dcesrv_fault(call, call->fault_code);
	}

	/* add the call to the pending list */
	dcesrv_call_set_list(call, DCESRV_LIST_PENDING_CALL_LIST);

	if (call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return NT_STATUS_OK;
	}

	return dcesrv_reply(call);
}


/*
  remove the call from the right list when freed
 */
static int dcesrv_call_dequeue(struct dcesrv_call_state *call)
{
	dcesrv_call_set_list(call, DCESRV_LIST_NONE);
	return 0;
}

_PUBLIC_ const struct tsocket_address *dcesrv_connection_get_local_address(struct dcesrv_connection *conn)
{
	return conn->local_address;
}

_PUBLIC_ const struct tsocket_address *dcesrv_connection_get_remote_address(struct dcesrv_connection *conn)
{
	return conn->remote_address;
}

/*
  process some input to a dcerpc endpoint server.
*/
static NTSTATUS dcesrv_process_ncacn_packet(struct dcesrv_connection *dce_conn,
					    struct ncacn_packet *pkt,
					    DATA_BLOB blob)
{
	NTSTATUS status;
	struct dcesrv_call_state *call;
	struct dcesrv_call_state *existing = NULL;
	size_t num_auth_ctx = 0;
	enum dcerpc_AuthType auth_type = 0;
	enum dcerpc_AuthLevel auth_level = 0;
	uint32_t auth_context_id = 0;

	call = talloc_zero(dce_conn, struct dcesrv_call_state);
	if (!call) {
		data_blob_free(&blob);
		talloc_free(pkt);
		return NT_STATUS_NO_MEMORY;
	}
	call->conn		= dce_conn;
	call->event_ctx		= dce_conn->event_ctx;
	call->state_flags	= call->conn->state_flags;
	call->time		= timeval_current();
	call->list              = DCESRV_LIST_NONE;

	talloc_steal(call, pkt);
	talloc_steal(call, blob.data);
	call->pkt = *pkt;

	if (dce_conn->max_auth_states == 0) {
		call->auth_state = dce_conn->default_auth_state;
	} else if (call->pkt.auth_length == 0) {
		if (call->pkt.ptype == DCERPC_PKT_REQUEST &&
		    dce_conn->default_auth_level_connect != NULL)
		{
			call->auth_state = dce_conn->default_auth_level_connect;
		} else {
			call->auth_state = dce_conn->default_auth_state;
		}
	}

	if (call->auth_state == NULL) {
		struct dcesrv_auth *a = NULL;

		auth_type = dcerpc_get_auth_type(&blob);
		auth_level = dcerpc_get_auth_level(&blob);
		auth_context_id = dcerpc_get_auth_context_id(&blob);

		if (call->pkt.ptype == DCERPC_PKT_REQUEST) {
			dce_conn->default_auth_level_connect = NULL;
			if (auth_level == DCERPC_AUTH_LEVEL_CONNECT) {
				dce_conn->got_explicit_auth_level_connect = true;
			}
		}

		for (a = dce_conn->auth_states; a != NULL; a = a->next) {
			num_auth_ctx++;

			if (a->auth_type != auth_type) {
				continue;
			}
			if (a->auth_finished && a->auth_level != auth_level) {
				continue;
			}
			if (a->auth_context_id != auth_context_id) {
				continue;
			}

			DLIST_PROMOTE(dce_conn->auth_states, a);
			call->auth_state = a;
			break;
		}
	}

	if (call->auth_state == NULL) {
		struct dcesrv_auth *a = NULL;

		if (num_auth_ctx >= dce_conn->max_auth_states) {
			return dcesrv_fault_disconnect(call,
					DCERPC_NCA_S_PROTO_ERROR);
		}

		a = dcesrv_auth_create(dce_conn);
		if (a == NULL) {
			talloc_free(call);
			return NT_STATUS_NO_MEMORY;
		}
		DLIST_ADD(dce_conn->auth_states, a);
		if (call->pkt.ptype == DCERPC_PKT_REQUEST) {
			/*
			 * This can never be valid.
			 */
			a->auth_invalid = true;
		}
		call->auth_state = a;
	}

	talloc_set_destructor(call, dcesrv_call_dequeue);

	if (call->conn->allow_bind) {
		/*
		 * Only one bind is possible per connection
		 */
		call->conn->allow_bind = false;
		return dcesrv_bind(call);
	}

	/* we have to check the signing here, before combining the
	   pdus */
	if (call->pkt.ptype == DCERPC_PKT_REQUEST) {
		dcesrv_default_auth_state_prepare_request(call);

		if (call->auth_state->auth_started &&
		    !call->auth_state->auth_finished) {
			return dcesrv_fault_disconnect(call,
					DCERPC_NCA_S_PROTO_ERROR);
		}

		status = dcerpc_verify_ncacn_packet_header(&call->pkt,
				DCERPC_PKT_REQUEST,
				call->pkt.u.request.stub_and_verifier.length,
				0, /* required_flags */
				DCERPC_PFC_FLAG_FIRST |
				DCERPC_PFC_FLAG_LAST |
				DCERPC_PFC_FLAG_PENDING_CANCEL |
				0x08 | /* this is not defined, but should be ignored */
				DCERPC_PFC_FLAG_CONC_MPX |
				DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
				DCERPC_PFC_FLAG_MAYBE |
				DCERPC_PFC_FLAG_OBJECT_UUID);
		if (!NT_STATUS_IS_OK(status)) {
			return dcesrv_fault_disconnect(call,
					DCERPC_NCA_S_PROTO_ERROR);
		}

		if (call->pkt.frag_length > DCERPC_FRAG_MAX_SIZE) {
			/*
			 * We don't use dcesrv_fault_disconnect()
			 * here, because we don't want to set
			 * DCERPC_PFC_FLAG_DID_NOT_EXECUTE
			 *
			 * Note that we don't check against the negotiated
			 * max_recv_frag, but a hard coded value.
			 */
			dcesrv_call_disconnect_after(call,
				"dcesrv_auth_request - frag_length too large");
			return dcesrv_fault(call,
					DCERPC_NCA_S_PROTO_ERROR);
		}

		if (call->pkt.pfc_flags & DCERPC_PFC_FLAG_FIRST) {
			if (dce_conn->pending_call_list != NULL) {
				/*
				 * concurrent requests are only allowed
				 * if DCERPC_PFC_FLAG_CONC_MPX was negotiated.
				 */
				if (!(dce_conn->state_flags & DCESRV_CALL_STATE_FLAG_MULTIPLEXED)) {
					dcesrv_call_disconnect_after(call,
						"dcesrv_auth_request - "
						"existing pending call without CONN_MPX");
					return dcesrv_fault(call,
						DCERPC_NCA_S_PROTO_ERROR);
				}
			}
			/* only one request is possible in the fragmented list */
			if (dce_conn->incoming_fragmented_call_list != NULL) {
				if (!(dce_conn->state_flags & DCESRV_CALL_STATE_FLAG_MULTIPLEXED)) {
					/*
					 * Without DCERPC_PFC_FLAG_CONC_MPX
					 * we need to return the FAULT on the
					 * already existing call.
					 *
					 * This is important to get the
					 * call_id and context_id right.
					 */
					TALLOC_FREE(call);
					call = dce_conn->incoming_fragmented_call_list;
				}
				dcesrv_call_disconnect_after(call,
					"dcesrv_auth_request - "
					"existing fragmented call");
				return dcesrv_fault(call,
						DCERPC_NCA_S_PROTO_ERROR);
			}
			if (call->pkt.pfc_flags & DCERPC_PFC_FLAG_PENDING_CANCEL) {
				return dcesrv_fault_disconnect(call,
						DCERPC_FAULT_NO_CALL_ACTIVE);
			}
			call->context = dcesrv_find_context(call->conn,
						call->pkt.u.request.context_id);
			if (call->context == NULL) {
				return dcesrv_fault_with_flags(call, DCERPC_NCA_S_UNKNOWN_IF,
					DCERPC_PFC_FLAG_DID_NOT_EXECUTE);
			}
		} else {
			const struct dcerpc_request *nr = &call->pkt.u.request;
			const struct dcerpc_request *er = NULL;
			int cmp;

			existing = dcesrv_find_fragmented_call(dce_conn,
							call->pkt.call_id);
			if (existing == NULL) {
				dcesrv_call_disconnect_after(call,
					"dcesrv_auth_request - "
					"no existing fragmented call");
				return dcesrv_fault(call,
						DCERPC_NCA_S_PROTO_ERROR);
			}
			er = &existing->pkt.u.request;

			if (call->pkt.ptype != existing->pkt.ptype) {
				/* trying to play silly buggers are we? */
				return dcesrv_fault_disconnect(existing,
						DCERPC_NCA_S_PROTO_ERROR);
			}
			cmp = memcmp(call->pkt.drep, existing->pkt.drep,
				     sizeof(pkt->drep));
			if (cmp != 0) {
				return dcesrv_fault_disconnect(existing,
						DCERPC_NCA_S_PROTO_ERROR);
			}
			if (nr->context_id != er->context_id)  {
				return dcesrv_fault_disconnect(existing,
						DCERPC_NCA_S_PROTO_ERROR);
			}
			if (nr->opnum != er->opnum)  {
				return dcesrv_fault_disconnect(existing,
						DCERPC_NCA_S_PROTO_ERROR);
			}
		}
	}

	if (call->pkt.ptype == DCERPC_PKT_REQUEST) {
		bool ok;
		uint8_t payload_offset = DCERPC_REQUEST_LENGTH;

		if (call->pkt.pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
			payload_offset += 16;
		}

		ok = dcesrv_auth_pkt_pull(call, &blob,
					  0, /* required_flags */
					  DCERPC_PFC_FLAG_FIRST |
					  DCERPC_PFC_FLAG_LAST |
					  DCERPC_PFC_FLAG_PENDING_CANCEL |
					  0x08 | /* this is not defined, but should be ignored */
					  DCERPC_PFC_FLAG_CONC_MPX |
					  DCERPC_PFC_FLAG_DID_NOT_EXECUTE |
					  DCERPC_PFC_FLAG_MAYBE |
					  DCERPC_PFC_FLAG_OBJECT_UUID,
					  payload_offset,
					  &call->pkt.u.request.stub_and_verifier);
		if (!ok) {
			/*
			 * We don't use dcesrv_fault_disconnect()
			 * here, because we don't want to set
			 * DCERPC_PFC_FLAG_DID_NOT_EXECUTE
			 */
			dcesrv_call_disconnect_after(call,
						"dcesrv_auth_request - failed");
			if (call->fault_code == 0) {
				call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
			}
			return dcesrv_fault(call, call->fault_code);
		}
	}

	/* see if this is a continued packet */
	if (existing != NULL) {
		struct dcerpc_request *er = &existing->pkt.u.request;
		const struct dcerpc_request *nr = &call->pkt.u.request;
		size_t available;
		size_t alloc_size;
		size_t alloc_hint;

		/*
		 * Up to 4 MByte are allowed by all fragments
		 */
		available = dce_conn->max_total_request_size;
		if (er->stub_and_verifier.length > available) {
			dcesrv_call_disconnect_after(existing,
				"dcesrv_auth_request - existing payload too large");
			return dcesrv_fault(existing, DCERPC_FAULT_ACCESS_DENIED);
		}
		available -= er->stub_and_verifier.length;
		if (nr->alloc_hint > available) {
			dcesrv_call_disconnect_after(existing,
				"dcesrv_auth_request - alloc hint too large");
			return dcesrv_fault(existing, DCERPC_FAULT_ACCESS_DENIED);
		}
		if (nr->stub_and_verifier.length > available) {
			dcesrv_call_disconnect_after(existing,
				"dcesrv_auth_request - new payload too large");
			return dcesrv_fault(existing, DCERPC_FAULT_ACCESS_DENIED);
		}
		alloc_hint = er->stub_and_verifier.length + nr->alloc_hint;
		/* allocate at least 1 byte */
		alloc_hint = MAX(alloc_hint, 1);
		alloc_size = er->stub_and_verifier.length +
			     nr->stub_and_verifier.length;
		alloc_size = MAX(alloc_size, alloc_hint);

		er->stub_and_verifier.data =
			talloc_realloc(existing,
				       er->stub_and_verifier.data,
				       uint8_t, alloc_size);
		if (er->stub_and_verifier.data == NULL) {
			TALLOC_FREE(call);
			return dcesrv_fault_with_flags(existing,
						       DCERPC_FAULT_OUT_OF_RESOURCES,
						       DCERPC_PFC_FLAG_DID_NOT_EXECUTE);
		}
		memcpy(er->stub_and_verifier.data +
		       er->stub_and_verifier.length,
		       nr->stub_and_verifier.data,
		       nr->stub_and_verifier.length);
		er->stub_and_verifier.length += nr->stub_and_verifier.length;

		existing->pkt.pfc_flags |= (call->pkt.pfc_flags & DCERPC_PFC_FLAG_LAST);

		TALLOC_FREE(call);
		call = existing;
	}

	/* this may not be the last pdu in the chain - if its isn't then
	   just put it on the incoming_fragmented_call_list and wait for the rest */
	if (call->pkt.ptype == DCERPC_PKT_REQUEST &&
	    !(call->pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) {
		/*
		 * Up to 4 MByte are allowed by all fragments
		 */
		if (call->pkt.u.request.alloc_hint > dce_conn->max_total_request_size) {
			dcesrv_call_disconnect_after(call,
				"dcesrv_auth_request - initial alloc hint too large");
			return dcesrv_fault(call, DCERPC_FAULT_ACCESS_DENIED);
		}
		dcesrv_call_set_list(call, DCESRV_LIST_FRAGMENTED_CALL_LIST);
		return NT_STATUS_OK;
	}

	/* This removes any fragments we may have had stashed away */
	dcesrv_call_set_list(call, DCESRV_LIST_NONE);

	switch (call->pkt.ptype) {
	case DCERPC_PKT_BIND:
		status = dcesrv_bind_nak(call,
			DCERPC_BIND_NAK_REASON_NOT_SPECIFIED);
		break;
	case DCERPC_PKT_AUTH3:
		status = dcesrv_auth3(call);
		break;
	case DCERPC_PKT_ALTER:
		status = dcesrv_alter(call);
		break;
	case DCERPC_PKT_REQUEST:
		status = dcesrv_request(call);
		break;
	case DCERPC_PKT_CO_CANCEL:
	case DCERPC_PKT_ORPHANED:
		/*
		 * Window just ignores CO_CANCEL and ORPHANED,
		 * so we do...
		 */
		status = NT_STATUS_OK;
		TALLOC_FREE(call);
		break;
	case DCERPC_PKT_BIND_ACK:
	case DCERPC_PKT_BIND_NAK:
	case DCERPC_PKT_ALTER_RESP:
	case DCERPC_PKT_RESPONSE:
	case DCERPC_PKT_FAULT:
	case DCERPC_PKT_SHUTDOWN:
	default:
		status = dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
		break;
	}

	/* if we are going to be sending a reply then add
	   it to the list of pending calls. We add it to the end to keep the call
	   list in the order we will answer */
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(call);
	}

	return status;
}

_PUBLIC_ NTSTATUS dcesrv_init_context(TALLOC_CTX *mem_ctx,
				      struct loadparm_context *lp_ctx,
				      struct dcesrv_context_callbacks *cb,
				      struct dcesrv_context **_dce_ctx)
{
	struct dcesrv_context *dce_ctx;

	dce_ctx = talloc_zero(mem_ctx, struct dcesrv_context);
	NT_STATUS_HAVE_NO_MEMORY(dce_ctx);

	if (uid_wrapper_enabled()) {
		setenv("UID_WRAPPER_MYUID", "1", 1);
	}
	dce_ctx->initial_euid = geteuid();
	if (uid_wrapper_enabled()) {
		unsetenv("UID_WRAPPER_MYUID");
	}

	dce_ctx->endpoint_list	= NULL;
	dce_ctx->lp_ctx = lp_ctx;
	dce_ctx->assoc_groups_idr = idr_init(dce_ctx);
	NT_STATUS_HAVE_NO_MEMORY(dce_ctx->assoc_groups_idr);
	dce_ctx->broken_connections = NULL;
	if (cb != NULL) {
		dce_ctx->callbacks = *cb;
	}

	*_dce_ctx = dce_ctx;
	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcesrv_reinit_context(struct dcesrv_context *dce_ctx)
{
	NTSTATUS status;

	status = dcesrv_shutdown_registered_ep_servers(dce_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Clear endpoints */
	while (dce_ctx->endpoint_list != NULL) {
		struct dcesrv_endpoint *e = dce_ctx->endpoint_list;
		DLIST_REMOVE(dce_ctx->endpoint_list, e);
		TALLOC_FREE(e);
	}

	/* Remove broken connections */
	dcesrv_cleanup_broken_connections(dce_ctx);

	/* Reinit assoc group idr */
	TALLOC_FREE(dce_ctx->assoc_groups_idr);
	dce_ctx->assoc_groups_idr = idr_init(dce_ctx);
	if (dce_ctx->assoc_groups_idr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcesrv_init_ep_servers(struct dcesrv_context *dce_ctx,
					 const char **endpoint_servers)
{
	NTSTATUS status;
	int i;

	if (endpoint_servers == NULL) {
		DBG_ERR("No endpoint servers configured\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (i=0;endpoint_servers[i];i++) {
		status = dcesrv_init_ep_server(dce_ctx, endpoint_servers[i]);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("failed to init endpoint server = '%s': %s\n",
				endpoint_servers[i], nt_errstr(status));
			return status;
		}
	}

	return NT_STATUS_OK;
}

/* the list of currently registered DCERPC endpoint servers.
 */
static struct ep_server {
	struct dcesrv_endpoint_server *ep_server;
} *ep_servers = NULL;
static int num_ep_servers = 0;

_PUBLIC_ NTSTATUS dcesrv_init_registered_ep_servers(
					struct dcesrv_context *dce_ctx)
{
	NTSTATUS status;
	int i;

	for (i = 0; i < num_ep_servers; i++) {
		status = dcesrv_init_ep_server(dce_ctx,
					       ep_servers[i].ep_server->name);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcesrv_init_ep_server(struct dcesrv_context *dce_ctx,
					const char *ep_server_name)
{
	struct dcesrv_endpoint_server *ep_server = NULL;
	NTSTATUS status;

	ep_server = discard_const_p(struct dcesrv_endpoint_server,
				    dcesrv_ep_server_byname(ep_server_name));
	if (ep_server == NULL) {
		DBG_ERR("Failed to find endpoint server '%s'\n",
			ep_server_name);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (ep_server->initialized) {
		return NT_STATUS_OK;
	}

	status = ep_server->init_server(dce_ctx, ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to init endpoint server '%s': %s\n",
			ep_server_name, nt_errstr(status));
		return status;
	}

	ep_server->initialized = true;

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcesrv_shutdown_registered_ep_servers(
					struct dcesrv_context *dce_ctx)
{
	NTSTATUS status;
	int i;

	for (i = 0; i < num_ep_servers; i++) {
		status = dcesrv_shutdown_ep_server(dce_ctx,
					ep_servers[i].ep_server->name);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcesrv_shutdown_ep_server(struct dcesrv_context *dce_ctx,
					    const char *ep_server_name)
{
	struct dcesrv_endpoint_server *ep_server = NULL;
	NTSTATUS status;

	ep_server = discard_const_p(struct dcesrv_endpoint_server,
				    dcesrv_ep_server_byname(ep_server_name));
	if (ep_server == NULL) {
		DBG_ERR("Failed to find endpoint server '%s'\n",
			ep_server_name);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (!ep_server->initialized) {
		return NT_STATUS_OK;
	}

	DBG_INFO("Shutting down DCE/RPC endpoint server '%s'\n",
		 ep_server_name);

	status = ep_server->shutdown_server(dce_ctx, ep_server);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to shutdown endpoint server '%s': %s\n",
			ep_server_name, nt_errstr(status));
		return status;
	}

	ep_server->initialized = false;

	return NT_STATUS_OK;
}

/*
  register a DCERPC endpoint server.

  The 'name' can be later used by other backends to find the operations
  structure for this backend.

*/
_PUBLIC_ NTSTATUS dcerpc_register_ep_server(const struct dcesrv_endpoint_server *ep_server)
{

	if (dcesrv_ep_server_byname(ep_server->name) != NULL) {
		/* its already registered! */
		DEBUG(0,("DCERPC endpoint server '%s' already registered\n",
			 ep_server->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	ep_servers = realloc_p(ep_servers, struct ep_server, num_ep_servers+1);
	if (!ep_servers) {
		smb_panic("out of memory in dcerpc_register");
	}

	ep_servers[num_ep_servers].ep_server = smb_xmemdup(ep_server, sizeof(*ep_server));
	ep_servers[num_ep_servers].ep_server->name = smb_xstrdup(ep_server->name);

	num_ep_servers++;

	DEBUG(3,("DCERPC endpoint server '%s' registered\n",
		 ep_server->name));

	return NT_STATUS_OK;
}

/*
  return the operations structure for a named backend of the specified type
*/
_PUBLIC_ const struct dcesrv_endpoint_server *dcesrv_ep_server_byname(const char *name)
{
	int i;

	for (i=0;i<num_ep_servers;i++) {
		if (strcmp(ep_servers[i].ep_server->name, name) == 0) {
			return ep_servers[i].ep_server;
		}
	}

	return NULL;
}

/*
  return the DCERPC module version, and the size of some critical types
  This can be used by endpoint server modules to either detect compilation errors, or provide
  multiple implementations for different smbd compilation options in one module
*/
const struct dcesrv_critical_sizes *dcerpc_module_version(void)
{
	static const struct dcesrv_critical_sizes critical_sizes = {
		DCERPC_MODULE_VERSION,
		sizeof(struct dcesrv_context),
		sizeof(struct dcesrv_endpoint),
		sizeof(struct dcesrv_endpoint_server),
		sizeof(struct dcesrv_interface),
		sizeof(struct dcesrv_if_list),
		sizeof(struct dcesrv_connection),
		sizeof(struct dcesrv_call_state),
		sizeof(struct dcesrv_auth),
		sizeof(struct dcesrv_handle)
	};

	return &critical_sizes;
}

_PUBLIC_ void dcesrv_terminate_connection(struct dcesrv_connection *dce_conn, const char *reason)
{
	struct dcesrv_context *dce_ctx = dce_conn->dce_ctx;
	struct dcesrv_auth *a = NULL;

	dce_conn->wait_send = NULL;
	dce_conn->wait_recv = NULL;
	dce_conn->wait_private = NULL;

	dce_conn->allow_bind = false;
	dce_conn->allow_alter = false;

	dce_conn->default_auth_state->auth_invalid = true;

	for (a = dce_conn->auth_states; a != NULL; a = a->next) {
		a->auth_invalid = true;
	}

	if (dce_conn->pending_call_list == NULL) {
		char *full_reason = talloc_asprintf(dce_conn, "dcesrv: %s", reason);

		DLIST_REMOVE(dce_ctx->broken_connections, dce_conn);
		dce_conn->transport.terminate_connection(dce_conn,
					full_reason ? full_reason : reason);
		return;
	}

	if (dce_conn->terminate != NULL) {
		return;
	}

	DEBUG(3,("dcesrv: terminating connection due to '%s' deferred due to pending calls\n",
		 reason));
	dce_conn->terminate = talloc_strdup(dce_conn, reason);
	if (dce_conn->terminate == NULL) {
		dce_conn->terminate = "dcesrv: deferred terminating connection - no memory";
	}
	DLIST_ADD_END(dce_ctx->broken_connections, dce_conn);
}

_PUBLIC_ void dcesrv_cleanup_broken_connections(struct dcesrv_context *dce_ctx)
{
	struct dcesrv_connection *cur, *next;

	next = dce_ctx->broken_connections;
	while (next != NULL) {
		cur = next;
		next = cur->next;

		if (cur->state_flags & DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL) {
			struct dcesrv_connection_context *context_cur, *context_next;

			context_next = cur->contexts;
			while (context_next != NULL) {
				context_cur = context_next;
				context_next = context_cur->next;

				dcesrv_connection_context_destructor(context_cur);
			}
		}

		dcesrv_terminate_connection(cur, cur->terminate);
	}
}

/* We need this include to be able to compile on some plateforms
 * (ie. freebsd 7.2) as it seems that <sys/uio.h> is not included
 * correctly.
 * It has to be that deep because otherwise we have a conflict on
 * const struct dcesrv_interface declaration.
 * This is mostly due to socket_wrapper defining #define bind swrap_bind
 * which conflict with the bind used before.
 */
#include "system/network.h"

struct dcesrv_sock_reply_state {
	struct dcesrv_connection *dce_conn;
	struct dcesrv_call_state *call;
	struct iovec iov;
};

static void dcesrv_sock_reply_done(struct tevent_req *subreq);
static void dcesrv_call_terminate_step1(struct tevent_req *subreq);

_PUBLIC_ void dcesrv_sock_report_output_data(struct dcesrv_connection *dce_conn)
{
	struct dcesrv_call_state *call;

	call = dce_conn->call_list;
	if (!call || !call->replies) {
		return;
	}

	while (call->replies) {
		struct data_blob_list_item *rep = call->replies;
		struct dcesrv_sock_reply_state *substate;
		struct tevent_req *subreq;

		substate = talloc_zero(call, struct dcesrv_sock_reply_state);
		if (!substate) {
			dcesrv_terminate_connection(dce_conn, "no memory");
			return;
		}

		substate->dce_conn = dce_conn;
		substate->call = NULL;

		DLIST_REMOVE(call->replies, rep);

		if (call->replies == NULL && call->terminate_reason == NULL) {
			substate->call = call;
		}

		substate->iov.iov_base = (void *) rep->blob.data;
		substate->iov.iov_len = rep->blob.length;

		subreq = tstream_writev_queue_send(substate,
						   dce_conn->event_ctx,
						   dce_conn->stream,
						   dce_conn->send_queue,
						   &substate->iov, 1);
		if (!subreq) {
			dcesrv_terminate_connection(dce_conn, "no memory");
			return;
		}
		tevent_req_set_callback(subreq, dcesrv_sock_reply_done,
					substate);
	}

	if (call->terminate_reason != NULL) {
		struct tevent_req *subreq;

		subreq = tevent_queue_wait_send(call,
						dce_conn->event_ctx,
						dce_conn->send_queue);
		if (!subreq) {
			dcesrv_terminate_connection(dce_conn, __location__);
			return;
		}
		tevent_req_set_callback(subreq, dcesrv_call_terminate_step1,
					call);
	}

	DLIST_REMOVE(call->conn->call_list, call);
	call->list = DCESRV_LIST_NONE;
}

static void dcesrv_sock_reply_done(struct tevent_req *subreq)
{
	struct dcesrv_sock_reply_state *substate = tevent_req_callback_data(subreq,
						struct dcesrv_sock_reply_state);
	int ret;
	int sys_errno;
	NTSTATUS status;
	struct dcesrv_call_state *call = substate->call;

	ret = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(sys_errno);
		dcesrv_terminate_connection(substate->dce_conn, nt_errstr(status));
		return;
	}

	talloc_free(substate);
	if (call) {
		talloc_free(call);
	}
}

static void dcesrv_call_terminate_step2(struct tevent_req *subreq);

static void dcesrv_call_terminate_step1(struct tevent_req *subreq)
{
	struct dcesrv_call_state *call = tevent_req_callback_data(subreq,
						struct dcesrv_call_state);
	bool ok;
	struct timeval tv;

	/* make sure we stop send queue before removing subreq */
	tevent_queue_stop(call->conn->send_queue);

	ok = tevent_queue_wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		dcesrv_terminate_connection(call->conn, __location__);
		return;
	}

	/* disconnect after 200 usecs */
	tv = timeval_current_ofs_usec(200);
	subreq = tevent_wakeup_send(call, call->conn->event_ctx, tv);
	if (subreq == NULL) {
		dcesrv_terminate_connection(call->conn, __location__);
		return;
	}
	tevent_req_set_callback(subreq, dcesrv_call_terminate_step2,
				call);
}

static void dcesrv_call_terminate_step2(struct tevent_req *subreq)
{
	struct dcesrv_call_state *call = tevent_req_callback_data(subreq,
						struct dcesrv_call_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		dcesrv_terminate_connection(call->conn, __location__);
		return;
	}

	dcesrv_terminate_connection(call->conn, call->terminate_reason);
}

static void dcesrv_conn_wait_done(struct tevent_req *subreq);

static void dcesrv_read_fragment_done(struct tevent_req *subreq)
{
	struct dcesrv_connection *dce_conn = tevent_req_callback_data(subreq,
					     struct dcesrv_connection);
	struct dcesrv_context *dce_ctx = dce_conn->dce_ctx;
	struct ncacn_packet *pkt;
	DATA_BLOB buffer;
	NTSTATUS status;

	if (dce_conn->terminate) {
		/*
		 * if the current connection is broken
		 * we need to clean it up before any other connection
		 */
		dcesrv_terminate_connection(dce_conn, dce_conn->terminate);
		dcesrv_cleanup_broken_connections(dce_ctx);
		return;
	}

	dcesrv_cleanup_broken_connections(dce_ctx);

	status = dcerpc_read_ncacn_packet_recv(subreq, dce_conn,
					       &pkt, &buffer);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		dcesrv_terminate_connection(dce_conn, nt_errstr(status));
		return;
	}

	status = dcesrv_process_ncacn_packet(dce_conn, pkt, buffer);
	if (!NT_STATUS_IS_OK(status)) {
		dcesrv_terminate_connection(dce_conn, nt_errstr(status));
		return;
	}

	/*
	 * This is used to block the connection during
	 * pending authentication.
	 */
	if (dce_conn->wait_send != NULL) {
		subreq = dce_conn->wait_send(dce_conn,
					     dce_conn->event_ctx,
					     dce_conn->wait_private);
		if (!subreq) {
			status = NT_STATUS_NO_MEMORY;
			dcesrv_terminate_connection(dce_conn, nt_errstr(status));
			return;
		}
		tevent_req_set_callback(subreq, dcesrv_conn_wait_done, dce_conn);
		return;
	}

	subreq = dcerpc_read_ncacn_packet_send(dce_conn,
					       dce_conn->event_ctx,
					       dce_conn->stream);
	if (!subreq) {
		status = NT_STATUS_NO_MEMORY;
		dcesrv_terminate_connection(dce_conn, nt_errstr(status));
		return;
	}
	tevent_req_set_callback(subreq, dcesrv_read_fragment_done, dce_conn);
}

static void dcesrv_conn_wait_done(struct tevent_req *subreq)
{
	struct dcesrv_connection *dce_conn = tevent_req_callback_data(subreq,
					     struct dcesrv_connection);
	struct dcesrv_context *dce_ctx = dce_conn->dce_ctx;
	NTSTATUS status;

	if (dce_conn->terminate) {
		/*
		 * if the current connection is broken
		 * we need to clean it up before any other connection
		 */
		dcesrv_terminate_connection(dce_conn, dce_conn->terminate);
		dcesrv_cleanup_broken_connections(dce_ctx);
		return;
	}

	dcesrv_cleanup_broken_connections(dce_ctx);

	status = dce_conn->wait_recv(subreq);
	dce_conn->wait_send = NULL;
	dce_conn->wait_recv = NULL;
	dce_conn->wait_private = NULL;
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		dcesrv_terminate_connection(dce_conn, nt_errstr(status));
		return;
	}

	status = dcesrv_connection_loop_start(dce_conn);
	if (!NT_STATUS_IS_OK(status)) {
		dcesrv_terminate_connection(dce_conn, nt_errstr(status));
		return;
	}
}

/**
 * retrieve credentials from a dce_call
 */
_PUBLIC_ struct cli_credentials *dcesrv_call_credentials(struct dcesrv_call_state *dce_call)
{
	struct dcesrv_auth *auth = dce_call->auth_state;
	SMB_ASSERT(auth->auth_finished);
	return auth->session_info->credentials;
}

/**
 * returns true if this is an authenticated call
 */
_PUBLIC_ bool dcesrv_call_authenticated(struct dcesrv_call_state *dce_call)
{
	struct dcesrv_auth *auth = dce_call->auth_state;
	enum security_user_level level;
	SMB_ASSERT(auth->auth_finished);
	level = security_session_user_level(auth->session_info, NULL);
	return level >= SECURITY_USER;
}

/**
 * retrieve account_name for a dce_call
 */
_PUBLIC_ const char *dcesrv_call_account_name(struct dcesrv_call_state *dce_call)
{
	struct dcesrv_auth *auth = dce_call->auth_state;
	SMB_ASSERT(auth->auth_finished);
	return auth->session_info->info->account_name;
}

/**
 * retrieve session_info from a dce_call
 */
_PUBLIC_ struct auth_session_info *dcesrv_call_session_info(struct dcesrv_call_state *dce_call)
{
	struct dcesrv_auth *auth = dce_call->auth_state;
	SMB_ASSERT(auth->auth_finished);
	return auth->session_info;
}

/**
 * retrieve auth type/level from a dce_call
 */
_PUBLIC_ void dcesrv_call_auth_info(struct dcesrv_call_state *dce_call,
				    enum dcerpc_AuthType *auth_type,
				    enum dcerpc_AuthLevel *auth_level)
{
	struct dcesrv_auth *auth = dce_call->auth_state;

	SMB_ASSERT(auth->auth_finished);

	if (auth_type != NULL) {
		*auth_type = auth->auth_type;
	}
	if (auth_level != NULL) {
		*auth_level = auth->auth_level;
	}
}

_PUBLIC_ NTSTATUS dcesrv_connection_loop_start(struct dcesrv_connection *conn)
{
	struct tevent_req *subreq;

	subreq = dcerpc_read_ncacn_packet_send(conn,
					       conn->event_ctx,
					       conn->stream);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, dcesrv_read_fragment_done, conn);

	return NT_STATUS_OK;
}
