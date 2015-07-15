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
#include "../lib/util/dlinklist.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/dcerpc_server_proto.h"
#include "rpc_server/common/proto.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "system/filesys.h"
#include "libcli/security/security.h"
#include "param/param.h"
#include "../lib/tsocket/tsocket.h"
#include "../libcli/named_pipe_auth/npa_tstream.h"
#include "smbd/service_stream.h"
#include "../lib/tsocket/tsocket.h"
#include "lib/socket/socket.h"
#include "smbd/process_model.h"
#include "lib/messaging/irpc.h"
#include "librpc/rpc/rpc_common.h"
#include "lib/util/samba_modules.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"

extern const struct dcesrv_interface dcesrv_mgmt_interface;


/*
  find an association group given a assoc_group_id
 */
static struct dcesrv_assoc_group *dcesrv_assoc_group_find(struct dcesrv_context *dce_ctx,
							  uint32_t id)
{
	void *id_ptr;

	id_ptr = idr_find(dce_ctx->assoc_groups_idr, id);
	if (id_ptr == NULL) {
		return NULL;
	}
	return talloc_get_type_abort(id_ptr, struct dcesrv_assoc_group);
}

/*
  take a reference to an existing association group
 */
static struct dcesrv_assoc_group *dcesrv_assoc_group_reference(TALLOC_CTX *mem_ctx,
							       struct dcesrv_context *dce_ctx,
							       uint32_t id)
{
	struct dcesrv_assoc_group *assoc_group;

	assoc_group = dcesrv_assoc_group_find(dce_ctx, id);
	if (assoc_group == NULL) {
		DEBUG(2,(__location__ ": Failed to find assoc_group 0x%08x\n", id));
		return NULL;
	}
	return talloc_reference(mem_ctx, assoc_group);
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
static struct dcesrv_assoc_group *dcesrv_assoc_group_new(TALLOC_CTX *mem_ctx,
							 struct dcesrv_context *dce_ctx)
{
	struct dcesrv_assoc_group *assoc_group;
	int id;

	assoc_group = talloc_zero(mem_ctx, struct dcesrv_assoc_group);
	if (assoc_group == NULL) {
		return NULL;
	}
	
	id = idr_get_new_random(dce_ctx->assoc_groups_idr, assoc_group, UINT16_MAX);
	if (id == -1) {
		talloc_free(assoc_group);
		DEBUG(0,(__location__ ": Out of association groups!\n"));
		return NULL;
	}

	assoc_group->id = id;
	assoc_group->dce_ctx = dce_ctx;

	talloc_set_destructor(assoc_group, dcesrv_assoc_group_destructor);

	return assoc_group;
}


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
static struct dcesrv_endpoint *find_endpoint(struct dcesrv_context *dce_ctx,
					     const struct dcerpc_binding *ep_description)
{
	struct dcesrv_endpoint *ep;
	for (ep=dce_ctx->endpoint_list; ep; ep=ep->next) {
		if (endpoints_match(ep->ep_description, ep_description)) {
			return ep;
		}
	}
	return NULL;
}

/*
  find a registered context_id from a bind or alter_context
*/
static struct dcesrv_connection_context *dcesrv_find_context(struct dcesrv_connection *conn, 
								   uint32_t context_id)
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
  find the interface operations on an endpoint
*/
static const struct dcesrv_interface *find_interface(const struct dcesrv_endpoint *endpoint,
						     const struct dcesrv_interface *iface)
{
	struct dcesrv_if_list *ifl;
	for (ifl=endpoint->interface_list; ifl; ifl=ifl->next) {
		if (interface_match(&(ifl->iface), iface)) {
			return &(ifl->iface);
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
static const struct dcesrv_interface *find_interface_by_uuid(const struct dcesrv_endpoint *endpoint,
							     const struct GUID *uuid, uint32_t if_version)
{
	struct dcesrv_if_list *ifl;
	for (ifl=endpoint->interface_list; ifl; ifl=ifl->next) {
		if (interface_match_by_uuid(&(ifl->iface), uuid, if_version)) {
			return &(ifl->iface);
		}
	}
	return NULL;
}

/*
  find the earlier parts of a fragmented call awaiting reassembily
*/
static struct dcesrv_call_state *dcesrv_find_fragmented_call(struct dcesrv_connection *dce_conn, uint16_t call_id)
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
*/
_PUBLIC_ NTSTATUS dcesrv_interface_register(struct dcesrv_context *dce_ctx,
				   const char *ep_name,
				   const struct dcesrv_interface *iface,
				   const struct security_descriptor *sd)
{
	struct dcesrv_endpoint *ep;
	struct dcesrv_if_list *ifl;
	struct dcerpc_binding *binding;
	bool add_ep = false;
	NTSTATUS status;
	
	status = dcerpc_parse_binding(dce_ctx, ep_name, &binding);

	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Trouble parsing binding string '%s'\n", ep_name));
		return status;
	}

	/* check if this endpoint exists
	 */
	if ((ep=find_endpoint(dce_ctx, binding))==NULL) {
		ep = talloc_zero(dce_ctx, struct dcesrv_endpoint);
		if (!ep) {
			return NT_STATUS_NO_MEMORY;
		}
		ZERO_STRUCTP(ep);
		ep->ep_description = talloc_move(ep, &binding);
		add_ep = true;

		/* add mgmt interface */
		ifl = talloc_zero(ep, struct dcesrv_if_list);
		if (!ifl) {
			return NT_STATUS_NO_MEMORY;
		}

		memcpy(&(ifl->iface), &dcesrv_mgmt_interface, 
			   sizeof(struct dcesrv_interface));

		DLIST_ADD(ep->interface_list, ifl);
	}

	/* see if the interface is already registered on te endpoint */
	if (find_interface(ep, iface)!=NULL) {
		DEBUG(0,("dcesrv_interface_register: interface '%s' already registered on endpoint '%s'\n",
			iface->name, ep_name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	/* talloc a new interface list element */
	ifl = talloc_zero(ep, struct dcesrv_if_list);
	if (!ifl) {
		return NT_STATUS_NO_MEMORY;
	}

	/* copy the given interface struct to the one on the endpoints interface list */
	memcpy(&(ifl->iface),iface, sizeof(struct dcesrv_interface));

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

	DEBUG(4,("dcesrv_interface_register: interface '%s' registered on endpoint '%s'\n",
		iface->name, ep_name));

	return NT_STATUS_OK;
}

NTSTATUS dcesrv_inherited_session_key(struct dcesrv_connection *p,
				      DATA_BLOB *session_key)
{
	if (p->auth_state.session_info->session_key.length) {
		*session_key = p->auth_state.session_info->session_key;
		return NT_STATUS_OK;
	}
	return NT_STATUS_NO_USER_SESSION_KEY;
}

/*
  fetch the user session key - may be default (above) or the SMB session key

  The key is always truncated to 16 bytes 
*/
_PUBLIC_ NTSTATUS dcesrv_fetch_session_key(struct dcesrv_connection *p,
				  DATA_BLOB *session_key)
{
	NTSTATUS status = p->auth_state.session_key(p, session_key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	session_key->length = MIN(session_key->length, 16);

	return NT_STATUS_OK;
}

/*
  connect to a dcerpc endpoint
*/
_PUBLIC_ NTSTATUS dcesrv_endpoint_connect(struct dcesrv_context *dce_ctx,
				 TALLOC_CTX *mem_ctx,
				 const struct dcesrv_endpoint *ep,
				 struct auth_session_info *session_info,
				 struct tevent_context *event_ctx,
				 struct imessaging_context *msg_ctx,
				 struct server_id server_id,
				 uint32_t state_flags,
				 struct dcesrv_connection **_p)
{
	struct dcesrv_connection *p;

	if (!session_info) {
		return NT_STATUS_ACCESS_DENIED;
	}

	p = talloc_zero(mem_ctx, struct dcesrv_connection);
	NT_STATUS_HAVE_NO_MEMORY(p);

	if (!talloc_reference(p, session_info)) {
		talloc_free(p);
		return NT_STATUS_NO_MEMORY;
	}

	p->dce_ctx = dce_ctx;
	p->endpoint = ep;
	p->packet_log_dir = lpcfg_lock_directory(dce_ctx->lp_ctx);
	p->auth_state.session_info = session_info;
	p->auth_state.session_key = dcesrv_generic_session_key;
	p->event_ctx = event_ctx;
	p->msg_ctx = msg_ctx;
	p->server_id = server_id;
	p->state_flags = state_flags;
	p->allow_bind = true;
	p->max_recv_frag = 5840;
	p->max_xmit_frag = 5840;

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
	if (call->conn->terminate != NULL) {
		return;
	}

	call->conn->allow_bind = false;
	call->conn->allow_alter = false;
	call->conn->allow_auth3 = false;
	call->conn->allow_request = false;

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

	status = ncacn_push_auth(&rep->blob, call, &pkt, NULL);
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

NTSTATUS dcesrv_interface_bind_require_integrity(struct dcesrv_call_state *dce_call,
						 const struct dcesrv_interface *iface)
{
	if (dce_call->context == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	dce_call->context->min_auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	return NT_STATUS_OK;
}

NTSTATUS dcesrv_interface_bind_require_privacy(struct dcesrv_call_state *dce_call,
					       const struct dcesrv_interface *iface)
{
	if (dce_call->context == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	dce_call->context->min_auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS dcesrv_interface_bind_reject_connect(struct dcesrv_call_state *dce_call,
						       const struct dcesrv_interface *iface)
{
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	const struct dcesrv_endpoint *endpoint = dce_call->conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct dcesrv_connection_context *context = dce_call->context;

	if (context == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

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

_PUBLIC_ NTSTATUS dcesrv_interface_bind_allow_connect(struct dcesrv_call_state *dce_call,
						      const struct dcesrv_interface *iface)
{
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	const struct dcesrv_endpoint *endpoint = dce_call->conn->endpoint;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct dcesrv_connection_context *context = dce_call->context;

	if (context == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

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

/*
  handle a bind request
*/
static NTSTATUS dcesrv_bind(struct dcesrv_call_state *call)
{
	uint32_t if_version, transfer_syntax_version;
	struct GUID uuid, *transfer_syntax_uuid;
	struct ncacn_packet pkt;
	struct data_blob_list_item *rep;
	NTSTATUS status;
	uint32_t result=0, reason=0;
	uint32_t context_id;
	const struct dcesrv_interface *iface;
	uint32_t extra_flags = 0;
	uint16_t max_req = 0;
	uint16_t max_rep = 0;
	const char *ep_prefix = "";
	const char *endpoint = NULL;

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

	/*
	  if provided, check the assoc_group is valid
	 */
	if (call->pkt.u.bind.assoc_group_id != 0) {
		call->conn->assoc_group = dcesrv_assoc_group_reference(call->conn,
								       call->conn->dce_ctx,
								       call->pkt.u.bind.assoc_group_id);
	} else {
		call->conn->assoc_group = dcesrv_assoc_group_new(call->conn,
								 call->conn->dce_ctx);
	}
	if (call->conn->assoc_group == NULL) {
		return dcesrv_bind_nak(call, 0);
	}

	if (call->pkt.u.bind.num_contexts < 1 ||
	    call->pkt.u.bind.ctx_list[0].num_transfer_syntaxes < 1) {
		return dcesrv_bind_nak(call, 0);
	}

	context_id = call->pkt.u.bind.ctx_list[0].context_id;
	if_version = call->pkt.u.bind.ctx_list[0].abstract_syntax.if_version;
	uuid = call->pkt.u.bind.ctx_list[0].abstract_syntax.uuid;

	transfer_syntax_version = call->pkt.u.bind.ctx_list[0].transfer_syntaxes[0].if_version;
	transfer_syntax_uuid = &call->pkt.u.bind.ctx_list[0].transfer_syntaxes[0].uuid;
	if (!GUID_equal(&ndr_transfer_syntax_ndr.uuid, transfer_syntax_uuid) != 0 ||
	    ndr_transfer_syntax_ndr.if_version != transfer_syntax_version) {
		char *uuid_str = GUID_string(call, transfer_syntax_uuid);
		/* we only do NDR encoded dcerpc */
		DEBUG(0,("Non NDR transfer syntax requested - %s\n", uuid_str));
		talloc_free(uuid_str);
		return dcesrv_bind_nak(call, 0);
	}

	iface = find_interface_by_uuid(call->conn->endpoint, &uuid, if_version);
	if (iface == NULL) {
		char *uuid_str = GUID_string(call, &uuid);
		DEBUG(2,("Request for unknown dcerpc interface %s/%d\n", uuid_str, if_version));
		talloc_free(uuid_str);

		/* we don't know about that interface */
		result = DCERPC_BIND_PROVIDER_REJECT;
		reason = DCERPC_BIND_REASON_ASYNTAX;		
	}

	if (iface) {
		/* add this context to the list of available context_ids */
		struct dcesrv_connection_context *context = talloc_zero(call->conn,
								   struct dcesrv_connection_context);
		if (context == NULL) {
			return dcesrv_bind_nak(call, 0);
		}
		context->conn = call->conn;
		context->iface = iface;
		context->context_id = context_id;
		/* legacy for openchange dcesrv_mapiproxy.c */
		context->assoc_group = call->conn->assoc_group;
		context->private_data = NULL;
		DLIST_ADD(call->conn->contexts, context);
		call->context = context;
		talloc_set_destructor(context, dcesrv_connection_context_destructor);

		dcesrv_prepare_context_auth(call);

		status = iface->bind(call, iface, if_version);
		if (!NT_STATUS_IS_OK(status)) {
			char *uuid_str = GUID_string(call, &uuid);
			DEBUG(2,("Request for dcerpc interface %s/%d rejected: %s\n",
				 uuid_str, if_version, nt_errstr(status)));
			talloc_free(uuid_str);
			/* we don't want to trigger the iface->unbind() hook */
			context->iface = NULL;
			talloc_free(call->context);
			call->context = NULL;
			return dcesrv_bind_nak(call, 0);
		}
	}

	if ((call->pkt.pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) &&
	    (call->state_flags & DCESRV_CALL_STATE_FLAG_MULTIPLEXED)) {
		call->context->conn->state_flags |= DCESRV_CALL_STATE_FLAG_MULTIPLEXED;
		extra_flags |= DCERPC_PFC_FLAG_CONC_MPX;
	}

	if (call->state_flags & DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL) {
		call->context->conn->state_flags |= DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL;
	}

	/* handle any authentication that is being requested */
	if (!dcesrv_auth_bind(call)) {
		struct dcesrv_auth *auth = &call->conn->auth_state;

		TALLOC_FREE(call->context);

		if (auth->auth_level != DCERPC_AUTH_LEVEL_NONE) {
			/*
			 * We only give INVALID_AUTH_TYPE if the auth_level was
			 * valid.
			 */
			return dcesrv_bind_nak(call,
					DCERPC_BIND_NAK_REASON_INVALID_AUTH_TYPE);
		}
		return dcesrv_bind_nak(call,
					DCERPC_BIND_NAK_REASON_NOT_SPECIFIED);
	}

	/* setup a bind_ack */
	dcesrv_init_hdr(&pkt, lpcfg_rpc_big_endian(call->conn->dce_ctx->lp_ctx));
	pkt.auth_length = 0;
	pkt.call_id = call->pkt.call_id;
	pkt.ptype = DCERPC_PKT_BIND_ACK;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt.u.bind_ack.max_xmit_frag = call->conn->max_xmit_frag;
	pkt.u.bind_ack.max_recv_frag = call->conn->max_recv_frag;
	pkt.u.bind_ack.assoc_group_id = call->conn->assoc_group->id;

	if (iface) {
		endpoint = dcerpc_binding_get_string_option(
				call->conn->endpoint->ep_description,
				"endpoint");
	}

	if (endpoint == NULL) {
		endpoint = "";
	}

	if (strncasecmp(endpoint, "\\pipe\\", 6) == 0) {
		/*
		 * TODO: check if this is really needed
		 *
		 * Or if we should fix this in our idl files.
		 */
		ep_prefix = "\\PIPE\\";
		endpoint += 6;
	}

	pkt.u.bind_ack.secondary_address = talloc_asprintf(call, "%s%s",
							   ep_prefix,
							   endpoint);
	if (pkt.u.bind_ack.secondary_address == NULL) {
		TALLOC_FREE(call->context);
		return NT_STATUS_NO_MEMORY;
	}
	pkt.u.bind_ack.num_results = 1;
	pkt.u.bind_ack.ctx_list = talloc_zero(call, struct dcerpc_ack_ctx);
	if (!pkt.u.bind_ack.ctx_list) {
		talloc_free(call->context);
		call->context = NULL;
		return NT_STATUS_NO_MEMORY;
	}
	pkt.u.bind_ack.ctx_list[0].result = result;
	pkt.u.bind_ack.ctx_list[0].reason.value = reason;
	pkt.u.bind_ack.ctx_list[0].syntax = ndr_transfer_syntax_ndr;
	pkt.u.bind_ack.auth_info = data_blob(NULL, 0);

	status = dcesrv_auth_bind_ack(call, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(call->context);
		call->context = NULL;
		return dcesrv_bind_nak(call, 0);
	}

	rep = talloc_zero(call, struct data_blob_list_item);
	if (!rep) {
		talloc_free(call->context);
		call->context = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	status = ncacn_push_auth(&rep->blob, call, &pkt,
				 call->out_auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(call->context);
		call->context = NULL;
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


/*
  handle a auth3 request
*/
static NTSTATUS dcesrv_auth3(struct dcesrv_call_state *call)
{
	NTSTATUS status;

	if (!call->conn->allow_auth3) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	if (call->conn->auth_state.auth_finished) {
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
	if (!dcesrv_auth_auth3(call)) {
		call->conn->auth_state.auth_invalid = true;
	}

	talloc_free(call);

	/* we don't send a reply to a auth3 request, except by a
	   fault */
	return NT_STATUS_OK;
}


/*
  handle a bind request
*/
static NTSTATUS dcesrv_alter_new_context(struct dcesrv_call_state *call, uint32_t context_id)
{
	uint32_t if_version, transfer_syntax_version;
	struct dcesrv_connection_context *context;
	const struct dcesrv_interface *iface;
	struct GUID uuid, *transfer_syntax_uuid;
	NTSTATUS status;

	if_version = call->pkt.u.alter.ctx_list[0].abstract_syntax.if_version;
	uuid = call->pkt.u.alter.ctx_list[0].abstract_syntax.uuid;

	transfer_syntax_version = call->pkt.u.alter.ctx_list[0].transfer_syntaxes[0].if_version;
	transfer_syntax_uuid = &call->pkt.u.alter.ctx_list[0].transfer_syntaxes[0].uuid;
	if (!GUID_equal(transfer_syntax_uuid, &ndr_transfer_syntax_ndr.uuid) ||
	    ndr_transfer_syntax_ndr.if_version != transfer_syntax_version) {
		/* we only do NDR encoded dcerpc */
		return NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED;
	}

	iface = find_interface_by_uuid(call->conn->endpoint, &uuid, if_version);
	if (iface == NULL) {
		char *uuid_str = GUID_string(call, &uuid);
		DEBUG(2,("Request for unknown dcerpc interface %s/%d\n", uuid_str, if_version));
		talloc_free(uuid_str);
		return NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED;
	}

	/* add this context to the list of available context_ids */
	context = talloc_zero(call->conn, struct dcesrv_connection_context);
	if (context == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	context->conn = call->conn;
	context->iface = iface;
	context->context_id = context_id;
	/* legacy for openchange dcesrv_mapiproxy.c */
	context->assoc_group = call->conn->assoc_group;
	context->private_data = NULL;
	DLIST_ADD(call->conn->contexts, context);
	call->context = context;
	talloc_set_destructor(context, dcesrv_connection_context_destructor);

	dcesrv_prepare_context_auth(call);

	status = iface->bind(call, iface, if_version);
	if (!NT_STATUS_IS_OK(status)) {
		/* we don't want to trigger the iface->unbind() hook */
		context->iface = NULL;
		talloc_free(context);
		call->context = NULL;
		return status;
	}

	return NT_STATUS_OK;
}

/* setup and send an alter_resp */
static NTSTATUS dcesrv_alter_resp(struct dcesrv_call_state *call,
				uint32_t result,
				uint32_t reason)
{
	struct ncacn_packet pkt;
	uint32_t extra_flags = 0;
	struct data_blob_list_item *rep = NULL;
	NTSTATUS status;

	dcesrv_init_hdr(&pkt, lpcfg_rpc_big_endian(call->conn->dce_ctx->lp_ctx));
	pkt.auth_length = 0;
	pkt.call_id = call->pkt.call_id;
	pkt.ptype = DCERPC_PKT_ALTER_RESP;
	if (result == 0) {
		if ((call->pkt.pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) &&
				call->context->conn->state_flags &
					DCESRV_CALL_STATE_FLAG_MULTIPLEXED) {
			extra_flags |= DCERPC_PFC_FLAG_CONC_MPX;
		}
		if (call->state_flags & DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL) {
			call->context->conn->state_flags |=
				DCESRV_CALL_STATE_FLAG_PROCESS_PENDING_CALL;
		}
	}
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt.u.alter_resp.max_xmit_frag = call->conn->max_xmit_frag;
	pkt.u.alter_resp.max_recv_frag = call->conn->max_recv_frag;
	pkt.u.alter_resp.assoc_group_id = call->conn->assoc_group->id;
	pkt.u.alter_resp.num_results = 1;
	pkt.u.alter_resp.ctx_list = talloc_zero(call, struct dcerpc_ack_ctx);
	if (!pkt.u.alter_resp.ctx_list) {
		return NT_STATUS_NO_MEMORY;
	}
	pkt.u.alter_resp.ctx_list[0].result = result;
	pkt.u.alter_resp.ctx_list[0].reason.value = reason;
	pkt.u.alter_resp.ctx_list[0].syntax = ndr_transfer_syntax_ndr;
	pkt.u.alter_resp.auth_info = data_blob(NULL, 0);
	pkt.u.alter_resp.secondary_address = "";

	status = dcesrv_auth_alter_ack(call, &pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return dcesrv_fault_disconnect(call, DCERPC_FAULT_SEC_PKG_ERROR);
	}

	rep = talloc_zero(call, struct data_blob_list_item);
	if (!rep) {
		return NT_STATUS_NO_MEMORY;
	}

	status = ncacn_push_auth(&rep->blob, call, &pkt, call->out_auth_info);
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

/*
  handle a alter context request
*/
static NTSTATUS dcesrv_alter(struct dcesrv_call_state *call)
{
	NTSTATUS status;
	const struct dcerpc_ctx_list *ctx = NULL;
	bool auth_ok = false;

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
		if (call->in_auth_info.auth_type == DCERPC_AUTH_TYPE_NONE) {
			return dcesrv_fault_disconnect(call,
					DCERPC_FAULT_ACCESS_DENIED);
		}
	}

	if (call->pkt.u.alter.num_contexts < 1) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}
	ctx = &call->pkt.u.alter.ctx_list[0];
	if (ctx->num_transfer_syntaxes < 1) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	/* see if they are asking for a new interface */
	call->context = dcesrv_find_context(call->conn, ctx->context_id);
	if (!call->context) {
		status = dcesrv_alter_new_context(call, ctx->context_id);
		if (!NT_STATUS_IS_OK(status)) {
			return dcesrv_alter_resp(call,
				DCERPC_BIND_PROVIDER_REJECT,
				DCERPC_BIND_REASON_ASYNTAX);
		}
	} else {
		bool ok;

		ok = ndr_syntax_id_equal(&ctx->abstract_syntax,
					 &call->context->iface->syntax_id);
		if (!ok) {
			return dcesrv_fault_disconnect(call,
					DCERPC_NCA_S_PROTO_ERROR);
		}

		if (ctx->num_transfer_syntaxes != 1) {
			return dcesrv_fault_disconnect(call,
					DCERPC_NCA_S_PROTO_ERROR);
		}

		ok = ndr_syntax_id_equal(&ctx->transfer_syntaxes[0],
					 &ndr_transfer_syntax_ndr);
		if (!ok) {
			return dcesrv_fault_disconnect(call,
					DCERPC_NCA_S_PROTO_ERROR);
		}
	}

	/* handle any authentication that is being requested */
	if (!auth_ok) {
		if (call->in_auth_info.auth_type !=
		    call->conn->auth_state.auth_type)
		{
			return dcesrv_fault_disconnect(call,
					DCERPC_FAULT_SEC_PKG_ERROR);
		}
		return dcesrv_fault_disconnect(call, DCERPC_FAULT_ACCESS_DENIED);
	}

	return dcesrv_alter_resp(call,
				DCERPC_BIND_ACK_RESULT_ACCEPTANCE,
				DCERPC_BIND_ACK_REASON_NOT_SPECIFIED);
}

/*
  possibly save the call for inspection with ndrdump
 */
static void dcesrv_save_call(struct dcesrv_call_state *call, const char *why)
{
#ifdef DEVELOPER
	char *fname;
	const char *dump_dir;
	dump_dir = lpcfg_parm_string(call->conn->dce_ctx->lp_ctx, NULL, "dcesrv", "stubs directory");
	if (!dump_dir) {
		return;
	}
	fname = talloc_asprintf(call, "%s/RPC-%s-%u-%s.dat",
				dump_dir,
				call->context->iface->name,
				call->pkt.u.request.opnum,
				why);
	if (file_save(fname, call->pkt.u.request.stub_and_verifier.data, call->pkt.u.request.stub_and_verifier.length)) {
		DEBUG(0,("RPC SAVED %s\n", fname));
	}
	talloc_free(fname);
#endif
}

static NTSTATUS dcesrv_check_verification_trailer(struct dcesrv_call_state *call)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const uint32_t bitmask1 = call->conn->auth_state.client_hdr_signing ?
		DCERPC_SEC_VT_CLIENT_SUPPORTS_HEADER_SIGNING : 0;
	const struct dcerpc_sec_vt_pcontext pcontext = {
		.abstract_syntax = call->context->iface->syntax_id,
		.transfer_syntax = ndr_transfer_syntax_ndr,
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
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(endpoint->ep_description);
	struct ndr_pull *pull;
	NTSTATUS status;
	struct dcesrv_connection_context *context;

	if (!call->conn->allow_request) {
		return dcesrv_fault_disconnect(call, DCERPC_NCA_S_PROTO_ERROR);
	}

	/* if authenticated, and the mech we use can't do async replies, don't use them... */
	if (call->conn->auth_state.gensec_security && 
	    !gensec_have_feature(call->conn->auth_state.gensec_security, GENSEC_FEATURE_ASYNC_REPLIES)) {
		call->state_flags &= ~DCESRV_CALL_STATE_FLAG_MAY_ASYNC;
	}

	context = dcesrv_find_context(call->conn, call->pkt.u.request.context_id);
	if (context == NULL) {
		return dcesrv_fault(call, DCERPC_FAULT_UNK_IF);
	}

	switch (call->conn->auth_state.auth_level) {
	case DCERPC_AUTH_LEVEL_NONE:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PRIVACY:
		break;
	default:
		if (!context->allow_connect) {
			char *addr;

			addr = tsocket_address_string(call->conn->remote_address,
						      call);

			DEBUG(2, ("%s: restrict auth_level_connect access "
				  "to [%s] with auth[type=0x%x,level=0x%x] "
				  "on [%s] from [%s]\n",
				  __func__, context->iface->name,
				  call->conn->auth_state.auth_type,
				  call->conn->auth_state.auth_level,
				  derpc_transport_string_by_transport(transport),
				  addr));
			return dcesrv_fault(call, DCERPC_FAULT_ACCESS_DENIED);
		}
		break;
	}

	if (call->conn->auth_state.auth_level < context->min_auth_level) {
		char *addr;

		addr = tsocket_address_string(call->conn->remote_address, call);

		DEBUG(2, ("%s: restrict access by min_auth_level[0x%x] "
			  "to [%s] with auth[type=0x%x,level=0x%x] "
			  "on [%s] from [%s]\n",
			  __func__,
			  context->min_auth_level,
			  context->iface->name,
			  call->conn->auth_state.auth_type,
			  call->conn->auth_state.auth_level,
			  derpc_transport_string_by_transport(transport),
			  addr));
		return dcesrv_fault(call, DCERPC_FAULT_ACCESS_DENIED);
	}

	pull = ndr_pull_init_blob(&call->pkt.u.request.stub_and_verifier, call);
	NT_STATUS_HAVE_NO_MEMORY(pull);

	pull->flags |= LIBNDR_FLAG_REF_ALLOC;

	call->context	= context;
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
	status = context->iface->ndr_pull(call, call, pull, &call->r);
	if (!NT_STATUS_IS_OK(status)) {
		if (call->fault_code == DCERPC_FAULT_OP_RNG_ERROR) {
			/* we got an unknown call */
			DEBUG(3,(__location__ ": Unknown RPC call %u on %s\n",
				 call->pkt.u.request.opnum, context->iface->name));
			dcesrv_save_call(call, "unknown");
		} else {
			dcesrv_save_call(call, "pullfail");
		}
		return dcesrv_fault(call, call->fault_code);
	}

	if (pull->offset != pull->data_size) {
		dcesrv_save_call(call, "extrabytes");
		DEBUG(3,("Warning: %d extra bytes in incoming RPC request\n", 
			 pull->data_size - pull->offset));
	}

	/* call the dispatch function */
	status = context->iface->dispatch(call, call, call->r);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("dcerpc fault in call %s:%02x - %s\n",
			 context->iface->name, 
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

	call = talloc_zero(dce_conn, struct dcesrv_call_state);
	if (!call) {
		data_blob_free(&blob);
		talloc_free(pkt);
		return NT_STATUS_NO_MEMORY;
	}
	call->conn		= dce_conn;
	call->event_ctx		= dce_conn->event_ctx;
	call->msg_ctx		= dce_conn->msg_ctx;
	call->state_flags	= call->conn->state_flags;
	call->time		= timeval_current();
	call->list              = DCESRV_LIST_NONE;

	talloc_steal(call, pkt);
	talloc_steal(call, blob.data);
	call->pkt = *pkt;

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
		if (!call->conn->allow_request) {
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
			/* only one request is possible in the fragmented list */
			if (dce_conn->incoming_fragmented_call_list != NULL) {
				TALLOC_FREE(call);
				call = dce_conn->incoming_fragmented_call_list;
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

		if (!dcesrv_auth_request(call, &blob)) {
			/*
			 * We don't use dcesrv_fault_disconnect()
			 * here, because we don't want to set
			 * DCERPC_PFC_FLAG_DID_NOT_EXECUTE
			 */
			dcesrv_call_disconnect_after(call,
						"dcesrv_auth_request - failed");
			return dcesrv_fault(call, DCERPC_FAULT_ACCESS_DENIED);
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
		available = DCERPC_NCACN_PAYLOAD_MAX_SIZE;
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
		if (call->pkt.u.request.alloc_hint > DCERPC_NCACN_PAYLOAD_MAX_SIZE) {
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
				      const char **endpoint_servers, struct dcesrv_context **_dce_ctx)
{
	NTSTATUS status;
	struct dcesrv_context *dce_ctx;
	int i;

	if (!endpoint_servers) {
		DEBUG(0,("dcesrv_init_context: no endpoint servers configured\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

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

	for (i=0;endpoint_servers[i];i++) {
		const struct dcesrv_endpoint_server *ep_server;

		ep_server = dcesrv_ep_server_byname(endpoint_servers[i]);
		if (!ep_server) {
			DEBUG(0,("dcesrv_init_context: failed to find endpoint server = '%s'\n", endpoint_servers[i]));
			return NT_STATUS_INTERNAL_ERROR;
		}

		status = ep_server->init_server(dce_ctx, ep_server);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("dcesrv_init_context: failed to init endpoint server = '%s': %s\n", endpoint_servers[i],
				nt_errstr(status)));
			return status;
		}
	}

	*_dce_ctx = dce_ctx;
	return NT_STATUS_OK;
}

/* the list of currently registered DCERPC endpoint servers.
 */
static struct ep_server {
	struct dcesrv_endpoint_server *ep_server;
} *ep_servers = NULL;
static int num_ep_servers;

/*
  register a DCERPC endpoint server. 

  The 'name' can be later used by other backends to find the operations
  structure for this backend.  

  The 'type' is used to specify whether this is for a disk, printer or IPC$ share
*/
_PUBLIC_ NTSTATUS dcerpc_register_ep_server(const void *_ep_server)
{
	const struct dcesrv_endpoint_server *ep_server = _ep_server;
	
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
const struct dcesrv_endpoint_server *dcesrv_ep_server_byname(const char *name)
{
	int i;

	for (i=0;i<num_ep_servers;i++) {
		if (strcmp(ep_servers[i].ep_server->name, name) == 0) {
			return ep_servers[i].ep_server;
		}
	}

	return NULL;
}

void dcerpc_server_init(struct loadparm_context *lp_ctx)
{
	static bool initialized;
#define _MODULE_PROTO(init) extern NTSTATUS init(void);
	STATIC_dcerpc_server_MODULES_PROTO;
	init_module_fn static_init[] = { STATIC_dcerpc_server_MODULES };
	init_module_fn *shared_init;

	if (initialized) {
		return;
	}
	initialized = true;

	shared_init = load_samba_modules(NULL, "dcerpc_server");

	run_init_functions(static_init);
	run_init_functions(shared_init);

	talloc_free(shared_init);
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

static void dcesrv_terminate_connection(struct dcesrv_connection *dce_conn, const char *reason)
{
	struct dcesrv_context *dce_ctx = dce_conn->dce_ctx;
	struct stream_connection *srv_conn;
	srv_conn = talloc_get_type(dce_conn->transport.private_data,
				   struct stream_connection);

	dce_conn->allow_bind = false;
	dce_conn->allow_auth3 = false;
	dce_conn->allow_alter = false;
	dce_conn->allow_request = false;

	if (dce_conn->pending_call_list == NULL) {
		char *full_reason = talloc_asprintf(dce_conn, "dcesrv: %s", reason);

		DLIST_REMOVE(dce_ctx->broken_connections, dce_conn);
		stream_terminate_connection(srv_conn, full_reason ? full_reason : reason);
		return;
	}

	if (dce_conn->terminate != NULL) {
		return;
	}

	DEBUG(3,("dcesrv: terminating connection due to '%s' defered due to pending calls\n",
		 reason));
	dce_conn->terminate = talloc_strdup(dce_conn, reason);
	if (dce_conn->terminate == NULL) {
		dce_conn->terminate = "dcesrv: defered terminating connection - no memory";
	}
	DLIST_ADD_END(dce_ctx->broken_connections, dce_conn);
}

static void dcesrv_cleanup_broken_connections(struct dcesrv_context *dce_ctx)
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

static void dcesrv_sock_report_output_data(struct dcesrv_connection *dce_conn)
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

struct dcesrv_socket_context {
	const struct dcesrv_endpoint *endpoint;
	struct dcesrv_context *dcesrv_ctx;
};


static void dcesrv_read_fragment_done(struct tevent_req *subreq);

static void dcesrv_sock_accept(struct stream_connection *srv_conn)
{
	NTSTATUS status;
	struct dcesrv_socket_context *dcesrv_sock = 
		talloc_get_type(srv_conn->private_data, struct dcesrv_socket_context);
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dcesrv_sock->endpoint->ep_description);
	struct dcesrv_connection *dcesrv_conn = NULL;
	int ret;
	struct tevent_req *subreq;
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

	status = dcesrv_endpoint_connect(dcesrv_sock->dcesrv_ctx,
					 srv_conn,
					 dcesrv_sock->endpoint,
					 srv_conn->session_info,
					 srv_conn->event.ctx,
					 srv_conn->msg_ctx,
					 srv_conn->server_id,
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
		dcesrv_conn->auth_state.session_key = dcesrv_inherited_session_key;
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

		ret = getpeereid(socket_get_fd(srv_conn->socket), &uid, &gid);
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
							     "/root/ncalrpc_as_system",
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

	irpc_add_name(srv_conn->msg_ctx, "rpc_server");

	subreq = dcerpc_read_ncacn_packet_send(dcesrv_conn,
					       dcesrv_conn->event_ctx,
					       dcesrv_conn->stream);
	if (!subreq) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0,("dcesrv_sock_accept: dcerpc_read_fragment_buffer_send(%s)\n",
			nt_errstr(status)));
		stream_terminate_connection(srv_conn, nt_errstr(status));
		return;
	}
	tevent_req_set_callback(subreq, dcesrv_read_fragment_done, dcesrv_conn);

	return;
}

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
			    struct tevent_context *event_ctx, const struct model_ops *model_ops)
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
				     dcesrv_sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(path=%s) failed - %s\n",
			 endpoint, nt_errstr(status)));
	}

	return status;
}

static NTSTATUS dcesrv_add_ep_ncalrpc(struct dcesrv_context *dce_ctx, 
				      struct loadparm_context *lp_ctx,
				      struct dcesrv_endpoint *e,
				      struct tevent_context *event_ctx, const struct model_ops *model_ops)
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
				     dcesrv_sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(identifier=%s,path=%s) failed - %s\n",
			 endpoint, full_path, nt_errstr(status)));
	}
	return status;
}

static NTSTATUS dcesrv_add_ep_np(struct dcesrv_context *dce_ctx,
				 struct loadparm_context *lp_ctx,
				 struct dcesrv_endpoint *e,
				 struct tevent_context *event_ctx, const struct model_ops *model_ops)
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
					  dcesrv_sock);
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
static NTSTATUS add_socket_rpc_tcp_iface(struct dcesrv_context *dce_ctx, struct dcesrv_endpoint *e,
					 struct tevent_context *event_ctx, const struct model_ops *model_ops,
					 const char *address)
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
				     dcesrv_sock);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(address=%s,port=%u) failed - %s\n", 
			 address, port, nt_errstr(status)));
		return status;
	}

	snprintf(port_str, sizeof(port_str), "%u", port);

	status = dcerpc_binding_set_string_option(e->ep_description,
						  "endpoint", port_str);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("dcerpc_binding_set_string_option(endpoint, %s) failed - %s\n",
			 port_str, nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

#include "lib/socket/netif.h" /* Included here to work around the fact that socket_wrapper redefines bind() */

static NTSTATUS dcesrv_add_ep_tcp(struct dcesrv_context *dce_ctx, 
				  struct loadparm_context *lp_ctx,
				  struct dcesrv_endpoint *e,
				  struct tevent_context *event_ctx, const struct model_ops *model_ops)
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
			status = add_socket_rpc_tcp_iface(dce_ctx, e, event_ctx, model_ops, address);
			NT_STATUS_NOT_OK_RETURN(status);
		}
	} else {
		char **wcard;
		int i;
		int num_binds = 0;
		wcard = iface_list_wildcard(dce_ctx);
		NT_STATUS_HAVE_NO_MEMORY(wcard);
		for (i=0; wcard[i]; i++) {
			status = add_socket_rpc_tcp_iface(dce_ctx, e, event_ctx, model_ops, wcard[i]);
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
		       const struct model_ops *model_ops)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(e->ep_description);

	switch (transport) {
	case NCACN_UNIX_STREAM:
		return dcesrv_add_ep_unix(dce_ctx, lp_ctx, e, event_ctx, model_ops);

	case NCALRPC:
		return dcesrv_add_ep_ncalrpc(dce_ctx, lp_ctx, e, event_ctx, model_ops);

	case NCACN_IP_TCP:
		return dcesrv_add_ep_tcp(dce_ctx, lp_ctx, e, event_ctx, model_ops);

	case NCACN_NP:
		return dcesrv_add_ep_np(dce_ctx, lp_ctx, e, event_ctx, model_ops);

	default:
		return NT_STATUS_NOT_SUPPORTED;
	}
}


/**
 * retrieve credentials from a dce_call
 */
_PUBLIC_ struct cli_credentials *dcesrv_call_credentials(struct dcesrv_call_state *dce_call)
{
	return dce_call->conn->auth_state.session_info->credentials;
}

/**
 * returns true if this is an authenticated call
 */
_PUBLIC_ bool dcesrv_call_authenticated(struct dcesrv_call_state *dce_call)
{
	enum security_user_level level;
	level = security_session_user_level(dce_call->conn->auth_state.session_info, NULL);
	return level >= SECURITY_USER;
}

/**
 * retrieve account_name for a dce_call
 */
_PUBLIC_ const char *dcesrv_call_account_name(struct dcesrv_call_state *dce_call)
{
	return dce_call->context->conn->auth_state.session_info->info->account_name;
}
