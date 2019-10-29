/*
   Unix SMB/CIFS implementation.

   server side dcerpc handle code

   Copyright (C) Andrew Tridgell 2003

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
#include "lib/util/dlinklist.h"
#include "rpc_server/dcerpc_server.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/auth.h"

/*
  destroy a rpc handle
*/
static int dcesrv_handle_destructor(struct dcesrv_handle *h)
{
	DLIST_REMOVE(h->assoc_group->handles, h);
	return 0;
}


/*
  allocate a new rpc handle
*/
_PUBLIC_
struct dcesrv_handle *dcesrv_handle_create(struct dcesrv_call_state *call,
					   uint8_t handle_type)
{
	struct dcesrv_connection_context *context = call->context;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(call);
	struct dcesrv_handle *h;
	struct dom_sid *sid;

	/*
	 * For simplicty, ensure we abort here for an interface that has no handles (programmer error)
	 */
	SMB_ASSERT((context->iface->flags & DCESRV_INTERFACE_FLAGS_HANDLES_NOT_USED) == 0);

	sid = &session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

	h = talloc_zero(context->conn->assoc_group, struct dcesrv_handle);
	if (!h) {
		return NULL;
	}
	h->data = NULL;
	h->sid = dom_sid_dup(h, sid);
	if (h->sid == NULL) {
		talloc_free(h);
		return NULL;
	}
	h->min_auth_level = call->auth_state->auth_level;
	h->assoc_group = context->conn->assoc_group;
	h->iface = context->iface;
	h->wire_handle.handle_type = handle_type;
	h->wire_handle.uuid = GUID_random();

	DLIST_ADD(context->conn->assoc_group->handles, h);

	talloc_set_destructor(h, dcesrv_handle_destructor);

	return h;
}

/**
  find an internal handle given a wire handle. If the wire handle is NULL then
  allocate a new handle
*/

_PUBLIC_
struct dcesrv_handle *dcesrv_handle_lookup(struct dcesrv_call_state *call,
					   const struct policy_handle *p,
					   uint8_t handle_type)
{
	struct dcesrv_connection_context *context = call->context;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(call);
	struct dcesrv_handle *h;
	struct dom_sid *sid;

	/*
	 * For simplicty, ensure we abort here for an interface that has no handles (programmer error)
	 */
	SMB_ASSERT((context->iface->flags & DCESRV_INTERFACE_FLAGS_HANDLES_NOT_USED) == 0);

	sid = &session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

	if (ndr_policy_handle_empty(p)) {
		/* TODO: we should probably return a NULL handle here */
		return dcesrv_handle_create(call, handle_type);
	}

	for (h=context->conn->assoc_group->handles; h; h=h->next) {
		if (h->wire_handle.handle_type == p->handle_type &&
		    GUID_equal(&p->uuid, &h->wire_handle.uuid)) {
			if (handle_type != DCESRV_HANDLE_ANY &&
			    p->handle_type != handle_type) {
				DEBUG(0,("client gave us the wrong handle type (%d should be %d)\n",
					 p->handle_type, handle_type));
				return NULL;
			}
			if (!dom_sid_equal(h->sid, sid)) {
				struct dom_sid_buf buf1, buf2;
				DBG_ERR("Attempt to use invalid sid %s - %s\n",
					dom_sid_str_buf(h->sid, &buf1),
					dom_sid_str_buf(sid, &buf2));
				return NULL;
			}
			if (call->auth_state->auth_level < h->min_auth_level) {
				DEBUG(0,(__location__ ": Attempt to use invalid auth_level %u < %u\n",
					 call->auth_state->auth_level,
					 h->min_auth_level));
				return NULL;
			}
			if (h->iface != context->iface) {
				DEBUG(0,(__location__ ": Attempt to use invalid iface\n"));
				return NULL;
			}
			return h;
		}
	}

	return NULL;
}

struct dcesrv_iface_state {
	struct dcesrv_iface_state *prev, *next;
	struct dcesrv_assoc_group *assoc;
	const struct dcesrv_interface *iface;
	struct dom_sid owner;
	const struct dcesrv_connection *conn;
	const struct dcesrv_auth *auth;
	const struct dcesrv_connection_context *pres;
	uint64_t magic;
	void *ptr;
	const char *location;
};

static int dcesrv_iface_state_destructor(struct dcesrv_iface_state *istate)
{
	DLIST_REMOVE(istate->assoc->iface_states, istate);
	return 0;
}

static void *dcesrv_iface_state_find(struct dcesrv_assoc_group *assoc,
			const struct dcesrv_interface *iface,
			const struct dom_sid *owner,
			const struct dcesrv_connection *conn,
			const struct dcesrv_auth *auth,
			const struct dcesrv_connection_context *pres,
			uint64_t magic,
			const void *ptr)
{
	struct dcesrv_iface_state *cur = NULL;

	for (cur = assoc->iface_states; cur != NULL; cur = cur->next) {
		bool match;

		SMB_ASSERT(cur->assoc == assoc);

		if (cur->ptr == ptr) {
			return cur->ptr;
		}

		if (cur->iface != iface) {
			continue;
		}

		match = dom_sid_equal(&cur->owner, owner);
		if (!match) {
			continue;
		}

		if (cur->conn != conn) {
			continue;
		}

		if (cur->auth != auth) {
			continue;
		}

		if (cur->pres != pres) {
			continue;
		}

		if (cur->magic != magic) {
			continue;
		}

		return cur->ptr;
	}

	return NULL;
}

static NTSTATUS dcesrv_iface_state_store(struct dcesrv_assoc_group *assoc,
				const struct dcesrv_interface *iface,
				const struct dom_sid *owner,
				const struct dcesrv_connection *conn,
				const struct dcesrv_auth *auth,
				const struct dcesrv_connection_context *pres,
				uint64_t magic,
				TALLOC_CTX *mem_ctx,
				void *ptr,
				const char *location)
{
	struct dcesrv_iface_state *istate = NULL;
	void *optr = NULL;

	optr = dcesrv_iface_state_find(assoc,
				       iface,
				       owner,
				       conn,
				       auth,
				       pres,
				       magic,
				       ptr);
	if (optr != NULL) {
		return NT_STATUS_OBJECTID_EXISTS;
	}

	istate = talloc_zero(ptr, struct dcesrv_iface_state);
	if (istate == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*istate = (struct dcesrv_iface_state) {
		.assoc = assoc,
		.iface = iface,
		.owner = *owner,
		.conn  = conn,
		.auth  = auth,
		.pres  = pres,
		.magic = magic,
		.location = location,
	};

	istate->ptr = talloc_steal(mem_ctx, ptr);

	talloc_set_destructor(istate, dcesrv_iface_state_destructor);

	DLIST_ADD_END(assoc->iface_states, istate);

	return NT_STATUS_OK;
}

NTSTATUS _dcesrv_iface_state_store_assoc(struct dcesrv_call_state *call,
				uint64_t magic,
				void *ptr,
				const char *location)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(call);
	const struct dom_sid *owner =
		&session_info->security_token->sids[0];
	NTSTATUS status;

	status = dcesrv_iface_state_store(call->conn->assoc_group,
					  call->context->iface,
					  owner,
					  NULL, /* conn */
					  NULL, /* auth */
					  NULL, /* pres */
					  magic,
					  call->conn->assoc_group, /* mem_ctx */
					  ptr,
					  location);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

void *_dcesrv_iface_state_find_assoc(struct dcesrv_call_state *call, uint64_t magic)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(call);
	const struct dom_sid *owner =
		&session_info->security_token->sids[0];
	void *ptr = NULL;

	ptr = dcesrv_iface_state_find(call->conn->assoc_group,
				      call->context->iface,
				      owner,
				      NULL, /* conn */
				      NULL, /* auth */
				      NULL, /* pres */
				      magic,
				      NULL); /* ptr */
	if (ptr == NULL) {
		return NULL;
	}

	return ptr;
}

NTSTATUS _dcesrv_iface_state_store_conn(struct dcesrv_call_state *call,
					uint64_t magic,
					void *ptr,
					const char *location)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(call);
	const struct dom_sid *owner =
		&session_info->security_token->sids[0];
	NTSTATUS status;

	status = dcesrv_iface_state_store(call->conn->assoc_group,
					  call->context->iface,
					  owner,
					  call->conn,
					  call->auth_state,
					  call->context,
					  magic,
					  call->conn, /* mem_ctx */
					  ptr,
					  location);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

void *_dcesrv_iface_state_find_conn(struct dcesrv_call_state *call, uint64_t magic)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(call);
	const struct dom_sid *owner =
		&session_info->security_token->sids[0];
	void *ptr = NULL;

	ptr = dcesrv_iface_state_find(call->conn->assoc_group,
				      call->context->iface,
				      owner,
				      call->conn,
				      call->auth_state,
				      call->context,
				      magic,
				      NULL); /* ptr */
	if (ptr == NULL) {
		return NULL;
	}

	return ptr;
}
