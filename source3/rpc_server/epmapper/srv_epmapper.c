/*
   Unix SMB/CIFS implementation.

   Endpoint server for the epmapper pipe

   Copyright (C) 2010-2011 Andreas Schneider <asn@samba.org>

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
#include "ntdomain.h"
#include "../libcli/security/security.h"
#include "../lib/tsocket/tsocket.h"
#include "srv_epmapper.h"
#include "auth.h"

#include "librpc/rpc/dcesrv_core.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_epmapper_scompat.h"
#include "rpc_server/rpc_server.h"

/* handle types for this module */
enum handle_types {HTYPE_LOOKUP};

typedef uint32_t error_status_t;

/* An endpoint combined with an interface description */
struct dcesrv_ep_iface {
	const char *name;
	struct ndr_syntax_id syntax_id;
	struct epm_tower ep;
};

/* A rpc service interface like samr, lsarpc or netlogon */
struct dcesrv_iface {
	const char *name;
	struct ndr_syntax_id syntax_id;
};

struct dcesrv_iface_list {
	struct dcesrv_iface_list *next, *prev;
	struct dcesrv_iface *iface;
};

/*
 * An endpoint can serve multiple rpc services interfaces.
 * For example \\pipe\netlogon can be used by lsarpc and netlogon.
 */
struct dcesrv_epm_endpoint {
	struct dcesrv_epm_endpoint *next, *prev;

	/* The type and the location of the endpoint */
	struct dcerpc_binding *ep_description;

	/* A list of rpc services able to connect to the endpoint */
	struct dcesrv_iface_list *iface_list;
};

struct dcesrv_ep_entry_list {
	struct dcesrv_ep_entry_list *next, *prev;

	uint32_t num_ents;
	struct epm_entry_t *entries;
};

struct rpc_eps {
	struct dcesrv_ep_iface *e;
	uint32_t count;
};

static struct dcesrv_epm_endpoint *endpoint_table = NULL;

/*
 * Check if the UUID and if_version match to an interface.
 */
static bool interface_match(const struct dcesrv_iface *if1,
			    const struct dcesrv_iface *if2)
{
	return GUID_equal(&if1->syntax_id.uuid, &if2->syntax_id.uuid);
}

/*
 * Find the interface operations on an endpoint.
 */
static const struct dcesrv_iface *find_interface(const struct dcesrv_epm_endpoint *endpoint,
						 const struct dcesrv_iface *iface)
{
	struct dcesrv_iface_list *iflist;

	for (iflist = endpoint->iface_list; iflist; iflist = iflist->next) {
		if (interface_match(iflist->iface, iface)) {
			return iflist->iface;
		}
	}

	return NULL;
}

#if 0
/*
 * See if a uuid and if_version match to an interface
 */
static bool interface_match_by_uuid(const struct dcesrv_iface *iface,
				    const struct GUID *uuid)
{
	return GUID_equal(&iface->syntax_id.uuid, uuid);
}
#endif

static struct dcesrv_iface_list *find_interface_list(const struct dcesrv_epm_endpoint *endpoint,
						     const struct dcesrv_iface *iface)
{
	struct dcesrv_iface_list *iflist;

	for (iflist = endpoint->iface_list; iflist; iflist = iflist->next) {
		if (interface_match(iflist->iface, iface)) {
			return iflist;
		}
	}

	return NULL;
}

/*
 * Check if two endpoints match.
 */
static bool endpoints_match(const struct dcerpc_binding *b1,
			    const struct dcerpc_binding *b2)
{
	enum dcerpc_transport_t t1;
	const char *ep1;
	const char *h1;
	enum dcerpc_transport_t t2;
	const char *ep2;
	const char *h2;

	t1 = dcerpc_binding_get_transport(b1);
	ep1 = dcerpc_binding_get_string_option(b1, "endpoint");
	h1 = dcerpc_binding_get_string_option(b1, "host");

	t2 = dcerpc_binding_get_transport(b2);
	ep2 = dcerpc_binding_get_string_option(b2, "endpoint");
	h2 = dcerpc_binding_get_string_option(b2, "host");

	if (t1 != t2) {
		return false;
	}

	if (!ep1 && ep2) {
		return false;
	}

	if (ep1 && !ep2) {
		return false;
	}

	if (ep1 && ep2) {
		if (!strequal(ep1, ep2)) {
			return false;
		}
	}

	if (!h1 && h2) {
		return false;
	}

	if (h1 && !h2) {
		return false;
	}

	if (h1 && h2) {
		if (!strequal(h1, h2)) {
			return false;
		}
	}

	return true;
}

static struct dcesrv_epm_endpoint *find_endpoint(struct dcesrv_epm_endpoint *endpoint_list,
					     struct dcerpc_binding *ep_description) {
	struct dcesrv_epm_endpoint *ep = NULL;

	for (ep = endpoint_list; ep != NULL; ep = ep->next) {
		if (endpoints_match(ep->ep_description, ep_description)) {
			return ep;
		}
	}

	return NULL;
}

/*
 * Build a list of all interfaces handled by all endpoint servers.
 */
static uint32_t build_ep_list(TALLOC_CTX *mem_ctx,
			      struct dcesrv_epm_endpoint *endpoint_list,
			      const struct GUID *uuid,
			      const char *srv_addr,
			      struct dcesrv_ep_iface **peps)
{
	struct dcesrv_ep_iface *eps = NULL;
	struct dcesrv_epm_endpoint *d = NULL;
	uint32_t total = 0;
	NTSTATUS status;

	*peps = NULL;

	for (d = endpoint_list; d != NULL; d = d->next) {
		struct dcesrv_iface_list *iface;
		struct dcerpc_binding *description;

		for (iface = d->iface_list; iface != NULL; iface = iface->next) {
			enum dcerpc_transport_t transport;
			const char *host = NULL;
			const char *host_addr = NULL;

#if 0
			/*
			 * Windows ignores the object uuid by default. There is
			 * one corner case. It is checked for the mgmt
			 * interface, which we do not implement here yet.
			 */
			if (uuid && !interface_match_by_uuid(iface->iface, uuid)) {
				continue;
			}
#endif

			eps = talloc_realloc(mem_ctx,
					     eps,
					     struct dcesrv_ep_iface,
					     total + 1);
			if (eps == NULL) {
				return 0;
			}
			eps[total].name = talloc_strdup(eps,
							iface->iface->name);
			if (eps[total].name == NULL) {
				return 0;
			}
			eps[total].syntax_id = iface->iface->syntax_id;

			description = dcerpc_binding_dup(mem_ctx, d->ep_description);
			if (description == NULL) {
				return 0;
			}

			status = dcerpc_binding_set_abstract_syntax(description,
							&iface->iface->syntax_id);
			if (!NT_STATUS_IS_OK(status)) {
				return 0;
			}

			transport = dcerpc_binding_get_transport(description);
			host = dcerpc_binding_get_string_option(description, "host");

			if (transport == NCACN_IP_TCP) {
				if (host == NULL) {
					host_addr = srv_addr;
				} else if (!is_ipaddress_v4(host)) {
					host_addr = srv_addr;
				} else if (strcmp(host, "0.0.0.0") == 0) {
					host_addr = srv_addr;
				}
			}

			if (host_addr != NULL) {
				status = dcerpc_binding_set_string_option(description,
									  "host",
									  host_addr);
				if (!NT_STATUS_IS_OK(status)) {
					return 0;
				}
			}

			status = dcerpc_binding_build_tower(eps,
							    description,
							    &eps[total].ep);
			TALLOC_FREE(description);
			if (NT_STATUS_IS_ERR(status)) {
				DEBUG(1, ("Unable to build tower for %s\n",
					  iface->iface->name));
				continue;
			}
			total++;
		}
	}

	*peps = eps;

	return total;
}

static bool is_privileged_pipe(struct auth_session_info *info) {
	/* If the user is not root, or has the system token, fail */
	if ((info->unix_token->uid != sec_initial_uid()) &&
	    !security_token_is_system(info->security_token)) {
		return false;
	}

	return true;
}

void srv_epmapper_delete_endpoints(struct dcesrv_connection *conn,
				   void *private_data)
{
	struct pipes_struct *p = dcesrv_get_pipes_struct(conn);
	struct dcesrv_auth *auth = NULL;
	struct epm_Delete r;
	struct dcesrv_ep_entry_list *el = p->ep_entries;
	error_status_t result;

	/* We have to set p->session_info to check if the connection is
	 * privileged and delete the endpoints registered by this connection.
	 * Set the default session info created at connection time as a
	 * fallback.
	 */
	p->session_info = conn->default_auth_state->session_info;

	/* Due to security context multiplexing we can have several states
	 * in the connection. Search the one of type NCALRPC_AS_SYSTEM to
	 * replace the default.
	 */
	for (auth = conn->auth_states; auth != NULL; auth = auth->next) {
		if (auth->auth_type == DCERPC_AUTH_TYPE_NCALRPC_AS_SYSTEM) {
			p->session_info = auth->session_info;
		}
	}

	while (el) {
		struct dcesrv_ep_entry_list *next = el->next;

		r.in.num_ents = el->num_ents;
		r.in.entries = el->entries;

		DEBUG(10, ("Delete_endpoints for: %s\n",
			   el->entries[0].annotation));

		result = _epm_Delete(p, &r);
		if (result != EPMAPPER_STATUS_OK) {
			DBG_ERR("Failed to delete endpoint maps\n");
			return;
		}

		DLIST_REMOVE(p->ep_entries, el);
		TALLOC_FREE(el);

		el = next;
	}
}

void srv_epmapper_cleanup(void)
{
	struct dcesrv_epm_endpoint *ep = endpoint_table;

	while (ep) {
		struct dcesrv_epm_endpoint *next = ep->next;

		DLIST_REMOVE(endpoint_table, ep);
		TALLOC_FREE(ep);

		ep = next;
	}
}

/*
 * epm_Insert
 *
 * Add the specified entries to an endpoint map.
 */
error_status_t _epm_Insert(struct pipes_struct *p,
			   struct epm_Insert *r)
{
	TALLOC_CTX *tmp_ctx;
	error_status_t rc;
	NTSTATUS status;
	uint32_t i;
	struct dcerpc_binding *b;
	struct dcesrv_epm_endpoint *ep = NULL;
	struct dcesrv_iface_list *iflist;
	struct dcesrv_iface *iface;
	bool add_ep;

	/* If this is not a privileged users, return */
	if (p->transport != NCALRPC ||
	    !is_privileged_pipe(p->session_info)) {
		p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
		return EPMAPPER_STATUS_CANT_PERFORM_OP;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return EPMAPPER_STATUS_NO_MEMORY;
	}

	DBG_NOTICE("Trying to add %"PRIu32" new entries.\n",
		   r->in.num_ents);

	for (i = 0; i < r->in.num_ents; i++) {
		enum dcerpc_transport_t transport;
		add_ep = false;
		b = NULL;

		status = dcerpc_binding_from_tower(tmp_ctx,
						   &r->in.entries[i].tower->tower,
						   &b);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_CANT_PERFORM_OP;
			goto done;
		}

		transport = dcerpc_binding_get_transport(b);
		DEBUG(3, ("_epm_Insert: Adding transport %s for %s\n",
			  derpc_transport_string_by_transport(transport),
			  r->in.entries[i].annotation));

		/* Check if the entry already exits */
		ep = find_endpoint(endpoint_table, b);
		if (ep == NULL) {
			/* No entry found, create it */
			ep = talloc_zero(NULL, struct dcesrv_epm_endpoint);
			if (ep == NULL) {
				rc = EPMAPPER_STATUS_NO_MEMORY;
				goto done;
			}
			add_ep = true;

			ep->ep_description = talloc_steal(ep, b);
		}

		/* TODO Replace the entry if the replace flag is set */

		/* Create an interface */
		iface = talloc(tmp_ctx, struct dcesrv_iface);
		if (iface == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		iface->name = talloc_strdup(iface, r->in.entries[i].annotation);
		if (iface->name == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		iface->syntax_id = dcerpc_binding_get_abstract_syntax(b);

		/*
		 * Check if the rpc service is alrady registered on the
		 * endpoint.
		 */
		if (find_interface(ep, iface) != NULL) {
			DEBUG(8, ("dcesrv_interface_register: interface '%s' "
				  "already registered on endpoint\n",
				  iface->name));
			/* FIXME wrong error code? */
			rc = EPMAPPER_STATUS_OK;
			goto done;
		}

		/* Create an entry for the interface */
		iflist = talloc(ep, struct dcesrv_iface_list);
		if (iflist == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		iflist->iface = talloc_move(iflist, &iface);

		/* Finally add the interface on the endpoint */
		DLIST_ADD(ep->iface_list, iflist);

		/* If it's a new endpoint add it to the endpoint_table */
		if (add_ep) {
			DLIST_ADD(endpoint_table, ep);
		}
	}

	if (r->in.num_ents > 0) {
		struct dcesrv_ep_entry_list *el;

		el = talloc_zero(p, struct dcesrv_ep_entry_list);
		if (el == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		el->num_ents = r->in.num_ents;
		el->entries = talloc_move(el, &r->in.entries);

		DLIST_ADD(p->ep_entries, el);
	}

	rc = EPMAPPER_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return rc;
}


/*
 * epm_Delete
 *
 * Delete the specified entries from an endpoint map.
 */
error_status_t _epm_Delete(struct pipes_struct *p,
			   struct epm_Delete *r)
{
	TALLOC_CTX *tmp_ctx;
	error_status_t rc;
	NTSTATUS status;
	uint32_t i;
	struct dcerpc_binding *b;
	struct dcesrv_epm_endpoint *ep = NULL;
	struct dcesrv_iface iface;
	struct dcesrv_iface_list *iflist;

	DEBUG(3, ("_epm_Delete: Trying to delete %u entries.\n",
		  r->in.num_ents));

	/* If this is not a privileged users, return */
	if (p->transport != NCALRPC ||
	    !is_privileged_pipe(p->session_info)) {
		p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
		return EPMAPPER_STATUS_CANT_PERFORM_OP;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return EPMAPPER_STATUS_NO_MEMORY;
	}

	for (i = 0; i < r->in.num_ents; i++) {
		enum dcerpc_transport_t transport;

		b = NULL;

		status = dcerpc_binding_from_tower(tmp_ctx,
						   &r->in.entries[i].tower->tower,
						   &b);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		transport = dcerpc_binding_get_transport(b);
		DEBUG(3, ("_epm_Delete: Deleting transport '%s' for '%s'\n",
			  derpc_transport_string_by_transport(transport),
			  r->in.entries[i].annotation));

		ep = find_endpoint(endpoint_table, b);
		if (ep == NULL) {
			rc = EPMAPPER_STATUS_OK;
			goto done;
		}

		iface.name = r->in.entries[i].annotation;
		iface.syntax_id = dcerpc_binding_get_abstract_syntax(b);

		iflist = find_interface_list(ep, &iface);
		if (iflist == NULL) {
			DEBUG(0, ("_epm_Delete: No interfaces left, delete endpoint\n"));
			DLIST_REMOVE(endpoint_table, ep);
			talloc_free(ep);

			rc = EPMAPPER_STATUS_OK;
			goto done;
		}

		DLIST_REMOVE(ep->iface_list, iflist);

		if (ep->iface_list == NULL) {
			DEBUG(0, ("_epm_Delete: No interfaces left, delete endpoint\n"));
			DLIST_REMOVE(endpoint_table, ep);
			talloc_free(ep);

			rc = EPMAPPER_STATUS_OK;
			goto done;
		}

	}

	rc = EPMAPPER_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return rc;
}


/*
 * epm_Lookup
 *
 * Lookup entries in an endpoint map.
 */
error_status_t _epm_Lookup(struct pipes_struct *p,
			   struct epm_Lookup *r)
{
	struct policy_handle *entry_handle;
	struct rpc_eps *eps;
	TALLOC_CTX *tmp_ctx;
	error_status_t rc;
	uint32_t count = 0;
	uint32_t num_ents = 0;
	uint32_t i;
	bool match = false;
	bool ok;
	NTSTATUS status;

	*r->out.num_ents = 0;
	r->out.entries = NULL;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return EPMAPPER_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("_epm_Lookup: Trying to lookup max. %u entries.\n",
		  r->in.max_ents));

	if (r->in.entry_handle == NULL ||
	    ndr_policy_handle_empty(r->in.entry_handle)) {
		char *srv_addr = NULL;

		DEBUG(7, ("_epm_Lookup: No entry_handle found, creating it.\n"));

		eps = talloc_zero(tmp_ctx, struct rpc_eps);
		if (eps == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		if (p->local_address != NULL &&
		    tsocket_address_is_inet(p->local_address, "ipv4"))
		{
			srv_addr = tsocket_address_inet_addr_string(p->local_address,
								    tmp_ctx);
		}

		switch (r->in.inquiry_type) {
		case RPC_C_EP_ALL_ELTS:
			/*
			 * Return all elements from the endpoint map. The
			 * interface_id, vers_option, and object parameters MUST
			 * be ignored.
			 */
			eps->count = build_ep_list(eps,
						   endpoint_table,
						   NULL,
						   srv_addr,
						   &eps->e);
			break;
		case RPC_C_EP_MATCH_BY_IF:
			/*
			 * Return endpoint map elements that contain the
			 * interface identifier specified by the interface_id
			 * and vers_option values.
			 *
			 * RPC_C_EP_MATCH_BY_IF and RPC_C_EP_MATCH_BY_BOTH
			 * need both the same endpoint list. There is a second
			 * check for the inquiry_type below which differentiates
			 * between them.
			 */
		case RPC_C_EP_MATCH_BY_BOTH:
			/*
			 * Return endpoint map elements that contain the
			 * interface identifier and object UUID specified by
			 * interface_id, vers_option, and object.
			 */
			eps->count = build_ep_list(eps,
						   endpoint_table,
						   &r->in.interface_id->uuid,
						   srv_addr,
						   &eps->e);
			break;
		case RPC_C_EP_MATCH_BY_OBJ:
			/*
			 * Return endpoint map elements that contain the object
			 * UUID specified by object.
			 */
			eps->count = build_ep_list(eps,
						   endpoint_table,
						   r->in.object,
						   srv_addr,
						   &eps->e);
			break;
		default:
			rc = EPMAPPER_STATUS_CANT_PERFORM_OP;
			goto done;
		}

		if (eps->count == 0) {
			rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
			goto done;
		}

		ok = create_policy_hnd(p, r->out.entry_handle, HTYPE_LOOKUP, eps);
		if (!ok) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		eps = find_policy_by_hnd(p,
					 r->out.entry_handle,
					 HTYPE_LOOKUP,
					 struct rpc_eps,
					 &status);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		entry_handle = r->out.entry_handle;
	} else {
		DEBUG(7, ("_epm_Lookup: Trying to find entry_handle.\n"));

		eps = find_policy_by_hnd(p,
					 r->in.entry_handle,
					 HTYPE_LOOKUP,
					 struct rpc_eps,
					 &status);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		entry_handle = r->in.entry_handle;
	}

	if (eps == NULL || eps->e == NULL) {
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	/* return the next N elements */
	count = r->in.max_ents;
	if (count > eps->count) {
		count = eps->count;
	}

	DEBUG(5, ("_epm_Lookup: Find %u entries\n", count));

	if (count == 0) {
		close_policy_hnd(p, entry_handle);
		ZERO_STRUCTP(r->out.entry_handle);

		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	r->out.entries = talloc_array(p->mem_ctx, struct epm_entry_t, count);
	if (r->out.entries == NULL) {
		rc = EPMAPPER_STATUS_NO_MEMORY;
		goto done;
	}

	for (i = 0; i < count; i++) {
		match = false;

		switch (r->in.inquiry_type) {
		case RPC_C_EP_ALL_ELTS:
			/*
			 * Return all elements from the endpoint map. The
			 * interface_id, vers_option, and object parameters MUST
			 * be ignored.
			 */
			match = true;
			break;
		case RPC_C_EP_MATCH_BY_IF:
			/*
			 * Return endpoint map elements that contain the
			 * interface identifier specified by the interface_id
			 * and vers_option values.
			 */
			if (GUID_equal(&r->in.interface_id->uuid,
				       &eps->e[i].syntax_id.uuid)) {
				match = true;
			}
			break;
		case RPC_C_EP_MATCH_BY_OBJ:
			/*
			 * Return endpoint map elements that contain the object
			 * UUID specified by object.
			 */
			if (GUID_equal(r->in.object,
				       &eps->e[i].syntax_id.uuid)) {
				match = true;
			}
			break;
		case RPC_C_EP_MATCH_BY_BOTH:
			/*
			 * Return endpoint map elements that contain the
			 * interface identifier and object UUID specified by
			 * interface_id, vers_option, and object.
			 */
			if (GUID_equal(&r->in.interface_id->uuid,
				       &eps->e[i].syntax_id.uuid) &&
			    GUID_equal(r->in.object, &eps->e[i].syntax_id.uuid)) {
				match = true;
			}
			break;
		default:
			return EPMAPPER_STATUS_CANT_PERFORM_OP;
		}

		if (match) {
			if (r->in.inquiry_type == RPC_C_EP_MATCH_BY_IF ||
			    r->in.inquiry_type == RPC_C_EP_MATCH_BY_OBJ) {
				/* Check interface version */

				match = false;
				switch (r->in.vers_option) {
				case RPC_C_VERS_ALL:
					/*
					 * Return endpoint map elements that
					 * contain the specified interface UUID,
					 * regardless of the version numbers.
					 */
					match = true;
					break;
				case RPC_C_VERS_COMPATIBLE:
					/*
					 * Return the endpoint map elements that
					 * contain the same major versions of
					 * the specified interface UUID and a
					 * minor version greater than or equal
					 * to the minor version of the specified
					 * UUID.
					 */
					if (r->in.interface_id->vers_major ==
					    (eps->e[i].syntax_id.if_version >> 16) &&
					    r->in.interface_id->vers_minor <=
					    (eps->e[i].syntax_id.if_version & 0xFFFF)) {
						match = true;
					}
					break;
				case RPC_C_VERS_EXACT:
					/*
					 * Return endpoint map elements that
					 * contain the specified version of the
					 * specified interface UUID.
					 */
					if (r->in.interface_id->vers_major ==
					    (eps->e[i].syntax_id.if_version >> 16) &&
					    r->in.interface_id->vers_minor ==
					    (eps->e[i].syntax_id.if_version & 0xFFFF)) {
						match = true;
					}
					match = true;
					break;
				case RPC_C_VERS_MAJOR_ONLY:
					/*
					 * Return endpoint map elements that
					 * contain the same version of the
					 * specified interface UUID and ignore
					 * the minor version.
					 */
					if (r->in.interface_id->vers_major ==
					    (eps->e[i].syntax_id.if_version >> 16)) {
						match = true;
					}
					match = true;
					break;
				case RPC_C_VERS_UPTO:
					/*
					 * Return endpoint map elements that
					 * contain a version of the specified
					 * interface UUID less than or equal to
					 * the specified major and minor
					 * version.
					 */
					if (r->in.interface_id->vers_major >
					    eps->e[i].syntax_id.if_version >> 16) {
						match = true;
					} else {
						if (r->in.interface_id->vers_major ==
						    (eps->e[i].syntax_id.if_version >> 16) &&
						    r->in.interface_id->vers_minor >=
						    (eps->e[i].syntax_id.if_version & 0xFFFF)) {
							match = true;
						}
					}
					break;
				default:
					return EPMAPPER_STATUS_CANT_PERFORM_OP;
				}
			}
		}

		if (match) {
			ZERO_STRUCT(r->out.entries[num_ents].object);

			DEBUG(10, ("_epm_Lookup: Adding tower for '%s'\n",
				   eps->e[i].name));
			r->out.entries[num_ents].annotation = talloc_strdup(r->out.entries,
									    eps->e[i].name);
			r->out.entries[num_ents].tower = talloc(r->out.entries,
								struct epm_twr_t);
			if (r->out.entries[num_ents].tower == NULL) {
				rc = EPMAPPER_STATUS_NO_MEMORY;
				goto done;
			}
			r->out.entries[num_ents].tower->tower.floors = talloc_move(r->out.entries[num_ents].tower, &eps->e[i].ep.floors);
			r->out.entries[num_ents].tower->tower.num_floors = eps->e[i].ep.num_floors;
			r->out.entries[num_ents].tower->tower_length = 0;

			num_ents++;
		}
	} /* end for loop */

	*r->out.num_ents = num_ents;

	eps->count -= count;
	eps->e += count;
	if (eps->count == 0) {
		close_policy_hnd(p, entry_handle);
		ZERO_STRUCTP(r->out.entry_handle);
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	rc = EPMAPPER_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return rc;
}

/*
 * epm_Map
 *
 * Apply some algorithm (using the fields in the map_tower) to an endpoint map
 * to produce a list of protocol towers.
 */
error_status_t _epm_Map(struct pipes_struct *p,
			struct epm_Map *r)
{
	struct policy_handle *entry_handle;
	enum dcerpc_transport_t transport;
	struct ndr_syntax_id ifid;
	struct epm_floor *floors;
	struct rpc_eps *eps;
	TALLOC_CTX *tmp_ctx;
	error_status_t rc;
	uint32_t count = 0;
	uint32_t num_towers = 0;
	uint32_t i;
	bool ok;
	NTSTATUS status;

	*r->out.num_towers = 0;
	r->out.towers = NULL;

	if (r->in.map_tower == NULL || r->in.max_towers == 0 ||
	    r->in.map_tower->tower.num_floors < 3) {
		return EPMAPPER_STATUS_NO_MORE_ENTRIES;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return EPMAPPER_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(r->out.entry_handle);

	DEBUG(5, ("_epm_Map: Trying to map max. %u towers.\n",
		  r->in.max_towers));

	/*
	 * A tower has normally up to 6 floors
	 *
	 * +-----------------------------------------------------------------+
	 * | Floor 1 | Provides the RPC interface identifier. (e.g. UUID for |
	 * |         | netlogon)                                             |
	 * +---------+-------------------------------------------------------+
	 * | Floor 2 | Transfer syntax (NDR endcoded)                        |
	 * +---------+-------------------------------------------------------+
	 * | Floor 3 | RPC protocol identifier (ncacn_tcp_ip, ncacn_np, ...) |
	 * +---------+-------------------------------------------------------+
	 * | Floor 4 | Port address (e.g. TCP Port: 49156)                   |
	 * +---------+-------------------------------------------------------+
	 * | Floor 5 | Transport (e.g. IP:192.168.51.10)                     |
	 * +---------+-------------------------------------------------------+
	 * | Floor 6 | Routing                                               |
	 * +---------+-------------------------------------------------------+
	 */
	floors = r->in.map_tower->tower.floors;

	/* We accept NDR as the transfer syntax */
	dcerpc_floor_get_lhs_data(&floors[1], &ifid);

	if (floors[1].lhs.protocol != EPM_PROTOCOL_UUID ||
	    !GUID_equal(&ifid.uuid, &ndr_transfer_syntax_ndr.uuid) ||
	    ifid.if_version != ndr_transfer_syntax_ndr.if_version) {
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	/* We only talk to sane transports */
	transport = dcerpc_transport_by_tower(&r->in.map_tower->tower);
	if (transport == NCA_UNKNOWN) {
		DEBUG(2, ("epm_Map: Client requested unknown transport with"
			  "levels: "));
		for (i = 2; i < r->in.map_tower->tower.num_floors; i++) {
			DEBUG(2, ("%d, ", r->in.map_tower->tower.floors[i].lhs.protocol));
		}
		DEBUG(2, ("\n"));
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	if (r->in.entry_handle == NULL ||
	    ndr_policy_handle_empty(r->in.entry_handle)) {
		struct GUID *obj;
		char *srv_addr = NULL;

		DEBUG(7, ("_epm_Map: No entry_handle found, creating it.\n"));

		eps = talloc_zero(tmp_ctx, struct rpc_eps);
		if (eps == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		/*
		 * *** ATTENTION ***
		 * CDE 1.1 states:
		 *
		 * ept_map()
		 *     Apply some algorithm (using the fields in the map_tower)
		 *     to an endpoint map to produce a list of protocol towers.
		 *
		 * The following code is the mysterious "some algorithm"!
		 */

		/* Filter by object id if one was given. */
		if (r->in.object == NULL || GUID_all_zero(r->in.object)) {
			obj = NULL;
		} else {
			obj = r->in.object;
		}

		if (p->local_address != NULL &&
		    tsocket_address_is_inet(p->local_address, "ipv4"))
		{
			srv_addr = tsocket_address_inet_addr_string(p->local_address,
								    tmp_ctx);
		}

		eps->count = build_ep_list(eps,
					   endpoint_table,
					   obj,
					   srv_addr,
					   &eps->e);
		if (eps->count == 0) {
			rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
			goto done;
		}

		/* Filter out endpoints which match the interface. */
		{
			struct rpc_eps *teps;
			uint32_t total = 0;

			teps = talloc_zero(tmp_ctx, struct rpc_eps);
			if (teps == NULL) {
				rc = EPMAPPER_STATUS_NO_MEMORY;
				goto done;
			}

			for (i = 0; i < eps->count; i++) {
				if (data_blob_cmp(&r->in.map_tower->tower.floors[0].lhs.lhs_data,
				                  &eps->e[i].ep.floors[0].lhs.lhs_data) != 0 ||
				    transport != dcerpc_transport_by_tower(&eps->e[i].ep)) {
					continue;
				}

				teps->e = talloc_realloc(tmp_ctx,
							 teps->e,
							 struct dcesrv_ep_iface,
							 total + 1);
				if (teps->e == NULL) {
					return 0;
				}

				teps->e[total].ep.floors = talloc_move(teps, &eps->e[i].ep.floors);
				teps->e[total].ep.num_floors = eps->e[i].ep.num_floors;
				teps->e[total].name = talloc_move(teps, &eps->e[i].name);
				teps->e[total].syntax_id = eps->e[i].syntax_id;

				total++;
			}

			teps->count = total;
			talloc_free(eps);
			eps = teps;
		}
		/* end of "some algorithm" */

		ok = create_policy_hnd(p, r->out.entry_handle, HTYPE_LOOKUP, eps);
		if (!ok) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		eps = find_policy_by_hnd(p,
					 r->out.entry_handle,
					 HTYPE_LOOKUP,
					 struct rpc_eps,
					 &status);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		entry_handle = r->out.entry_handle;
	} else {
		DEBUG(7, ("_epm_Map: Trying to find entry_handle.\n"));

		eps = find_policy_by_hnd(p,
					 r->in.entry_handle,
					 HTYPE_LOOKUP,
					 struct rpc_eps,
					 &status);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		entry_handle = r->in.entry_handle;
	}

	if (eps == NULL || eps->e == NULL) {
		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	/* return the next N elements */
	count = r->in.max_towers;
	if (count > eps->count) {
		count = eps->count;
	}

	if (count == 0) {
		close_policy_hnd(p, entry_handle);
		ZERO_STRUCTP(r->out.entry_handle);

		rc = EPMAPPER_STATUS_NO_MORE_ENTRIES;
		goto done;
	}

	r->out.towers = talloc_array(p->mem_ctx, struct epm_twr_p_t, count);
	if (r->out.towers == NULL) {
		rc = EPMAPPER_STATUS_NO_MEMORY;
		goto done;
	}

	for (i = 0; i < count; i++) {
		DEBUG(7, ("_epm_Map: Map tower for '%s'\n",
			   eps->e[i].name));

		r->out.towers[num_towers].twr = talloc(r->out.towers,
						       struct epm_twr_t);
		if (r->out.towers[num_towers].twr == NULL) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}
		r->out.towers[num_towers].twr->tower.floors = talloc_move(r->out.towers[num_towers].twr, &eps->e[i].ep.floors);
		r->out.towers[num_towers].twr->tower.num_floors = eps->e[i].ep.num_floors;
		r->out.towers[num_towers].twr->tower_length = 0;

		num_towers++;
	}

	*r->out.num_towers = num_towers;

	eps->count -= count;
	eps->e += count;
	if (eps->count == 0) {
		close_policy_hnd(p, entry_handle);
		ZERO_STRUCTP(r->out.entry_handle);
	}

	rc = EPMAPPER_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return rc;
}

/*
 * epm_LookupHandleFree
 */
error_status_t _epm_LookupHandleFree(struct pipes_struct *p,
				     struct epm_LookupHandleFree *r)
{
	if (r->in.entry_handle == NULL) {
		return EPMAPPER_STATUS_OK;
	}

	if (is_valid_policy_hnd(r->in.entry_handle)) {
		close_policy_hnd(p, r->in.entry_handle);
	}

	r->out.entry_handle = r->in.entry_handle;

	return EPMAPPER_STATUS_OK;
}


/*
 * epm_InqObject
 *
 * A client implementation SHOULD NOT call this method. These extensions do not
 * provide an alternative method.
 */
error_status_t _epm_InqObject(struct pipes_struct *p,
		      struct epm_InqObject *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
 * epm_MgmtDelete
 *
 * A client implementation SHOULD NOT call this method. These extensions do not
 * provide an alternative method.
*/
error_status_t _epm_MgmtDelete(struct pipes_struct *p,
		       struct epm_MgmtDelete *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_MapAuth
*/
error_status_t _epm_MapAuth(struct pipes_struct *p,
		    struct epm_MapAuth *r)
{
	p->fault_state = DCERPC_FAULT_OP_RNG_ERROR;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}

static NTSTATUS epmapper__op_shutdown_server(struct dcesrv_context *dce_ctx,
			const struct dcesrv_endpoint_server *ep_server);

#define DCESRV_INTERFACE_EPMAPPER_SHUTDOWN_SERVER \
       epmapper_shutdown_server

static NTSTATUS epmapper_shutdown_server(struct dcesrv_context *dce_ctx,
		const struct dcesrv_endpoint_server *ep_server)
{
	srv_epmapper_cleanup();

	return epmapper__op_shutdown_server(dce_ctx, ep_server);
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_epmapper_scompat.c"

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
