/*
   Unix SMB/CIFS implementation.

   Endpoint server for the epmapper pipe

   Copyright (C) 2010      Andreas Schneider <asn@samba.org>

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
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/srv_epmapper.h"

typedef uint32_t error_status_t;

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
struct dcesrv_endpoint {
	struct dcesrv_endpoint *next, *prev;

	/* The type and the location of the endpoint */
	struct dcerpc_binding *ep_description;

	/* A list of rpc services able to connect to the endpoint */
	struct dcesrv_iface_list *iface_list;
};

struct dcesrv_endpoint *endpoint_table;

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
static const struct dcesrv_iface *find_interface(const struct dcesrv_endpoint *endpoint,
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

/*
 * Check if two endpoints match.
 */
static bool endpoints_match(const struct dcerpc_binding *ep1,
			    const struct dcerpc_binding *ep2)
{
	if (ep1->transport != ep2->transport) {
		return false;
	}

	if (!ep1->endpoint || !ep2->endpoint) {
		return ep1->endpoint == ep2->endpoint;
	}

	if (!strequal(ep1->endpoint, ep2->endpoint)) {
		return false;
	}

	return true;
}

static struct dcesrv_endpoint *find_endpoint(struct dcesrv_endpoint *endpoint_list,
					     struct dcerpc_binding *ep_description) {
	struct dcesrv_endpoint *ep;

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
			      struct dcesrv_endpoint *endpoint_list,
			      struct dcesrv_ep_iface **peps)
{
	struct dcesrv_ep_iface *eps;
	struct dcesrv_endpoint *d;
	uint32_t total = 0;
	NTSTATUS status;

	*peps = NULL;

	for (d = endpoint_list; d != NULL; d = d->next) {
		struct dcesrv_iface_list *iface;
		struct dcerpc_binding *description;

		for (iface = d->iface_list; iface != NULL; iface = iface->next) {
			eps = talloc_realloc(mem_ctx,
					     eps,
					     struct dcesrv_ep_iface,
					     total + 1);
			if (eps == NULL) {
				return 0;
			}
			eps[total].name = iface->iface->name;

			description = d->ep_description;
			description->object = iface->iface->syntax_id;

			status = dcerpc_binding_build_tower(eps,
							    description,
							    &eps[total].ep);
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

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return EPMAPPER_STATUS_NO_MEMORY;
	}

	DEBUG(3, ("_epm_Insert: Trying to add %u new entries.\n",
		  r->in.num_ents));

	/* TODO Check if we have a priviledged pipe/handle */

	for (i = 0; i < r->in.num_ents; i++) {
		struct dcerpc_binding *b = NULL;
		struct dcesrv_endpoint *ep;
		struct dcesrv_iface_list *iflist;
		struct dcesrv_iface *iface;
		bool add_ep = false;

		status = dcerpc_binding_from_tower(tmp_ctx,
						   &r->in.entries[i].tower->tower,
						   &b);
		if (!NT_STATUS_IS_OK(status)) {
			rc = EPMAPPER_STATUS_NO_MEMORY;
			goto done;
		}

		DEBUG(3, ("_epm_Insert: Adding transport %s for %s\n",
			  derpc_transport_string_by_transport(b->transport),
			  r->in.entries[i].annotation));

		/* Check if the entry already exits */
		ep = find_endpoint(endpoint_table, b);
		if (ep == NULL) {
			/* No entry found, create it */
			ep = talloc_zero(NULL, struct dcesrv_endpoint);
			if (ep == NULL) {
				rc = EPMAPPER_STATUS_CANT_PERFORM_OP;
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
		iface->syntax_id = b->object;

		/*
		 * Check if the rpc service is alrady registered on the
		 * endpoint.
		 */
		if (find_interface(ep, iface) != NULL) {
			DEBUG(0, ("dcesrv_interface_register: interface '%s' "
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

	rc = EPMAPPER_STATUS_OK;
done:
	talloc_free(tmp_ctx);

	return rc;
}


/*
  epm_Delete
*/
error_status_t _epm_Delete(struct pipes_struct *p,
		   struct epm_Delete *r)
{
	/* Check if we have a priviledged pipe/handle */

	/* Delete the entry */

	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_Lookup
*/
error_status_t _epm_Lookup(struct pipes_struct *p,
		   struct epm_Lookup *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
 * Apply some algorithm (using the fields in the map_tower) to an endpoint map
 * to produce a list of protocol towers.
 */
error_status_t _epm_Map(struct pipes_struct *p,
			struct epm_Map *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}

/*
  epm_LookupHandleFree
*/
error_status_t _epm_LookupHandleFree(struct pipes_struct *p,
			     struct epm_LookupHandleFree *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_InqObject
*/
error_status_t _epm_InqObject(struct pipes_struct *p,
		      struct epm_InqObject *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_MgmtDelete
*/
error_status_t _epm_MgmtDelete(struct pipes_struct *p,
		       struct epm_MgmtDelete *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}


/*
  epm_MapAuth
*/
error_status_t _epm_MapAuth(struct pipes_struct *p,
		    struct epm_MapAuth *r)
{
	p->rng_fault_state = true;
	return EPMAPPER_STATUS_CANT_PERFORM_OP;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
