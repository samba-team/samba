/*
   Unix SMB/CIFS implementation.

   endpoint server for the mgmt pipe

   Copyright (C) Jelmer Vernooij 2006

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
#include "librpc/gen_ndr/ndr_mgmt.h"

#define DCESRV_INTERFACE_MGMT_BIND(context, iface) \
       dcesrv_interface_mgmt_bind(context, iface)
/*
 * This #define allows the mgmt interface to accept invalid
 * association groups, because association groups are to coordinate
 * handles, and handles are not used in mgmt. This in turn avoids
 * the need to coordinate these across multiple possible NETLOGON
 * processes, as an mgmt interface is added to each
 */

#define DCESRV_INTERFACE_MGMT_FLAGS DCESRV_INTERFACE_FLAGS_HANDLES_NOT_USED

static NTSTATUS dcesrv_interface_mgmt_bind(struct dcesrv_connection_context *context,
					     const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_allow_connect(context, iface);
}

/*
  mgmt_inq_if_ids
*/
static WERROR dcesrv_mgmt_inq_if_ids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_inq_if_ids *r)
{
	const struct dcesrv_endpoint *ep = dce_call->conn->endpoint;
	struct dcesrv_if_list *l = NULL;
	struct rpc_if_id_vector_t *vector = NULL;

	vector = talloc(mem_ctx, struct rpc_if_id_vector_t);
	if (vector == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	vector->count = 0;
	vector->if_id = NULL;

	for (l = ep->interface_list; l; l = l->next) {
		bool filter;

		filter = ndr_syntax_id_equal(&l->iface->syntax_id, &ndr_table_mgmt.syntax_id);
		if (filter) {
			/*
			 * We should not return the mgmt syntax itself here
			 */
			continue;
		}

		vector->count++;
		vector->if_id = talloc_realloc(vector, vector->if_id, struct ndr_syntax_id_p, vector->count);
		if (vector->if_id == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		vector->if_id[vector->count-1].id = &l->iface->syntax_id;
	}

	*r->out.if_id_vector = vector;
	return WERR_OK;
}


/*
  mgmt_inq_stats
*/
static WERROR dcesrv_mgmt_inq_stats(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_inq_stats *r)
{
	if (r->in.max_count != MGMT_STATS_ARRAY_MAX_SIZE)
		return WERR_NOT_SUPPORTED;

	r->out.statistics->statistics = talloc_zero_array(mem_ctx,
							  uint32_t,
							  r->in.max_count);
	if (r->out.statistics->statistics == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	r->out.statistics->count = r->in.max_count;
	/* FIXME */
	r->out.statistics->statistics[MGMT_STATS_CALLS_IN] = 0;
	r->out.statistics->statistics[MGMT_STATS_CALLS_OUT] = 0;
	r->out.statistics->statistics[MGMT_STATS_PKTS_IN] = 0;
	r->out.statistics->statistics[MGMT_STATS_PKTS_OUT] = 0;

	return WERR_OK;
}


/*
  mgmt_is_server_listening
*/
static uint32_t dcesrv_mgmt_is_server_listening(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_is_server_listening *r)
{
	*r->out.status = 0;
	return 1;
}


/*
  mgmt_stop_server_listening
*/
static WERROR dcesrv_mgmt_stop_server_listening(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_stop_server_listening *r)
{
	return WERR_ACCESS_DENIED;
}


/*
  mgmt_inq_princ_name
*/
static WERROR dcesrv_mgmt_inq_princ_name(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct mgmt_inq_princ_name *r)
{
	const char *principal = NULL;

	if (r->in.princ_name_size < 1) {
		DCESRV_FAULT(DCERPC_FAULT_BAD_STUB_DATA);
	}

	r->out.princ_name = "";

	principal = dcesrv_auth_type_principal_find(dce_call->conn->dce_ctx,
						    r->in.authn_proto);
	if (principal == NULL) {
		return WERR_RPC_S_UNKNOWN_AUTHN_SERVICE;
	}

	if (strlen(principal) + 1 > r->in.princ_name_size) {
		return WERR_INSUFFICIENT_BUFFER;
	}

	r->out.princ_name = principal;
	return WERR_OK;
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_mgmt_s.c"

const struct dcesrv_interface *dcesrv_get_mgmt_interface(void)
{
	return &dcesrv_mgmt_interface;
}
