/*
   Unix SMB/CIFS implementation.

   implement the DsWriteAccountSpn call

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Andrew Tridgell   2010

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
#include "rpc_server/dcerpc_server.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"

/*
  drsuapi_DsWriteAccountSpn
*/
WERROR dcesrv_drsuapi_DsWriteAccountSpn(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct drsuapi_DsWriteAccountSpn *r)
{
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *h;

	*r->out.level_out = r->in.level;

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	r->out.res = talloc(mem_ctx, union drsuapi_DsWriteAccountSpnResult);
	W_ERROR_HAVE_NO_MEMORY(r->out.res);

	switch (r->in.level) {
		case 1: {
			struct drsuapi_DsWriteAccountSpnRequest1 *req;
			struct ldb_message *msg;
			int count, i, ret;
			unsigned spn_count=0;

			req = &r->in.req->req1;
			count = req->count;

			msg = ldb_msg_new(mem_ctx);
			if (msg == NULL) {
				return WERR_NOMEM;
			}

			msg->dn = ldb_dn_new(msg, b_state->sam_ctx, req->object_dn);
			if ( ! ldb_dn_validate(msg->dn)) {
				r->out.res->res1.status = WERR_OK;
				return WERR_OK;
			}

			/* construct mods */
			for (i = 0; i < count; i++) {
				ret = samdb_msg_add_string(b_state->sam_ctx,
							   msg, msg, "servicePrincipalName",
							   req->spn_names[i].str);
				if (ret != LDB_SUCCESS) {
					return WERR_NOMEM;
				}
				spn_count++;
			}

			if (msg->num_elements == 0) {
				DEBUG(2,("No SPNs need changing on %s\n", ldb_dn_get_linearized(msg->dn)));
				r->out.res->res1.status = WERR_OK;
				return WERR_OK;
			}

			for (i=0;i<msg->num_elements;i++) {
				switch (req->operation) {
				case DRSUAPI_DS_SPN_OPERATION_ADD:
					msg->elements[i].flags = LDB_FLAG_MOD_ADD;
					break;
				case DRSUAPI_DS_SPN_OPERATION_REPLACE:
					msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
					break;
				case DRSUAPI_DS_SPN_OPERATION_DELETE:
					msg->elements[i].flags = LDB_FLAG_MOD_DELETE;
					break;
				}
			}

			/* Apply to database */
			ret = dsdb_modify(b_state->sam_ctx, msg, DSDB_MODIFY_PERMISSIVE);
			if (ret != 0) {
				DEBUG(0,("Failed to modify SPNs on %s: %s\n",
					 ldb_dn_get_linearized(msg->dn),
					 ldb_errstring(b_state->sam_ctx)));
				r->out.res->res1.status = WERR_ACCESS_DENIED;
			} else {
				DEBUG(2,("Modified %u SPNs on %s\n", spn_count, ldb_dn_get_linearized(msg->dn)));
				r->out.res->res1.status = WERR_OK;
			}

			return WERR_OK;
		}
	}

	return WERR_UNKNOWN_LEVEL;
}
