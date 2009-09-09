/* 
   Unix SMB/CIFS implementation.

   implement the DsAddEntry call

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Andrew Tridgell   2009
   
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
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "auth/auth.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"

/* 
  drsuapi_DsAddEntry
*/
WERROR dcesrv_drsuapi_DsAddEntry(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct drsuapi_DsAddEntry *r)
{
	WERROR status;
	struct drsuapi_bind_state *b_state;
	struct dcesrv_handle *h;
	uint32_t num = 0;
	struct drsuapi_DsReplicaObjectIdentifier2 *ids = NULL;

	if (DEBUGLVL(4)) {
		NDR_PRINT_FUNCTION_DEBUG(drsuapi_DsAddEntry, NDR_IN, r);
	}

	/* TODO: check which out level the client supports */

	ZERO_STRUCTP(r->out.ctr);
	r->out.level_out = 3;
	r->out.ctr->ctr3.level = 1;
	r->out.ctr->ctr3.error = talloc_zero(mem_ctx, union drsuapi_DsAddEntryError);

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	switch (r->in.level) {
	case 2:
		status = dsdb_origin_objects_commit(b_state->sam_ctx,
						    mem_ctx,
						    &r->in.req->req2.first_object,
						    &num,
						    &ids);
		if (!W_ERROR_IS_OK(status)) {
			r->out.ctr->ctr3.error->info1.status = status;
			W_ERROR_NOT_OK_RETURN(status);
		}

		r->out.ctr->ctr3.count = num;
		r->out.ctr->ctr3.objects = ids;

		return WERR_OK;
	default:
		break;
	}

	return WERR_FOOBAR;
}
