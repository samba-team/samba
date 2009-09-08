/* 
   Unix SMB/CIFS implementation.

   implement the DRSUpdateRefs call

   Copyright (C) Andrew Tridgell 2009
   
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
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "auth/auth.h"

/*
  load the repsTo structure for a given partition GUID
 */
static WERROR uref_loadreps(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx, struct GUID *guid,
			    struct repsTo *reps)
{
	struct ldb_dn *dn;
	const char *attrs[] = { "repsTo", NULL };
	struct ldb_result *res;
	const struct ldb_val *v;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	if (dsdb_find_dn_by_guid(sam_ctx, tmp_ctx, GUID_string(tmp_ctx, guid), &dn) != LDB_SUCCESS) {
		DEBUG(0,("drsuapi_addref: failed to find partition with GUID %s\n",
			 GUID_string(tmp_ctx, guid)));
		talloc_free(tmp_ctx);
		return WERR_DS_DRA_BAD_NC;
	}

	/* TODO: possibly check in the rootDSE to see that this DN is
	 * one of our partition roots */	 

	if (ldb_search(sam_ctx, tmp_ctx, &res, dn, LDB_SCOPE_BASE, attrs, NULL) != LDB_SUCCESS) {
		DEBUG(0,("drsuapi_addref: failed to read partition object\n"));
		talloc_free(tmp_ctx);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	v = ldb_msg_find_ldb_val(res->msgs[0], "repsTo");
	if (v == NULL) {
		/* treat as empty empty */
		ZERO_STRUCTP(reps);
		reps->version = REPSTO_VERSION1;
	} else {
		enum ndr_err_code ndr_err;
		ndr_err = ndr_pull_struct_blob(v, mem_ctx, lp_iconv_convenience(ldb_get_opaque(sam_ctx, "loadparm")),
					       reps, 
					       (ndr_pull_flags_fn_t)ndr_pull_repsTo);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(tmp_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
	}

	talloc_free(tmp_ctx);
	
	return WERR_OK;
}

/*
  save the repsTo structure for a given partition GUID
 */
static WERROR uref_savereps(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx, struct GUID *guid,
			    struct repsTo *reps)
{
	struct ldb_dn *dn;
	struct ldb_val v;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	enum ndr_err_code ndr_err;
	struct ldb_message *msg;
	struct ldb_message_element *el;

	if (dsdb_find_dn_by_guid(sam_ctx, tmp_ctx, GUID_string(tmp_ctx, guid), &dn) != LDB_SUCCESS) {
		DEBUG(0,("drsuapi_addref: failed to find partition with GUID %s\n",
			 GUID_string(tmp_ctx, guid)));
		talloc_free(tmp_ctx);
		return WERR_DS_DRA_BAD_NC;
	}

	ndr_err = ndr_push_struct_blob(&v, tmp_ctx, lp_iconv_convenience(ldb_get_opaque(sam_ctx, "loadparm")),
				       reps, 
				       (ndr_push_flags_fn_t)ndr_push_repsTo);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto failed;
	}

	msg = ldb_msg_new(tmp_ctx);
	msg->dn = dn;
	if (ldb_msg_add_empty(msg, "repsTo", LDB_FLAG_MOD_REPLACE, &el) != LDB_SUCCESS) {
		goto failed;
	}
	el->num_values = 1;
	el->values = &v;

	if (ldb_modify(sam_ctx, msg) != LDB_SUCCESS) {
		DEBUG(0,("Failed to store repsTo - %s\n", ldb_errstring(sam_ctx)));
		goto failed;
	}

	talloc_free(tmp_ctx);
	
	return WERR_OK;

failed:
	talloc_free(tmp_ctx);
	return WERR_DS_DRA_INTERNAL_ERROR;
}

/*
  add a replication destination for a given partition GUID
 */
static WERROR uref_add_dest(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx, 
			    struct GUID *guid, struct repsToDest *dest)
{
	struct repsTo reps;
	WERROR werr;
	struct repsTov1 *rv1;

	werr = uref_loadreps(sam_ctx, mem_ctx, guid, &reps);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	if (reps.version != REPSTO_VERSION1) {
		DEBUG(0,("Wrong version number %u on disk\n",
			 reps.version));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	rv1 = &reps.ctr.r;
	rv1->reps = talloc_realloc(mem_ctx, rv1->reps, struct repsToDest, rv1->count+1);
	if (rv1->reps == NULL) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	rv1->reps[rv1->count] = *dest;
	rv1->count++;

	werr = uref_savereps(sam_ctx, mem_ctx, guid, &reps);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	return WERR_OK;	
}

/*
  delete a replication destination for a given partition GUID
 */
static WERROR uref_del_dest(struct ldb_context *sam_ctx, TALLOC_CTX *mem_ctx, 
			    struct GUID *guid, struct GUID *dest_guid)
{
	struct repsTo reps;
	WERROR werr;
	struct repsTov1 *rv1;
	int i;

	werr = uref_loadreps(sam_ctx, mem_ctx, guid, &reps);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	if (reps.version != REPSTO_VERSION1) {
		DEBUG(0,("Wrong version number %u on disk\n", reps.version));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	rv1 = &reps.ctr.r;

	for (i=0; i<rv1->count; i++) {
		if (GUID_compare(dest_guid, &rv1->reps[i].dest_guid) == 0) {
			if (i+1 < rv1->count) {
				memmove(&rv1->reps[i], &rv1->reps[i+1], sizeof(rv1->reps[i])*(rv1->count-(i+1)));
			}
			rv1->count--;
		}
	}

	werr = uref_savereps(sam_ctx, mem_ctx, guid, &reps);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	return WERR_OK;	
}

/* 
  drsuapi_DsReplicaUpdateRefs
*/
WERROR dcesrv_drsuapi_DsReplicaUpdateRefs(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					  struct drsuapi_DsReplicaUpdateRefs *r)
{
	struct drsuapi_DsReplicaUpdateRefsRequest1 *req;
	struct ldb_context *sam_ctx;
	WERROR werr;

	if (r->in.level != 1) {
		DEBUG(0,("DrReplicUpdateRefs - unsupported level %u\n", r->in.level));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	req = &r->in.req.req1;
	DEBUG(4,("DrReplicUpdateRefs for host '%s' with GUID %s options 0x%08x nc=%s\n",
		 req->dest_dsa_dns_name, GUID_string(mem_ctx, &req->dest_dsa_guid),
		 req->options,
		 drs_ObjectIdentifier_to_string(mem_ctx, req->naming_context)));

	/* TODO: We need to authenticate this operation pretty carefully */
	sam_ctx = samdb_connect(mem_ctx, dce_call->event_ctx, dce_call->conn->dce_ctx->lp_ctx, 
				system_session(mem_ctx, dce_call->conn->dce_ctx->lp_ctx));
	if (!sam_ctx) {
		return WERR_DS_DRA_INTERNAL_ERROR;		
	}

	if (ldb_transaction_start(sam_ctx) != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to start transaction on samdb\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;		
	}

	if (req->options & DRSUAPI_DS_REPLICA_UPDATE_DELETE_REFERENCE) {
		werr = uref_del_dest(sam_ctx, mem_ctx, &req->naming_context->guid, &req->dest_dsa_guid);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,("Failed to delete repsTo for %s\n",
				 GUID_string(dce_call, &req->dest_dsa_guid)));
			goto failed;
		}
	}

	if (req->options & DRSUAPI_DS_REPLICA_UPDATE_ADD_REFERENCE) {
		struct repsToDest dest;

		dest.dest_dsa_dns_name = req->dest_dsa_dns_name;
		dest.dest_guid         = req->dest_dsa_guid;
		dest.options           = req->options;

		werr = uref_add_dest(sam_ctx, mem_ctx, &req->naming_context->guid, &dest);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,("Failed to delete repsTo for %s\n",
				 GUID_string(dce_call, &dest.dest_guid)));
			goto failed;
		}
	}

	if (ldb_transaction_commit(sam_ctx) != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to commit transaction on samdb\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;		
	}

	talloc_free(sam_ctx);
	return WERR_OK;

failed:
	ldb_transaction_cancel(sam_ctx);
	talloc_free(sam_ctx);
	return werr;
}

