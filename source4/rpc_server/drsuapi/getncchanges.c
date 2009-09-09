/* 
   Unix SMB/CIFS implementation.

   implement the DRSUpdateRefs call

   Copyright (C) Anatoliy Atanasov 2009
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
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "auth/auth.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"

/* 
  drsuapi_DsGetNCChanges
*/
WERROR dcesrv_drsuapi_DsGetNCChanges(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsGetNCChanges *r)
{
	struct ldb_result *site_res;
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot;
	struct drsuapi_bind_state *b_state;
	struct ldb_dn *ncRoot_dn;
	int ret;
	int i;
	int j;
	int uSN;
	struct dsdb_schema *schema;
	struct drsuapi_DsReplicaOIDMapping_Ctr *ctr;
	time_t t = time(NULL);
	NTTIME now;
	struct drsuapi_DsReplicaObjectListItemEx *currentObject;
	struct dom_sid *zero_sid;
	struct ldb_dn *obj_dn;
	enum ndr_err_code ndr_err;
	const struct ldb_val *md_value;
	struct replPropertyMetaDataBlob md;
	ZERO_STRUCT(md);
	md.version = 1;
	b_state = talloc_zero(mem_ctx, struct drsuapi_bind_state);
	W_ERROR_HAVE_NO_MEMORY(b_state);
	zero_sid = talloc_zero(mem_ctx, struct dom_sid);
	/*
	 * connect to the samdb
	 */
	b_state->sam_ctx = samdb_connect(b_state, dce_call->event_ctx, dce_call->conn->dce_ctx->lp_ctx, dce_call->conn->auth_state.session_info);
	if (!b_state->sam_ctx) {
		return WERR_FOOBAR;
	}

	/* Check request revision. */
	if (r->in.level != 8) {
		return WERR_REVISION_MISMATCH;
	}

        /* Perform access checks. */
	if (r->in.req->req8.naming_context == NULL) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	ncRoot = r->in.req->req8.naming_context;
	if (ncRoot == NULL) {
		return WERR_DS_DRA_BAD_NC;
	}

	DEBUG(4,("DsGetNSChanges with uSHChanged >= %llu\n", 
		 (unsigned long long)r->in.req->req8.highwatermark.highest_usn));

	/* Construct response. */
	ncRoot_dn = ldb_dn_new(mem_ctx, b_state->sam_ctx, ncRoot->dn);
	ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, mem_ctx, &site_res,
			 ncRoot_dn, LDB_SCOPE_SUBTREE, NULL,
					      "(&(uSNChanged>=%llu)(objectClass=*))", 
					      (unsigned long long)r->in.req->req8.highwatermark.highest_usn);
	if (ret != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	*r->out.level_out = 6;
	r->out.ctr->ctr6.naming_context = talloc(mem_ctx, struct drsuapi_DsReplicaObjectIdentifier);
	*r->out.ctr->ctr6.naming_context = *ncRoot;
	/* TODO: linked attributes*/
	r->out.ctr->ctr6.linked_attributes_count = 0;
	r->out.ctr->ctr6.linked_attributes = NULL;

	r->out.ctr->ctr6.object_count = 0;
	r->out.ctr->ctr6.more_data = false;
	r->out.ctr->ctr6.uptodateness_vector = NULL;

	/* Prefix mapping */
	schema = dsdb_get_schema(b_state->sam_ctx);
	if (!schema) {
		DEBUG(0,("No schema in b_state->sam_ctx"));
	}

	dsdb_get_oid_mappings_drsuapi(schema, true, mem_ctx, &ctr);
	r->out.ctr->ctr6.mapping_ctr = *ctr;

	r->out.ctr->ctr6.source_dsa_guid = *(samdb_ntds_objectGUID(b_state->sam_ctx));
	r->out.ctr->ctr6.source_dsa_invocation_id = *(samdb_ntds_invocation_id(b_state->sam_ctx));

	r->out.ctr->ctr6.old_highwatermark = r->in.req->req8.highwatermark;
	r->out.ctr->ctr6.new_highwatermark = r->in.req->req8.highwatermark;

	r->out.ctr->ctr6.first_object = talloc(mem_ctx, struct drsuapi_DsReplicaObjectListItemEx);
	currentObject = r->out.ctr->ctr6.first_object;

	for(i=0; i<site_res->count; i++) {
		uSN = ldb_msg_find_attr_as_int(site_res->msgs[i],"uSNChanged", -1);
		r->out.ctr->ctr6.object_count++;
		if (uSN > r->out.ctr->ctr6.new_highwatermark.highest_usn) {
			r->out.ctr->ctr6.new_highwatermark.highest_usn = uSN;
		}

		if (ldb_dn_compare(ncRoot_dn, site_res->msgs[i]->dn) == 0) {
			currentObject->is_nc_prefix = true;
			currentObject->parent_object_guid = NULL;
		} else {
			currentObject->is_nc_prefix = false;
			currentObject->parent_object_guid = talloc(mem_ctx, struct GUID);
			*currentObject->parent_object_guid = samdb_result_guid(site_res->msgs[i], "parentGUID");
		}
		currentObject->next_object = NULL;

		currentObject->meta_data_ctr = talloc(mem_ctx, struct drsuapi_DsReplicaMetaDataCtr);
		md_value = ldb_msg_find_ldb_val(site_res->msgs[i], "replPropertyMetaData");
		if (md_value) {
			ndr_err = ndr_pull_struct_blob(md_value, mem_ctx,
						       lp_iconv_convenience(ldb_get_opaque(b_state->sam_ctx, "loadparm")), &md,
						       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return WERR_DS_DRA_INTERNAL_ERROR;
			}

			if (md.version != 1) {
				return WERR_DS_DRA_INTERNAL_ERROR;
			}

			currentObject->meta_data_ctr->count = md.ctr.ctr1.count;
			currentObject->meta_data_ctr->meta_data = talloc_array(mem_ctx, struct drsuapi_DsReplicaMetaData, md.ctr.ctr1.count);
			for (j=0; j<md.ctr.ctr1.count; j++) {
				currentObject->meta_data_ctr->meta_data[j].originating_change_time = md.ctr.ctr1.array[j].originating_change_time;
				currentObject->meta_data_ctr->meta_data[j].version = md.ctr.ctr1.array[j].version;
				currentObject->meta_data_ctr->meta_data[j].originating_invocation_id = md.ctr.ctr1.array[j].originating_invocation_id;
				currentObject->meta_data_ctr->meta_data[j].originating_usn = md.ctr.ctr1.array[j].originating_usn;
			}
		} else {
			currentObject->meta_data_ctr->meta_data = talloc(mem_ctx, struct drsuapi_DsReplicaMetaData);
			currentObject->meta_data_ctr->count = 0;
		}
		currentObject->object.identifier = talloc(mem_ctx, struct drsuapi_DsReplicaObjectIdentifier);
		obj_dn = ldb_msg_find_attr_as_dn(b_state->sam_ctx, mem_ctx, site_res->msgs[i], "distinguishedName");
		currentObject->object.identifier->dn = ldb_dn_get_linearized(obj_dn);
		currentObject->object.identifier->guid = GUID_zero();
		currentObject->object.identifier->sid = *zero_sid;

		currentObject->object.attribute_ctr.num_attributes = site_res->msgs[i]->num_elements;
		/* Exclude non-replicate attributes from the responce.*/
		for (j=0; j<site_res->msgs[i]->num_elements; j++) {
			const struct dsdb_attribute *sa;
			sa = dsdb_attribute_by_lDAPDisplayName(schema, site_res->msgs[i]->elements[j].name);
			if (sa && sa->systemFlags & SYSTEM_FLAG_CR_NTDS_NC) {
				ldb_msg_remove_attr(site_res->msgs[i], site_res->msgs[i]->elements[j].name);
				currentObject->object.attribute_ctr.num_attributes--;
			}
		}
		currentObject->object.attribute_ctr.attributes = talloc_array(mem_ctx, struct drsuapi_DsReplicaAttribute,
									      currentObject->object.attribute_ctr.num_attributes);
		for (j=0; j<currentObject->object.attribute_ctr.num_attributes; j++) {
			dsdb_attribute_ldb_to_drsuapi(b_state->sam_ctx, schema,&site_res->msgs[i]->elements[j], mem_ctx,
						      &currentObject->object.attribute_ctr.attributes[j]);
		}

		if (i == (site_res->count-1)) {
			break;
		}
		currentObject->next_object = talloc(mem_ctx, struct drsuapi_DsReplicaObjectListItemEx);
		currentObject = currentObject->next_object;
	}

	r->out.ctr->ctr6.uptodateness_vector = talloc(mem_ctx, struct drsuapi_DsReplicaCursor2CtrEx);

	r->out.ctr->ctr6.uptodateness_vector->version = 2;
	r->out.ctr->ctr6.uptodateness_vector->count = 1;
	r->out.ctr->ctr6.uptodateness_vector->reserved1 = 0;
	r->out.ctr->ctr6.uptodateness_vector->reserved2 = 0;
	r->out.ctr->ctr6.uptodateness_vector->cursors = talloc(mem_ctx, struct drsuapi_DsReplicaCursor2);

	r->out.ctr->ctr6.uptodateness_vector->cursors[0].source_dsa_invocation_id = *(samdb_ntds_invocation_id(b_state->sam_ctx));
	r->out.ctr->ctr6.uptodateness_vector->cursors[0].highest_usn = r->out.ctr->ctr6.new_highwatermark.highest_usn;
	unix_to_nt_time(&now, t);
	r->out.ctr->ctr6.uptodateness_vector->cursors[0].last_sync_success = now;

	return WERR_OK;
}
