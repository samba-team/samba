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
#include "rpc_server/dcerpc_server_proto.h"
#include "../libcli/drsuapi/drsuapi.h"
#include "../libcli/security/dom_sid.h"

/* 
  drsuapi_DsGetNCChanges for one object
*/
static WERROR get_nc_changes_build_object(struct drsuapi_DsReplicaObjectListItemEx *obj,
					  struct ldb_message *msg,
					  struct ldb_context *sam_ctx,
					  struct ldb_dn *ncRoot_dn,
					  struct dsdb_schema *schema,
					  DATA_BLOB *session_key)
{
	const struct ldb_val *md_value;
	int i;
	struct ldb_dn *obj_dn;
	struct replPropertyMetaDataBlob md;
	struct dom_sid *sid;
	uint32_t rid = 0;

	if (ldb_dn_compare(ncRoot_dn, msg->dn) == 0) {
		obj->is_nc_prefix = true;
		obj->parent_object_guid = NULL;
	} else {
		obj->is_nc_prefix = false;
		obj->parent_object_guid = talloc(obj, struct GUID);
		*obj->parent_object_guid = samdb_result_guid(msg, "parentGUID");
	}
	obj->next_object = NULL;
	
	obj->meta_data_ctr = talloc(obj, struct drsuapi_DsReplicaMetaDataCtr);
	md_value = ldb_msg_find_ldb_val(msg, "replPropertyMetaData");
	if (md_value) {
		enum ndr_err_code ndr_err;
		ndr_err = ndr_pull_struct_blob(md_value, obj,
					       lp_iconv_convenience(ldb_get_opaque(sam_ctx, "loadparm")), &md,
					       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		
		if (md.version != 1) {
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		
		obj->meta_data_ctr->count = md.ctr.ctr1.count;
		obj->meta_data_ctr->meta_data = talloc_array(obj, struct drsuapi_DsReplicaMetaData, md.ctr.ctr1.count);
		for (i=0; i<md.ctr.ctr1.count; i++) {
			obj->meta_data_ctr->meta_data[i].originating_change_time = md.ctr.ctr1.array[i].originating_change_time;
			obj->meta_data_ctr->meta_data[i].version = md.ctr.ctr1.array[i].version;
			obj->meta_data_ctr->meta_data[i].originating_invocation_id = md.ctr.ctr1.array[i].originating_invocation_id;
			obj->meta_data_ctr->meta_data[i].originating_usn = md.ctr.ctr1.array[i].originating_usn;
		}
	} else {
		obj->meta_data_ctr->meta_data = talloc(obj, struct drsuapi_DsReplicaMetaData);
		obj->meta_data_ctr->count = 0;
		ZERO_STRUCT(md);
	}
	obj->object.identifier = talloc(obj, struct drsuapi_DsReplicaObjectIdentifier);
	obj_dn = ldb_msg_find_attr_as_dn(sam_ctx, obj, msg, "distinguishedName");
	obj->object.identifier->dn = ldb_dn_get_linearized(obj_dn);
	obj->object.identifier->guid = samdb_result_guid(msg, "objectGUID");
	sid = samdb_result_dom_sid(obj, msg, "objectSid");
	if (sid) {
		dom_sid_split_rid(NULL, sid, NULL, &rid);
		obj->object.identifier->sid = *sid;
	} else {
		ZERO_STRUCT(obj->object.identifier->sid);
	}

	obj->object.attribute_ctr.num_attributes = obj->meta_data_ctr->count;
	obj->object.attribute_ctr.attributes = talloc_array(obj, struct drsuapi_DsReplicaAttribute,
							    obj->object.attribute_ctr.num_attributes);

	/*
	 * Note that the meta_data array and the attributes array must
	 * be the same size and in the same order
	 */
	for (i=0; i<obj->object.attribute_ctr.num_attributes; i++) {
		const struct dsdb_attribute *sa;
		struct ldb_message_element *el;
		WERROR werr;

		sa = dsdb_attribute_by_attributeID_id(schema, md.ctr.ctr1.array[i].attid);
		if (!sa) {
			DEBUG(0,("Unable to find attributeID %u in schema\n", md.ctr.ctr1.array[i].attid));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		el = ldb_msg_find_element(msg, sa->lDAPDisplayName);
		if (el == NULL) {
			DEBUG(0,("No element '%s' for attributeID %u in message\n", 
				 sa->lDAPDisplayName, md.ctr.ctr1.array[i].attid));
			ZERO_STRUCT(obj->object.attribute_ctr.attributes[i]);
			obj->object.attribute_ctr.attributes[i].attid = md.ctr.ctr1.array[i].attid;
		} else {
			werr = dsdb_attribute_ldb_to_drsuapi(sam_ctx, schema, el, obj,
							     &obj->object.attribute_ctr.attributes[i]);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,("Unable to convert %s to DRS object - %s\n", 
					 sa->lDAPDisplayName, win_errstr(werr)));
				return werr;
			}

			/* some attributes needs to be encrypted
			   before being sent */
			werr = drsuapi_encrypt_attribute(obj, session_key, rid, 
							 &obj->object.attribute_ctr.attributes[i]);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,("Unable to encrypt %s in DRS object - %s\n", 
					 sa->lDAPDisplayName, win_errstr(werr)));
				return werr;
			}
		}
	}

	return WERR_OK;
}

/* 
  drsuapi_DsGetNCChanges
*/
WERROR dcesrv_drsuapi_DsGetNCChanges(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsGetNCChanges *r)
{
	struct ldb_result *site_res;
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot;
	struct ldb_context *sam_ctx;
	struct ldb_dn *ncRoot_dn;
	int ret;
	int i;
	struct dsdb_schema *schema;
	struct drsuapi_DsReplicaOIDMapping_Ctr *ctr;
	time_t t = time(NULL);
	NTTIME now;
	struct drsuapi_DsReplicaObjectListItemEx *currentObject;
	NTSTATUS status;
	DATA_BLOB session_key;
	const char *attrs[] = { "*", "parentGUID", NULL };

	/*
	 * connect to the samdb. TODO: We need to check that the caller
	 * has the rights to do this. This exposes all attributes,
	 * including all passwords.
	 */
	sam_ctx = samdb_connect(mem_ctx, dce_call->event_ctx, dce_call->conn->dce_ctx->lp_ctx, 
				system_session(mem_ctx, dce_call->conn->dce_ctx->lp_ctx));
	if (!sam_ctx) {
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

	DEBUG(4,("DsGetNSChanges with uSNChanged >= %llu\n", 
		 (unsigned long long)r->in.req->req8.highwatermark.highest_usn));

	/* we need the session key for encrypting password attributes */
	status = dcesrv_inherited_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": Failed to get session key\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;		
	}

	/* Construct response. */
	ncRoot_dn = ldb_dn_new(mem_ctx, sam_ctx, ncRoot->dn);
	ret = drsuapi_search_with_extended_dn(sam_ctx, mem_ctx, &site_res,
					      ncRoot_dn, LDB_SCOPE_SUBTREE, attrs,
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
	schema = dsdb_get_schema(sam_ctx);
	if (!schema) {
		DEBUG(0,("No schema in sam_ctx\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	dsdb_get_oid_mappings_drsuapi(schema, true, mem_ctx, &ctr);
	r->out.ctr->ctr6.mapping_ctr = *ctr;

	r->out.ctr->ctr6.source_dsa_guid = *(samdb_ntds_objectGUID(sam_ctx));
	r->out.ctr->ctr6.source_dsa_invocation_id = *(samdb_ntds_invocation_id(sam_ctx));

	r->out.ctr->ctr6.old_highwatermark = r->in.req->req8.highwatermark;
	r->out.ctr->ctr6.new_highwatermark = r->in.req->req8.highwatermark;

	r->out.ctr->ctr6.first_object = talloc(mem_ctx, struct drsuapi_DsReplicaObjectListItemEx);
	currentObject = r->out.ctr->ctr6.first_object;

	for(i=0; i<site_res->count; i++) {
		int uSN;
		WERROR werr;

		uSN = ldb_msg_find_attr_as_int(site_res->msgs[i], "uSNChanged", -1);
		r->out.ctr->ctr6.object_count++;
		if (uSN > r->out.ctr->ctr6.new_highwatermark.highest_usn) {
			r->out.ctr->ctr6.new_highwatermark.highest_usn = uSN;
		}

		werr = get_nc_changes_build_object(currentObject, site_res->msgs[i], sam_ctx, ncRoot_dn, 
						   schema, &session_key);
		if (!W_ERROR_IS_OK(werr)) {
			r->out.ctr->ctr6.first_object = NULL;
			return werr;
		}
		if (i == (site_res->count-1)) {
			break;
		}
		currentObject->next_object = talloc_zero(mem_ctx, struct drsuapi_DsReplicaObjectListItemEx);
		currentObject = currentObject->next_object;
	}

	r->out.ctr->ctr6.uptodateness_vector = talloc(mem_ctx, struct drsuapi_DsReplicaCursor2CtrEx);

	r->out.ctr->ctr6.uptodateness_vector->version = 2;
	r->out.ctr->ctr6.uptodateness_vector->count = 1;
	r->out.ctr->ctr6.uptodateness_vector->reserved1 = 0;
	r->out.ctr->ctr6.uptodateness_vector->reserved2 = 0;
	r->out.ctr->ctr6.uptodateness_vector->cursors = talloc(mem_ctx, struct drsuapi_DsReplicaCursor2);

	r->out.ctr->ctr6.uptodateness_vector->cursors[0].source_dsa_invocation_id = *(samdb_ntds_invocation_id(sam_ctx));
	r->out.ctr->ctr6.uptodateness_vector->cursors[0].highest_usn = r->out.ctr->ctr6.new_highwatermark.highest_usn;
	unix_to_nt_time(&now, t);
	r->out.ctr->ctr6.uptodateness_vector->cursors[0].last_sync_success = now;

	return WERR_OK;
}
