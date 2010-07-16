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
#include "rpc_server/dcerpc_server.h"
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"
#include "rpc_server/dcerpc_server_proto.h"
#include "../libcli/drsuapi/drsuapi.h"
#include "libcli/security/security.h"
#include "lib/util/binsearch.h"
#include "lib/util/tsort.h"
#include "auth/session.h"

/*
  build a DsReplicaObjectIdentifier from a ldb msg
 */
static struct drsuapi_DsReplicaObjectIdentifier *get_object_identifier(TALLOC_CTX *mem_ctx,
								       struct ldb_message *msg)
{
	struct drsuapi_DsReplicaObjectIdentifier *identifier;
	struct dom_sid *sid;

	identifier = talloc(mem_ctx, struct drsuapi_DsReplicaObjectIdentifier);
	if (identifier == NULL) {
		return NULL;
	}

	identifier->dn = ldb_dn_alloc_linearized(identifier, msg->dn);
	identifier->guid = samdb_result_guid(msg, "objectGUID");

	sid = samdb_result_dom_sid(identifier, msg, "objectSid");
	if (sid) {
		identifier->sid = *sid;
	} else {
		ZERO_STRUCT(identifier->sid);
	}
	return identifier;
}

static int udv_compare(const struct GUID *guid1, struct GUID guid2)
{
	return GUID_compare(guid1, &guid2);
}

/*
  see if we can filter an attribute using the uptodateness_vector
 */
static bool udv_filter(const struct drsuapi_DsReplicaCursorCtrEx *udv,
		       const struct GUID *originating_invocation_id,
		       uint64_t originating_usn)
{
	const struct drsuapi_DsReplicaCursor *c;
	if (udv == NULL) return false;
	BINARY_ARRAY_SEARCH(udv->cursors, udv->count, source_dsa_invocation_id, 
			    originating_invocation_id, udv_compare, c);
	if (c && originating_usn <= c->highest_usn) {
		return true;
	}
	return false;
	
}

/* 
  drsuapi_DsGetNCChanges for one object
*/
static WERROR get_nc_changes_build_object(struct drsuapi_DsReplicaObjectListItemEx *obj,
					  struct ldb_message *msg,
					  struct ldb_context *sam_ctx,
					  struct ldb_dn *ncRoot_dn,
					  struct dsdb_schema *schema,
					  DATA_BLOB *session_key,
					  uint64_t highest_usn,
					  uint32_t replica_flags,
					  struct drsuapi_DsReplicaCursorCtrEx *uptodateness_vector)
{
	const struct ldb_val *md_value;
	unsigned int i, n;
	struct replPropertyMetaDataBlob md;
	uint32_t rid = 0;
	enum ndr_err_code ndr_err;
	uint32_t *attids;
	const char *rdn;
	const struct dsdb_attribute *rdn_sa;
	unsigned int instanceType;

	instanceType = ldb_msg_find_attr_as_uint(msg, "instanceType", 0);
	if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
		obj->is_nc_prefix = true;
		obj->parent_object_guid = NULL;
	} else {
		obj->is_nc_prefix = false;
		obj->parent_object_guid = talloc(obj, struct GUID);
		if (obj->parent_object_guid == NULL) {
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
		*obj->parent_object_guid = samdb_result_guid(msg, "parentGUID");
		if (GUID_all_zero(obj->parent_object_guid)) {
			DEBUG(0,(__location__ ": missing parentGUID for %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
	}
	obj->next_object = NULL;
	
	md_value = ldb_msg_find_ldb_val(msg, "replPropertyMetaData");
	if (!md_value) {
		/* nothing to send */
		return WERR_OK;
	}

	if (instanceType & INSTANCE_TYPE_UNINSTANT) {
		/* don't send uninstantiated objects */
		return WERR_OK;
	}

	ndr_err = ndr_pull_struct_blob(md_value, obj, &md,
				       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	
	if (md.version != 1) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	rdn = ldb_dn_get_rdn_name(msg->dn);
	if (rdn == NULL) {
		DEBUG(0,(__location__ ": No rDN for %s\n", ldb_dn_get_linearized(msg->dn)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	rdn_sa = dsdb_attribute_by_lDAPDisplayName(schema, rdn);
	if (rdn_sa == NULL) {
		DEBUG(0,(__location__ ": Can't find dsds_attribute for rDN %s in %s\n", 
			 rdn, ldb_dn_get_linearized(msg->dn)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	obj->meta_data_ctr = talloc(obj, struct drsuapi_DsReplicaMetaDataCtr);
	attids = talloc_array(obj, uint32_t, md.ctr.ctr1.count);

	obj->object.identifier = get_object_identifier(obj, msg);
	if (obj->object.identifier == NULL) {
		return WERR_NOMEM;
	}
	dom_sid_split_rid(NULL, &obj->object.identifier->sid, NULL, &rid);
	
	obj->meta_data_ctr->meta_data = talloc_array(obj, struct drsuapi_DsReplicaMetaData, md.ctr.ctr1.count);
	for (n=i=0; i<md.ctr.ctr1.count; i++) {
		const struct dsdb_attribute *sa;
		/* if the attribute has not changed, and it is not the
		   instanceType then don't include it */
		if (md.ctr.ctr1.array[i].local_usn < highest_usn &&
		    md.ctr.ctr1.array[i].attid != DRSUAPI_ATTRIBUTE_instanceType) continue;

		/* don't include the rDN */
		if (md.ctr.ctr1.array[i].attid == rdn_sa->attributeID_id) continue;

		sa = dsdb_attribute_by_attributeID_id(schema, md.ctr.ctr1.array[i].attid);
		if (!sa) {
			DEBUG(0,(__location__ ": Failed to find attribute in schema for attrid %u mentioned in replPropertyMetaData of %s\n", 
				 (unsigned int)md.ctr.ctr1.array[i].attid, 
				 ldb_dn_get_linearized(msg->dn)));
			return WERR_DS_DRA_INTERNAL_ERROR;		
		}

		if (sa->linkID) {
			struct ldb_message_element *el;
			el = ldb_msg_find_element(msg, sa->lDAPDisplayName);
			if (el && el->num_values && dsdb_dn_is_upgraded_link_val(&el->values[0])) {
				/* don't send upgraded links inline */
				continue;
			}
		}

		/* filter by uptodateness_vector */
		if (md.ctr.ctr1.array[i].attid != DRSUAPI_ATTRIBUTE_instanceType &&
		    udv_filter(uptodateness_vector,
			       &md.ctr.ctr1.array[i].originating_invocation_id, 
			       md.ctr.ctr1.array[i].originating_usn)) {
			continue;
		}

		/*
		 * If the recipient is a RODC, then we should not add any
		 * RODC filtered attribute
		 *
		 * TODO: This is not strictly correct, as it doesn't allow for administrators
		 * to setup some users to transfer passwords to specific RODCs. To support that
		 * we would instead remove this check and rely on extended ACL checking in the dsdb
		 * acl module.
		 */
		if (dsdb_attr_in_rodc_fas(replica_flags, sa)) {
			continue;
		}

		obj->meta_data_ctr->meta_data[n].originating_change_time = md.ctr.ctr1.array[i].originating_change_time;
		obj->meta_data_ctr->meta_data[n].version = md.ctr.ctr1.array[i].version;
		obj->meta_data_ctr->meta_data[n].originating_invocation_id = md.ctr.ctr1.array[i].originating_invocation_id;
		obj->meta_data_ctr->meta_data[n].originating_usn = md.ctr.ctr1.array[i].originating_usn;
		attids[n] = md.ctr.ctr1.array[i].attid;
		n++;
	}

	/* ignore it if its an empty change. Note that renames always
	 * change the 'name' attribute, so they won't be ignored by
	 * this */
	if (n == 0 ||
	    (n == 1 && attids[0] == DRSUAPI_ATTRIBUTE_instanceType)) {
		talloc_free(obj->meta_data_ctr);
		obj->meta_data_ctr = NULL;
		return WERR_OK;
	}

	obj->meta_data_ctr->count = n;

	obj->object.flags = DRSUAPI_DS_REPLICA_OBJECT_FROM_MASTER;
	obj->object.attribute_ctr.num_attributes = obj->meta_data_ctr->count;
	obj->object.attribute_ctr.attributes = talloc_array(obj, struct drsuapi_DsReplicaAttribute,
							    obj->object.attribute_ctr.num_attributes);

	/*
	 * Note that the meta_data array and the attributes array must
	 * be the same size and in the same order
	 */
	for (i=0; i<obj->object.attribute_ctr.num_attributes; i++) {
		struct ldb_message_element *el;
		WERROR werr;
		const struct dsdb_attribute *sa;
	
		sa = dsdb_attribute_by_attributeID_id(schema, attids[i]);
		if (!sa) {
			DEBUG(0,("Unable to find attributeID %u in schema\n", attids[i]));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		el = ldb_msg_find_element(msg, sa->lDAPDisplayName);
		if (el == NULL) {
			/* this happens for attributes that have been removed */
			DEBUG(5,("No element '%s' for attributeID %u in message\n",
				 sa->lDAPDisplayName, attids[i]));
			ZERO_STRUCT(obj->object.attribute_ctr.attributes[i]);
			obj->object.attribute_ctr.attributes[i].attid = attids[i];
		} else {
			werr = dsdb_attribute_ldb_to_drsuapi(sam_ctx, schema, el, obj,
							     &obj->object.attribute_ctr.attributes[i]);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,("Unable to convert %s to DRS object - %s\n", 
					 sa->lDAPDisplayName, win_errstr(werr)));
				return werr;
			}
			/* if DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING is set
			 * check if attribute is secret and send a null value
			 */
			if (replica_flags & DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING) {
				drsuapi_process_secret_attribute(&obj->object.attribute_ctr.attributes[i],
								 &obj->meta_data_ctr->meta_data[i]);
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
  add one linked attribute from an object to the list of linked
  attributes in a getncchanges request
 */
static WERROR get_nc_changes_add_la(TALLOC_CTX *mem_ctx,
				    struct ldb_context *sam_ctx,
				    const struct dsdb_schema *schema,
				    const struct dsdb_attribute *sa,
				    struct ldb_message *msg,
				    struct dsdb_dn *dsdb_dn,
				    struct drsuapi_DsReplicaLinkedAttribute **la_list,
				    uint32_t *la_count)
{
	struct drsuapi_DsReplicaLinkedAttribute *la;
	bool active;
	NTSTATUS status;
	WERROR werr;

	(*la_list) = talloc_realloc(mem_ctx, *la_list, struct drsuapi_DsReplicaLinkedAttribute, (*la_count)+1);
	W_ERROR_HAVE_NO_MEMORY(*la_list);

	la = &(*la_list)[*la_count];

	la->identifier = get_object_identifier(*la_list, msg);
	W_ERROR_HAVE_NO_MEMORY(la->identifier);

	active = (dsdb_dn_rmd_flags(dsdb_dn->dn) & DSDB_RMD_FLAG_DELETED) == 0;

	la->attid = sa->attributeID_id;
	la->flags = active?DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE:0;

	status = dsdb_get_extended_dn_nttime(dsdb_dn->dn, &la->originating_add_time, "RMD_ADDTIME");
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_uint32(dsdb_dn->dn, &la->meta_data.version, "RMD_VERSION");
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_nttime(dsdb_dn->dn, &la->meta_data.originating_change_time, "RMD_CHANGETIME");
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_guid(dsdb_dn->dn, &la->meta_data.originating_invocation_id, "RMD_INVOCID");
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_uint64(dsdb_dn->dn, &la->meta_data.originating_usn, "RMD_ORIGINATING_USN");
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	werr = dsdb_dn_la_to_blob(sam_ctx, sa, schema, *la_list, dsdb_dn, &la->value.blob);
	W_ERROR_NOT_OK_RETURN(werr);

	(*la_count)++;
	return WERR_OK;
}


/*
  add linked attributes from an object to the list of linked
  attributes in a getncchanges request
 */
static WERROR get_nc_changes_add_links(struct ldb_context *sam_ctx,
				       TALLOC_CTX *mem_ctx,
				       struct ldb_dn *ncRoot_dn,
				       struct dsdb_schema *schema,
				       uint64_t highest_usn,
				       uint32_t replica_flags,
				       struct ldb_message *msg,
				       struct drsuapi_DsReplicaLinkedAttribute **la_list,
				       uint32_t *la_count,
				       struct drsuapi_DsReplicaCursorCtrEx *uptodateness_vector)
{
	unsigned int i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	uint64_t uSNChanged = ldb_msg_find_attr_as_int(msg, "uSNChanged", -1);

	for (i=0; i<msg->num_elements; i++) {
		struct ldb_message_element *el = &msg->elements[i];
		const struct dsdb_attribute *sa;
		unsigned int j;

		sa = dsdb_attribute_by_lDAPDisplayName(schema, el->name);

		if (!sa || sa->linkID == 0 || (sa->linkID & 1)) {
			/* we only want forward links */
			continue;
		}

		if (el->num_values && !dsdb_dn_is_upgraded_link_val(&el->values[0])) {
			/* its an old style link, it will have been
			 * sent in the main replication data */
			continue;
		}

		for (j=0; j<el->num_values; j++) {
			struct dsdb_dn *dsdb_dn;
			uint64_t local_usn;
			NTSTATUS status;
			WERROR werr;

			dsdb_dn = dsdb_dn_parse(tmp_ctx, sam_ctx, &el->values[j], sa->syntax->ldap_oid);
			if (dsdb_dn == NULL) {
				DEBUG(1,(__location__ ": Failed to parse DN for %s in %s\n",
					 el->name, ldb_dn_get_linearized(msg->dn)));
				talloc_free(tmp_ctx);
				return WERR_DS_DRA_INTERNAL_ERROR;
			}

			status = dsdb_get_extended_dn_uint64(dsdb_dn->dn, &local_usn, "RMD_LOCAL_USN");
			if (!NT_STATUS_IS_OK(status)) {
				/* this can happen for attributes
				   given to us with old style meta
				   data */
				continue;
			}

			if (local_usn > uSNChanged) {
				DEBUG(1,(__location__ ": uSNChanged less than RMD_LOCAL_USN for %s on %s\n",
					 el->name, ldb_dn_get_linearized(msg->dn)));
				talloc_free(tmp_ctx);
				return WERR_DS_DRA_INTERNAL_ERROR;
			}

			if (local_usn < highest_usn) {
				continue;
			}

			werr = get_nc_changes_add_la(mem_ctx, sam_ctx, schema, sa, msg,
						     dsdb_dn, la_list, la_count);
			if (!W_ERROR_IS_OK(werr)) {
				talloc_free(tmp_ctx);
				return werr;
			}
		}
	}

	talloc_free(tmp_ctx);
	return WERR_OK;
}

/*
  fill in the cursors return based on the replUpToDateVector for the ncRoot_dn
 */
static WERROR get_nc_changes_udv(struct ldb_context *sam_ctx,
				 struct ldb_dn *ncRoot_dn,
				 struct drsuapi_DsReplicaCursor2CtrEx *udv)
{
	int ret;

	udv->version = 2;
	udv->reserved1 = 0;
	udv->reserved2 = 0;

	ret = dsdb_load_udv_v2(sam_ctx, ncRoot_dn, udv, &udv->cursors, &udv->count);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to load UDV for %s - %s\n",
			 ldb_dn_get_linearized(ncRoot_dn), ldb_errstring(sam_ctx)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	
	return WERR_OK;
}


/* comparison function for linked attributes - see CompareLinks() in
 * MS-DRSR section 4.1.10.5.17 */
static int linked_attribute_compare(const struct drsuapi_DsReplicaLinkedAttribute *la1,
				    const struct drsuapi_DsReplicaLinkedAttribute *la2,
				    struct ldb_context *sam_ctx)
{
	int c;
	WERROR werr;
	TALLOC_CTX *tmp_ctx;
	const struct dsdb_schema *schema;
	const struct dsdb_attribute *schema_attrib;
	struct dsdb_dn *dn1, *dn2;
	struct GUID guid1, guid2;
	NTSTATUS status;

	c = GUID_compare(&la1->identifier->guid,
			 &la2->identifier->guid);
	if (c != 0) return c;

	if (la1->attid != la2->attid) {
		return la1->attid < la2->attid? -1:1;
	}

	if ((la1->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE) !=
	    (la2->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE)) {
		return (la1->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE)? 1:-1;
	}

	/* we need to get the target GUIDs to compare */
	tmp_ctx = talloc_new(sam_ctx);

	schema = dsdb_get_schema(sam_ctx, tmp_ctx);
	schema_attrib = dsdb_attribute_by_attributeID_id(schema, la1->attid);

	werr = dsdb_dn_la_from_blob(sam_ctx, schema_attrib, schema, tmp_ctx, la1->value.blob, &dn1);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,(__location__ ": Bad la1 blob in sort\n"));
		talloc_free(tmp_ctx);
		return 0;
	}

	werr = dsdb_dn_la_from_blob(sam_ctx, schema_attrib, schema, tmp_ctx, la2->value.blob, &dn2);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,(__location__ ": Bad la2 blob in sort\n"));
		talloc_free(tmp_ctx);
		return 0;
	}

	status = dsdb_get_extended_dn_guid(dn1->dn, &guid1, "GUID");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": Bad la1 guid in sort\n"));
		talloc_free(tmp_ctx);
		return 0;
	}
	status = dsdb_get_extended_dn_guid(dn2->dn, &guid2, "GUID");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": Bad la2 guid in sort\n"));
		talloc_free(tmp_ctx);
		return 0;
	}

	talloc_free(tmp_ctx);

	return GUID_compare(&guid1, &guid2);
}


/*
  sort the objects we send by tree order
 */
static int site_res_cmp_parent_order(struct ldb_message **m1, struct ldb_message **m2)
{
	return ldb_dn_compare((*m2)->dn, (*m1)->dn);
}

/*
  sort the objects we send first by uSNChanged
 */
static int site_res_cmp_usn_order(struct ldb_message **m1, struct ldb_message **m2)
{
	unsigned usnchanged1, usnchanged2;
	unsigned cn1, cn2;
	cn1 = ldb_dn_get_comp_num((*m1)->dn);
	cn2 = ldb_dn_get_comp_num((*m2)->dn);
	if (cn1 != cn2) {
		return cn1 > cn2 ? 1 : -1;
	}
	usnchanged1 = ldb_msg_find_attr_as_uint(*m1, "uSNChanged", 0);
	usnchanged2 = ldb_msg_find_attr_as_uint(*m2, "uSNChanged", 0);
	if (usnchanged1 == usnchanged2) {
		return 0;
	}
	return usnchanged1 > usnchanged2 ? 1 : -1;
}


/*
  handle a DRSUAPI_EXOP_FSMO_RID_ALLOC call
 */
static WERROR getncchanges_rid_alloc(struct drsuapi_bind_state *b_state,
				     TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsGetNCChangesRequest8 *req8,
				     struct drsuapi_DsGetNCChangesCtr6 *ctr6)
{
	struct ldb_dn *rid_manager_dn, *fsmo_role_dn, *req_dn;
	int ret;
	struct ldb_context *ldb = b_state->sam_ctx;
	struct ldb_result *ext_res;
	struct ldb_dn *base_dn;
	struct dsdb_fsmo_extended_op *exop;

	/*
	  steps:
	    - verify that the DN being asked for is the RID Manager DN
	    - verify that we are the RID Manager
	 */

	/* work out who is the RID Manager */
	ret = samdb_rid_manager_dn(ldb, mem_ctx, &rid_manager_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, (__location__ ": Failed to find RID Manager object - %s\n", ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	req_dn = ldb_dn_new(mem_ctx, ldb, req8->naming_context->dn);
	if (!req_dn ||
	    !ldb_dn_validate(req_dn) ||
	    ldb_dn_compare(req_dn, rid_manager_dn) != 0) {
		/* that isn't the RID Manager DN */
		DEBUG(0,(__location__ ": RID Alloc request for wrong DN %s\n",
			 req8->naming_context->dn));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_MISMATCH;
		return WERR_OK;
	}

	/* find the DN of the RID Manager */
	ret = samdb_reference_dn(ldb, mem_ctx, rid_manager_dn, "fSMORoleOwner", &fsmo_role_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to find fSMORoleOwner in RID Manager object - %s\n",
			 ldb_errstring(ldb)));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if (ldb_dn_compare(samdb_ntds_settings_dn(ldb), fsmo_role_dn) != 0) {
		/* we're not the RID Manager - go away */
		DEBUG(0,(__location__ ": RID Alloc request when not RID Manager\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_OK;
	}

	exop = talloc(mem_ctx, struct dsdb_fsmo_extended_op);
	W_ERROR_HAVE_NO_MEMORY(exop);

	exop->fsmo_info = req8->fsmo_info;
	exop->destination_dsa_guid = req8->destination_dsa_guid;

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed transaction start - %s\n",
			 ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	ret = ldb_extended(ldb, DSDB_EXTENDED_ALLOCATE_RID_POOL, exop, &ext_res);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed extended allocation RID pool operation - %s\n",
			 ldb_errstring(ldb)));
		ldb_transaction_cancel(ldb);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed transaction commit - %s\n",
			 ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	talloc_free(ext_res);

	base_dn = ldb_get_default_basedn(ldb);

	DEBUG(2,("Allocated RID pool for server %s\n",
		 GUID_string(mem_ctx, &req8->destination_dsa_guid)));

	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;

	return WERR_OK;
}



/* state of a partially completed getncchanges call */
struct drsuapi_getncchanges_state {
	struct ldb_result *site_res;
	uint32_t num_sent;
	struct ldb_dn *ncRoot_dn;
	uint64_t min_usn;
	uint64_t highest_usn;
	struct ldb_dn *last_dn;
	struct drsuapi_DsReplicaLinkedAttribute *la_list;
	uint32_t la_count;
	bool la_sorted;
	uint32_t la_idx;
	struct drsuapi_DsReplicaCursorCtrEx *uptodateness_vector;
};

/* 
  drsuapi_DsGetNCChanges

  see MS-DRSR 4.1.10.5.2 for basic logic of this function
*/
WERROR dcesrv_drsuapi_DsGetNCChanges(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsGetNCChanges *r)
{
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot;
	int ret;
	unsigned int i;
	struct dsdb_schema *schema;
	struct drsuapi_DsReplicaOIDMapping_Ctr *ctr;
	struct drsuapi_DsReplicaObjectListItemEx **currentObject;
	NTSTATUS status;
	DATA_BLOB session_key;
	const char *attrs[] = { "*", "distinguishedName",
				"nTSecurityDescriptor",
				"parentGUID",
				"replPropertyMetaData",
				"unicodePwd",
				"dBCSPwd",
				"ntPwdHistory",
				"lmPwdHistory",
				"supplementalCredentials",
				NULL };
	WERROR werr;
	struct dcesrv_handle *h;
	struct drsuapi_bind_state *b_state;	
	struct drsuapi_getncchanges_state *getnc_state;
	struct drsuapi_DsGetNCChangesRequest8 *req8;
	uint32_t options;
	uint32_t max_objects;
	uint32_t max_links;
	uint32_t link_count = 0;
	uint32_t link_total = 0;
	uint32_t link_given = 0;
	struct ldb_dn *search_dn = NULL;
	bool am_rodc;
	enum security_user_level security_level;

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	*r->out.level_out = 6;
	/* TODO: linked attributes*/
	r->out.ctr->ctr6.linked_attributes_count = 0;
	r->out.ctr->ctr6.linked_attributes = NULL;

	r->out.ctr->ctr6.object_count = 0;
	r->out.ctr->ctr6.nc_object_count = 0;
	r->out.ctr->ctr6.more_data = false;
	r->out.ctr->ctr6.uptodateness_vector = NULL;

	/* a RODC doesn't allow for any replication */
	ret = samdb_rodc(b_state->sam_ctx, &am_rodc);
	if (ret == LDB_SUCCESS && am_rodc) {
		DEBUG(0,(__location__ ": DsGetNCChanges attempt on RODC\n"));
		return WERR_DS_DRA_SOURCE_DISABLED;
	}

	/* Check request revision. 
	   TODO: Adding mappings to req8 from the other levels
	 */
	if (r->in.level != 8) {
		DEBUG(0,(__location__ ": Request for DsGetNCChanges with unsupported level %u\n",
			 r->in.level));
		return WERR_REVISION_MISMATCH;
	}

	req8 = &r->in.req->req8;

        /* Perform access checks. */
	/* TODO: we need to support a sync on a specific non-root
	 * DN. We'll need to find the real partition root here */
	ncRoot = req8->naming_context;
	if (ncRoot == NULL) {
		DEBUG(0,(__location__ ": Request for DsGetNCChanges with no NC\n"));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	if (samdb_ntds_options(b_state->sam_ctx, &options) != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}
	
	if ((options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) &&
	    !(req8->replica_flags & DRSUAPI_DRS_SYNC_FORCED)) {
		return WERR_DS_DRA_SOURCE_DISABLED;
	}

	werr = drs_security_level_check(dce_call, "DsGetNCChanges", SECURITY_RO_DOMAIN_CONTROLLER);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	/* for non-administrator replications, check that they have
	   given the correct source_dsa_invocation_id */
	security_level = security_session_user_level(dce_call->conn->auth_state.session_info,
						     samdb_domain_sid(b_state->sam_ctx));
	if (security_level == SECURITY_RO_DOMAIN_CONTROLLER &&
	    (req8->replica_flags & DRSUAPI_DRS_WRIT_REP)) {
		DEBUG(0,(__location__ ": Attempt to do writeable replication by RODC %s\n",
			 dom_sid_string(mem_ctx,
					dce_call->conn->auth_state.session_info->security_token->user_sid)));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}


	if (req8->replica_flags & DRSUAPI_DRS_FULL_SYNC_PACKET) {
		/* Ignore the _in_ uptpdateness vector*/
		req8->uptodateness_vector = NULL;
	} 

	/* we don't yet support extended operations */
	switch (req8->extended_op) {
	case DRSUAPI_EXOP_NONE:
		break;

	case DRSUAPI_EXOP_FSMO_RID_ALLOC:
		werr = getncchanges_rid_alloc(b_state, mem_ctx, req8, &r->out.ctr->ctr6);
		W_ERROR_NOT_OK_RETURN(werr);
		search_dn = ldb_get_default_basedn(b_state->sam_ctx);
		break;

	case DRSUAPI_EXOP_FSMO_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_RID_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_REQ_PDC:
	case DRSUAPI_EXOP_FSMO_ABANDON_ROLE:
	case DRSUAPI_EXOP_REPL_OBJ:
	case DRSUAPI_EXOP_REPL_SECRET:
		DEBUG(0,(__location__ ": Request for DsGetNCChanges unsupported extended op 0x%x\n",
			 (unsigned)req8->extended_op));
		return WERR_DS_DRA_NOT_SUPPORTED;
	}

	getnc_state = b_state->getncchanges_state;

	/* see if a previous replication has been abandoned */
	if (getnc_state) {
		struct ldb_dn *new_dn = ldb_dn_new(getnc_state, b_state->sam_ctx, ncRoot->dn);
		if (ldb_dn_compare(new_dn, getnc_state->ncRoot_dn) != 0) {
			DEBUG(0,(__location__ ": DsGetNCChanges 2nd replication on different DN %s %s (last_dn %s)\n",
				 ldb_dn_get_linearized(new_dn),
				 ldb_dn_get_linearized(getnc_state->ncRoot_dn),
				 ldb_dn_get_linearized(getnc_state->last_dn)));
			talloc_free(getnc_state);
			getnc_state = NULL;
		}
	}

	if (getnc_state == NULL) {
		getnc_state = talloc_zero(b_state, struct drsuapi_getncchanges_state);
		if (getnc_state == NULL) {
			return WERR_NOMEM;
		}
		b_state->getncchanges_state = getnc_state;
		getnc_state->ncRoot_dn = ldb_dn_new(getnc_state, b_state->sam_ctx, ncRoot->dn);
	}

	if (!ldb_dn_validate(getnc_state->ncRoot_dn) ||
	    ldb_dn_is_null(getnc_state->ncRoot_dn)) {
		DEBUG(0,(__location__ ": Bad DN '%s'\n", ncRoot->dn));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	/* we need the session key for encrypting password attributes */
	status = dcesrv_inherited_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": Failed to get session key\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;		
	}

	/* 
	   TODO: MS-DRSR section 4.1.10.1.1
	   Work out if this is the start of a new cycle */

	if (getnc_state->site_res == NULL) {
		char* search_filter;
		enum ldb_scope scope = LDB_SCOPE_SUBTREE;
		const char *extra_filter;

		extra_filter = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "object filter");

		getnc_state->min_usn = req8->highwatermark.highest_usn;

		/* Construct response. */
		search_filter = talloc_asprintf(mem_ctx,
						"(uSNChanged>=%llu)",
						(unsigned long long)(getnc_state->min_usn+1));
	
		if (extra_filter) {
			search_filter = talloc_asprintf(mem_ctx, "(&%s(%s))", search_filter, extra_filter);
		}

		if (req8->replica_flags & DRSUAPI_DRS_CRITICAL_ONLY) {
			search_filter = talloc_asprintf(mem_ctx,
							"(&%s(isCriticalSystemObject=TRUE))",
							search_filter);
		}
		
		if (req8->replica_flags & DRSUAPI_DRS_ASYNC_REP) {
			scope = LDB_SCOPE_BASE;
		}
		
		if (!search_dn) {
			search_dn = getnc_state->ncRoot_dn;
		}

		DEBUG(1,(__location__ ": getncchanges on %s using filter %s\n",
			 ldb_dn_get_linearized(getnc_state->ncRoot_dn), search_filter));
		ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, getnc_state, &getnc_state->site_res,
						      search_dn, scope, attrs,
						      search_filter);
		if (ret != LDB_SUCCESS) {
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if (req8->replica_flags & DRSUAPI_DRS_GET_ANC) {
			TYPESAFE_QSORT(getnc_state->site_res->msgs,
				       getnc_state->site_res->count,
				       site_res_cmp_parent_order);
		} else {
			TYPESAFE_QSORT(getnc_state->site_res->msgs,
				       getnc_state->site_res->count,
				       site_res_cmp_usn_order);
		}

		getnc_state->uptodateness_vector = talloc_steal(getnc_state, req8->uptodateness_vector);
		if (getnc_state->uptodateness_vector) {
			/* make sure its sorted */
			TYPESAFE_QSORT(getnc_state->uptodateness_vector->cursors,
				       getnc_state->uptodateness_vector->count,
				       drsuapi_DsReplicaCursor_compare);
		}
	}

	/* Prefix mapping */
	schema = dsdb_get_schema(b_state->sam_ctx, mem_ctx);
	if (!schema) {
		DEBUG(0,("No schema in sam_ctx\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	r->out.ctr->ctr6.naming_context = talloc(mem_ctx, struct drsuapi_DsReplicaObjectIdentifier);
	*r->out.ctr->ctr6.naming_context = *ncRoot;

	if (dsdb_find_guid_by_dn(b_state->sam_ctx, getnc_state->ncRoot_dn, 
				 &r->out.ctr->ctr6.naming_context->guid) != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to find GUID of ncRoot_dn %s\n",
			 ldb_dn_get_linearized(getnc_state->ncRoot_dn)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	/* find the SID if there is one */
	dsdb_find_sid_by_dn(b_state->sam_ctx, getnc_state->ncRoot_dn, &r->out.ctr->ctr6.naming_context->sid);

	dsdb_get_oid_mappings_drsuapi(schema, true, mem_ctx, &ctr);
	r->out.ctr->ctr6.mapping_ctr = *ctr;

	r->out.ctr->ctr6.source_dsa_guid = *(samdb_ntds_objectGUID(b_state->sam_ctx));
	r->out.ctr->ctr6.source_dsa_invocation_id = *(samdb_ntds_invocation_id(b_state->sam_ctx));

	r->out.ctr->ctr6.old_highwatermark = req8->highwatermark;
	r->out.ctr->ctr6.new_highwatermark = req8->highwatermark;

	r->out.ctr->ctr6.first_object = NULL;
	currentObject = &r->out.ctr->ctr6.first_object;

	/* use this to force single objects at a time, which is useful
	 * for working out what object is giving problems
	 */
	max_objects = lpcfg_parm_int(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "max object sync", 1000);
	if (req8->max_object_count < max_objects) {
		max_objects = req8->max_object_count;
	}
	/*
	 * TODO: work out how the maximum should be calculated
	 */
	max_links = lpcfg_parm_int(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "max link sync", 1500);

	for(i=getnc_state->num_sent; 
	    i<getnc_state->site_res->count && 
		    (r->out.ctr->ctr6.object_count < max_objects);
	    i++) {
		int uSN;
		struct drsuapi_DsReplicaObjectListItemEx *obj;
		struct ldb_message *msg = getnc_state->site_res->msgs[i];

		obj = talloc_zero(mem_ctx, struct drsuapi_DsReplicaObjectListItemEx);

		werr = get_nc_changes_build_object(obj, msg,
						   b_state->sam_ctx, getnc_state->ncRoot_dn, 
						   schema, &session_key, getnc_state->min_usn,
						   req8->replica_flags, getnc_state->uptodateness_vector);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		werr = get_nc_changes_add_links(b_state->sam_ctx, getnc_state,
						getnc_state->ncRoot_dn,
						schema, getnc_state->min_usn,
						req8->replica_flags,
						msg,
						&getnc_state->la_list,
						&getnc_state->la_count,
						getnc_state->uptodateness_vector);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		uSN = ldb_msg_find_attr_as_int(msg, "uSNChanged", -1);
		if (uSN > r->out.ctr->ctr6.new_highwatermark.tmp_highest_usn) {
			r->out.ctr->ctr6.new_highwatermark.tmp_highest_usn = uSN;
		}
		if (uSN > getnc_state->highest_usn) {
			getnc_state->highest_usn = uSN;
		}

		if (obj->meta_data_ctr == NULL) {
			DEBUG(8,(__location__ ": getncchanges skipping send of object %s\n",
				 ldb_dn_get_linearized(msg->dn)));
			/* no attributes to send */
			talloc_free(obj);
			continue;
		}

		r->out.ctr->ctr6.object_count++;
		
		*currentObject = obj;
		currentObject = &obj->next_object;

		talloc_free(getnc_state->last_dn);
		getnc_state->last_dn = ldb_dn_copy(getnc_state, msg->dn);

		DEBUG(8,(__location__ ": replicating object %s\n", ldb_dn_get_linearized(msg->dn)));
	}

	getnc_state->num_sent += r->out.ctr->ctr6.object_count;

	r->out.ctr->ctr6.nc_object_count = getnc_state->site_res->count;

	/* the client can us to call UpdateRefs on its behalf to
	   re-establish monitoring of the NC */
	if ((req8->replica_flags & (DRSUAPI_DRS_ADD_REF | DRSUAPI_DRS_REF_GCSPN)) &&
	    !GUID_all_zero(&req8->destination_dsa_guid)) {
		struct drsuapi_DsReplicaUpdateRefsRequest1 ureq;
		DEBUG(3,("UpdateRefs on getncchanges for %s\n",
			 GUID_string(mem_ctx, &req8->destination_dsa_guid)));
		ureq.naming_context = ncRoot;
		ureq.dest_dsa_dns_name = talloc_asprintf(mem_ctx, "%s._msdcs.%s",
							 GUID_string(mem_ctx, &req8->destination_dsa_guid),
							 lpcfg_realm(dce_call->conn->dce_ctx->lp_ctx));
		if (!ureq.dest_dsa_dns_name) {
			return WERR_NOMEM;
		}
		ureq.dest_dsa_guid = req8->destination_dsa_guid;
		ureq.options = DRSUAPI_DRS_ADD_REF |
			DRSUAPI_DRS_ASYNC_OP |
			DRSUAPI_DRS_GETCHG_CHECK;
		werr = drsuapi_UpdateRefs(b_state, mem_ctx, &ureq);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__ ": Failed UpdateRefs in DsGetNCChanges - %s\n",
				 win_errstr(werr)));
		}
	}

	/*
	 * TODO:
	 * This is just a guess, how to calculate the
	 * number of linked attributes to send, we need to
	 * find out how to do this right.
	 */
	if (r->out.ctr->ctr6.object_count >= max_links) {
		max_links = 0;
	} else {
		max_links -= r->out.ctr->ctr6.object_count;
	}

	link_total = getnc_state->la_count;

	if (i < getnc_state->site_res->count) {
		r->out.ctr->ctr6.more_data = true;
	} else {
		/* sort the whole array the first time */
		if (!getnc_state->la_sorted) {
			LDB_TYPESAFE_QSORT(getnc_state->la_list, getnc_state->la_count,
					   b_state->sam_ctx, linked_attribute_compare);
			getnc_state->la_sorted = true;
		}

		link_count = getnc_state->la_count - getnc_state->la_idx;
		link_count = MIN(max_links, link_count);

		r->out.ctr->ctr6.linked_attributes_count = link_count;
		r->out.ctr->ctr6.linked_attributes = getnc_state->la_list + getnc_state->la_idx;

		getnc_state->la_idx += link_count;
		link_given = getnc_state->la_idx;

		if (getnc_state->la_idx < getnc_state->la_count) {
			r->out.ctr->ctr6.more_data = true;
		}
	}

	if (!r->out.ctr->ctr6.more_data) {
		talloc_steal(mem_ctx, getnc_state->la_list);

		r->out.ctr->ctr6.uptodateness_vector = talloc(mem_ctx, struct drsuapi_DsReplicaCursor2CtrEx);
		r->out.ctr->ctr6.new_highwatermark.highest_usn = r->out.ctr->ctr6.new_highwatermark.tmp_highest_usn;

		werr = get_nc_changes_udv(b_state->sam_ctx, getnc_state->ncRoot_dn, 
					  r->out.ctr->ctr6.uptodateness_vector);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		talloc_free(getnc_state);
		b_state->getncchanges_state = NULL;
	}

	if (req8->extended_op != DRSUAPI_EXOP_NONE) {
		r->out.ctr->ctr6.uptodateness_vector = NULL;
		r->out.ctr->ctr6.nc_object_count = 0;
		ZERO_STRUCT(r->out.ctr->ctr6.new_highwatermark);
	}

	DEBUG(r->out.ctr->ctr6.more_data?2:1,
	      ("DsGetNCChanges with uSNChanged >= %llu flags 0x%08x on %s gave %u objects (done %u/%u) %u links (done %u/%u)\n",
	       (unsigned long long)(req8->highwatermark.highest_usn+1),
	       req8->replica_flags, ncRoot->dn,
	       r->out.ctr->ctr6.object_count,
	       i, r->out.ctr->ctr6.more_data?getnc_state->site_res->count:i,
	       r->out.ctr->ctr6.linked_attributes_count,
	       link_given, link_total));

#if 0
	if (!r->out.ctr->ctr6.more_data) {
		NDR_PRINT_FUNCTION_DEBUG(drsuapi_DsGetNCChanges, NDR_BOTH, r);
	}
#endif

	return WERR_OK;
}
