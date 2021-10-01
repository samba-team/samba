/* 
   Unix SMB/CIFS implementation.

   implement the DSGetNCChanges call

   Copyright (C) Anatoliy Atanasov 2009
   Copyright (C) Andrew Tridgell 2009-2010
   Copyright (C) Andrew Bartlett 2010-2016

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
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "libcli/security/session.h"
#include "rpc_server/drsuapi/dcesrv_drsuapi.h"
#include "../libcli/drsuapi/drsuapi.h"
#include "lib/util/binsearch.h"
#include "lib/util/tsort.h"
#include "auth/session.h"
#include "dsdb/common/util.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "librpc/gen_ndr/ndr_misc.h"

#undef DBGC_CLASS
#define DBGC_CLASS            DBGC_DRS_REPL

#define DRS_GUID_SIZE       16
#define DEFAULT_MAX_OBJECTS 1000
#define DEFAULT_MAX_LINKS   1500

/*
 * state of a partially-completed replication cycle. This state persists
 * over multiple calls to dcesrv_drsuapi_DsGetNCChanges()
 */
struct drsuapi_getncchanges_state {
	struct db_context *obj_cache;
	struct GUID *guids;
	uint32_t num_records;
	uint32_t num_processed;
	struct ldb_dn *ncRoot_dn;
	struct GUID ncRoot_guid;
	bool is_schema_nc;
	bool is_get_anc;
	bool is_get_tgt;
	uint64_t min_usn;
	uint64_t max_usn;
	struct drsuapi_DsReplicaHighWaterMark last_hwm;
	struct ldb_dn *last_dn;
	struct drsuapi_DsReplicaHighWaterMark final_hwm;
	struct drsuapi_DsReplicaCursor2CtrEx *final_udv;
	struct drsuapi_DsReplicaLinkedAttribute *la_list;
	uint32_t la_count;
	uint32_t la_idx;

	/* these are just used for debugging the replication's progress */
	uint32_t links_given;
	uint32_t total_links;
};

/* We must keep the GUIDs in NDR form for sorting */
struct la_for_sorting {
	const struct drsuapi_DsReplicaLinkedAttribute *link;
	uint8_t target_guid[DRS_GUID_SIZE];
	uint8_t source_guid[DRS_GUID_SIZE];
};

/*
 * stores the state for a chunk of replication data. This state information
 * only exists for a single call to dcesrv_drsuapi_DsGetNCChanges()
 */
struct getncchanges_repl_chunk {
	uint32_t max_objects;
	uint32_t max_links;
	uint32_t tgt_la_count;
	bool immediate_link_sync;
	time_t max_wait;
	time_t start;

	/* stores the objects to be sent in this chunk */
	uint32_t object_count;
	struct drsuapi_DsReplicaObjectListItemEx *object_list;

	/* the last object added to this replication chunk */
	struct drsuapi_DsReplicaObjectListItemEx *last_object;
};

static int drsuapi_DsReplicaHighWaterMark_cmp(const struct drsuapi_DsReplicaHighWaterMark *h1,
					      const struct drsuapi_DsReplicaHighWaterMark *h2)
{
	if (h1->highest_usn < h2->highest_usn) {
		return -1;
	} else if (h1->highest_usn > h2->highest_usn) {
		return 1;
	} else if (h1->tmp_highest_usn < h2->tmp_highest_usn) {
		return -1;
	} else if (h1->tmp_highest_usn > h2->tmp_highest_usn) {
		return 1;
	} else if (h1->reserved_usn < h2->reserved_usn) {
		return -1;
	} else if (h1->reserved_usn > h2->reserved_usn) {
		return 1;
	}

	return 0;
}

/*
  build a DsReplicaObjectIdentifier from a ldb msg
 */
static struct drsuapi_DsReplicaObjectIdentifier *get_object_identifier(TALLOC_CTX *mem_ctx,
								       const struct ldb_message *msg)
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

static int uint32_t_cmp(uint32_t a1, uint32_t a2)
{
	if (a1 == a2) return 0;
	return a1 > a2 ? 1 : -1;
}

static int uint32_t_ptr_cmp(uint32_t *a1, uint32_t *a2)
{
	if (*a1 == *a2) return 0;
	return *a1 > *a2 ? 1 : -1;
}

static WERROR getncchanges_attid_remote_to_local(const struct dsdb_schema *schema,
						 const struct dsdb_syntax_ctx *ctx,
						 enum drsuapi_DsAttributeId remote_attid_as_enum,
						 enum drsuapi_DsAttributeId *local_attid_as_enum,
						 const struct dsdb_attribute **_sa)
{
	WERROR werr;
	const struct dsdb_attribute *sa = NULL;

	if (ctx->pfm_remote == NULL) {
		DEBUG(7, ("No prefixMap supplied, falling back to local prefixMap.\n"));
		goto fail;
	}

	werr = dsdb_attribute_drsuapi_remote_to_local(ctx,
						      remote_attid_as_enum,
						      local_attid_as_enum,
						      _sa);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(3, ("WARNING: Unable to resolve remote attid, falling back to local prefixMap.\n"));
		goto fail;
	}

	return werr;
fail:

	sa = dsdb_attribute_by_attributeID_id(schema, remote_attid_as_enum);
	if (sa == NULL) {
		return WERR_DS_DRA_SCHEMA_MISMATCH;
	} else {
		if (local_attid_as_enum != NULL) {
			*local_attid_as_enum = sa->attributeID_id;
		}
		if (_sa != NULL) {
			*_sa = sa;
		}
		return WERR_OK;
	}
}

static WERROR getncchanges_update_revealed_list(struct ldb_context *sam_ctx,
						TALLOC_CTX *mem_ctx,
						struct ldb_message **msg,
						struct ldb_dn *object_dn,
						const struct GUID *object_guid,
						const struct dsdb_attribute *sa,
						struct replPropertyMetaData1 *meta_data,
						struct ldb_message *revealed_users)
{
	enum ndr_err_code ndr_err;
	int ldb_err;
	char *attr_str = NULL;
	char *attr_hex = NULL;
	DATA_BLOB attr_blob;
	struct ldb_message_element *existing = NULL, *el_add = NULL, *el_del = NULL;
	const char * const * secret_attributes = ldb_get_opaque(sam_ctx, "LDB_SECRET_ATTRIBUTE_LIST");

	if (!ldb_attr_in_list(secret_attributes,
			      sa->lDAPDisplayName)) {
		return WERR_OK;
	}


	ndr_err = ndr_push_struct_blob(&attr_blob, mem_ctx, meta_data, (ndr_push_flags_fn_t)ndr_push_replPropertyMetaData1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	attr_hex = hex_encode_talloc(mem_ctx, attr_blob.data, attr_blob.length);
	if (attr_hex == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	attr_str = talloc_asprintf(mem_ctx, "B:%zd:%s:%s", attr_blob.length*2, attr_hex, ldb_dn_get_linearized(object_dn));
	if (attr_str == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	existing = ldb_msg_find_element(revealed_users, "msDS-RevealedUsers");
	if (existing != NULL) {
		/* Replace the old value (if one exists) with the current one */
		struct parsed_dn *link_dns;
		struct parsed_dn *exact = NULL, *unused = NULL;
		uint8_t attid[4];
		DATA_BLOB partial_meta;

		ldb_err = get_parsed_dns_trusted(mem_ctx, existing, &link_dns);
		if (ldb_err != LDB_SUCCESS) {
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		/* Construct a partial metadata blob to match on in the DB */
		SIVAL(attid, 0, sa->attributeID_id);
		partial_meta.length = 4;
		partial_meta.data = attid;

		/* Binary search using GUID and attribute id for uniqueness */
		ldb_err = parsed_dn_find(sam_ctx, link_dns, existing->num_values,
					 object_guid, object_dn,
					 partial_meta, 4,
					 &exact, &unused,
					 DSDB_SYNTAX_BINARY_DN, true);

		if (ldb_err != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed parsed DN find - %s\n",
				 ldb_errstring(sam_ctx)));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if (exact != NULL) {
			/* Perform some verification of the blob */
			struct replPropertyMetaData1 existing_meta_data;
			ndr_err = ndr_pull_struct_blob_all_noalloc(&exact->dsdb_dn->extra_part,
								   &existing_meta_data,
								   (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaData1);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return WERR_DS_DRA_INTERNAL_ERROR;
			}

			if (existing_meta_data.attid == sa->attributeID_id) {
				ldb_err = ldb_msg_add_empty(*msg, "msDS-RevealedUsers", LDB_FLAG_MOD_DELETE, &el_del);
				if (ldb_err != LDB_SUCCESS) {
					return WERR_DS_DRA_INTERNAL_ERROR;
				}

				el_del->values = talloc_array((*msg)->elements, struct ldb_val, 1);
				if (el_del->values == NULL) {
					return WERR_NOT_ENOUGH_MEMORY;
				}
				el_del->values[0] = *exact->v;
				el_del->num_values = 1;
			} else {
				return WERR_DS_DRA_INTERNAL_ERROR;
			}
		}
	}

	ldb_err = ldb_msg_add_empty(*msg, "msDS-RevealedUsers", LDB_FLAG_MOD_ADD, &el_add);
	if (ldb_err != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	el_add->values = talloc_array((*msg)->elements, struct ldb_val, 1);
	if (el_add->values == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;

	}

	el_add->values[0] = data_blob_string_const(attr_str);
	el_add->num_values = 1;

	return WERR_OK;
}

/*
 * This function filter attributes for build_object based on the
 * uptodatenessvector and partial attribute set.
 *
 * Any secret attributes are forced here for REPL_SECRET, and audited at this
 * point with msDS-RevealedUsers.
 */
static WERROR get_nc_changes_filter_attrs(struct drsuapi_DsReplicaObjectListItemEx *obj,
					  struct replPropertyMetaDataBlob md,
					  struct ldb_context *sam_ctx,
					  const struct ldb_message *msg,
					  const struct GUID *guid,
					  uint32_t *count,
					  uint64_t highest_usn,
					  const struct dsdb_attribute *rdn_sa,
					  struct dsdb_schema *schema,
					  struct drsuapi_DsReplicaCursorCtrEx *uptodateness_vector,
					  struct drsuapi_DsPartialAttributeSet *partial_attribute_set,
					  uint32_t *local_pas,
					  uint32_t *attids,
					  bool exop_secret,
					  struct ldb_message **revealed_list_msg,
					  struct ldb_message *existing_revealed_list_msg)
{
	uint32_t i, n;
	WERROR werr;
	for (n=i=0; i<md.ctr.ctr1.count; i++) {
		const struct dsdb_attribute *sa;
		bool force_attribute = false;

		/* if the attribute has not changed, and it is not the
		   instanceType then don't include it */
		if (md.ctr.ctr1.array[i].local_usn < highest_usn &&
		    !exop_secret &&
		    md.ctr.ctr1.array[i].attid != DRSUAPI_ATTID_instanceType) continue;

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

		if (exop_secret &&
		    !dsdb_attr_in_rodc_fas(sa)) {
			force_attribute = true;
			DEBUG(4,("Forcing attribute %s in %s\n",
				 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
			werr = getncchanges_update_revealed_list(sam_ctx, obj,
								 revealed_list_msg,
								 msg->dn, guid, sa,
								 &md.ctr.ctr1.array[i],
								 existing_revealed_list_msg);
			if (!W_ERROR_IS_OK(werr)) {
				return werr;
			}
		}

		/* filter by uptodateness_vector */
		if (md.ctr.ctr1.array[i].attid != DRSUAPI_ATTID_instanceType &&
		    !force_attribute &&
		    udv_filter(uptodateness_vector,
			       &md.ctr.ctr1.array[i].originating_invocation_id,
			       md.ctr.ctr1.array[i].originating_usn)) {
			continue;
		}

		/* filter by partial_attribute_set */
		if (partial_attribute_set && !force_attribute) {
			uint32_t *result = NULL;
			BINARY_ARRAY_SEARCH_V(local_pas, partial_attribute_set->num_attids, sa->attributeID_id,
					      uint32_t_cmp, result);
			if (result == NULL) {
				continue;
			}
		}

		obj->meta_data_ctr->meta_data[n].originating_change_time = md.ctr.ctr1.array[i].originating_change_time;
		obj->meta_data_ctr->meta_data[n].version = md.ctr.ctr1.array[i].version;
		obj->meta_data_ctr->meta_data[n].originating_invocation_id = md.ctr.ctr1.array[i].originating_invocation_id;
		obj->meta_data_ctr->meta_data[n].originating_usn = md.ctr.ctr1.array[i].originating_usn;
		attids[n] = md.ctr.ctr1.array[i].attid;

		n++;
	}

	*count = n;

	return WERR_OK;
}

/* 
  drsuapi_DsGetNCChanges for one object
*/
static WERROR get_nc_changes_build_object(struct drsuapi_DsReplicaObjectListItemEx *obj,
					  const struct ldb_message *msg,
					  struct ldb_context *sam_ctx,
					  struct drsuapi_getncchanges_state *getnc_state,
					  struct dsdb_schema *schema,
					  DATA_BLOB *session_key,
					  struct drsuapi_DsGetNCChangesRequest10 *req10,
					  bool force_object_return,
					  uint32_t *local_pas,
					  struct ldb_dn *machine_dn,
					  const struct GUID *guid)
{
	const struct ldb_val *md_value;
	uint32_t i, n;
	struct replPropertyMetaDataBlob md;
	uint32_t rid = 0;
	int ldb_err;
	enum ndr_err_code ndr_err;
	uint32_t *attids;
	const char *rdn;
	const struct dsdb_attribute *rdn_sa;
	uint64_t uSNChanged;
	unsigned int instanceType;
	struct dsdb_syntax_ctx syntax_ctx;
	struct ldb_result *res = NULL;
	WERROR werr;
	int ret;
	uint32_t replica_flags = req10->replica_flags;
	struct drsuapi_DsPartialAttributeSet *partial_attribute_set =
			req10->partial_attribute_set;
	struct drsuapi_DsReplicaCursorCtrEx *uptodateness_vector =
			req10->uptodateness_vector;
	enum drsuapi_DsExtendedOperation extended_op = req10->extended_op;
	bool is_schema_nc = getnc_state->is_schema_nc;
	uint64_t highest_usn = getnc_state->min_usn;

	/* make dsdb sytanx context for conversions */
	dsdb_syntax_ctx_init(&syntax_ctx, sam_ctx, schema);
	syntax_ctx.is_schema_nc = is_schema_nc;

	uSNChanged = ldb_msg_find_attr_as_uint64(msg, "uSNChanged", 0);
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

	if (uSNChanged <= highest_usn) {
		/* nothing to send */
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
		return WERR_NOT_ENOUGH_MEMORY;
	}
	dom_sid_split_rid(NULL, &obj->object.identifier->sid, NULL, &rid);

	obj->meta_data_ctr->meta_data = talloc_array(obj, struct drsuapi_DsReplicaMetaData, md.ctr.ctr1.count);

	if (extended_op == DRSUAPI_EXOP_REPL_SECRET) {
		/* Get the existing revealed users for the destination */
		struct ldb_message *revealed_list_msg = NULL;
		struct ldb_message *existing_revealed_list_msg = NULL;
		const char *machine_attrs[] = {
			"msDS-RevealedUsers",
			NULL
		};

		revealed_list_msg = ldb_msg_new(sam_ctx);
		if (revealed_list_msg == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		revealed_list_msg->dn = machine_dn;

		ret = ldb_transaction_start(sam_ctx);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed transaction start - %s\n",
				 ldb_errstring(sam_ctx)));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		ldb_err = dsdb_search_dn(sam_ctx, obj, &res, machine_dn, machine_attrs, DSDB_SEARCH_SHOW_EXTENDED_DN);
		if (ldb_err != LDB_SUCCESS || res->count != 1) {
			ldb_transaction_cancel(sam_ctx);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		existing_revealed_list_msg = res->msgs[0];

		werr = get_nc_changes_filter_attrs(obj, md, sam_ctx, msg,
						   guid, &n, highest_usn,
						   rdn_sa, schema,
						   uptodateness_vector,
						   partial_attribute_set, local_pas,
						   attids,
						   true,
						   &revealed_list_msg,
						   existing_revealed_list_msg);
		if (!W_ERROR_IS_OK(werr)) {
			ldb_transaction_cancel(sam_ctx);
			return werr;
		}

		if (revealed_list_msg != NULL) {
			ret = ldb_modify(sam_ctx, revealed_list_msg);
			if (ret != LDB_SUCCESS) {
				DEBUG(0,(__location__ ": Failed to alter revealed links - %s\n",
					 ldb_errstring(sam_ctx)));
				ldb_transaction_cancel(sam_ctx);
				return WERR_DS_DRA_INTERNAL_ERROR;
			}
		}

		ret = ldb_transaction_commit(sam_ctx);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed transaction commit - %s\n",
				 ldb_errstring(sam_ctx)));
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
	} else {
		werr = get_nc_changes_filter_attrs(obj, md, sam_ctx, msg, guid,
						   &n, highest_usn, rdn_sa,
						   schema, uptodateness_vector,
						   partial_attribute_set, local_pas,
						   attids,
						   false,
						   NULL,
						   NULL);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
	}

	/* ignore it if its an empty change. Note that renames always
	 * change the 'name' attribute, so they won't be ignored by
	 * this

	 * the force_object_return check is used to force an empty
	 * object return when we timeout in the getncchanges loop.
	 * This allows us to return an empty object, which keeps the
	 * client happy while preventing timeouts
	 */
	if (n == 0 ||
	    (n == 1 &&
	     attids[0] == DRSUAPI_ATTID_instanceType &&
	     !force_object_return)) {
		talloc_free(obj->meta_data_ctr);
		obj->meta_data_ctr = NULL;
		return WERR_OK;
	}

	obj->meta_data_ctr->count = n;

	obj->object.flags = DRSUAPI_DS_REPLICA_OBJECT_FROM_MASTER;
	obj->object.attribute_ctr.num_attributes = obj->meta_data_ctr->count;
	obj->object.attribute_ctr.attributes = talloc_array(obj, struct drsuapi_DsReplicaAttribute,
							    obj->object.attribute_ctr.num_attributes);
	if (obj->object.attribute_ctr.attributes == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/*
	 * Note that the meta_data array and the attributes array must
	 * be the same size and in the same order
	 */
	for (i=0; i<obj->object.attribute_ctr.num_attributes; i++) {
		struct ldb_message_element *el;
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
			obj->object.attribute_ctr.attributes[i].attid =
					dsdb_attribute_get_attid(sa, syntax_ctx.is_schema_nc);
		} else {
			werr = sa->syntax->ldb_to_drsuapi(&syntax_ctx, sa, el, obj,
			                                  &obj->object.attribute_ctr.attributes[i]);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,("Unable to convert %s on %s to DRS object - %s\n",
					 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn),
					 win_errstr(werr)));
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
				DEBUG(0,("Unable to encrypt %s on %s in DRS object - %s\n",
					 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn),
					 win_errstr(werr)));
				return werr;
			}
		}
		if (attids[i] != obj->object.attribute_ctr.attributes[i].attid) {
			DEBUG(0, ("Unable to replicate attribute %s on %s via DRS, incorrect attributeID:  "
				  "0x%08x vs 0x%08x "
				  "Run dbcheck!\n",
				  sa->lDAPDisplayName,
				  ldb_dn_get_linearized(msg->dn),
				  attids[i],
				  obj->object.attribute_ctr.attributes[i].attid));
			return WERR_DS_DATABASE_ERROR;
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
				    const struct ldb_message *msg,
				    struct dsdb_dn *dsdb_dn,
				    struct drsuapi_DsReplicaLinkedAttribute **la_list,
				    uint32_t *la_count,
				    bool is_schema_nc)
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

	if (!active) {
		/* We have to check that the inactive link still point to an existing object */
		struct GUID guid;
		struct ldb_dn *tdn;
		int ret;
		const char *v;

		v = ldb_msg_find_attr_as_string(msg, "isDeleted", "FALSE");
		if (strncmp(v, "TRUE", 4) == 0) {
			/*
			  * Note: we skip the transmition of the deleted link even if the other part used to
			  * know about it because when we transmit the deletion of the object, the link will
			  * be deleted too due to deletion of object where link points and Windows do so.
			  */
			if (dsdb_functional_level(sam_ctx) >= DS_DOMAIN_FUNCTION_2008_R2) {
				v = ldb_msg_find_attr_as_string(msg, "isRecycled", "FALSE");
				/*
				 * On Windows 2008R2 isRecycled is always present even if FL or DL are < FL 2K8R2
				 * if it join an existing domain with deleted objets, it firsts impose to have a
				 * schema with the is-Recycled object and for all deleted objects it adds the isRecycled
				 * either during initial replication or after the getNCChanges.
				 * Behavior of samba has been changed to always have this attribute if it's present in the schema.
				 *
				 * So if FL <2K8R2 isRecycled might be here or not but we don't care, it's meaning less.
				 * If FL >=2K8R2 we are sure that this attribute will be here.
				 * For this kind of forest level we do not return the link if the object is recycled
				 * (isRecycled = true).
				 */
				if (strncmp(v, "TRUE", 4) == 0) {
					DEBUG(2, (" object %s is recycled, not returning linked attribute !\n",
								ldb_dn_get_linearized(msg->dn)));
					return WERR_OK;
				}
			} else {
				return WERR_OK;
			}
		}
		status = dsdb_get_extended_dn_guid(dsdb_dn->dn, &guid, "GUID");
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,(__location__ " Unable to extract GUID in linked attribute '%s' in '%s'\n",
				sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
			return ntstatus_to_werror(status);
		}
		ret = dsdb_find_dn_by_guid(sam_ctx, mem_ctx, &guid, 0, &tdn);
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			DEBUG(2, (" Search of guid %s returned 0 objects, skipping it !\n",
						GUID_string(mem_ctx, &guid)));
			return WERR_OK;
		} else if (ret != LDB_SUCCESS) {
			DEBUG(0, (__location__ " Search of guid %s failed with error code %d\n",
						GUID_string(mem_ctx, &guid),
						ret));
			return WERR_OK;
		}
	}
	la->attid = dsdb_attribute_get_attid(sa, is_schema_nc);
	la->flags = active?DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE:0;

	status = dsdb_get_extended_dn_uint32(dsdb_dn->dn, &la->meta_data.version, "RMD_VERSION");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " No RMD_VERSION in linked attribute '%s' in '%s'\n",
			 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_nttime(dsdb_dn->dn, &la->meta_data.originating_change_time, "RMD_CHANGETIME");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " No RMD_CHANGETIME in linked attribute '%s' in '%s'\n",
			 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_guid(dsdb_dn->dn, &la->meta_data.originating_invocation_id, "RMD_INVOCID");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " No RMD_INVOCID in linked attribute '%s' in '%s'\n",
			 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		return ntstatus_to_werror(status);
	}
	status = dsdb_get_extended_dn_uint64(dsdb_dn->dn, &la->meta_data.originating_usn, "RMD_ORIGINATING_USN");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ " No RMD_ORIGINATING_USN in linked attribute '%s' in '%s'\n",
			 sa->lDAPDisplayName, ldb_dn_get_linearized(msg->dn)));
		return ntstatus_to_werror(status);
	}

	status = dsdb_get_extended_dn_nttime(dsdb_dn->dn, &la->originating_add_time, "RMD_ADDTIME");
	if (!NT_STATUS_IS_OK(status)) {
		/* this is possible for upgraded links */
		la->originating_add_time = la->meta_data.originating_change_time;
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
				       bool is_schema_nc,
				       struct dsdb_schema *schema,
				       uint64_t highest_usn,
				       uint32_t replica_flags,
				       const struct ldb_message *msg,
				       struct drsuapi_DsReplicaLinkedAttribute **la_list,
				       uint32_t *la_count,
				       struct drsuapi_DsReplicaCursorCtrEx *uptodateness_vector)
{
	unsigned int i;
	TALLOC_CTX *tmp_ctx = NULL;
	uint64_t uSNChanged = ldb_msg_find_attr_as_uint64(msg, "uSNChanged", 0);
	bool is_critical = ldb_msg_find_attr_as_bool(msg, "isCriticalSystemObject", false);

	if (replica_flags & DRSUAPI_DRS_CRITICAL_ONLY) {
		if (!is_critical) {
			return WERR_OK;
		}
	}

	if (uSNChanged <= highest_usn) {
		return WERR_OK;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

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
			uint64_t originating_usn;
			NTSTATUS status, status2;
			WERROR werr;
			struct GUID originating_invocation_id;

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

			if (local_usn <= highest_usn) {
				continue;
			}

			status = dsdb_get_extended_dn_guid(dsdb_dn->dn,
							   &originating_invocation_id,
							   "RMD_INVOCID");
			status2 = dsdb_get_extended_dn_uint64(dsdb_dn->dn,
							      &originating_usn,
							      "RMD_ORIGINATING_USN");

			if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(status2)) {
				if (udv_filter(uptodateness_vector,
					       &originating_invocation_id,
					       originating_usn)) {
					continue;
				}
			}

			werr = get_nc_changes_add_la(mem_ctx, sam_ctx, schema,
						     sa, msg, dsdb_dn, la_list,
						     la_count, is_schema_nc);
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
static int linked_attribute_compare(const struct la_for_sorting *la1,
				    const struct la_for_sorting *la2)
{
	int c;
	c = memcmp(la1->source_guid,
		   la2->source_guid, sizeof(la2->source_guid));
	if (c != 0) {
		return c;
	}

	if (la1->link->attid != la2->link->attid) {
		return la1->link->attid < la2->link->attid? -1:1;
	}

	if ((la1->link->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE) !=
	    (la2->link->flags & DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE)) {
		return (la1->link->flags &
			DRSUAPI_DS_LINKED_ATTRIBUTE_FLAG_ACTIVE)? 1:-1;
	}

	return memcmp(la1->target_guid,
		      la2->target_guid, sizeof(la2->target_guid));
}

struct drsuapi_changed_objects {
	struct ldb_dn *dn;
	struct GUID guid;
	uint64_t usn;
};

/*
  sort the objects we send first by uSNChanged
 */
static int site_res_cmp_usn_order(struct drsuapi_changed_objects *m1,
				  struct drsuapi_changed_objects *m2,
				  struct drsuapi_getncchanges_state *getnc_state)
{
	int ret;

	ret = ldb_dn_compare(getnc_state->ncRoot_dn, m1->dn);
	if (ret == 0) {
		return -1;
	}

	ret = ldb_dn_compare(getnc_state->ncRoot_dn, m2->dn);
	if (ret == 0) {
		return 1;
	}

	if (m1->usn == m2->usn) {
		return ldb_dn_compare(m2->dn, m1->dn);
	}

	if (m1->usn < m2->usn) {
		return -1;
	}

	return 1;
}


/*
  handle a DRSUAPI_EXOP_FSMO_RID_ALLOC call
 */
static WERROR getncchanges_rid_alloc(struct drsuapi_bind_state *b_state,
				     TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsGetNCChangesRequest10 *req10,
				     struct drsuapi_DsGetNCChangesCtr6 *ctr6,
				     struct ldb_dn **rid_manager_dn)
{
	struct ldb_dn *req_dn, *ntds_dn = NULL;
	int ret;
	struct ldb_context *ldb = b_state->sam_ctx;
	struct ldb_result *ext_res;
	struct dsdb_fsmo_extended_op *exop;
	bool is_us;

	/*
	  steps:
	    - verify that the DN being asked for is the RID Manager DN
	    - verify that we are the RID Manager
	 */

	/* work out who is the RID Manager, also return to caller */
	ret = samdb_rid_manager_dn(ldb, mem_ctx, rid_manager_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, (__location__ ": Failed to find RID Manager object - %s\n", ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	req_dn = drs_ObjectIdentifier_to_dn(mem_ctx, ldb, req10->naming_context);
	if (!ldb_dn_validate(req_dn) ||
	    ldb_dn_compare(req_dn, *rid_manager_dn) != 0) {
		/* that isn't the RID Manager DN */
		DEBUG(0,(__location__ ": RID Alloc request for wrong DN %s\n",
			 drs_ObjectIdentifier_to_string(mem_ctx, req10->naming_context)));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_MISMATCH;
		return WERR_OK;
	}

	/* TODO: make sure ntds_dn is a valid nTDSDSA object */
	ret = dsdb_find_dn_by_guid(ldb, mem_ctx, &req10->destination_dsa_guid, 0, &ntds_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, (__location__ ": Unable to find NTDS object for guid %s - %s\n",
			  GUID_string(mem_ctx, &req10->destination_dsa_guid), ldb_errstring(ldb)));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_UNKNOWN_CALLER;
		return WERR_OK;
	}

	/* find the DN of the RID Manager */
	ret = samdb_reference_dn_is_our_ntdsa(ldb, *rid_manager_dn, "fSMORoleOwner", &is_us);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to find fSMORoleOwner in RID Manager object\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if (!is_us) {
		/* we're not the RID Manager - go away */
		DEBUG(0,(__location__ ": RID Alloc request when not RID Manager\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_OK;
	}

	exop = talloc(mem_ctx, struct dsdb_fsmo_extended_op);
	W_ERROR_HAVE_NO_MEMORY(exop);

	exop->fsmo_info = req10->fsmo_info;
	exop->destination_dsa_guid = req10->destination_dsa_guid;

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

	DEBUG(2,("Allocated RID pool for server %s\n",
		 GUID_string(mem_ctx, &req10->destination_dsa_guid)));

	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;

	return WERR_OK;
}

/*
  handle a DRSUAPI_EXOP_REPL_SECRET call
 */
static WERROR getncchanges_repl_secret(struct drsuapi_bind_state *b_state,
				       TALLOC_CTX *mem_ctx,
				       struct drsuapi_DsGetNCChangesRequest10 *req10,
				       struct dom_sid *user_sid,
				       struct drsuapi_DsGetNCChangesCtr6 *ctr6,
				       bool has_get_all_changes,
				       struct ldb_dn **machine_dn)
{
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot = req10->naming_context;
	struct ldb_dn *obj_dn = NULL;
	struct ldb_dn *ntds_dn = NULL, *server_dn = NULL;
	struct ldb_dn *rodc_dn, *krbtgt_link_dn;
	int ret;
	const char *rodc_attrs[] = { "msDS-KrbTgtLink",
				     "msDS-NeverRevealGroup",
				     "msDS-RevealOnDemandGroup",
				     "userAccountControl",
				     NULL };
	const char *obj_attrs[] = { "tokenGroups", "objectSid", "UserAccountControl", "msDS-KrbTgtLinkBL", NULL };
	struct ldb_result *rodc_res = NULL, *obj_res = NULL;
	const struct dom_sid *object_sid = NULL;
	WERROR werr;

	DEBUG(3,(__location__ ": DRSUAPI_EXOP_REPL_SECRET extended op on %s\n",
		 drs_ObjectIdentifier_to_string(mem_ctx, ncRoot)));

	/*
	 * we need to work out if we will allow this DC to
	 * replicate the secrets for this object
	 *
	 * see 4.1.10.5.14 GetRevealSecretsPolicyForUser for details
	 * of this function
	 */

	if (b_state->sam_ctx_system == NULL) {
		/* this operation needs system level access */
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_ACCESS_DENIED;
		return WERR_DS_DRA_ACCESS_DENIED;
	}

	/*
	 * Before we accept or deny, fetch the machine DN for the destination
	 * DSA GUID.
	 *
	 * If we are the RODC, we will check that this matches the SID.
	 */
	ret = dsdb_find_dn_by_guid(b_state->sam_ctx_system, mem_ctx,
				   &req10->destination_dsa_guid, 0,
				   &ntds_dn);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	server_dn = ldb_dn_get_parent(mem_ctx, ntds_dn);
	if (server_dn == NULL) {
		goto failed;
	}

	ret = samdb_reference_dn(b_state->sam_ctx_system, mem_ctx, server_dn,
				 "serverReference", machine_dn);

	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	/*
	 * In MS-DRSR.pdf 5.99 IsGetNCChangesPermissionGranted
	 *
	 * The pseudo code indicate
	 * revealsecrets = true
	 * if IsRevealSecretRequest(msgIn) then
	 *   if AccessCheckCAR(ncRoot, Ds-Replication-Get-Changes-All) = false
	 *   then
	 *     if (msgIn.ulExtendedOp = EXOP_REPL_SECRETS) then
	 *     <... check if this account is ok to be replicated on this DC ...>
	 *     <... and if not reveal secrets = no ...>
	 *     else
	 *       reveal secrets = false
	 *     endif
	 *   endif
	 * endif
	 *
	 * Which basically means that if you have GET_ALL_CHANGES rights (~== RWDC)
	 * then you can do EXOP_REPL_SECRETS
	 */
	obj_dn = drs_ObjectIdentifier_to_dn(mem_ctx, b_state->sam_ctx_system, ncRoot);
	if (!ldb_dn_validate(obj_dn)) goto failed;

	if (has_get_all_changes) {
		goto allowed;
	}

	rodc_dn = ldb_dn_new_fmt(mem_ctx, b_state->sam_ctx_system, "<SID=%s>",
				 dom_sid_string(mem_ctx, user_sid));
	if (!ldb_dn_validate(rodc_dn)) goto failed;

	/*
	 * do the two searches we need
	 * We need DSDB_SEARCH_SHOW_EXTENDED_DN as we get a SID lists
	 * out of the extended DNs
	 */
	ret = dsdb_search_dn(b_state->sam_ctx_system, mem_ctx, &rodc_res, rodc_dn, rodc_attrs,
			     DSDB_SEARCH_SHOW_EXTENDED_DN);
	if (ret != LDB_SUCCESS || rodc_res->count != 1) goto failed;

	ret = dsdb_search_dn(b_state->sam_ctx_system, mem_ctx, &obj_res, obj_dn, obj_attrs, 0);
	if (ret != LDB_SUCCESS || obj_res->count != 1) goto failed;

	/* if the object SID is equal to the user_sid, allow */
	object_sid = samdb_result_dom_sid(mem_ctx, obj_res->msgs[0], "objectSid");
	if (object_sid == NULL) {
		goto failed;
	}
	if (dom_sid_equal(user_sid, object_sid)) {
		goto allowed;
	}

	/*
	 * Must be an RODC account at this point, verify machine DN matches the
	 * SID account
	 */
	if (ldb_dn_compare(rodc_res->msgs[0]->dn, *machine_dn) != 0) {
		goto denied;
	}

	/* an RODC is allowed to get its own krbtgt account secrets */
	krbtgt_link_dn = samdb_result_dn(b_state->sam_ctx_system, mem_ctx,
					 rodc_res->msgs[0], "msDS-KrbTgtLink", NULL);
	if (krbtgt_link_dn != NULL &&
	    ldb_dn_compare(obj_dn, krbtgt_link_dn) == 0) {
		goto allowed;
	}

	werr = samdb_confirm_rodc_allowed_to_repl_to(b_state->sam_ctx_system,
						     rodc_res->msgs[0],
						     obj_res->msgs[0]);

	if (W_ERROR_IS_OK(werr)) {
		goto allowed;
	}

	/* default deny */
denied:
	DEBUG(2,(__location__ ": Denied single object with secret replication for %s by RODC %s\n",
		 ldb_dn_get_linearized(obj_dn), ldb_dn_get_linearized(rodc_res->msgs[0]->dn)));
	ctr6->extended_ret = DRSUAPI_EXOP_ERR_NONE;
	return WERR_DS_DRA_SECRETS_DENIED;

allowed:
	DEBUG(2,(__location__ ": Allowed single object with secret replication for %s by %s %s\n",
		 ldb_dn_get_linearized(obj_dn), has_get_all_changes?"RWDC":"RODC",
		 ldb_dn_get_linearized(*machine_dn)));
	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;
	req10->highwatermark.highest_usn = 0;
	return WERR_OK;

failed:
	DEBUG(2,(__location__ ": Failed single secret replication for %s by RODC %s\n",
		 ldb_dn_get_linearized(obj_dn), dom_sid_string(mem_ctx, user_sid)));
	ctr6->extended_ret = DRSUAPI_EXOP_ERR_NONE;
	return WERR_DS_DRA_BAD_DN;
}

/*
  handle a DRSUAPI_EXOP_REPL_OBJ call
 */
static WERROR getncchanges_repl_obj(struct drsuapi_bind_state *b_state,
				    TALLOC_CTX *mem_ctx,
				    struct drsuapi_DsGetNCChangesRequest10 *req10,
				    struct dom_sid *user_sid,
				    struct drsuapi_DsGetNCChangesCtr6 *ctr6)
{
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot = req10->naming_context;

	DEBUG(3,(__location__ ": DRSUAPI_EXOP_REPL_OBJ extended op on %s\n",
		 drs_ObjectIdentifier_to_string(mem_ctx, ncRoot)));

	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;
	return WERR_OK;
}


/*
  handle DRSUAPI_EXOP_FSMO_REQ_ROLE,
  DRSUAPI_EXOP_FSMO_RID_REQ_ROLE,
  and DRSUAPI_EXOP_FSMO_REQ_PDC calls
 */
static WERROR getncchanges_change_master(struct drsuapi_bind_state *b_state,
					 TALLOC_CTX *mem_ctx,
					 struct drsuapi_DsGetNCChangesRequest10 *req10,
					 struct drsuapi_DsGetNCChangesCtr6 *ctr6)
{
	struct ldb_dn *req_dn, *ntds_dn;
	int ret;
	unsigned int i;
	struct ldb_context *ldb = b_state->sam_ctx;
	struct ldb_message *msg;
	bool is_us;

	/*
	  steps:
	    - verify that the client dn exists
	    - verify that we are the current master
	 */

	req_dn = drs_ObjectIdentifier_to_dn(mem_ctx, ldb, req10->naming_context);
	if (!ldb_dn_validate(req_dn)) {
		/* that is not a valid dn */
		DEBUG(0,(__location__ ": FSMO role transfer request for invalid DN %s\n",
			 drs_ObjectIdentifier_to_string(mem_ctx, req10->naming_context)));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_MISMATCH;
		return WERR_OK;
	}

	/* find the DN of the current role owner */
	ret = samdb_reference_dn_is_our_ntdsa(ldb, req_dn, "fSMORoleOwner", &is_us);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to find fSMORoleOwner in RID Manager object\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if (!is_us) {
		/* we're not the RID Manager or role owner - go away */
		DEBUG(0,(__location__ ": FSMO role or RID manager transfer owner request when not role owner\n"));
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_FSMO_NOT_OWNER;
		return WERR_OK;
	}

	/* change the current master */
	msg = ldb_msg_new(ldb);
	W_ERROR_HAVE_NO_MEMORY(msg);
	msg->dn = drs_ObjectIdentifier_to_dn(msg, ldb, req10->naming_context);
	W_ERROR_HAVE_NO_MEMORY(msg->dn);

	/* TODO: make sure ntds_dn is a valid nTDSDSA object */
	ret = dsdb_find_dn_by_guid(ldb, msg, &req10->destination_dsa_guid, 0, &ntds_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, (__location__ ": Unable to find NTDS object for guid %s - %s\n",
			  GUID_string(mem_ctx, &req10->destination_dsa_guid), ldb_errstring(ldb)));
		talloc_free(msg);
		ctr6->extended_ret = DRSUAPI_EXOP_ERR_UNKNOWN_CALLER;
		return WERR_OK;
	}

	ret = ldb_msg_add_string(msg, "fSMORoleOwner", ldb_dn_get_linearized(ntds_dn));
	if (ret != 0) {
		talloc_free(msg);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	for (i=0;i<msg->num_elements;i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed transaction start - %s\n",
			 ldb_errstring(ldb)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	ret = ldb_modify(ldb, msg);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to change current owner - %s\n",
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

	ctr6->extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;

	return WERR_OK;
}

/*
  see if this getncchanges request includes a request to reveal secret information
 */
static WERROR dcesrv_drsuapi_is_reveal_secrets_request(struct drsuapi_bind_state *b_state,
						       struct drsuapi_DsGetNCChangesRequest10 *req10,
						       struct dsdb_schema_prefixmap *pfm_remote,
						       bool *is_secret_request)
{
	enum drsuapi_DsExtendedOperation exop;
	uint32_t i;
	struct dsdb_schema *schema;
	struct dsdb_syntax_ctx syntax_ctx;

	*is_secret_request = true;

	exop = req10->extended_op;

	switch (exop) {
	case DRSUAPI_EXOP_FSMO_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_RID_ALLOC:
	case DRSUAPI_EXOP_FSMO_RID_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_REQ_PDC:
	case DRSUAPI_EXOP_FSMO_ABANDON_ROLE:
		/* FSMO exops can reveal secrets */
		*is_secret_request = true;
		return WERR_OK;
	case DRSUAPI_EXOP_REPL_SECRET:
	case DRSUAPI_EXOP_REPL_OBJ:
	case DRSUAPI_EXOP_NONE:
		break;
	}

	if (req10->replica_flags & DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING) {
		*is_secret_request = false;
		return WERR_OK;
	}

	if (exop == DRSUAPI_EXOP_REPL_SECRET ||
	    req10->partial_attribute_set == NULL) {
		/* they want secrets */
		*is_secret_request = true;
		return WERR_OK;
	}

	schema = dsdb_get_schema(b_state->sam_ctx, NULL);
	dsdb_syntax_ctx_init(&syntax_ctx, b_state->sam_ctx, schema);
	syntax_ctx.pfm_remote = pfm_remote;

	/* check the attributes they asked for */
	for (i=0; i<req10->partial_attribute_set->num_attids; i++) {
		const struct dsdb_attribute *sa;
		WERROR werr = getncchanges_attid_remote_to_local(schema,
								 &syntax_ctx,
								 req10->partial_attribute_set->attids[i],
								 NULL,
								 &sa);

		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__": attid 0x%08X not found: %s\n",
				 req10->partial_attribute_set->attids[i], win_errstr(werr)));
			return werr;
		}

		if (!dsdb_attr_in_rodc_fas(sa)) {
			*is_secret_request = true;
			return WERR_OK;
		}
	}

	if (req10->partial_attribute_set_ex) {
		/* check the extended attributes they asked for */
		for (i=0; i<req10->partial_attribute_set_ex->num_attids; i++) {
			const struct dsdb_attribute *sa;
			WERROR werr = getncchanges_attid_remote_to_local(schema,
									 &syntax_ctx,
									 req10->partial_attribute_set_ex->attids[i],
									 NULL,
									 &sa);

			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,(__location__": attid 0x%08X not found: %s\n",
					 req10->partial_attribute_set_ex->attids[i], win_errstr(werr)));
				return werr;
			}

			if (!dsdb_attr_in_rodc_fas(sa)) {
				*is_secret_request = true;
				return WERR_OK;
			}
		}
	}

	*is_secret_request = false;
	return WERR_OK;
}

/*
  see if this getncchanges request is only for attributes in the GC
  partial attribute set
 */
static WERROR dcesrv_drsuapi_is_gc_pas_request(struct drsuapi_bind_state *b_state,
					       struct drsuapi_DsGetNCChangesRequest10 *req10,
					       struct dsdb_schema_prefixmap *pfm_remote,
					       bool *is_gc_pas_request)
{
	enum drsuapi_DsExtendedOperation exop;
	uint32_t i;
	struct dsdb_schema *schema;
	struct dsdb_syntax_ctx syntax_ctx;

	exop = req10->extended_op;

	switch (exop) {
	case DRSUAPI_EXOP_FSMO_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_RID_ALLOC:
	case DRSUAPI_EXOP_FSMO_RID_REQ_ROLE:
	case DRSUAPI_EXOP_FSMO_REQ_PDC:
	case DRSUAPI_EXOP_FSMO_ABANDON_ROLE:
	case DRSUAPI_EXOP_REPL_SECRET:
		*is_gc_pas_request = false;
		return WERR_OK;
	case DRSUAPI_EXOP_REPL_OBJ:
	case DRSUAPI_EXOP_NONE:
		break;
	}

	if (req10->partial_attribute_set == NULL) {
		/* they want it all */
		*is_gc_pas_request = false;
		return WERR_OK;
	}

	schema = dsdb_get_schema(b_state->sam_ctx, NULL);
	dsdb_syntax_ctx_init(&syntax_ctx, b_state->sam_ctx, schema);
	syntax_ctx.pfm_remote = pfm_remote;

	/* check the attributes they asked for */
	for (i=0; i<req10->partial_attribute_set->num_attids; i++) {
		const struct dsdb_attribute *sa;
		WERROR werr = getncchanges_attid_remote_to_local(schema,
								 &syntax_ctx,
								 req10->partial_attribute_set->attids[i],
								 NULL,
								 &sa);

		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__": attid 0x%08X not found: %s\n",
				 req10->partial_attribute_set->attids[i], win_errstr(werr)));
			return werr;
		}

		if (!sa->isMemberOfPartialAttributeSet) {
			*is_gc_pas_request = false;
			return WERR_OK;
		}
	}

	if (req10->partial_attribute_set_ex) {
		/* check the extended attributes they asked for */
		for (i=0; i<req10->partial_attribute_set_ex->num_attids; i++) {
			const struct dsdb_attribute *sa;
			WERROR werr = getncchanges_attid_remote_to_local(schema,
									 &syntax_ctx,
									 req10->partial_attribute_set_ex->attids[i],
									 NULL,
									 &sa);

			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,(__location__": attid 0x%08X not found: %s\n",
					 req10->partial_attribute_set_ex->attids[i], win_errstr(werr)));
				return werr;
			}

			if (!sa->isMemberOfPartialAttributeSet) {
				*is_gc_pas_request = false;
				return WERR_OK;
			}
		}
	}

	*is_gc_pas_request = true;
	return WERR_OK;
}


/*
  map from req8 to req10
 */
static struct drsuapi_DsGetNCChangesRequest10 *
getncchanges_map_req8(TALLOC_CTX *mem_ctx,
		      struct drsuapi_DsGetNCChangesRequest8 *req8)
{
	struct drsuapi_DsGetNCChangesRequest10 *req10 = talloc_zero(mem_ctx,
								    struct drsuapi_DsGetNCChangesRequest10);
	if (req10 == NULL) {
		return NULL;
	}

	req10->destination_dsa_guid = req8->destination_dsa_guid;
	req10->source_dsa_invocation_id = req8->source_dsa_invocation_id;
	req10->naming_context = req8->naming_context;
	req10->highwatermark = req8->highwatermark;
	req10->uptodateness_vector = req8->uptodateness_vector;
	req10->replica_flags = req8->replica_flags;
	req10->max_object_count = req8->max_object_count;
	req10->max_ndr_size = req8->max_ndr_size;
	req10->extended_op = req8->extended_op;
	req10->fsmo_info = req8->fsmo_info;
	req10->partial_attribute_set = req8->partial_attribute_set;
	req10->partial_attribute_set_ex = req8->partial_attribute_set_ex;
	req10->mapping_ctr = req8->mapping_ctr;

	return req10;
}

static const char *collect_objects_attrs[] = { "uSNChanged",
					       "objectGUID" ,
					       NULL };

/**
 * Collects object for normal replication cycle.
 */
static WERROR getncchanges_collect_objects(struct drsuapi_bind_state *b_state,
					   TALLOC_CTX *mem_ctx,
					   struct drsuapi_DsGetNCChangesRequest10 *req10,
					   struct ldb_dn *search_dn,
					   const char *extra_filter,
					   struct ldb_result **search_res)
{
	int ret;
	char* search_filter;
	enum ldb_scope scope = LDB_SCOPE_SUBTREE;
	struct drsuapi_getncchanges_state *getnc_state = b_state->getncchanges_state;
	bool critical_only = false;

	if (req10->replica_flags & DRSUAPI_DRS_CRITICAL_ONLY) {
		critical_only = true;
	}

	if (req10->extended_op == DRSUAPI_EXOP_REPL_OBJ ||
	    req10->extended_op == DRSUAPI_EXOP_REPL_SECRET) {
		scope = LDB_SCOPE_BASE;
		critical_only = false;
	}

	/* Construct response. */
	search_filter = talloc_asprintf(mem_ctx,
					"(uSNChanged>=%llu)",
					(unsigned long long)(getnc_state->min_usn+1));

	if (extra_filter) {
		search_filter = talloc_asprintf(mem_ctx, "(&%s(%s))", search_filter, extra_filter);
	}

	if (critical_only) {
		search_filter = talloc_asprintf(mem_ctx,
						"(&%s(isCriticalSystemObject=TRUE))",
						search_filter);
	}

	if (req10->replica_flags & DRSUAPI_DRS_ASYNC_REP) {
		scope = LDB_SCOPE_BASE;
	}

	if (!search_dn) {
		search_dn = getnc_state->ncRoot_dn;
	}

	DEBUG(2,(__location__ ": getncchanges on %s using filter %s\n",
		 ldb_dn_get_linearized(getnc_state->ncRoot_dn), search_filter));
	ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, getnc_state, search_res,
					      search_dn, scope,
					      collect_objects_attrs,
					      search_filter);
	if (ret != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	return WERR_OK;
}

/**
 * Collects object for normal replication cycle.
 */
static WERROR getncchanges_collect_objects_exop(struct drsuapi_bind_state *b_state,
						TALLOC_CTX *mem_ctx,
						struct drsuapi_DsGetNCChangesRequest10 *req10,
						struct drsuapi_DsGetNCChangesCtr6 *ctr6,
						struct ldb_dn *search_dn,
						const char *extra_filter,
						struct ldb_result **search_res)
{
	/* we have nothing to do in case of ex-op failure */
	if (ctr6->extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
		return WERR_OK;
	}

	switch (req10->extended_op) {
	case DRSUAPI_EXOP_FSMO_RID_ALLOC:
	{
		int ret;
		struct ldb_dn *ntds_dn = NULL;
		struct ldb_dn *server_dn = NULL;
		struct ldb_dn *machine_dn = NULL;
		struct ldb_dn *rid_set_dn = NULL;
		struct ldb_result *search_res2 = NULL;
		struct ldb_result *search_res3 = NULL;
		TALLOC_CTX *frame = talloc_stackframe();
		/* get RID manager, RID set and server DN (in that order) */

		/* This first search will get the RID Manager */
		ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, frame,
						      search_res,
						      search_dn, LDB_SCOPE_BASE,
						      collect_objects_attrs,
						      NULL);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get RID Manager object %s - %s",
				  ldb_dn_get_linearized(search_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if ((*search_res)->count != 1) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get RID Manager object %s - %u objects returned",
				  ldb_dn_get_linearized(search_dn),
				  (*search_res)->count));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		/* Now extend it to the RID set */

		/* Find the computer account DN for the destination
		 * dsa GUID specified */

		ret = dsdb_find_dn_by_guid(b_state->sam_ctx, frame,
					   &req10->destination_dsa_guid, 0,
					   &ntds_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Unable to find NTDS object for guid %s - %s\n",
				  GUID_string(frame,
					      &req10->destination_dsa_guid),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		server_dn = ldb_dn_get_parent(frame, ntds_dn);
		if (!server_dn) {
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		ret = samdb_reference_dn(b_state->sam_ctx, frame, server_dn,
					 "serverReference", &machine_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to find serverReference in %s - %s",
				  ldb_dn_get_linearized(server_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		ret = samdb_reference_dn(b_state->sam_ctx, frame, machine_dn,
					 "rIDSetReferences", &rid_set_dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to find rIDSetReferences in %s - %s",
				  ldb_dn_get_linearized(server_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}


		/* This first search will get the RID Manager, now get the RID set */
		ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, frame,
						      &search_res2,
						      rid_set_dn, LDB_SCOPE_BASE,
						      collect_objects_attrs,
						      NULL);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get RID Set object %s - %s",
				  ldb_dn_get_linearized(rid_set_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if (search_res2->count != 1) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get RID Set object %s - %u objects returned",
				  ldb_dn_get_linearized(rid_set_dn),
				  search_res2->count));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		/* Finally get the server DN */
		ret = drsuapi_search_with_extended_dn(b_state->sam_ctx, frame,
						      &search_res3,
						      machine_dn, LDB_SCOPE_BASE,
						      collect_objects_attrs,
						      NULL);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get server object %s - %s",
				  ldb_dn_get_linearized(server_dn),
				  ldb_errstring(b_state->sam_ctx)));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		if (search_res3->count != 1) {
			DEBUG(1, ("DRSUAPI_EXOP_FSMO_RID_ALLOC: Failed to get server object %s - %u objects returned",
				  ldb_dn_get_linearized(server_dn),
				  search_res3->count));
			TALLOC_FREE(frame);
			return WERR_DS_DRA_INTERNAL_ERROR;
		}

		/* Now extend the original search_res with these answers */
		(*search_res)->count = 3;

		(*search_res)->msgs = talloc_realloc(frame, (*search_res)->msgs,
						     struct ldb_message *,
						     (*search_res)->count);
		if ((*search_res)->msgs == NULL) {
			TALLOC_FREE(frame);
			return WERR_NOT_ENOUGH_MEMORY;
		}


		talloc_steal(mem_ctx, *search_res);
		(*search_res)->msgs[1] =
			talloc_steal((*search_res)->msgs, search_res2->msgs[0]);
		(*search_res)->msgs[2] =
			talloc_steal((*search_res)->msgs, search_res3->msgs[0]);

		TALLOC_FREE(frame);
		return WERR_OK;
	}
	default:
		/* TODO: implement extended op specific collection
		 * of objects. Right now we just normal procedure
		 * for collecting objects */
		return getncchanges_collect_objects(b_state, mem_ctx, req10, search_dn, extra_filter, search_res);
	}
}

static void dcesrv_drsuapi_update_highwatermark(const struct ldb_message *msg,
						uint64_t max_usn,
						struct drsuapi_DsReplicaHighWaterMark *hwm)
{
	uint64_t uSN = ldb_msg_find_attr_as_uint64(msg, "uSNChanged", 0);

	if (uSN > max_usn) {
		/*
		 * Only report the max_usn we had at the start
		 * of the replication cycle.
		 *
		 * If this object has changed lately we better
		 * let the destination dsa refetch the change.
		 * This is better than the risk of loosing some
		 * objects or linked attributes.
		 */
		return;
	}

	if (uSN <= hwm->tmp_highest_usn) {
		return;
	}

	hwm->tmp_highest_usn = uSN;
	hwm->reserved_usn = 0;
}

/**
 * Adds an object's GUID to the cache of objects already sent.
 * This avoids us sending the same object multiple times when
 * the GetNCChanges request uses a flag like GET_ANC.
 */
static WERROR dcesrv_drsuapi_obj_cache_add(struct db_context *obj_cache,
					   const struct GUID *guid)
{
	enum ndr_err_code ndr_err;
	uint8_t guid_buf[DRS_GUID_SIZE] = { 0, };
	DATA_BLOB b = {
		.data = guid_buf,
		.length = sizeof(guid_buf),
	};
	TDB_DATA key = {
		.dptr = b.data,
		.dsize = b.length,
	};
	TDB_DATA val = {
		.dptr = NULL,
		.dsize = 0,
	};
	NTSTATUS status;

	ndr_err = ndr_push_struct_into_fixed_blob(&b, guid,
			(ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	status = dbwrap_store(obj_cache, key, val, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	return WERR_OK;
}

/**
 * Checks if the object with the GUID specified already exists in the
 * object cache, i.e. it's already been sent in a GetNCChanges response.
 */
static WERROR dcesrv_drsuapi_obj_cache_exists(struct db_context *obj_cache,
					      const struct GUID *guid)
{
	enum ndr_err_code ndr_err;
	uint8_t guid_buf[DRS_GUID_SIZE] = { 0, };
	DATA_BLOB b = {
		.data = guid_buf,
		.length = sizeof(guid_buf),
	};
	TDB_DATA key = {
		.dptr = b.data,
		.dsize = b.length,
	};
	bool exists;

	ndr_err = ndr_push_struct_into_fixed_blob(&b, guid,
			(ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	exists = dbwrap_exists(obj_cache, key);
	if (!exists) {
		return WERR_OBJECT_NOT_FOUND;
	}

	return WERR_OBJECT_NAME_EXISTS;
}

/**
 * Copies the la_list specified into a sorted array, ready to be sent in a
 * GetNCChanges response.
 */
static WERROR getncchanges_get_sorted_array(const struct drsuapi_DsReplicaLinkedAttribute *la_list,
					    const uint32_t link_count,
					    struct ldb_context *sam_ctx,
					    TALLOC_CTX *mem_ctx,
					    const struct dsdb_schema *schema,
					    struct la_for_sorting **ret_array)
{
	int j;
	struct la_for_sorting *guid_array;
	WERROR werr = WERR_OK;

	*ret_array = NULL;
	guid_array = talloc_array(mem_ctx, struct la_for_sorting, link_count);
	if (guid_array == NULL) {
		DEBUG(0, ("Out of memory allocating %u linked attributes for sorting", link_count));
		return WERR_NOT_ENOUGH_MEMORY;
	}

	for (j = 0; j < link_count; j++) {

		/* we need to get the target GUIDs to compare */
		struct dsdb_dn *dn;
		const struct drsuapi_DsReplicaLinkedAttribute *la = &la_list[j];
		const struct dsdb_attribute *schema_attrib;
		const struct ldb_val *target_guid;
		DATA_BLOB source_guid;
		TALLOC_CTX *frame = talloc_stackframe();
		NTSTATUS status;

		schema_attrib = dsdb_attribute_by_attributeID_id(schema, la->attid);

		werr = dsdb_dn_la_from_blob(sam_ctx, schema_attrib, schema, frame, la->value.blob, &dn);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__ ": Bad la blob in sort\n"));
			TALLOC_FREE(frame);
			return werr;
		}

		/* Extract the target GUID in NDR form */
		target_guid = ldb_dn_get_extended_component(dn->dn, "GUID");
		if (target_guid == NULL
				|| target_guid->length != sizeof(guid_array[0].target_guid)) {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		} else {
			/* Repack the source GUID as NDR for sorting */
			status = GUID_to_ndr_blob(&la->identifier->guid,
						  frame,
						  &source_guid);
		}

		if (!NT_STATUS_IS_OK(status)
				|| source_guid.length != sizeof(guid_array[0].source_guid)) {
			DEBUG(0,(__location__ ": Bad la guid in sort\n"));
			TALLOC_FREE(frame);
			return ntstatus_to_werror(status);
		}

		guid_array[j].link = &la_list[j];
		memcpy(guid_array[j].target_guid, target_guid->data,
		       sizeof(guid_array[j].target_guid));
		memcpy(guid_array[j].source_guid, source_guid.data,
		       sizeof(guid_array[j].source_guid));
		TALLOC_FREE(frame);
	}

	TYPESAFE_QSORT(guid_array, link_count, linked_attribute_compare);

	*ret_array = guid_array;

	return werr;
}


/**
 * Adds any ancestor/parent objects of the child_obj specified.
 * This is needed when the GET_ANC flag is specified in the request.
 * @param new_objs if parents are added, this gets updated to point to a chain
 * of parent objects (with the parents first and the child last)
 */
static WERROR getncchanges_add_ancestors(struct drsuapi_DsReplicaObjectListItemEx *child_obj,
					 struct ldb_dn *child_dn,
					 TALLOC_CTX *mem_ctx,
					 struct ldb_context *sam_ctx,
					 struct drsuapi_getncchanges_state *getnc_state,
					 struct dsdb_schema *schema,
					 DATA_BLOB *session_key,
					 struct drsuapi_DsGetNCChangesRequest10 *req10,
					 uint32_t *local_pas,
					 struct ldb_dn *machine_dn,
					 struct drsuapi_DsReplicaObjectListItemEx **new_objs)
{
	int ret;
	const struct GUID *next_anc_guid = NULL;
	WERROR werr = WERR_OK;
	static const char * const msg_attrs[] = {
					    "*",
					    "nTSecurityDescriptor",
					    "parentGUID",
					    "replPropertyMetaData",
					    DSDB_SECRET_ATTRIBUTES,
					    NULL };

	next_anc_guid = child_obj->parent_object_guid;

	while (next_anc_guid != NULL) {
		struct drsuapi_DsReplicaObjectListItemEx *anc_obj = NULL;
		struct ldb_message *anc_msg = NULL;
		struct ldb_result *anc_res = NULL;
		struct ldb_dn *anc_dn = NULL;

		/*
		 * Don't send an object twice. (If we've sent the object, then
		 * we've also sent all its parents as well)
		 */
		werr = dcesrv_drsuapi_obj_cache_exists(getnc_state->obj_cache,
						       next_anc_guid);
		if (W_ERROR_EQUAL(werr, WERR_OBJECT_NAME_EXISTS)) {
			return WERR_OK;
		}
		if (W_ERROR_IS_OK(werr)) {
			return WERR_INTERNAL_ERROR;
		}
		if (!W_ERROR_EQUAL(werr, WERR_OBJECT_NOT_FOUND)) {
			return werr;
		}

		anc_obj = talloc_zero(mem_ctx,
				      struct drsuapi_DsReplicaObjectListItemEx);
		if (anc_obj == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		anc_dn = ldb_dn_new_fmt(anc_obj, sam_ctx, "<GUID=%s>",
					GUID_string(anc_obj, next_anc_guid));
		if (anc_dn == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		ret = drsuapi_search_with_extended_dn(sam_ctx, anc_obj,
						      &anc_res, anc_dn,
						      LDB_SCOPE_BASE,
						      msg_attrs, NULL);
		if (ret != LDB_SUCCESS) {
			const char *anc_str = NULL;
			const char *obj_str = NULL;

			anc_str = ldb_dn_get_extended_linearized(anc_obj,
								 anc_dn,
								 1);
			obj_str = ldb_dn_get_extended_linearized(anc_obj,
								 child_dn,
								 1);

			DBG_ERR("getncchanges: failed to fetch ANC "
				"DN %s for DN %s - %s\n",
				anc_str, obj_str, ldb_errstring(sam_ctx));
			return WERR_DS_DRA_INCONSISTENT_DIT;
		}

		anc_msg = anc_res->msgs[0];

		werr = get_nc_changes_build_object(anc_obj, anc_msg,
						   sam_ctx,
						   getnc_state,
						   schema, session_key,
						   req10,
						   false, /* force_object_return */
						   local_pas,
						   machine_dn,
						   next_anc_guid);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		/*
		 * Regardless of whether we actually use it or not,
		 * we add it to the cache so we don't look at it again
		 */
		werr = dcesrv_drsuapi_obj_cache_add(getnc_state->obj_cache,
						    next_anc_guid);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		/*
		 * Any ancestors which are below the highwatermark
		 * or uptodateness_vector shouldn't be added,
		 * but we still look further up the
		 * tree for ones which have been changed recently.
		 */
		if (anc_obj->meta_data_ctr != NULL) {

			/*
			 * prepend the parent to the list so that the client-side
			 * adds the parent object before it adds the children
			 */
			anc_obj->next_object = *new_objs;
			*new_objs = anc_obj;
		}

		anc_msg = NULL;
		TALLOC_FREE(anc_res);
		TALLOC_FREE(anc_dn);

		/*
		 * We may need to resolve more parents...
		 */
		next_anc_guid = anc_obj->parent_object_guid;
	}
	return werr;
}

/**
 * Adds a list of new objects into the current chunk of replication data to send
 */
static void getncchanges_chunk_add_objects(struct getncchanges_repl_chunk *repl_chunk,
					   struct drsuapi_DsReplicaObjectListItemEx *obj_list)
{
	struct drsuapi_DsReplicaObjectListItemEx *obj;

	/*
	 * We track the last object added to the replication chunk, so just add
	 * the new object-list onto the end
	 */
	if (repl_chunk->object_list == NULL) {
		repl_chunk->object_list = obj_list;
	} else {
		repl_chunk->last_object->next_object = obj_list;
	}

	for (obj = obj_list; obj != NULL; obj = obj->next_object) {
		repl_chunk->object_count += 1;

		/*
		 * Remember the last object in the response - we'll use this to
		 * link the next object(s) processed onto the existing list
		 */
		if (obj->next_object == NULL) {
			repl_chunk->last_object = obj;
		}
	}
}

/**
 * Gets the object to send, packed into an RPC struct ready to send. This also
 * adds the object to the object cache, and adds any ancestors (if needed).
 * @param msg - DB search result for the object to add
 * @param guid - GUID of the object to add
 * @param ret_obj_list - returns the object ready to be sent (in a list, along
 * with any ancestors that might be needed). NULL if nothing to send.
 */
static WERROR getncchanges_get_obj_to_send(const struct ldb_message *msg,
					   TALLOC_CTX *mem_ctx,
					   struct ldb_context *sam_ctx,
					   struct drsuapi_getncchanges_state *getnc_state,
					   struct dsdb_schema *schema,
					   DATA_BLOB *session_key,
					   struct drsuapi_DsGetNCChangesRequest10 *req10,
					   bool force_object_return,
					   uint32_t *local_pas,
					   struct ldb_dn *machine_dn,
					   const struct GUID *guid,
					   struct drsuapi_DsReplicaObjectListItemEx **ret_obj_list)
{
	struct drsuapi_DsReplicaObjectListItemEx *obj;
	WERROR werr;

	*ret_obj_list = NULL;

	obj = talloc_zero(mem_ctx, struct drsuapi_DsReplicaObjectListItemEx);
	W_ERROR_HAVE_NO_MEMORY(obj);

	werr = get_nc_changes_build_object(obj, msg, sam_ctx, getnc_state,
					   schema, session_key, req10,
					   force_object_return,
					   local_pas, machine_dn, guid);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	/*
	 * The object may get filtered out by the UTDV's USN and not actually
	 * sent, in which case there's nothing more to do here
	 */
	if (obj->meta_data_ctr == NULL) {
		TALLOC_FREE(obj);
		return WERR_OK;
	}

	if (getnc_state->obj_cache != NULL) {
		werr = dcesrv_drsuapi_obj_cache_add(getnc_state->obj_cache,
						    guid);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
	}

	*ret_obj_list = obj;

	/*
	 * If required, also add any ancestors that the client may need to know
	 * about before it can resolve this object. These get prepended to the
	 * ret_obj_list so the client adds them first.
	 */
	if (getnc_state->is_get_anc) {
		werr = getncchanges_add_ancestors(obj, msg->dn, mem_ctx,
						  sam_ctx, getnc_state,
						  schema, session_key,
						  req10, local_pas,
						  machine_dn, ret_obj_list);
	}

	return werr;
}

/**
 * Returns the number of links that are waiting to be sent
 */
static uint32_t getncchanges_chunk_links_pending(struct getncchanges_repl_chunk *repl_chunk,
						 struct drsuapi_getncchanges_state *getnc_state)
{
	uint32_t links_to_send = 0;

	if (getnc_state->is_get_tgt) {

		/*
		 * when the GET_TGT flag is set, only include the linked
		 * attributes whose target object has already been checked
		 * (i.e. they're ready to send).
		 */
		if (repl_chunk->tgt_la_count > getnc_state->la_idx) {
			links_to_send = (repl_chunk->tgt_la_count -
					 getnc_state->la_idx);
		}
	} else {
		links_to_send = getnc_state->la_count - getnc_state->la_idx;
	}

	return links_to_send;
}

/**
 * Returns the max number of links that will fit in the current replication chunk
 */
static uint32_t getncchanges_chunk_max_links(struct getncchanges_repl_chunk *repl_chunk)
{
	uint32_t max_links = 0;

	if (repl_chunk->max_links != DEFAULT_MAX_LINKS ||
	    repl_chunk->max_objects != DEFAULT_MAX_OBJECTS) {

		/*
		 * We're using non-default settings, so don't try to adjust
		 * them, just trust the user has configured decent values
		 */
		max_links = repl_chunk->max_links;

	} else if (repl_chunk->max_links > repl_chunk->object_count) {

		/*
		 * This is just an approximate guess to avoid overfilling the
		 * replication chunk. It's the logic we've used historically.
		 * E.g. if we've already sent 1000 objects, then send 1000 fewer
		 * links. For comparison, the max that Windows seems to send is
		 * ~2700 links and ~250 objects (although this may vary based
		 * on timeouts)
		 */
		max_links = repl_chunk->max_links - repl_chunk->object_count;
	}

	return max_links;
}

/**
 * Returns true if the current GetNCChanges() call has taken longer than its
 * allotted time. This prevents the client from timing out.
 */
static bool getncchanges_chunk_timed_out(struct getncchanges_repl_chunk *repl_chunk)
{
	return (time(NULL) - repl_chunk->start > repl_chunk->max_wait);
}

/**
 * Returns true if the current chunk of replication data has reached the
 * max_objects and/or max_links thresholds.
 */
static bool getncchanges_chunk_is_full(struct getncchanges_repl_chunk *repl_chunk,
				       struct drsuapi_getncchanges_state *getnc_state)
{
	bool chunk_full = false;
	uint32_t links_to_send;
	uint32_t chunk_limit;

	/* check if the current chunk is already full with objects */
	if (repl_chunk->object_count >= repl_chunk->max_objects) {
		chunk_full = true;

	} else if (repl_chunk->object_count > 0 &&
		   getncchanges_chunk_timed_out(repl_chunk)) {

		/*
		 * We've exceeded our allotted time building this chunk,
		 * and we have at least one object to send back to the client
		 */
		chunk_full = true;

	} else if (repl_chunk->immediate_link_sync) {

		/* check if the chunk is already full with links */
		links_to_send = getncchanges_chunk_links_pending(repl_chunk,
								 getnc_state);

		chunk_limit = getncchanges_chunk_max_links(repl_chunk);

		/*
		 * The chunk is full if we've got more links to send than will
		 * fit in one chunk
		 */
		if (links_to_send > 0 && chunk_limit <= links_to_send) {
			chunk_full = true;
		}
	}

	return chunk_full;
}

/**
 * Goes through any new linked attributes and checks that the target object
 * will be known to the client, i.e. we've already sent it in an replication
 * chunk. If not, then it adds the target object to the current replication
 * chunk. This is only done when the client specifies DRS_GET_TGT.
 */
static WERROR getncchanges_chunk_add_la_targets(struct getncchanges_repl_chunk *repl_chunk,
						struct drsuapi_getncchanges_state *getnc_state,
						uint32_t start_la_index,
						TALLOC_CTX *mem_ctx,
						struct ldb_context *sam_ctx,
						struct dsdb_schema *schema,
						DATA_BLOB *session_key,
						struct drsuapi_DsGetNCChangesRequest10 *req10,
						uint32_t *local_pas,
						struct ldb_dn *machine_dn)
{
	int ret;
	uint32_t i;
	uint32_t max_la_index;
	uint32_t max_links;
	uint32_t target_count = 0;
	WERROR werr = WERR_OK;
	static const char * const msg_attrs[] = {
					    "*",
					    "nTSecurityDescriptor",
					    "parentGUID",
					    "replPropertyMetaData",
					    DSDB_SECRET_ATTRIBUTES,
					    NULL };

	/*
	 * A object can potentially link to thousands of targets. Only bother
	 * checking as many targets as will fit into the current response
	 */
	max_links = getncchanges_chunk_max_links(repl_chunk);
	max_la_index = MIN(getnc_state->la_count,
			   start_la_index + max_links);

	/* loop through any linked attributes to check */
	for (i = start_la_index;
	     (i < max_la_index &&
	      !getncchanges_chunk_is_full(repl_chunk, getnc_state));
	     i++) {

		struct GUID target_guid;
		struct drsuapi_DsReplicaObjectListItemEx *new_objs = NULL;
		const struct drsuapi_DsReplicaLinkedAttribute *la;
		struct ldb_result *msg_res;
		struct ldb_dn *search_dn;
		TALLOC_CTX *tmp_ctx;
		struct dsdb_dn *dn;
		const struct dsdb_attribute *schema_attrib;
		NTSTATUS status;
		bool same_nc;

		la = &getnc_state->la_list[i];
		tmp_ctx = talloc_new(mem_ctx);

		/*
		 * Track what linked attribute targets we've checked. We might
		 * not have time to check them all, so we should only send back
		 * the ones we've actually checked.
		 */
		repl_chunk->tgt_la_count = i + 1;

		/* get the GUID of the linked attribute's target object */
		schema_attrib = dsdb_attribute_by_attributeID_id(schema,
								 la->attid);

		werr = dsdb_dn_la_from_blob(sam_ctx, schema_attrib, schema,
					    tmp_ctx, la->value.blob, &dn);

		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__ ": Bad la blob\n"));
			return werr;
		}

		status = dsdb_get_extended_dn_guid(dn->dn, &target_guid, "GUID");

		if (!NT_STATUS_IS_OK(status)) {
			return ntstatus_to_werror(status);
		}

		/*
		 * if the target isn't in the cache, then the client
		 * might not know about it, so send the target now
		 */
		werr = dcesrv_drsuapi_obj_cache_exists(getnc_state->obj_cache,
						       &target_guid);

		if (W_ERROR_EQUAL(werr, WERR_OBJECT_NAME_EXISTS)) {

			/* target already sent, nothing to do */
			TALLOC_FREE(tmp_ctx);
			continue;
		}

		same_nc = dsdb_objects_have_same_nc(sam_ctx, tmp_ctx, dn->dn,
						    getnc_state->ncRoot_dn);

		/* don't try to fetch target objects from another partition */
		if (!same_nc) {
			TALLOC_FREE(tmp_ctx);
			continue;
		}

		search_dn = ldb_dn_new_fmt(tmp_ctx, sam_ctx, "<GUID=%s>",
					   GUID_string(tmp_ctx, &target_guid));
		W_ERROR_HAVE_NO_MEMORY(search_dn);

		ret = drsuapi_search_with_extended_dn(sam_ctx, tmp_ctx,
						      &msg_res, search_dn,
						      LDB_SCOPE_BASE,
						      msg_attrs, NULL);

		/*
		 * Don't fail the replication if we can't find the target.
		 * This could happen for a one-way linked attribute, if the
		 * target is deleted and then later expunged (thus, the source
		 * object can be left with a hanging link). Continue to send
		 * the the link (the client-side has already tried once with
		 * GET_TGT, so it should just end up ignoring it).
		 */
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			DBG_WARNING("Encountered unknown link target DN %s\n",
				    ldb_dn_get_extended_linearized(tmp_ctx, dn->dn, 1));
			TALLOC_FREE(tmp_ctx);
			continue;

		} else if (ret != LDB_SUCCESS) {
			DBG_ERR("Failed to fetch link target DN %s - %s\n",
				ldb_dn_get_extended_linearized(tmp_ctx, dn->dn, 1),
				ldb_errstring(sam_ctx));
			return WERR_DS_DRA_INCONSISTENT_DIT;
		}

		/*
		 * Construct an object, ready to send (this will include
		 * the object's ancestors as well, if GET_ANC is set)
		 */
		werr = getncchanges_get_obj_to_send(msg_res->msgs[0], mem_ctx,
						    sam_ctx, getnc_state,
						    schema, session_key, req10,
						    false, local_pas,
						    machine_dn, &target_guid,
						    &new_objs);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		if (new_objs != NULL) {
			target_count++;
			getncchanges_chunk_add_objects(repl_chunk, new_objs);
		}
		TALLOC_FREE(tmp_ctx);
	}

	if (target_count > 0) {
		DEBUG(3, ("GET_TGT: checked %u link-attrs, added %u target objs\n",
			  i - start_la_index, target_count));
	}

	return WERR_OK;
}

/**
 * Creates a helper struct used for building a chunk of replication data,
 * i.e. used over a single call to dcesrv_drsuapi_DsGetNCChanges().
 */
static struct getncchanges_repl_chunk * getncchanges_chunk_new(TALLOC_CTX *mem_ctx,
							       struct dcesrv_call_state *dce_call,
							       struct drsuapi_DsGetNCChangesRequest10 *req10)
{
	struct getncchanges_repl_chunk *repl_chunk;

	repl_chunk = talloc_zero(mem_ctx, struct getncchanges_repl_chunk);

	repl_chunk->start = time(NULL);

	repl_chunk->max_objects = lpcfg_parm_int(dce_call->conn->dce_ctx->lp_ctx, NULL,
						 "drs", "max object sync",
						 DEFAULT_MAX_OBJECTS);

	/*
	 * The client control here only applies in normal replication, not extended
	 * operations, which return a fixed set, even if the caller
	 * sets max_object_count == 0
	 */
	if (req10->extended_op == DRSUAPI_EXOP_NONE) {

		/*
		 * use this to force single objects at a time, which is useful
		 * for working out what object is giving problems
		 */
		if (req10->max_object_count < repl_chunk->max_objects) {
			repl_chunk->max_objects = req10->max_object_count;
		}
	}

	repl_chunk->max_links =
			lpcfg_parm_int(dce_call->conn->dce_ctx->lp_ctx, NULL,
				       "drs", "max link sync",
					DEFAULT_MAX_LINKS);

	repl_chunk->immediate_link_sync =
			lpcfg_parm_bool(dce_call->conn->dce_ctx->lp_ctx, NULL,
					"drs", "immediate link sync", false);

	/*
	 * Maximum time that we can spend in a getncchanges
	 * in order to avoid timeout of the other part.
	 * 10 seconds by default.
	 */
	repl_chunk->max_wait = lpcfg_parm_int(dce_call->conn->dce_ctx->lp_ctx,
					      NULL, "drs", "max work time", 10);

	return repl_chunk;
}

/*
  drsuapi_DsGetNCChanges

  see MS-DRSR 4.1.10.5.2 for basic logic of this function
*/
WERROR dcesrv_drsuapi_DsGetNCChanges(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct drsuapi_DsGetNCChanges *r)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);
	struct drsuapi_DsReplicaObjectIdentifier *ncRoot;
	int ret;
	uint32_t i, k;
	struct dsdb_schema *schema;
	struct drsuapi_DsReplicaOIDMapping_Ctr *ctr;
	struct getncchanges_repl_chunk *repl_chunk;
	NTSTATUS status;
	DATA_BLOB session_key;
	WERROR werr;
	struct dcesrv_handle *h;
	struct drsuapi_bind_state *b_state;
	struct drsuapi_getncchanges_state *getnc_state;
	struct drsuapi_DsGetNCChangesRequest10 *req10;
	uint32_t options;
	uint32_t link_count = 0;
	struct ldb_dn *search_dn = NULL;
	bool am_rodc;
	enum security_user_level security_level;
	struct ldb_context *sam_ctx;
	struct dom_sid *user_sid;
	bool is_secret_request;
	bool is_gc_pas_request;
	struct drsuapi_changed_objects *changes;
	bool has_get_all_changes = false;
	struct GUID invocation_id;
	static const struct drsuapi_DsReplicaLinkedAttribute no_linked_attr;
	struct dsdb_schema_prefixmap *pfm_remote = NULL;
	bool full = true;
	uint32_t *local_pas = NULL;
	struct ldb_dn *machine_dn = NULL; /* Only used for REPL SECRET EXOP */

	DCESRV_PULL_HANDLE_WERR(h, r->in.bind_handle, DRSUAPI_BIND_HANDLE);
	b_state = h->data;

	/* sam_ctx_system is not present for non-administrator users */
	sam_ctx = b_state->sam_ctx_system?b_state->sam_ctx_system:b_state->sam_ctx;

	invocation_id = *(samdb_ntds_invocation_id(sam_ctx));

	*r->out.level_out = 6;

	r->out.ctr->ctr6.linked_attributes_count = 0;
	r->out.ctr->ctr6.linked_attributes = discard_const_p(struct drsuapi_DsReplicaLinkedAttribute, &no_linked_attr);

	r->out.ctr->ctr6.object_count = 0;
	r->out.ctr->ctr6.nc_object_count = 0;
	r->out.ctr->ctr6.more_data = false;
	r->out.ctr->ctr6.uptodateness_vector = NULL;
	r->out.ctr->ctr6.source_dsa_guid = *(samdb_ntds_objectGUID(sam_ctx));
	r->out.ctr->ctr6.source_dsa_invocation_id = *(samdb_ntds_invocation_id(sam_ctx));
	r->out.ctr->ctr6.first_object = NULL;

	/* Check request revision. 
	 */
	switch (r->in.level) {
	case 8:
		req10 = getncchanges_map_req8(mem_ctx, &r->in.req->req8);
		if (req10 == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case 10:
		req10 = &r->in.req->req10;
		break;
	default:
		DEBUG(0,(__location__ ": Request for DsGetNCChanges with unsupported level %u\n",
			 r->in.level));
		return WERR_REVISION_MISMATCH;
	}

	repl_chunk = getncchanges_chunk_new(mem_ctx, dce_call, req10);

	if (repl_chunk == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* a RODC doesn't allow for any replication */
	ret = samdb_rodc(sam_ctx, &am_rodc);
	if (ret == LDB_SUCCESS && am_rodc) {
		DEBUG(0,(__location__ ": DsGetNCChanges attempt on RODC\n"));
		return WERR_DS_DRA_SOURCE_DISABLED;
	}

        /* Perform access checks. */
	/* TODO: we need to support a sync on a specific non-root
	 * DN. We'll need to find the real partition root here */
	ncRoot = req10->naming_context;
	if (ncRoot == NULL) {
		DEBUG(0,(__location__ ": Request for DsGetNCChanges with no NC\n"));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	if (samdb_ntds_options(sam_ctx, &options) != LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if ((options & DS_NTDSDSA_OPT_DISABLE_OUTBOUND_REPL) &&
	    !(req10->replica_flags & DRSUAPI_DRS_SYNC_FORCED)) {
		return WERR_DS_DRA_SOURCE_DISABLED;
	}

	user_sid = &session_info->security_token->sids[PRIMARY_USER_SID_INDEX];

	/* all clients must have GUID_DRS_GET_CHANGES */
	werr = drs_security_access_check_nc_root(sam_ctx,
						 mem_ctx,
						 session_info->security_token,
						 req10->naming_context,
						 GUID_DRS_GET_CHANGES);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	if (dsdb_functional_level(sam_ctx) >= DS_DOMAIN_FUNCTION_2008) {
		full = req10->partial_attribute_set == NULL &&
		       req10->partial_attribute_set_ex == NULL;
	} else {
		full = (options & DRSUAPI_DRS_WRIT_REP) != 0;
	}

	werr = dsdb_schema_pfm_from_drsuapi_pfm(&req10->mapping_ctr, true,
						mem_ctx, &pfm_remote, NULL);

	/* We were supplied a partial attribute set, without the prefix map! */
	if (!full && !W_ERROR_IS_OK(werr)) {
		if (req10->mapping_ctr.num_mappings == 0) {
			/*
			 * Despite the fact MS-DRSR specifies that this shouldn't
			 * happen, Windows RODCs will in fact not provide a prefixMap.
			 */
			DEBUG(5,(__location__ ": Failed to provide a remote prefixMap,"
				 " falling back to local prefixMap\n"));
		} else {
			DEBUG(0,(__location__ ": Failed to decode remote prefixMap: %s\n",
				 win_errstr(werr)));
			return werr;
		}
	}

	/* allowed if the GC PAS and client has
	   GUID_DRS_GET_FILTERED_ATTRIBUTES */
	werr = dcesrv_drsuapi_is_gc_pas_request(b_state, req10, pfm_remote, &is_gc_pas_request);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}
	if (is_gc_pas_request) {
		werr = drs_security_access_check_nc_root(sam_ctx,
							 mem_ctx,
							 session_info->security_token,
							 req10->naming_context,
							 GUID_DRS_GET_FILTERED_ATTRIBUTES);
		if (W_ERROR_IS_OK(werr)) {
			goto allowed;
		}
	}

	werr = dcesrv_drsuapi_is_reveal_secrets_request(b_state, req10,
							pfm_remote,
							&is_secret_request);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}
	if (is_secret_request) {
		werr = drs_security_access_check_nc_root(sam_ctx,
							 mem_ctx,
							 session_info->security_token,
							 req10->naming_context,
							 GUID_DRS_GET_ALL_CHANGES);
		if (!W_ERROR_IS_OK(werr)) {
			/* Only bail if this is not a EXOP_REPL_SECRET */
			if (req10->extended_op != DRSUAPI_EXOP_REPL_SECRET) {
				return werr;
			}
		} else {
			has_get_all_changes = true;
		}
	}

allowed:
	/* for non-administrator replications, check that they have
	   given the correct source_dsa_invocation_id */
	security_level = security_session_user_level(session_info,
						     samdb_domain_sid(sam_ctx));
	if (security_level == SECURITY_RO_DOMAIN_CONTROLLER) {
		if (req10->replica_flags & DRSUAPI_DRS_WRIT_REP) {
			/* we rely on this flag being unset for RODC requests */
			req10->replica_flags &= ~DRSUAPI_DRS_WRIT_REP;
		}
	}

	if (req10->replica_flags & DRSUAPI_DRS_FULL_SYNC_PACKET) {
		/* Ignore the _in_ uptpdateness vector*/
		req10->uptodateness_vector = NULL;
	}

	if (GUID_all_zero(&req10->source_dsa_invocation_id)) {
		req10->source_dsa_invocation_id = invocation_id;
	}

	if (!GUID_equal(&req10->source_dsa_invocation_id, &invocation_id)) {
		/*
		 * The given highwatermark is only valid relative to the
		 * specified source_dsa_invocation_id.
		 */
		ZERO_STRUCT(req10->highwatermark);
	}

	getnc_state = b_state->getncchanges_state;

	/* see if a previous replication has been abandoned */
	if (getnc_state) {
		struct ldb_dn *new_dn = drs_ObjectIdentifier_to_dn(getnc_state, sam_ctx, ncRoot);
		if (ldb_dn_compare(new_dn, getnc_state->ncRoot_dn) != 0) {
			DEBUG(0,(__location__ ": DsGetNCChanges 2nd replication on different DN %s %s (last_dn %s)\n",
				 ldb_dn_get_linearized(new_dn),
				 ldb_dn_get_linearized(getnc_state->ncRoot_dn),
				 ldb_dn_get_linearized(getnc_state->last_dn)));
			TALLOC_FREE(getnc_state);
			b_state->getncchanges_state = NULL;
		}
	}

	if (getnc_state) {
		ret = drsuapi_DsReplicaHighWaterMark_cmp(&getnc_state->last_hwm,
							 &req10->highwatermark);
		if (ret != 0) {
			DEBUG(0,(__location__ ": DsGetNCChanges 2nd replication "
				 "on DN %s %s highwatermark (last_dn %s)\n",
				 ldb_dn_get_linearized(getnc_state->ncRoot_dn),
				 (ret > 0) ? "older" : "newer",
				 ldb_dn_get_linearized(getnc_state->last_dn)));
			TALLOC_FREE(getnc_state);
			b_state->getncchanges_state = NULL;
		}
	}

	if (getnc_state == NULL) {
		struct ldb_result *res = NULL;
		const char *attrs[] = {
			"instanceType",
			"objectGuID",
			NULL
		};
		uint32_t nc_instanceType;
		struct ldb_dn *ncRoot_dn;

		ncRoot_dn = drs_ObjectIdentifier_to_dn(mem_ctx, sam_ctx, ncRoot);
		if (ncRoot_dn == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		ret = dsdb_search_dn(sam_ctx, mem_ctx, &res,
				     ncRoot_dn, attrs,
				     DSDB_SEARCH_SHOW_DELETED |
				     DSDB_SEARCH_SHOW_RECYCLED);
		if (ret != LDB_SUCCESS) {
			DBG_WARNING("Failed to find ncRoot_dn %s\n",
				    ldb_dn_get_linearized(ncRoot_dn));
			return WERR_DS_DRA_BAD_DN;
		}
		nc_instanceType = ldb_msg_find_attr_as_int(res->msgs[0],
							   "instanceType",
							   0);

		if (req10->extended_op != DRSUAPI_EXOP_NONE) {
			r->out.ctr->ctr6.extended_ret = DRSUAPI_EXOP_ERR_SUCCESS;
		}

		/*
		 * This is the first replication cycle and it is
		 * a good place to handle extended operations
		 *
		 * FIXME: we don't fully support extended operations yet
		 */
		switch (req10->extended_op) {
		case DRSUAPI_EXOP_NONE:
			if ((nc_instanceType & INSTANCE_TYPE_IS_NC_HEAD) == 0) {
				const char *dn_str
					= ldb_dn_get_linearized(ncRoot_dn);

				DBG_NOTICE("Rejecting full replication on "
					   "not NC %s", dn_str);

				return WERR_DS_CANT_FIND_EXPECTED_NC;
			}

			break;
		case DRSUAPI_EXOP_FSMO_RID_ALLOC:
			werr = getncchanges_rid_alloc(b_state, mem_ctx, req10, &r->out.ctr->ctr6, &search_dn);
			W_ERROR_NOT_OK_RETURN(werr);
			if (r->out.ctr->ctr6.extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
				return WERR_OK;
			}
			break;
		case DRSUAPI_EXOP_REPL_SECRET:
			werr = getncchanges_repl_secret(b_state, mem_ctx, req10,
						        user_sid,
						        &r->out.ctr->ctr6,
						        has_get_all_changes,
							&machine_dn);
			r->out.result = werr;
			W_ERROR_NOT_OK_RETURN(werr);
			break;
		case DRSUAPI_EXOP_FSMO_REQ_ROLE:
			werr = getncchanges_change_master(b_state, mem_ctx, req10, &r->out.ctr->ctr6);
			W_ERROR_NOT_OK_RETURN(werr);
			if (r->out.ctr->ctr6.extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
				return WERR_OK;
			}
			break;
		case DRSUAPI_EXOP_FSMO_RID_REQ_ROLE:
			werr = getncchanges_change_master(b_state, mem_ctx, req10, &r->out.ctr->ctr6);
			W_ERROR_NOT_OK_RETURN(werr);
			if (r->out.ctr->ctr6.extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
				return WERR_OK;
			}
			break;
		case DRSUAPI_EXOP_FSMO_REQ_PDC:
			werr = getncchanges_change_master(b_state, mem_ctx, req10, &r->out.ctr->ctr6);
			W_ERROR_NOT_OK_RETURN(werr);
			if (r->out.ctr->ctr6.extended_ret != DRSUAPI_EXOP_ERR_SUCCESS) {
				return WERR_OK;
			}
			break;
		case DRSUAPI_EXOP_REPL_OBJ:
			werr = getncchanges_repl_obj(b_state, mem_ctx, req10, user_sid, &r->out.ctr->ctr6);
			r->out.result = werr;
			W_ERROR_NOT_OK_RETURN(werr);
			break;

		case DRSUAPI_EXOP_FSMO_ABANDON_ROLE:

			DEBUG(0,(__location__ ": Request for DsGetNCChanges unsupported extended op 0x%x\n",
				 (unsigned)req10->extended_op));
			return WERR_DS_DRA_NOT_SUPPORTED;
		}

		/* Initialize the state we'll store over the replication cycle */
		getnc_state = talloc_zero(b_state, struct drsuapi_getncchanges_state);
		if (getnc_state == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		b_state->getncchanges_state = getnc_state;

		getnc_state->ncRoot_dn = ncRoot_dn;
		talloc_steal(getnc_state, ncRoot_dn);

		getnc_state->ncRoot_guid = samdb_result_guid(res->msgs[0],
							     "objectGUID");
		ncRoot->guid = getnc_state->ncRoot_guid;

		/* find out if we are to replicate Schema NC */
		ret = ldb_dn_compare_base(ldb_get_schema_basedn(sam_ctx),
					  ncRoot_dn);
		getnc_state->is_schema_nc = (0 == ret);

		TALLOC_FREE(res);
	}

	if (!ldb_dn_validate(getnc_state->ncRoot_dn) ||
	    ldb_dn_is_null(getnc_state->ncRoot_dn)) {
		DEBUG(0,(__location__ ": Bad DN '%s'\n",
			 drs_ObjectIdentifier_to_string(mem_ctx, ncRoot)));
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	ncRoot->guid = getnc_state->ncRoot_guid;

	/* we need the session key for encrypting password attributes */
	status = dcesrv_auth_session_key(dce_call, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": Failed to get session key\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	/* 
	   TODO: MS-DRSR section 4.1.10.1.1
	   Work out if this is the start of a new cycle */

	if (getnc_state->guids == NULL) {
		const char *extra_filter;
		struct ldb_result *search_res = NULL;
		static const struct drsuapi_DsReplicaCursorCtrEx empty_udv;
		const struct drsuapi_DsReplicaCursorCtrEx *udv = NULL;

		extra_filter = lpcfg_parm_string(dce_call->conn->dce_ctx->lp_ctx, NULL, "drs", "object filter");

		if (req10->extended_op == DRSUAPI_EXOP_NONE) {
			if (req10->uptodateness_vector != NULL) {
				udv = req10->uptodateness_vector;
			} else {
				udv = &empty_udv;
			}

			getnc_state->min_usn = req10->highwatermark.highest_usn;
			for (i = 0; i < udv->count; i++) {
				bool match;
				const struct drsuapi_DsReplicaCursor *cur =
					&udv->cursors[i];

				match = GUID_equal(&invocation_id,
						   &cur->source_dsa_invocation_id);
				if (!match) {
					continue;
				}
				if (cur->highest_usn > getnc_state->min_usn) {
					getnc_state->min_usn = cur->highest_usn;
				}
				break;
			}
		} else {
			/* We do not want REPL_SECRETS or REPL_SINGLE to return empty-handed */
			udv = &empty_udv;
			getnc_state->min_usn = 0;
		}

		getnc_state->max_usn = getnc_state->min_usn;

		getnc_state->final_udv = talloc_zero(getnc_state,
					struct drsuapi_DsReplicaCursor2CtrEx);
		if (getnc_state->final_udv == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		werr = get_nc_changes_udv(sam_ctx, getnc_state->ncRoot_dn,
					  getnc_state->final_udv);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		if (req10->extended_op == DRSUAPI_EXOP_NONE) {
			werr = getncchanges_collect_objects(b_state, mem_ctx, req10,
							    search_dn, extra_filter,
							    &search_res);
		} else {
			werr = getncchanges_collect_objects_exop(b_state, mem_ctx, req10,
								 &r->out.ctr->ctr6,
								 search_dn, extra_filter,
								 &search_res);
		}
		W_ERROR_NOT_OK_RETURN(werr);

		/* extract out the GUIDs list */
		getnc_state->num_records = search_res ? search_res->count : 0;
		getnc_state->guids = talloc_array(getnc_state, struct GUID, getnc_state->num_records);
		W_ERROR_HAVE_NO_MEMORY(getnc_state->guids);

		changes = talloc_array(getnc_state,
				       struct drsuapi_changed_objects,
				       getnc_state->num_records);
		W_ERROR_HAVE_NO_MEMORY(changes);

		for (i=0; i<getnc_state->num_records; i++) {
			changes[i].dn = search_res->msgs[i]->dn;
			changes[i].guid = samdb_result_guid(search_res->msgs[i], "objectGUID");
			changes[i].usn = ldb_msg_find_attr_as_uint64(search_res->msgs[i], "uSNChanged", 0);

			if (changes[i].usn > getnc_state->max_usn) {
				getnc_state->max_usn = changes[i].usn;
			}
		}

		/* RID_ALLOC returns 3 objects in a fixed order */
		if (req10->extended_op == DRSUAPI_EXOP_FSMO_RID_ALLOC) {
			/* Do nothing */
		} else {
			LDB_TYPESAFE_QSORT(changes,
					   getnc_state->num_records,
					   getnc_state,
					   site_res_cmp_usn_order);
		}

		for (i=0; i < getnc_state->num_records; i++) {
			getnc_state->guids[i] = changes[i].guid;
			if (GUID_all_zero(&getnc_state->guids[i])) {
				DEBUG(2,("getncchanges: bad objectGUID from %s\n",
					 ldb_dn_get_linearized(search_res->msgs[i]->dn)));
				return WERR_DS_DRA_INTERNAL_ERROR;
			}
		}

		getnc_state->final_hwm.tmp_highest_usn = getnc_state->max_usn;
		getnc_state->final_hwm.reserved_usn = 0;
		getnc_state->final_hwm.highest_usn = getnc_state->max_usn;

		talloc_free(search_res);
		talloc_free(changes);

		if (req10->extended_op == DRSUAPI_EXOP_NONE) {
			getnc_state->is_get_anc =
				((req10->replica_flags & DRSUAPI_DRS_GET_ANC) != 0);
			getnc_state->is_get_tgt =
				((req10->more_flags & DRSUAPI_DRS_GET_TGT) != 0);
		}

		/*
		 * when using GET_ANC or GET_TGT, cache the objects that have
		 * been already sent, to avoid sending them multiple times
		 */
		if (getnc_state->is_get_anc || getnc_state->is_get_tgt) {
			DEBUG(3,("Using object cache, GET_ANC %u, GET_TGT %u\n",
				 getnc_state->is_get_anc,
				 getnc_state->is_get_tgt));

			getnc_state->obj_cache = db_open_rbt(getnc_state);
			if (getnc_state->obj_cache == NULL) {
				return WERR_NOT_ENOUGH_MEMORY;
			}
		}
	}

	if (req10->uptodateness_vector) {
		/* make sure its sorted */
		TYPESAFE_QSORT(req10->uptodateness_vector->cursors,
			       req10->uptodateness_vector->count,
			       drsuapi_DsReplicaCursor_compare);
	}

	/* Prefix mapping */
	schema = dsdb_get_schema(sam_ctx, mem_ctx);
	if (!schema) {
		DEBUG(0,("No schema in sam_ctx\n"));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	r->out.ctr->ctr6.naming_context = talloc(mem_ctx, struct drsuapi_DsReplicaObjectIdentifier);
	if (r->out.ctr->ctr6.naming_context == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	*r->out.ctr->ctr6.naming_context = *ncRoot;

	/* find the SID if there is one */
	dsdb_find_sid_by_dn(sam_ctx, getnc_state->ncRoot_dn, &r->out.ctr->ctr6.naming_context->sid);

	dsdb_get_oid_mappings_drsuapi(schema, true, mem_ctx, &ctr);
	r->out.ctr->ctr6.mapping_ctr = *ctr;

	r->out.ctr->ctr6.source_dsa_guid = *(samdb_ntds_objectGUID(sam_ctx));
	r->out.ctr->ctr6.source_dsa_invocation_id = *(samdb_ntds_invocation_id(sam_ctx));

	r->out.ctr->ctr6.old_highwatermark = req10->highwatermark;
	r->out.ctr->ctr6.new_highwatermark = req10->highwatermark;

	/*
	 * If the client has already set GET_TGT then we know they can handle
	 * receiving the linked attributes interleaved with the source objects
	 */
	if (getnc_state->is_get_tgt) {
		repl_chunk->immediate_link_sync = true;
	}

	if (req10->partial_attribute_set != NULL) {
		struct dsdb_syntax_ctx syntax_ctx;
		uint32_t j = 0;

		dsdb_syntax_ctx_init(&syntax_ctx, sam_ctx, schema);
		syntax_ctx.pfm_remote = pfm_remote;

		local_pas = talloc_array(b_state, uint32_t, req10->partial_attribute_set->num_attids);

		for (j = 0; j < req10->partial_attribute_set->num_attids; j++) {
			getncchanges_attid_remote_to_local(schema,
							   &syntax_ctx,
							   req10->partial_attribute_set->attids[j],
							   (enum drsuapi_DsAttributeId *)&local_pas[j],
							   NULL);
		}

		TYPESAFE_QSORT(local_pas,
			       req10->partial_attribute_set->num_attids,
			       uint32_t_ptr_cmp);
	}

	/*
	 * Check in case we're still processing the links from an object in the
	 * previous chunk. We want to send the links (and any targets needed)
	 * before moving on to the next object.
	 */
	if (getnc_state->is_get_tgt) {
		werr = getncchanges_chunk_add_la_targets(repl_chunk,
							 getnc_state,
							 getnc_state->la_idx,
							 mem_ctx, sam_ctx,
							 schema, &session_key,
							 req10, local_pas,
							 machine_dn);

		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
	}

	for (i=getnc_state->num_processed;
	     i<getnc_state->num_records &&
		     !getncchanges_chunk_is_full(repl_chunk, getnc_state);
	    i++) {
		struct drsuapi_DsReplicaObjectListItemEx *new_objs = NULL;
		struct ldb_message *msg;
		static const char * const msg_attrs[] = {
					    "*",
					    "nTSecurityDescriptor",
					    "parentGUID",
					    "replPropertyMetaData",
					    DSDB_SECRET_ATTRIBUTES,
					    NULL };
		struct ldb_result *msg_res;
		struct ldb_dn *msg_dn;
		bool obj_already_sent = false;
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		uint32_t old_la_index;

		msg_dn = ldb_dn_new_fmt(tmp_ctx, sam_ctx, "<GUID=%s>",
					GUID_string(tmp_ctx, &getnc_state->guids[i]));
		W_ERROR_HAVE_NO_MEMORY(msg_dn);

		/*
		 * by re-searching here we avoid having a lot of full
		 * records in memory between calls to getncchanges.
		 *
		 * We expect that we may get some objects that vanish
		 * (tombstone expunge) between the first and second
		 * check.
		 */
		ret = drsuapi_search_with_extended_dn(sam_ctx, tmp_ctx, &msg_res,
						      msg_dn,
						      LDB_SCOPE_BASE, msg_attrs, NULL);
		if (ret != LDB_SUCCESS) {
			if (ret != LDB_ERR_NO_SUCH_OBJECT) {
				DEBUG(1,("getncchanges: failed to fetch DN %s - %s\n",
					 ldb_dn_get_extended_linearized(tmp_ctx, msg_dn, 1),
					 ldb_errstring(sam_ctx)));
			}
			TALLOC_FREE(tmp_ctx);
			continue;
		}

		if (msg_res->count == 0) {
			DEBUG(1,("getncchanges: got LDB_SUCCESS but failed"
				 "to get any results in fetch of DN "
				 "%s (race with tombstone expunge?)\n",
				 ldb_dn_get_extended_linearized(tmp_ctx,
								msg_dn, 1)));
			TALLOC_FREE(tmp_ctx);
			continue;
		}

		msg = msg_res->msgs[0];

		/*
		 * Check if we've already sent the object as an ancestor of
		 * another object. If so, we don't need to send it again
		 */
		if (getnc_state->obj_cache != NULL) {
			werr = dcesrv_drsuapi_obj_cache_exists(getnc_state->obj_cache,
							       &getnc_state->guids[i]);
			if (W_ERROR_EQUAL(werr, WERR_OBJECT_NAME_EXISTS)) {
				obj_already_sent = true;
			}
		}

		if (!obj_already_sent) {
			bool max_wait_reached;

			max_wait_reached = getncchanges_chunk_timed_out(repl_chunk);

			/*
			 * Construct an object, ready to send (this will include
			 * the object's ancestors as well, if needed)
			 */
			werr = getncchanges_get_obj_to_send(msg, mem_ctx, sam_ctx,
							    getnc_state, schema,
							    &session_key, req10,
							    max_wait_reached,
							    local_pas, machine_dn,
							    &getnc_state->guids[i],
							    &new_objs);
			if (!W_ERROR_IS_OK(werr)) {
				return werr;
			}
		}

		old_la_index = getnc_state->la_count;

		/*
		 * We've reached the USN where this object naturally occurs.
		 * Regardless of whether we've already sent the object (as an
		 * ancestor), we add its links and update the HWM at this point
		 */
		werr = get_nc_changes_add_links(sam_ctx, getnc_state,
						getnc_state->is_schema_nc,
						schema, getnc_state->min_usn,
						req10->replica_flags,
						msg,
						&getnc_state->la_list,
						&getnc_state->la_count,
						req10->uptodateness_vector);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		dcesrv_drsuapi_update_highwatermark(msg,
					getnc_state->max_usn,
					&r->out.ctr->ctr6.new_highwatermark);

		if (new_objs != NULL) {

			/*
			 * Add the object (and, if GET_ANC, any parents it may
			 * have) into the current chunk of replication data
			 */
			getncchanges_chunk_add_objects(repl_chunk, new_objs);

			talloc_free(getnc_state->last_dn);
			getnc_state->last_dn = talloc_move(getnc_state, &msg->dn);
		}

		DEBUG(8,(__location__ ": %s object %s\n",
			 new_objs ? "replicating" : "skipping send of",
			 ldb_dn_get_linearized(msg->dn)));

		getnc_state->total_links += (getnc_state->la_count - old_la_index);

		/*
		 * If the GET_TGT flag was set, check any new links added to
		 * make sure the client knows about the link target object
		 */
		if (getnc_state->is_get_tgt) {
			werr = getncchanges_chunk_add_la_targets(repl_chunk,
								 getnc_state,
								 old_la_index,
								 mem_ctx, sam_ctx,
								 schema, &session_key,
								 req10, local_pas,
								 machine_dn);

			if (!W_ERROR_IS_OK(werr)) {
				return werr;
			}
		}

		TALLOC_FREE(tmp_ctx);
	}

	/* copy the constructed object list into the response message */
	r->out.ctr->ctr6.object_count = repl_chunk->object_count;
	r->out.ctr->ctr6.first_object = repl_chunk->object_list;

	getnc_state->num_processed = i;

	if (i < getnc_state->num_records) {
		r->out.ctr->ctr6.more_data = true;
	}

	/* the client can us to call UpdateRefs on its behalf to
	   re-establish monitoring of the NC */
	if ((req10->replica_flags & (DRSUAPI_DRS_ADD_REF | DRSUAPI_DRS_REF_GCSPN)) &&
	    !GUID_all_zero(&req10->destination_dsa_guid)) {
		struct drsuapi_DsReplicaUpdateRefsRequest1 ureq;
		DEBUG(3,("UpdateRefs on getncchanges for %s\n",
			 GUID_string(mem_ctx, &req10->destination_dsa_guid)));
		ureq.naming_context = ncRoot;
		ureq.dest_dsa_dns_name = samdb_ntds_msdcs_dns_name(sam_ctx, mem_ctx,
								   &req10->destination_dsa_guid);
		if (!ureq.dest_dsa_dns_name) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		ureq.dest_dsa_guid = req10->destination_dsa_guid;
		ureq.options = DRSUAPI_DRS_ADD_REF |
			DRSUAPI_DRS_ASYNC_OP |
			DRSUAPI_DRS_GETCHG_CHECK;

		/* we also need to pass through the
		   DRSUAPI_DRS_REF_GCSPN bit so that repsTo gets flagged
		   to send notifies using the GC SPN */
		ureq.options |= (req10->replica_flags & DRSUAPI_DRS_REF_GCSPN);

		werr = drsuapi_UpdateRefs(imsg_ctx,
					  dce_call->event_ctx,
					  b_state,
					  mem_ctx,
					  &ureq);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__ ": Failed UpdateRefs on %s for %s in DsGetNCChanges - %s\n",
				 drs_ObjectIdentifier_to_string(mem_ctx, ncRoot), ureq.dest_dsa_dns_name,
				 win_errstr(werr)));
		}
	}

	/*
	 * Work out how many links we can send in this chunk. The default is to
	 * send all the links last, but there is a config option to send them
	 * immediately, in the same chunk as their source object
	 */
	if (!r->out.ctr->ctr6.more_data || repl_chunk->immediate_link_sync) {
		link_count = getncchanges_chunk_links_pending(repl_chunk,
							      getnc_state);
		link_count = MIN(link_count,
				 getncchanges_chunk_max_links(repl_chunk));
	}

	/* If we've got linked attributes to send, add them now */
	if (link_count > 0) {
		struct la_for_sorting *la_sorted;

		/*
		 * Grab a chunk of linked attributes off the list and put them
		 * in sorted array, ready to send
		 */
		werr = getncchanges_get_sorted_array(&getnc_state->la_list[getnc_state->la_idx],
						     link_count,
						     sam_ctx, getnc_state,
						     schema,
						     &la_sorted);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		r->out.ctr->ctr6.linked_attributes_count = link_count;
		r->out.ctr->ctr6.linked_attributes = talloc_array(r->out.ctr, struct drsuapi_DsReplicaLinkedAttribute, link_count);
		if (r->out.ctr->ctr6.linked_attributes == NULL) {
			DEBUG(0, ("Out of memory allocating %u linked attributes for output", link_count));
			return WERR_NOT_ENOUGH_MEMORY;
		}

		for (k = 0; k < link_count; k++) {
			r->out.ctr->ctr6.linked_attributes[k] = *la_sorted[k].link;
		}

		getnc_state->la_idx += link_count;
		getnc_state->links_given += link_count;

		if (getnc_state->la_idx < getnc_state->la_count) {
			r->out.ctr->ctr6.more_data = true;
		} else {

			/*
			 * We've now sent all the links seen so far, so we can
			 * reset la_list back to an empty list again. Note that
			 * the steal means the linked attribute memory gets
			 * freed after this RPC message is sent on the wire.
			 */
			talloc_steal(mem_ctx, getnc_state->la_list);
			getnc_state->la_list = NULL;
			getnc_state->la_idx = 0;
			getnc_state->la_count = 0;
		}

		TALLOC_FREE(la_sorted);
	}

	if (req10->replica_flags & DRSUAPI_DRS_GET_NC_SIZE) {
		/*
		 * TODO: This implementation is wrong
		 * we should find out the total number of
		 * objects and links in the whole naming context
		 * at the start of the cycle and return these
		 * values in each message.
		 *
		 * For now we keep our current strategy and return
		 * the number of objects for this cycle and the number
		 * of links we found so far during the cycle.
		 */
		r->out.ctr->ctr6.nc_object_count = getnc_state->num_records;
		r->out.ctr->ctr6.nc_linked_attributes_count = getnc_state->total_links;
	}

	if (!r->out.ctr->ctr6.more_data) {

		/* this is the last response in the replication cycle */
		r->out.ctr->ctr6.new_highwatermark = getnc_state->final_hwm;
		r->out.ctr->ctr6.uptodateness_vector = talloc_move(mem_ctx,
							&getnc_state->final_udv);

		/*
		 * Free the state info stored for the replication cycle. Note
		 * that the RPC message we're sending contains links stored in
		 * getnc_state. mem_ctx is local to this RPC call, so the memory
		 * will get freed after the RPC message is sent on the wire.
		 */
		talloc_steal(mem_ctx, getnc_state);
		b_state->getncchanges_state = NULL;
	} else {
		ret = drsuapi_DsReplicaHighWaterMark_cmp(&r->out.ctr->ctr6.old_highwatermark,
							 &r->out.ctr->ctr6.new_highwatermark);
		if (ret == 0) {
			/*
			 * We need to make sure that we never return the
			 * same highwatermark within the same replication
			 * cycle more than once. Otherwise we cannot detect
			 * when the client uses an unexptected highwatermark.
			 *
			 * This is a HACK which is needed because our
			 * object ordering is wrong and set tmp_highest_usn
			 * to a value that is higher than what we already
			 * sent to the client (destination dsa).
			 */
			r->out.ctr->ctr6.new_highwatermark.reserved_usn += 1;
		}

		getnc_state->last_hwm = r->out.ctr->ctr6.new_highwatermark;
	}

	if (req10->extended_op != DRSUAPI_EXOP_NONE) {
		r->out.ctr->ctr6.uptodateness_vector = NULL;
		r->out.ctr->ctr6.nc_object_count = 0;
		ZERO_STRUCT(r->out.ctr->ctr6.new_highwatermark);
	}

	TALLOC_FREE(repl_chunk);

	DEBUG(r->out.ctr->ctr6.more_data?4:2,
	      ("DsGetNCChanges with uSNChanged >= %llu flags 0x%08x on %s gave %u objects (done %u/%u) %u links (done %u/%u (as %s))\n",
	       (unsigned long long)(req10->highwatermark.highest_usn+1),
	       req10->replica_flags, drs_ObjectIdentifier_to_string(mem_ctx, ncRoot),
	       r->out.ctr->ctr6.object_count,
	       i, r->out.ctr->ctr6.more_data?getnc_state->num_records:i,
	       r->out.ctr->ctr6.linked_attributes_count,
	       getnc_state->links_given, getnc_state->total_links,
	       dom_sid_string(mem_ctx, user_sid)));

#if 0
	if (!r->out.ctr->ctr6.more_data && req10->extended_op != DRSUAPI_EXOP_NONE) {
		NDR_PRINT_FUNCTION_DEBUG(drsuapi_DsGetNCChanges, NDR_BOTH, r);
	}
#endif

	return WERR_OK;
}

