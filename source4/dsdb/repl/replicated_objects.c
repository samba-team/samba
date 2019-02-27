/* 
   Unix SMB/CIFS mplementation.
   Helper functions for applying replicated objects
   
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
    
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
#include "dsdb/samdb/samdb.h"
#include <ldb_errors.h>
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "../libcli/drsuapi/drsuapi.h"
#include "libcli/auth/libcli_auth.h"
#include "param/param.h"

#undef DBGC_CLASS
#define DBGC_CLASS            DBGC_DRS_REPL

static WERROR dsdb_repl_merge_working_schema(struct ldb_context *ldb,
					     struct dsdb_schema *dest_schema,
					     const struct dsdb_schema *ref_schema)
{
	const struct dsdb_class *cur_class = NULL;
	const struct dsdb_attribute *cur_attr = NULL;
	int ret;

	for (cur_class = ref_schema->classes;
	     cur_class;
	     cur_class = cur_class->next)
	{
		const struct dsdb_class *tmp1;
		struct dsdb_class *tmp2;

		tmp1 = dsdb_class_by_governsID_id(dest_schema,
						  cur_class->governsID_id);
		if (tmp1 != NULL) {
			continue;
		}

		/*
		 * Do a shallow copy so that original next and prev are
		 * not modified, we don't need to do a deep copy
		 * as the rest won't be modified and this is for
		 * a short lived object.
		 */
		tmp2 = talloc(dest_schema, struct dsdb_class);
		if (tmp2 == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		*tmp2 = *cur_class;
		DLIST_ADD(dest_schema->classes, tmp2);
	}

	for (cur_attr = ref_schema->attributes;
	     cur_attr;
	     cur_attr = cur_attr->next)
	{
		const struct dsdb_attribute *tmp1;
		struct dsdb_attribute *tmp2;

		tmp1 = dsdb_attribute_by_attributeID_id(dest_schema,
						cur_attr->attributeID_id);
		if (tmp1 != NULL) {
			continue;
		}

		/*
		 * Do a shallow copy so that original next and prev are
		 * not modified, we don't need to do a deep copy
		 * as the rest won't be modified and this is for
		 * a short lived object.
		 */
		tmp2 = talloc(dest_schema, struct dsdb_attribute);
		if (tmp2 == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		*tmp2 = *cur_attr;
		DLIST_ADD(dest_schema->attributes, tmp2);
	}

	ret = dsdb_setup_sorted_accessors(ldb, dest_schema);
	if (LDB_SUCCESS != ret) {
		DEBUG(0,("Failed to add new attribute to reference schema!\n"));
		return WERR_INTERNAL_ERROR;
	}

	return WERR_OK;
}

WERROR dsdb_repl_resolve_working_schema(struct ldb_context *ldb,
					struct dsdb_schema_prefixmap *pfm_remote,
					uint32_t cycle_before_switching,
					struct dsdb_schema *initial_schema,
					struct dsdb_schema *resulting_schema,
					uint32_t object_count,
					const struct drsuapi_DsReplicaObjectListItemEx *first_object)
{
	struct schema_list {
		struct schema_list *next, *prev;
		const struct drsuapi_DsReplicaObjectListItemEx *obj;
	};
	struct schema_list *schema_list = NULL, *schema_list_item, *schema_list_next_item;
	WERROR werr;
	struct dsdb_schema *working_schema;
	const struct drsuapi_DsReplicaObjectListItemEx *cur;
	DATA_BLOB empty_key = data_blob_null;
	int ret, pass_no;
	uint32_t ignore_attids[] = {
			DRSUAPI_ATTID_auxiliaryClass,
			DRSUAPI_ATTID_mayContain,
			DRSUAPI_ATTID_mustContain,
			DRSUAPI_ATTID_possSuperiors,
			DRSUAPI_ATTID_systemPossSuperiors,
			DRSUAPI_ATTID_INVALID
	};
	TALLOC_CTX *frame = talloc_stackframe();

	/* create a list of objects yet to be converted */
	for (cur = first_object; cur; cur = cur->next_object) {
		schema_list_item = talloc(frame, struct schema_list);
		if (schema_list_item == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		schema_list_item->obj = cur;
		DLIST_ADD_END(schema_list, schema_list_item);
	}

	/* resolve objects until all are resolved and in local schema */
	pass_no = 1;
	working_schema = initial_schema;

	while (schema_list) {
		uint32_t converted_obj_count = 0;
		uint32_t failed_obj_count = 0;

		if (resulting_schema != working_schema) {
			/*
			 * If the selfmade schema is not the schema used to
			 * translate and validate replicated object,
			 * Which means that we are using the bootstrap schema
			 * Then we add attributes and classes that were already
			 * translated to the working schema, the idea is that
			 * we might need to add new attributes and classes
			 * to be able to translate critical replicated objects
			 * and without that we wouldn't be able to translate them
			 */
			werr = dsdb_repl_merge_working_schema(ldb,
							working_schema,
							resulting_schema);
			if (!W_ERROR_IS_OK(werr)) {
				talloc_free(frame);
				return werr;
			}
		}

		for (schema_list_item = schema_list;
		     schema_list_item;
		     schema_list_item=schema_list_next_item) {
			struct dsdb_extended_replicated_object object;

			cur = schema_list_item->obj;

			/*
			 * Save the next item, now we have saved out
			 * the current one, so we can DLIST_REMOVE it
			 * safely
			 */
			schema_list_next_item = schema_list_item->next;

			/*
			 * Convert the objects into LDB messages using the
			 * schema we have so far. It's ok if we fail to convert
			 * an object. We should convert more objects on next pass.
			 */
			werr = dsdb_convert_object_ex(ldb, working_schema,
						      NULL,
						      pfm_remote,
						      cur, &empty_key,
						      ignore_attids,
						      0,
						      schema_list_item, &object);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(4,("debug: Failed to convert schema "
					 "object %s into ldb msg, "
					 "will try during next loop\n",
					 cur->object.identifier->dn));

				failed_obj_count++;
			} else {
				/*
				 * Convert the schema from ldb_message format
				 * (OIDs as OID strings) into schema, using
				 * the remote prefixMap
				 *
				 * It's not likely, but possible to get the
				 * same object twice and we should keep
				 * the last instance.
				 */
				werr = dsdb_schema_set_el_from_ldb_msg_dups(ldb,
								resulting_schema,
								object.msg,
								true);
				if (!W_ERROR_IS_OK(werr)) {
					DEBUG(4,("debug: failed to convert "
						 "object %s into a schema element, "
						 "will try during next loop: %s\n",
						 ldb_dn_get_linearized(object.msg->dn),
						 win_errstr(werr)));
					failed_obj_count++;
				} else {
					DEBUG(8,("Converted object %s into a schema element\n",
						 ldb_dn_get_linearized(object.msg->dn)));
					DLIST_REMOVE(schema_list, schema_list_item);
					TALLOC_FREE(schema_list_item);
					converted_obj_count++;
				}
			}
		}

		DEBUG(4,("Schema load pass %d: converted %d, %d of %d objects left to be converted.\n",
			 pass_no, converted_obj_count, failed_obj_count, object_count));

		/* check if we converted any objects in this pass */
		if (converted_obj_count == 0) {
			DEBUG(0,("Can't continue Schema load: "
				 "didn't manage to convert any objects: "
				 "all %d remaining of %d objects "
				 "failed to convert\n",
				 failed_obj_count, object_count));
			talloc_free(frame);
			return WERR_INTERNAL_ERROR;
		}

		/*
		 * Don't try to load the schema if there is missing object
		 * _and_ we are on the first pass as some critical objects
		 * might be missing.
		 */
		if (failed_obj_count == 0 || pass_no > cycle_before_switching) {
			/* prepare for another cycle */
			working_schema = resulting_schema;

			ret = dsdb_setup_sorted_accessors(ldb, working_schema);
			if (LDB_SUCCESS != ret) {
				DEBUG(0,("Failed to create schema-cache indexes!\n"));
				talloc_free(frame);
				return WERR_INTERNAL_ERROR;
			}
		}
		pass_no++;
	}

	talloc_free(frame);
	return WERR_OK;
}

/**
 * Multi-pass working schema creation
 * Function will:
 *  - shallow copy initial schema supplied
 *  - create a working schema in multiple passes
 *    until all objects are resolved
 * Working schema is a schema with Attributes, Classes
 * and indexes, but w/o subClassOf, possibleSupperiors etc.
 * It is to be used just us cache for converting attribute values.
 */
WERROR dsdb_repl_make_working_schema(struct ldb_context *ldb,
				     const struct dsdb_schema *initial_schema,
				     const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr,
				     uint32_t object_count,
				     const struct drsuapi_DsReplicaObjectListItemEx *first_object,
				     const DATA_BLOB *gensec_skey,
				     TALLOC_CTX *mem_ctx,
				     struct dsdb_schema **_schema_out)
{
	WERROR werr;
	struct dsdb_schema_prefixmap *pfm_remote;
	uint32_t r;
	struct dsdb_schema *working_schema;

	/* make a copy of the iniatial_scheam so we don't mess with it */
	working_schema = dsdb_schema_copy_shallow(mem_ctx, ldb, initial_schema);
	if (!working_schema) {
		DEBUG(0,(__location__ ": schema copy failed!\n"));
		return WERR_NOT_ENOUGH_MEMORY;
	}
	working_schema->resolving_in_progress = true;

	/* we are going to need remote prefixMap for decoding */
	werr = dsdb_schema_pfm_from_drsuapi_pfm(mapping_ctr, true,
						working_schema, &pfm_remote, NULL);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,(__location__ ": Failed to decode remote prefixMap: %s\n",
			 win_errstr(werr)));
		talloc_free(working_schema);
		return werr;
	}

	for (r=0; r < pfm_remote->length; r++) {
		const struct dsdb_schema_prefixmap_oid *rm = &pfm_remote->prefixes[r];
		bool found_oid = false;
		uint32_t l;

		for (l=0; l < working_schema->prefixmap->length; l++) {
			const struct dsdb_schema_prefixmap_oid *lm = &working_schema->prefixmap->prefixes[l];
			int cmp;

			cmp = data_blob_cmp(&rm->bin_oid, &lm->bin_oid);
			if (cmp == 0) {
				found_oid = true;
				break;
			}
		}

		if (found_oid) {
			continue;
		}

		/*
		 * We prefer the same is as we got from the remote peer
		 * if there's no conflict.
		 */
		werr = dsdb_schema_pfm_add_entry(working_schema->prefixmap,
						 rm->bin_oid, &rm->id, NULL);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__ ": Failed to merge remote prefixMap: %s",
				 win_errstr(werr)));
			talloc_free(working_schema);
			return werr;
		}
	}

	werr = dsdb_repl_resolve_working_schema(ldb,
						pfm_remote,
						0, /* cycle_before_switching */
						working_schema,
						working_schema,
						object_count,
						first_object);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("%s: dsdb_repl_resolve_working_schema() failed: %s",
			  __location__, win_errstr(werr)));
		talloc_free(working_schema);
		return werr;
	}

	working_schema->resolving_in_progress = false;

	*_schema_out = working_schema;

	return WERR_OK;
}

static bool dsdb_attid_in_list(const uint32_t attid_list[], uint32_t attid)
{
	const uint32_t *cur;
	if (!attid_list) {
		return false;
	}
	for (cur = attid_list; *cur != DRSUAPI_ATTID_INVALID; cur++) {
		if (*cur == attid) {
			return true;
		}
	}
	return false;
}

WERROR dsdb_convert_object_ex(struct ldb_context *ldb,
			      const struct dsdb_schema *schema,
			      struct ldb_dn *partition_dn,
			      const struct dsdb_schema_prefixmap *pfm_remote,
			      const struct drsuapi_DsReplicaObjectListItemEx *in,
			      const DATA_BLOB *gensec_skey,
			      const uint32_t *ignore_attids,
			      uint32_t dsdb_repl_flags,
			      TALLOC_CTX *mem_ctx,
			      struct dsdb_extended_replicated_object *out)
{
	WERROR status = WERR_OK;
	uint32_t i;
	struct ldb_message *msg;
	struct replPropertyMetaDataBlob *md;
	int instanceType;
	struct ldb_message_element *instanceType_e = NULL;
	NTTIME whenChanged = 0;
	time_t whenChanged_t;
	const char *whenChanged_s;
	struct dom_sid *sid = NULL;
	uint32_t rid = 0;
	uint32_t attr_count;

	if (!in->object.identifier) {
		return WERR_FOOBAR;
	}

	if (!in->object.identifier->dn || !in->object.identifier->dn[0]) {
		return WERR_FOOBAR;
	}

	if (in->object.attribute_ctr.num_attributes != 0 && !in->meta_data_ctr) {
		return WERR_FOOBAR;
	}

	if (in->object.attribute_ctr.num_attributes != in->meta_data_ctr->count) {
		return WERR_FOOBAR;
	}

	sid = &in->object.identifier->sid;
	if (sid->num_auths > 0) {
		rid = sid->sub_auths[sid->num_auths - 1];
	}

	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn			= ldb_dn_new(msg, ldb, in->object.identifier->dn);
	W_ERROR_HAVE_NO_MEMORY(msg->dn);

	msg->num_elements	= in->object.attribute_ctr.num_attributes;
	msg->elements		= talloc_array(msg, struct ldb_message_element,
					       msg->num_elements);
	W_ERROR_HAVE_NO_MEMORY(msg->elements);

	md = talloc(mem_ctx, struct replPropertyMetaDataBlob);
	W_ERROR_HAVE_NO_MEMORY(md);

	md->version		= 1;
	md->reserved		= 0;
	md->ctr.ctr1.count	= in->meta_data_ctr->count;
	md->ctr.ctr1.reserved	= 0;
	md->ctr.ctr1.array	= talloc_array(mem_ctx,
					       struct replPropertyMetaData1,
					       md->ctr.ctr1.count);
	W_ERROR_HAVE_NO_MEMORY(md->ctr.ctr1.array);

	for (i=0, attr_count=0; i < in->meta_data_ctr->count; i++, attr_count++) {
		struct drsuapi_DsReplicaAttribute *a;
		struct drsuapi_DsReplicaMetaData *d;
		struct replPropertyMetaData1 *m;
		struct ldb_message_element *e;
		uint32_t j;

		a = &in->object.attribute_ctr.attributes[i];
		d = &in->meta_data_ctr->meta_data[i];
		m = &md->ctr.ctr1.array[attr_count];
		e = &msg->elements[attr_count];

		if (dsdb_attid_in_list(ignore_attids, a->attid)) {
			attr_count--;
			continue;
		}

		if (GUID_all_zero(&d->originating_invocation_id)) {
			status = WERR_DS_SRC_GUID_MISMATCH;
			DEBUG(0, ("Refusing replication of object containing invalid zero invocationID on attribute %d of %s: %s\n",
				  a->attid,
				  ldb_dn_get_linearized(msg->dn),
				  win_errstr(status)));
			return status;
		}

		if (a->attid == DRSUAPI_ATTID_instanceType) {
			if (instanceType_e != NULL) {
				return WERR_FOOBAR;
			}
			instanceType_e = e;
		}

		for (j=0; j<a->value_ctr.num_values; j++) {
			status = drsuapi_decrypt_attribute(a->value_ctr.values[j].blob,
							   gensec_skey, rid,
							   dsdb_repl_flags, a);
			if (!W_ERROR_IS_OK(status)) {
				break;
			}
		}
		if (W_ERROR_EQUAL(status, WERR_TOO_MANY_SECRETS)) {
			WERROR get_name_status = dsdb_attribute_drsuapi_to_ldb(ldb, schema, pfm_remote,
									       a, msg->elements, e, NULL);
			if (W_ERROR_IS_OK(get_name_status)) {
				DEBUG(0, ("Unxpectedly got secret value %s on %s from DRS server\n",
					  e->name, ldb_dn_get_linearized(msg->dn)));
			} else {
				DEBUG(0, ("Unxpectedly got secret value on %s from DRS server",
					  ldb_dn_get_linearized(msg->dn)));
			}
		} else if (!W_ERROR_IS_OK(status)) {
			return status;
		}

		/*
		 * This function also fills in the local attid value,
		 * based on comparing the remote and local prefixMap
		 * tables.  If we don't convert the value, then we can
		 * have invalid values in the replPropertyMetaData we
		 * store on disk, as the prefixMap is per host, not
		 * per-domain.  This may be why Microsoft added the
		 * msDS-IntID feature, however this is not used for
		 * extra attributes in the schema partition itself.
		 */
		status = dsdb_attribute_drsuapi_to_ldb(ldb, schema, pfm_remote,
						       a, msg->elements, e,
						       &m->attid);
		W_ERROR_NOT_OK_RETURN(status);

		m->version			= d->version;
		m->originating_change_time	= d->originating_change_time;
		m->originating_invocation_id	= d->originating_invocation_id;
		m->originating_usn		= d->originating_usn;
		m->local_usn			= 0;

		if (a->attid == DRSUAPI_ATTID_name) {
			const struct ldb_val *rdn_val = ldb_dn_get_rdn_val(msg->dn);
			if (rdn_val == NULL) {
				DEBUG(0, ("Unxpectedly unable to get RDN from %s for validation",
					  ldb_dn_get_linearized(msg->dn)));
				return WERR_FOOBAR;
			}
			if (e->num_values != 1) {
				DEBUG(0, ("Unxpectedly got wrong number of attribute values (got %u, expected 1) when checking RDN against name of %s",
					  e->num_values,
					  ldb_dn_get_linearized(msg->dn)));
				return WERR_FOOBAR;
			}
			if (data_blob_cmp(rdn_val,
					  &e->values[0]) != 0) {
				DEBUG(0, ("Unxpectedly got mismatching RDN values when checking RDN against name of %s",
					  ldb_dn_get_linearized(msg->dn)));
				return WERR_FOOBAR;
			}
		}
		if (d->originating_change_time > whenChanged) {
			whenChanged = d->originating_change_time;
		}

	}

	msg->num_elements = attr_count;
	md->ctr.ctr1.count = attr_count;

	if (instanceType_e == NULL) {
		return WERR_FOOBAR;
	}

	instanceType = ldb_msg_find_attr_as_int(msg, "instanceType", 0);

	if ((instanceType & INSTANCE_TYPE_IS_NC_HEAD)
	    && partition_dn != NULL) {
		int partition_dn_cmp = ldb_dn_compare(partition_dn, msg->dn);
		if (partition_dn_cmp != 0) {
			DEBUG(4, ("Remote server advised us of a new partition %s while processing %s, ignoring\n",
				  ldb_dn_get_linearized(msg->dn),
				  ldb_dn_get_linearized(partition_dn)));
			return WERR_DS_ADD_REPLICA_INHIBITED;
		}
	}

	if (dsdb_repl_flags & DSDB_REPL_FLAG_PARTIAL_REPLICA) {
		/* the instanceType type for partial_replica
		   replication is sent via DRS with TYPE_WRITE set, but
		   must be used on the client with TYPE_WRITE removed
		*/
		if (instanceType & INSTANCE_TYPE_WRITE) {
			/*
			 * Make sure we do not change the order
			 * of msg->elements!
			 *
			 * That's why we use
			 * instanceType_e->num_values = 0
			 * instead of
			 * ldb_msg_remove_attr(msg, "instanceType");
			 */
			struct ldb_message_element *e;

			e = ldb_msg_find_element(msg, "instanceType");
			if (e != instanceType_e) {
				DEBUG(0,("instanceType_e[%p] changed to e[%p]\n",
					 instanceType_e, e));
				return WERR_FOOBAR;
			}

			instanceType_e->num_values = 0;

			instanceType &= ~INSTANCE_TYPE_WRITE;
			if (ldb_msg_add_fmt(msg, "instanceType", "%d", instanceType) != LDB_SUCCESS) {
				return WERR_INTERNAL_ERROR;
			}
		}
	} else {
		if (!(instanceType & INSTANCE_TYPE_WRITE)) {
			DBG_ERR("Refusing to replicate %s from a read-only "
				"replica into a read-write replica!\n",
				ldb_dn_get_linearized(msg->dn));
			return WERR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA;
		}
	}

	whenChanged_t = nt_time_to_unix(whenChanged);
	whenChanged_s = ldb_timestring(msg, whenChanged_t);
	W_ERROR_HAVE_NO_MEMORY(whenChanged_s);

	out->object_guid = in->object.identifier->guid;

	if (in->parent_object_guid == NULL) {
		out->parent_guid = NULL;
	} else {
		out->parent_guid = talloc(mem_ctx, struct GUID);
		W_ERROR_HAVE_NO_MEMORY(out->parent_guid);
		*out->parent_guid = *in->parent_object_guid;
	}

	out->msg		= msg;
	out->when_changed	= whenChanged_s;
	out->meta_data		= md;
	return WERR_OK;
}

WERROR dsdb_replicated_objects_convert(struct ldb_context *ldb,
				       const struct dsdb_schema *schema,
				       struct ldb_dn *partition_dn,
				       const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr,
				       uint32_t object_count,
				       const struct drsuapi_DsReplicaObjectListItemEx *first_object,
				       uint32_t linked_attributes_count,
				       const struct drsuapi_DsReplicaLinkedAttribute *linked_attributes,
				       const struct repsFromTo1 *source_dsa,
				       const struct drsuapi_DsReplicaCursor2CtrEx *uptodateness_vector,
				       const DATA_BLOB *gensec_skey,
				       uint32_t dsdb_repl_flags,
				       TALLOC_CTX *mem_ctx,
				       struct dsdb_extended_replicated_objects **objects)
{
	WERROR status;
	struct dsdb_schema_prefixmap *pfm_remote;
	struct dsdb_extended_replicated_objects *out;
	const struct drsuapi_DsReplicaObjectListItemEx *cur;
	struct dsdb_syntax_ctx syntax_ctx;
	uint32_t i;

	out = talloc_zero(mem_ctx, struct dsdb_extended_replicated_objects);
	W_ERROR_HAVE_NO_MEMORY(out);
	out->version		= DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION;
	out->dsdb_repl_flags    = dsdb_repl_flags;

	/*
	 * Ensure schema is kept valid for as long as 'out'
	 * which may contain pointers to it
	 */
	schema = talloc_reference(out, schema);
	W_ERROR_HAVE_NO_MEMORY(schema);

	status = dsdb_schema_pfm_from_drsuapi_pfm(mapping_ctr, true,
						  out, &pfm_remote, NULL);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,(__location__ ": Failed to decode remote prefixMap: %s\n",
			 win_errstr(status)));
		talloc_free(out);
		return status;
	}

	/* use default syntax conversion context */
	dsdb_syntax_ctx_init(&syntax_ctx, ldb, schema);
	syntax_ctx.pfm_remote = pfm_remote;

	if (ldb_dn_compare(partition_dn, ldb_get_schema_basedn(ldb)) != 0) {
		/*
		 * check for schema changes in case
		 * we are not replicating Schema NC
		 */
		status = dsdb_schema_info_cmp(schema, mapping_ctr);
		if (!W_ERROR_IS_OK(status)) {
			DEBUG(4,("Can't replicate %s because remote schema has changed since we last replicated the schema\n",
				 ldb_dn_get_linearized(partition_dn)));
			talloc_free(out);
			return status;
		}
	}

	out->partition_dn	= partition_dn;

	out->source_dsa		= source_dsa;
	out->uptodateness_vector= uptodateness_vector;

	out->num_objects	= 0;
	out->objects		= talloc_array(out,
					       struct dsdb_extended_replicated_object,
					       object_count);
	W_ERROR_HAVE_NO_MEMORY_AND_FREE(out->objects, out);

	for (i=0, cur = first_object; cur; cur = cur->next_object, i++) {
		if (i == object_count) {
			talloc_free(out);
			return WERR_FOOBAR;
		}

		status = dsdb_convert_object_ex(ldb, schema, out->partition_dn,
						pfm_remote,
						cur, gensec_skey,
						NULL,
						dsdb_repl_flags,
						out->objects,
						&out->objects[out->num_objects]);

		/*
		 * Check to see if we have been advised of a
		 * subdomain or new application partition.  We don't
		 * want to start on that here, instead the caller
		 * should consider if it would like to replicate it
		 * based on the cross-ref object.
		 */
		if (W_ERROR_EQUAL(status, WERR_DS_ADD_REPLICA_INHIBITED)) {
			struct GUID_txt_buf guid_str;
			DBG_ERR("Ignoring object outside partition %s %s: %s\n",
				GUID_buf_string(&cur->object.identifier->guid,
						&guid_str),
				cur->object.identifier->dn,
				win_errstr(status));
			continue;
		}

		if (!W_ERROR_IS_OK(status)) {
			talloc_free(out);
			DEBUG(0,("Failed to convert object %s: %s\n",
				 cur->object.identifier->dn,
				 win_errstr(status)));
			return status;
		}

		/* Assuming we didn't skip or error, increment the number of objects */
		out->num_objects++;
	}
	out->objects = talloc_realloc(out, out->objects,
				      struct dsdb_extended_replicated_object,
				      out->num_objects);
	if (out->num_objects != 0 && out->objects == NULL) {
		talloc_free(out);
		return WERR_FOOBAR;
	}
	if (i != object_count) {
		talloc_free(out);
		return WERR_FOOBAR;
	}

	out->linked_attributes = talloc_array(out,
					      struct drsuapi_DsReplicaLinkedAttribute,
					      linked_attributes_count);
	W_ERROR_HAVE_NO_MEMORY_AND_FREE(out->linked_attributes, out);

	for (i=0; i < linked_attributes_count; i++) {
		const struct drsuapi_DsReplicaLinkedAttribute *ra = &linked_attributes[i];
		struct drsuapi_DsReplicaLinkedAttribute *la = &out->linked_attributes[i];

		if (ra->identifier == NULL) {
			talloc_free(out);
			return WERR_BAD_NET_RESP;
		}

		*la = *ra;

		la->identifier = talloc_zero(out->linked_attributes,
					     struct drsuapi_DsReplicaObjectIdentifier);
		W_ERROR_HAVE_NO_MEMORY_AND_FREE(la->identifier, out);

		/*
		 * We typically only get the guid filled
		 * and the repl_meta_data module only cares abouf
		 * the guid.
		 */
		la->identifier->guid = ra->identifier->guid;

		if (ra->value.blob != NULL) {
			la->value.blob = talloc_zero(out->linked_attributes,
						     DATA_BLOB);
			W_ERROR_HAVE_NO_MEMORY_AND_FREE(la->value.blob, out);

			if (ra->value.blob->length != 0) {
				*la->value.blob = data_blob_dup_talloc(la->value.blob,
								       *ra->value.blob);
				W_ERROR_HAVE_NO_MEMORY_AND_FREE(la->value.blob->data, out);
			}
		}

		status = dsdb_attribute_drsuapi_remote_to_local(&syntax_ctx,
								ra->attid,
								&la->attid,
								NULL);
		if (!W_ERROR_IS_OK(status)) {
			DEBUG(0,(__location__": linked_attribute[%u] attid 0x%08X not found: %s\n",
				 i, ra->attid, win_errstr(status)));
			return status;
		}
	}

	out->linked_attributes_count = linked_attributes_count;

	/* free pfm_remote, we won't need it anymore */
	talloc_free(pfm_remote);

	*objects = out;
	return WERR_OK;
}

/**
 * Commits a list of replicated objects.
 *
 * @param working_schema dsdb_schema to be used for resolving
 * 			 Classes/Attributes during Schema replication. If not NULL,
 * 			 it will be set on ldb and used while committing replicated objects
 */
WERROR dsdb_replicated_objects_commit(struct ldb_context *ldb,
				      struct dsdb_schema *working_schema,
				      struct dsdb_extended_replicated_objects *objects,
				      uint64_t *notify_uSN)
{
	WERROR werr;
	struct ldb_result *ext_res;
	struct dsdb_schema *cur_schema = NULL;
	struct dsdb_schema *new_schema = NULL;
	int ret;
	uint64_t seq_num1, seq_num2;
	bool used_global_schema = false;

	TALLOC_CTX *tmp_ctx = talloc_new(objects);
	if (!tmp_ctx) {
		DEBUG(0,("Failed to start talloc\n"));
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/* wrap the extended operation in a transaction 
	   See [MS-DRSR] 3.3.2 Transactions
	 */
	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ " Failed to start transaction: %s\n",
			 ldb_errstring(ldb)));
		return WERR_FOOBAR;
	}

	ret = dsdb_load_partition_usn(ldb, objects->partition_dn, &seq_num1, NULL);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ " Failed to load partition uSN\n"));
		ldb_transaction_cancel(ldb);
		TALLOC_FREE(tmp_ctx);
		return WERR_FOOBAR;		
	}

	/*
	 * Set working_schema for ldb in case we are replicating from Schema NC.
	 * Schema won't be reloaded during Replicated Objects commit, as it is
	 * done in a transaction. So we need some way to search for newly
	 * added Classes and Attributes
	 */
	if (working_schema) {
		/* store current schema so we can fall back in case of failure */
		cur_schema = dsdb_get_schema(ldb, tmp_ctx);
		used_global_schema = dsdb_uses_global_schema(ldb);

		ret = dsdb_reference_schema(ldb, working_schema, SCHEMA_MEMORY_ONLY);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ "Failed to reference working schema - %s\n",
				 ldb_strerror(ret)));
			/* TODO: Map LDB Error to NTSTATUS? */
			ldb_transaction_cancel(ldb);
			TALLOC_FREE(tmp_ctx);
			return WERR_INTERNAL_ERROR;
		}
	}

	ret = ldb_extended(ldb, DSDB_EXTENDED_REPLICATED_OBJECTS_OID, objects, &ext_res);
	if (ret != LDB_SUCCESS) {
		/* restore previous schema */
		if (used_global_schema) { 
			dsdb_set_global_schema(ldb);
		} else if (cur_schema) {
			dsdb_reference_schema(ldb, cur_schema, SCHEMA_MEMORY_ONLY);
		}

		if (W_ERROR_EQUAL(objects->error, WERR_DS_DRA_RECYCLED_TARGET)) {
			DEBUG(3,("Missing target while attempting to apply records: %s\n",
				 ldb_errstring(ldb)));
		} else if (W_ERROR_EQUAL(objects->error, WERR_DS_DRA_MISSING_PARENT)) {
			DEBUG(3,("Missing parent while attempting to apply records: %s\n",
				 ldb_errstring(ldb)));
		} else {
			DEBUG(1,("Failed to apply records: %s: %s\n",
				 ldb_errstring(ldb), ldb_strerror(ret)));
		}
		ldb_transaction_cancel(ldb);
		TALLOC_FREE(tmp_ctx);

		if (!W_ERROR_IS_OK(objects->error)) {
			return objects->error;
		}
		return WERR_FOOBAR;
	}
	talloc_free(ext_res);

	/* Save our updated prefixMap and check the schema is good. */
	if (working_schema) {
		struct ldb_result *ext_res_2;

		werr = dsdb_write_prefixes_from_schema_to_ldb(working_schema,
							      ldb,
							      working_schema);
		if (!W_ERROR_IS_OK(werr)) {
			/* restore previous schema */
			if (used_global_schema) { 
				dsdb_set_global_schema(ldb);
			} else if (cur_schema ) {
				dsdb_reference_schema(ldb,
						      cur_schema,
						      SCHEMA_MEMORY_ONLY);
			}
			DEBUG(0,("Failed to save updated prefixMap: %s\n",
				 win_errstr(werr)));
			ldb_transaction_cancel(ldb);
			TALLOC_FREE(tmp_ctx);
			return werr;
		}

		/*
		 * Use dsdb_schema_from_db through dsdb extended to check we
		 * can load the schema currently sitting in the transaction.
		 * We need this check because someone might have written to
		 * the schema or prefixMap before we started the transaction,
		 * which may have caused corruption.
		 */
		ret = ldb_extended(ldb, DSDB_EXTENDED_SCHEMA_LOAD,
				   NULL, &ext_res_2);

		if (ret != LDB_SUCCESS) {
			if (used_global_schema) {
				dsdb_set_global_schema(ldb);
			} else if (cur_schema) {
				dsdb_reference_schema(ldb, cur_schema, SCHEMA_MEMORY_ONLY);
			}
			DEBUG(0,("Corrupt schema write attempt detected, "
				 "aborting schema modification operation.\n"
				 "This probably happened due to bad timing of "
				 "another schema edit: %s (%s)\n",
				 ldb_errstring(ldb),
				 ldb_strerror(ret)));
			ldb_transaction_cancel(ldb);
			TALLOC_FREE(tmp_ctx);
			return WERR_FOOBAR;
		}
	}

	ret = ldb_transaction_prepare_commit(ldb);
	if (ret != LDB_SUCCESS) {
		/* restore previous schema */
		if (used_global_schema) { 
			dsdb_set_global_schema(ldb);
		} else if (cur_schema ) {
			dsdb_reference_schema(ldb, cur_schema, SCHEMA_MEMORY_ONLY);
		}
		DBG_ERR(" Failed to prepare commit of transaction: %s (%s)\n",
			ldb_errstring(ldb),
			ldb_strerror(ret));
		TALLOC_FREE(tmp_ctx);
		return WERR_FOOBAR;
	}

	ret = dsdb_load_partition_usn(ldb, objects->partition_dn, &seq_num2, NULL);
	if (ret != LDB_SUCCESS) {
		/* restore previous schema */
		if (used_global_schema) { 
			dsdb_set_global_schema(ldb);
		} else if (cur_schema ) {
			dsdb_reference_schema(ldb, cur_schema, SCHEMA_MEMORY_ONLY);
		}
		DEBUG(0,(__location__ " Failed to load partition uSN\n"));
		ldb_transaction_cancel(ldb);
		TALLOC_FREE(tmp_ctx);
		return WERR_FOOBAR;		
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		/* restore previous schema */
		if (used_global_schema) { 
			dsdb_set_global_schema(ldb);
		} else if (cur_schema ) {
			dsdb_reference_schema(ldb, cur_schema, SCHEMA_MEMORY_ONLY);
		}
		DEBUG(0,(__location__ " Failed to commit transaction\n"));
		TALLOC_FREE(tmp_ctx);
		return WERR_FOOBAR;
	}

	if (seq_num1 > *notify_uSN) {
		/*
		 * A notify was already required before
		 * the current transaction.
		 */
	} else if (objects->originating_updates) {
		/*
		 * Applying the replicated changes
		 * required originating updates,
		 * so a notify is required.
		 */
	} else {
		/*
		 * There's no need to notify the
		 * server about the change we just from it.
		 */
		*notify_uSN = seq_num2;
	}

	/*
	 * Reset the Schema used by ldb. This will lead to
	 * a schema cache being refreshed from database.
	 */
	if (working_schema) {
		/* Reload the schema */
		new_schema = dsdb_get_schema(ldb, tmp_ctx);
		/* TODO:
		 * If dsdb_get_schema() fails, we just fall back
		 * to what we had.  However, the database is probably
		 * unable to operate for other users from this
		 * point... */
		if (new_schema == NULL || new_schema == working_schema) {
			DBG_ERR("Failed to re-load schema after commit of "
				"transaction (working: %p/%"PRIu64", new: "
				"%p/%"PRIu64")\n", new_schema,
				new_schema != NULL ?
				new_schema->metadata_usn : 0,
				working_schema, working_schema->metadata_usn);
			dsdb_reference_schema(ldb, cur_schema, SCHEMA_MEMORY_ONLY);
			if (used_global_schema) {
				dsdb_set_global_schema(ldb);
			}
			TALLOC_FREE(tmp_ctx);
			return WERR_INTERNAL_ERROR;
		} else if (used_global_schema) {
			dsdb_make_schema_global(ldb, new_schema);
		}
	}

	DEBUG(2,("Replicated %u objects (%u linked attributes) for %s\n",
		 objects->num_objects, objects->linked_attributes_count,
		 ldb_dn_get_linearized(objects->partition_dn)));
		 
	TALLOC_FREE(tmp_ctx);
	return WERR_OK;
}

static WERROR dsdb_origin_object_convert(struct ldb_context *ldb,
					 const struct dsdb_schema *schema,
					 const struct drsuapi_DsReplicaObjectListItem *in,
					 TALLOC_CTX *mem_ctx,
					 struct ldb_message **_msg)
{
	WERROR status;
	unsigned int i;
	struct ldb_message *msg;

	if (!in->object.identifier) {
		return WERR_FOOBAR;
	}

	if (!in->object.identifier->dn || !in->object.identifier->dn[0]) {
		return WERR_FOOBAR;
	}

	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn	= ldb_dn_new(msg, ldb, in->object.identifier->dn);
	W_ERROR_HAVE_NO_MEMORY(msg->dn);

	msg->num_elements	= in->object.attribute_ctr.num_attributes;
	msg->elements		= talloc_array(msg, struct ldb_message_element,
					       msg->num_elements);
	W_ERROR_HAVE_NO_MEMORY(msg->elements);

	for (i=0; i < msg->num_elements; i++) {
		struct drsuapi_DsReplicaAttribute *a;
		struct ldb_message_element *e;

		a = &in->object.attribute_ctr.attributes[i];
		e = &msg->elements[i];

		status = dsdb_attribute_drsuapi_to_ldb(ldb, schema, schema->prefixmap,
						       a, msg->elements, e, NULL);
		W_ERROR_NOT_OK_RETURN(status);
	}


	*_msg = msg;

	return WERR_OK;
}

WERROR dsdb_origin_objects_commit(struct ldb_context *ldb,
				  TALLOC_CTX *mem_ctx,
				  const struct drsuapi_DsReplicaObjectListItem *first_object,
				  uint32_t *_num,
				  uint32_t dsdb_repl_flags,
				  struct drsuapi_DsReplicaObjectIdentifier2 **_ids)
{
	WERROR status;
	const struct dsdb_schema *schema;
	const struct drsuapi_DsReplicaObjectListItem *cur;
	struct ldb_message **objects;
	struct drsuapi_DsReplicaObjectIdentifier2 *ids;
	uint32_t i;
	uint32_t num_objects = 0;
	const char * const attrs[] = {
		"objectGUID",
		"objectSid",
		NULL
	};
	struct ldb_result *res;
	int ret;

	for (cur = first_object; cur; cur = cur->next_object) {
		num_objects++;
	}

	if (num_objects == 0) {
		return WERR_OK;
	}

	ret = ldb_transaction_start(ldb);
	if (ret != LDB_SUCCESS) {
		return WERR_DS_INTERNAL_FAILURE;
	}

	objects	= talloc_array(mem_ctx, struct ldb_message *,
			       num_objects);
	if (objects == NULL) {
		status = WERR_NOT_ENOUGH_MEMORY;
		goto cancel;
	}

	schema = dsdb_get_schema(ldb, objects);
	if (!schema) {
		return WERR_DS_SCHEMA_NOT_LOADED;
	}

	for (i=0, cur = first_object; cur; cur = cur->next_object, i++) {
		status = dsdb_origin_object_convert(ldb, schema, cur,
						    objects, &objects[i]);
		if (!W_ERROR_IS_OK(status)) {
			goto cancel;
		}
	}

	ids = talloc_array(mem_ctx,
			   struct drsuapi_DsReplicaObjectIdentifier2,
			   num_objects);
	if (ids == NULL) {
		status = WERR_NOT_ENOUGH_MEMORY;
		goto cancel;
	}

	if (dsdb_repl_flags & DSDB_REPL_FLAG_ADD_NCNAME) {
		/* check for possible NC creation */
		for (i=0; i < num_objects; i++) {
			struct ldb_message *msg = objects[i];
			struct ldb_message_element *el;
			struct ldb_dn *nc_dn;

			if (ldb_msg_check_string_attribute(msg, "objectClass", "crossRef") == 0) {
				continue;
			}
			el = ldb_msg_find_element(msg, "nCName");
			if (el == NULL || el->num_values != 1) {
				continue;
			}
			nc_dn = ldb_dn_from_ldb_val(objects, ldb, &el->values[0]);
			if (!ldb_dn_validate(nc_dn)) {
				continue;
			}
			ret = dsdb_create_partial_replica_NC(ldb, nc_dn);
			if (ret != LDB_SUCCESS) {
				status = WERR_DS_INTERNAL_FAILURE;
				goto cancel;
			}
		}
	}

	for (i=0; i < num_objects; i++) {
		struct dom_sid *sid = NULL;
		struct ldb_request *add_req;

		DEBUG(6,(__location__ ": adding %s\n", 
			 ldb_dn_get_linearized(objects[i]->dn)));

		ret = ldb_build_add_req(&add_req,
					ldb,
					objects,
					objects[i],
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
		if (ret != LDB_SUCCESS) {
			status = WERR_DS_INTERNAL_FAILURE;
			goto cancel;
		}

		ret = ldb_request_add_control(add_req, LDB_CONTROL_RELAX_OID, true, NULL);
		if (ret != LDB_SUCCESS) {
			status = WERR_DS_INTERNAL_FAILURE;
			goto cancel;
		}
		
		ret = ldb_request(ldb, add_req);
		if (ret == LDB_SUCCESS) {
			ret = ldb_wait(add_req->handle, LDB_WAIT_ALL);
		}
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed add of %s - %s\n",
				 ldb_dn_get_linearized(objects[i]->dn), ldb_errstring(ldb)));
			status = WERR_DS_INTERNAL_FAILURE;
			goto cancel;
		}

		talloc_free(add_req);

		ret = ldb_search(ldb, objects, &res, objects[i]->dn,
				 LDB_SCOPE_BASE, attrs,
				 "(objectClass=*)");
		if (ret != LDB_SUCCESS) {
			status = WERR_DS_INTERNAL_FAILURE;
			goto cancel;
		}
		ids[i].guid = samdb_result_guid(res->msgs[0], "objectGUID");
		sid = samdb_result_dom_sid(objects, res->msgs[0], "objectSid");
		if (sid) {
			ids[i].sid = *sid;
		} else {
			ZERO_STRUCT(ids[i].sid);
		}
	}

	ret = ldb_transaction_commit(ldb);
	if (ret != LDB_SUCCESS) {
		return WERR_DS_INTERNAL_FAILURE;
	}

	talloc_free(objects);

	*_num = num_objects;
	*_ids = ids;
	return WERR_OK;

cancel:
	talloc_free(objects);
	ldb_transaction_cancel(ldb);
	return status;
}
