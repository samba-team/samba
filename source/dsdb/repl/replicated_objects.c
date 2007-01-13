/* 
   Unix SMB/CIFS mplementation.
   Helper functions for applying replicated objects
   
   Copyright (C) Stefan Metzmacher 2007
    
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
*/

#include "includes.h"
#include "dsdb/samdb/samdb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"

static WERROR dsdb_convert_object(struct ldb_context *ldb,
				  const struct dsdb_schema *schema,
				  struct dsdb_extended_replicated_objects *ctr,
				  const struct drsuapi_DsReplicaObjectListItemEx *in,
				  TALLOC_CTX *mem_ctx,
				  struct dsdb_extended_replicated_object *out)
{
	NTSTATUS nt_status;
	WERROR status;
	uint32_t i;
	struct ldb_message *msg;
	struct replPropertyMetaDataBlob *md;
	struct ldb_val guid_value;
	NTTIME whenChanged = 0;
	time_t whenChanged_t;
	const char *whenChanged_s;
	const char *rdn_name = NULL;
	const struct ldb_val *rdn_value = NULL;
	const struct dsdb_attribute *rdn_attr = NULL;
	uint32_t rdn_attid;
	struct drsuapi_DsReplicaAttribute *name_a = NULL;
	struct drsuapi_DsReplicaMetaData *name_d = NULL;
	struct replPropertyMetaData1 *rdn_m = NULL;
	int ret;

	if (!in->object.identifier) {
		return WERR_FOOBAR;
	}

	if (!in->object.identifier->dn || !in->object.identifier->dn[0]) {
		return WERR_FOOBAR;
	}

	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn			= ldb_dn_new(msg, ldb, in->object.identifier->dn);
	W_ERROR_HAVE_NO_MEMORY(msg->dn);

	rdn_name	= ldb_dn_get_rdn_name(msg->dn);
	rdn_attr	= dsdb_attribute_by_lDAPDisplayName(schema, rdn_name);
	if (!rdn_attr) {
		return WERR_FOOBAR;
	}
	rdn_attid	= rdn_attr->attributeID_id;
	rdn_value	= ldb_dn_get_rdn_val(msg->dn);

	msg->num_elements	= in->object.attribute_ctr.num_attributes;
	msg->elements		= talloc_array(msg, struct ldb_message_element,
					       msg->num_elements);
	W_ERROR_HAVE_NO_MEMORY(msg->elements);

	for (i=0; i < msg->num_elements; i++) {
		status = dsdb_attribute_drsuapi_to_ldb(schema,
						       &in->object.attribute_ctr.attributes[i],
						       msg->elements, &msg->elements[i]);
		W_ERROR_NOT_OK_RETURN(status);
	}

	if (in->object.attribute_ctr.num_attributes != 0 && !in->meta_data_ctr) {
		return WERR_FOOBAR;
	}

	if (in->object.attribute_ctr.num_attributes != in->meta_data_ctr->count) {
		return WERR_FOOBAR;
	}

	md = talloc(mem_ctx, struct replPropertyMetaDataBlob);
	W_ERROR_HAVE_NO_MEMORY(md);

	md->version		= 1;
	md->reserved		= 0;
	md->ctr.ctr1.count	= in->meta_data_ctr->count;
	md->ctr.ctr1.reserved	= 0;
	md->ctr.ctr1.array	= talloc_array(mem_ctx,
					       struct replPropertyMetaData1,
					       md->ctr.ctr1.count + 1); /* +1 because of the RDN attribute */
	W_ERROR_HAVE_NO_MEMORY(md->ctr.ctr1.array);

	for (i=0; i < in->meta_data_ctr->count; i++) {
		struct drsuapi_DsReplicaAttribute *a;
		struct drsuapi_DsReplicaMetaData *d;
		struct replPropertyMetaData1 *m;

		a = &in->object.attribute_ctr.attributes[i];
		d = &in->meta_data_ctr->meta_data[i];
		m = &md->ctr.ctr1.array[i];

		m->attid			= a->attid;
		m->version			= d->version;
		m->orginating_time		= d->orginating_time;
		m->orginating_invocation_id	= d->orginating_invocation_id;
		m->orginating_usn		= d->orginating_usn;
		m->local_usn			= 0;

		if (d->orginating_time > whenChanged) {
			whenChanged = d->orginating_time;
		}

		if (a->attid == DRSUAPI_ATTRIBUTE_name) {
			name_a = a;
			name_d = d;
			rdn_m = &md->ctr.ctr1.array[md->ctr.ctr1.count];
		}
	}

	if (rdn_m) {
		ret = ldb_msg_add_value(msg, rdn_attr->lDAPDisplayName, rdn_value, NULL);
		if (ret != LDB_SUCCESS) {
			return WERR_FOOBAR;
		}

		rdn_m->attid				= rdn_attid;
		rdn_m->version				= name_d->version;
		rdn_m->orginating_time			= name_d->orginating_time;
		rdn_m->orginating_invocation_id		= name_d->orginating_invocation_id;
		rdn_m->orginating_usn			= name_d->orginating_usn;
		rdn_m->local_usn			= 0;
		md->ctr.ctr1.count++;

	}

	whenChanged_t = nt_time_to_unix(whenChanged);
	whenChanged_s = ldb_timestring(msg, whenChanged_t);
	W_ERROR_HAVE_NO_MEMORY(whenChanged_s);

	nt_status = ndr_push_struct_blob(&guid_value, msg, &in->object.identifier->guid,
					 (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ntstatus_to_werror(nt_status);
	}

	out->msg		= msg;
	out->guid_value		= guid_value;
	out->when_changed	= whenChanged_s;
	out->meta_data		= md;
	return WERR_OK;
}

WERROR dsdb_extended_replicated_objects_commit(struct ldb_context *ldb,
					       const char *partition_dn,
					       const struct dsdb_schema *schema,
					       const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr,
					       uint32_t object_count,
					       const struct drsuapi_DsReplicaObjectListItemEx *first_object,
					       uint32_t linked_attributes_count,
					       const struct drsuapi_DsReplicaLinkedAttribute *linked_attributes,
					       const struct repsFromTo1 *source_dsa,
					       const struct drsuapi_DsReplicaCursor2CtrEx *uptodateness_vector,
					       TALLOC_CTX *mem_ctx,
					       struct dsdb_extended_replicated_objects **_out)
{
	WERROR status;
	struct dsdb_extended_replicated_objects *out;
	struct ldb_result *ext_res;
	const struct drsuapi_DsReplicaObjectListItemEx *cur;
	uint32_t i;
	int ret;

	status = dsdb_verify_oid_mappings(schema, mapping_ctr);
	W_ERROR_NOT_OK_RETURN(status);

	out = talloc_zero(mem_ctx, struct dsdb_extended_replicated_objects);
	W_ERROR_HAVE_NO_MEMORY(out);

	out->partition_dn = ldb_dn_new(out, ldb, partition_dn);
	W_ERROR_HAVE_NO_MEMORY(out->partition_dn);

	out->source_dsa		= source_dsa;
	out->uptodateness_vector= uptodateness_vector;

	out->num_objects	= object_count;
	out->objects		= talloc_array(out,
					       struct dsdb_extended_replicated_object,
					       out->num_objects);
	W_ERROR_HAVE_NO_MEMORY(out->objects);

	for (i=0, cur = first_object; cur; cur = cur->next_object, i++) {
		if (i == out->num_objects) {
			return WERR_FOOBAR;
		}

		status = dsdb_convert_object(ldb, schema, out, cur, out->objects, &out->objects[i]);
		W_ERROR_NOT_OK_RETURN(status);
	}
	if (i != out->num_objects) {
		return WERR_FOOBAR;
	}

	/* TODO: handle linked attributes */

	ret = ldb_extended(ldb, DSDB_EXTENDED_REPLICATED_OBJECTS_OID, out, &ext_res);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to apply records: %d\n",
			ret));
		talloc_free(out);
		return WERR_FOOBAR;
	}
	talloc_free(ext_res);

	if (_out) {
		*_out = out;
	} else {
		talloc_free(out);
	}

	return WERR_OK;
}
