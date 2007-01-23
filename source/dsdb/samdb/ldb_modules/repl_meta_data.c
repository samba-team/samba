/* 
   ldb database library

   Copyright (C) Simo Sorce  2004-2006
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher 2007

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb repl_meta_data module
 *
 *  Description: - add a unique objectGUID onto every new record,
 *               - handle whenCreated, whenChanged timestamps
 *               - handle uSNCreated, uSNChanged numbers
 *               - handle replPropertyMetaData attribute
 *
 *  Author: Simo Sorce
 *  Author: Stefan Metzmacher
 */

#include "includes.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"

struct replmd_replicated_request {
	struct ldb_module *module;
	struct ldb_handle *handle;
	struct ldb_request *orig_req;

	const struct dsdb_schema *schema;

	struct dsdb_extended_replicated_objects *objs;

	uint32_t index_current;

	struct {
		TALLOC_CTX *mem_ctx;
		struct ldb_request *search_req;
		struct ldb_message *search_msg;
		int search_ret;
		struct ldb_request *change_req;
		int change_ret;
	} sub;
};

static struct replmd_replicated_request *replmd_replicated_init_handle(struct ldb_module *module,
								       struct ldb_request *req,
								       struct dsdb_extended_replicated_objects *objs)
{
	struct replmd_replicated_request *ar;
	struct ldb_handle *h;
	const struct dsdb_schema *schema;

	schema = dsdb_get_schema(module->ldb);
	if (!schema) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "replmd_replicated_init_handle: no loaded schema found\n");
		return NULL;
	}

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module	= module;
	h->state	= LDB_ASYNC_PENDING;
	h->status	= LDB_SUCCESS;

	ar = talloc_zero(h, struct replmd_replicated_request);
	if (ar == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data	= ar;

	ar->module	= module;
	ar->handle	= h;
	ar->orig_req	= req;
	ar->schema	= schema;
	ar->objs	= objs;

	req->handle = h;

	return ar;
}

static struct ldb_message_element *replmd_find_attribute(const struct ldb_message *msg, const char *name)
{
	int i;

	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(name, msg->elements[i].name) == 0) {
			return &msg->elements[i];
		}
	}

	return NULL;
}

/*
  add a time element to a record
*/
static int add_time_element(struct ldb_message *msg, const char *attr, time_t t)
{
	struct ldb_message_element *el;
	char *s;

	if (ldb_msg_find_element(msg, attr) != NULL) {
		return 0;
	}

	s = ldb_timestring(msg, t);
	if (s == NULL) {
		return -1;
	}

	if (ldb_msg_add_string(msg, attr, s) != 0) {
		return -1;
	}

	el = ldb_msg_find_element(msg, attr);
	/* always set as replace. This works because on add ops, the flag
	   is ignored */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return 0;
}

/*
  add a uint64_t element to a record
*/
static int add_uint64_element(struct ldb_message *msg, const char *attr, uint64_t v)
{
	struct ldb_message_element *el;

	if (ldb_msg_find_element(msg, attr) != NULL) {
		return 0;
	}

	if (ldb_msg_add_fmt(msg, attr, "%llu", (unsigned long long)v) != 0) {
		return -1;
	}

	el = ldb_msg_find_element(msg, attr);
	/* always set as replace. This works because on add ops, the flag
	   is ignored */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return 0;
}

static int replmd_replPropertyMetaData1_attid_sort(const struct replPropertyMetaData1 *m1,
						   const struct replPropertyMetaData1 *m2,
						   const uint32_t *rdn_attid)
{
	if (m1->attid == m2->attid) {
		return 0;
	}

	/*
	 * the rdn attribute should be at the end!
	 * so we need to return a value greater than zero
	 * which means m1 is greater than m2
	 */
	if (m1->attid == *rdn_attid) {
		return 1;
	}

	/*
	 * the rdn attribute should be at the end!
	 * so we need to return a value less than zero
	 * which means m2 is greater than m1
	 */
	if (m2->attid == *rdn_attid) {
		return -1;
	}

	return m1->attid - m2->attid;
}

static void replmd_replPropertyMetaDataCtr1_sort(struct replPropertyMetaDataCtr1 *ctr1,
						 const uint32_t *rdn_attid)
{
	ldb_qsort(ctr1->array, ctr1->count, sizeof(struct replPropertyMetaData1),
		  discard_const_p(void, rdn_attid), (ldb_qsort_cmp_fn_t)replmd_replPropertyMetaData1_attid_sort);
}

static int replmd_ldb_message_element_attid_sort(const struct ldb_message_element *e1,
						 const struct ldb_message_element *e2,
						 const struct dsdb_schema *schema)
{
	const struct dsdb_attribute *a1;
	const struct dsdb_attribute *a2;

	/* 
	 * TODO: make this faster by caching the dsdb_attribute pointer
	 *       on the ldb_messag_element
	 */

	a1 = dsdb_attribute_by_lDAPDisplayName(schema, e1->name);
	a2 = dsdb_attribute_by_lDAPDisplayName(schema, e2->name);

	/*
	 * TODO: remove this check, we should rely on e1 and e2 having valid attribute names
	 *       in the schema
	 */
	if (!a1 || !a2) {
		return strcasecmp(e1->name, e2->name);
	}

	return a1->attributeID_id - a2->attributeID_id;
}

static void replmd_ldb_message_sort(struct ldb_message *msg,
				    const struct dsdb_schema *schema)
{
	ldb_qsort(msg->elements, msg->num_elements, sizeof(struct ldb_message_element),
		  discard_const_p(void, schema), (ldb_qsort_cmp_fn_t)replmd_ldb_message_element_attid_sort);
}

static int replmd_prepare_originating(struct ldb_module *module, struct ldb_request *req,
				      struct ldb_dn *dn, const char *fn_name,
				      int (*fn)(struct ldb_module *,
			 			struct ldb_request *,
						const struct dsdb_schema *,
						const struct dsdb_control_current_partition *))
{
	const struct dsdb_schema *schema;
	const struct ldb_control *partition_ctrl;
	const struct dsdb_control_current_partition *partition;
 
	/* do not manipulate our control entries */
	if (ldb_dn_is_special(dn)) {
		return ldb_next_request(module, req);
	}

	schema = dsdb_get_schema(module->ldb);
	if (!schema) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "%s: no dsdb_schema loaded",
			      fn_name);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	partition_ctrl = get_control_from_list(req->controls, DSDB_CONTROL_CURRENT_PARTITION_OID);
	if (!partition_ctrl) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "%s: no current partition control found",
			      fn_name);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	partition = talloc_get_type(partition_ctrl->data,
				    struct dsdb_control_current_partition);
	if (!partition) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "%s: current partition control contains invalid data",
			      fn_name);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (partition->version != DSDB_CONTROL_CURRENT_PARTITION_VERSION) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "%s: current partition control contains invalid version [%u != %u]\n",
			      fn_name, partition->version, DSDB_CONTROL_CURRENT_PARTITION_VERSION);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	return fn(module, req, schema, partition);
}

static int replmd_add_originating(struct ldb_module *module,
				  struct ldb_request *req,
				  const struct dsdb_schema *schema,
				  const struct dsdb_control_current_partition *partition)
{
	struct ldb_request *down_req;
	struct ldb_message_element *attribute;
	struct ldb_message *msg;
	struct ldb_val v;
	struct GUID guid;
	uint64_t seq_num;
	NTSTATUS nt_status;
	int ret;
	time_t t = time(NULL);

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "replmd_add_originating\n");

	if ((attribute = replmd_find_attribute(req->op.add.message, "objectGUID")) != NULL ) {
		return ldb_next_request(module, req);
	}

	down_req = talloc(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*down_req = *req;

	/* we have to copy the message as the caller might have it as a const */
	down_req->op.add.message = msg = ldb_msg_copy_shallow(down_req, req->op.add.message);
	if (msg == NULL) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* a new GUID */
	guid = GUID_random();

	nt_status = ndr_push_struct_blob(&v, msg, &guid, 
					 (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_msg_add_value(msg, "objectGUID", &v, NULL);
	if (ret) {
		talloc_free(down_req);
		return ret;
	}
	
	if (add_time_element(msg, "whenCreated", t) != 0 ||
	    add_time_element(msg, "whenChanged", t) != 0) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Get a sequence number from the backend */
	ret = ldb_sequence_number(module->ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret == LDB_SUCCESS) {
		if (add_uint64_element(msg, "uSNCreated", seq_num) != 0 ||
		    add_uint64_element(msg, "uSNChanged", seq_num) != 0) {
			talloc_free(down_req);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	ldb_set_timeout_from_prev_req(module->ldb, req, down_req);

	/* go on with the call chain */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->handle = down_req->handle;
	}

	return ret;
}

static int replmd_add(struct ldb_module *module, struct ldb_request *req)
{
	return replmd_prepare_originating(module, req, req->op.add.message->dn,
					  "replmd_add", replmd_add_originating);
}

static int replmd_modify_originating(struct ldb_module *module,
				     struct ldb_request *req,
				     const struct dsdb_schema *schema,
				     const struct dsdb_control_current_partition *partition)
{
	struct ldb_request *down_req;
	struct ldb_message *msg;
	int ret;
	time_t t = time(NULL);
	uint64_t seq_num;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "replmd_modify_originating\n");

	down_req = talloc(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*down_req = *req;

	/* we have to copy the message as the caller might have it as a const */
	down_req->op.mod.message = msg = ldb_msg_copy_shallow(down_req, req->op.mod.message);
	if (msg == NULL) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (add_time_element(msg, "whenChanged", t) != 0) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Get a sequence number from the backend */
	ret = ldb_sequence_number(module->ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret == LDB_SUCCESS) {
		if (add_uint64_element(msg, "uSNChanged", seq_num) != 0) {
			talloc_free(down_req);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	ldb_set_timeout_from_prev_req(module->ldb, req, down_req);

	/* go on with the call chain */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->handle = down_req->handle;
	}

	return ret;
}

static int replmd_modify(struct ldb_module *module, struct ldb_request *req)
{
	return replmd_prepare_originating(module, req, req->op.mod.message->dn,
					  "replmd_modify", replmd_modify_originating);
}

static int replmd_replicated_request_reply_helper(struct replmd_replicated_request *ar, int ret)
{
	struct ldb_reply *ares = NULL;

	ar->handle->status = ret;
	ar->handle->state = LDB_ASYNC_DONE;

	if (!ar->orig_req->callback) {
		return LDB_SUCCESS;
	}
	
	/* we're done and need to report the success to the caller */
	ares = talloc_zero(ar, struct ldb_reply);
	if (!ares) {
		ar->handle->status = LDB_ERR_OPERATIONS_ERROR;
		ar->handle->state = LDB_ASYNC_DONE;
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ares->type	= LDB_REPLY_EXTENDED;
	ares->response	= NULL;

	return ar->orig_req->callback(ar->module->ldb, ar->orig_req->context, ares);
}

static int replmd_replicated_request_done(struct replmd_replicated_request *ar)
{
	return replmd_replicated_request_reply_helper(ar, LDB_SUCCESS);
}

static int replmd_replicated_request_error(struct replmd_replicated_request *ar, int ret)
{
	return replmd_replicated_request_reply_helper(ar, ret);
}

static int replmd_replicated_request_werror(struct replmd_replicated_request *ar, WERROR status)
{
	int ret = LDB_ERR_OTHER;
	/* TODO: do some error mapping */
	return replmd_replicated_request_reply_helper(ar, ret);
}

static int replmd_replicated_apply_next(struct replmd_replicated_request *ar);

static int replmd_replicated_apply_add_callback(struct ldb_context *ldb,
						void *private_data,
						struct ldb_reply *ares)
{
#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	struct replmd_replicated_request *ar = talloc_get_type(private_data,
					       struct replmd_replicated_request);

	ar->sub.change_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
	if (ar->sub.change_ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ar->sub.change_ret);
	}

	talloc_free(ar->sub.mem_ctx);
	ZERO_STRUCT(ar->sub);

	ar->index_current++;

	return replmd_replicated_apply_next(ar);
#else
	return LDB_SUCCESS;
#endif
}

static int replmd_replicated_apply_add(struct replmd_replicated_request *ar)
{
	NTSTATUS nt_status;
	struct ldb_message *msg;
	struct replPropertyMetaDataBlob *md;
	struct ldb_val md_value;
	uint32_t i;
	uint64_t seq_num;
	int ret;

	/*
	 * TODO: check if the parent object exist
	 */

	/*
	 * TODO: handle the conflict case where an object with the
	 *       same name exist
	 */

	msg = ar->objs->objects[ar->index_current].msg;
	md = ar->objs->objects[ar->index_current].meta_data;

	ret = ldb_sequence_number(ar->module->ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = ldb_msg_add_value(msg, "objectGUID", &ar->objs->objects[ar->index_current].guid_value, NULL);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = ldb_msg_add_string(msg, "whenChanged", ar->objs->objects[ar->index_current].when_changed);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = samdb_msg_add_uint64(ar->module->ldb, msg, msg, "uSNCreated", seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = samdb_msg_add_uint64(ar->module->ldb, msg, msg, "uSNChanged", seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	/*
	 * the meta data array is already sorted by the caller
	 */
	for (i=0; i < md->ctr.ctr1.count; i++) {
		md->ctr.ctr1.array[i].local_usn = seq_num;
	}
	nt_status = ndr_push_struct_blob(&md_value, msg, md,
					 (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}
	ret = ldb_msg_add_value(msg, "replPropertyMetaData", &md_value, NULL);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	replmd_ldb_message_sort(msg, ar->schema);

	ret = ldb_build_add_req(&ar->sub.change_req,
				ar->module->ldb,
				ar->sub.mem_ctx,
				msg,
				NULL,
				ar,
				replmd_replicated_apply_add_callback);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	return ldb_next_request(ar->module, ar->sub.change_req);
#else
	ret = ldb_next_request(ar->module, ar->sub.change_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	ar->sub.change_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
	if (ar->sub.change_ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ar->sub.change_ret);
	}

	talloc_free(ar->sub.mem_ctx);
	ZERO_STRUCT(ar->sub);

	ar->index_current++;

	return LDB_SUCCESS;
#endif
}

static int replmd_replPropertyMetaData1_conflict_compare(struct replPropertyMetaData1 *m1,
							 struct replPropertyMetaData1 *m2)
{
	int ret;

	if (m1->version != m2->version) {
		return m1->version - m2->version;
	}

	if (m1->orginating_time != m2->orginating_time) {
		return m1->orginating_time - m2->orginating_time;
	}

	ret = GUID_compare(&m1->orginating_invocation_id, &m2->orginating_invocation_id);
	if (ret != 0) {
		return ret;
	}

	return m1->orginating_usn - m2->orginating_usn;
}

static int replmd_replicated_apply_merge_callback(struct ldb_context *ldb,
						  void *private_data,
						  struct ldb_reply *ares)
{
#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	struct replmd_replicated_request *ar = talloc_get_type(private_data,
					       struct replmd_replicated_request);

	ret = ldb_next_request(ar->module, ar->sub.change_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	ar->sub.change_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
	if (ar->sub.change_ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ar->sub.change_ret);
	}

	talloc_free(ar->sub.mem_ctx);
	ZERO_STRUCT(ar->sub);

	ar->index_current++;

	return LDB_SUCCESS;
#else
	return LDB_SUCCESS;
#endif
}

static int replmd_replicated_apply_merge(struct replmd_replicated_request *ar)
{
	NTSTATUS nt_status;
	struct ldb_message *msg;
	struct replPropertyMetaDataBlob *rmd;
	struct replPropertyMetaDataBlob omd;
	const struct ldb_val *omd_value;
	struct replPropertyMetaDataBlob nmd;
	struct ldb_val nmd_value;
	uint32_t i,j,ni=0;
	uint32_t removed_attrs = 0;
	uint64_t seq_num;
	int ret;

	msg = ar->objs->objects[ar->index_current].msg;
	rmd = ar->objs->objects[ar->index_current].meta_data;
	ZERO_STRUCT(omd);
	omd.version = 1;

	/*
	 * TODO: add rename conflict handling
	 */
	if (ldb_dn_compare(msg->dn, ar->sub.search_msg->dn) != 0) {
		ldb_debug_set(ar->module->ldb, LDB_DEBUG_FATAL, "replmd_replicated_apply_merge[%u]: rename not supported",
			      ar->index_current);
		ldb_debug(ar->module->ldb, LDB_DEBUG_FATAL, "%s => %s\n",
			  ldb_dn_get_linearized(ar->sub.search_msg->dn),
			  ldb_dn_get_linearized(msg->dn));
		return replmd_replicated_request_werror(ar, WERR_NOT_SUPPORTED);
	}

	ret = ldb_sequence_number(ar->module->ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	/* find existing meta data */
	omd_value = ldb_msg_find_ldb_val(ar->sub.search_msg, "replPropertyMetaData");
	if (omd_value) {
		nt_status = ndr_pull_struct_blob(omd_value, ar->sub.mem_ctx, &omd,
						 (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
		}

		if (omd.version != 1) {
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		}
	}

	ZERO_STRUCT(nmd);
	nmd.version = 1;
	nmd.ctr.ctr1.count = omd.ctr.ctr1.count + rmd->ctr.ctr1.count;
	nmd.ctr.ctr1.array = talloc_array(ar->sub.mem_ctx,
					  struct replPropertyMetaData1,
					  nmd.ctr.ctr1.count);
	if (!nmd.ctr.ctr1.array) return replmd_replicated_request_werror(ar, WERR_NOMEM);

	/* first copy the old meta data */
	for (i=0; i < omd.ctr.ctr1.count; i++) {
		nmd.ctr.ctr1.array[ni]	= omd.ctr.ctr1.array[i];
		ni++;
	}

	/* now merge in the new meta data */
	for (i=0; i < rmd->ctr.ctr1.count; i++) {
		bool found = false;

		rmd->ctr.ctr1.array[i].local_usn = seq_num;

		for (j=0; j < ni; j++) {
			int cmp;

			if (rmd->ctr.ctr1.array[i].attid != nmd.ctr.ctr1.array[j].attid) {
				continue;
			}

			cmp = replmd_replPropertyMetaData1_conflict_compare(&rmd->ctr.ctr1.array[i],
									    &nmd.ctr.ctr1.array[j]);
			if (cmp > 0) {
				/* replace the entry */
				nmd.ctr.ctr1.array[j] = rmd->ctr.ctr1.array[i];
				found = true;
				break;
			}

			/* we don't want to apply this change so remove the attribute */
			ldb_msg_remove_element(msg, &msg->elements[i-removed_attrs]);
			removed_attrs++;

			found = true;
			break;
		}

		if (found) continue;

		nmd.ctr.ctr1.array[ni] = rmd->ctr.ctr1.array[i];
		ni++;
	}

	/*
	 * finally correct the size of the meta_data array
	 */
	nmd.ctr.ctr1.count = ni;

	/*
	 * the rdn attribute (the alias for the name attribute),
	 * 'cn' for most objects is the last entry in the meta data array
	 * we have stored
	 *
	 * sort the new meta data array
	 */
	{
		struct replPropertyMetaData1 *rdn_p;
		uint32_t rdn_idx = omd.ctr.ctr1.count - 1;

		rdn_p = &nmd.ctr.ctr1.array[rdn_idx];
		replmd_replPropertyMetaDataCtr1_sort(&nmd.ctr.ctr1, &rdn_p->attid);
	}

	/* create the meta data value */
	nt_status = ndr_push_struct_blob(&nmd_value, msg, &nmd,
					 (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}

	/*
	 * check if some replicated attributes left, otherwise skip the ldb_modify() call
	 */
	if (msg->num_elements == 0) {
		ldb_debug(ar->module->ldb, LDB_DEBUG_TRACE, "replmd_replicated_apply_merge[%u]: skip replace\n",
			  ar->index_current);
		goto next_object;
	}

	ldb_debug(ar->module->ldb, LDB_DEBUG_TRACE, "replmd_replicated_apply_merge[%u]: replace %u attributes\n",
		  ar->index_current, msg->num_elements);

	/*
	 * when we now that we'll modify the record, add the whenChanged, uSNChanged
	 * and replPopertyMetaData attributes
	 */
	ret = ldb_msg_add_string(msg, "whenChanged", ar->objs->objects[ar->index_current].when_changed);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}
	ret = samdb_msg_add_uint64(ar->module->ldb, msg, msg, "uSNChanged", seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}
	ret = ldb_msg_add_value(msg, "replPropertyMetaData", &nmd_value, NULL);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	replmd_ldb_message_sort(msg, ar->schema);

	/* we want to replace the old values */
	for (i=0; i < msg->num_elements; i++) {
		msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
	}

	ret = ldb_build_mod_req(&ar->sub.change_req,
				ar->module->ldb,
				ar->sub.mem_ctx,
				msg,
				NULL,
				ar,
				replmd_replicated_apply_merge_callback);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	return ldb_next_request(ar->module, ar->sub.change_req);
#else
	ret = ldb_next_request(ar->module, ar->sub.change_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	ar->sub.change_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
	if (ar->sub.change_ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ar->sub.change_ret);
	}

next_object:
	talloc_free(ar->sub.mem_ctx);
	ZERO_STRUCT(ar->sub);

	ar->index_current++;

	return LDB_SUCCESS;
#endif
}

static int replmd_replicated_apply_search_callback(struct ldb_context *ldb,
						   void *private_data,
						   struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar = talloc_get_type(private_data,
					       struct replmd_replicated_request);
	bool is_done = false;

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		ar->sub.search_msg = talloc_steal(ar->sub.mem_ctx, ares->message);
		break;
	case LDB_REPLY_REFERRAL:
		/* we ignore referrals */
		break;
	case LDB_REPLY_EXTENDED:
	case LDB_REPLY_DONE:
		is_done = true;
	}

	talloc_free(ares);

#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	if (is_done) {
		ar->sub.search_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
		if (ar->sub.search_ret != LDB_SUCCESS) {
			return replmd_replicated_request_error(ar, ar->sub.search_ret);
		}
		if (ar->sub.search_msg) {
			return replmd_replicated_apply_merge(ar);
		}
		return replmd_replicated_apply_add(ar);
	}
#endif
	return LDB_SUCCESS;
}

static int replmd_replicated_apply_search(struct replmd_replicated_request *ar)
{
	int ret;
	char *tmp_str;
	char *filter;

	tmp_str = ldb_binary_encode(ar->sub.mem_ctx, ar->objs->objects[ar->index_current].guid_value);
	if (!tmp_str) return replmd_replicated_request_werror(ar, WERR_NOMEM);

	filter = talloc_asprintf(ar->sub.mem_ctx, "(objectGUID=%s)", tmp_str);
	if (!filter) return replmd_replicated_request_werror(ar, WERR_NOMEM);
	talloc_free(tmp_str);

	ret = ldb_build_search_req(&ar->sub.search_req,
				   ar->module->ldb,
				   ar->sub.mem_ctx,
				   ar->objs->partition_dn,
				   LDB_SCOPE_SUBTREE,
				   filter,
				   NULL,
				   NULL,
				   ar,
				   replmd_replicated_apply_search_callback);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	return ldb_next_request(ar->module, ar->sub.search_req);
#else
	ret = ldb_next_request(ar->module, ar->sub.search_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	ar->sub.search_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
	if (ar->sub.search_ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ar->sub.search_ret);
	}
	if (ar->sub.search_msg) {
		return replmd_replicated_apply_merge(ar);
	}

	return replmd_replicated_apply_add(ar);
#endif
}

static int replmd_replicated_apply_next(struct replmd_replicated_request *ar)
{
#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	if (ar->index_current >= ar->objs->num_objects) {
		return replmd_replicated_uptodate_vector(ar);
	}
#endif

	ar->sub.mem_ctx = talloc_new(ar);
	if (!ar->sub.mem_ctx) return replmd_replicated_request_werror(ar, WERR_NOMEM);

	return replmd_replicated_apply_search(ar);
}

static int replmd_replicated_uptodate_modify_callback(struct ldb_context *ldb,
						      void *private_data,
						      struct ldb_reply *ares)
{
#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	struct replmd_replicated_request *ar = talloc_get_type(private_data,
					       struct replmd_replicated_request);

	ar->sub.change_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
	if (ar->sub.change_ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ar->sub.change_ret);
	}

	talloc_free(ar->sub.mem_ctx);
	ZERO_STRUCT(ar->sub);

	return replmd_replicated_request_done(ar);
#else
	return LDB_SUCCESS;
#endif
}

static int replmd_drsuapi_DsReplicaCursor2_compare(const struct drsuapi_DsReplicaCursor2 *c1,
						   const struct drsuapi_DsReplicaCursor2 *c2)
{
	return GUID_compare(&c1->source_dsa_invocation_id, &c2->source_dsa_invocation_id);
}

static int replmd_replicated_uptodate_modify(struct replmd_replicated_request *ar)
{
	NTSTATUS nt_status;
	struct ldb_message *msg;
	struct replUpToDateVectorBlob ouv;
	const struct ldb_val *ouv_value;
	const struct drsuapi_DsReplicaCursor2CtrEx *ruv;
	struct replUpToDateVectorBlob nuv;
	struct ldb_val nuv_value;
	struct ldb_message_element *nuv_el = NULL;
	const struct GUID *our_invocation_id;
	struct ldb_message_element *orf_el = NULL;
	struct repsFromToBlob nrf;
	struct ldb_val *nrf_value = NULL;
	struct ldb_message_element *nrf_el = NULL;
	uint32_t i,j,ni=0;
	uint64_t seq_num;
	bool found = false;
	time_t t = time(NULL);
	NTTIME now;
	int ret;

	ruv = ar->objs->uptodateness_vector;
	ZERO_STRUCT(ouv);
	ouv.version = 2;
	ZERO_STRUCT(nuv);
	nuv.version = 2;

	unix_to_nt_time(&now, t);

	/* 
	 * we use the next sequence number for our own highest_usn
	 * because we will do a modify request and this will increment
	 * our highest_usn
	 */
	ret = ldb_sequence_number(ar->module->ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	/*
	 * first create the new replUpToDateVector
	 */
	ouv_value = ldb_msg_find_ldb_val(ar->sub.search_msg, "replUpToDateVector");
	if (ouv_value) {
		nt_status = ndr_pull_struct_blob(ouv_value, ar->sub.mem_ctx, &ouv,
						 (ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
		}

		if (ouv.version != 2) {
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		}
	}

	/*
	 * the new uptodateness vector will at least
	 * contain 2 entries, one for the source_dsa and one the local server
	 *
	 * plus optional values from our old vector and the one from the source_dsa
	 */
	nuv.ctr.ctr2.count = 2 + ouv.ctr.ctr2.count;
	if (ruv) nuv.ctr.ctr2.count += ruv->count;
	nuv.ctr.ctr2.cursors = talloc_array(ar->sub.mem_ctx,
					    struct drsuapi_DsReplicaCursor2,
					    nuv.ctr.ctr2.count);
	if (!nuv.ctr.ctr2.cursors) return replmd_replicated_request_werror(ar, WERR_NOMEM);

	/* first copy the old vector */
	for (i=0; i < ouv.ctr.ctr2.count; i++) {
		nuv.ctr.ctr2.cursors[ni] = ouv.ctr.ctr2.cursors[i];
		ni++;
	}

	/* merge in the source_dsa vector is available */
	for (i=0; (ruv && i < ruv->count); i++) {
		found = false;

		for (j=0; j < ni; j++) {
			if (!GUID_equal(&ruv->cursors[i].source_dsa_invocation_id,
					&nuv.ctr.ctr2.cursors[j].source_dsa_invocation_id)) {
				continue;
			}

			found = true;

			/*
			 * we update only the highest_usn and not the latest_sync_success time,
			 * because the last success stands for direct replication
			 */
			if (ruv->cursors[i].highest_usn > nuv.ctr.ctr2.cursors[j].highest_usn) {
				nuv.ctr.ctr2.cursors[j].highest_usn = ruv->cursors[i].highest_usn;
			}
			break;			
		}

		if (found) continue;

		/* if it's not there yet, add it */
		nuv.ctr.ctr2.cursors[ni] = ruv->cursors[i];
		ni++;
	}

	/*
	 * merge in the current highwatermark for the source_dsa
	 */
	found = false;
	for (j=0; j < ni; j++) {
		if (!GUID_equal(&ar->objs->source_dsa->source_dsa_invocation_id,
				&nuv.ctr.ctr2.cursors[j].source_dsa_invocation_id)) {
			continue;
		}

		found = true;

		/*
		 * here we update the highest_usn and last_sync_success time
		 * because we're directly replicating from the source_dsa
		 *
		 * and use the tmp_highest_usn because this is what we have just applied
		 * to our ldb
		 */
		nuv.ctr.ctr2.cursors[j].highest_usn		= ar->objs->source_dsa->highwatermark.tmp_highest_usn;
		nuv.ctr.ctr2.cursors[j].last_sync_success	= now;
		break;
	}
	if (!found) {
		/*
		 * here we update the highest_usn and last_sync_success time
		 * because we're directly replicating from the source_dsa
		 *
		 * and use the tmp_highest_usn because this is what we have just applied
		 * to our ldb
		 */
		nuv.ctr.ctr2.cursors[ni].source_dsa_invocation_id= ar->objs->source_dsa->source_dsa_invocation_id;
		nuv.ctr.ctr2.cursors[ni].highest_usn		= ar->objs->source_dsa->highwatermark.tmp_highest_usn;
		nuv.ctr.ctr2.cursors[ni].last_sync_success	= now;
		ni++;
	}

	/*
	 * merge our own current values if we have a invocation_id already
	 * attached to the ldb
	 */
	our_invocation_id = samdb_ntds_invocation_id(ar->module->ldb);
	if (our_invocation_id) {
		found = false;
		for (j=0; j < ni; j++) {
			if (!GUID_equal(our_invocation_id,
					&nuv.ctr.ctr2.cursors[j].source_dsa_invocation_id)) {
				continue;
			}

			found = true;

			/*
			 * here we update the highest_usn and last_sync_success time
			 * because it's our own entry
			 */
			nuv.ctr.ctr2.cursors[j].highest_usn		= seq_num;
			nuv.ctr.ctr2.cursors[j].last_sync_success	= now;
			break;
		}
		if (!found) {
			/*
			 * here we update the highest_usn and last_sync_success time
			 * because it's our own entry
			 */
			nuv.ctr.ctr2.cursors[ni].source_dsa_invocation_id= *our_invocation_id;
			nuv.ctr.ctr2.cursors[ni].highest_usn		= seq_num;
			nuv.ctr.ctr2.cursors[ni].last_sync_success	= now;
			ni++;
		}
	}

	/*
	 * finally correct the size of the cursors array
	 */
	nuv.ctr.ctr2.count = ni;

	/*
	 * sort the cursors
	 */
	qsort(nuv.ctr.ctr2.cursors, nuv.ctr.ctr2.count,
	      sizeof(struct drsuapi_DsReplicaCursor2),
	      (comparison_fn_t)replmd_drsuapi_DsReplicaCursor2_compare);

	/*
	 * create the change ldb_message
	 */
	msg = ldb_msg_new(ar->sub.mem_ctx);
	if (!msg) return replmd_replicated_request_werror(ar, WERR_NOMEM);
	msg->dn = ar->sub.search_msg->dn;

	nt_status = ndr_push_struct_blob(&nuv_value, msg, &nuv,
					 (ndr_push_flags_fn_t)ndr_push_replUpToDateVectorBlob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}
	ret = ldb_msg_add_value(msg, "replUpToDateVector", &nuv_value, &nuv_el);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}
	nuv_el->flags = LDB_FLAG_MOD_REPLACE;

	/*
	 * now create the new repsFrom value from the given repsFromTo1 structure
	 */
	ZERO_STRUCT(nrf);
	nrf.version					= 1;
	nrf.ctr.ctr1					= *ar->objs->source_dsa;
	/* and fix some values... */
	nrf.ctr.ctr1.consecutive_sync_failures		= 0;
	nrf.ctr.ctr1.last_success			= now;
	nrf.ctr.ctr1.last_attempt			= now;
	nrf.ctr.ctr1.result_last_attempt		= WERR_OK;
	nrf.ctr.ctr1.highwatermark.highest_usn		= nrf.ctr.ctr1.highwatermark.tmp_highest_usn;

	/*
	 * first see if we already have a repsFrom value for the current source dsa
	 * if so we'll later replace this value
	 */
	orf_el = ldb_msg_find_element(ar->sub.search_msg, "repsFrom");
	if (orf_el) {
		for (i=0; i < orf_el->num_values; i++) {
			struct repsFromToBlob *trf;

			trf = talloc(ar->sub.mem_ctx, struct repsFromToBlob);
			if (!trf) return replmd_replicated_request_werror(ar, WERR_NOMEM);

			nt_status = ndr_pull_struct_blob(&orf_el->values[i], trf, trf,
							 (ndr_pull_flags_fn_t)ndr_pull_repsFromToBlob);
			if (!NT_STATUS_IS_OK(nt_status)) {
				return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
			}

			if (trf->version != 1) {
				return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
			}

			/*
			 * we compare the source dsa objectGUID not the invocation_id
			 * because we want only one repsFrom value per source dsa
			 * and when the invocation_id of the source dsa has changed we don't need 
			 * the old repsFrom with the old invocation_id
			 */
			if (!GUID_equal(&trf->ctr.ctr1.source_dsa_obj_guid,
					&ar->objs->source_dsa->source_dsa_obj_guid)) {
				talloc_free(trf);
				continue;
			}

			talloc_free(trf);
			nrf_value = &orf_el->values[i];
			break;
		}

		/*
		 * copy over all old values to the new ldb_message
		 */
		ret = ldb_msg_add_empty(msg, "repsFrom", 0, &nrf_el);
		if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);
		*nrf_el = *orf_el;
	}

	/*
	 * if we haven't found an old repsFrom value for the current source dsa
	 * we'll add a new value
	 */
	if (!nrf_value) {
		struct ldb_val zero_value;
		ZERO_STRUCT(zero_value);
		ret = ldb_msg_add_value(msg, "repsFrom", &zero_value, &nrf_el);
		if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

		nrf_value = &nrf_el->values[nrf_el->num_values - 1];
	}

	/* we now fill the value which is already attached to ldb_message */
	nt_status = ndr_push_struct_blob(nrf_value, msg, &nrf,
					 (ndr_push_flags_fn_t)ndr_push_repsFromToBlob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}

	/* 
	 * the ldb_message_element for the attribute, has all the old values and the new one
	 * so we'll replace the whole attribute with all values
	 */
	nrf_el->flags = LDB_FLAG_MOD_REPLACE;

	/* prepare the ldb_modify() request */
	ret = ldb_build_mod_req(&ar->sub.change_req,
				ar->module->ldb,
				ar->sub.mem_ctx,
				msg,
				NULL,
				ar,
				replmd_replicated_uptodate_modify_callback);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	return ldb_next_request(ar->module, ar->sub.change_req);
#else
	ret = ldb_next_request(ar->module, ar->sub.change_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	ar->sub.change_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
	if (ar->sub.change_ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ar->sub.change_ret);
	}

	talloc_free(ar->sub.mem_ctx);
	ZERO_STRUCT(ar->sub);

	return replmd_replicated_request_done(ar);
#endif
}

static int replmd_replicated_uptodate_search_callback(struct ldb_context *ldb,
						      void *private_data,
						      struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar = talloc_get_type(private_data,
					       struct replmd_replicated_request);
	bool is_done = false;

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		ar->sub.search_msg = talloc_steal(ar->sub.mem_ctx, ares->message);
		break;
	case LDB_REPLY_REFERRAL:
		/* we ignore referrals */
		break;
	case LDB_REPLY_EXTENDED:
	case LDB_REPLY_DONE:
		is_done = true;
	}

	talloc_free(ares);

#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	if (is_done) {
		ar->sub.search_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
		if (ar->sub.search_ret != LDB_SUCCESS) {
			return replmd_replicated_request_error(ar, ar->sub.search_ret);
		}
		if (!ar->sub.search_msg) {
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		}

		return replmd_replicated_uptodate_modify(ar);
	}
#endif
	return LDB_SUCCESS;
}

static int replmd_replicated_uptodate_search(struct replmd_replicated_request *ar)
{
	int ret;
	static const char *attrs[] = {
		"replUpToDateVector",
		"repsFrom",
		NULL
	};

	ret = ldb_build_search_req(&ar->sub.search_req,
				   ar->module->ldb,
				   ar->sub.mem_ctx,
				   ar->objs->partition_dn,
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs,
				   NULL,
				   ar,
				   replmd_replicated_uptodate_search_callback);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	return ldb_next_request(ar->module, ar->sub.search_req);
#else
	ret = ldb_next_request(ar->module, ar->sub.search_req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	ar->sub.search_ret = ldb_wait(ar->sub.search_req->handle, LDB_WAIT_ALL);
	if (ar->sub.search_ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ar->sub.search_ret);
	}
	if (!ar->sub.search_msg) {
		return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
	}

	return replmd_replicated_uptodate_modify(ar);
#endif
}

static int replmd_replicated_uptodate_vector(struct replmd_replicated_request *ar)
{
	ar->sub.mem_ctx = talloc_new(ar);
	if (!ar->sub.mem_ctx) return replmd_replicated_request_werror(ar, WERR_NOMEM);

	return replmd_replicated_uptodate_search(ar);
}

static int replmd_extended_replicated_objects(struct ldb_module *module, struct ldb_request *req)
{
	struct dsdb_extended_replicated_objects *objs;
	struct replmd_replicated_request *ar;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "replmd_extended_replicated_objects\n");

	objs = talloc_get_type(req->op.extended.data, struct dsdb_extended_replicated_objects);
	if (!objs) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "replmd_extended_replicated_objects: invalid extended data\n");
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (objs->version != DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "replmd_extended_replicated_objects: extended data invalid version [%u != %u]\n",
			  objs->version, DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	ar = replmd_replicated_init_handle(module, req, objs);
	if (!ar) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

#ifdef REPLMD_FULL_ASYNC /* TODO: active this code when ldb support full async code */ 
	return replmd_replicated_apply_next(ar);
#else
	while (ar->index_current < ar->objs->num_objects &&
	       req->handle->state != LDB_ASYNC_DONE) { 
		replmd_replicated_apply_next(ar);
	}

	if (req->handle->state != LDB_ASYNC_DONE) {
		replmd_replicated_uptodate_vector(ar);
	}

	return LDB_SUCCESS;
#endif
}

static int replmd_extended(struct ldb_module *module, struct ldb_request *req)
{
	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_REPLICATED_OBJECTS_OID) == 0) {
		return replmd_extended_replicated_objects(module, req);
	}

	return ldb_next_request(module, req);
}

static int replmd_wait_none(struct ldb_handle *handle) {
	struct replmd_replicated_request *ar;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ar = talloc_get_type(handle->private_data, struct replmd_replicated_request);
	if (!ar) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we do only sync calls */
	if (handle->state != LDB_ASYNC_DONE) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return handle->status;
}

static int replmd_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = replmd_wait_none(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int replmd_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return replmd_wait_all(handle);
	} else {
		return replmd_wait_none(handle);
	}
}

static const struct ldb_module_ops replmd_ops = {
	.name          = "repl_meta_data",
	.add           = replmd_add,
	.modify        = replmd_modify,
	.extended      = replmd_extended,
	.wait          = replmd_wait
};

int repl_meta_data_module_init(void)
{
	return ldb_register_module(&replmd_ops);
}
