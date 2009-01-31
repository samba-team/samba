/* 
   ldb database library

   Copyright (C) Simo Sorce  2004-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
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
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/flags.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"

struct replmd_replicated_request {
	struct ldb_module *module;
	struct ldb_request *req;

	const struct dsdb_schema *schema;

	struct dsdb_extended_replicated_objects *objs;

	/* the controls we pass down */
	struct ldb_control **controls;

	uint32_t index_current;

	struct ldb_message *search_msg;
};

static struct replmd_replicated_request *replmd_ctx_init(struct ldb_module *module,
					  struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ac;

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct replmd_replicated_request);
	if (ac == NULL) {
		ldb_oom(ldb);
		return NULL;
	}

	ac->module = module;
	ac->req	= req;
	return ac;
}

/*
  add a time element to a record
*/
static int add_time_element(struct ldb_message *msg, const char *attr, time_t t)
{
	struct ldb_message_element *el;
	char *s;

	if (ldb_msg_find_element(msg, attr) != NULL) {
		return LDB_SUCCESS;
	}

	s = ldb_timestring(msg, t);
	if (s == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ldb_msg_add_string(msg, attr, s) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	el = ldb_msg_find_element(msg, attr);
	/* always set as replace. This works because on add ops, the flag
	   is ignored */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
}

/*
  add a uint64_t element to a record
*/
static int add_uint64_element(struct ldb_message *msg, const char *attr, uint64_t v)
{
	struct ldb_message_element *el;

	if (ldb_msg_find_element(msg, attr) != NULL) {
		return LDB_SUCCESS;
	}

	if (ldb_msg_add_fmt(msg, attr, "%llu", (unsigned long long)v) != LDB_SUCCESS) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	el = ldb_msg_find_element(msg, attr);
	/* always set as replace. This works because on add ops, the flag
	   is ignored */
	el->flags = LDB_FLAG_MOD_REPLACE;

	return LDB_SUCCESS;
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

static int replmd_op_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ac;

	ac = talloc_get_type(req->context, struct replmd_replicated_request);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb,
				  "invalid ldb_reply_type in callback");
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	return ldb_module_done(ac->req, ares->controls,
				ares->response, LDB_SUCCESS);
}

static int replmd_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ac;
	const struct dsdb_schema *schema;
	enum ndr_err_code ndr_err;
	struct ldb_request *down_req;
	struct ldb_message *msg;
	const struct dsdb_attribute *rdn_attr = NULL;
	struct GUID guid;
	struct ldb_val guid_value;
	struct replPropertyMetaDataBlob nmd;
	struct ldb_val nmd_value;
	uint64_t seq_num;
	const struct GUID *our_invocation_id;
	time_t t = time(NULL);
	NTTIME now;
	char *time_str;
	int ret;
	uint32_t i, ni=0;

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_add\n");

	schema = dsdb_get_schema(ldb);
	if (!schema) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "replmd_modify: no dsdb_schema loaded");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	ac = replmd_ctx_init(module, req);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->schema = schema;

	if (ldb_msg_find_element(req->op.add.message, "objectGUID") != NULL) {
		ldb_debug_set(ldb, LDB_DEBUG_ERROR,
			      "replmd_add: it's not allowed to add an object with objectGUID\n");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* Get a sequence number from the backend */
	ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* a new GUID */
	guid = GUID_random();

	/* get our invicationId */
	our_invocation_id = samdb_ntds_invocation_id(ldb);
	if (!our_invocation_id) {
		ldb_debug_set(ldb, LDB_DEBUG_ERROR,
			      "replmd_add: unable to find invocationId\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(ac, req->op.add.message);
	if (msg == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* generated times */
	unix_to_nt_time(&now, t);
	time_str = ldb_timestring(msg, t);
	if (!time_str) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* 
	 * remove autogenerated attributes
	 */
	ldb_msg_remove_attr(msg, "whenCreated");
	ldb_msg_remove_attr(msg, "whenChanged");
	ldb_msg_remove_attr(msg, "uSNCreated");
	ldb_msg_remove_attr(msg, "uSNChanged");
	ldb_msg_remove_attr(msg, "replPropertyMetaData");

	/*
	 * readd replicated attributes
	 */
	ret = ldb_msg_add_string(msg, "whenCreated", time_str);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* build the replication meta_data */
	ZERO_STRUCT(nmd);
	nmd.version		= 1;
	nmd.ctr.ctr1.count	= msg->num_elements;
	nmd.ctr.ctr1.array	= talloc_array(msg,
					       struct replPropertyMetaData1,
					       nmd.ctr.ctr1.count);
	if (!nmd.ctr.ctr1.array) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i=0; i < msg->num_elements; i++) {
		struct ldb_message_element *e = &msg->elements[i];
		struct replPropertyMetaData1 *m = &nmd.ctr.ctr1.array[ni];
		const struct dsdb_attribute *sa;

		if (e->name[0] == '@') continue;

		sa = dsdb_attribute_by_lDAPDisplayName(schema, e->name);
		if (!sa) {
			ldb_debug_set(ldb, LDB_DEBUG_ERROR,
				      "replmd_add: attribute '%s' not defined in schema\n",
				      e->name);
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		}

		if ((sa->systemFlags & 0x00000001) || (sa->systemFlags & 0x00000004)) {
			/* if the attribute is not replicated (0x00000001)
			 * or constructed (0x00000004) it has no metadata
			 */
			continue;
		}

		m->attid			= sa->attributeID_id;
		m->version			= 1;
		m->originating_change_time	= now;
		m->originating_invocation_id	= *our_invocation_id;
		m->originating_usn		= seq_num;
		m->local_usn			= seq_num;
		ni++;

		if (ldb_attr_cmp(e->name, ldb_dn_get_rdn_name(msg->dn))) {
			rdn_attr = sa;
		}
	}

	/* fix meta data count */
	nmd.ctr.ctr1.count = ni;

	/*
	 * sort meta data array, and move the rdn attribute entry to the end
	 */
	replmd_replPropertyMetaDataCtr1_sort(&nmd.ctr.ctr1, &rdn_attr->attributeID_id);

	/* generated NDR encoded values */
	ndr_err = ndr_push_struct_blob(&guid_value, msg, 
				       NULL,
				       &guid,
				       (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ndr_err = ndr_push_struct_blob(&nmd_value, msg, 
				       lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")),
				       &nmd,
				       (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * add the autogenerated values
	 */
	ret = ldb_msg_add_value(msg, "objectGUID", &guid_value, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_msg_add_string(msg, "whenChanged", time_str);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNCreated", seq_num);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNChanged", seq_num);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_msg_add_value(msg, "replPropertyMetaData", &nmd_value, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * sort the attributes by attid before storing the object
	 */
	replmd_ldb_message_sort(msg, schema);

	ret = ldb_build_add_req(&down_req, ldb, ac,
				msg,
				req->controls,
				ac, replmd_op_callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

static int replmd_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ac;
	const struct dsdb_schema *schema;
	struct ldb_request *down_req;
	struct ldb_message *msg;
	int ret;
	time_t t = time(NULL);
	uint64_t seq_num;

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_modify\n");

	schema = dsdb_get_schema(ldb);
	if (!schema) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL,
			      "replmd_modify: no dsdb_schema loaded");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	ac = replmd_ctx_init(module, req);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->schema = schema;

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(ac, req->op.mod.message);
	if (msg == NULL) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* TODO:
	 * - get the whole old object
	 * - if the old object doesn't exist report an error
	 * - give an error when a readonly attribute should
	 *   be modified
	 * - merge the changed into the old object
	 *   if the caller set values to the same value
	 *   ignore the attribute, return success when no
	 *   attribute was changed
	 * - calculate the new replPropertyMetaData attribute
	 */

	if (add_time_element(msg, "whenChanged", t) != LDB_SUCCESS) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Get a sequence number from the backend */
	ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret == LDB_SUCCESS) {
		if (add_uint64_element(msg, "uSNChanged", seq_num) != LDB_SUCCESS) {
			talloc_free(ac);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/* TODO:
	 * - sort the attributes by attid with replmd_ldb_message_sort()
	 * - replace the old object with the newly constructed one
	 */

	ret = ldb_build_mod_req(&down_req, ldb, ac,
				msg,
				req->controls,
				ac, replmd_op_callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	talloc_steal(down_req, msg);

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

static int replmd_replicated_request_error(struct replmd_replicated_request *ar, int ret)
{
	return ret;
}

static int replmd_replicated_request_werror(struct replmd_replicated_request *ar, WERROR status)
{
	int ret = LDB_ERR_OTHER;
	/* TODO: do some error mapping */
	return ret;
}

static int replmd_replicated_apply_next(struct replmd_replicated_request *ar);

static int replmd_replicated_apply_add_callback(struct ldb_request *req,
						struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	int ret;

	ldb = ldb_module_get_ctx(ar->module);

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb, "Invalid reply type\n!");
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);
	ar->index_current++;

	ret = replmd_replicated_apply_next(ar);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ar->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int replmd_replicated_apply_add(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	struct ldb_request *change_req;
	enum ndr_err_code ndr_err;
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

	ldb = ldb_module_get_ctx(ar->module);
	msg = ar->objs->objects[ar->index_current].msg;
	md = ar->objs->objects[ar->index_current].meta_data;

	ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &seq_num);
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

	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNCreated", seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNChanged", seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	/*
	 * the meta data array is already sorted by the caller
	 */
	for (i=0; i < md->ctr.ctr1.count; i++) {
		md->ctr.ctr1.array[i].local_usn = seq_num;
	}
	ndr_err = ndr_push_struct_blob(&md_value, msg, 
				       lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")),
				       md,
				       (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}
	ret = ldb_msg_add_value(msg, "replPropertyMetaData", &md_value, NULL);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	replmd_ldb_message_sort(msg, ar->schema);

	ret = ldb_build_add_req(&change_req,
				ldb,
				ar,
				msg,
				ar->controls,
				ar,
				replmd_replicated_apply_add_callback,
				ar->req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	return ldb_next_request(ar->module, change_req);
}

static int replmd_replPropertyMetaData1_conflict_compare(struct replPropertyMetaData1 *m1,
							 struct replPropertyMetaData1 *m2)
{
	int ret;

	if (m1->version != m2->version) {
		return m1->version - m2->version;
	}

	if (m1->originating_change_time != m2->originating_change_time) {
		return m1->originating_change_time - m2->originating_change_time;
	}

	ret = GUID_compare(&m1->originating_invocation_id, &m2->originating_invocation_id);
	if (ret != 0) {
		return ret;
	}

	return m1->originating_usn - m2->originating_usn;
}

static int replmd_replicated_apply_merge_callback(struct ldb_request *req,
						  struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	int ret;

	ldb = ldb_module_get_ctx(ar->module);

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb, "Invalid reply type\n!");
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);
	ar->index_current++;

	ret = replmd_replicated_apply_next(ar);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ar->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int replmd_replicated_apply_merge(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	struct ldb_request *change_req;
	enum ndr_err_code ndr_err;
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

	ldb = ldb_module_get_ctx(ar->module);
	msg = ar->objs->objects[ar->index_current].msg;
	rmd = ar->objs->objects[ar->index_current].meta_data;
	ZERO_STRUCT(omd);
	omd.version = 1;

	/*
	 * TODO: add rename conflict handling
	 */
	if (ldb_dn_compare(msg->dn, ar->search_msg->dn) != 0) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL, "replmd_replicated_apply_merge[%u]: rename not supported",
			      ar->index_current);
		ldb_debug(ldb, LDB_DEBUG_FATAL, "%s => %s\n",
			  ldb_dn_get_linearized(ar->search_msg->dn),
			  ldb_dn_get_linearized(msg->dn));
		return replmd_replicated_request_werror(ar, WERR_NOT_SUPPORTED);
	}

	ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	/* find existing meta data */
	omd_value = ldb_msg_find_ldb_val(ar->search_msg, "replPropertyMetaData");
	if (omd_value) {
		ndr_err = ndr_pull_struct_blob(omd_value, ar,
					       lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")), &omd,
					       (ndr_pull_flags_fn_t)ndr_pull_replPropertyMetaDataBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
			return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
		}

		if (omd.version != 1) {
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		}
	}

	ZERO_STRUCT(nmd);
	nmd.version = 1;
	nmd.ctr.ctr1.count = omd.ctr.ctr1.count + rmd->ctr.ctr1.count;
	nmd.ctr.ctr1.array = talloc_array(ar,
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
	ndr_err = ndr_push_struct_blob(&nmd_value, msg, 
				       lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")),
				       &nmd,
				       (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}

	/*
	 * check if some replicated attributes left, otherwise skip the ldb_modify() call
	 */
	if (msg->num_elements == 0) {
		ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_replicated_apply_merge[%u]: skip replace\n",
			  ar->index_current);

		ar->index_current++;
		return replmd_replicated_apply_next(ar);
	}

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_replicated_apply_merge[%u]: replace %u attributes\n",
		  ar->index_current, msg->num_elements);

	/*
	 * when we know that we'll modify the record, add the whenChanged, uSNChanged
	 * and replPopertyMetaData attributes
	 */
	ret = ldb_msg_add_string(msg, "whenChanged", ar->objs->objects[ar->index_current].when_changed);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}
	ret = samdb_msg_add_uint64(ldb, msg, msg, "uSNChanged", seq_num);
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

	ret = ldb_build_mod_req(&change_req,
				ldb,
				ar,
				msg,
				ar->controls,
				ar,
				replmd_replicated_apply_merge_callback,
				ar->req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	return ldb_next_request(ar->module, change_req);
}

static int replmd_replicated_apply_search_callback(struct ldb_request *req,
						   struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	int ret;

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS &&
	    ares->error != LDB_ERR_NO_SUCH_OBJECT) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		ar->search_msg = talloc_steal(ar, ares->message);
		break;

	case LDB_REPLY_REFERRAL:
		/* we ignore referrals */
		break;

	case LDB_REPLY_DONE:
		if (ar->search_msg != NULL) {
			ret = replmd_replicated_apply_merge(ar);
		} else {
			ret = replmd_replicated_apply_add(ar);
		}
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ar->req, NULL, NULL, ret);
		}
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

static int replmd_replicated_uptodate_vector(struct replmd_replicated_request *ar);

static int replmd_replicated_apply_next(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	int ret;
	char *tmp_str;
	char *filter;
	struct ldb_request *search_req;

	if (ar->index_current >= ar->objs->num_objects) {
		/* done with it, go to the last op */
		return replmd_replicated_uptodate_vector(ar);
	}

	ldb = ldb_module_get_ctx(ar->module);
	ar->search_msg = NULL;

	tmp_str = ldb_binary_encode(ar, ar->objs->objects[ar->index_current].guid_value);
	if (!tmp_str) return replmd_replicated_request_werror(ar, WERR_NOMEM);

	filter = talloc_asprintf(ar, "(objectGUID=%s)", tmp_str);
	if (!filter) return replmd_replicated_request_werror(ar, WERR_NOMEM);
	talloc_free(tmp_str);

	ret = ldb_build_search_req(&search_req,
				   ldb,
				   ar,
				   ar->objs->partition_dn,
				   LDB_SCOPE_SUBTREE,
				   filter,
				   NULL,
				   NULL,
				   ar,
				   replmd_replicated_apply_search_callback,
				   ar->req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	return ldb_next_request(ar->module, search_req);
}

static int replmd_replicated_uptodate_modify_callback(struct ldb_request *req,
						      struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	ldb = ldb_module_get_ctx(ar->module);

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ldb, "Invalid reply type\n!");
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);

	return ldb_module_done(ar->req, NULL, NULL, LDB_SUCCESS);
}

static int replmd_drsuapi_DsReplicaCursor2_compare(const struct drsuapi_DsReplicaCursor2 *c1,
						   const struct drsuapi_DsReplicaCursor2 *c2)
{
	return GUID_compare(&c1->source_dsa_invocation_id, &c2->source_dsa_invocation_id);
}

static int replmd_replicated_uptodate_modify(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	struct ldb_request *change_req;
	enum ndr_err_code ndr_err;
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

	ldb = ldb_module_get_ctx(ar->module);
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
	ret = ldb_sequence_number(ldb, LDB_SEQ_NEXT, &seq_num);
	if (ret != LDB_SUCCESS) {
		return replmd_replicated_request_error(ar, ret);
	}

	/*
	 * first create the new replUpToDateVector
	 */
	ouv_value = ldb_msg_find_ldb_val(ar->search_msg, "replUpToDateVector");
	if (ouv_value) {
		ndr_err = ndr_pull_struct_blob(ouv_value, ar,
					       lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")), &ouv,
					       (ndr_pull_flags_fn_t)ndr_pull_replUpToDateVectorBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
			return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
		}

		if (ouv.version != 2) {
			return replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		}
	}

	/*
	 * the new uptodateness vector will at least
	 * contain 1 entry, one for the source_dsa
	 *
	 * plus optional values from our old vector and the one from the source_dsa
	 */
	nuv.ctr.ctr2.count = 1 + ouv.ctr.ctr2.count;
	if (ruv) nuv.ctr.ctr2.count += ruv->count;
	nuv.ctr.ctr2.cursors = talloc_array(ar,
					    struct drsuapi_DsReplicaCursor2,
					    nuv.ctr.ctr2.count);
	if (!nuv.ctr.ctr2.cursors) return replmd_replicated_request_werror(ar, WERR_NOMEM);

	/* first copy the old vector */
	for (i=0; i < ouv.ctr.ctr2.count; i++) {
		nuv.ctr.ctr2.cursors[ni] = ouv.ctr.ctr2.cursors[i];
		ni++;
	}

	/* get our invocation_id if we have one already attached to the ldb */
	our_invocation_id = samdb_ntds_invocation_id(ldb);

	/* merge in the source_dsa vector is available */
	for (i=0; (ruv && i < ruv->count); i++) {
		found = false;

		if (our_invocation_id &&
		    GUID_equal(&ruv->cursors[i].source_dsa_invocation_id,
			       our_invocation_id)) {
			continue;
		}

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
	msg = ldb_msg_new(ar);
	if (!msg) return replmd_replicated_request_werror(ar, WERR_NOMEM);
	msg->dn = ar->search_msg->dn;

	ndr_err = ndr_push_struct_blob(&nuv_value, msg, 
				       lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")), 
				       &nuv,
				       (ndr_push_flags_fn_t)ndr_push_replUpToDateVectorBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
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
	orf_el = ldb_msg_find_element(ar->search_msg, "repsFrom");
	if (orf_el) {
		for (i=0; i < orf_el->num_values; i++) {
			struct repsFromToBlob *trf;

			trf = talloc(ar, struct repsFromToBlob);
			if (!trf) return replmd_replicated_request_werror(ar, WERR_NOMEM);

			ndr_err = ndr_pull_struct_blob(&orf_el->values[i], trf, lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")), trf,
						       (ndr_pull_flags_fn_t)ndr_pull_repsFromToBlob);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
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
	ndr_err = ndr_push_struct_blob(nrf_value, msg, 
				       lp_iconv_convenience(ldb_get_opaque(ldb, "loadparm")),
				       &nrf,
				       (ndr_push_flags_fn_t)ndr_push_repsFromToBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		return replmd_replicated_request_werror(ar, ntstatus_to_werror(nt_status));
	}

	/* 
	 * the ldb_message_element for the attribute, has all the old values and the new one
	 * so we'll replace the whole attribute with all values
	 */
	nrf_el->flags = LDB_FLAG_MOD_REPLACE;

	/* prepare the ldb_modify() request */
	ret = ldb_build_mod_req(&change_req,
				ldb,
				ar,
				msg,
				ar->controls,
				ar,
				replmd_replicated_uptodate_modify_callback,
				ar->req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	return ldb_next_request(ar->module, change_req);
}

static int replmd_replicated_uptodate_search_callback(struct ldb_request *req,
						      struct ldb_reply *ares)
{
	struct replmd_replicated_request *ar = talloc_get_type(req->context,
					       struct replmd_replicated_request);
	int ret;

	if (!ares) {
		return ldb_module_done(ar->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS &&
	    ares->error != LDB_ERR_NO_SUCH_OBJECT) {
		return ldb_module_done(ar->req, ares->controls,
					ares->response, ares->error);
	}

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		ar->search_msg = talloc_steal(ar, ares->message);
		break;

	case LDB_REPLY_REFERRAL:
		/* we ignore referrals */
		break;

	case LDB_REPLY_DONE:
		if (ar->search_msg == NULL) {
			ret = replmd_replicated_request_werror(ar, WERR_DS_DRA_INTERNAL_ERROR);
		} else {
			ret = replmd_replicated_uptodate_modify(ar);
		}
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ar->req, NULL, NULL, ret);
		}
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}


static int replmd_replicated_uptodate_vector(struct replmd_replicated_request *ar)
{
	struct ldb_context *ldb;
	int ret;
	static const char *attrs[] = {
		"replUpToDateVector",
		"repsFrom",
		NULL
	};
	struct ldb_request *search_req;

	ldb = ldb_module_get_ctx(ar->module);
	ar->search_msg = NULL;

	ret = ldb_build_search_req(&search_req,
				   ldb,
				   ar,
				   ar->objs->partition_dn,
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs,
				   NULL,
				   ar,
				   replmd_replicated_uptodate_search_callback,
				   ar->req);
	if (ret != LDB_SUCCESS) return replmd_replicated_request_error(ar, ret);

	return ldb_next_request(ar->module, search_req);
}

static int replmd_extended_replicated_objects(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct dsdb_extended_replicated_objects *objs;
	struct replmd_replicated_request *ar;
	struct ldb_control **ctrls;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "replmd_extended_replicated_objects\n");

	objs = talloc_get_type(req->op.extended.data, struct dsdb_extended_replicated_objects);
	if (!objs) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "replmd_extended_replicated_objects: invalid extended data\n");
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (objs->version != DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "replmd_extended_replicated_objects: extended data invalid version [%u != %u]\n",
			  objs->version, DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	ar = replmd_ctx_init(module, req);
	if (!ar)
		return LDB_ERR_OPERATIONS_ERROR;

	ar->objs = objs;
	ar->schema = dsdb_get_schema(ldb);
	if (!ar->schema) {
		ldb_debug_set(ldb, LDB_DEBUG_FATAL, "replmd_ctx_init: no loaded schema found\n");
		talloc_free(ar);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	ctrls = req->controls;

	if (req->controls) {
		req->controls = talloc_memdup(ar, req->controls,
					      talloc_get_size(req->controls));
		if (!req->controls) return replmd_replicated_request_werror(ar, WERR_NOMEM);
	}

	ret = ldb_request_add_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID, false, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ar->controls = req->controls;
	req->controls = ctrls;

	return replmd_replicated_apply_next(ar);
}

static int replmd_extended(struct ldb_module *module, struct ldb_request *req)
{
	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_REPLICATED_OBJECTS_OID) == 0) {
		return replmd_extended_replicated_objects(module, req);
	}

	return ldb_next_request(module, req);
}

_PUBLIC_ const struct ldb_module_ops ldb_repl_meta_data_module_ops = {
	.name          = "repl_meta_data",
	.add           = replmd_add,
	.modify        = replmd_modify,
	.extended      = replmd_extended,
};
