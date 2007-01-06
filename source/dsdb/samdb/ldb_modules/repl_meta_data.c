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
#include "librpc/gen_ndr/ndr_misc.h"
#include "dsdb/samdb/samdb.h"

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

static int replmd_add_replicated(struct ldb_module *module, struct ldb_request *req, struct ldb_control *ctrl)
{
	struct ldb_control **saved_ctrls;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "replmd_add_replicated\n");

	if (!save_controls(ctrl, req, &saved_ctrls)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_next_request(module, req);
	req->controls = saved_ctrls;

	return ret;
}

static int replmd_add_originating(struct ldb_module *module, struct ldb_request *req)
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
	struct ldb_control *ctrl;

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	ctrl = get_control_from_list(req->controls, DSDB_CONTROL_REPLICATED_OBJECT_OID);
	if (ctrl) {
		/* handle replicated objects different */
		return replmd_add_replicated(module, req, ctrl);
	}

	return replmd_add_originating(module, req);
}

static int replmd_modify_replicated(struct ldb_module *module, struct ldb_request *req, struct ldb_control *ctrl)
{
	struct ldb_control **saved_ctrls;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "replmd_modify_replicated\n");

	if (!save_controls(ctrl, req, &saved_ctrls)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_next_request(module, req);
	req->controls = saved_ctrls;

	return ret;
}

static int replmd_modify_originating(struct ldb_module *module, struct ldb_request *req)
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
	struct ldb_control *ctrl;

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	ctrl = get_control_from_list(req->controls, DSDB_CONTROL_REPLICATED_OBJECT_OID);
	if (ctrl) {
		/* handle replicated objects different */
		return replmd_modify_replicated(module, req, ctrl);
	}

	return replmd_modify_originating(module, req);
}

static const struct ldb_module_ops replmd_ops = {
	.name          = "repl_meta_data",
	.add           = replmd_add,
	.modify        = replmd_modify,
};

int repl_meta_data_module_init(void)
{
	return ldb_register_module(&replmd_ops);
}
