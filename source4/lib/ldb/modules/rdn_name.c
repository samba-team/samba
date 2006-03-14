/* 
   ldb database library

   Copyright (C) Andrew Bartlet 2005
   Copyright (C) Simo Sorce     2006

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
 *  Name: rdb_name
 *
 *  Component: ldb rdn name module
 *
 *  Description: keep a consistent name attribute on objects manpulations
 *
 *  Author: Andrew Bartlet
 *
 *  Modifications:
 *    - made the module async
 *      Simo Sorce Mar 2006
 */

#include "includes.h"
#include "ldb/include/includes.h"

static struct ldb_message_element *rdn_name_find_attribute(const struct ldb_message *msg, const char *name)
{
	int i;

	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(name, msg->elements[i].name) == 0) {
			return &msg->elements[i];
		}
	}

	return NULL;
}

static int rdn_name_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;
	int i, ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "rdn_name_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	msg2 = talloc(module, struct ldb_message);
	if (!msg2) {
		return -1;
	}

	msg2->dn = msg->dn;
	msg2->num_elements = msg->num_elements;
	msg2->private_data = msg->private_data;
	msg2->elements = talloc_array(msg2, struct ldb_message_element, msg2->num_elements);
	for (i = 0; i < msg2->num_elements; i++) {
		msg2->elements[i] = msg->elements[i];
	}

	rdn = ldb_dn_get_rdn(msg2, msg2->dn);
	if (!rdn) {
		talloc_free(msg2);
		return -1;
	}
	
	/* Perhaps someone above us tried to set this? */
	if ((attribute = rdn_name_find_attribute(msg, "name")) != NULL ) {
		attribute->num_values = 0;
	}

	if (ldb_msg_add_value(msg2, "name", &rdn->value) != 0) {
		talloc_free(msg2);
		return -1;
	}

	attribute = rdn_name_find_attribute(msg2, rdn->name);

	if (!attribute) {
		if (ldb_msg_add_value(msg2, rdn->name, &rdn->value) != 0) {
			talloc_free(msg2);
			return -1;
		}
	} else {
		const struct ldb_attrib_handler *handler
			= ldb_attrib_handler(module->ldb, rdn->name);
		for (i=0; i < attribute->num_values; i++) {
			if (handler->comparison_fn(module->ldb, msg2, &rdn->value, &attribute->values[i]) == 0) {
				/* overwrite so it matches in case */
				attribute->values[i] = rdn->value;
				break;
			}
		}
		if (i == attribute->num_values) {
			ldb_debug_set(module->ldb, LDB_DEBUG_FATAL, 
				      "RDN mismatch on %s: %s", 
				      ldb_dn_linearize(msg2, msg2->dn), rdn->name);
			talloc_free(msg2);
			return -1;
		}
	}

	req->op.add.message = msg2;
	ret = ldb_next_request(module, req);
	req->op.add.message = msg;

	talloc_free(msg2);

	return ret;
}

static int rdn_name_modify(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.mod.message;
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;
	int ret, i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "rdn_name_modify_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	/* Perhaps someone above us knows better */
	if ((attribute = rdn_name_find_attribute(msg, "name")) != NULL ) {
		return ldb_next_request(module, req);
	}

	msg2 = talloc(module, struct ldb_message);
	if (!msg2) {
		return -1;
	}

	msg2->dn = msg->dn;
	msg2->num_elements = msg->num_elements;
	msg2->private_data = msg->private_data;
	msg2->elements = talloc_array(msg2, struct ldb_message_element, msg2->num_elements);
	for (i = 0; i < msg2->num_elements; i++) {
		msg2->elements[i] = msg->elements[i];
	}
	
	rdn = ldb_dn_get_rdn(msg2, msg2->dn);
	if (!rdn) {
		talloc_free(msg2);
		return -1;
	}
	
	if (ldb_msg_add_value(msg2, "name", &rdn->value) != 0) {
		talloc_free(msg2);
		return -1;
	}

	attribute = rdn_name_find_attribute(msg2, "name");
	if (!attribute) {
		talloc_free(msg2);
		return -1;
	}

	attribute->flags = LDB_FLAG_MOD_REPLACE;

	req->op.add.message = msg2;
	ret = ldb_next_request(module, req);
	req->op.add.message = msg;

	talloc_free(msg2);

	return ret;
}

static int rdn_name_add_async(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_request *down_req;
	struct ldb_message *msg;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;
	int i, ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "rdn_name_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	down_req = talloc(module, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg = ldb_msg_copy_shallow(down_req, req->op.add.message);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	rdn = ldb_dn_get_rdn(msg, msg->dn);
	if (rdn == NULL) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* Perhaps someone above us tried to set this? */
	if ((attribute = rdn_name_find_attribute(msg, "name")) != NULL ) {
		attribute->num_values = 0;
	}

	if (ldb_msg_add_value(msg, "name", &rdn->value) != 0) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	attribute = rdn_name_find_attribute(msg, rdn->name);

	if (!attribute) {
		if (ldb_msg_add_value(msg, rdn->name, &rdn->value) != 0) {
			talloc_free(down_req);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		const struct ldb_attrib_handler *handler = ldb_attrib_handler(module->ldb, rdn->name);

		for (i = 0; i < attribute->num_values; i++) {
			if (handler->comparison_fn(module->ldb, msg, &rdn->value, &attribute->values[i]) == 0) {
				/* overwrite so it matches in case */
				attribute->values[i] = rdn->value;
				break;
			}
		}
		if (i == attribute->num_values) {
			ldb_debug_set(module->ldb, LDB_DEBUG_FATAL, 
				      "RDN mismatch on %s: %s", 
				      ldb_dn_linearize(msg, msg->dn), rdn->name);
			talloc_free(down_req);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	down_req->op.add.message = msg;
	
	down_req->controls = req->controls;
	down_req->creds = req->creds;

	down_req->async.context = req->async.context;
	down_req->async.callback = req->async.callback;
	down_req->async.timeout = req->async.timeout;

	/* go on with the call chain */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->async.handle = down_req->async.handle;
	}

	return ret;
}

static int rdn_name_modify_async(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_request *down_req;
	struct ldb_message *msg;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "rdn_name_modify_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	/* Perhaps someone above us knows better */
	if ((attribute = rdn_name_find_attribute(req->op.mod.message, "name")) != NULL ) {
		return ldb_next_request(module, req);
	}

	/* FIXME: are we sure we wont to change "name" on each and every modify operation ?? */
	down_req = talloc(module, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	msg = ldb_msg_copy_shallow(down_req, req->op.add.message);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	rdn = ldb_dn_get_rdn(msg, msg->dn);
	if (rdn == NULL) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	if (ldb_msg_add_value(msg, "name", &rdn->value) != 0) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	attribute = rdn_name_find_attribute(msg, "name");
	if (!attribute) {
		talloc_free(down_req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	attribute->flags = LDB_FLAG_MOD_REPLACE;

	down_req->op.add.message = msg;
	
	down_req->controls = req->controls;
	down_req->creds = req->creds;

	down_req->async.context = req->async.context;
	down_req->async.callback = req->async.callback;
	down_req->async.timeout = req->async.timeout;

	/* go on with the call chain */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->async.handle = down_req->async.handle;
	}

	return ret;
}

static int rdn_name_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_ADD:
		return rdn_name_add(module, req);

	case LDB_REQ_MODIFY:
		return rdn_name_modify(module, req);

	case LDB_ASYNC_ADD:
		return rdn_name_add_async(module, req);

	case LDB_ASYNC_MODIFY:
		return rdn_name_modify_async(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static const struct ldb_module_ops rdn_name_ops = {
	.name              = "rdn_name",
	.request           = rdn_name_request
};


int ldb_rdn_name_init(void)
{
	return ldb_register_module(&rdn_name_ops);
}
