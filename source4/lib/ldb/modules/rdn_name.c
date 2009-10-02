/* 
   ldb database library

   Copyright (C) Andrew Bartlett 2005-2009
   Copyright (C) Simo Sorce 2006-2008
   Copyright (C) Matthias Dieter Wallnöfer 2009

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
 *  Name: rdn_name
 *
 *  Component: ldb rdn name module
 *
 *  Description: keep a consistent name attribute on objects manpulations
 *
 *  Author: Andrew Bartlett
 *
 *  Modifications:
 *    - made the module async
 *      Simo Sorce Mar 2006
 */

#include "ldb_includes.h"
#include "ldb_module.h"

struct rdn_name_private {
	/* rename operation? */
	bool rename;
};

struct rename_context {
	struct ldb_module *module;
	struct ldb_request *req;

	struct ldb_reply *ares;
};

static int rdn_name_init(struct ldb_module *module)
{
	struct rdn_name_private *rdn_name_private;
	struct ldb_context *ldb = ldb_module_get_ctx(module);

	rdn_name_private = talloc_zero(module, struct rdn_name_private);
	if (rdn_name_private == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ldb_module_set_private(module, rdn_name_private);

	return ldb_next_init(module);
}

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

static int rdn_name_add_callback(struct ldb_request *req,
				 struct ldb_reply *ares)
{
	struct rename_context *ac;

	ac = talloc_get_type(req->context, struct rename_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	return ldb_module_done(ac->req, ares->controls,
					ares->response, LDB_SUCCESS);
}

static int rdn_name_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_request *down_req;
	struct rename_context *ac;
	struct ldb_message *msg;
	struct ldb_message_element *attribute;
	const struct ldb_schema_attribute *a;
	const char *rdn_name;
	struct ldb_val rdn_val;
	int i, ret;

	ldb = ldb_module_get_ctx(module);
	ldb_debug(ldb, LDB_DEBUG_TRACE, "rdn_name_add_record");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	ac = talloc_zero(req, struct rename_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;

	msg = ldb_msg_copy_shallow(req, req->op.add.message);
	if (msg == NULL) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	rdn_name = ldb_dn_get_rdn_name(msg->dn);
	if (rdn_name == NULL) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	rdn_val = ldb_val_dup(msg, ldb_dn_get_rdn_val(msg->dn));
	
	/* Perhaps someone above us tried to set this? */
	if ((attribute = rdn_name_find_attribute(msg, "name")) != NULL ) {
		attribute->num_values = 0;
	}

	if (ldb_msg_add_value(msg, "name", &rdn_val, NULL) != 0) {
		talloc_free(ac);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	attribute = rdn_name_find_attribute(msg, rdn_name);

	if (!attribute) {
		if (ldb_msg_add_value(msg, rdn_name, &rdn_val, NULL) != 0) {
			talloc_free(ac);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		a = ldb_schema_attribute_by_name(ldb, rdn_name);

		for (i = 0; i < attribute->num_values; i++) {
			ret = a->syntax->comparison_fn(ldb, msg,
					&rdn_val, &attribute->values[i]);
			if (ret == 0) {
				/* overwrite so it matches in case */
				attribute->values[i] = rdn_val;
				break;
			}
		}
		if (i == attribute->num_values) {
			char *rdn_errstring = talloc_asprintf(ac,
				"RDN mismatch on %s: %s (%.*s) should match one of:", 
				ldb_dn_get_linearized(msg->dn), rdn_name, 
				(int)rdn_val.length, (const char *)rdn_val.data);
			for (i = 0; i < attribute->num_values; i++) {
				rdn_errstring = talloc_asprintf_append(
					rdn_errstring, " (%.*s)",
					(int)attribute->values[i].length, 
					(const char *)attribute->values[i].data);
			}
			ldb_set_errstring(ldb, rdn_errstring);
			talloc_free(ac);
			/* Match AD's error here */
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
	}

	ret = ldb_build_add_req(&down_req, ldb, req,
				msg,
				req->controls,
				ac, rdn_name_add_callback,
				req);
	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

	talloc_steal(down_req, msg);

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

static int rdn_modify_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct rdn_name_private *rdn_name_private;
	struct rename_context *ac;

	ac = talloc_get_type(req->context, struct rename_context);
	rdn_name_private = talloc_get_type(ldb_module_get_private(ac->module),
						struct rdn_name_private);

	/* our rename is finished */
	rdn_name_private->rename = false;

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	/* the only supported reply right now is a LDB_REPLY_DONE */
	if (ares->type != LDB_REPLY_DONE) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	/* send saved controls eventually */
	return ldb_module_done(ac->req, ac->ares->controls,
				ac->ares->response, LDB_SUCCESS);
}

static int rdn_rename_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct rdn_name_private *rdn_name_private;
	struct rename_context *ac;
	struct ldb_context *ldb;
	struct ldb_request *mod_req;
	const char *rdn_name;
	struct ldb_val rdn_val;
	struct ldb_message *msg;
	int ret;

	ac = talloc_get_type(req->context, struct rename_context);
	ldb = ldb_module_get_ctx(ac->module);
	rdn_name_private = talloc_get_type(ldb_module_get_private(ac->module),
						struct rdn_name_private);

	if (!ares) {
		goto error;
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	/* the only supported reply right now is a LDB_REPLY_DONE */
	if (ares->type != LDB_REPLY_DONE) {
		goto error;
	}

	/* save reply for caller */
	ac->ares = talloc_steal(ac, ares);

	msg = ldb_msg_new(ac);
	if (msg == NULL) {
		goto error;
	}
	msg->dn = ldb_dn_copy(msg, ac->req->op.rename.newdn);
	if (msg->dn == NULL) {
		goto error;
	}
	rdn_name = ldb_dn_get_rdn_name(ac->req->op.rename.newdn);
	if (rdn_name == NULL) {
		goto error;
	}
	
	rdn_val = ldb_val_dup(msg, ldb_dn_get_rdn_val(ac->req->op.rename.newdn));
	
	if (ldb_msg_add_empty(msg, rdn_name, LDB_FLAG_MOD_REPLACE, NULL) != 0) {
		goto error;
	}
	if (ldb_msg_add_value(msg, rdn_name, &rdn_val, NULL) != 0) {
		goto error;
	}
	if (ldb_msg_add_empty(msg, "name", LDB_FLAG_MOD_REPLACE, NULL) != 0) {
		goto error;
	}
	if (ldb_msg_add_value(msg, "name", &rdn_val, NULL) != 0) {
		goto error;
	}

	/* we do a rename */
	rdn_name_private->rename = true;

	ret = ldb_build_mod_req(&mod_req, ldb,
				ac, msg, NULL,
				ac, rdn_modify_callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}
	talloc_steal(mod_req, msg);

	/* do the mod call */
	return ldb_request(ldb, mod_req);

error:
	return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
}

static int rdn_name_rename(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct rename_context *ac;
	struct ldb_request *down_req;
	int ret;

	ldb = ldb_module_get_ctx(module);
	ldb_debug(ldb, LDB_DEBUG_TRACE, "rdn_name_rename");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.rename.newdn)) {
		return ldb_next_request(module, req);
	}

	ac = talloc_zero(req, struct rename_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->req = req;

	ret = ldb_build_rename_req(&down_req,
				   ldb,
				   ac,
				   req->op.rename.olddn,
				   req->op.rename.newdn,
				   req->controls,
				   ac,
				   rdn_rename_callback,
				   req);

	if (ret != LDB_SUCCESS) {
		talloc_free(ac);
		return ret;
	}

	/* rename first, modify "name" if rename is ok */
	return ldb_next_request(module, down_req);
}

static int rdn_name_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct rdn_name_private *rdn_name_private =
		talloc_get_type(ldb_module_get_private(module), struct rdn_name_private);
	struct ldb_context *ldb;

	ldb = ldb_module_get_ctx(module);
	ldb_debug(ldb, LDB_DEBUG_TRACE, "rdn_name_rename");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	if ((!rdn_name_private->rename)
			&& ldb_msg_find_element(req->op.mod.message, "name")) {
		ldb_asprintf_errstring(ldb, "Modify of 'name' on %s not permitted, must use 'rename' operation instead",
				       ldb_dn_get_linearized(req->op.mod.message->dn));
		return LDB_ERR_NOT_ALLOWED_ON_RDN;
	}

	if ((!rdn_name_private->rename)
			&& ldb_msg_find_element(req->op.mod.message, ldb_dn_get_rdn_name(req->op.mod.message->dn))) {
		ldb_asprintf_errstring(ldb, "Modify of RDN '%s' on %s not permitted, must use 'rename' operation instead",
				       ldb_dn_get_rdn_name(req->op.mod.message->dn), ldb_dn_get_linearized(req->op.mod.message->dn));
		return LDB_ERR_NOT_ALLOWED_ON_RDN;
	}

	/* All OK, they kept their fingers out of the special attributes */
	return ldb_next_request(module, req);
}

const struct ldb_module_ops ldb_rdn_name_module_ops = {
	.name              = "rdn_name",
	.init_context	   = rdn_name_init,
	.add               = rdn_name_add,
	.modify            = rdn_name_modify,
	.rename            = rdn_name_rename
};
