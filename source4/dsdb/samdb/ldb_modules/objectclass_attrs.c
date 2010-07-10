/*
   ldb database library

   Copyright (C) Simo Sorce  2006-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Matthias Dieter Wallnöfer 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: objectclass attribute checking module
 *
 *  Description: this checks the attributes on a directory entry (if they're
 *    allowed, if the syntax is correct, if mandatory ones are missing,
 *    denies the deletion of mandatory ones...). The module contains portions
 *    of the "objectclass" and the "validate_update" LDB module.
 *
 *  Author: Matthias Dieter Wallnöfer
 */

#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"

struct oc_context {

	struct ldb_module *module;
	struct ldb_request *req;
	const struct dsdb_schema *schema;

	struct ldb_reply *search_res;
	struct ldb_reply *mod_ares;
};

static struct oc_context *oc_init_context(struct ldb_module *module,
					  struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct oc_context *ac;

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct oc_context);
	if (ac == NULL) {
		ldb_oom(ldb);
		return NULL;
	}

	ac->module = module;
	ac->req = req;
	ac->schema = dsdb_get_schema(ldb, ac);

	return ac;
}

static int oc_op_callback(struct ldb_request *req, struct ldb_reply *ares);

static int attr_handler(struct oc_context *ac)
{
	struct ldb_context *ldb;
	struct ldb_message *msg;
	struct ldb_request *child_req;
	const struct dsdb_attribute *attr;
	unsigned int i;
	int ret;
	WERROR werr;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->req->operation == LDB_ADD) {
		msg = ldb_msg_copy_shallow(ac, ac->req->op.add.message);
	} else {
		msg = ldb_msg_copy_shallow(ac, ac->req->op.mod.message);
	}
	if (msg == NULL) {
		return ldb_oom(ldb);
	}

	/* Check if attributes exist in the schema, if the values match,
	 * if they're not operational and fix the names to the match the schema
	 * case */
	for (i = 0; i < msg->num_elements; i++) {
		attr = dsdb_attribute_by_lDAPDisplayName(ac->schema,
							 msg->elements[i].name);
		if (attr == NULL) {
			ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' was not found in the schema!",
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		}

		if ((attr->linkID & 1) == 1) {
			/* Odd is for the target.  Illegal to modify */
			ldb_asprintf_errstring(ldb, 
					       "objectclass_attrs: attribute '%s' on entry '%s' must not be modified directly, it is a linked attribute", 
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		
		werr = attr->syntax->validate_ldb(ldb, ac->schema, attr,
						  &msg->elements[i]);
		if (!W_ERROR_IS_OK(werr)) {
			ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' contains at least one invalid value!",
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}

		if ((attr->systemFlags & DS_FLAG_ATTR_IS_CONSTRUCTED) != 0) {
			ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' is constructed!",
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			if (ac->req->operation == LDB_ADD) {
				return LDB_ERR_UNDEFINED_ATTRIBUTE_TYPE;
			} else {
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		}

		/* subsitute the attribute name to match in case */
		msg->elements[i].name = attr->lDAPDisplayName;
	}

	if (ac->req->operation == LDB_ADD) {
		ret = ldb_build_add_req(&child_req, ldb, ac,
					msg, ac->req->controls,
					ac, oc_op_callback, ac->req);
	} else {
		ret = ldb_build_mod_req(&child_req, ldb, ac,
					msg, ac->req->controls,
					ac, oc_op_callback, ac->req);
	}
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, child_req);
}

/*
  these are attributes which are left over from old ways of doing
  things in ldb, and are harmless
 */
static const char *harmless_attrs[] = { "parentGUID", NULL };

static int attr_handler2(struct oc_context *ac)
{
	struct ldb_context *ldb;
	struct ldb_message_element *oc_element;
	struct ldb_message *msg;
	const char **must_contain, **may_contain, **found_must_contain;
	const struct dsdb_attribute *attr;
	unsigned int i;
	bool found;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->search_res == NULL) {
		return ldb_operr(ldb);
	}

	/* We rely here on the preceeding "objectclass" LDB module which did
	 * already fix up the objectclass list (inheritance, order...). */
	oc_element = ldb_msg_find_element(ac->search_res->message,
					  "objectClass");
	if (oc_element == NULL) {
		return ldb_operr(ldb);
	}

	must_contain = dsdb_full_attribute_list(ac, ac->schema, oc_element,
						DSDB_SCHEMA_ALL_MUST);
	may_contain =  dsdb_full_attribute_list(ac, ac->schema, oc_element,
						DSDB_SCHEMA_ALL_MAY);
	found_must_contain = const_str_list(str_list_copy(ac, must_contain));
	if ((must_contain == NULL) || (may_contain == NULL)
	    || (found_must_contain == NULL)) {
		return ldb_operr(ldb);
	}

	/* Check if all specified attributes are valid in the given
	 * objectclasses and if they meet additional schema restrictions. */
	msg = ac->search_res->message;
	for (i = 0; i < msg->num_elements; i++) {
		attr = dsdb_attribute_by_lDAPDisplayName(ac->schema,
							 msg->elements[i].name);
		if (attr == NULL) {
			return ldb_operr(ldb);
		}

		/* Check if they're single-valued if this is requested */
		if ((msg->elements[i].num_values > 1) && (attr->isSingleValued)) {
			ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' is single-valued!",
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			if (ac->req->operation == LDB_ADD) {
				return LDB_ERR_CONSTRAINT_VIOLATION;
			} else {
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			}
		}

		/* We can use "str_list_check" with "strcmp" here since the
		 * attribute informations from the schema are always equal
		 * up-down-cased. */
		found = str_list_check(must_contain, attr->lDAPDisplayName);
		if (found) {
			str_list_remove(found_must_contain, attr->lDAPDisplayName);
		} else {
			found = str_list_check(may_contain, attr->lDAPDisplayName);
		}
		if (!found) {
			found = str_list_check(harmless_attrs, attr->lDAPDisplayName);
		}
		if (!found) {
			ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' does not exist in the specified objectclasses!",
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}
	}

	if (found_must_contain[0] != NULL) {
		ldb_asprintf_errstring(ldb, "objectclass_attrs: at least one mandatory attribute ('%s') on entry '%s' wasn't specified!",
				       found_must_contain[0],
				       ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	return ldb_module_done(ac->req, ac->mod_ares->controls,
			       ac->mod_ares->response, LDB_SUCCESS);
}

static int get_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct oc_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct oc_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
				       ares->response, ares->error);
	}

	ldb_reset_err_string(ldb);

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ac->search_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_ERR_OPERATIONS_ERROR);
		}

		ac->search_res = talloc_steal(ac, ares);
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);
		ret = attr_handler2(ac);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		break;
	}

	return LDB_SUCCESS;
}

static int oc_op_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct oc_context *ac;
	struct ldb_context *ldb;
	struct ldb_request *search_req;
	struct ldb_dn *base_dn;
	int ret;

	ac = talloc_get_type(req->context, struct oc_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(ac->req, ares->referral);
	}

	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls, ares->response,
				       ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}

	ac->search_res = NULL;
	ac->mod_ares = talloc_steal(ac, ares);

	/* This looks up all attributes of our just added/modified entry */
	base_dn = ac->req->operation == LDB_ADD ? ac->req->op.add.message->dn
		: ac->req->op.mod.message->dn;
	ret = ldb_build_search_req(&search_req, ldb, ac, base_dn,
				   LDB_SCOPE_BASE, "(objectClass=*)",
				   NULL, NULL, ac,
				   get_search_callback, ac->req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	ret = ldb_request_add_control(search_req, LDB_CONTROL_SHOW_DELETED_OID,
				      true, NULL);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	ret = ldb_next_request(ac->module, search_req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	/* "ldb_module_done" isn't called here since we need to do additional
	 * checks. It is called at the end of "attr_handler2". */
	return LDB_SUCCESS;
}

static int objectclass_attrs_add(struct ldb_module *module,
				 struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct oc_context *ac;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_attrs_add\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* without schema, there isn't much to do here */
	if (ac->schema == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	return attr_handler(ac);
}

static int objectclass_attrs_modify(struct ldb_module *module,
				    struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct oc_context *ac;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_attrs_modify\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* without schema, there isn't much to do here */
	if (ac->schema == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	return attr_handler(ac);
}

_PUBLIC_ const struct ldb_module_ops ldb_objectclass_attrs_module_ops = {
	.name		   = "objectclass_attrs",
	.add               = objectclass_attrs_add,
	.modify            = objectclass_attrs_modify
};
