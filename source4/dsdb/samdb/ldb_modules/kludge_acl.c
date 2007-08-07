/* 
   ldb database library

   Copyright (C) Andrew Bartlett 2005
   Copyright (C) Simo Sorce 2006

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

/*
 *  Name: ldb
 *
 *  Component: ldb kludge ACL module
 *
 *  Description: Simple module to enforce a simple form of access
 *               control, sufficient for securing a default Samba4 
 *               installation.
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"

/* Kludge ACL rules:
 *
 * - System can read passwords
 * - Administrators can write anything
 * - Users can read anything that is not a password
 *
 */

enum user_is {
	ANONYMOUS,
	USER,
	ADMINISTRATOR,
	SYSTEM
};

struct kludge_private_data {
	const char **password_attrs;
};

static enum user_is what_is_user(struct ldb_module *module) 
{
	struct auth_session_info *session_info
		= ldb_get_opaque(module->ldb, "sessionInfo");
	if (!session_info) {
		return ANONYMOUS;
	}
	
	if (security_token_is_system(session_info->security_token)) {
		return SYSTEM;
	}

	if (security_token_is_anonymous(session_info->security_token)) {
		return ANONYMOUS;
	}

	if (security_token_has_builtin_administrators(session_info->security_token)) {
		return ADMINISTRATOR;
	}

	if (security_token_has_nt_authenticated_users(session_info->security_token)) {
		return USER;
	}

	return ANONYMOUS;
}

static const char *user_name(TALLOC_CTX *mem_ctx, struct ldb_module *module) 
{
	struct auth_session_info *session_info
		= ldb_get_opaque(module->ldb, "sessionInfo");
	if (!session_info) {
		return "UNKNOWN (NULL)";
	}
	
	return talloc_asprintf(mem_ctx, "%s\\%s",
			       session_info->server_info->domain_name,
			       session_info->server_info->account_name);
}

/* search */
struct kludge_acl_context {

	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_reply *);

	enum user_is user_type;
	bool allowedAttributes;
	bool allowedAttributesEffective;
	bool allowedChildClasses;
	bool allowedChildClassesEffective;
	const char **attrs;
};

/* read all objectClasses */

static int kludge_acl_allowedAttributes(struct ldb_context *ldb, struct ldb_message *msg,
					const char *attrName) 
{
	struct ldb_message_element *oc_el;
	struct ldb_message_element *allowedAttributes;
	const struct dsdb_schema *schema = dsdb_get_schema(ldb);
	const struct dsdb_class *class;
	int i, j, ret;
	/* Must remove any existing attribute, or else confusion reins */
	ldb_msg_remove_attr(msg, attrName);
	ret = ldb_msg_add_empty(msg, attrName, 0, &allowedAttributes);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	
	/* To ensure that oc_el is valid, we must look for it after 
	   we alter the element array in ldb_msg_add_empty() */
	oc_el = ldb_msg_find_element(msg, "objectClass");

	for (i=0; oc_el && i < oc_el->num_values; i++) {
		class = dsdb_class_by_lDAPDisplayName(schema, (const char *)oc_el->values[i].data);
		if (!class) {
			/* We don't know this class?  what is going on? */
			continue;
		}

		for (j=0; class->mayContain && class->mayContain[j]; j++) {
			ldb_msg_add_string(msg, attrName, class->mayContain[j]);
		}
		for (j=0; class->mustContain && class->mustContain[j]; j++) {
			ldb_msg_add_string(msg, attrName, class->mustContain[j]);
		}
		for (j=0; class->systemMayContain && class->systemMayContain[j]; j++) {
			ldb_msg_add_string(msg, attrName, class->systemMayContain[j]);
		}
		for (j=0; class->systemMustContain && class->systemMustContain[j]; j++) {
			ldb_msg_add_string(msg, attrName, class->systemMustContain[j]);
		}
	}
		
	if (allowedAttributes->num_values > 1) {
		qsort(allowedAttributes->values, 
		      allowedAttributes->num_values, 
		      sizeof(*allowedAttributes->values),
		      (comparison_fn_t)data_blob_cmp);
	
		for (i=1 ; i < allowedAttributes->num_values; i++) {
			struct ldb_val *val1 = &allowedAttributes->values[i-1];
			struct ldb_val *val2 = &allowedAttributes->values[i];
			if (data_blob_cmp(val1, val2) == 0) {
				memmove(val1, val2, (allowedAttributes->num_values - i) * sizeof( struct ldb_val)); 
				allowedAttributes->num_values--;
				i--;
			}
		}
	}

	return 0;

}
/* read all objectClasses */

static int kludge_acl_childClasses(struct ldb_context *ldb, struct ldb_message *msg,
				   const char *attrName) 
{
	struct ldb_message_element *oc_el;
	struct ldb_message_element *allowedClasses;
	const struct dsdb_schema *schema = dsdb_get_schema(ldb);
	const struct dsdb_class *class;
	int i, j, ret;
	/* Must remove any existing attribute, or else confusion reins */
	ldb_msg_remove_attr(msg, attrName);
	ret = ldb_msg_add_empty(msg, attrName, 0, &allowedClasses);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	
	/* To ensure that oc_el is valid, we must look for it after 
	   we alter the element array in ldb_msg_add_empty() */
	oc_el = ldb_msg_find_element(msg, "objectClass");

	for (i=0; oc_el && i < oc_el->num_values; i++) {
		class = dsdb_class_by_lDAPDisplayName(schema, (const char *)oc_el->values[i].data);
		if (!class) {
			/* We don't know this class?  what is going on? */
			continue;
		}

		for (j=0; class->possibleInferiors && class->possibleInferiors[j]; j++) {
			ldb_msg_add_string(msg, attrName, class->possibleInferiors[j]);
		}
	}
		
	if (allowedClasses->num_values > 1) {
		qsort(allowedClasses->values, 
		      allowedClasses->num_values, 
		      sizeof(*allowedClasses->values),
		      (comparison_fn_t)data_blob_cmp);
	
		for (i=1 ; i < allowedClasses->num_values; i++) {
			struct ldb_val *val1 = &allowedClasses->values[i-1];
			struct ldb_val *val2 = &allowedClasses->values[i];
			if (data_blob_cmp(val1, val2) == 0) {
				memmove(val1, val2, (allowedClasses->num_values - i) * sizeof( struct ldb_val)); 
				allowedClasses->num_values--;
				i--;
			}
		}
	}

	return 0;

}

/* find all attributes allowed by all these objectClasses */

static int kludge_acl_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct kludge_acl_context *ac;
	struct kludge_private_data *data;
	int i, ret;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		goto error;
	}

	ac = talloc_get_type(context, struct kludge_acl_context);
	data = talloc_get_type(ac->module->private_data, struct kludge_private_data);

	if (ares->type != LDB_REPLY_ENTRY) {
		return ac->up_callback(ldb, ac->up_context, ares);
	}

	if (ac->allowedAttributes) {
		ret = kludge_acl_allowedAttributes(ldb, ares->message, "allowedAttributes");
		if (ret != LDB_SUCCESS) {
			return ret;

		}
	}
	if (ac->allowedChildClasses) {
		ret = kludge_acl_childClasses(ldb, ares->message, "allowedChildClasses");
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	if (data && data->password_attrs) /* if we are not initialized just get through */
	{
		switch (ac->user_type) {
		case SYSTEM:
		case ADMINISTRATOR:
			if (ac->allowedAttributesEffective) {
				ret = kludge_acl_allowedAttributes(ldb, ares->message, "allowedAttributesEffective");
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
			if (ac->allowedChildClassesEffective) {
				ret = kludge_acl_childClasses(ldb, ares->message, "allowedChildClassesEffective");
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
			break;
		default:
			/* remove password attributes */
			for (i = 0; data->password_attrs[i]; i++) {
				ldb_msg_remove_attr(ares->message, data->password_attrs[i]);
			}
		}
	}

	if ((ac->allowedAttributes || ac->allowedAttributesEffective
	     || ac->allowedChildClasses || ac->allowedChildClassesEffective) && 
	    (!ldb_attr_in_list(ac->attrs, "objectClass") && 
	     !ldb_attr_in_list(ac->attrs, "*"))) {
		ldb_msg_remove_attr(ares->message, "objectClass");
	}

	return ac->up_callback(ldb, ac->up_context, ares);

error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int kludge_acl_search(struct ldb_module *module, struct ldb_request *req)
{
	struct kludge_acl_context *ac;
	struct ldb_request *down_req;
	struct kludge_private_data *data;
	int ret, i;

	req->handle = NULL;

	ac = talloc(req, struct kludge_acl_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data = talloc_get_type(module->private_data, struct kludge_private_data);

	ac->module = module;
	ac->up_context = req->context;
	ac->up_callback = req->callback;
	ac->user_type = what_is_user(module);
	ac->attrs = req->op.search.attrs;

	down_req = talloc_zero(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	down_req->operation = req->operation;
	down_req->op.search.base = req->op.search.base;
	down_req->op.search.scope = req->op.search.scope;
	down_req->op.search.tree = req->op.search.tree;
	down_req->op.search.attrs = req->op.search.attrs;

	ac->allowedAttributes = ldb_attr_in_list(req->op.search.attrs, "allowedAttributes");

	ac->allowedAttributesEffective = ldb_attr_in_list(req->op.search.attrs, "allowedAttributesEffective");

	ac->allowedChildClasses = ldb_attr_in_list(req->op.search.attrs, "allowedChildClasses");

	ac->allowedChildClassesEffective = ldb_attr_in_list(req->op.search.attrs, "allowedChildClassesEffective");

	if (ac->allowedAttributes || ac->allowedAttributesEffective || ac->allowedChildClasses || ac->allowedChildClassesEffective) {
		down_req->op.search.attrs
			= ldb_attr_list_copy_add(down_req, down_req->op.search.attrs, "objectClass");
	}

	/*  FIXME: I hink we should copy the tree and keep the original
	 *  unmodified. SSS */
	/* replace any attributes in the parse tree that are private,
	   so we don't allow a search for 'sambaPassword=penguin',
	   just as we would not allow that attribute to be returned */
	switch (ac->user_type) {
	case SYSTEM:
		break;
	default:
		/* remove password attributes */
		for (i = 0; data && data->password_attrs && data->password_attrs[i]; i++) {
			ldb_parse_tree_attr_replace(down_req->op.search.tree, 
						    data->password_attrs[i],
						    "kludgeACLredactedattribute");
		}
	}

	down_req->controls = req->controls;

	down_req->context = ac;
	down_req->callback = kludge_acl_callback;
	ldb_set_timeout_from_prev_req(module->ldb, req, down_req);

	/* perform the search */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->handle = down_req->handle;
	}

	return ret;
}

/* ANY change type */
static int kludge_acl_change(struct ldb_module *module, struct ldb_request *req)
{
	enum user_is user_type = what_is_user(module);
	switch (user_type) {
	case SYSTEM:
	case ADMINISTRATOR:
		return ldb_next_request(module, req);
	default:
		ldb_asprintf_errstring(module->ldb,
				       "kludge_acl_change: "
				       "attempted database modify not permitted. "
				       "User %s is not SYSTEM or an administrator",
				       user_name(req, module));
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
}

static int kludge_acl_init(struct ldb_module *module)
{
	int ret, i;
	TALLOC_CTX *mem_ctx = talloc_new(module);
	static const char *attrs[] = { "passwordAttribute", NULL };
	struct ldb_result *res;
	struct ldb_message *msg;
	struct ldb_message_element *password_attributes;

	struct kludge_private_data *data;

	data = talloc(module, struct kludge_private_data);
	if (data == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data->password_attrs = NULL;
	module->private_data = data;

	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_search(module->ldb, ldb_dn_new(mem_ctx, module->ldb, "@KLUDGEACL"),
			 LDB_SCOPE_BASE,
			 NULL, attrs,
			 &res);
	if (ret != LDB_SUCCESS) {
		goto done;
	}
	talloc_steal(mem_ctx, res);
	if (res->count == 0) {
		goto done;
	}

	if (res->count > 1) {
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	msg = res->msgs[0];

	password_attributes = ldb_msg_find_element(msg, "passwordAttribute");
	if (!password_attributes) {
		goto done;
	}
	data->password_attrs = talloc_array(data, const char *, password_attributes->num_values + 1);
	if (!data->password_attrs) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	for (i=0; i < password_attributes->num_values; i++) {
		data->password_attrs[i] = (const char *)password_attributes->values[i].data;	
		talloc_steal(data->password_attrs, password_attributes->values[i].data);
	}
	data->password_attrs[i] = NULL;

done:
	talloc_free(mem_ctx);
	return ldb_next_init(module);
}

static const struct ldb_module_ops kludge_acl_ops = {
	.name		   = "kludge_acl",
	.search            = kludge_acl_search,
	.add               = kludge_acl_change,
	.modify            = kludge_acl_change,
	.del               = kludge_acl_change,
	.rename            = kludge_acl_change,
	.extended          = kludge_acl_change,
	.init_context	   = kludge_acl_init
};

int ldb_kludge_acl_init(void)
{
	return ldb_register_module(&kludge_acl_ops);
}
