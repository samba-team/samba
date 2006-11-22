/* 
   ldb database library

   Copyright (C) Andrew Bartlett 2005
   Copyright (C) Simo Sorce 2006

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
};

static int kludge_acl_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct kludge_acl_context *ac;
	struct kludge_private_data *data;
	int i;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		goto error;
	}

	ac = talloc_get_type(context, struct kludge_acl_context);
	data = talloc_get_type(ac->module->private_data, struct kludge_private_data);

	if (ares->type == LDB_REPLY_ENTRY
		&& data->password_attrs) /* if we are not initialized just get through */
	{
		switch (ac->user_type) {
		case SYSTEM:
		case ADMINISTRATOR:
			break;
		default:
			/* remove password attributes */
			for (i = 0; data->password_attrs[i]; i++) {
				ldb_msg_remove_attr(ares->message, data->password_attrs[i]);
			}
		}
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
	int ret;

	req->handle = NULL;

	ac = talloc(req, struct kludge_acl_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->up_context = req->context;
	ac->up_callback = req->callback;
	ac->user_type = what_is_user(module);

	down_req = talloc_zero(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	down_req->operation = req->operation;
	down_req->op.search.base = req->op.search.base;
	down_req->op.search.scope = req->op.search.scope;
	down_req->op.search.tree = req->op.search.tree;
	down_req->op.search.attrs = req->op.search.attrs;
	
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
	.init_context	   = kludge_acl_init
};

int ldb_kludge_acl_init(void)
{
	return ldb_register_module(&kludge_acl_ops);
}
