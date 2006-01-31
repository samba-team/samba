/* 
   ldb database library

   Copyright (C) Andrew Bartlett 2005

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
	
	if (is_system_token(session_info->security_token)) {
		return SYSTEM;
	}

	if (is_administrator_token(session_info->security_token)) {
		return ADMINISTRATOR;
	}
	if (is_authenticated_token(session_info->security_token)) {
		return USER;
	}
	if (is_anonymous_token(session_info->security_token)) {
		return ANONYMOUS;
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
	return ANONYMOUS;
}

/* search */
static int kludge_acl_search(struct ldb_module *module, struct ldb_request *req)
{
	struct kludge_private_data *data = talloc_get_type(module->private_data, struct kludge_private_data);
	struct ldb_message *msg;
	enum user_is user_type;
	int i, j, ret;

	/* go down the path and wait for reply to filter out stuff if needed */
	ret = ldb_next_request(module, req);

	/* We may not be fully initialised yet, or we might have just
	 * got an error */
	if (ret != LDB_SUCCESS || !data->password_attrs) {
		return ret;
	}

	user_type = what_is_user(module);
	switch (user_type) {
	case SYSTEM:
	case ADMINISTRATOR:
		return ret;
	default:
		/* For every message, remove password attributes */
		for (i=0; i < req->op.search.res->count; i++) {
			msg = req->op.search.res->msgs[i];
			for (j=0; data->password_attrs[j]; j++) {
				ldb_msg_remove_attr(msg, data->password_attrs[j]);
			}
		}
	}
	return ret;
}

/* ANY change type */
static int kludge_acl_change(struct ldb_module *module, struct ldb_request *req){
	enum user_is user_type = what_is_user(module);
	switch (user_type) {
	case SYSTEM:
	case ADMINISTRATOR:
		return ldb_next_request(module, req);
	default:
		ldb_set_errstring(module, 
				  talloc_asprintf(req, "kludge_acl_change: "
						  "attempted database modify not permitted. User %s is not SYSTEM or an administrator",
						  user_name(req, module)));
		return LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS;
	}
}

/* start a transaction */
static int kludge_acl_start_trans(struct ldb_module *module)
{
	return ldb_next_start_trans(module);
}

/* end a transaction */
static int kludge_acl_end_trans(struct ldb_module *module)
{
	return ldb_next_end_trans(module);
}

/* delete a transaction */
static int kludge_acl_del_trans(struct ldb_module *module)
{
	return ldb_next_del_trans(module);
}

static int kludge_acl_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return kludge_acl_search(module, req);
	case LDB_REQ_REGISTER:
		return ldb_next_request(module, req);
	default:
		/* anything else must be a change of some kind */
		return kludge_acl_change(module, req);
	}
}

static int kludge_acl_init_2(struct ldb_module *module)
{
	int ret, i;
	TALLOC_CTX *mem_ctx = talloc_new(module);
	const char *attrs[] = { "attribute", NULL };
	struct ldb_result *res;
	struct ldb_message *msg;
	struct ldb_message_element *password_attributes;

	struct kludge_private_data *data = talloc_get_type(module->private_data, struct kludge_private_data);
	data->password_attrs = NULL;

	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_search(module->ldb, ldb_dn_explode(mem_ctx, "@KLUDGEACL"),
			 LDB_SCOPE_BASE,
			 NULL, attrs,
			 &res);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}
	talloc_steal(mem_ctx, res);
	if (res->count == 0) {
		talloc_free(mem_ctx);
		data->password_attrs = NULL;
		return LDB_SUCCESS;
	}

	if (res->count > 1) {
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	msg = res->msgs[0];

	password_attributes = ldb_msg_find_element(msg, "passwordAttribute");
	if (!password_attributes) {
		talloc_free(mem_ctx);
		return LDB_SUCCESS;
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
	talloc_free(mem_ctx);
	return LDB_SUCCESS;
}

static const struct ldb_module_ops kludge_acl_ops = {
	.name		   = "kludge_acl",
	.request      	   = kludge_acl_request,
	.start_transaction = kludge_acl_start_trans,
	.end_transaction   = kludge_acl_end_trans,
	.del_transaction   = kludge_acl_del_trans,
	.second_stage_init = kludge_acl_init_2
};

struct ldb_module *kludge_acl_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;
	struct kludge_private_data *data;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	data = talloc(ctx, struct kludge_private_data);
	if (data == NULL) {
		talloc_free(ctx);
		return NULL;
	}

	data->password_attrs = NULL;
	ctx->private_data = data;

	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &kludge_acl_ops;

	return ctx;
}
