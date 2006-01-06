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

const char *password_attribs[] = {
	"sambaPassword",
	"ntPwdHash",
	"sambaNTPwdHistory",
	"lmPwdHash", 
	"sambaLMPwdHistory",
	"krb5key"
};

enum user_is {
	ANONYMOUS,
	USER,
	ADMINISTRATOR,
	SYSTEM
};

struct private_data {

	char *some_private_data;
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
		return SYSTEM;
	}
	if (is_authenticated_token(session_info->security_token)) {
		return USER;
	}
	if (is_anonymous_token(session_info->security_token)) {
		return ANONYMOUS;
	}
	return ANONYMOUS;
}

/* search */
static int kludge_acl_search(struct ldb_module *module, struct ldb_request *req)
{
	enum user_is user_type;
	int ret = ldb_next_request(module, req);
	struct ldb_message *msg;
	int i, j;

	if (ret != LDB_SUCCESS) {
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
			for (j=0; j < ARRAY_SIZE(password_attribs); j++) {
				ldb_msg_remove_attr(msg, password_attribs[j]);
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
						  "attempted database modify not permitted. User is not SYSTEM or an administrator"));
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

static int kludge_acl_destructor(void *module_ctx)
{
	struct ldb_module *ctx = talloc_get_type(module_ctx, struct ldb_module);
	struct private_data *data = talloc_get_type(ctx->private_data, struct private_data);
	/* put your clean-up functions here */
	if (data->some_private_data) talloc_free(data->some_private_data);
	return 0;
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

static const struct ldb_module_ops kludge_acl_ops = {
	.name		   = "kludge_acl",
	.request      	   = kludge_acl_request,
	.start_transaction = kludge_acl_start_trans,
	.end_transaction   = kludge_acl_end_trans,
	.del_transaction   = kludge_acl_del_trans,
};

struct ldb_module *kludge_acl_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;
	struct private_data *data;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	data = talloc(ctx, struct private_data);
	if (data == NULL) {
		talloc_free(ctx);
		return NULL;
	}

	data->some_private_data = NULL;
	ctx->private_data = data;

	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &kludge_acl_ops;

	talloc_set_destructor (ctx, kludge_acl_destructor);

	return ctx;
}
