/* 
   Unix SMB/CIFS implementation.

   rootDSE ldb module

   Copyright (C) Andrew Tridgell 2005
   
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

#include "includes.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include <time.h>

/*
  return 1 if a specific attribute has been requested
*/
static int do_attribute(const char * const *attrs, const char *name)
{
	return attrs == NULL ||
		ldb_attr_in_list(attrs, name) ||
		ldb_attr_in_list(attrs, "*");
}

/*
  add dynamically generated attributes to rootDSE result
*/
static int rootdse_add_dynamic(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_search *s = &req->op.search;
	struct ldb_message *msg;

	/* this is gross, and will be removed when I change ldb_result not
	   to be so pointer crazy :-) */
	if (s->res[0][0].msgs == NULL) {
		return LDB_SUCCESS;
	}

	msg = s->res[0][0].msgs[0];

	msg->dn = ldb_dn_explode(msg, "");

	if (do_attribute(s->attrs, "currentTime")) {
		if (ldb_msg_add_string(msg, "currentTime", 
				       ldb_timestring(msg, time(NULL))) != 0) {
			goto failed;
		}
	}

	/* TODO: lots more dynamic attributes should be added here */

	return 0;

failed:
	return LDB_ERR_OPERATIONS_ERROR;
}

/*
  handle search requests
*/
static int rootdse_search_bytree(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_request r = *req;
	struct ldb_search *s = &r.op.search;
	int ret;
	TALLOC_CTX *tmp_ctx;

	/* see if its for the rootDSE */
	if (s->scope != LDB_SCOPE_BASE ||
	    (s->base && s->base->comp_num != 0)) {
		return ldb_next_request(module, req);
	}

	tmp_ctx = talloc_new(module);

	/* in our db we store the rootDSE with a DN of cn=rootDSE */
	s->base = ldb_dn_explode(tmp_ctx, "cn=rootDSE");
	s->tree = ldb_parse_tree(tmp_ctx, "dn=*");
	if (s->base == NULL || s->tree == NULL) {
		ldb_oom(module->ldb);
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* grab the static contents of the record */
	ret = ldb_next_request(module, &r);

	req->op.search.res = s->res;

	if (ret == LDB_SUCCESS) {
		ret = rootdse_add_dynamic(module, req);
	}

	talloc_free(tmp_ctx);

	return ret;
}


static int rootdse_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {
	case LDB_REQ_SEARCH:
		return rootdse_search_bytree(module, req);
	default:
		break;
	}
	return ldb_next_request(module, req);
}

static const struct ldb_module_ops rootdse_ops = {
	.name		= "rootdse",
	.request	= rootdse_request
};

#ifdef HAVE_DLOPEN_DISABLED
struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *rootdse_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &rootdse_ops;
	ctx->private_data = NULL;

	return ctx;
}

