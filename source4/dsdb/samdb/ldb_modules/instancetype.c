/* 
   ldb database library

   Copyright (C) Simo Sorce  2004-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007

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
 *  Component: ldb instancetype module
 *
 *  Description: add an instanceType onto every new record
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb_module.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "dsdb/samdb/samdb.h"
#include "../libds/common/flags.h"

struct it_context {
	struct ldb_module *module;
	struct ldb_request *req;
};

static int it_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct it_context *ac;

	ac = talloc_get_type(req->context, struct it_context);
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
		ldb_set_errstring(ldb, "Invalid reply type!");
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
}

/* add_record: add instancetype attribute */
static int instancetype_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_request *down_req;
	struct ldb_message *msg;
	struct it_context *ac;
	uint32_t instance_type;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "instancetype_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	if (ldb_msg_find_element(req->op.add.message, "instanceType")) {
		unsigned int instanceType = ldb_msg_find_attr_as_uint(req->op.add.message, "instanceType", 0);

		if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
			/* Do something in future */
		}
		
		/* TODO: we need to validate and possibly create a new
		   partition */
		return ldb_next_request(module, req);		
	}

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(req, req->op.add.message);
	if (msg == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * TODO: calculate correct instance type
	 */
	instance_type = INSTANCE_TYPE_WRITE;

	ret = ldb_msg_add_fmt(msg, "instanceType", "%u", instance_type);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_add_req(&down_req, ldb, req,
				msg,
				req->controls,
				req->context, req->callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

_PUBLIC_ const struct ldb_module_ops ldb_instancetype_module_ops = {
	.name          = "instancetype",
	.add           = instancetype_add,
};
