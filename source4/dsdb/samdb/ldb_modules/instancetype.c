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
#include "ldb.h"
#include "ldb_module.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "dsdb/samdb/samdb.h"
#include "../libds/common/flags.h"
#include "dsdb/samdb/ldb_modules/util.h"

struct it_context {
	struct ldb_module *module;
	struct ldb_request *req;
	struct ldb_request *add_req;
};

static int it_add_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct it_context *ac;

	ac = talloc_get_type(req->context, struct it_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(ac->req, ares->referral);
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

	/* Add the boilerplate entries */

	return ldb_module_done(ac->req, ares->controls,
			       ares->response, ares->error);
}

/* add_record: add instancetype attribute */
static int instancetype_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_request *down_req;
	struct ldb_message *msg;
	struct ldb_message_element *el;
	struct it_context *ac;
	uint32_t instance_type;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "instancetype_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	el = ldb_msg_find_element(req->op.add.message, "instanceType");
	if (el != NULL) {
		unsigned int instanceType;

		if (el->num_values != 1) {
			ldb_set_errstring(ldb, "instancetype: the 'instanceType' attribute is single-valued!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		instanceType = ldb_msg_find_attr_as_uint(req->op.add.message,
							 "instanceType", 0);
		if (!(instanceType & INSTANCE_TYPE_IS_NC_HEAD)) {
			return ldb_next_request(module, req);		
		}

		/* Forward the 'add' to the modules below, but if it
		 * succeeds, then we might need to add the boilerplate
		 * entries (lost+found, deleted objects) */
		ac = talloc(req, struct it_context);
		if (ac == NULL) {
			return ldb_oom(ldb);
		}
		ac->module = module;
		ac->req = req;
		
		ret = ldb_build_add_req(&ac->add_req, ldb_module_get_ctx(ac->module), ac,
					ac->req->op.add.message,
					ac->req->controls,
					ac, it_add_callback,
					ac->req);
		
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		
		/* Do the original add */
		return ldb_next_request(ac->module, ac->add_req);
	}

	/* we have to copy the message as the caller might have it as a const */
	msg = ldb_msg_copy_shallow(req, req->op.add.message);
	if (msg == NULL) {
		return ldb_oom(ldb);
	}

	/*
	 * TODO: calculate correct instance type
	 */
	instance_type = INSTANCE_TYPE_WRITE;

	ret = ldb_msg_add_fmt(msg, "instanceType", "%u", instance_type);
	if (ret != LDB_SUCCESS) {
		return ldb_oom(ldb);
	}

	ret = ldb_build_add_req(&down_req, ldb, req,
				msg,
				req->controls,
				req, dsdb_next_callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* go on with the call chain */
	return ldb_next_request(module, down_req);
}

/* deny instancetype modification */
static int instancetype_mod(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_message_element *el;

	el = ldb_msg_find_element(req->op.mod.message, "instanceType");
	if (el != NULL) {
		ldb_set_errstring(ldb, "instancetype: the 'instanceType' attribute can never be changed!");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	return ldb_next_request(module, req);
}

_PUBLIC_ const struct ldb_module_ops ldb_instancetype_module_ops = {
	.name          = "instancetype",
	.add           = instancetype_add,
	.modify        = instancetype_mod
};
