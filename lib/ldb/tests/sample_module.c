/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007

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

#include "replace.h"
#include "ldb_module.h"

static int sample_add_callback(struct ldb_request *down_req,
			       struct ldb_reply *ares)
{
	struct ldb_request *req =
		talloc_get_type_abort(down_req->context,
		struct ldb_request);

	if (ares == NULL) {
		return ldb_module_done(req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(req, ares->referral);
	}

	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(req, ares->controls,
				       ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		return ldb_module_done(req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}

	return ldb_module_done(req, ares->controls,
			       ares->response, LDB_SUCCESS);
}

static int sample_add(struct ldb_module *mod, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(mod);
	struct ldb_control *control = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_request *down_req = NULL;
	int ret;

	/* check if there's a relax control */
	control = ldb_request_get_control(req, LDB_CONTROL_RELAX_OID);
	if (control != NULL) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	msg = ldb_msg_copy_shallow(req, req->op.add.message);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_msg_add_fmt(msg, "touchedBy", "sample");
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_build_add_req(&down_req, ldb, req,
				msg,
				req->controls,
				req, sample_add_callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(down_req, msg);

	/* go on with the call chain */
	return ldb_next_request(mod, down_req);
}

static int sample_modify(struct ldb_module *mod, struct ldb_request *req)
{
	struct ldb_control *control;

	/* check if there's a relax control */
	control = ldb_request_get_control(req, LDB_CONTROL_RELAX_OID);
	if (control != NULL) {
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* not found go on */
	return ldb_next_request(mod, req);
}


static struct ldb_module_ops ldb_sample_module_ops = {
	.name              = "sample",
	.add		   = sample_add,
	.del		   = sample_modify,
	.modify		   = sample_modify,
};

int ldb_sample_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_sample_module_ops);
}
