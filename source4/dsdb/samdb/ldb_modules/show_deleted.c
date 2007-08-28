/* 
   ldb database library

   Copyright (C) Simo Sorce  2005
   Copyright (C) Stefa Metzmacher <metze@samba.org> 2007

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
 *  Name: ldb
 *
 *  Component: ldb deleted objects control module
 *
 *  Description: this module hides deleted objects, and returns them if the control is there
 *
 *  Author: Stefan Metzmacher
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"

/* search */
struct show_deleted_search_request {

	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_reply *);

	bool remove_from_msg;
};

static int show_deleted_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct show_deleted_search_request *ar;

	ar = talloc_get_type(context, struct show_deleted_search_request);

	if (ares->type == LDB_REPLY_ENTRY) {
		bool isDeleted;

		isDeleted = ldb_msg_find_attr_as_bool(ares->message, "isDeleted", false);

		if (isDeleted) {
			goto skip_deleted;
		}

		if (ar->remove_from_msg) {
			ldb_msg_remove_attr(ares->message, "isDeleted");
		}
	}

	return ar->up_callback(ldb, ar->up_context, ares);

skip_deleted:
	talloc_free(ares);
	return LDB_SUCCESS;
}

static int show_deleted_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;
	struct ldb_control **saved_controls;
	struct show_deleted_search_request *ar;
	struct ldb_request *down_req;
	char **new_attrs;
	uint32_t num_attrs = 0;
	uint32_t i;
	int ret;

	/* check if there's a show deleted control */
	control = ldb_request_get_control(req, LDB_CONTROL_SHOW_DELETED_OID);

	/* copy the request for modification */
	down_req = talloc(req, struct ldb_request);
	if (down_req == NULL) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* copy the request */
	*down_req = *req;

	/* if a control is there remove if from the modified request */
	if (control && !save_controls(control, down_req, &saved_controls)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* if we had a control, then just go on to the next request as we have nothing to hide */
	if (control) {
		goto next_request;
	}

	ar = talloc(down_req, struct show_deleted_search_request);
	if (ar == NULL) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ar->module		= module;
	ar->up_context		= req->context;
	ar->up_callback		= req->callback;
	ar->remove_from_msg	= true;

	/* check if attrs only is specified, in that case check wether we need to modify them */
	if (down_req->op.search.attrs) {
		for (i=0; (down_req->op.search.attrs && down_req->op.search.attrs[i]); i++) {
			num_attrs++;
			if (strcasecmp(down_req->op.search.attrs[i], "*") == 0) {
				ar->remove_from_msg = false;
			} else if (strcasecmp(down_req->op.search.attrs[i], "isDeleted") == 0) {
				ar->remove_from_msg = false;
			}
		}
	} else {
		ar->remove_from_msg = false;
	}

	if (ar->remove_from_msg) {
		new_attrs = talloc_array(down_req, char *, num_attrs + 2);
		if (!new_attrs) {
			ldb_oom(module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		for (i=0; i < num_attrs; i++) {
			new_attrs[i] = discard_const_p(char, down_req->op.search.attrs[i]);		
		}
		new_attrs[i] = talloc_strdup(new_attrs, "isDeleted");
		if (!new_attrs[i]) {
			ldb_oom(module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		new_attrs[i+1] = NULL;
		down_req->op.search.attrs = (const char * const *)new_attrs;
	}

	down_req->context = ar;
	down_req->callback = show_deleted_search_callback;
	ldb_set_timeout_from_prev_req(module->ldb, req, down_req);

next_request:
	/* perform the search */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->handle = down_req->handle;
	}

	return ret;
}

static int show_deleted_init(struct ldb_module *module)
{
	struct ldb_request *req;
	int ret;

	req = talloc(module, struct ldb_request);
	if (req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_REGISTER_CONTROL;
	req->op.reg_control.oid = LDB_CONTROL_SHOW_DELETED_OID;
	req->controls = NULL;

	ret = ldb_request(module->ldb, req);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "show_deleted: Unable to register control with rootdse!\n");
		talloc_free(req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_free(req);
	return ldb_next_init(module);
}

static const struct ldb_module_ops show_deleted_ops = {
	.name		   = "show_deleted",
	.search            = show_deleted_search,
	.init_context	   = show_deleted_init
};

int ldb_show_deleted_init(void)
{
	return ldb_register_module(&show_deleted_ops);
}
