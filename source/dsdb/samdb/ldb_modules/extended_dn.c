/* 
   ldb database library

   Copyright (C) Simo Sorce  2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb extended dn control module
 *
 *  Description: this module builds a special dn
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"

#include <time.h>

static BOOL is_attr_in_list(const char * const * attrs, const char *attr)
{
	int i;

	for (i = 0; attrs[i]; i++) {
		if (strcasecmp(attrs[i], attr) == 0)
			return True;
	}

	return False;
}

static char **copy_attrs(void *mem_ctx, const char * const * attrs)
{
	char **new;
	int i, num;

	for (num = 0; attrs[num]; num++);

	new = talloc_array(mem_ctx, char *, num + 1);
	if (!new) return NULL;

	for(i = 0; i < num; i++) {
		new[i] = talloc_strdup(new, attrs[i]);
		if (!new[i]) {
			talloc_free(new);
			return NULL;
		}
	}
	new[i] = NULL;

	return new;
}

static BOOL add_attrs(void *mem_ctx, char ***attrs, const char *attr)
{
	char **new;
	int num;

	for (num = 0; (*attrs)[num]; num++);

	new = talloc_realloc(mem_ctx, *attrs, char *, num + 2);
	if (!new) return False;

	*attrs = new;

	new[num] = talloc_strdup(new, attr);
	if (!new[num]) return False;

	new[num + 1] = NULL;

	return True;
}

static BOOL inject_extended_dn(struct ldb_message *msg,
				struct ldb_context *ldb,
				int type,
				BOOL remove_guid,
				BOOL remove_sid)
{
	const struct ldb_val *val;
	struct GUID guid;
	struct dom_sid *sid;
	char *object_guid;
	char *object_sid;
	char *new_dn;

	/* retrieve object_guid */
	guid = samdb_result_guid(msg, "objectGUID");
	object_guid = GUID_string(msg, &guid);
	if (!object_guid)
		return False;

	if (remove_guid)
		ldb_msg_remove_attr(msg, "objectGUID");

	/* retrieve object_sid */
	object_sid = NULL;
	sid = samdb_result_dom_sid(msg, msg, "objectSID");
	if (sid) {
		object_sid = dom_sid_string(msg, sid);
		if (!object_sid)
			return False;

		if (remove_sid)
			ldb_msg_remove_attr(msg, "objectSID");
	}

	/* TODO: handle type */
	switch (type) {
		case 0:
		case 1:
			if (object_sid) {
				new_dn = talloc_asprintf(msg, "<GUID=%s>;<SID=%s>;%s",
							 object_guid, object_sid,
							 ldb_dn_get_linearized(msg->dn));
			} else {
				new_dn = talloc_asprintf(msg, "<GUID=%s>;%s",
							 object_guid,
							 ldb_dn_get_linearized(msg->dn));
			}
			break;
		default:
			return False;
	}

	if (!new_dn)
		return False;

	msg->dn = ldb_dn_new(msg, ldb, new_dn);
	if (! ldb_dn_validate(msg->dn))
		return False;

	val = ldb_msg_find_ldb_val(msg, "distinguishedName");
	if (val) {
		ldb_msg_remove_attr(msg, "distinguishedName");
		if (ldb_msg_add_steal_string(msg, "distinguishedName", new_dn))
			return False;
	}

	return True;
}

/* search */
struct extended_context {

	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_reply *);

	const char * const *attrs;
	BOOL remove_guid;
	BOOL remove_sid;
	int extended_type;
};

static int extended_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct extended_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		goto error;
	}

	ac = talloc_get_type(context, struct extended_context);

	if (ares->type == LDB_REPLY_ENTRY) {
		/* for each record returned post-process to add any derived
		   attributes that have been asked for */
		if (!inject_extended_dn(ares->message, ldb, ac->extended_type, ac->remove_guid, ac->remove_sid)) {
			goto error;
		}
	}

	return ac->up_callback(ldb, ac->up_context, ares);

error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int extended_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;
	struct ldb_extended_dn_control *extended_ctrl;
	struct ldb_control **saved_controls;
	struct extended_context *ac;
	struct ldb_request *down_req;
	char **new_attrs;
	int ret;

	/* check if there's an extended dn control */
	control = get_control_from_list(req->controls, LDB_CONTROL_EXTENDED_DN_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	extended_ctrl = talloc_get_type(control->data, struct ldb_extended_dn_control);
	if (!extended_ctrl) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	ac = talloc(req, struct extended_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->module = module;
	ac->up_context = req->context;
	ac->up_callback = req->callback;
	ac->attrs = req->op.search.attrs;
	ac->remove_guid = False;
	ac->remove_sid = False;
	ac->extended_type = extended_ctrl->type;

	down_req = talloc_zero(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	down_req->operation = req->operation;
	down_req->op.search.base = req->op.search.base;
	down_req->op.search.scope = req->op.search.scope;
	down_req->op.search.tree = req->op.search.tree;

	/* check if attrs only is specified, in that case check wether we need to modify them */
	if (req->op.search.attrs) {
		if (! is_attr_in_list(req->op.search.attrs, "objectGUID")) {
			ac->remove_guid = True;
		}
		if (! is_attr_in_list(req->op.search.attrs, "objectSID")) {
			ac->remove_sid = True;
		}
		if (ac->remove_guid || ac->remove_sid) {
			new_attrs = copy_attrs(down_req, req->op.search.attrs);
			if (new_attrs == NULL)
				return LDB_ERR_OPERATIONS_ERROR;
			
			if (ac->remove_guid) {
				if (!add_attrs(down_req, &new_attrs, "objectGUID"))
					return LDB_ERR_OPERATIONS_ERROR;
			}
			if (ac->remove_sid) {
				if (!add_attrs(down_req, &new_attrs, "objectSID"))
					return LDB_ERR_OPERATIONS_ERROR;
			}

			down_req->op.search.attrs = (const char * const *)new_attrs;
		}
	}

	down_req->controls = req->controls;

	/* save it locally and remove it from the list */
	/* we do not need to replace them later as we
	 * are keeping the original req intact */
	if (!save_controls(control, down_req, &saved_controls)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	down_req->context = ac;
	down_req->callback = extended_callback;
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

static int extended_init(struct ldb_module *module)
{
	struct ldb_request *req;
	int ret;

	req = talloc(module, struct ldb_request);
	if (req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_REGISTER_CONTROL;
	req->op.reg_control.oid = LDB_CONTROL_EXTENDED_DN_OID;
	req->controls = NULL;

	ret = ldb_request(module->ldb, req);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "extended_dn: Unable to register control with rootdse!\n");
		talloc_free(req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_free(req);
	return ldb_next_init(module);
}

static const struct ldb_module_ops extended_dn_ops = {
	.name		   = "extended_dn",
	.search            = extended_search,
	.init_context	   = extended_init
};

int ldb_extended_dn_init(void)
{
	return ldb_register_module(&extended_dn_ops);
}
