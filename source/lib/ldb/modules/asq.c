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
 *  Component: ldb attribute scoped query control module
 *
 *  Description: this module searches all the the objects pointed
 *  		 by the DNs contained in the references attribute
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/includes.h"

#define ASQ_CTRL_SUCCESS			0
#define ASQ_CTRL_INVALID_ATTRIBUTE_SYNTAX	21
#define ASQ_CTRL_UNWILLING_TO_PERFORM		53
#define ASQ_CTRL_AFFECTS_MULTIPLE_DSA		71

static int build_response(struct ldb_result *res, int result)
{
	struct ldb_asq_control *asq;
	int i;

	if (res->controls) {
		for (i = 0; res->controls[i]; i++);
		res->controls = talloc_realloc(res, res->controls, struct ldb_control *, i + 2);
	} else {
		i = 0;
		res->controls = talloc_array(res, struct ldb_control *, 2);
	}
	if (res->controls == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	res->controls[i] = talloc(res->controls, struct ldb_control);
	if (res->controls[i] == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	res->controls[i]->oid = LDB_CONTROL_ASQ_OID;
	res->controls[i]->critical = 0;

	asq = talloc_zero(res->controls[i], struct ldb_asq_control);
	if (asq == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	asq->result = result;
	
	res->controls[i]->data = asq;

	res->controls[i + 1] = NULL;

	return LDB_SUCCESS;
}

/* search */
static int asq_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;
	struct ldb_asq_control *asq_ctrl;
	struct ldb_request *base_req;
	struct ldb_message_element *el;
	struct ldb_result *res;
	char **base_attrs;
	int i, c, ret;

	/* check if there's a paged request control */
	control = get_control_from_list(req->controls, LDB_CONTROL_ASQ_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	/* pre-allocate a clean result structure */
	req->op.search.res = res = talloc_zero(req, struct ldb_result);
	if (res == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	/* check the search is well formed */
	if (req->op.search.scope != LDB_SCOPE_BASE) {
		return build_response(res, ASQ_CTRL_UNWILLING_TO_PERFORM);
	}

	asq_ctrl = talloc_get_type(control->data, struct ldb_asq_control);

	/* get the object to retrieve the DNs to search */
	base_req = talloc_zero(req, struct ldb_request);
	if (base_req == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	base_req->operation = LDB_REQ_SEARCH;
	base_req->op.search.base = req->op.search.base;
	base_req->op.search.scope = LDB_SCOPE_BASE;
	base_req->op.search.tree = req->op.search.tree;
	base_attrs = talloc_array(base_req, char *, 2);
	if (base_attrs == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	base_attrs[0] = talloc_strdup(base_attrs, asq_ctrl->source_attribute);
	if (base_attrs[0] == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	base_attrs[1] = NULL;
	base_req->op.search.attrs = (const char * const *)base_attrs;
	base_req->creds = req->creds;

	ret = ldb_request(module->ldb, base_req);

	if (ret != LDB_SUCCESS)
		return ret;

	/* look up the DNs */
	el = ldb_msg_find_element(base_req->op.search.res->msgs[0],
				  asq_ctrl->source_attribute);
	/* no values found */
	if (el == NULL) {
		return build_response(res, ASQ_CTRL_SUCCESS);
	}

	for (i = 0, c = 0; i < el->num_values; i++) {
		struct ldb_request *exp_req;

		exp_req = talloc_zero(req, struct ldb_request);
		if (exp_req == NULL)
			return LDB_ERR_OPERATIONS_ERROR;
		exp_req->operation = LDB_REQ_SEARCH;
		exp_req->op.search.base = ldb_dn_explode(exp_req, (const char *)el->values[i].data);
		if (exp_req->op.search.base == NULL) {
			return build_response(res, ASQ_CTRL_INVALID_ATTRIBUTE_SYNTAX);
		}
		exp_req->op.search.scope = LDB_SCOPE_BASE;
		exp_req->op.search.tree = req->op.search.tree;
		exp_req->op.search.attrs = req->op.search.attrs;
		exp_req->creds = req->creds;

		ret = ldb_request(module->ldb, exp_req);

		if (ret != LDB_SUCCESS)
			return ret;

		if (exp_req->op.search.res && exp_req->op.search.res->count != 0) {
			if (res->msgs == NULL) {
				res->msgs = talloc_array(res,
						struct ldb_message *, 2);
			} else {
				res->msgs = talloc_realloc(res, res->msgs,
						struct ldb_message *, c + 2);
			}
			if (res->msgs == NULL)
				return LDB_ERR_OPERATIONS_ERROR;

			res->msgs[c] = talloc_steal(res->msgs, exp_req->op.search.res->msgs[0]);
			c++;
		}

		if (res->msgs) {
			res->msgs[c] = NULL;
			res->count = c;
		}

		talloc_free(exp_req);
	}

	return build_response(res, ASQ_CTRL_SUCCESS);
}

static int asq(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return asq_search(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static int asq_init_2(struct ldb_module *module)
{
	struct ldb_request request;
	int ret;

	request.operation = LDB_REQ_REGISTER;
	request.op.reg.oid = LDB_CONTROL_ASQ_OID;
	request.controls = NULL;

	ret = ldb_request(module->ldb, &request);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "asq: Unable to register control with rootdse!\n");
		return LDB_ERR_OTHER;
	}

	return ldb_next_second_stage_init(module);
}


static const struct ldb_module_ops asq_ops = {
	.name		   = "asq",
	.request      	   = asq,
	.second_stage_init = asq_init_2
};

struct ldb_module *asq_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &asq_ops;
	ctx->private_data = NULL;

	return ctx;
}
