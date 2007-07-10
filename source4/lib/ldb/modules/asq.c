/* 
   ldb database library

   Copyright (C) Simo Sorce  2005

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
 *  Component: ldb attribute scoped query control module
 *
 *  Description: this module searches all the the objects pointed
 *  		 by the DNs contained in the references attribute
 *
 *  Author: Simo Sorce
 */

#include "ldb_includes.h"

struct asq_context {

	enum {ASQ_INIT, ASQ_SEARCH_BASE, ASQ_SEARCH_MULTI} step;

	struct ldb_module *module;
	struct ldb_request *orig_req;

	struct ldb_asq_control *asq_ctrl;

	const char * const *req_attrs;
	char *req_attribute;
	enum {
		ASQ_CTRL_SUCCESS			= 0,
		ASQ_CTRL_INVALID_ATTRIBUTE_SYNTAX	= 21,
		ASQ_CTRL_UNWILLING_TO_PERFORM		= 53,
		ASQ_CTRL_AFFECTS_MULTIPLE_DSA		= 71
	} asq_ret;

	struct ldb_request *base_req;
	struct ldb_reply *base_res;

	struct ldb_request **reqs;
	int num_reqs;
	int cur_req;

	struct ldb_control **controls;
};

static struct ldb_handle *init_handle(struct ldb_request *req, struct ldb_module *module)
{
	struct asq_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct asq_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = ASQ_INIT;
	ac->module = module;
	ac->orig_req = req;

	return h;
}

static int asq_terminate(struct ldb_handle *handle)
{
	struct asq_context *ac;
	struct ldb_reply *ares;
	struct ldb_asq_control *asq;
	int i;

	ac = talloc_get_type(handle->private_data, struct asq_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	handle->status = LDB_SUCCESS;
	handle->state = LDB_ASYNC_DONE;

	ares = talloc_zero(ac, struct ldb_reply);
	if (ares == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	ares->type = LDB_REPLY_DONE;

	if (ac->controls) {
		for (i = 0; ac->controls[i]; i++);
		ares->controls = talloc_move(ares, &ac->controls);
	} else {
		i = 0;
	}

	ares->controls = talloc_realloc(ares, ares->controls, struct ldb_control *, i + 2);
	
	if (ares->controls == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	ares->controls[i] = talloc(ares->controls, struct ldb_control);
	if (ares->controls[i] == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	ares->controls[i]->oid = LDB_CONTROL_ASQ_OID;
	ares->controls[i]->critical = 0;

	asq = talloc_zero(ares->controls[i], struct ldb_asq_control);
	if (asq == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	asq->result = ac->asq_ret;
	
	ares->controls[i]->data = asq;

	ares->controls[i + 1] = NULL;

	ac->orig_req->callback(ac->module->ldb, ac->orig_req->context, ares);

	return LDB_SUCCESS;
}

static int asq_base_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct asq_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		goto error;
	}

	ac = talloc_get_type(context, struct asq_context);
	if (ac == NULL) {
		goto error;
	}

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		ac->base_res = talloc_move(ac, &ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int asq_reqs_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct asq_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		goto error;
	}

	ac = talloc_get_type(context, struct asq_context);
	if (ac == NULL) {
		goto error;
	}

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {

		/* pass the message up to the original callback as we
		 * do not have to elaborate on it any further */
		return ac->orig_req->callback(ac->module->ldb, ac->orig_req->context, ares);
		
	} else { /* ignore any REFERRAL or DONE reply */
		talloc_free(ares);
	}

	return LDB_SUCCESS;
error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int asq_build_first_request(struct asq_context *ac)
{
	char **base_attrs;

	ac->base_req = talloc_zero(ac, struct ldb_request);
	if (ac->base_req == NULL) return LDB_ERR_OPERATIONS_ERROR;

	ac->base_req->operation = ac->orig_req->operation;
	ac->base_req->op.search.base = ac->orig_req->op.search.base;
	ac->base_req->op.search.scope = LDB_SCOPE_BASE;
	ac->base_req->op.search.tree = ac->orig_req->op.search.tree;
	base_attrs = talloc_array(ac->base_req, char *, 2);
	if (base_attrs == NULL) return LDB_ERR_OPERATIONS_ERROR;

	base_attrs[0] = talloc_strdup(base_attrs, ac->asq_ctrl->source_attribute);
	if (base_attrs[0] == NULL) return LDB_ERR_OPERATIONS_ERROR;

	base_attrs[1] = NULL;
	ac->base_req->op.search.attrs = (const char * const *)base_attrs;

	ac->base_req->context = ac;
	ac->base_req->callback = asq_base_callback;
	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->base_req);

	return LDB_SUCCESS;
}

static int asq_build_multiple_requests(struct asq_context *ac, struct ldb_handle *handle)
{
	struct ldb_message_element *el;
	int i;

	/* look up the DNs */
	if (ac->base_res == NULL) {
		return LDB_ERR_NO_SUCH_OBJECT;
	}
	el = ldb_msg_find_element(ac->base_res->message, ac->req_attribute);
	/* no values found */
	if (el == NULL) {
		ac->asq_ret = ASQ_CTRL_SUCCESS;
		return asq_terminate(handle);
	}

	ac->num_reqs = el->num_values;
	ac->cur_req = 0;
	ac->reqs = talloc_array(ac, struct ldb_request *, ac->num_reqs);
	if (ac->reqs == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i = 0; i < el->num_values; i++) {

		ac->reqs[i] = talloc_zero(ac->reqs, struct ldb_request);
		if (ac->reqs[i] == NULL)
			return LDB_ERR_OPERATIONS_ERROR;
		ac->reqs[i]->operation = LDB_SEARCH;
		ac->reqs[i]->op.search.base = ldb_dn_new(ac->reqs[i], ac->module->ldb, (const char *)el->values[i].data);
		if ( ! ldb_dn_validate(ac->reqs[i]->op.search.base)) {
			ac->asq_ret = ASQ_CTRL_INVALID_ATTRIBUTE_SYNTAX;
			return asq_terminate(handle);
		}
		ac->reqs[i]->op.search.scope = LDB_SCOPE_BASE;
		ac->reqs[i]->op.search.tree = ac->base_req->op.search.tree;
		ac->reqs[i]->op.search.attrs = ac->req_attrs;

		ac->reqs[i]->context = ac;
		ac->reqs[i]->callback = asq_reqs_callback;
		ldb_set_timeout_from_prev_req(ac->module->ldb, ac->base_req, ac->reqs[i]);
	}

	return LDB_SUCCESS;
}

static int asq_search_continue(struct ldb_handle *handle)
{
	struct asq_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	ac = talloc_get_type(handle->private_data, struct asq_context);
	if (ac == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	switch (ac->step) {
	case ASQ_INIT:
		/* check the search is well formed */
		if (ac->orig_req->op.search.scope != LDB_SCOPE_BASE) {
			ac->asq_ret = ASQ_CTRL_UNWILLING_TO_PERFORM;
			return asq_terminate(handle);
		}

		ac->req_attrs = ac->orig_req->op.search.attrs;
		ac->req_attribute = talloc_strdup(ac, ac->asq_ctrl->source_attribute);
		if (ac->req_attribute == NULL)
			return LDB_ERR_OPERATIONS_ERROR;

		/* get the object to retrieve the DNs to search */
		ret = asq_build_first_request(ac);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	
		ac->step = ASQ_SEARCH_BASE;

		handle->state = LDB_ASYNC_PENDING;
		handle->status = LDB_SUCCESS;

		return ldb_request(ac->module->ldb, ac->base_req);

	case ASQ_SEARCH_BASE:

		ret = ldb_wait(ac->base_req->handle, LDB_WAIT_NONE);
		
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}

		if (ac->base_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->base_req->handle->status;
			goto done;
		}

		if (ac->base_req->handle->state == LDB_ASYNC_DONE) {

			/* build up the requests call chain */
			ret = asq_build_multiple_requests(ac, handle);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			if (handle->state == LDB_ASYNC_DONE) {
				return LDB_SUCCESS;
			}

			ac->step = ASQ_SEARCH_MULTI;

			return ldb_request(ac->module->ldb, ac->reqs[ac->cur_req]);
		}

		/* request still pending, return to cycle again */
		return LDB_SUCCESS;

	case ASQ_SEARCH_MULTI:

		ret = ldb_wait(ac->reqs[ac->cur_req]->handle, LDB_WAIT_NONE);
		
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->reqs[ac->cur_req]->handle->status != LDB_SUCCESS) {
			handle->status = ac->reqs[ac->cur_req]->handle->status;
		}

		if (ac->reqs[ac->cur_req]->handle->state == LDB_ASYNC_DONE) {
			ac->cur_req++;

			if (ac->cur_req < ac->num_reqs) {
				return ldb_request(ac->module->ldb, ac->reqs[ac->cur_req]);
			}

			return asq_terminate(handle);
		}

		/* request still pending, return to cycle again */
		return LDB_SUCCESS;

	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
		break;
	}

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}

static int asq_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;
	struct asq_context *ac;
	struct ldb_handle *h;

	/* check if there's a paged request control */
	control = ldb_request_get_control(req, LDB_CONTROL_ASQ_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	req->handle = NULL;

	if (!req->callback || !req->context) {
		ldb_set_errstring(module->ldb,
				  "Async interface called with NULL callback function or NULL context");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	h = init_handle(req, module);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct asq_context);

	ac->asq_ctrl = talloc_get_type(control->data, struct ldb_asq_control);
	if (!ac->asq_ctrl) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	req->handle = h;

	return asq_search_continue(h);
}

static int asq_wait_all(struct ldb_handle *handle)
{
	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = asq_search_continue(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int asq_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return asq_wait_all(handle);
	} else {
		return asq_search_continue(handle);
	}
}

static int asq_init(struct ldb_module *module)
{
	struct ldb_request *req;
	int ret;

	req = talloc_zero(module, struct ldb_request);
	if (req == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "asq: Out of memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_REGISTER_CONTROL;
	req->op.reg_control.oid = LDB_CONTROL_ASQ_OID;

	ret = ldb_request(module->ldb, req);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "asq: Unable to register control with rootdse!\n");
	}

	return ldb_next_init(module);
}


static const struct ldb_module_ops asq_ops = {
	.name		   = "asq",
	.search		   = asq_search,
	.wait              = asq_wait,
	.init_context	   = asq_init
};

int ldb_asq_init(void)
{
	return ldb_register_module(&asq_ops);
}
