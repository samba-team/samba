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
static int asq_search(struct ldb_module *module, struct ldb_control *control, struct ldb_request *req)
{
	struct ldb_asq_control *asq_ctrl;
	struct ldb_request *base_req;
	struct ldb_message_element *el;
	struct ldb_result *res;
	char **base_attrs;
	int i, c, ret;

	/* pre-allocate a clean result structure */
	req->op.search.res = res = talloc_zero(req, struct ldb_result);
	if (res == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	/* check the search is well formed */
	if (req->op.search.scope != LDB_SCOPE_BASE) {
		return build_response(res, ASQ_CTRL_UNWILLING_TO_PERFORM);
	}

	asq_ctrl = talloc_get_type(control->data, struct ldb_asq_control);
	if (!asq_ctrl) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

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

	if (ret != LDB_SUCCESS) {
		talloc_free(base_req);
		return ret;
	}

	if (base_req->op.search.res->count == 0) {
		talloc_free(base_req);
		return build_response(res, ASQ_CTRL_SUCCESS);
	}
	
	/* look up the DNs */
	el = ldb_msg_find_element(base_req->op.search.res->msgs[0],
				  asq_ctrl->source_attribute);
	/* no values found */
	if (el == NULL) {
		talloc_free(base_req);
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

	talloc_free(base_req);

	return build_response(res, ASQ_CTRL_SUCCESS);
}

struct asq_async_context {
	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_async_result *);
	int timeout;

	const char * const *req_attrs;
	char *req_attribute;
	int asq_ret;

	struct ldb_request *base_req;
	struct ldb_async_result *base_res;

	struct ldb_request **reqs;
	int num_reqs;
	int cur_req;

	struct ldb_control **controls;
};

static struct ldb_async_handle *init_handle(void *mem_ctx, struct ldb_module *module,
					    void *context,
					    int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
					    int timeout)
{
	struct asq_async_context *ac;
	struct ldb_async_handle *h;

	h = talloc_zero(mem_ctx, struct ldb_async_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct asq_async_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->module = module;
	ac->up_context = context;
	ac->up_callback = callback;
	ac->timeout = timeout;

	return h;
}

static int asq_terminate(struct ldb_async_handle *handle)
{
	struct asq_async_context *ac;
	struct ldb_async_result *ares;
	struct ldb_asq_control *asq;
	int i;

	ac = talloc_get_type(handle->private_data, struct asq_async_context);

	handle->status = LDB_SUCCESS;
	handle->state = LDB_ASYNC_DONE;

	ares = talloc_zero(ac, struct ldb_async_result);
	if (ares == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	ares->type = LDB_REPLY_DONE;

	if (ac->controls) {
		for (i = 0; ac->controls[i]; i++);
		ares->controls = talloc_steal(ares, ac->controls);
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

	ac->up_callback(ac->module->ldb, ac->up_context, ares);

	return LDB_SUCCESS;
}

static int asq_base_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct asq_async_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context or Result in callback"));
		goto error;
	}

	ac = talloc_get_type(context, struct asq_async_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		ac->base_res = talloc_steal(ac, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int asq_reqs_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct asq_async_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context or Result in callback"));
		goto error;
	}

	ac = talloc_get_type(context, struct asq_async_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {

		/* pass the message up to the original callback as we
		 * do not have to elaborate on it any further */
		return ac->up_callback(ac->module->ldb, ac->up_context, ares);
		
	} else { /* ignore any REFERRAL or DONE reply */
		talloc_free(ares);
	}

	return LDB_SUCCESS;
error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int asq_search_async(struct ldb_module *module, struct ldb_control *control, struct ldb_request *req)
{
	struct ldb_asq_control *asq_ctrl;
	struct asq_async_context *ac;
	struct ldb_async_handle *h;
	char **base_attrs;
	int ret;

	req->async.handle = NULL;

	if (!req->async.callback || !req->async.context) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module,
				  "Async interface called with NULL callback function or NULL context"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	asq_ctrl = talloc_get_type(control->data, struct ldb_asq_control);
	if (!asq_ctrl) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	h = init_handle(req, module, req->async.context, req->async.callback, req->async.timeout);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct asq_async_context);

	req->async.handle = h;

	/* check the search is well formed */
	if (req->op.search.scope != LDB_SCOPE_BASE) {
		ac->asq_ret = ASQ_CTRL_UNWILLING_TO_PERFORM;
		return asq_terminate(h);
	}

	ac->req_attrs = req->op.search.attrs;
	ac->req_attribute = talloc_strdup(ac, asq_ctrl->source_attribute);
	if (ac->req_attribute == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	/* get the object to retrieve the DNs to search */
	ac->base_req = talloc_zero(req, struct ldb_request);
	if (ac->base_req == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	ac->base_req->operation = req->operation;
	ac->base_req->op.search.base = req->op.search.base;
	ac->base_req->op.search.scope = LDB_SCOPE_BASE;
	ac->base_req->op.search.tree = req->op.search.tree;
	base_attrs = talloc_array(ac->base_req, char *, 2);
	if (base_attrs == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	base_attrs[0] = talloc_strdup(base_attrs, asq_ctrl->source_attribute);
	if (base_attrs[0] == NULL)
		return LDB_ERR_OPERATIONS_ERROR;
	base_attrs[1] = NULL;
	ac->base_req->op.search.attrs = (const char * const *)base_attrs;
	ac->base_req->creds = req->creds;

	ac->base_req->async.context = ac;
	ac->base_req->async.callback = asq_base_callback;
	ac->base_req->async.timeout = req->async.timeout;

	ret = ldb_request(module->ldb, ac->base_req);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static int asq_async_requests(struct ldb_async_handle *handle) {
	struct asq_async_context *ac;
	struct ldb_message_element *el;
	int i;

	ac = talloc_get_type(handle->private_data, struct asq_async_context);

	/* look up the DNs */
	el = ldb_msg_find_element(ac->base_res->message, ac->req_attribute);
	/* no values found */
	if (el == NULL) {
		ac->asq_ret = ASQ_CTRL_SUCCESS;
		return asq_terminate(handle);
	}

	/* build up the requests call chain */
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
		ac->reqs[i]->operation = LDB_ASYNC_SEARCH;
		ac->reqs[i]->op.search.base = ldb_dn_explode(ac->reqs[i], (const char *)el->values[i].data);
		if (ac->reqs[i]->op.search.base == NULL) {
			ac->asq_ret = ASQ_CTRL_INVALID_ATTRIBUTE_SYNTAX;
			return asq_terminate(handle);
		}
		ac->reqs[i]->op.search.scope = LDB_SCOPE_BASE;
		ac->reqs[i]->op.search.tree = ac->base_req->op.search.tree;
		ac->reqs[i]->op.search.attrs = ac->req_attrs;
		ac->reqs[i]->creds = ac->base_req->creds;

		ac->reqs[i]->async.context = ac;
		ac->reqs[i]->async.callback = asq_reqs_callback;
		ac->reqs[i]->async.timeout = ac->base_req->async.timeout;
	}

	return LDB_SUCCESS;
}

static int asq_async_wait(struct ldb_async_handle *handle, enum ldb_async_wait_type type)
{
	struct asq_async_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;

	ac = talloc_get_type(handle->private_data, struct asq_async_context);

	if (type == LDB_WAIT_ALL) {
		while (ac->base_req->async.handle->state != LDB_ASYNC_DONE) {
			ret = ldb_async_wait(ac->base_req->async.handle, type);
			if (ret != LDB_SUCCESS) goto error;
		}

		ret = asq_async_requests(handle);
		if (ret != LDB_SUCCESS) goto error;

		for (; ac->cur_req < ac->num_reqs; ac->cur_req++) {
			ret = ldb_request(ac->module->ldb, ac->reqs[ac->cur_req]);
			if (ret != LDB_SUCCESS) goto error;

			while (ac->reqs[ac->cur_req]->async.handle->state != LDB_ASYNC_DONE) {
				ret = ldb_async_wait(ac->reqs[ac->cur_req]->async.handle, type);
				if (ret != LDB_SUCCESS) goto error;
			}
		}

		return asq_terminate(handle);
	}

	/* type == LDB_WAIT_NONE */

	if (ac->base_req->async.handle->state != LDB_ASYNC_DONE) {
		ret = ldb_async_wait(ac->base_req->async.handle, type);
		if (ret != LDB_SUCCESS) goto error;

		if (ac->base_req->async.handle->state != LDB_ASYNC_DONE) {
			return ret;
		}
	}

	if (ac->reqs == NULL) {
		/* need to build up the reqs array before calling out */
		ret = asq_async_requests(handle);
		if (ret != LDB_SUCCESS) goto error;
	}

	if (ac->cur_req < ac->num_reqs) {

		if (ac->reqs[ac->cur_req]->async.handle == NULL) {
			ret = ldb_request(ac->module->ldb, ac->reqs[ac->cur_req]);
			if (ret != LDB_SUCCESS) goto error;
		}

		if (ac->reqs[ac->cur_req]->async.handle->state != LDB_ASYNC_DONE) {
			ret = ldb_async_wait(ac->reqs[ac->cur_req]->async.handle, type);
			if (ret != LDB_SUCCESS) goto error;
		}

		if (ac->reqs[ac->cur_req]->async.handle->state == LDB_ASYNC_DONE) {
			ac->cur_req++;
		}

		return handle->status;
	}

	return asq_terminate(handle);

error:
	handle->state = LDB_ASYNC_DONE;
	handle->status = ret;
	return ret;
}

static int asq(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;

	/* check if there's a paged request control */
	control = get_control_from_list(req->controls, LDB_CONTROL_ASQ_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return asq_search(module, control, req);
	
	case LDB_ASYNC_SEARCH:
		return asq_search_async(module, control, req);

	default:
		return LDB_ERR_PROTOCOL_ERROR;

	}
}

static int asq_init(struct ldb_module *module)
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

	return ldb_next_init(module);
}


static const struct ldb_module_ops asq_ops = {
	.name		   = "asq",
	.request      	   = asq,
	.async_wait        = asq_async_wait,
	.init_context	   = asq_init
};

int ldb_asq_init(void)
{
	return ldb_register_module(&asq_ops);
}
