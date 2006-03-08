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
 *  Component: ldb server side sort control module
 *
 *  Description: this module sorts the results of a search
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/includes.h"

struct opaque {
	struct ldb_context *ldb;
	const struct ldb_attrib_handler *h;
	const char *attribute;
	int reverse;
	int result;
};

struct sort_async_context {
	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_async_result *);
	int timeout;

	char *attributeName;
	char *orderingRule;
	int reverse;

	struct ldb_request *req;
	struct ldb_message **msgs;
	char **referrals;
	struct ldb_control **controls;
	int num_msgs;
	int num_refs;

	const struct ldb_attrib_handler *h;
	int sort_result;
};

static struct ldb_async_handle *init_handle(void *mem_ctx, struct ldb_module *module,
					    void *context,
					    int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
					    int timeout)
{
	struct sort_async_context *ac;
	struct ldb_async_handle *h;

	h = talloc_zero(mem_ctx, struct ldb_async_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct sort_async_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	ac->module = module;
	ac->up_context = context;
	ac->up_callback = callback;
	ac->timeout = timeout;

	return h;
}

static int build_response(void *mem_ctx, struct ldb_control ***ctrls, int result, const char *desc)
{
	struct ldb_control **controls;
	struct ldb_sort_resp_control *resp;
	int i;

	if (*ctrls) {
		controls = *ctrls;
		for (i = 0; controls[i]; i++);
		controls = talloc_realloc(mem_ctx, controls, struct ldb_control *, i + 2);
	} else {
		i = 0;
		controls = talloc_array(mem_ctx, struct ldb_control *, 2);
	}
	if (! controls )
		return LDB_ERR_OPERATIONS_ERROR;

	*ctrls = controls;

	controls[i+1] = NULL;
	controls[i] = talloc(controls, struct ldb_control);
	if (! controls[i] )
		return LDB_ERR_OPERATIONS_ERROR;

	controls[i]->oid = LDB_CONTROL_SORT_RESP_OID;
	controls[i]->critical = 0;

	resp = talloc(controls[i], struct ldb_sort_resp_control);
	if (! resp )
		return LDB_ERR_OPERATIONS_ERROR;

	resp->result = result;
	resp->attr_desc = talloc_strdup(resp, desc);

	if (! resp->attr_desc )
		return LDB_ERR_OPERATIONS_ERROR;
	
	controls[i]->data = resp;

	return LDB_SUCCESS;
}

static int sort_compare(struct ldb_message **msg1, struct ldb_message **msg2, void *opaque)
{
	struct opaque *data = (struct opaque *)opaque;
	struct ldb_message_element *el1, *el2;

	if (data->result != 0) {
		/* an error occurred previously,
		 * let's exit the sorting by returning always 0 */
		return 0;
	}

	el1 = ldb_msg_find_element(*msg1, data->attribute);
	el2 = ldb_msg_find_element(*msg2, data->attribute);

	if (!el1 || !el2) {
		/* the attribute was not found return and
		 * set an error */
		data->result = 53;
		return 0;
	}

	if (data->reverse)
		return data->h->comparison_fn(data->ldb, data, &el2->values[0], &el1->values[0]);

	return data->h->comparison_fn(data->ldb, data, &el1->values[0], &el2->values[0]);
}

static int sort_compare_async(struct ldb_message **msg1, struct ldb_message **msg2, void *opaque)
{
	struct sort_async_context *ac = talloc_get_type(opaque, struct sort_async_context);
	struct ldb_message_element *el1, *el2;

	if (ac->sort_result != 0) {
		/* an error occurred previously,
		 * let's exit the sorting by returning always 0 */
		return 0;
	}

	el1 = ldb_msg_find_element(*msg1, ac->attributeName);
	el2 = ldb_msg_find_element(*msg2, ac->attributeName);

	if (!el1 || !el2) {
		/* the attribute was not found return and
		 * set an error */
		ac->sort_result = 53;
		return 0;
	}

	if (ac->reverse)
		return ac->h->comparison_fn(ac->module->ldb, ac, &el2->values[0], &el1->values[0]);

	return ac->h->comparison_fn(ac->module->ldb, ac, &el1->values[0], &el2->values[0]);
}

/* search */
static int server_sort_search(struct ldb_module *module, struct ldb_control *control, struct ldb_request *req)
{
	struct ldb_result *sort_result = NULL;
	struct ldb_control **saved_controls;
	struct ldb_server_sort_control **sort_ctrls;
	int ret, result = 0;
	int do_sort = 1;

	sort_ctrls = talloc_get_type(control->data, struct ldb_server_sort_control *);
	if (!sort_ctrls) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	/* FIXME: we do not support more than one attribute for sorting right now */
	/* FIXME: we need to check if the attribute type exist or return an error */
	if (sort_ctrls[1] != NULL)
		do_sort = 0;
		
	if (!do_sort && control->critical) {
		sort_result = talloc_zero(req, struct ldb_result);
		if (!sort_result)
			return LDB_ERR_OPERATIONS_ERROR;

		req->op.search.res = sort_result;
	
		/* 53 = unwilling to perform */
		if ((ret = build_response(sort_result, &sort_result->controls, 53, "sort control is not complete yet")) != LDB_SUCCESS) {
			return ret;
		}

		return LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
	}

	/* save it locally and remove it from the list */
	if (!save_controls(control, req, &saved_controls)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_next_request(module, req);

	if (req->controls) talloc_free(req->controls);
	req->controls = saved_controls;

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* SORT HERE */
	if (do_sort) {
		struct opaque *data;
	       
		data = talloc(module, struct opaque);
		if (!data)
			return LDB_ERR_OPERATIONS_ERROR;
		
		data->attribute = sort_ctrls[0]->attributeName;
		data->reverse = sort_ctrls[0]->reverse;
		data->ldb = module->ldb;
		data->h = ldb_attrib_handler(data->ldb, data->attribute);
		data->result = 0;
		sort_result = req->op.search.res;

		ldb_qsort(sort_result->msgs,
			  sort_result->count,
			  sizeof(struct ldb_message *),
			  data,
			  (ldb_qsort_cmp_fn_t)sort_compare);

		result = data->result;

		talloc_free(data);
	} else {
		result = 53;
	}

	if ((ret = build_response(sort_result, &sort_result->controls, result, "sort control is not complete yet")) != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static int server_sort_search_async_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct sort_async_context *ac = NULL;
	
 	if (!context || !ares) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context or Result in callback"));
		goto error;
	}	

       	ac = talloc_get_type(context, struct sort_async_context);

	if (ares->type == LDB_REPLY_ENTRY) {
		ac->msgs = talloc_realloc(ac, ac->msgs, struct ldb_message *, ac->num_msgs + 2);
		if (! ac->msgs) {
			goto error;
		}

		ac->msgs[ac->num_msgs + 1] = NULL;

		ac->msgs[ac->num_msgs] = talloc_steal(ac->msgs, ares->message);
		if (! ac->msgs[ac->num_msgs]) {
			goto error;
		}

		ac->num_msgs++;
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		ac->referrals = talloc_realloc(ac, ac->referrals, char *, ac->num_refs + 2);
		if (! ac->referrals) {
			goto error;
		}

		ac->referrals[ac->num_refs + 1] = NULL;

		ac->referrals[ac->num_refs] = talloc_steal(ac->referrals, ares->referral);
		if (! ac->referrals[ac->num_refs]) {
			goto error;
		}

		ac->num_refs++;
	}

	if (ares->type == LDB_REPLY_DONE) {
		if (ares->controls) {
			ac->controls = talloc_steal(ac, ares->controls);
			if (! ac->controls) {
				goto error;
			}
		}
	}

	talloc_free(ares);
	return LDB_SUCCESS;

error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int server_sort_search_async(struct ldb_module *module, struct ldb_control *control, struct ldb_request *req)
{
	struct ldb_server_sort_control **sort_ctrls;
	struct ldb_control **saved_controls;
	struct sort_async_context *ac;
	struct ldb_async_handle *h;
	int ret;

	req->async.handle = NULL;

	if (!req->async.callback || !req->async.context) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Async interface called with NULL callback function or NULL context"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	h = init_handle(req, module, req->async.context, req->async.callback, req->async.timeout);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct sort_async_context);

	sort_ctrls = talloc_get_type(control->data, struct ldb_server_sort_control *);
	if (!sort_ctrls) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	/* FIXME: we do not support more than one attribute for sorting right now */
	/* FIXME: we need to check if the attribute type exist or return an error */
		
	if (sort_ctrls[1] != NULL) {
		if (control->critical) {
			struct ldb_async_result *ares;

			ares = talloc_zero(req, struct ldb_async_result);
			if (!ares)
				return LDB_ERR_OPERATIONS_ERROR;

			/* 53 = unwilling to perform */
			ares->type = LDB_REPLY_DONE;
			if ((ret = build_response(ares, &ares->controls, 53, "sort control is not complete yet")) != LDB_SUCCESS) {
				return ret;
			}

			h->status = LDB_ERR_UNSUPPORTED_CRITICAL_EXTENSION;
			h->state = LDB_ASYNC_DONE;
			ret = ac->up_callback(module->ldb, ac->up_context, ares);

			return ret;
		} else {
			/* just pass the call down and don't do any sorting */
			ldb_next_request(module, req);
		}
	}

	ac->attributeName = sort_ctrls[0]->attributeName;
	ac->orderingRule = sort_ctrls[0]->orderingRule;
	ac->reverse = sort_ctrls[0]->reverse;

	ac->req = talloc(req, struct ldb_request);
	if (!ac->req)
		return LDB_ERR_OPERATIONS_ERROR;

	ac->req->operation = req->operation;
	ac->req->op.search.base = req->op.search.base;
	ac->req->op.search.scope = req->op.search.scope;
	ac->req->op.search.tree = req->op.search.tree;
	ac->req->op.search.attrs = req->op.search.attrs;
	ac->req->controls = req->controls;

	/* save it locally and remove it from the list */
	/* we do not need to replace them later as we
	 * are keeping the original req intact */
	if (!save_controls(control, ac->req, &saved_controls)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->req->creds = req->creds;

	ac->req->async.context = ac;
	ac->req->async.callback = server_sort_search_async_callback;
	ac->req->async.timeout = req->async.timeout;

	req->async.handle = h;

	return ldb_next_request(module, ac->req);
}

static int server_sort(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;

	/* check if there's a paged request control */
	control = get_control_from_list(req->controls, LDB_CONTROL_SERVER_SORT_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return server_sort_search(module, control, req);

	case LDB_ASYNC_SEARCH:
		return server_sort_search_async(module, control, req);

	default:
		return LDB_ERR_PROTOCOL_ERROR;

	}
}

static int server_sort_async_results(struct ldb_async_handle *handle)
{
	struct sort_async_context *ac;
	struct ldb_async_result *ares;
	int i, ret;

	ac = talloc_get_type(handle->private_data, struct sort_async_context);

	ac->h = ldb_attrib_handler(ac->module->ldb, ac->attributeName);
	ac->sort_result = 0;

	ldb_qsort(ac->msgs, ac->num_msgs,
		  sizeof(struct ldb_message *),
		  ac, (ldb_qsort_cmp_fn_t)sort_compare_async);

	for (i = 0; i < ac->num_msgs; i++) {
		ares = talloc_zero(ac, struct ldb_async_result);
		if (!ares) {
			handle->status = LDB_ERR_OPERATIONS_ERROR;
			return handle->status;
		}

		ares->type = LDB_REPLY_ENTRY;
		ares->message = talloc_steal(ares, ac->msgs[i]);
		
		handle->status = ac->up_callback(ac->module->ldb, ac->up_context, ares);
		if (handle->status != LDB_SUCCESS) {
			return handle->status;
		}
	}

	for (i = 0; i < ac->num_refs; i++) {
		ares = talloc_zero(ac, struct ldb_async_result);
		if (!ares) {
			handle->status = LDB_ERR_OPERATIONS_ERROR;
			return handle->status;
		}

		ares->type = LDB_REPLY_REFERRAL;
		ares->referral = talloc_steal(ares, ac->referrals[i]);
		
		handle->status = ac->up_callback(ac->module->ldb, ac->up_context, ares);
		if (handle->status != LDB_SUCCESS) {
			return handle->status;
		}
	}

	ares = talloc_zero(ac, struct ldb_async_result);
	if (!ares) {
		handle->status = LDB_ERR_OPERATIONS_ERROR;
		return handle->status;
	}

	ares->type = LDB_REPLY_DONE;
	ares->controls = talloc_steal(ares, ac->controls);
		
	handle->status = ac->up_callback(ac->module->ldb, ac->up_context, ares);
	if (handle->status != LDB_SUCCESS) {
		return handle->status;
	}

	if ((ret = build_response(ac, &ac->controls, ac->sort_result, "sort control is not complete yet")) != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static int server_sort_async_wait(struct ldb_async_handle *handle, enum ldb_async_wait_type type)
{
	struct sort_async_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac = talloc_get_type(handle->private_data, struct sort_async_context);

	ret = ldb_async_wait(ac->req->async.handle, type);

	if (ret != LDB_SUCCESS) {
		handle->status = ret;
		return ret;
	}
		
	handle->state = ac->req->async.handle->state;
	handle->status = ac->req->async.handle->status;

	if (handle->status != LDB_SUCCESS) {
		return handle->status;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		ret = server_sort_async_results(handle);
	}

	return ret;
}

static int server_sort_init(struct ldb_module *module)
{
	struct ldb_request *req;
	int ret;

	req = talloc(module, struct ldb_request);
	if (req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_REGISTER;
	req->op.reg.oid = LDB_CONTROL_SERVER_SORT_OID;
	req->controls = NULL;

	ret = ldb_request(module->ldb, req);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "server_sort: Unable to register control with rootdse!\n");
		talloc_free(req);
		return LDB_ERR_OTHER;
	}

	talloc_free(req);
	return ldb_next_init(module);
}

static const struct ldb_module_ops server_sort_ops = {
	.name		   = "server_sort",
	.request      	   = server_sort,
	.async_wait        = server_sort_async_wait,
	.init_context	   = server_sort_init
};

int ldb_sort_init(void)
{
	return ldb_register_module(&server_sort_ops);
}
