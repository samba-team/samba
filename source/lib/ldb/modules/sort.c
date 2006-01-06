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
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"

struct opaque {
	struct ldb_context *ldb;
	const struct ldb_attrib_handler *h;
	const char *attribute;
	int reverse;
	int result;
};

static int build_response(struct ldb_result *res, int result, const char *desc)
{
	struct ldb_sort_resp_control *resp;
	int i;

	if (res->controls) {
		for (i = 0; res->controls[i]; i++);
		res->controls = talloc_realloc(res, res->controls, struct ldb_control *, i + 2);
	} else {
		i = 0;
		res->controls = talloc_array(res, struct ldb_control *, 2);
	}
	if (! res->controls )
		return LDB_ERR_OPERATIONS_ERROR;

	res->controls[i+1] = NULL;
	res->controls[i] = talloc(res->controls, struct ldb_control);
	if (! res->controls[i] )
		return LDB_ERR_OPERATIONS_ERROR;

	res->controls[i]->oid = LDB_CONTROL_SORT_RESP_OID;
	res->controls[i]->critical = 0;

	resp = talloc(res->controls[i], struct ldb_sort_resp_control);
	if (! resp )
		return LDB_ERR_OPERATIONS_ERROR;

	resp->result = result;
	resp->attr_desc = talloc_strdup(resp, desc);

	if (! resp->attr_desc )
		return LDB_ERR_OPERATIONS_ERROR;
	
	res->controls[i]->data = resp;

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

/* search */
static int server_sort_search(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_result *sort_result = NULL;
	struct ldb_control *control;
	struct ldb_control **saved_controls;
	struct ldb_server_sort_control **sort_ctrls;
	int ret, result = 0;
	int do_sort = 1;

	/* check if there's a paged request control */
	control = get_control_from_list(req->controls, LDB_CONTROL_SERVER_SORT_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	sort_ctrls = talloc_get_type(control->data, struct ldb_server_sort_control *);

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
		if ((ret = build_response(sort_result, 53, "sort control is not complete yet")) != LDB_SUCCESS) {
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

		/* FIXME: I don't like to use a static structure like sort_control
		 * we need to either:
		 * a) write a qsort function that takes a third void parameter
		 * or
		 * b) prepare a structure with all elements pre digested like:
		 * 	struct element {
		 * 		struct ldb_message_element *el;
		 * 		struct ldb_message *msg;
		 * 	}
		 *
		 * 	this mean we will have to do a linear scan of
		 * 	the msgs array to build the new sort array, and
		 * 	then do a linear scan of the resulting array
		 * 	to rebuild the msgs array in the original shape.
		 */

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

	if ((ret = build_response(sort_result, result, "sort control is not complete yet")) != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

static int server_sort(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return server_sort_search(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static int server_sort_init_2(struct ldb_module *module)
{
	struct ldb_request request;
	int ret;

	request.operation = LDB_REQ_REGISTER;
	request.op.reg.oid = LDB_CONTROL_SERVER_SORT_OID;
	request.controls = NULL;

	ret = ldb_request(module->ldb, &request);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "server_sort: Unable to register control with rootdse!\n");
		return LDB_ERR_OTHER;
	}

	return ldb_next_second_stage_init(module);
}

static const struct ldb_module_ops server_sort_ops = {
	.name		   = "server_sort",
	.request      	   = server_sort,
	.second_stage_init = server_sort_init_2
};

struct ldb_module *server_sort_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &server_sort_ops;
	ctx->private_data = NULL;

	return ctx;
}
