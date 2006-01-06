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
 *  Component: ldb paged results control module
 *
 *  Description: this module caches a complete search and sends back
 *  		 results in chunks as asked by the client
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"

#include <time.h>

struct results_store {
	char *cookie;
	time_t timestamp;
	int num_sent;
	struct ldb_result *result;
	struct results_store *prev;
	struct results_store *next;
};

struct private_data {

	int next_free_id;
	struct results_store *store;
	
};


static struct results_store *new_store(struct private_data *priv)
{
	struct results_store *new;
	int new_id = priv->next_free_id++;

	/* TODO: we should have a limit on the number of
	 * outstanding paged searches
	 */

	new = talloc(priv, struct results_store);
	if (!new) return NULL;

	new->cookie = talloc_asprintf(new, "%d", new_id);
	if (!new->cookie) {
		talloc_free(new);
		return NULL;
	}

	new->timestamp = time(NULL);

	new->num_sent = 0;
	new->result = NULL;

	/* put this entry as first */
	new->prev = NULL;
	new->next = priv->store;
	if (priv->store != NULL) priv->store->prev = new;
	priv->store = new;

	return new;
}

static void remove_store(struct results_store *store)
{
	if (store->prev) {
		store->prev->next = store->next;
	}
	if (store->next) {
		store->next->prev = store->prev;
	}
	talloc_free(store);
}

/* search */
static int paged_search(struct ldb_module *module, struct ldb_request *req)
{
	struct private_data *private_data = talloc_get_type(module->private_data, struct private_data);
	struct results_store *current = NULL;
	struct ldb_result *paged_result;
	struct ldb_control **saved_controls;
	struct ldb_control *control;
	struct ldb_paged_control *paged_ctrl;
	struct ldb_paged_control *paged_ret;
	int i, ret;

	/* check if there's a paged request control */
	control = get_control_from_list(req->controls, LDB_CONTROL_PAGED_RESULTS_OID);

	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	paged_ctrl = talloc_get_type(control->data, struct ldb_paged_control);

	/* check if it is a continuation search the store */
	if (paged_ctrl->cookie_len != 0) {
		for (current = private_data->store; current; current = current->next) {
			if (strcmp(current->cookie, paged_ctrl->cookie) == 0) {
				current->timestamp = time(NULL);
				break;
			}
		}
		if (current == NULL) {
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}

	/* is this a brand new paged request ? */
	if (current == NULL) {

		/* save controls list and remove this one from the list */
		if (!save_controls(control, req, &saved_controls)) {
			return LDB_ERR_OTHER;
		}

		/* perform the search */
		ret = ldb_next_request(module, req);

		/* restore original controls list */
		if (req->controls) talloc_free(req->controls);
		req->controls = saved_controls;

		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/* create a new entry in the cache */
		current = new_store(private_data);
		if (!current) {
			return LDB_ERR_OTHER;
		}

		/* steal the search result */
		current->result = talloc_steal(current, req->op.search.res);
		req->op.search.res = NULL;
	}

	/* create a container for the next batch of results */
	paged_result = talloc(current, struct ldb_result);
	if (!paged_result) {
		return LDB_ERR_OTHER;
	}
	paged_result->count = 0;
	paged_result->msgs = NULL;
	paged_result->controls = NULL;

	/* check if it is an abandon */
	if (paged_ctrl->size == 0) {
		req->op.search.res = talloc_steal(private_data, paged_result);
		remove_store(current);
		return LDB_SUCCESS;
	}

	/* return a batch of results */
		
	paged_result->controls = talloc_array(paged_result, struct ldb_control *, 2);
	if (!paged_result->controls) {
		talloc_free(paged_result);
		return LDB_ERR_OTHER;
	}

	paged_result->controls[0] = talloc(paged_result->controls, struct ldb_control);
	if (!paged_result->controls[0]) {
		talloc_free(paged_result);
		return LDB_ERR_OTHER;
	}
	paged_result->controls[0]->oid = talloc_strdup(paged_result->controls[0], LDB_CONTROL_PAGED_RESULTS_OID);
	paged_result->controls[0]->critical = 0;
	paged_result->controls[1] = NULL;

	paged_ret = talloc(paged_result->controls[0], struct ldb_paged_control);
	if (!paged_ret) {
		talloc_free(paged_result);
		return LDB_ERR_OTHER;
	}
	paged_result->controls[0]->data = paged_ret;

	if (paged_ctrl->size >= current->result->count) {
		paged_ret->size = 0;
		paged_ret->cookie = NULL;
		paged_ret->cookie_len = 0;
		paged_result->count = current->result->count;
		current->result->count = 0;
	} else {
		paged_ret->size = current->result->count;
		paged_ret->cookie = talloc_strdup(paged_ret, current->cookie);
		paged_ret->cookie_len = strlen(paged_ret->cookie) + 1;
		paged_result->count = paged_ctrl->size;
		current->result->count -= paged_ctrl->size;
	}

	paged_result->msgs = talloc_array(paged_result, struct ldb_message *, paged_result->count + 1);
	if (!paged_result->msgs) {
		talloc_free(paged_result);
		return LDB_ERR_OTHER;
	}
	for (i = 0; i < paged_result->count; i++) {
		paged_result->msgs[i] = talloc_steal(paged_result->msgs, current->result->msgs[current->num_sent + i]);
	}
	current->num_sent += paged_result->count;
	paged_result->msgs[paged_result->count] = NULL;

	req->op.search.res = paged_result;

	return LDB_SUCCESS;	
}

static int paged_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return paged_search(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static int paged_request_init_2(struct ldb_module *module)
{
	struct ldb_request request;
	int ret;

	request.operation = LDB_REQ_REGISTER;
	request.op.reg.oid = LDB_CONTROL_PAGED_RESULTS_OID;
	request.controls = NULL;

	ret = ldb_request(module->ldb, &request);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "paged_request: Unable to register control with rootdse!\n");
		return LDB_ERR_OTHER;
	}

	return ldb_next_second_stage_init(module);
}

static const struct ldb_module_ops paged_ops = {
	.name		   = "paged_results",
	.request      	   = paged_request,
	.second_stage_init = paged_request_init_2
};

struct ldb_module *paged_results_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;
	struct private_data *data;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	data = talloc(ctx, struct private_data);
	if (data == NULL) {
		talloc_free(ctx);
		return NULL;
	}

	data->next_free_id = 1;
	data->store = NULL;
	ctx->private_data = data;

	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &paged_ops;

	return ctx;
}
