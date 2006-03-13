/* 
   ldb database library

   Copyright (C) Simo Sorce  2005-2006

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
 *  Name: paged_result
 *
 *  Component: ldb paged results control module
 *
 *  Description: this module caches a complete search and sends back
 *  		 results in chunks as asked by the client
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/includes.h"

struct message_store {
	/* keep the whole ldb_async_result as an optimization
	 * instead of freeing and talloc-ing the container
	 * on each result */
	struct ldb_async_result *r;
	struct message_store *next;
};

struct results_store {
	char *cookie;
	time_t timestamp;
	int num_sent; /* To be removed */
	struct ldb_result *result; /* To be removed */
	struct results_store *prev;
	struct results_store *next;
	
	struct message_store *first;
	struct message_store *last;
	int num_entries;

	struct message_store *first_ref;
	struct message_store *last_ref;

	struct ldb_control **controls;

	struct ldb_request *req;
};

struct private_data {

	int next_free_id;
	struct results_store *store;
	
};

int store_destructor(void *data)
{
	struct results_store *store = talloc_get_type(data, struct results_store);

	if (store->prev) {
		store->prev->next = store->next;
	}
	if (store->next) {
		store->next->prev = store->prev;
	}
	
	return 0;
}

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

	new->num_sent = 0; /* To be removed */
	new->result = NULL; /* To be removed */

	new->first = NULL;
	new->num_entries = 0;
	new->first_ref = NULL;
	new->controls = NULL;

	/* put this entry as first */
	new->prev = NULL;
	new->next = priv->store;
	if (priv->store != NULL) priv->store->prev = new;
	priv->store = new;

	talloc_set_destructor(new, store_destructor);

	return new;
}

/* search */
static int paged_search(struct ldb_module *module, struct ldb_control *control, struct ldb_request *req)
{
	struct private_data *private_data = talloc_get_type(module->private_data, struct private_data);
	struct results_store *current = NULL;
	struct ldb_result *paged_result;
	struct ldb_control **saved_controls;
	struct ldb_paged_control *paged_ctrl;
	struct ldb_paged_control *paged_ret;
	int i, ret;

	paged_ctrl = talloc_get_type(control->data, struct ldb_paged_control);
	if (!paged_ctrl) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

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
		talloc_free(current);
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

struct paged_async_context {
	struct ldb_module *module;
	void *up_context;
	int (*up_callback)(struct ldb_context *, void *, struct ldb_async_result *);
	int timeout;

	int size;

	struct results_store *store;
};

static struct ldb_async_handle *init_handle(void *mem_ctx, struct ldb_module *module,
					    void *context,
					    int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
					    int timeout)
{
	struct paged_async_context *ac;
	struct ldb_async_handle *h;

	h = talloc_zero(mem_ctx, struct ldb_async_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct paged_async_context);
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

static int paged_search_async_callback(struct ldb_context *ldb, void *context, struct ldb_async_result *ares)
{
	struct paged_async_context *ac = NULL;

	if (!context || !ares) {
		ldb_set_errstring(ldb, talloc_asprintf(ldb, "NULL Context or Result in callback"));
		goto error;
	}

	ac = talloc_get_type(context, struct paged_async_context);

	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->store->first == NULL) {
			ac->store->first = ac->store->last = talloc(ac->store, struct message_store);
		} else {
			ac->store->last->next = talloc(ac->store, struct message_store);
			ac->store->last = ac->store->last->next;
		}
		if (ac->store->last == NULL) {
			goto error;
		}

		ac->store->num_entries++;

		ac->store->last->r = talloc_steal(ac->store->last, ares);
		if (ac->store->last->r == NULL) {
			goto error;
		}
		ac->store->last->next = NULL;
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		if (ac->store->first_ref == NULL) {
			ac->store->first_ref = ac->store->last_ref = talloc(ac->store, struct message_store);
		} else {
			ac->store->last_ref->next = talloc(ac->store, struct message_store);
			ac->store->last_ref = ac->store->last_ref->next;
		}
		if (ac->store->last_ref == NULL) {
			goto error;
		}

		ac->store->last_ref->r = talloc_steal(ac->store->last, ares);
		if (ac->store->last_ref->r == NULL) {
			goto error;
		}
		ac->store->last_ref->next = NULL;
	}

	if (ares->type == LDB_REPLY_DONE) {
		if (ares->controls) {
			ac->store->controls = talloc_steal(ac->store, ares->controls);
			if (! ac->store->controls) {
				goto error;
			}
		}
		talloc_free(ares);
	}

	return LDB_SUCCESS;

error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

static int paged_search_async(struct ldb_module *module, struct ldb_control *control, struct ldb_request *req)
{
	struct private_data *private_data = talloc_get_type(module->private_data, struct private_data);
	struct ldb_paged_control *paged_ctrl;
	struct ldb_control **saved_controls;
	struct paged_async_context *ac;
	struct ldb_async_handle *h;
	int ret;

	req->async.handle = NULL;

	if (!req->async.callback || !req->async.context) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module,
				  "Async interface called with NULL callback function or NULL context"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	paged_ctrl = talloc_get_type(control->data, struct ldb_paged_control);
	if (!paged_ctrl) {
		return LDB_ERR_PROTOCOL_ERROR;
	}

	h = init_handle(req, module, req->async.context, req->async.callback, req->async.timeout);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct paged_async_context);

	ac->size = paged_ctrl->size;

	/* check if it is a continuation search the store */
	if (paged_ctrl->cookie_len == 0) {
		
		ac->store = new_store(private_data);
		if (ac->store == NULL) {
			talloc_free(h);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		ac->store->req = talloc(ac->store, struct ldb_request);
		if (!ac->store->req)
			return LDB_ERR_OPERATIONS_ERROR;

		ac->store->req->operation = req->operation;
		ac->store->req->op.search.base = req->op.search.base;
		ac->store->req->op.search.scope = req->op.search.scope;
		ac->store->req->op.search.tree = req->op.search.tree;
		ac->store->req->op.search.attrs = req->op.search.attrs;
		ac->store->req->controls = req->controls;

		/* save it locally and remove it from the list */
		/* we do not need to replace them later as we
		 * are keeping the original req intact */
		if (!save_controls(control, ac->store->req, &saved_controls)) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ac->store->req->creds = req->creds;

		ac->store->req->async.context = ac;
		ac->store->req->async.callback = paged_search_async_callback;
		ac->store->req->async.timeout = req->async.timeout;

		ret = ldb_next_request(module, ac->store->req);

	} else {
		struct results_store *current = NULL;

		for (current = private_data->store; current; current = current->next) {
			if (strcmp(current->cookie, paged_ctrl->cookie) == 0) {
				current->timestamp = time(NULL);
				break;
			}
		}
		if (current == NULL) {
			talloc_free(h);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		ac->store = current;
		ret = LDB_SUCCESS;
	}

	req->async.handle = h;

	/* check if it is an abandon */
	if (ac->size == 0) {
		talloc_free(ac->store);
		h->status = LDB_SUCCESS;
		h->state = LDB_ASYNC_DONE;
		return LDB_SUCCESS;
	}

	/* TODO: age out old outstanding requests */

	return ret;

}

static int paged_async_results(struct ldb_async_handle *handle)
{
	struct paged_async_context *ac;
	struct ldb_paged_control *paged;
	struct ldb_async_result *ares;
	struct message_store *msg;
	int i, num_ctrls, ret;

	ac = talloc_get_type(handle->private_data, struct paged_async_context);

	if (ac->store == NULL)
		return LDB_ERR_OPERATIONS_ERROR;

	while (ac->store->num_entries > 0 && ac->size > 0) {
		msg = ac->store->first;
		ret = ac->up_callback(ac->module->ldb, ac->up_context, msg->r);
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			handle->state = LDB_ASYNC_DONE;
			return ret;
		}

		ac->store->first = msg->next;
		talloc_free(msg);
		ac->store->num_entries--;
		ac->size--;
	}

	handle->state = LDB_ASYNC_DONE;

	while (ac->store->first_ref != NULL) {
		msg = ac->store->first_ref;
		ret = ac->up_callback(ac->module->ldb, ac->up_context, msg->r);
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			handle->state = LDB_ASYNC_DONE;
			return ret;
		}

		ac->store->first_ref = msg->next;
		talloc_free(msg);
	}

	ares = talloc_zero(ac->store, struct ldb_async_result);
	if (ares == NULL) {
		handle->status = LDB_ERR_OPERATIONS_ERROR;
		return handle->status;
	}
	num_ctrls = 2;
	i = 0;

	if (ac->store->controls != NULL) {
		ares->controls = ac->store->controls;
		while (ares->controls[i]) i++; /* counting */

		ares->controls = talloc_steal(ares, ac->store->controls);
		num_ctrls += i;
	}

	ares->controls = talloc_realloc(ares, ares->controls, struct ldb_control *, num_ctrls);
	if (ares->controls == NULL) {
		handle->status = LDB_ERR_OPERATIONS_ERROR;
		return handle->status;
	}

	ares->controls[i] = talloc(ares->controls, struct ldb_control);
	if (ares->controls[i] == NULL) {
		handle->status = LDB_ERR_OPERATIONS_ERROR;
		return handle->status;
	}

	ares->controls[i]->oid = talloc_strdup(ares->controls[i], LDB_CONTROL_PAGED_RESULTS_OID);
	if (ares->controls[i]->oid == NULL) {
		handle->status = LDB_ERR_OPERATIONS_ERROR;
		return handle->status;
	}
		
	ares->controls[i]->critical = 0;
	ares->controls[i + 1] = NULL;

	paged = talloc(ares->controls[i], struct ldb_paged_control);
	if (paged == NULL) {
		handle->status = LDB_ERR_OPERATIONS_ERROR;
		return handle->status;
	}
	
	ares->controls[i]->data = paged;

	if (ac->size > 0) {
		paged->size = 0;
		paged->cookie = NULL;
		paged->cookie_len = 0;
	} else {
		paged->size = ac->store->num_entries;
		paged->cookie = talloc_strdup(paged, ac->store->cookie);
		paged->cookie_len = strlen(paged->cookie) + 1;
	}

	ares->type = LDB_REPLY_DONE;

	ret = ac->up_callback(ac->module->ldb, ac->up_context, ares);

	handle->status = ret;

	return ret;
}

static int paged_async_wait(struct ldb_async_handle *handle, enum ldb_async_wait_type type)
{
	struct paged_async_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;

	ac = talloc_get_type(handle->private_data, struct paged_async_context);

	if (ac->store->req->async.handle->state == LDB_ASYNC_DONE) {
		/* if lower level is finished we do not need to call it anymore */
		/* return all we have until size == 0 or we empty storage */
		ret = paged_async_results(handle);

		/* we are done, if num_entries is zero free the storage
		 * as that mean we delivered the last batch */
		if (ac->store->num_entries == 0) {
			talloc_free(ac->store);
		}

		return ret;
	}

	if (type == LDB_WAIT_ALL) {
		while (ac->store->req->async.handle->state != LDB_ASYNC_DONE) {
			ret = ldb_async_wait(ac->store->req->async.handle, type);
			if (ret != LDB_SUCCESS) {
				handle->state = LDB_ASYNC_DONE;
				handle->status = ret;
				return ret;
			}
		}

		ret = paged_async_results(handle);

		/* we are done, if num_entries is zero free the storage
		 * as that mean we delivered the last batch */
		if (ac->store->num_entries == 0) {
			talloc_free(ac->store);
		}

		return ret;
	}

	ret = ldb_async_wait(ac->store->req->async.handle, type);
	if (ret != LDB_SUCCESS) {
		handle->state = LDB_ASYNC_DONE;
		handle->status = ret;
		return ret;
	}

	handle->status = ret;

	if (ac->store->num_entries >= ac->size ||
	    ac->store->req->async.handle->state == LDB_ASYNC_DONE) {

		ret = paged_async_results(handle);

		/* we are done, if num_entries is zero free the storage
		 * as that mean we delivered the last batch */
		if (ac->store->num_entries == 0) {
			talloc_free(ac->store);
		}
	}

	return ret;
}

static int paged_request(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_control *control;

	/* check if there's a paged request control */
	control = get_control_from_list(req->controls, LDB_CONTROL_PAGED_RESULTS_OID);
	if (control == NULL) {
		/* not found go on */
		return ldb_next_request(module, req);
	}

	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return paged_search(module, control, req);

	case LDB_ASYNC_SEARCH:
		return paged_search_async(module, control, req);

	default:
		return LDB_ERR_PROTOCOL_ERROR;

	}
}

static int paged_request_init(struct ldb_module *module)
{
	struct private_data *data;
	struct ldb_request *req;
	int ret;

	data = talloc(module, struct private_data);
	if (data == NULL) {
		return LDB_ERR_OTHER;
	}
	
	data->next_free_id = 1;
	data->store = NULL;
	module->private_data = data;

	req = talloc(module, struct ldb_request);
	if (req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_REQ_REGISTER;
	req->op.reg.oid = LDB_CONTROL_PAGED_RESULTS_OID;
	req->controls = NULL;

	ret = ldb_request(module->ldb, req);
	if (ret != LDB_SUCCESS) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "paged_request: Unable to register control with rootdse!\n");
		talloc_free(req);
		return LDB_ERR_OTHER;
	}

	talloc_free(req);
	return ldb_next_init(module);
}

static const struct ldb_module_ops paged_ops = {
	.name		   	= "paged_results",
	.request        = paged_request,
	.async_wait     = paged_async_wait,
	.init_context 	= paged_request_init
};

int ldb_paged_results_init(void)
{
	return ldb_register_module(&paged_ops);
}

