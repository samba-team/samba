/* 
   Partitions ldb module

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006

   * NOTICE: this module is NOT released under the GNU LGPL license as
   * other ldb code. This module is release under the GNU GPL v2 or
   * later license.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb partitions module
 *
 *  Description: Implement LDAP partitions
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb/include/includes.h"

struct partition {
	struct ldb_module *module;
	const char *backend;
	struct ldb_dn *dn;
};
struct partition_private_data {
	struct partition **partitions;
};

struct partition_async_context {
	struct ldb_module *module;
	struct ldb_request *orig_req;

	struct ldb_request **search_req;
	BOOL *finished_search;
	int num_searches;
};

static struct ldb_async_handle *partition_init_handle(struct ldb_request *req, struct ldb_module *module)
{
	struct partition_async_context *ac;
	struct ldb_async_handle *h;

	h = talloc_zero(req, struct ldb_async_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct partition_async_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Out of Memory"));
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	ac->module = module;
	ac->orig_req = req;

	return h;
}

struct ldb_module *make_module_for_next_request(TALLOC_CTX *mem_ctx, 
						struct ldb_context *ldb,
						struct ldb_module *module) 
{
	struct ldb_module *current;
	static const struct ldb_module_ops ops; /* zero */
	current = talloc_zero(mem_ctx, struct ldb_module);
	if (current == NULL) {
		return module;
	}
	
	current->ldb = ldb;
	current->ops = &ops;
	current->prev = NULL;
	current->next = module;
	return current;
}

struct ldb_module *find_backend(struct ldb_module *module, struct ldb_request *req, const struct ldb_dn *dn)
{
	int i;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	/* Look at base DN */
	/* Figure out which partition it is under */
	/* Skip the lot if 'data' isn't here yet (initialistion) */
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		if (ldb_dn_compare_base(module->ldb, 
					data->partitions[i]->dn, 
					dn) == 0) {
			return make_module_for_next_request(req, module->ldb, data->partitions[i]->module);
		}
	}

	return module;
};

static int partition_send_search(struct partition_async_context *ac, struct ldb_module *partition)
{
	int ret;
	struct ldb_module *next = make_module_for_next_request(ac->module, ac->module->ldb, partition);
	
	ac->search_req = talloc_realloc(ac, ac->search_req, 
					struct ldb_request *, ac->num_searches + 1);
	if (!ac->search_req) {
		ldb_set_errstring(ac->module->ldb, talloc_asprintf(ac->module->ldb, "Out of memory!"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac->search_req[ac->num_searches] = talloc(ac, struct ldb_request);
	if (ac->search_req[ac->num_searches] == NULL) {
		ldb_set_errstring(ac->module->ldb, talloc_asprintf(ac->module->ldb, "Out of memory!"));
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	*ac->search_req[ac->num_searches] = *ac->orig_req; /* copy the request */
	
	/* Spray off search requests to all backends */
	ret = ldb_next_request(next, ac->search_req[ac->num_searches]); 
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	
	ac->num_searches++;
	return LDB_SUCCESS;
}

/* search */
static int partition_search(struct ldb_module *module, struct ldb_request *req)
{
	/* Find backend */
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	/* issue request */

	/* (later) consider if we should be searching multiple
	 * partitions (for 'invisible' partition behaviour */
	if (ldb_get_opaque(module->ldb, "global_catalog")) {
		int ret, i;
		struct ldb_async_handle *h;
		struct partition_async_context *ac;
		
		h = partition_init_handle(req, module);
		if (!h) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		/* return our own handle to deal with this call */
		req->async.handle = h;
		
		ac = talloc_get_type(h->private_data, struct partition_async_context);
		
		ac->orig_req = req;
		ac->num_searches = 0;

		for (i=0; data && data->partitions && data->partitions[i]; i++) {
			/* Find all partitions under the search base */
			if (ldb_dn_compare_base(module->ldb, 
						req->op.search.base,
						data->partitions[i]->dn) == 0) {
				ret = partition_send_search(ac, data->partitions[i]->module);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
		}

		/* Perhaps we didn't match any partitions.  Try the main partition, then all partitions */
		if (ac->num_searches == 0) {
			ret = partition_send_search(ac, module->next);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			for (i=0; data && data->partitions && data->partitions[i]; i++) {
				ret = partition_send_search(ac, data->partitions[i]->module);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
		}
		
		ac->finished_search = talloc_zero_array(ac, BOOL, ac->num_searches);
		if (!ac->finished_search) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		return LDB_SUCCESS;
	} else {
		struct ldb_module *backend = find_backend(module, req, req->op.search.base);
	
		return ldb_next_request(backend, req);
	}
}

/* add */
static int partition_add(struct ldb_module *module, struct ldb_request *req)
{
	/* Find backend */
	struct ldb_module *backend = find_backend(module, req, req->op.add.message->dn);
	
	/* issue request */

	return ldb_next_request(backend, req);
}

/* modify */
static int partition_modify(struct ldb_module *module, struct ldb_request *req)
{
	/* Find backend */
	struct ldb_module *backend = find_backend(module, req, req->op.mod.message->dn);
	
	/* issue request */

	return ldb_next_request(backend, req);
}

/* delete */
static int partition_delete(struct ldb_module *module, struct ldb_request *req)
{
	/* Find backend */
	struct ldb_module *backend = find_backend(module, req, req->op.del.dn);
	
	/* issue request */

	return ldb_next_request(backend, req);
}

/* rename */
static int partition_rename(struct ldb_module *module, struct ldb_request *req)
{
	/* Find backend */
	struct ldb_module *backend = find_backend(module, req, req->op.rename.olddn);
	struct ldb_module *backend2 = find_backend(module, req, req->op.rename.newdn);

	if (backend->next != backend2->next) {
		return LDB_ERR_AFFECTS_MULTIPLE_DSAS;
	}

	/* issue request */

	/* (later) consider if we should be searching multiple partitions */
	return ldb_next_request(backend, req);
}

/* start a transaction */
static int partition_start_trans(struct ldb_module *module)
{
	int i, ret;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	/* Look at base DN */
	/* Figure out which partition it is under */
	/* Skip the lot if 'data' isn't here yet (initialistion) */
	ret = ldb_next_start_trans(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		struct ldb_module *next = make_module_for_next_request(module, module->ldb, data->partitions[i]->module);

		ret = ldb_next_start_trans(next);
		talloc_free(next);
		if (ret != LDB_SUCCESS) {
			/* Back it out, if it fails on one */
			for (i--; i >= 0; i--) {
				next = make_module_for_next_request(module, module->ldb, data->partitions[i]->module);
				ldb_next_del_trans(next);
				talloc_free(next);
			}
			return ret;
		}
	}
	return LDB_SUCCESS;
}

/* end a transaction */
static int partition_end_trans(struct ldb_module *module)
{
	int i, ret, ret2 = LDB_SUCCESS;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	ret = ldb_next_end_trans(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Look at base DN */
	/* Figure out which partition it is under */
	/* Skip the lot if 'data' isn't here yet (initialistion) */
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		struct ldb_module *next = make_module_for_next_request(module, module->ldb, data->partitions[i]->module);
		
		ret = ldb_next_end_trans(next);
		talloc_free(next);
		if (ret != LDB_SUCCESS) {
			ret2 = ret;
		}
	}

	if (ret != LDB_SUCCESS) {
		/* Back it out, if it fails on one */
		for (i=0; data && data->partitions && data->partitions[i]; i++) {
			struct ldb_module *next = make_module_for_next_request(module, module->ldb, data->partitions[i]->module);
			ldb_next_del_trans(next);
			talloc_free(next);
		}
	}
	return ret;
}

/* delete a transaction */
static int partition_del_trans(struct ldb_module *module)
{
	int i, ret, ret2 = LDB_SUCCESS;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	ret = ldb_next_del_trans(module);
	if (ret != LDB_SUCCESS) {
		ret2 = ret;
	}

	/* Look at base DN */
	/* Figure out which partition it is under */
	/* Skip the lot if 'data' isn't here yet (initialistion) */
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		struct ldb_module *next = make_module_for_next_request(module, module->ldb, data->partitions[i]->module);
		
		ret = ldb_next_del_trans(next);
		talloc_free(next);
		if (ret != LDB_SUCCESS) {
			ret2 = ret;
		}
	}
	return ret2;
}

static int partition_sequence_number(struct ldb_module *module, struct ldb_request *req)
{
	int i, ret;
	uint64_t seq_number = 0;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	ret = ldb_next_request(module, req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	seq_number = seq_number + req->op.seq_num.seq_num;

	/* Look at base DN */
	/* Figure out which partition it is under */
	/* Skip the lot if 'data' isn't here yet (initialistion) */
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		struct ldb_module *next = make_module_for_next_request(req, module->ldb, data->partitions[i]->module);
		
		ret = ldb_next_request(next, req);
		talloc_free(next);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		seq_number = seq_number + req->op.seq_num.seq_num;
	}
	req->op.seq_num.seq_num = seq_number;
	return LDB_SUCCESS;
}

static int sort_compare(void *void1,
			void *void2, void *opaque)
{
	struct ldb_context *ldb = talloc_get_type(opaque, struct ldb_context);
	struct partition **pp1 = void1;
	struct partition **pp2 = void2;
	struct partition *partition1 = talloc_get_type(*pp1, struct partition);
	struct partition *partition2 = talloc_get_type(*pp2, struct partition);

	return ldb_dn_compare(ldb, partition1->dn, partition2->dn);
}

static int partition_init(struct ldb_module *module)
{
	int ret, i;
	TALLOC_CTX *mem_ctx = talloc_new(module);
	static const char *attrs[] = { "partition", NULL };
	struct ldb_result *res;
	struct ldb_message *msg;
	struct ldb_message_element *partition_attributes;

	struct partition_private_data *data;

	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data = talloc(mem_ctx, struct partition_private_data);
	if (data == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_search(module->ldb, ldb_dn_explode(mem_ctx, "@PARTITION"),
			 LDB_SCOPE_BASE,
			 NULL, attrs,
			 &res);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}
	talloc_steal(mem_ctx, res);
	if (res->count == 0) {
		talloc_free(mem_ctx);
		return ldb_next_init(module);
	}

	if (res->count > 1) {
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	msg = res->msgs[0];

	partition_attributes = ldb_msg_find_element(msg, "partition");
	if (!partition_attributes) {
		ldb_set_errstring(module->ldb, 
				  talloc_asprintf(module, "partition_init: "
						  "no partitions specified"));
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	data->partitions = talloc_array(data, struct partition *, partition_attributes->num_values + 1);
	if (!data->partitions) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	for (i=0; i < partition_attributes->num_values; i++) {
		char *base = talloc_strdup(data->partitions, (char *)partition_attributes->values[i].data);
		char *p = strchr(base, ':');
		if (!p) {
			ldb_set_errstring(module->ldb, 
					  talloc_asprintf(module, "partition_init: "
							  "invalid form for partition record (missing ':'): %s", base));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		p[0] = '\0';
		p++;
		if (!p[0]) {
			ldb_set_errstring(module->ldb, 
					  talloc_asprintf(module, "partition_init: "
							  "invalid form for partition record (missing backend database): %s", base));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		data->partitions[i] = talloc(data->partitions, struct partition);
		if (!data->partitions[i]) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		data->partitions[i]->dn = ldb_dn_explode(data->partitions[i], base);
		if (!data->partitions[i]->dn) {
			ldb_set_errstring(module->ldb, 
					  talloc_asprintf(module, "partition_init: "
							  "invalid DN in partition record: %s", base));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		data->partitions[i]->backend = private_path(data->partitions[i], p);
		ret = ldb_connect_backend(module->ldb, data->partitions[i]->backend, NULL, &data->partitions[i]->module);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	data->partitions[i] = NULL;

	/* sort these into order, most to least specific */
	ldb_qsort(data->partitions, partition_attributes->num_values, sizeof(*data->partitions), 
		  module->ldb, sort_compare);

	for (i=0; data->partitions[i]; i++) {
		struct ldb_request *req;
		req = talloc_zero(mem_ctx, struct ldb_request);
		if (req == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "partition: Out of memory!\n");
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		req->operation = LDB_REQ_REGISTER_PARTITION;
		req->op.reg_partition.dn = data->partitions[i]->dn;
		
		ret = ldb_request(module->ldb, req);
		if (ret != LDB_SUCCESS) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "partition: Unable to register partition with rootdse!\n");
			return LDB_ERR_OTHER;
		}
		talloc_free(req);
	}

	module->private_data = data;
	talloc_steal(module, data);
	
	talloc_free(mem_ctx);
	return ldb_next_init(module);
}

static int partition_async_wait_none(struct ldb_async_handle *handle) {
	struct partition_async_context *ac;
	int ret;
	int i;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct partition_async_context);

	for (i=0; i < ac->num_searches; i++) {
		ret = ldb_async_wait(ac->search_req[i]->async.handle, LDB_WAIT_NONE);
		
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req[i]->async.handle->status != LDB_SUCCESS) {
			handle->status = ac->search_req[i]->async.handle->status;
			goto done;
		}
		
		if (ac->search_req[i]->async.handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}
	}

	ret = LDB_SUCCESS;

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}


static int partition_async_wait_all(struct ldb_async_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = partition_async_wait_none(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int partition_async_wait(struct ldb_async_handle *handle, enum ldb_async_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return partition_async_wait_all(handle);
	} else {
		return partition_async_wait_none(handle);
	}
}

static const struct ldb_module_ops partition_ops = {
	.name		   = "partition",
	.init_context	   = partition_init,
	.search            = partition_search,
	.add               = partition_add,
	.modify            = partition_modify,
	.del               = partition_delete,
	.rename            = partition_rename,
	.start_transaction = partition_start_trans,
	.end_transaction   = partition_end_trans,
	.del_transaction   = partition_del_trans,
	.sequence_number   = partition_sequence_number,
	.async_wait        = partition_async_wait
};

int ldb_partition_init(void)
{
	return ldb_register_module(&partition_ops);
}
