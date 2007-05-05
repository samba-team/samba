
/* 
   Partitions ldb module

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007

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
 *  Author: Stefan Metzmacher
 */

#include "includes.h"
#include "ldb/include/ldb_includes.h"
#include "dsdb/samdb/samdb.h"

struct partition_private_data {
	struct dsdb_control_current_partition **partitions;
	struct ldb_dn **replicate;
};

struct partition_context {
	struct ldb_module *module;
	struct ldb_handle *handle;
	struct ldb_request *orig_req;

	struct ldb_request **down_req;
	int num_requests;
	int finished_requests;
};

static struct partition_context *partition_init_handle(struct ldb_request *req, struct ldb_module *module)
{
	struct partition_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct partition_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data	= ac;

	ac->module = module;
	ac->handle = h;
	ac->orig_req = req;

	req->handle = h;

	return ac;
}

static struct ldb_module *make_module_for_next_request(TALLOC_CTX *mem_ctx, 
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

static struct dsdb_control_current_partition *find_partition(struct partition_private_data *data,
							     struct ldb_dn *dn)
{
	int i;

	/* Look at base DN */
	/* Figure out which partition it is under */
	/* Skip the lot if 'data' isn't here yet (initialistion) */
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		if (ldb_dn_compare_base(data->partitions[i]->dn, dn) == 0) {
			return data->partitions[i];
		}
	}

	return NULL;
};

static struct ldb_module *find_backend(struct ldb_module *module, struct ldb_request *req, struct ldb_dn *dn)
{
	struct dsdb_control_current_partition *partition;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);

	/* Skip the lot if 'data' isn't here yet (initialistion) */
	if (!data) {
		return module;
	}

	partition = find_partition(data, dn);
	if (!partition) {
		return module;
	}

	return make_module_for_next_request(req, module->ldb, partition->module);
};

/*
  fire the caller's callback for every entry, but only send 'done' once.
*/
static int partition_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct partition_context *ac;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "partition_search_callback: NULL Context or Result in 'search' callback");
		goto error;
	}

	ac = talloc_get_type(context, struct partition_context);

	if (ares->type == LDB_REPLY_ENTRY) {
		return ac->orig_req->callback(ldb, ac->orig_req->context, ares);
	} else {
		ac->finished_requests++;
		if (ac->finished_requests == ac->num_requests) {
			return ac->orig_req->callback(ldb, ac->orig_req->context, ares);
		} else {
			talloc_free(ares);
			return LDB_SUCCESS;
		}
	}
error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}

/*
  only fire the 'last' callback, and only for START-TLS for now 
*/
static int partition_other_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct partition_context *ac;

	if (!context) {
		ldb_set_errstring(ldb, "partition_other_callback: NULL Context in 'other' callback");
		goto error;
	}

	ac = talloc_get_type(context, struct partition_context);

	if (!ac->orig_req->callback) {
		talloc_free(ares);
		return LDB_SUCCESS;
	}

	if (!ares 
	    || (ares->type == LDB_REPLY_EXTENDED 
		&& strcmp(ares->response->oid, LDB_EXTENDED_START_TLS_OID))) {
		ac->finished_requests++;
		if (ac->finished_requests == ac->num_requests) {
			return ac->orig_req->callback(ldb, ac->orig_req->context, ares);
		}
		talloc_free(ares);
		return LDB_SUCCESS;
	}
	ldb_set_errstring(ldb, "partition_other_callback: Unknown reply type, only supports START_TLS");
error:
	talloc_free(ares);
	return LDB_ERR_OPERATIONS_ERROR;
}


static int partition_send_request(struct partition_context *ac, struct ldb_control *remove_control, 
				  struct dsdb_control_current_partition *partition)
{
	int ret;
	struct ldb_module *backend;
	struct ldb_request *req;
	struct ldb_control **saved_controls;

	if (partition) {
		backend = make_module_for_next_request(ac, ac->module->ldb, partition->module);
	} else {
		backend = ac->module;
	}

	ac->down_req = talloc_realloc(ac, ac->down_req, 
					struct ldb_request *, ac->num_requests + 1);
	if (!ac->down_req) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	req = ac->down_req[ac->num_requests] = talloc(ac, struct ldb_request);
	if (req == NULL) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	*req = *ac->orig_req; /* copy the request */

	if (req->controls) {
		req->controls
			= talloc_memdup(req,
					ac->orig_req->controls, talloc_get_size(ac->orig_req->controls));
		if (req->controls == NULL) {
			ldb_oom(ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	if (req->operation == LDB_SEARCH) {
		/* If the search is for 'more' than this partition,
		 * then change the basedn, so a remote LDAP server
		 * doesn't object */
		if (partition) {
			if (ldb_dn_compare_base(partition->dn, req->op.search.base) != 0) {
				req->op.search.base = partition->dn;
			}
		} else {
			req->op.search.base = NULL;
		}
		req->callback = partition_search_callback;
		req->context = ac;
	} else {
		req->callback = partition_other_callback;
		req->context = ac;
	}

	/* Remove a control, so we don't confuse a backend server */
	if (remove_control && !save_controls(remove_control, req, &saved_controls)) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	if (partition) {
		ret = ldb_request_add_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID, false, partition);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* Spray off search requests to all backends */
	ret = ldb_next_request(backend, req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->num_requests++;
	return LDB_SUCCESS;
}

/* Send a request down to all the partitions */
static int partition_send_all(struct ldb_module *module, 
			      struct partition_context *ac, 
			      struct ldb_control *remove_control, 
			      struct ldb_request *req) 
{
	int i;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	int ret = partition_send_request(ac, remove_control, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	for (i=0; data && data->partitions && data->partitions[i]; i++) {
		ret = partition_send_request(ac, remove_control, data->partitions[i]);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	return LDB_SUCCESS;
}

/* Figure out which backend a request needs to be aimed at.  Some
 * requests must be replicated to all backends */
static int partition_replicate(struct ldb_module *module, struct ldb_request *req, struct ldb_dn *dn) 
{
	unsigned i;
	int ret;
	struct dsdb_control_current_partition *partition;
	struct ldb_module *backend;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);
	
	if (req->operation != LDB_SEARCH) {
		/* Is this a special DN, we need to replicate to every backend? */
		for (i=0; data->replicate && data->replicate[i]; i++) {
			if (ldb_dn_compare(data->replicate[i], 
					   dn) == 0) {
				struct partition_context *ac;
				
				ac = partition_init_handle(req, module);
				if (!ac) {
					return LDB_ERR_OPERATIONS_ERROR;
				}
				
				return partition_send_all(module, ac, NULL, req);
			}
		}
	}

	/* Otherwise, we need to find the partition to fire it to */

	/* Find partition */
	partition = find_partition(data, dn);
	if (!partition) {
		/*
		 * if we haven't found a matching partition
		 * pass the request to the main ldb
		 *
		 * TODO: we should maybe return an error here
		 *       if it's not a special dn
		 */
		return ldb_next_request(module, req);
	}

	backend = make_module_for_next_request(req, module->ldb, partition->module);
	if (!backend) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_request_add_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID, false, partition);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* issue request */
	return ldb_next_request(backend, req);
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
	struct ldb_control *search_control = ldb_request_get_control(req, LDB_CONTROL_SEARCH_OPTIONS_OID);
	
	struct ldb_search_options_control *search_options = NULL;
	if (search_control) {
		search_options = talloc_get_type(search_control->data, struct ldb_search_options_control);
	}

	if (search_options && (search_options->search_options & LDB_SEARCH_OPTION_PHANTOM_ROOT)) {
		int ret, i;
		struct partition_context *ac;
		struct ldb_control *remove_control = NULL;
		if ((search_options->search_options & ~LDB_SEARCH_OPTION_PHANTOM_ROOT) == 0) {
			/* We have processed this flag, so we are done with this control now */
			remove_control = search_control;
		}
		ac = partition_init_handle(req, module);
		if (!ac) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* Search from the base DN */
		if (!req->op.search.base || ldb_dn_is_null(req->op.search.base)) {
			return partition_send_all(module, ac, remove_control, req);
		}
		for (i=0; data && data->partitions && data->partitions[i]; i++) {
			/* Find all partitions under the search base */
			if (ldb_dn_compare_base(req->op.search.base, data->partitions[i]->dn) == 0) {
				ret = partition_send_request(ac, remove_control, data->partitions[i]);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
		}

		/* Perhaps we didn't match any partitions.  Try the main partition, only */
		if (ac->num_requests == 0) {
			talloc_free(ac);
			return ldb_next_request(module, req);
		}
		
		return LDB_SUCCESS;
	} else {
		/* Handle this like all other requests */
		return partition_replicate(module, req, req->op.search.base);
	}
}

/* add */
static int partition_add(struct ldb_module *module, struct ldb_request *req)
{
	return partition_replicate(module, req, req->op.add.message->dn);
}

/* modify */
static int partition_modify(struct ldb_module *module, struct ldb_request *req)
{
	return partition_replicate(module, req, req->op.mod.message->dn);
}

/* delete */
static int partition_delete(struct ldb_module *module, struct ldb_request *req)
{
	return partition_replicate(module, req, req->op.del.dn);
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

	return partition_replicate(module, req, req->op.rename.olddn);
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
	uint64_t timestamp_sequence = 0;
	uint64_t timestamp = 0;
	struct partition_private_data *data = talloc_get_type(module->private_data, 
							      struct partition_private_data);

	switch (req->op.seq_num.type) {
	case LDB_SEQ_NEXT:
	case LDB_SEQ_HIGHEST_SEQ:
	       	ret = ldb_next_request(module, req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		if (req->op.seq_num.flags & LDB_SEQ_TIMESTAMP_SEQUENCE) {
			timestamp_sequence = req->op.seq_num.seq_num;
		} else {
			seq_number = seq_number + req->op.seq_num.seq_num;
		}

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
			if (req->op.seq_num.flags & LDB_SEQ_TIMESTAMP_SEQUENCE) {
				timestamp_sequence = MAX(timestamp_sequence, req->op.seq_num.seq_num);
			} else {
				seq_number = seq_number + req->op.seq_num.seq_num;
			}
		}
		/* fall though */
	case LDB_SEQ_HIGHEST_TIMESTAMP:
	{
		struct ldb_request *date_req = talloc(req, struct ldb_request);
		if (!date_req) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		*date_req = *req;
		date_req->op.seq_num.flags = LDB_SEQ_HIGHEST_TIMESTAMP;

		ret = ldb_next_request(module, date_req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		timestamp = date_req->op.seq_num.seq_num;
		
		/* Look at base DN */
		/* Figure out which partition it is under */
		/* Skip the lot if 'data' isn't here yet (initialistion) */
		for (i=0; data && data->partitions && data->partitions[i]; i++) {
			struct ldb_module *next = make_module_for_next_request(req, module->ldb, data->partitions[i]->module);
			
			ret = ldb_next_request(next, date_req);
			talloc_free(next);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			timestamp = MAX(timestamp, date_req->op.seq_num.seq_num);
		}
		break;
	}
	}

	switch (req->op.seq_num.flags) {
	case LDB_SEQ_NEXT:
	case LDB_SEQ_HIGHEST_SEQ:
		
		req->op.seq_num.flags = 0;

		/* Has someone above set a timebase sequence? */
		if (timestamp_sequence) {
			req->op.seq_num.seq_num = (((unsigned long long)timestamp << 24) | (seq_number & 0xFFFFFF));
		} else {
			req->op.seq_num.seq_num = seq_number;
		}

		if (timestamp_sequence > req->op.seq_num.seq_num) {
			req->op.seq_num.seq_num = timestamp_sequence;
			req->op.seq_num.flags |= LDB_SEQ_TIMESTAMP_SEQUENCE;
		}

		req->op.seq_num.flags |= LDB_SEQ_GLOBAL_SEQUENCE;
		break;
	case LDB_SEQ_HIGHEST_TIMESTAMP:
		req->op.seq_num.seq_num = timestamp;
		break;
	}

	switch (req->op.seq_num.flags) {
	case LDB_SEQ_NEXT:
		req->op.seq_num.seq_num++;
	}
	return LDB_SUCCESS;
}

static int partition_extended_replicated_objects(struct ldb_module *module, struct ldb_request *req)
{
	struct dsdb_extended_replicated_objects *ext;

	ext = talloc_get_type(req->op.extended.data, struct dsdb_extended_replicated_objects);
	if (!ext) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "partition_extended_replicated_objects: invalid extended data\n");
		return LDB_ERR_PROTOCOL_ERROR;
	}

	if (ext->version != DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "partition_extended_replicated_objects: extended data invalid version [%u != %u]\n",
			  ext->version, DSDB_EXTENDED_REPLICATED_OBJECTS_VERSION);
		return LDB_ERR_PROTOCOL_ERROR;
	}

	return partition_replicate(module, req, ext->partition_dn);
}

/* extended */
static int partition_extended(struct ldb_module *module, struct ldb_request *req)
{
	struct partition_context *ac;

	if (strcmp(req->op.extended.oid, DSDB_EXTENDED_REPLICATED_OBJECTS_OID) == 0) {
		return partition_extended_replicated_objects(module, req);
	}

	/* 
	 * as the extended operation has no dn
	 * we need to send it to all partitions
	 */

	ac = partition_init_handle(req, module);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
			
	return partition_send_all(module, ac, NULL, req);
}

static int sort_compare(void *void1,
			void *void2, void *opaque)
{
	struct dsdb_control_current_partition **pp1 = void1;
	struct dsdb_control_current_partition **pp2 = void2;
	struct dsdb_control_current_partition *partition1 = talloc_get_type(*pp1,
							    struct dsdb_control_current_partition);
	struct dsdb_control_current_partition *partition2 = talloc_get_type(*pp2,
							    struct dsdb_control_current_partition);

	return ldb_dn_compare(partition1->dn, partition2->dn);
}

static const char *relative_path(struct ldb_module *module, 
				 TALLOC_CTX *mem_ctx, 
				 const char *name) 
{
	const char *base_url = ldb_get_opaque(module->ldb, "ldb_url");
	char *path, *p, *full_name;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}
	path = talloc_strdup(mem_ctx, base_url);
	if (path == NULL) {
		return NULL;
	}
	if ( (p = strrchr(path, '/')) != NULL) {
		p[0] = '\0';
	} else {
		talloc_free(path);
		return NULL;
	}
	full_name = talloc_asprintf(mem_ctx, "%s/%s", path, name);
	talloc_free(path);
	return full_name;
}

static int partition_init(struct ldb_module *module)
{
	int ret, i;
	TALLOC_CTX *mem_ctx = talloc_new(module);
	static const char *attrs[] = { "partition", "replicateEntries", "modules", NULL };
	struct ldb_result *res;
	struct ldb_message *msg;
	struct ldb_message_element *partition_attributes;
	struct ldb_message_element *replicate_attributes;
	struct ldb_message_element *modules_attributes;

	struct partition_private_data *data;

	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data = talloc(mem_ctx, struct partition_private_data);
	if (data == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_search(module->ldb, ldb_dn_new(mem_ctx, module->ldb, "@PARTITION"),
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
		ldb_set_errstring(module->ldb, "partition_init: no partitions specified");
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	data->partitions = talloc_array(data, struct dsdb_control_current_partition *, partition_attributes->num_values + 1);
	if (!data->partitions) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	for (i=0; i < partition_attributes->num_values; i++) {
		char *base = talloc_strdup(data->partitions, (char *)partition_attributes->values[i].data);
		char *p = strchr(base, ':');
		if (!p) {
			ldb_asprintf_errstring(module->ldb, 
						"partition_init: "
						"invalid form for partition record (missing ':'): %s", base);
			talloc_free(mem_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		p[0] = '\0';
		p++;
		if (!p[0]) {
			ldb_asprintf_errstring(module->ldb, 
						"partition_init: "
						"invalid form for partition record (missing backend database): %s", base);
			talloc_free(mem_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		data->partitions[i] = talloc(data->partitions, struct dsdb_control_current_partition);
		if (!data->partitions[i]) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		data->partitions[i]->version = DSDB_CONTROL_CURRENT_PARTITION_VERSION;

		data->partitions[i]->dn = ldb_dn_new(data->partitions[i], module->ldb, base);
		if (!data->partitions[i]->dn) {
			ldb_asprintf_errstring(module->ldb, 
						"partition_init: invalid DN in partition record: %s", base);
			talloc_free(mem_ctx);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		data->partitions[i]->backend = relative_path(module, 
							     data->partitions[i], 
							     p);
		ret = ldb_connect_backend(module->ldb, data->partitions[i]->backend, NULL, &data->partitions[i]->module);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
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
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		req->operation = LDB_REQ_REGISTER_PARTITION;
		req->op.reg_partition.dn = data->partitions[i]->dn;
		
		ret = ldb_request(module->ldb, req);
		if (ret != LDB_SUCCESS) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "partition: Unable to register partition with rootdse!\n");
			talloc_free(mem_ctx);
			return LDB_ERR_OTHER;
		}
		talloc_free(req);
	}

	replicate_attributes = ldb_msg_find_element(msg, "replicateEntries");
	if (!replicate_attributes) {
		data->replicate = NULL;
	} else {
		data->replicate = talloc_array(data, struct ldb_dn *, replicate_attributes->num_values + 1);
		if (!data->replicate) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		for (i=0; i < replicate_attributes->num_values; i++) {
			data->replicate[i] = ldb_dn_new(data->replicate, module->ldb, (const char *)replicate_attributes->values[i].data);
			if (!ldb_dn_validate(data->replicate[i])) {
				ldb_asprintf_errstring(module->ldb, 
							"partition_init: "
							"invalid DN in partition replicate record: %s", 
							replicate_attributes->values[i].data);
				talloc_free(mem_ctx);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		}
		data->replicate[i] = NULL;
	}

	/* Make the private data available to any searches the modules may trigger in initialisation */
	module->private_data = data;
	talloc_steal(module, data);
	
	modules_attributes = ldb_msg_find_element(msg, "modules");
	if (modules_attributes) {
		for (i=0; i < modules_attributes->num_values; i++) {
			struct ldb_dn *base_dn;
			int partition_idx;
			struct dsdb_control_current_partition *partition = NULL;
			const char **modules = NULL;

			char *base = talloc_strdup(data->partitions, (char *)modules_attributes->values[i].data);
			char *p = strchr(base, ':');
			if (!p) {
				ldb_asprintf_errstring(module->ldb, 
							"partition_init: "
							"invalid form for partition module record (missing ':'): %s", base);
				talloc_free(mem_ctx);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
			p[0] = '\0';
			p++;
			if (!p[0]) {
				ldb_asprintf_errstring(module->ldb, 
							"partition_init: "
							"invalid form for partition module record (missing backend database): %s", base);
				talloc_free(mem_ctx);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}

			modules = ldb_modules_list_from_string(module->ldb, mem_ctx,
							       p);
			
			base_dn = ldb_dn_new(mem_ctx, module->ldb, base);
			if (!ldb_dn_validate(base_dn)) {
				talloc_free(mem_ctx);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			
			for (partition_idx = 0; data->partitions[partition_idx]; partition_idx++) {
				if (ldb_dn_compare(data->partitions[partition_idx]->dn, base_dn) == 0) {
					partition = data->partitions[partition_idx];
					break;
				}
			}
			
			if (!partition) {
				ldb_asprintf_errstring(module->ldb, 
							"partition_init: "
							"invalid form for partition module record (no such partition): %s", base);
				talloc_free(mem_ctx);
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
			
			ret = ldb_load_modules_list(module->ldb, modules, partition->module, &partition->module);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(module->ldb, 
						       "partition_init: "
						       "loading backend for %s failed: %s", 
						       base, ldb_errstring(module->ldb));
				talloc_free(mem_ctx);
				return ret;
			}
			ret = ldb_init_module_chain(module->ldb, partition->module);
			if (ret != LDB_SUCCESS) {
				ldb_asprintf_errstring(module->ldb, 
						       "partition_init: "
						       "initialising backend for %s failed: %s", 
						       base, ldb_errstring(module->ldb));
				talloc_free(mem_ctx);
				return ret;
			}
		}
	}

	talloc_free(mem_ctx);
	return ldb_next_init(module);
}

static int partition_wait_none(struct ldb_handle *handle) {
	struct partition_context *ac;
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

	ac = talloc_get_type(handle->private_data, struct partition_context);

	for (i=0; i < ac->num_requests; i++) {
		ret = ldb_wait(ac->down_req[i]->handle, LDB_WAIT_NONE);
		
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req[i]->handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req[i]->handle->status;
			goto done;
		}
		
		if (ac->down_req[i]->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}
	}

	ret = LDB_SUCCESS;

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}


static int partition_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = partition_wait_none(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int partition_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return partition_wait_all(handle);
	} else {
		return partition_wait_none(handle);
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
	.extended          = partition_extended,
	.sequence_number   = partition_sequence_number,
	.start_transaction = partition_start_trans,
	.end_transaction   = partition_end_trans,
	.del_transaction   = partition_del_trans,
	.wait              = partition_wait
};

int ldb_partition_init(void)
{
	return ldb_register_module(&partition_ops);
}
