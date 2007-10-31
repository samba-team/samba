/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb linked_attributes module
 *
 *  Description: Module to ensure linked attribute pairs remain in sync
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"

struct linked_attributes_context {
	struct ldb_module *module;
	struct ldb_handle *handle;
	struct ldb_request *orig_req;

	struct ldb_request **down_req;
	int num_requests;
	int finished_requests;
};

static struct linked_attributes_context *linked_attributes_init_handle(struct ldb_request *req, 
								 struct ldb_module *module)
{
	struct linked_attributes_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct linked_attributes_context);
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

/* add */
static int linked_attributes_add(struct ldb_module *module, struct ldb_request *req)
{
	int i, j, ret;
	struct linked_attributes_context *ac;

	const struct dsdb_schema *schema = dsdb_get_schema(module->ldb);
	if (!schema) {
		/* without schema, this doesn't make any sense */
		return ldb_next_request(module, req);
	}

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}


	ac = linked_attributes_init_handle(req, module);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* prepare the first operation */
	ac->down_req = talloc_realloc(ac, ac->down_req, 
				      struct ldb_request *, 1);
	if (!ac->down_req) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ac->down_req[0] = talloc(ac->down_req, struct ldb_request);
	if (!ac->down_req[0]) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*(ac->down_req[0]) = *req; /* copy the request */
	
	ac->num_requests++;
	
	/* Run the original request */
	ret = ldb_next_request(module, req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	for (i=0; i < req->op.add.message->num_elements; i++) {
		const struct dsdb_attribute *target_attr;
		const struct ldb_message_element *el = &req->op.add.message->elements[i];
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(schema, el->name);
		if (!schema_attr) {
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s is not a valid attribute in schema", req->op.add.message->elements[i].name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;			
		}
		/* We have a valid attribute, not find out if it is linked */
		if (schema_attr->linkID == 0) {
			continue;
		}
		
		if ((schema_attr->linkID & 1) == 1) {
			/* Odd is for the target.  Illigal to modify */
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s must not be modified directly, it is a linked attribute", req->op.add.message->elements[i].name);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		
		/* Even link IDs are for the originating attribute */
		
		/* Now find the target attribute */
		target_attr = dsdb_attribute_by_linkID(schema, schema_attr->linkID + 1);
		if (!target_attr) {
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s does not have valid link target", req->op.add.message->elements[i].name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;			
		}

		/* Prepare the modify (add element) on the targets */

		/* For each value being added, we need to setup the modify */
		for (j=0; j < el->num_values; j++) {
			struct ldb_request *new_req;
			/* Create the modify request */
			struct ldb_message *new_msg = ldb_msg_new(ac->down_req);
			if (!new_msg) {
				ldb_oom(module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			new_msg->dn = ldb_dn_new(new_msg, module->ldb, (char *)el->values[j].data);
			if (!new_msg->dn) {
				ldb_asprintf_errstring(module->ldb, 
					       "attribute %s value %s was not a valid DN", req->op.add.message->elements[i].name,
						       el->values[j].data);
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}

			ret = ldb_msg_add_empty(new_msg, target_attr->lDAPDisplayName, 
						LDB_FLAG_MOD_ADD, NULL);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			ret = ldb_msg_add_string(new_msg, target_attr->lDAPDisplayName, 
						 ldb_dn_get_linearized(ac->orig_req->op.add.message->dn));
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			ret = ldb_build_mod_req(&new_req, module->ldb, ac->down_req,
						new_msg,
						NULL,
						NULL,
						NULL);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			talloc_steal(new_req, new_msg);
			
			ldb_set_timeout_from_prev_req(module->ldb, req, new_req);
			
			/* Now add it to the list */
			ac->down_req = talloc_realloc(ac, ac->down_req, 
						      struct ldb_request *, ac->num_requests + 1);
			if (!ac->down_req) {
				ldb_oom(ac->module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			ac->down_req[ac->num_requests] = new_req;
			ac->num_requests++;

			/* Run the new request */
			ret = ldb_next_request(module, new_req);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}
	return ret;
}

/* modify */
static int linked_attributes_modify(struct ldb_module *module, struct ldb_request *req)
{
	/* Look over list of modifications */
	/* Find if any are for linked attributes */
	/* Determine the effect of the modification */
	/* Apply the modify to the linked entry */

	int i, j, ret;
	struct linked_attributes_context *ac;

	const struct dsdb_schema *schema = dsdb_get_schema(module->ldb);
	if (!schema) {
		/* without schema, this doesn't make any sense */
		return ldb_next_request(module, req);
	}

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}


	ac = linked_attributes_init_handle(req, module);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* prepare the first operation */
	ac->down_req = talloc_realloc(ac, ac->down_req, 
				      struct ldb_request *, 1);
	if (!ac->down_req) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ac->down_req[0] = talloc(ac->down_req, struct ldb_request);
	if (!ac->down_req[0]) {
		ldb_oom(ac->module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	*(ac->down_req[0]) = *req; /* copy the request */
	
	ac->num_requests++;
	
	/* Run the original request */
	ret = ldb_next_request(module, req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	for (i=0; i < req->op.mod.message->num_elements; i++) {
		const struct dsdb_attribute *target_attr;
		const struct ldb_message_element *el = &req->op.mod.message->elements[i];
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(schema, el->name);
		if (!schema_attr) {
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s is not a valid attribute in schema", req->op.mod.message->elements[i].name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;			
		}
		/* We have a valid attribute, not find out if it is linked */
		if (schema_attr->linkID == 0) {
			continue;
		}
		
		if ((schema_attr->linkID & 1) == 1) {
			/* Odd is for the target.  Illigal to modify */
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s must not be modified directly, it is a linked attribute", req->op.mod.message->elements[i].name);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		
		/* Even link IDs are for the originating attribute */
		
		/* Now find the target attribute */
		target_attr = dsdb_attribute_by_linkID(schema, schema_attr->linkID + 1);
		if (!target_attr) {
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s does not have valid link target", req->op.mod.message->elements[i].name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;			
		}

		if ((el->flags & LDB_FLAG_MOD_MASK) == LDB_FLAG_MOD_REPLACE) {
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s may not be replaced, only added or deleted", req->op.mod.message->elements[i].name);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		/* Prepare the modify (mod element) on the targets */

		/* For each value being moded, we need to setup the modify */
		for (j=0; j < el->num_values; j++) {
			struct ldb_request *new_req;
			/* Create the modify request */
			struct ldb_message *new_msg = ldb_msg_new(ac->down_req);
			if (!new_msg) {
				ldb_oom(module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			new_msg->dn = ldb_dn_new(new_msg, module->ldb, (char *)el->values[j].data);
			if (!new_msg->dn) {
				ldb_asprintf_errstring(module->ldb, 
					       "attribute %s value %s was not a valid DN", req->op.mod.message->elements[i].name,
						       el->values[j].data);
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}

			ret = ldb_msg_add_empty(new_msg, target_attr->lDAPDisplayName, 
						el->flags & LDB_FLAG_MOD_MASK, NULL);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			ret = ldb_msg_add_string(new_msg, target_attr->lDAPDisplayName, 
						 ldb_dn_get_linearized(ac->orig_req->op.add.message->dn));
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			ret = ldb_build_mod_req(&new_req, module->ldb, ac->down_req,
						new_msg,
						NULL,
						NULL,
						NULL);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			talloc_steal(new_req, new_msg);
			
			ldb_set_timeout_from_prev_req(module->ldb, req, new_req);
			
			/* Now add it to the list */
			ac->down_req = talloc_realloc(ac, ac->down_req, 
						      struct ldb_request *, ac->num_requests + 1);
			if (!ac->down_req) {
				ldb_oom(ac->module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			ac->down_req[ac->num_requests] = new_req;
			ac->num_requests++;

			/* Run the new request */
			ret = ldb_next_request(module, new_req);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}
	return ret;
}

/* delete */
static int linked_attributes_delete(struct ldb_module *module, struct ldb_request *req)
{
	/* Look up list of linked attributes */
	/* Search to see if any linked attributes are in this entry */
	return ldb_next_request(module, req);
}

/* rename */
static int linked_attributes_rename(struct ldb_module *module, struct ldb_request *req)
{
	/* Look up list of linked attributes */
	/* Search to see if any linked attributes are in this entry */
	return ldb_next_request(module, req);
}

static int linked_attributes_wait_none(struct ldb_handle *handle) {
	struct linked_attributes_context *ac;
	int i, ret = LDB_ERR_OPERATIONS_ERROR;
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct linked_attributes_context);

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

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;

}

static int linked_attributes_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = linked_attributes_wait_none(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int linked_attributes_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return linked_attributes_wait_all(handle);
	} else {
		return linked_attributes_wait_none(handle);
	}
}

static const struct ldb_module_ops linked_attributes_ops = {
	.name		   = "linked_attributes",
	.add               = linked_attributes_add,
	.modify            = linked_attributes_modify,
	.del               = linked_attributes_delete,
	.rename            = linked_attributes_rename,
	.wait              = linked_attributes_wait,
};

int ldb_linked_attributes_init(void)
{
	return ldb_register_module(&linked_attributes_ops);
}
