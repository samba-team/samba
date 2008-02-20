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
	enum la_step {LA_SEARCH, LA_DO_OPS, LA_DO_ORIG} step;
	struct ldb_module *module;
	struct ldb_handle *handle;
	struct ldb_request *orig_req;

	struct ldb_request *search_req;
	struct ldb_request **down_req;
	struct ldb_request *orig_down_req;

	int num_requests;
	int finished_requests;

	const char **linked_attrs;
};

struct replace_context {
	struct linked_attributes_context *ac;
	struct ldb_message_element *el;
};

static int linked_attributes_rename_del_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares);

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
	
	ac->orig_down_req = talloc(ac, struct ldb_request);
	if (!ac->orig_down_req) {
		ldb_oom(ac->module->ldb);
		return NULL;
	}

	*ac->orig_down_req = *req;

	req->handle = h;

	return ac;
}

/* Common routine to handle reading the attributes and creating a
 * series of modify requests */

static int setup_modifies(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, 
			  struct linked_attributes_context *ac,
			  const struct ldb_message *msg, 
			  struct ldb_dn *olddn, struct ldb_dn *newdn) 
{
	int i, j, ret = LDB_SUCCESS;
	const struct dsdb_schema *schema = dsdb_get_schema(ldb);
	/* Look up each of the returned attributes */
	/* Find their schema */
	/* And it is an actual entry: now create a series of modify requests */
	for (i=0; i < msg->num_elements; i++) {
		int otherid;
		const struct dsdb_attribute *target_attr;
		const struct ldb_message_element *el = &msg->elements[i];
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(schema, el->name);
		if (!schema_attr) {
			ldb_asprintf_errstring(ldb, 
					       "attribute %s is not a valid attribute in schema", el->name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;			
		}
		/* We have a valid attribute, but if it's not linked they maybe we just got an extra return on our search... */
		if (schema_attr->linkID == 0) {
			continue;
		}
		
		/* Depending on which direction this link is in, we need to find it's partner */
		if ((schema_attr->linkID & 1) == 1) {
			otherid = schema_attr->linkID - 1;
		} else {
			otherid = schema_attr->linkID + 1;
		}
		
		/* Now find the target attribute */
		target_attr = dsdb_attribute_by_linkID(schema, otherid);
		if (!target_attr) {
			ldb_asprintf_errstring(ldb, 
					       "attribute %s does not have valid link target", el->name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;			
		}
		
		/* For each value being moded, we need to setup the modify */
		for (j=0; j < el->num_values; j++) {
			struct ldb_message_element *ret_el;
			struct ldb_request *new_req;
			struct ldb_message *new_msg;

			/* Create a spot in the list for the requests */
			ac->down_req = talloc_realloc(ac, ac->down_req, 
						      struct ldb_request *, ac->num_requests + 1);
			if (!ac->down_req) {
				ldb_oom(ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			/* Create the modify request */
			new_msg = ldb_msg_new(ac->down_req);
			if (!new_msg) {
				ldb_oom(ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			new_msg->dn = ldb_dn_new(new_msg, ldb, (char *)el->values[j].data);
			if (!new_msg->dn) {
				ldb_asprintf_errstring(ldb, 
						       "attribute %s value %s was not a valid DN", msg->elements[i].name,
						       el->values[j].data);
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}
			
			if (olddn) {
				ret = ldb_msg_add_empty(new_msg, target_attr->lDAPDisplayName, 
							LDB_FLAG_MOD_DELETE, &ret_el);
				if (ret != LDB_SUCCESS) {
					return ret;
				}	
				ret_el->values = talloc_array(new_msg, struct ldb_val, 1);
				if (!ret_el->values) {
					ldb_oom(ldb);
					return LDB_ERR_OPERATIONS_ERROR;
				}
				ret_el->values[0] = data_blob_string_const(ldb_dn_get_linearized(olddn));
				ret_el->num_values = 1;
			}
			
			if (newdn) {
				ret = ldb_msg_add_empty(new_msg, target_attr->lDAPDisplayName, 
							LDB_FLAG_MOD_ADD, &ret_el);
				if (ret != LDB_SUCCESS) {
					return ret;
				}	
				ret_el->values = talloc_array(new_msg, struct ldb_val, 1);
				if (!ret_el->values) {
					ldb_oom(ldb);
					return LDB_ERR_OPERATIONS_ERROR;
				}
				ret_el->values[0] = data_blob_string_const(ldb_dn_get_linearized(newdn));
				ret_el->num_values = 1;
			}

			ret = ldb_build_mod_req(&new_req, ldb, ac->down_req,
						new_msg,
						NULL,
						NULL,
						NULL);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			talloc_steal(new_req, new_msg);
			
			ldb_set_timeout_from_prev_req(ldb, ac->orig_req, new_req);
			
			ac->down_req[ac->num_requests] = new_req;
			ac->num_requests++;
			

			/* Run the new request */
			ret = ldb_next_request(ac->module, new_req);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}
	return ret;
}

/* add */
static int linked_attributes_add(struct ldb_module *module, struct ldb_request *req)
{
	int i;
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
	
	ac->step = LA_DO_OPS;
	
	/* Need to ensure we only have forward links being specified */
	for (i=0; i < req->op.add.message->num_elements; i++) {
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
	}

	/* Now call the common routine to setup the modifies across all the attributes */
	return setup_modifies(module->ldb, ac, ac, req->op.add.message, NULL, req->op.add.message->dn);
}

struct merge {
	struct ldb_dn *dn;
	bool add;
	bool ignore;
};

static int merge_cmp(struct merge *merge1, struct merge *merge2) {
	int ret;
	ret = ldb_dn_compare(merge1->dn, merge2->dn);
	if (ret == 0) {
		if (merge1->add == merge2->add) {
			return 0;
		}
		if (merge1->add == true) {
			return 1;
		}
		return -1;
	}
	return ret;
}

static int linked_attributes_mod_replace_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares) 
{
	struct replace_context *ac2 = talloc_get_type(context, struct replace_context);
	struct linked_attributes_context *ac = ac2->ac;
    
	/* OK, we have one search result here: */

	/* Only entries are interesting, and we only want the olddn */
	if (ares->type == LDB_REPLY_ENTRY
	    && ldb_dn_compare(ares->message->dn, ac->orig_req->op.mod.message->dn) == 0) {
		/* only bother at all if there were some linked attributes found */
		struct ldb_message_element *search_el
			= ldb_msg_find_element(ares->message,
					       ac2->el->name);
		
		/* See if this element already exists */
		if (search_el) {

			struct merge *merged_list = NULL;

			int ret, size = 0, i;
			struct ldb_message *msg = ldb_msg_new(ac);
			if (!msg) {
				ldb_oom(ac->module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			/* Add all the existing elements, marking as 'proposed for delete' by setting .add = false */
			for (i=0; i < search_el->num_values; i++) {
				merged_list = talloc_realloc(ares, merged_list, struct merge, size + 1);
				merged_list[size].dn = ldb_dn_new(merged_list, ldb, (char *)search_el->values[i].data);
				merged_list[size].add = false;
				merged_list[size].ignore = false;
				size++;
			}

			/* Add all the new replacement elements, marking as 'proposed for add' by setting .add = true */
			for (i=0; i < ac2->el->num_values; i++) {
				merged_list = talloc_realloc(ares, merged_list, struct merge, size + 1);
				merged_list[size].dn = ldb_dn_new(merged_list, ldb, (char *)ac2->el->values[i].data);
				merged_list[size].add = true;
				merged_list[size].ignore = false;
				size++;
			}

			/* Sort the list, so we can pick out an add and delete for the same DN, and eliminate them */
			qsort(merged_list, size,
			      sizeof(*merged_list),
			      (comparison_fn_t)merge_cmp);

			/* Now things are sorted, it is trivial to mark pairs of DNs as 'ignore' */
			for (i=0; i + 1 < size; i++) {
				if (ldb_dn_compare(merged_list[i].dn, 
						   merged_list[i+1].dn) == 0 
				    /* Fortunetly the sort also sorts 'add == false' first */
				    && merged_list[i].add == false
				    && merged_list[i+1].add == true) {

					/* Mark as ignore, so we include neither in the actual operations */
					merged_list[i].ignore = true;
					merged_list[i+1].ignore = true;
				}
			}

			/* Arrange to delete anything the search found that we don't re-add */
			for (i=0; i < size; i++) {
				if (merged_list[i].ignore == false
				    && merged_list[i].add == false) {
					ldb_msg_add_steal_string(msg, search_el->name, 
								 ldb_dn_get_linearized(merged_list[i].dn));
				}
			}

			/* The DN to set on the linked attributes is the original DN of the modify message */
			msg->dn = ac->orig_req->op.mod.message->dn;
			
			ret = setup_modifies(ac->module->ldb, ac2, ac, msg, ares->message->dn, NULL);
			if (ret != LDB_SUCCESS) {
				return ret;
			}

			/* Now add links for all the actually new elements */
			for (i=0; i < size; i++) {
				if (merged_list[i].ignore == false && merged_list[i].add == true) {
					ldb_msg_add_steal_string(msg, search_el->name, 
								 ldb_dn_get_linearized(merged_list[i].dn));
				}
			}

			ret = setup_modifies(ac->module->ldb, ac2, ac, msg, NULL, ares->message->dn);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			talloc_free(merged_list);

		} else {
			/* Looks like it doesn't exist, process like an 'add' */
			struct ldb_message *msg = ldb_msg_new(ac);
			if (!msg) {
				ldb_oom(ac->module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			msg->num_elements = 1;
			msg->elements = ac2->el;
			msg->dn = ac->orig_req->op.mod.message->dn;

			return setup_modifies(ac->module->ldb, ac2, ac, msg, NULL, ac->orig_req->op.mod.message->dn);
		}
		talloc_free(ares);
		return LDB_SUCCESS;
	} else if (ares->type == LDB_REPLY_ENTRY) {
		/* Guh?  We only asked for this DN */
		return LDB_ERR_OPERATIONS_ERROR;

	} else {
		talloc_free(ares);
		return LDB_SUCCESS;
	}
	
	
}
/* modify */
static int linked_attributes_modify(struct ldb_module *module, struct ldb_request *req)
{
	/* Look over list of modifications */
	/* Find if any are for linked attributes */
	/* Determine the effect of the modification */
	/* Apply the modify to the linked entry */

	int i, j;
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
	ac->step = LA_DO_OPS;

	for (i=0; i < req->op.mod.message->num_elements; i++) {
		int ret;
		struct ldb_request *new_req;
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

		/* Replace with new set of values */
		if (((el->flags & LDB_FLAG_MOD_MASK) == LDB_FLAG_MOD_REPLACE)
		    && el->num_values > 0) {
			struct replace_context *ac2 = talloc(ac, struct replace_context);
			const char **attrs = talloc_array(ac, const char *, 2);
			if (!attrs || !ac2) {
				ldb_oom(ac->module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			attrs[0] = el->name;
			attrs[1] = NULL;

			ac2->ac = ac;
			ac2->el = el;

			/* We need to setup a search, compare with the list, and then setup add/del as required */
			
			/* The callback does all the hard work here */
			ret = ldb_build_search_req(&new_req, module->ldb, req,
						   req->op.mod.message->dn, 
						   LDB_SCOPE_BASE,
						   "(objectClass=*)",
						   attrs,
						   NULL, 
						   ac2, 
						   linked_attributes_mod_replace_search_callback);
			
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			talloc_steal(new_req, attrs);
			
			/* Create a spot in the list for the requests */
			ac->down_req = talloc_realloc(ac, ac->down_req, 
						      struct ldb_request *, ac->num_requests + 1);
			if (!ac->down_req) {
				ldb_oom(ac->module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			ac->down_req[ac->num_requests] = talloc_steal(ac->down_req, new_req);
			ac->num_requests++;

			ret = ldb_next_request(module, new_req);
			
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			continue;

			/* Delete all values case */
		} else if (((el->flags & LDB_FLAG_MOD_MASK) & (LDB_FLAG_MOD_DELETE|LDB_FLAG_MOD_REPLACE)) 
			   && el->num_values == 0) {
			const char **attrs = talloc_array(ac, const char *, 2);
			if (!attrs) {
				ldb_oom(ac->module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			attrs[0] = el->name;
			attrs[1] = NULL;

			/* We need to setup a search, and then setup del as required */
			
			/* The callback does all the hard work here, acting identically to if we had delted the whole entry */
			ret = ldb_build_search_req(&new_req, module->ldb, req,
						   req->op.mod.message->dn, 
						   LDB_SCOPE_BASE,
						   "(objectClass=*)",
						   attrs,
						   NULL, 
						   ac, 
						   linked_attributes_rename_del_search_callback);

			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			talloc_steal(new_req, attrs);
			
			/* Create a spot in the list for the requests */
			ac->down_req = talloc_realloc(ac, ac->down_req, 
						      struct ldb_request *, ac->num_requests + 1);
			if (!ac->down_req) {
				ldb_oom(ac->module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}

			ac->down_req[ac->num_requests] = talloc_steal(ac->down_req, new_req);
			ac->num_requests++;
			
			ret = ldb_next_request(module, new_req);
		
			if (ret != LDB_SUCCESS) {
				return ret;
			}
			
			continue;
		}

		/* Prepare the modify (mod element) on the targets, for a normal modify request */

		/* For each value being moded, we need to setup the modify */
		for (j=0; j < el->num_values; j++) {
			/* Create the modify request */
			struct ldb_message *new_msg = ldb_msg_new(ac);
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

			ret = ldb_build_mod_req(&new_req, module->ldb, ac,
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
			ac->down_req[ac->num_requests] = talloc_steal(ac->down_req, new_req);
			ac->num_requests++;

			/* Run the new request */
			ret = ldb_next_request(module, new_req);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}
	return LDB_SUCCESS;
}

static int linked_attributes_rename_del_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares) 
{
	struct linked_attributes_context *ac = talloc_get_type(context, struct linked_attributes_context);
	struct ldb_dn *olddn, *newdn;
    
	switch (ac->orig_req->operation) {
	case LDB_DELETE:
	{
		olddn = ac->orig_req->op.del.dn;
		newdn = NULL;
		break;
	} 
	/* This isn't the general modify case, just the modify when we are asked to delete all values */
	case LDB_MODIFY:
	{
		olddn = ac->orig_req->op.mod.message->dn;
		newdn = NULL;
		break;
	} 
	case LDB_RENAME:
	{
		olddn = ac->orig_req->op.rename.olddn;
		newdn = ac->orig_req->op.rename.newdn;
		break;
	}	
	default:
		return LDB_ERR_OPERATIONS_ERROR;
	}
	

	/* OK, we have one search result here: */

	/* Only entries are interesting, and we only want the olddn */
	if (ares->type == LDB_REPLY_ENTRY
	    && ldb_dn_compare(ares->message->dn, olddn) == 0) {
		/* only bother at all if there were some linked attributes found */
		if (ares->message->num_elements > 0) {
			return setup_modifies(ldb, ac, ac,
					      ares->message, olddn, newdn);
		}
		talloc_free(ares);
		return LDB_SUCCESS;
	} else if (ares->type == LDB_REPLY_ENTRY) {
		/* Guh?  We only asked for this DN */
		return LDB_ERR_OPERATIONS_ERROR;

	} else {
		talloc_free(ares);
		return LDB_SUCCESS;
	}
	
	
}
/* rename */
static int linked_attributes_rename(struct ldb_module *module, struct ldb_request *req)
{
	/* Look up list of linked attributes */
	const char **attrs;
	WERROR werr;
	int ret;
	struct linked_attributes_context *ac;
	struct ldb_request *new_req;
	const struct dsdb_schema *schema = dsdb_get_schema(module->ldb);
	if (!schema) {
		/* without schema, this doesn't make any sense */
		return ldb_next_request(module, req);
	}

	/* This gets complex:  We need to:
	   - Do a search for the entry 
	   - Wait for these result to appear
	   - In the callback for the result, issue a modify request based on the linked attributes found
	   - Wait for each modify result
	   - Regain our sainity 
	*/

	ac = linked_attributes_init_handle(req, module);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	werr = dsdb_linked_attribute_lDAPDisplayName_list(schema, ac, &attrs);
	if (!W_ERROR_IS_OK(werr)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	ret = ldb_build_search_req(&new_req, module->ldb, req,
				   req->op.rename.olddn, 
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs,
				   NULL, 
				   ac, 
				   linked_attributes_rename_del_search_callback);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(new_req, attrs);

	ac->search_req = new_req;
	ac->step = LA_SEARCH;
	return ldb_next_request(module, new_req);
}

/* delete */
static int linked_attributes_delete(struct ldb_module *module, struct ldb_request *req)
{
	/* Look up list of linked attributes */
	const char **attrs;
	WERROR werr;
	int ret;
	struct ldb_request *new_req;
	struct linked_attributes_context *ac;
	const struct dsdb_schema *schema = dsdb_get_schema(module->ldb);
	if (!schema) {
		/* without schema, this doesn't make any sense */
		return ldb_next_request(module, req);
	}

	/* This gets complex:  We need to:
	   - Do a search for the entry 
	   - Wait for these result to appear
	   - In the callback for the result, issue a modify request based on the linked attributes found
	   - Wait for each modify result
	   - Regain our sainity 
	*/

	ac = linked_attributes_init_handle(req, module);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	werr = dsdb_linked_attribute_lDAPDisplayName_list(schema, ac, &attrs);
	if (!W_ERROR_IS_OK(werr)) {
		return LDB_ERR_OPERATIONS_ERROR;
	};
	
	ret = ldb_build_search_req(&new_req, module->ldb, req,
				   req->op.del.dn, 
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs,
				   NULL, 
				   ac, 
				   linked_attributes_rename_del_search_callback);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(new_req, attrs);

	ac->search_req = new_req;
	ac->step = LA_SEARCH;
	return ldb_next_request(module, new_req);
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

	switch (ac->step) {
	case LA_SEARCH:
		ret = ldb_wait(ac->search_req->handle, LDB_WAIT_NONE);
		
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->search_req->handle->status;
			goto done;
		}
		
		if (ac->search_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}
		ac->step = LA_DO_OPS;
		return LDB_SUCCESS;

	case LA_DO_OPS:
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

		/* Now run the original request */
		ac->step = LA_DO_ORIG;
		return ldb_next_request(ac->module, ac->orig_down_req);

	case LA_DO_ORIG:
		ret = ldb_wait(ac->orig_down_req->handle, LDB_WAIT_NONE);
		
		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->orig_down_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->orig_down_req->handle->status;
			goto done;
		}
		
		if (ac->orig_down_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}
		ret = LDB_SUCCESS;
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

_PUBLIC_ const struct ldb_module_ops ldb_linked_attributes_module_ops = {
	.name		   = "linked_attributes",
	.add               = linked_attributes_add,
	.modify            = linked_attributes_modify,
	.del               = linked_attributes_delete,
	.rename            = linked_attributes_rename,
	.wait              = linked_attributes_wait,
};
