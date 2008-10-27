/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2007
   Copyright (C) Simo Sorce <idra@samba.org> 2008

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

struct la_op_store {
	struct la_op_store *next;
	enum la_op {LA_OP_ADD, LA_OP_DEL} op;
	struct ldb_dn *dn;
	char *name;
	char *value;
};

struct replace_context {
	struct la_context *ac;
	unsigned int num_elements;
	struct ldb_message_element *el;
};

struct la_context {
	const struct dsdb_schema *schema;
	struct ldb_module *module;
	struct ldb_request *req;

	struct replace_context *rc;
	struct la_op_store *ops;
	struct la_op_store *cur;
};

static struct la_context *linked_attributes_init(struct ldb_module *module,
						 struct ldb_request *req)
{
	struct la_context *ac;

	ac = talloc_zero(req, struct la_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	ac->schema = dsdb_get_schema(module->ldb);
	ac->module = module;
	ac->req = req;

	return ac;
}

/* Common routine to handle reading the attributes and creating a
 * series of modify requests */
static int la_store_op(struct la_context *ac,
		       enum la_op op, struct ldb_val *dn,
			const char *name, const char *value)
{
	struct la_op_store *os, *tmp;
	struct ldb_dn *op_dn;

	op_dn = ldb_dn_from_ldb_val(ac, ac->module->ldb, dn);
	if (!op_dn) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* optimize out del - add operations that would end up
	 * with no changes */
	if (ac->ops && op == LA_OP_DEL) {
		/* do a linear search to find out if there is
		 * an equivalent add */
		os = ac->ops;
		while (os->next) {

			tmp = os->next;
			if (tmp->op == LA_OP_ADD) {

				if ((strcmp(name, tmp->name) == 0) &&
				    (strcmp(value, tmp->value) == 0) &&
				    (ldb_dn_compare(op_dn, tmp->dn) == 0)) {

					break;
				}
			}
			os = os->next;
		}
		if (os->next) {
			/* pair found, remove it and return */
			os->next = tmp->next;
			talloc_free(tmp);
			talloc_free(op_dn);
			return LDB_SUCCESS;
		}
	}

	os = talloc_zero(ac, struct la_op_store);
	if (!os) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	os->op = op;

	os->dn = talloc_steal(os, op_dn);
	if (!os->dn) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	os->name = talloc_strdup(os, name);
	if (!os->name) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if ((op != LA_OP_DEL) && (value == NULL)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	if (value) {
		os->value = talloc_strdup(os, value);
		if (!os->value) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	if (ac->ops) {
		ac->cur->next = os;
	} else {
		ac->ops = os;
	}
	ac->cur = os;

	return LDB_SUCCESS;
}

static int la_op_search_callback(struct ldb_request *req,
				 struct ldb_reply *ares);
static int la_do_mod_request(struct la_context *ac);
static int la_mod_callback(struct ldb_request *req,
			   struct ldb_reply *ares);
static int la_down_req(struct la_context *ac);
static int la_down_callback(struct ldb_request *req,
			    struct ldb_reply *ares);



/* add */
static int linked_attributes_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct dsdb_attribute *target_attr;
	struct la_context *ac;
	const char *attr_name;
	const char *attr_val;
	int ret;
	int i, j;

	if (ldb_dn_is_special(req->op.add.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ac = linked_attributes_init(module, req);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (!ac->schema) {
		/* without schema, this doesn't make any sense */
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	/* Need to ensure we only have forward links being specified */
	for (i=0; i < req->op.add.message->num_elements; i++) {
		const struct ldb_message_element *el = &req->op.add.message->elements[i];
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(ac->schema, el->name);
		if (!schema_attr) {
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s is not a valid attribute in schema", el->name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;			
		}
		/* We have a valid attribute, now find out if it is linked */
		if (schema_attr->linkID == 0) {
			continue;
		}
		
		if ((schema_attr->linkID & 1) == 1) {
			/* Odd is for the target.  Illigal to modify */
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s must not be modified directly, it is a linked attribute", el->name);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		
		/* Even link IDs are for the originating attribute */
		target_attr = dsdb_attribute_by_linkID(ac->schema, schema_attr->linkID + 1);
		if (!target_attr) {
			/*
			 * windows 2003 has a broken schema where
			 * the definition of msDS-IsDomainFor
			 * is missing (which is supposed to be
			 * the backlink of the msDS-HasDomainNCs
			 * attribute
			 */
			continue;
		}

		attr_name = target_attr->lDAPDisplayName;
		attr_val = ldb_dn_get_linearized(ac->req->op.add.message->dn);

		for (j = 0; j < el->num_values; j++) {
			ret = la_store_op(ac, LA_OP_ADD,
					  &el->values[j],
					  attr_name, attr_val);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}
	}

	/* if no linked attributes are present continue */
	if (ac->ops == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	/* start with the first one */
	return la_do_mod_request(ac);
}

static int la_mod_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	const struct dsdb_attribute *schema_attr;
	const struct dsdb_attribute *target_attr;
	struct ldb_message_element *search_el;
	struct replace_context *rc;
	struct la_context *ac;
	const char *attr_name;
	const char *dn;
	int i, j;
	int ret = LDB_SUCCESS;

	ac = talloc_get_type(req->context, struct la_context);
	rc = ac->rc;

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	/* Only entries are interesting, and we only want the olddn */
	switch (ares->type) {
	case LDB_REPLY_ENTRY:

		if (ldb_dn_compare(ares->message->dn, ac->req->op.mod.message->dn) != 0) {
			/* Guh?  We only asked for this DN */
			ldb_oom(ac->module->ldb);
			talloc_free(ares);
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}

		dn = ldb_dn_get_linearized(ac->req->op.add.message->dn);

		for (i = 0; i < rc->num_elements; i++) {

			schema_attr = dsdb_attribute_by_lDAPDisplayName(ac->schema, rc->el[i].name);
			if (!schema_attr) {
				ldb_asprintf_errstring(ac->module->ldb,
					"attribute %s is not a valid attribute in schema",
					rc->el[i].name);
				talloc_free(ares);
				return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OBJECT_CLASS_VIOLATION);
			}

			search_el = ldb_msg_find_element(ares->message,
							 rc->el[i].name);

			/* See if this element already exists */
			/* otherwise just ignore as
			 * the add has already been scheduled */
			if ( ! search_el) {
				continue;
			}

			target_attr = dsdb_attribute_by_linkID(ac->schema, schema_attr->linkID + 1);
			if (!target_attr) {
				/*
				 * windows 2003 has a broken schema where
				 * the definition of msDS-IsDomainFor
				 * is missing (which is supposed to be
				 * the backlink of the msDS-HasDomainNCs
				 * attribute
				 */
				continue;
			}
			attr_name = target_attr->lDAPDisplayName;

			/* make sure we manage each value */
			for (j = 0; j < search_el->num_values; j++) {
				ret = la_store_op(ac, LA_OP_DEL,
						  &search_el->values[j],
						  attr_name, dn);
				if (ret != LDB_SUCCESS) {
					talloc_free(ares);
					return ldb_module_done(ac->req,
							       NULL, NULL, ret);
				}
			}
		}

		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		break;

	case LDB_REPLY_DONE:

		talloc_free(ares);

		/* All mods set up, start with the first one */
		ret = la_do_mod_request(ac);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		return LDB_SUCCESS;
	}

	talloc_free(ares);
	return ret;
}


/* modify */
static int linked_attributes_modify(struct ldb_module *module, struct ldb_request *req)
{
	/* Look over list of modifications */
	/* Find if any are for linked attributes */
	/* Determine the effect of the modification */
	/* Apply the modify to the linked entry */

	int i, j;
	struct la_context *ac;
	struct ldb_request *search_req;
	int ret;

	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ac = linked_attributes_init(module, req);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (!ac->schema) {
		/* without schema, this doesn't make any sense */
		return ldb_next_request(module, req);
	}

	ac->rc = NULL;

	for (i=0; i < req->op.mod.message->num_elements; i++) {
		bool store_el = false;
		const char *attr_name;
		const char *attr_val;
		const struct dsdb_attribute *target_attr;
		const struct ldb_message_element *el = &req->op.mod.message->elements[i];
		const struct dsdb_attribute *schema_attr
			= dsdb_attribute_by_lDAPDisplayName(ac->schema, el->name);
		if (!schema_attr) {
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s is not a valid attribute in schema", el->name);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;			
		}
		/* We have a valid attribute, now find out if it is linked */
		if (schema_attr->linkID == 0) {
			continue;
		}
		
		if ((schema_attr->linkID & 1) == 1) {
			/* Odd is for the target.  Illegal to modify */
			ldb_asprintf_errstring(module->ldb, 
					       "attribute %s must not be modified directly, it is a linked attribute", el->name);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		
		/* Even link IDs are for the originating attribute */
		
		/* Now find the target attribute */
		target_attr = dsdb_attribute_by_linkID(ac->schema, schema_attr->linkID + 1);
		if (!target_attr) {
			/*
			 * windows 2003 has a broken schema where
			 * the definition of msDS-IsDomainFor
			 * is missing (which is supposed to be
			 * the backlink of the msDS-HasDomainNCs
			 * attribute
			 */
			continue;
		}

		attr_name = target_attr->lDAPDisplayName;
		attr_val = ldb_dn_get_linearized(ac->req->op.mod.message->dn);

		switch (el->flags & LDB_FLAG_MOD_MASK) {
		case LDB_FLAG_MOD_REPLACE:
			/* treat as just a normal add the delete part is handled by the callback */
			store_el = true;

			/* break intentionally missing */

		case LDB_FLAG_MOD_ADD:

			/* For each value being added, we need to setup the adds */
			for (j = 0; j < el->num_values; j++) {
				ret = la_store_op(ac, LA_OP_ADD,
						  &el->values[j],
						  attr_name, attr_val);
				if (ret != LDB_SUCCESS) {
					return ret;
				}
			}
			break;

		case LDB_FLAG_MOD_DELETE:

			if (el->num_values) {
				/* For each value being deleted, we need to setup the delete */
				for (j = 0; j < el->num_values; j++) {
					ret = la_store_op(ac, LA_OP_DEL,
							  &el->values[j],
							  attr_name, attr_val);
					if (ret != LDB_SUCCESS) {
						return ret;
					}
				}
			} else {
				/* Flag that there was a DELETE
				 * without a value specified, so we
				 * need to look for the old value */
				store_el = true;
			}

			break;
		}

		if (store_el) {
			struct ldb_message_element *search_el;

			/* Fill out ac->rc only if we have to find the old values */
			if (!ac->rc) {
				ac->rc = talloc_zero(ac, struct replace_context);
				if (!ac->rc) {
					ldb_oom(module->ldb);
					return LDB_ERR_OPERATIONS_ERROR;
				}
			}

			search_el = talloc_realloc(ac->rc, ac->rc->el,
						   struct ldb_message_element,
						   ac->rc->num_elements +1);
			if (!search_el) {
				ldb_oom(module->ldb);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			ac->rc->el = search_el;

			ac->rc->el[ac->rc->num_elements] = *el;
			ac->rc->num_elements++;
		}
	}

	/* both replace and delete without values are handled in the callback
	 * after the search on the entry to be modified is performed */

	/* Only bother doing a search of this entry (to find old
	 * values) if replace or delete operations are attempted */
	if (ac->rc) {
		const char **attrs;

		attrs = talloc_array(ac->rc, const char *, ac->rc->num_elements +1);
		if (!attrs) {
			ldb_oom(module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		for (i = 0; i < ac->rc->num_elements; i++) {
			attrs[i] = ac->rc->el[i].name;
		}
		attrs[i] = NULL;

		/* The callback does all the hard work here */
		ret = ldb_build_search_req(&search_req, module->ldb, ac,
					   req->op.mod.message->dn,
					   LDB_SCOPE_BASE,
					   "(objectClass=*)", attrs,
					   NULL,
					   ac, la_mod_search_callback,
					   req);

		if (ret == LDB_SUCCESS) {
			talloc_steal(search_req, attrs);

			ret = ldb_next_request(module, search_req);
		}

		
	} else {
		if (ac->ops) {
			/* Jump directly to handling the modifies */
			ret = la_do_mod_request(ac);
		} else {
			/* nothing to do for this module, proceed */
			talloc_free(ac);
			ret = ldb_next_request(module, req);
		}
	}

	return ret;
}

/* delete, rename */
static int linked_attributes_op(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_request *search_req;
	struct ldb_dn *base_dn;
	struct la_context *ac;
	const char **attrs;
	WERROR werr;
	int ret;

	/* This gets complex:  We need to:
	   - Do a search for the entry
	   - Wait for these result to appear
	   - In the callback for the result, issue a modify
		request based on the linked attributes found
	   - Wait for each modify result
	   - Regain our sainity
	*/

	switch (req->operation) {
	case LDB_RENAME:
		base_dn = req->op.rename.olddn;
		break;
	case LDB_DELETE:
		base_dn = req->op.del.dn;
		break;
	default:
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac = linked_attributes_init(module, req);
	if (!ac) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (!ac->schema) {
		/* without schema, this doesn't make any sense */
		return ldb_next_request(module, req);
	}

	werr = dsdb_linked_attribute_lDAPDisplayName_list(ac->schema, ac, &attrs);
	if (!W_ERROR_IS_OK(werr)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&search_req, module->ldb, req,
				   base_dn, LDB_SCOPE_BASE,
				   "(objectClass=*)", attrs,
				   NULL,
				   ac, la_op_search_callback,
				   req);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(search_req, attrs);

	return ldb_next_request(module, search_req);
}

static int la_op_search_callback(struct ldb_request *req,
				 struct ldb_reply *ares)
{
	struct la_context *ac;
	const struct dsdb_attribute *schema_attr;
	const struct dsdb_attribute *target_attr;
	const struct ldb_message_element *el;
	const char *attr_name;
	const char *deldn;
	const char *adddn;
	int i, j;
	int ret;

	ac = talloc_get_type(req->context, struct la_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	/* Only entries are interesting, and we only want the olddn */
	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		ret = ldb_dn_compare(ares->message->dn, req->op.search.base);
		if (ret != 0) {
			/* Guh?  We only asked for this DN */
			talloc_free(ares);
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}
		if (ares->message->num_elements == 0) {
			/* only bother at all if there were some
			 * linked attributes found */
			talloc_free(ares);
			return LDB_SUCCESS;
		}

		switch (ac->req->operation) {
		case LDB_DELETE:
			deldn = ldb_dn_get_linearized(ac->req->op.del.dn);
			adddn = NULL;
			break;
		case LDB_RENAME:
			deldn = ldb_dn_get_linearized(ac->req->op.rename.olddn);
			adddn = ldb_dn_get_linearized(ac->req->op.rename.newdn);
			break;
		default:
			talloc_free(ares);
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}

		for (i = 0; i < ares->message->num_elements; i++) {
			el = &ares->message->elements[i];

			schema_attr = dsdb_attribute_by_lDAPDisplayName(ac->schema, el->name);
			if (!schema_attr) {
				ldb_asprintf_errstring(ac->module->ldb,
					"attribute %s is not a valid attribute"
					" in schema", el->name);
				talloc_free(ares);
				return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OBJECT_CLASS_VIOLATION);
			}

			/* Valid attribute, now find out if it is linked */
			if (schema_attr->linkID == 0) {
				/* Not a linked attribute, skip */
				continue;
			}

			if ((schema_attr->linkID & 1) == 0) {
				/* Odd is for the target. */
				target_attr = dsdb_attribute_by_linkID(ac->schema, schema_attr->linkID + 1);
				if (!target_attr) {
					continue;
				}
				attr_name = target_attr->lDAPDisplayName;
			} else {
				target_attr = dsdb_attribute_by_linkID(ac->schema, schema_attr->linkID - 1);
				if (!target_attr) {
					continue;
				}
				attr_name = target_attr->lDAPDisplayName;
			}
			for (j = 0; j < el->num_values; j++) {
				ret = la_store_op(ac, LA_OP_DEL,
						  &el->values[j],
						  attr_name, deldn);
				if (ret != LDB_SUCCESS) {
					talloc_free(ares);
					return ldb_module_done(ac->req,
							       NULL, NULL, ret);
				}
				if (!adddn) continue;
				ret = la_store_op(ac, LA_OP_ADD,
						  &el->values[j],
						  attr_name, adddn);
				if (ret != LDB_SUCCESS) {
					talloc_free(ares);
					return ldb_module_done(ac->req,
							       NULL, NULL, ret);
				}
			}
		}

		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		break;

	case LDB_REPLY_DONE:

		talloc_free(ares);

		if (ac->ops) {
			/* start the mod requests chain */
			ret = la_do_mod_request(ac);
		} else {
			ret = la_down_req(ac);
		}
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		return LDB_SUCCESS;
	}

	talloc_free(ares);
	return LDB_SUCCESS;
}

/* do a linked attributes modify request */
static int la_do_mod_request(struct la_context *ac)
{
	struct ldb_message_element *ret_el;
	struct ldb_request *mod_req;
	struct ldb_message *new_msg;
	struct ldb_context *ldb;
	int ret;

	ldb = ac->module->ldb;

	/* Create the modify request */
	new_msg = ldb_msg_new(ac);
	if (!new_msg) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	new_msg->dn = ldb_dn_copy(new_msg, ac->ops->dn);
	if (!new_msg->dn) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (ac->ops->op == LA_OP_ADD) {
		ret = ldb_msg_add_empty(new_msg, ac->ops->name,
					LDB_FLAG_MOD_ADD, &ret_el);
	} else {
		ret = ldb_msg_add_empty(new_msg, ac->ops->name,
					LDB_FLAG_MOD_DELETE, &ret_el);
	}
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	ret_el->values = talloc_array(new_msg, struct ldb_val, 1);
	if (!ret_el->values) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret_el->values[0] = data_blob_string_const(ac->ops->value);
	ret_el->num_values = 1;

	/* use ac->ops as the mem_ctx so that the request will be freed
	 * in the callback as soon as completed */
	ret = ldb_build_mod_req(&mod_req, ldb, ac->ops,
				new_msg,
				NULL,
				ac, la_mod_callback,
				ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	talloc_steal(mod_req, new_msg);

	/* Run the new request */
	return ldb_next_request(ac->module, mod_req);
}

static int la_mod_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct la_context *ac;
	struct la_op_store *os;
	int ret;

	ac = talloc_get_type(req->context, struct la_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ac->module->ldb,
				  "invalid ldb_reply_type in callback");
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);

	if (ac->ops) {
		os = ac->ops;
		ac->ops = os->next;

		/* this frees the request too
		 * DO NOT access 'req' after this point */
		talloc_free(os);
	}

	/* as last op run the original request */
	if (ac->ops) {
		ret = la_do_mod_request(ac);
	} else {
		ret = la_down_req(ac);
	}

	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}
	return LDB_SUCCESS;
}

static int la_down_req(struct la_context *ac)
{
	struct ldb_request *down_req;
	int ret;

	switch (ac->req->operation) {
	case LDB_ADD:
		ret = ldb_build_add_req(&down_req, ac->module->ldb, ac,
					ac->req->op.add.message,
					ac->req->controls,
					ac, la_down_callback,
					ac->req);
		break;
	case LDB_MODIFY:
		ret = ldb_build_mod_req(&down_req, ac->module->ldb, ac,
					ac->req->op.mod.message,
					ac->req->controls,
					ac, la_down_callback,
					ac->req);
		break;
	case LDB_DELETE:
		ret = ldb_build_del_req(&down_req, ac->module->ldb, ac,
					ac->req->op.del.dn,
					ac->req->controls,
					ac, la_down_callback,
					ac->req);
		break;
	case LDB_RENAME:
		ret = ldb_build_rename_req(&down_req, ac->module->ldb, ac,
					   ac->req->op.rename.olddn,
					   ac->req->op.rename.newdn,
					   ac->req->controls,
					   ac, la_down_callback,
					   ac->req);
		break;
	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
	}
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, down_req);
}

static int la_down_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct la_context *ac;

	ac = talloc_get_type(req->context, struct la_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		ldb_set_errstring(ac->module->ldb,
				  "invalid ldb_reply_type in callback");
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	return ldb_module_done(ac->req, ares->controls,
				ares->response, ares->error);
}

_PUBLIC_ const struct ldb_module_ops ldb_linked_attributes_module_ops = {
	.name		   = "linked_attributes",
	.add               = linked_attributes_add,
	.modify            = linked_attributes_modify,
	.del               = linked_attributes_op,
	.rename            = linked_attributes_op,
};
