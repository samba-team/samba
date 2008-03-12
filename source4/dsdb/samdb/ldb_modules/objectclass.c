/* 
   ldb database library

   Copyright (C) Simo Sorce  2006
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2007

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
 *  Component: objectClass sorting module
 *
 *  Description: 
 *  - sort the objectClass attribute into the class
 *    hierarchy, 
 *  - fix DNs and attributes into 'standard' case
 *  - Add objectCategory and ntSecurityDescriptor defaults
 *
 *  Author: Andrew Bartlett
 */


#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"
#include "lib/util/dlinklist.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "auth/auth.h"
#include "param/param.h"

struct oc_context {

	enum oc_step {OC_DO_REQ, OC_SEARCH_SELF, OC_DO_MOD, 
		      OC_SEARCH_ADD_PARENT, OC_DO_ADD, 
		      OC_SEARCH_RENAME_PARENT, OC_DO_RENAME} step;

	struct ldb_module *module;
	struct ldb_request *orig_req;

	struct ldb_request *down_req;

	struct ldb_request *search_req;
	struct ldb_reply *search_res;

	struct ldb_request *add_req;
	struct ldb_request *mod_req;
	struct ldb_request *rename_req;
};

struct class_list {
	struct class_list *prev, *next;
	const struct dsdb_class *objectclass;
};

static int objectclass_do_add(struct ldb_handle *h);

static struct ldb_handle *oc_init_handle(struct ldb_request *req, struct ldb_module *module)
{
	struct oc_context *ac;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	ac = talloc_zero(h, struct oc_context);
	if (ac == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)ac;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->module = module;
	ac->orig_req = req;

	return h;
}

/* Sort objectClasses into correct order, and validate that all
 * objectClasses specified actually exist in the schema
 */

static int objectclass_sort(struct ldb_module *module,
			    const struct dsdb_schema *schema,
			    struct ldb_message *msg, /* so that when we create new elements, we put it on the right parent */
			    TALLOC_CTX *mem_ctx,
			    struct ldb_message_element *objectclass_element,
			    struct class_list **sorted_out) 
{
	int i;
	int layer;
	struct class_list *sorted = NULL, *parent_class = NULL,
		*subclass = NULL, *unsorted = NULL, *current, *poss_subclass, *poss_parent, *new_parent;
	/* DESIGN:
	 *
	 * We work on 4 different 'bins' (implemented here as linked lists):
	 *
	 * * sorted:       the eventual list, in the order we wish to push
	 *                 into the database.  This is the only ordered list.
	 *
	 * * parent_class: The current parent class 'bin' we are
	 *                 trying to find subclasses for
	 *
	 * * subclass:     The subclasses we have found so far
	 *
	 * * unsorted:     The remaining objectClasses
	 *
	 * The process is a matter of filtering objectClasses up from
	 * unsorted into sorted.  Order is irrelevent in the later 3 'bins'.
	 * 
	 * We start with 'top' (found and promoted to parent_class
	 * initially).  Then we find (in unsorted) all the direct
	 * subclasses of 'top'.  parent_classes is concatenated onto
	 * the end of 'sorted', and subclass becomes the list in
	 * parent_class.
	 *
	 * We then repeat, until we find no more subclasses.  Any left
	 * over classes are added to the end.
	 *
	 */

	/* Firstly, dump all the objectClass elements into the
	 * unsorted bin, except for 'top', which is special */
	for (i=0; i < objectclass_element->num_values; i++) {
		current = talloc(mem_ctx, struct class_list);
		if (!current) {
			ldb_set_errstring(module->ldb, "objectclass: out of memory allocating objectclass list");
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		current->objectclass = dsdb_class_by_lDAPDisplayName(schema, (const char *)objectclass_element->values[i].data);
		if (!current->objectclass) {
			ldb_asprintf_errstring(module->ldb, "objectclass %s is not a valid objectClass in schema", (const char *)objectclass_element->values[i].data);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}

		/* this is the root of the tree.  We will start
		 * looking for subclasses from here */
		if (ldb_attr_cmp("top", current->objectclass->lDAPDisplayName) == 0) {
			DLIST_ADD_END(parent_class, current, struct class_list *);
		} else {
			DLIST_ADD_END(unsorted, current, struct class_list *);
		}
	}

	if (parent_class == NULL) {
		current = talloc(mem_ctx, struct class_list);
		current->objectclass = dsdb_class_by_lDAPDisplayName(schema, "top");
		DLIST_ADD_END(parent_class, current, struct class_list *);
	}

	/* For each object:  find parent chain */
	for (current = unsorted; schema && current; current = current->next) {
		for (poss_parent = unsorted; poss_parent; poss_parent = poss_parent->next) {
			if (ldb_attr_cmp(poss_parent->objectclass->lDAPDisplayName, current->objectclass->subClassOf) == 0) {
				break;
			}
		}
		/* If we didn't get to the end of the list, we need to add this parent */
		if (poss_parent || (ldb_attr_cmp("top", current->objectclass->subClassOf) == 0)) {
			continue;
		}

		new_parent = talloc(mem_ctx, struct class_list);
		new_parent->objectclass = dsdb_class_by_lDAPDisplayName(schema, current->objectclass->subClassOf);
		DLIST_ADD_END(unsorted, new_parent, struct class_list *);
	}

	/* DEBUGGING aid:  how many layers are we down now? */
	layer = 0;
	do {
		layer++;
		/* Find all the subclasses of classes in the
		 * parent_classes.  Push them onto the subclass list */

		/* Ensure we don't bother if there are no unsorted entries left */
		for (current = parent_class; schema && unsorted && current; current = current->next) {
			/* Walk the list of possible subclasses in unsorted */
			for (poss_subclass = unsorted; poss_subclass; ) {
				struct class_list *next;
				
				/* Save the next pointer, as the DLIST_ macros will change poss_subclass->next */
				next = poss_subclass->next;

				if (ldb_attr_cmp(poss_subclass->objectclass->subClassOf, current->objectclass->lDAPDisplayName) == 0) {
					DLIST_REMOVE(unsorted, poss_subclass);
					DLIST_ADD(subclass, poss_subclass);
					
					break;
				}
				poss_subclass = next;
			}
		}

		/* Now push the parent_classes as sorted, we are done with
		these.  Add to the END of the list by concatenation */
		DLIST_CONCATENATE(sorted, parent_class, struct class_list *);

		/* and now find subclasses of these */
		parent_class = subclass;
		subclass = NULL;

		/* If we didn't find any subclasses we will fall out
		 * the bottom here */
	} while (parent_class);

	if (!unsorted) {
		*sorted_out = sorted;
		return LDB_SUCCESS;
	}

	if (!schema) {
		/* If we don't have schema yet, then just merge the lists again */
		DLIST_CONCATENATE(sorted, unsorted, struct class_list *);
		*sorted_out = sorted;
		return LDB_SUCCESS;
	}

	/* This shouldn't happen, and would break MMC, perhaps there
	 * was no 'top', a conflict in the objectClasses or some other
	 * schema error?
	 */
	ldb_asprintf_errstring(module->ldb, "objectclass %s is not a valid objectClass in objectClass chain", unsorted->objectclass->lDAPDisplayName);
	return LDB_ERR_OBJECT_CLASS_VIOLATION;
}

static DATA_BLOB *get_sd(struct ldb_module *module, TALLOC_CTX *mem_ctx, 
			 const struct dsdb_class *objectclass) 
{
	enum ndr_err_code ndr_err;
	DATA_BLOB *linear_sd;
	struct auth_session_info *session_info
		= ldb_get_opaque(module->ldb, "sessionInfo");
	struct security_descriptor *sd;

	if (!objectclass->defaultSecurityDescriptor) {
		return NULL;
	}
	
	sd = sddl_decode(mem_ctx, 
			 objectclass->defaultSecurityDescriptor,
			 samdb_domain_sid(module->ldb));

	if (!sd || !session_info || !session_info->security_token) {
		return NULL;
	}
	
	sd->owner_sid = session_info->security_token->user_sid;
	sd->group_sid = session_info->security_token->group_sid;
	
	linear_sd = talloc(mem_ctx, DATA_BLOB);
	if (!linear_sd) {
		return NULL;
	}

	ndr_err = ndr_push_struct_blob(linear_sd, mem_ctx, 
					lp_iconv_convenience(ldb_get_opaque(module->ldb, "loadparm")),
				       sd,
				       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NULL;
	}
	
	return linear_sd;

}

static int get_search_callback(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct oc_context *ac;

	ac = talloc_get_type(context, struct oc_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (ac->search_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ac->search_res = talloc_move(ac, &ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

/* Fix up the DN to be in the standard form, taking particular care to match the parent DN

   This should mean that if the parent is:
    CN=Users,DC=samba,DC=example,DC=com
   and a proposed child is
    cn=Admins ,cn=USERS,dc=Samba,dc=example,dc=COM

   The resulting DN should be:

    CN=Admins,CN=Users,DC=samba,DC=example,DC=com
   
 */
static int fix_dn(TALLOC_CTX *mem_ctx, 
		  struct ldb_dn *newdn, struct ldb_dn *parent_dn, 
		  struct ldb_dn **fixed_dn) 
{
	char *upper_rdn_attr;
	/* Fix up the DN to be in the standard form, taking particular care to match the parent DN */
	*fixed_dn = ldb_dn_copy(mem_ctx, parent_dn);

	/* We need the attribute name in upper case */
	upper_rdn_attr = strupper_talloc(*fixed_dn, 
					 ldb_dn_get_rdn_name(newdn));
	if (!upper_rdn_attr) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
					       
	/* Create a new child */
	if (ldb_dn_add_child_fmt(*fixed_dn, "X=X") == false) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* And replace it with CN=foo (we need the attribute in upper case */
	return ldb_dn_set_component(*fixed_dn, 0, upper_rdn_attr,
				    *ldb_dn_get_rdn_val(newdn));
}

/* Fix all attribute names to be in the correct case, and check they are all valid per the schema */
static int fix_attributes(struct ldb_context *ldb, const struct dsdb_schema *schema, struct ldb_message *msg) 
{
	int i;
	for (i=0; i < msg->num_elements; i++) {
		const struct dsdb_attribute *attribute = dsdb_attribute_by_lDAPDisplayName(schema, msg->elements[i].name);
		if (!attribute) {
			ldb_asprintf_errstring(ldb, "attribute %s is not a valid attribute in schema", msg->elements[i].name);
			return LDB_ERR_UNDEFINED_ATTRIBUTE_TYPE;
		}
		msg->elements[i].name = attribute->lDAPDisplayName;
	}

	return LDB_SUCCESS;
}

static int objectclass_add(struct ldb_module *module, struct ldb_request *req)
{

	static const char * const attrs[] = { NULL };

	struct ldb_handle *h;
	struct oc_context *ac;
	struct ldb_dn *parent_dn;
	int ret;
	
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectclass_add\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	/* Need to object to this, but cn=rootdse doesn't hae an objectClass... */
	if (ldb_msg_find_element(req->op.add.message, 
				 "objectClass") == NULL) {
		return ldb_next_request(module, req);
	}

	h = oc_init_handle(req, module);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct oc_context);
	
	/* return or own handle to deal with this call */
	req->handle = h;

	/* If there isn't a parent, just go on to the add processing */
	if (ldb_dn_get_comp_num(ac->orig_req->op.add.message->dn) == 1) {
		return objectclass_do_add(h);
	}

	parent_dn = ldb_dn_get_parent(ac, ac->orig_req->op.add.message->dn);
	if (parent_dn == NULL) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req(&ac->search_req, module->ldb,
				   ac, parent_dn, LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL, 
				   ac, get_search_callback);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(ac->search_req, parent_dn);

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->search_req);

	ac->step = OC_SEARCH_ADD_PARENT;

	return ldb_next_request(ac->module, ac->search_req);
}

static int objectclass_do_add(struct ldb_handle *h) 
{
	const struct dsdb_schema *schema;
	struct oc_context *ac;
	struct ldb_message_element *objectclass_element;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	struct class_list *sorted, *current;
	int ret;
      
	ac = talloc_get_type(h->private_data, struct oc_context);
	schema = dsdb_get_schema(ac->module->ldb);

	mem_ctx = talloc_new(ac);
	if (mem_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->add_req = talloc(ac, struct ldb_request);
	if (ac->add_req == NULL) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*ac->add_req = *ac->orig_req;

	ac->add_req->op.add.message = msg = ldb_msg_copy_shallow(ac->add_req, ac->orig_req->op.add.message);

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->add_req);
	
	/* Check we have a valid parent */
	if (ac->search_res == NULL) {
		if (ldb_dn_compare(ldb_get_root_basedn(ac->module->ldb), ac->orig_req->op.add.message->dn) == 0) {
			/* Allow the tree to be started */
			
			/* but don't keep any error string, it's meaningless */
			ldb_set_errstring(ac->module->ldb, NULL);
		} else {
			ldb_asprintf_errstring(ac->module->ldb, "objectclass: Cannot add %s, parent does not exist!", 
					       ldb_dn_get_linearized(ac->orig_req->op.add.message->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	} else {
		
		/* Fix up the DN to be in the standard form, taking particular care to match the parent DN */
		ret = fix_dn(msg, 
			     ac->orig_req->op.add.message->dn,
			     ac->search_res->message->dn,
			     &msg->dn);

		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ac->module->ldb, "Could not munge DN %s into normal form", 
					       ldb_dn_get_linearized(ac->orig_req->op.add.message->dn));
			return ret;
		}

		/* TODO: Check this is a valid child to this parent,
		 * by reading the allowedChildClasses and
		 * allowedChildClasssesEffective attributes */

	}

	if (schema) {
		ret = fix_attributes(ac->module->ldb, schema, msg);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}

		/* This is now the objectClass list from the database */
		objectclass_element = ldb_msg_find_element(msg, "objectClass");
		
		if (!objectclass_element) {
			/* Where did it go?  bail now... */
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ret = objectclass_sort(ac->module, schema, msg, mem_ctx, objectclass_element, &sorted);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}
		
		ldb_msg_remove_attr(msg, "objectClass");
		ret = ldb_msg_add_empty(msg, "objectClass", 0, NULL);
		
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}
		
		/* We must completely replace the existing objectClass entry,
		 * because we need it sorted */
		
		/* Move from the linked list back into an ldb msg */
		for (current = sorted; current; current = current->next) {
			ret = ldb_msg_add_string(msg, "objectClass", current->objectclass->lDAPDisplayName);
			if (ret != LDB_SUCCESS) {
				ldb_set_errstring(ac->module->ldb, 
						  "objectclass: could not re-add sorted "
						  "objectclass to modify msg");
				talloc_free(mem_ctx);
				return ret;
			}
			/* Last one is the critical one */
			if (!current->next) {
				if (!ldb_msg_find_element(msg, "objectCategory")) {
					ldb_msg_add_string(msg, "objectCategory", 
							   current->objectclass->defaultObjectCategory);
				}
				if (!ldb_msg_find_element(msg, "showInAdvancedViewOnly") && (current->objectclass->defaultHidingValue == true)) {
					ldb_msg_add_string(msg, "showInAdvancedViewOnly", 
							   "TRUE");
				}
				if (!ldb_msg_find_element(msg, "nTSecurityDescriptor")) {
					DATA_BLOB *sd = get_sd(ac->module, mem_ctx, current->objectclass);
					if (sd) {
						ldb_msg_add_steal_value(msg, "nTSecurityDescriptor", sd);
					}
				}
			}
		}
	}

	talloc_free(mem_ctx);
	ret = ldb_msg_sanity_check(ac->module->ldb, msg);


	if (ret != LDB_SUCCESS) {
		return ret;
	}

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = OC_DO_ADD;

	/* perform the add */
	return ldb_next_request(ac->module, ac->add_req);
}

static int objectclass_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_message_element *objectclass_element;
	struct ldb_message *msg;
	const struct dsdb_schema *schema = dsdb_get_schema(module->ldb);
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectclass_modify\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}
	
	/* Without schema, there isn't much to do here */
	if (!schema) {
		return ldb_next_request(module, req);
	}
	objectclass_element = ldb_msg_find_element(req->op.mod.message, "objectClass");

	/* If no part of this touches the objectClass, then we don't
	 * need to make any changes.  */

	/* If the only operation is the deletion of the objectClass
	 * then go on with just fixing the attribute case */
	if (!objectclass_element) {
		struct ldb_request *down_req = talloc(req, struct ldb_request);
		if (down_req == NULL) {
			ldb_set_errstring(module->ldb, "Out of memory!");
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		*down_req = *req; /* copy the request */
		
		down_req->op.mod.message = msg = ldb_msg_copy_shallow(down_req, req->op.mod.message);
		
		if (down_req->op.mod.message == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		ret = fix_attributes(module->ldb, schema, msg);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/* go on with the call chain */
		ret = ldb_next_request(module, down_req);
		
		/* do not free down_req as the call results may be linked to it,
		 * it will be freed when the upper level request get freed */
		if (ret == LDB_SUCCESS) {
			req->handle = down_req->handle;
		}
		return ret;
	}

	switch (objectclass_element->flags & LDB_FLAG_MOD_MASK) {
	case LDB_FLAG_MOD_DELETE:
		if (objectclass_element->num_values == 0) {
			return LDB_ERR_OBJECT_CLASS_MODS_PROHIBITED;
		}
		break;
	case LDB_FLAG_MOD_REPLACE:
	{
		struct ldb_request *down_req;
		struct class_list *sorted, *current;
		TALLOC_CTX *mem_ctx;
		mem_ctx = talloc_new(req);
		if (mem_ctx == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		/* prepare the first operation */
		down_req = talloc(req, struct ldb_request);
		if (down_req == NULL) {
			ldb_set_errstring(module->ldb, "Out of memory!");
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		*down_req = *req; /* copy the request */
		
		down_req->op.mod.message = msg = ldb_msg_copy_shallow(down_req, req->op.mod.message);
		
		if (down_req->op.mod.message == NULL) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		ret = fix_attributes(module->ldb, schema, msg);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}

		ret = objectclass_sort(module, schema, msg, mem_ctx, objectclass_element, &sorted);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/* We must completely replace the existing objectClass entry,
		 * because we need it sorted */
		
		ldb_msg_remove_attr(msg, "objectClass");
		ret = ldb_msg_add_empty(msg, "objectClass", LDB_FLAG_MOD_REPLACE, NULL);
		
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}

		/* Move from the linked list back into an ldb msg */
		for (current = sorted; current; current = current->next) {
			ret = ldb_msg_add_string(msg, "objectClass", current->objectclass->lDAPDisplayName);
			if (ret != LDB_SUCCESS) {
				ldb_set_errstring(module->ldb, "objectclass: could not re-add sorted objectclass to modify msg");
				talloc_free(mem_ctx);
				return ret;
			}
		}
		
		talloc_free(mem_ctx);

		ret = ldb_msg_sanity_check(module->ldb, msg);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}
		
		/* go on with the call chain */
		ret = ldb_next_request(module, down_req);
		
		/* do not free down_req as the call results may be linked to it,
		 * it will be freed when the upper level request get freed */
		if (ret == LDB_SUCCESS) {
			req->handle = down_req->handle;
		}
		return ret;
	}
	}

	/* This isn't the default branch of the switch, but a 'in any
	 * other case'.  When a delete isn't for all objectClasses for
	 * example
	 */
	{
		struct ldb_handle *h;
		struct oc_context *ac;
		
		h = oc_init_handle(req, module);
		if (!h) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ac = talloc_get_type(h->private_data, struct oc_context);
		
		/* return or own handle to deal with this call */
		req->handle = h;
		
		/* prepare the first operation */
		ac->down_req = talloc(ac, struct ldb_request);
		if (ac->down_req == NULL) {
			ldb_oom(ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		*(ac->down_req) = *req; /* copy the request */
		
		ac->down_req->op.mod.message = msg = ldb_msg_copy_shallow(ac->down_req, req->op.mod.message);
		
		if (ac->down_req->op.mod.message == NULL) {
			ldb_oom(ac->module->ldb);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		ret = fix_attributes(ac->module->ldb, schema, msg);
		if (ret != LDB_SUCCESS) {
			ldb_oom(ac->module->ldb);
			return ret;
		}

		ac->down_req->context = NULL;
		ac->down_req->callback = NULL;
		ldb_set_timeout_from_prev_req(module->ldb, req, ac->down_req);
		
		ac->step = OC_DO_REQ;

		return ldb_next_request(module, ac->down_req);
	}
}

static int objectclass_search_self(struct ldb_handle *h) 
{
	int ret;
	struct oc_context *ac;
	static const char * const attrs[] = { "objectClass", NULL };

	ac = talloc_get_type(h->private_data, struct oc_context);

	ret = ldb_build_search_req(&ac->search_req, ac->module->ldb,
				   ac, ac->orig_req->op.mod.message->dn, LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL, 
				   ac, get_search_callback);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->search_req);

	ac->step = OC_SEARCH_SELF;

	return ldb_next_request(ac->module, ac->search_req);
}

static int objectclass_do_mod(struct ldb_handle *h) {

	const struct dsdb_schema *schema;
	struct oc_context *ac;
	struct ldb_message_element *objectclass_element;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	struct class_list *sorted, *current;
	int ret;
      
	ac = talloc_get_type(h->private_data, struct oc_context);
	schema = dsdb_get_schema(ac->module->ldb);

	mem_ctx = talloc_new(ac);
	if (mem_ctx == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->mod_req = talloc(ac, struct ldb_request);
	if (ac->mod_req == NULL) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ac->mod_req->operation = LDB_MODIFY;
	ac->mod_req->controls = NULL;
	ac->mod_req->context = ac;
	ac->mod_req->callback = NULL;
	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->mod_req);
	
	/* use a new message structure */
	ac->mod_req->op.mod.message = msg = ldb_msg_new(ac->mod_req);
	if (msg == NULL) {
		ldb_set_errstring(ac->module->ldb, "objectclass: could not create new modify msg");
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* This is now the objectClass list from the database */
	objectclass_element = ldb_msg_find_element(ac->search_res->message, 
						   "objectClass");
	if (!objectclass_element) {
		/* Where did it go?  bail now... */
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* modify dn */
	msg->dn = ac->orig_req->op.mod.message->dn;

	ret = objectclass_sort(ac->module, schema, msg, mem_ctx, objectclass_element, &sorted);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* We must completely replace the existing objectClass entry.
	 * We could do a constrained add/del, but we are meant to be
	 * in a transaction... */

	ret = ldb_msg_add_empty(msg, "objectClass", LDB_FLAG_MOD_REPLACE, NULL);
	if (ret != LDB_SUCCESS) {
		ldb_set_errstring(ac->module->ldb, "objectclass: could not clear objectclass in modify msg");
		talloc_free(mem_ctx);
		return ret;
	}
	
	/* Move from the linked list back into an ldb msg */
	for (current = sorted; current; current = current->next) {
		ret = ldb_msg_add_string(msg, "objectClass", current->objectclass->lDAPDisplayName);
		if (ret != LDB_SUCCESS) {
			ldb_set_errstring(ac->module->ldb, "objectclass: could not re-add sorted objectclass to modify msg");
			talloc_free(mem_ctx);
			return ret;
		}
	}

	ret = ldb_msg_sanity_check(ac->module->ldb, msg);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}


	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = OC_DO_MOD;

	talloc_free(mem_ctx);
	/* perform the search */
	return ldb_next_request(ac->module, ac->mod_req);
}

static int objectclass_rename(struct ldb_module *module, struct ldb_request *req)
{

	static const char * const attrs[] = { NULL };

	struct ldb_handle *h;
	struct oc_context *ac;
	struct ldb_dn *parent_dn;
	int ret;
	
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectclass_rename\n");

	if (ldb_dn_is_special(req->op.rename.newdn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}
	
	/* Firstly ensure we are not trying to rename it to be a child of itself */
	if ((ldb_dn_compare_base(req->op.rename.olddn, req->op.rename.newdn) == 0) 
	    && (ldb_dn_compare(req->op.rename.olddn, req->op.rename.newdn) != 0)) {
		ldb_asprintf_errstring(module->ldb, "Cannot rename %s to be a child of itself",
				       ldb_dn_get_linearized(req->op.rename.olddn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	h = oc_init_handle(req, module);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ac = talloc_get_type(h->private_data, struct oc_context);
	
	/* return or own handle to deal with this call */
	req->handle = h;

	parent_dn = ldb_dn_get_parent(ac, ac->orig_req->op.rename.newdn);
	if (parent_dn == NULL) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	ret = ldb_build_search_req(&ac->search_req, module->ldb,
				   ac, parent_dn, LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL, 
				   ac, get_search_callback);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	talloc_steal(ac->search_req, parent_dn);
	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->search_req);

	ac->step = OC_SEARCH_RENAME_PARENT;

	return ldb_next_request(ac->module, ac->search_req);
}

static int objectclass_do_rename(struct ldb_handle *h) 
{
	struct oc_context *ac;
	int ret;
      
	ac = talloc_get_type(h->private_data, struct oc_context);

	ac->rename_req = talloc(ac, struct ldb_request);
	if (ac->rename_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*ac->rename_req = *ac->orig_req;

	ldb_set_timeout_from_prev_req(ac->module->ldb, ac->orig_req, ac->rename_req);
	
	/* Check we have a valid parent */
	if (ac->search_res == NULL) {
		ldb_asprintf_errstring(ac->module->ldb, "objectclass: Cannot rename %s, parent does not exist!", 
				       ldb_dn_get_linearized(ac->orig_req->op.rename.newdn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}
	
	/* Fix up the DN to be in the standard form, taking particular care to match the parent DN */
	ret = fix_dn(ac->rename_req, 
		     ac->orig_req->op.rename.newdn, 
		     ac->search_res->message->dn, 
		     &ac->rename_req->op.rename.newdn);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* TODO: Check this is a valid child to this parent,
	 * by reading the allowedChildClasses and
	 * allowedChildClasssesEffective attributes */

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	ac->step = OC_DO_RENAME;

	/* perform the rename */
	return ldb_next_request(ac->module, ac->rename_req);
}

static int oc_wait(struct ldb_handle *handle) {
	struct oc_context *ac;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	ac = talloc_get_type(handle->private_data, struct oc_context);

	switch (ac->step) {
	case OC_DO_REQ:
		ret = ldb_wait(ac->down_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->down_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->down_req->handle->status;
			goto done;
		}

		if (ac->down_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* mods done, go on */
		return objectclass_search_self(handle);

	case OC_SEARCH_SELF:
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

		/* self search done, go on */
		return objectclass_do_mod(handle);

	case OC_DO_MOD:
		ret = ldb_wait(ac->mod_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->mod_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->mod_req->handle->status;
			goto done;
		}

		if (ac->mod_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	case OC_SEARCH_ADD_PARENT:
		ret = ldb_wait(ac->search_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_OBJECT) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req->handle->status != LDB_SUCCESS
		    && ac->search_req->handle->status != LDB_ERR_NO_SUCH_OBJECT) {
			handle->status = ac->search_req->handle->status;
			goto done;
		}

		if (ac->search_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* parent search done, go on */
		return objectclass_do_add(handle);

	case OC_DO_ADD:
		ret = ldb_wait(ac->add_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->add_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->add_req->handle->status;
			goto done;
		}

		if (ac->add_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	case OC_SEARCH_RENAME_PARENT:
		ret = ldb_wait(ac->search_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_OBJECT) {
			handle->status = ret;
			goto done;
		}
		if (ac->search_req->handle->status != LDB_SUCCESS && ac->search_req->handle->status != LDB_ERR_NO_SUCH_OBJECT) {
			handle->status = ac->search_req->handle->status;
			goto done;
		}

		if (ac->search_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		/* parent search done, go on */
		return objectclass_do_rename(handle);

	case OC_DO_RENAME:
		ret = ldb_wait(ac->rename_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (ac->rename_req->handle->status != LDB_SUCCESS) {
			handle->status = ac->rename_req->handle->status;
			goto done;
		}

		if (ac->rename_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;
		
	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = LDB_SUCCESS;

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}

static int oc_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = oc_wait(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int objectclass_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return oc_wait_all(handle);
	} else {
		return oc_wait(handle);
	}
}

_PUBLIC_ const struct ldb_module_ops ldb_objectclass_module_ops = {
	.name		   = "objectclass",
	.add           = objectclass_add,
	.modify        = objectclass_modify,
	.rename        = objectclass_rename,
	.wait          = objectclass_wait
};
