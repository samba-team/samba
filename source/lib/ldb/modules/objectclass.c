/* 
   ldb database library

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
 *  Component: objectClass sorting module
 *
 *  Description: sort the objectClass attribute into the class hierarchy
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb/include/includes.h"

/* It turns out the MMC assumes that the last objectClass in the list
 * is the most specific subclass.  As such, we must sort the list,
 * according to the schema.
 *
 * For performance, we do this on the add/modify, not on the search
 *
 * We perform the original add/modify, then search for that is now in
 * the objectClass list. We can then then replace that with the new
 * sorted list.  The backend is expected to preserve ordering for
 * subsequent searches.
 *
 * We are in a transaction, so this is all perfectly safe...
 */

static int objectclass_handle(struct ldb_module *module, struct ldb_request *req, const struct ldb_message *msg)
{
	TALLOC_CTX *mem_ctx;
	int ret;
	struct ldb_request *search_request;
	struct ldb_request *modify_request;
	struct ldb_message *modify_msg;
	struct ldb_result *res;
	const char *attrs[] = { "objectClass", NULL };
	struct class_list {
		struct class_list *prev, *next;
		const char *objectclass;
	};
	struct class_list *sorted = NULL, *parent_class = NULL, 
		*subclass = NULL, *unsorted = NULL, *current, *poss_subclass;
	int i;
	int layer;

	struct ldb_message_element *objectclass_element;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectclass_handle\n");

	if (ldb_dn_is_special(msg->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	ret = ldb_next_request(module, req);

	if (ret) {
		return ret;
	}

	if (ldb_msg_find_element(msg, "objectClass") == NULL ) {
		/* No sign of the objectClass:  no change, nothing to see here */
		return ret;
	}

	/* Thanks to transactions: Now do a search, find the full list
	 * of objectClasses and do the sort */

	mem_ctx = talloc_new(module);
	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	search_request = talloc(mem_ctx, struct ldb_request);
	if (!search_request) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	search_request->operation       = LDB_REQ_SEARCH;
	search_request->op.search.base  = msg->dn;
	search_request->op.search.scope = LDB_SCOPE_BASE;
	search_request->op.search.tree  = ldb_parse_tree(module->ldb, NULL);
	search_request->op.search.attrs = attrs;
	search_request->controls = NULL;

	ret = ldb_next_request(module, search_request);
	if (ret) {
		return ret;
	}

	res = search_request->op.search.res;
	talloc_steal(mem_ctx, res);
	if (res->count != 1) {
		ldb_set_errstring(module->ldb, 
				  talloc_asprintf(mem_ctx, "objectClass_handle: "
						  "search for %s found %d != 1 objects, for entry we just added/modified",
						  ldb_dn_linearize(mem_ctx, msg->dn),
						  res->count));
		/* What happened?  The above add/modify worked... */
		talloc_free(mem_ctx);
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	/* This is now the objectClass list from the database */
	objectclass_element = ldb_msg_find_element(res->msgs[0], "objectClass");
	if (!objectclass_element) {
		/* Perhaps the above was a remove?  Move along now, nothing to see here */
		talloc_free(mem_ctx);
		return LDB_SUCCESS;
	}
	
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
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		current->objectclass = (const char *)objectclass_element->values[i].data;

		/* this is the root of the tree.  We will start
		 * looking for subclasses from here */
		if (ldb_attr_cmp("top", current->objectclass) == 0) {
			DLIST_ADD(parent_class, current);
		} else {
			DLIST_ADD(unsorted, current);
		}
	}

	/* DEBUGGING aid:  how many layers are we down now? */
	layer = 0;
	do {
		layer++;
		/* Find all the subclasses of classes in the
		 * parent_classes.  Push them onto the subclass list */

		/* Ensure we don't bother if there are no unsorted entries left */
		for (current = parent_class; unsorted && current; current = current->next) {
			const char **subclasses = ldb_subclass_list(module->ldb, current->objectclass);

			/* Walk the list of possible subclasses in unsorted */
			for (poss_subclass = unsorted; poss_subclass; ) {
				struct class_list *next;
				
				/* Save the next pointer, as the DLIST_ macros will change poss_subclass->next */
				next = poss_subclass->next;

				for (i = 0; subclasses && subclasses[i]; i++) {
					if (ldb_attr_cmp(poss_subclass->objectclass, subclasses[i]) == 0) {
						DLIST_REMOVE(unsorted, poss_subclass);
						DLIST_ADD(subclass, poss_subclass);

						break;
					}
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

	/* This shouldn't happen, and would break MMC, but we can't
	 * afford to loose objectClasses.  Perhaps there was no 'top',
	 * or some other schema error? 
	 *
	 * Detecting schema errors is the job of the schema module, so
	 * at this layer we just try not to loose data
 	 */
	DLIST_CONCATENATE(sorted, unsorted, struct class_list *);

	modify_msg = ldb_msg_new(mem_ctx);
	if (!modify_msg) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	modify_msg->dn = talloc_reference(modify_msg, msg->dn);

	/* We must completely replace the existing objectClass entry.
	 * We could do a constrained add/del, but we are meant to be
	 * in a transaction... */

	ret = ldb_msg_add_empty(modify_msg, "objectClass", LDB_FLAG_MOD_REPLACE);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}
	
	/* Move from the linked list back into an ldb msg */
	for (current = sorted; current; current = current->next) {
		ret = ldb_msg_add_string(modify_msg, "objectClass", current->objectclass);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}
	}

	ret = ldb_msg_sanity_check(modify_msg);
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}

	modify_request = talloc(mem_ctx, struct ldb_request);
	if (!modify_request) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	modify_request->operation = LDB_REQ_MODIFY;
	modify_request->op.mod.message = modify_msg;
	modify_request->controls = NULL;

	/* And now push the write into the database */
	ret = ldb_next_request(module, modify_request);
	
	talloc_free(mem_ctx);
	return ret;
}

static int objectclass_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

		/* only care about add and modify requests */
	case LDB_REQ_ADD:
		return objectclass_handle(module, req, req->op.add.message);

	case LDB_REQ_MODIFY:
		return objectclass_handle(module, req, req->op.mod.message);

	default:
		return ldb_next_request(module, req);

	}
}

static const struct ldb_module_ops objectclass_ops = {
	.name		   = "objectclass",
	.request      	   = objectclass_request,
};

int ldb_objectclass_init(void)
{
	return ldb_register_module(&objectclass_ops);
}
