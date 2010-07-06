/* 
   ldb database library

   Copyright (C) Simo Sorce  2006-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Matthias Dieter Wallnöfer 2010

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
 *  Component: objectClass sorting and constraint checking module
 *
 *  Description: 
 *  - sort the objectClass attribute into the class
 *    hierarchy and perform constraint checks (correct RDN name,
 *    valid parent),
 *  - fix DNs into 'standard' case
 *  - Add objectCategory and some other attribute defaults
 *
 *  Author: Andrew Bartlett
 */


#include "includes.h"
#include "ldb_module.h"
#include "util/dlinklist.h"
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "auth/auth.h"
#include "param/param.h"
#include "../libds/common/flags.h"
#include "util.h"

struct oc_context {

	struct ldb_module *module;
	struct ldb_request *req;
	const struct dsdb_schema *schema;

	struct ldb_reply *search_res;
	struct ldb_reply *search_res2;

	int (*step_fn)(struct oc_context *);
};

struct class_list {
	struct class_list *prev, *next;
	const struct dsdb_class *objectclass;
};

static struct oc_context *oc_init_context(struct ldb_module *module,
					  struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct oc_context *ac;

	ldb = ldb_module_get_ctx(module);

	ac = talloc_zero(req, struct oc_context);
	if (ac == NULL) {
		ldb_oom(ldb);
		return NULL;
	}

	ac->module = module;
	ac->req = req;
	ac->schema = dsdb_get_schema(ldb, ac);

	return ac;
}

static int objectclass_do_add(struct oc_context *ac);

/* Sort objectClasses into correct order, and validate that all
 * objectClasses specified actually exist in the schema
 */

static int objectclass_sort(struct ldb_module *module,
			    const struct dsdb_schema *schema,
			    TALLOC_CTX *mem_ctx,
			    struct ldb_message_element *objectclass_element,
			    struct class_list **sorted_out) 
{
	struct ldb_context *ldb;
	unsigned int i, lowest;
	struct class_list *unsorted = NULL, *sorted = NULL, *current = NULL, *poss_parent = NULL, *new_parent = NULL, *current_lowest = NULL;

	ldb = ldb_module_get_ctx(module);

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
			return ldb_oom(ldb);
		}
		current->objectclass = dsdb_class_by_lDAPDisplayName_ldb_val(schema, &objectclass_element->values[i]);
		if (!current->objectclass) {
			ldb_asprintf_errstring(ldb, "objectclass %.*s is not a valid objectClass in schema", 
					       (int)objectclass_element->values[i].length, (const char *)objectclass_element->values[i].data);
			/* This looks weird, but windows apparently returns this for invalid objectClass values */
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		} else if (current->objectclass->isDefunct) {
			ldb_asprintf_errstring(ldb, "objectclass %.*s marked as isDefunct objectClass in schema - not valid for new objects", 
					       (int)objectclass_element->values[i].length, (const char *)objectclass_element->values[i].data);
			/* This looks weird, but windows apparently returns this for invalid objectClass values */
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		}

		/* Don't add top to list, we will do that later */
		if (ldb_attr_cmp("top", current->objectclass->lDAPDisplayName) != 0) {
			DLIST_ADD_END(unsorted, current, struct class_list *);
		}
	}

	/* Add top here, to prevent duplicates */
	current = talloc(mem_ctx, struct class_list);
	current->objectclass = dsdb_class_by_lDAPDisplayName(schema, "top");
	DLIST_ADD_END(sorted, current, struct class_list *);


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

	do
	{
		lowest = UINT_MAX;
		current_lowest = NULL;
		for (current = unsorted; schema && current; current = current->next) {
			if(current->objectclass->subClass_order < lowest) {
				current_lowest = current;
				lowest = current->objectclass->subClass_order;
			}
		}

		if(current_lowest != NULL) {
			DLIST_REMOVE(unsorted,current_lowest);
			DLIST_ADD_END(sorted,current_lowest, struct class_list *);
		}
	} while(unsorted);


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
	ldb_asprintf_errstring(ldb, "objectclass %s is not a valid objectClass in objectClass chain", unsorted->objectclass->lDAPDisplayName);
	return LDB_ERR_OBJECT_CLASS_VIOLATION;
}

static int get_search_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct ldb_context *ldb;
	struct oc_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct oc_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}
	if (ares->error != LDB_SUCCESS &&
	    ares->error != LDB_ERR_NO_SUCH_OBJECT) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	ldb_reset_err_string(ldb);

	switch (ares->type) {
	case LDB_REPLY_ENTRY:
		if (ac->search_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return ldb_module_done(ac->req, NULL, NULL,
						LDB_ERR_OPERATIONS_ERROR);
		}

		ac->search_res = talloc_steal(ac, ares);
		break;

	case LDB_REPLY_REFERRAL:
		/* ignore */
		talloc_free(ares);
		break;

	case LDB_REPLY_DONE:
		talloc_free(ares);
		ret = ac->step_fn(ac);
		if (ret != LDB_SUCCESS) {
			return ldb_module_done(ac->req, NULL, NULL, ret);
		}
		break;
	}

	return LDB_SUCCESS;
}

static int oc_op_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	struct oc_context *ac;

	ac = talloc_get_type(req->context, struct oc_context);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(ac->req, ares->referral);
	}

	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	return ldb_module_done(ac->req, ares->controls,
				ares->response, ares->error);
}

/* Fix up the DN to be in the standard form, taking particular care to match the parent DN

   This should mean that if the parent is:
    CN=Users,DC=samba,DC=example,DC=com
   and a proposed child is
    cn=Admins ,cn=USERS,dc=Samba,dc=example,dc=COM

   The resulting DN should be:

    CN=Admins,CN=Users,DC=samba,DC=example,DC=com
   
 */
static int fix_dn(struct ldb_context *ldb,
		  TALLOC_CTX *mem_ctx,
		  struct ldb_dn *newdn, struct ldb_dn *parent_dn, 
		  struct ldb_dn **fixed_dn) 
{
	char *upper_rdn_attr;
	const struct ldb_val *rdn_val;

	/* Fix up the DN to be in the standard form, taking particular care to match the parent DN */
	*fixed_dn = ldb_dn_copy(mem_ctx, parent_dn);

	/* We need the attribute name in upper case */
	upper_rdn_attr = strupper_talloc(*fixed_dn, 
					 ldb_dn_get_rdn_name(newdn));
	if (!upper_rdn_attr) {
		return ldb_operr(ldb);
	}

	/* Create a new child */
	if (ldb_dn_add_child_fmt(*fixed_dn, "X=X") == false) {
		return ldb_operr(ldb);
	}


	rdn_val = ldb_dn_get_rdn_val(newdn);

#if 0
	/* the rules for rDN length constraints are more complex than
	this. Until we understand them we need to leave this
	constraint out. Otherwise we break replication, as windows
	does sometimes send us rDNs longer than 64 */
	if (!rdn_val || rdn_val->length > 64) {
		DEBUG(2,(__location__ ": WARNING: rDN longer than 64 limit for '%s'\n", ldb_dn_get_linearized(newdn)));
	}
#endif


	/* And replace it with CN=foo (we need the attribute in upper case */
	return ldb_dn_set_component(*fixed_dn, 0, upper_rdn_attr, *rdn_val);
}


static int objectclass_do_add(struct oc_context *ac);

static int objectclass_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_request *search_req;
	struct oc_context *ac;
	struct ldb_dn *parent_dn;
	const struct ldb_val *val;
	char *value;
	int ret;
	static const char * const parent_attrs[] = { "objectGUID", "objectClass", NULL };

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_add\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	/* An add operation on the root basedn has a special handling when the
	 * relax control isn't specified. */
	if (ldb_dn_compare(ldb_get_root_basedn(ldb), req->op.add.message->dn) == 0) {
		if (ldb_request_get_control(req,
					    LDB_CONTROL_RELAX_OID) == NULL) {
			/* When we are trying to readd the root basedn then
			 * this is denied, but with an interesting mechanism:
			 * there is generated a referral with the last
			 * component value as hostname. */
			val = ldb_dn_get_component_val(req->op.add.message->dn,
						       ldb_dn_get_comp_num(req->op.add.message->dn) - 1);
			if (val == NULL) {
				return ldb_operr(ldb);
			}
			value = talloc_asprintf(req, "ldap://%s/%s", val->data,
						ldb_dn_get_linearized(req->op.add.message->dn));
			if (value == NULL) {
				return ldb_oom(ldb);
			}

			return ldb_module_send_referral(req, value);
		}
	}

	/* the various objectclasses must be specified on add operations */
	if (ldb_msg_find_element(req->op.add.message, "objectClass") == NULL) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot add %s, no objectclass specified!",
				       ldb_dn_get_linearized(req->op.add.message->dn));
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* If there isn't a parent, just go on to the add processing */
	if (ldb_dn_get_comp_num(ac->req->op.add.message->dn) == 1) {
		return objectclass_do_add(ac);
	}

	/* get copy of parent DN */
	parent_dn = ldb_dn_get_parent(ac, ac->req->op.add.message->dn);
	if (parent_dn == NULL) {
		return ldb_oom(ldb);
	}

	ret = ldb_build_search_req(&search_req, ldb,
				   ac, parent_dn, LDB_SCOPE_BASE,
				   "(objectClass=*)", parent_attrs,
				   NULL,
				   ac, get_search_callback,
				   req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step_fn = objectclass_do_add;

	return ldb_next_request(ac->module, search_req);
}

static int objectclass_do_add(struct oc_context *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *add_req;
	struct ldb_message_element *objectclass_element, *el;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	struct class_list *sorted, *current;
	const char *rdn_name = NULL;
	char *value;
	const struct dsdb_class *objectclass;
	int32_t systemFlags = 0;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	msg = ldb_msg_copy_shallow(ac, ac->req->op.add.message);

	/* Check if we have a valid parent - this check is needed since
	 * we don't get a LDB_ERR_NO_SUCH_OBJECT error. */
	if (ac->search_res == NULL) {
		if (ldb_dn_compare(ldb_get_root_basedn(ldb), msg->dn) == 0) {
			/* Allow the tree to be started but don't keep any
			 * error strings - they're meaningless. */
			ldb_set_errstring(ldb, NULL);
		} else {
			ldb_asprintf_errstring(ldb, "objectclass: Cannot add %s, parent does not exist!", 
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_NO_SUCH_OBJECT;
		}
	} else {
		/* Fix up the DN to be in the standard form, taking
		 * particular care to match the parent DN */
		ret = fix_dn(ldb, msg,
			     ac->req->op.add.message->dn,
			     ac->search_res->message->dn,
			     &msg->dn);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(ldb, "objectclass: Could not munge DN %s into normal form",
					       ldb_dn_get_linearized(ac->req->op.add.message->dn));
			return ret;
		}
	}

	mem_ctx = talloc_new(ac);
	if (mem_ctx == NULL) {
		return ldb_oom(ldb);
	}

	if (ac->schema != NULL) {
		/* This is now the objectClass list from the database */
		objectclass_element = ldb_msg_find_element(msg, "objectClass");

		if (!objectclass_element) {
			/* Where did it go?  bail now... */
			talloc_free(mem_ctx);
			return ldb_operr(ldb);
		}
		ret = objectclass_sort(ac->module, ac->schema, mem_ctx,
				       objectclass_element, &sorted);
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
			value = talloc_strdup(msg, current->objectclass->lDAPDisplayName);
			if (value == NULL) {
				talloc_free(mem_ctx);
				return ldb_oom(ldb);
			}
			ret = ldb_msg_add_string(msg, "objectClass", value);
			if (ret != LDB_SUCCESS) {
				ldb_set_errstring(ldb,
						  "objectclass: could not re-add sorted "
						  "objectclass to modify msg");
				talloc_free(mem_ctx);
				return ret;
			}
		}

		/* Retrive the message again so get_last_structural_class works */
		objectclass_element = ldb_msg_find_element(msg, "objectClass");

		/* Make sure its valid to add an object of this type */
		objectclass = get_last_structural_class(ac->schema,
							objectclass_element);
		if(objectclass == NULL) {
			ldb_asprintf_errstring(ldb,
					       "Failed to find a structural class for %s",
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		rdn_name = ldb_dn_get_rdn_name(msg->dn);
		if (objectclass->rDNAttID
			&& ldb_attr_cmp(rdn_name, objectclass->rDNAttID) != 0) {
			ldb_asprintf_errstring(ldb,
						"RDN %s is not correct for most specific structural objectclass %s, should be %s",
						rdn_name, objectclass->lDAPDisplayName, objectclass->rDNAttID);
			return LDB_ERR_NAMING_VIOLATION;
		}

		if (ac->search_res && ac->search_res->message) {
			struct ldb_message_element *oc_el
				= ldb_msg_find_element(ac->search_res->message, "objectClass");

			bool allowed_class = false;
			unsigned int i, j;
			for (i=0; allowed_class == false && oc_el && i < oc_el->num_values; i++) {
				const struct dsdb_class *sclass;

				sclass = dsdb_class_by_lDAPDisplayName_ldb_val(ac->schema,
									       &oc_el->values[i]);
				if (!sclass) {
					/* We don't know this class?  what is going on? */
					continue;
				}
				for (j=0; sclass->systemPossibleInferiors && sclass->systemPossibleInferiors[j]; j++) {
					if (ldb_attr_cmp(objectclass->lDAPDisplayName, sclass->systemPossibleInferiors[j]) == 0) {
						allowed_class = true;
						break;
					}
				}
			}

			if (!allowed_class) {
				ldb_asprintf_errstring(ldb, "structural objectClass %s is not a valid child class for %s",
						objectclass->lDAPDisplayName, ldb_dn_get_linearized(ac->search_res->message->dn));
				return LDB_ERR_NAMING_VIOLATION;
			}
		}

		if (objectclass->systemOnly && !ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID)) {
			ldb_asprintf_errstring(ldb, "objectClass %s is systemOnly, rejecting creation of %s",
						objectclass->lDAPDisplayName, ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		if (!ldb_msg_find_element(msg, "objectCategory")) {
			struct dsdb_extended_dn_store_format *dn_format = talloc_get_type(ldb_module_get_private(ac->module), struct dsdb_extended_dn_store_format);
			if (dn_format && dn_format->store_extended_dn_in_ldb == false) {
				/* Strip off extended components */
				struct ldb_dn *dn = ldb_dn_new(msg, ldb, objectclass->defaultObjectCategory);
				value = ldb_dn_alloc_linearized(msg, dn);
				talloc_free(dn);
			} else {
				value = talloc_strdup(msg, objectclass->defaultObjectCategory);
			}
			if (value == NULL) {
				talloc_free(mem_ctx);
				return ldb_oom(ldb);
			}
			ldb_msg_add_string(msg, "objectCategory", value);
		}
		if (!ldb_msg_find_element(msg, "showInAdvancedViewOnly") && (objectclass->defaultHidingValue == true)) {
			ldb_msg_add_string(msg, "showInAdvancedViewOnly",
						"TRUE");
		}

		/* There are very special rules for systemFlags, see MS-ADTS 3.1.1.5.2.4 */
		el = ldb_msg_find_element(msg, "systemFlags");

		systemFlags = ldb_msg_find_attr_as_int(msg, "systemFlags", 0);

		if (el) {
			/* Only these flags may be set by a client, but we can't tell between a client and our provision at this point */
			/* systemFlags &= ( SYSTEM_FLAG_CONFIG_ALLOW_RENAME | SYSTEM_FLAG_CONFIG_ALLOW_MOVE | SYSTEM_FLAG_CONFIG_LIMITED_MOVE); */
			ldb_msg_remove_element(msg, el);
		}

		/* This flag is only allowed on attributeSchema objects */
		if (ldb_attr_cmp(objectclass->lDAPDisplayName, "attributeSchema") == 0) {
			systemFlags &= ~SYSTEM_FLAG_ATTR_IS_RDN;
		}

		if (ldb_attr_cmp(objectclass->lDAPDisplayName, "server") == 0) {
			systemFlags |= (int32_t)(SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE | SYSTEM_FLAG_CONFIG_ALLOW_RENAME | SYSTEM_FLAG_CONFIG_ALLOW_LIMITED_MOVE);
		} else if (ldb_attr_cmp(objectclass->lDAPDisplayName, "site") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "serverContainer") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "ntDSDSA") == 0) {
			systemFlags |= (int32_t)(SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE);

		} else if (ldb_attr_cmp(objectclass->lDAPDisplayName, "siteLink") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "siteLinkBridge") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "nTDSConnection") == 0) {
			systemFlags |= (int32_t)(SYSTEM_FLAG_CONFIG_ALLOW_RENAME);
		}

		/* TODO: If parent object is site or subnet, also add (SYSTEM_FLAG_CONFIG_ALLOW_RENAME) */

		if (el || systemFlags != 0) {
			samdb_msg_add_int(ldb, msg, msg, "systemFlags", systemFlags);
		}
	}

	talloc_free(mem_ctx);
	ret = ldb_msg_sanity_check(ldb, msg);


	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_build_add_req(&add_req, ldb, ac,
				msg,
				ac->req->controls,
				ac, oc_op_callback,
				ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* perform the add */
	return ldb_next_request(ac->module, add_req);
}

static int oc_modify_callback(struct ldb_request *req,
				struct ldb_reply *ares);
static int objectclass_do_mod(struct oc_context *ac);

static int objectclass_modify(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct ldb_message_element *objectclass_element;
	struct ldb_message *msg;
	struct ldb_request *down_req;
	struct oc_context *ac;
	bool oc_changes = false;
	int ret;

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_modify\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	/* As with the "real" AD we don't accept empty messages */
	if (req->op.mod.message->num_elements == 0) {
		ldb_set_errstring(ldb, "objectclass: modify message must have "
				       "elements/attributes!");
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* Without schema, there isn't much to do here */
	if (ac->schema == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	msg = ldb_msg_copy_shallow(ac, req->op.mod.message);
	if (msg == NULL) {
		return ldb_operr(ldb);
	}

	/* For now change everything except the objectclasses */

	objectclass_element = ldb_msg_find_element(msg, "objectClass");
	if (objectclass_element != NULL) {
		ldb_msg_remove_attr(msg, "objectClass");
		oc_changes = true;
	}

	ret = ldb_build_mod_req(&down_req, ldb, ac,
				msg,
				req->controls, ac,
				oc_changes ? oc_modify_callback : oc_op_callback,
				req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(module, down_req);
}

static int oc_modify_callback(struct ldb_request *req, struct ldb_reply *ares)
{
	static const char * const attrs[] = { "objectClass", NULL };
	struct ldb_context *ldb;
	struct ldb_request *search_req;
	struct oc_context *ac;
	int ret;

	ac = talloc_get_type(req->context, struct oc_context);
	ldb = ldb_module_get_ctx(ac->module);

	if (!ares) {
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	if (ares->type == LDB_REPLY_REFERRAL) {
		return ldb_module_send_referral(ac->req, ares->referral);
	}

	if (ares->error != LDB_SUCCESS) {
		return ldb_module_done(ac->req, ares->controls,
					ares->response, ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
					LDB_ERR_OPERATIONS_ERROR);
	}

	talloc_free(ares);

	/* this looks up the real existing object for fetching some important
	 * informations (objectclasses) */
	ret = ldb_build_search_req(&search_req, ldb,
				   ac, ac->req->op.mod.message->dn,
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL, 
				   ac, get_search_callback,
				   ac->req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	ac->step_fn = objectclass_do_mod;

	ret = ldb_next_request(ac->module, search_req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	return LDB_SUCCESS;
}

static int objectclass_do_mod(struct oc_context *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *mod_req;
	char *value;
	struct ldb_message_element *oc_el_entry, *oc_el_change;
	struct ldb_val *vals;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	struct class_list *sorted, *current;
	const struct dsdb_class *objectclass;
	unsigned int i, j;
	bool found, replace = false;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	/* we should always have a valid entry when we enter here */
	if (ac->search_res == NULL) {
		return ldb_operr(ldb);
	}

	oc_el_entry = ldb_msg_find_element(ac->search_res->message,
					   "objectClass");
	if (oc_el_entry == NULL) {
		/* existing entry without a valid object class? */
		return ldb_operr(ldb);
	}

	oc_el_change = ldb_msg_find_element(ac->req->op.mod.message,
					    "objectClass");
	if (oc_el_change == NULL) {
		/* we should have an objectclass change operation */
		return ldb_operr(ldb);
	}

	/* use a new message structure */
	msg = ldb_msg_new(ac);
	if (msg == NULL) {
		return ldb_oom(ldb);
	}

	msg->dn = ac->req->op.mod.message->dn;

	mem_ctx = talloc_new(ac);
	if (mem_ctx == NULL) {
		return ldb_oom(ldb);
	}

	switch (oc_el_change->flags & LDB_FLAG_MOD_MASK) {
	case LDB_FLAG_MOD_ADD:
		/* Merge the two message elements */
		for (i = 0; i < oc_el_change->num_values; i++) {
			for (j = 0; j < oc_el_entry->num_values; j++) {
				if (strcasecmp((char *)oc_el_change->values[i].data,
					       (char *)oc_el_entry->values[j].data) == 0) {
					/* we cannot add an already existing object class */
					talloc_free(mem_ctx);
					return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
				}
			}
			/* append the new object class value - code was copied
			 * from "ldb_msg_add_value" */
			vals = talloc_realloc(oc_el_entry, oc_el_entry->values,
					      struct ldb_val,
					      oc_el_entry->num_values + 1);
			if (vals == NULL) {
				talloc_free(mem_ctx);
				return ldb_oom(ldb);
			}
			oc_el_entry->values = vals;
			oc_el_entry->values[oc_el_entry->num_values] =
				oc_el_change->values[i];
			++(oc_el_entry->num_values);
		}

		objectclass = get_last_structural_class(ac->schema,
							oc_el_change);
		if (objectclass != NULL) {
			/* we cannot add a new structural object class */
			talloc_free(mem_ctx);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}

		/* Now do the sorting */
		ret = objectclass_sort(ac->module, ac->schema, mem_ctx,
				       oc_el_entry, &sorted);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}

		break;

	case LDB_FLAG_MOD_REPLACE:
		/* Do the sorting for the change message element */
		ret = objectclass_sort(ac->module, ac->schema, mem_ctx,
				       oc_el_change, &sorted);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}

		/* this is a replace */
		replace = true;

		break;

	case LDB_FLAG_MOD_DELETE:
		/* get the actual top-most structural objectclass */
		objectclass = get_last_structural_class(ac->schema,
							oc_el_entry);
		if (objectclass == NULL) {
			talloc_free(mem_ctx);
			return ldb_operr(ldb);
		}

		/* Merge the two message elements */
		for (i = 0; i < oc_el_change->num_values; i++) {
			found = false;
			for (j = 0; j < oc_el_entry->num_values; j++) {
				if (strcasecmp((char *)oc_el_change->values[i].data,
					       (char *)oc_el_entry->values[j].data) == 0) {
					found = true;
					/* delete the object class value -
					 * code was copied from
					 * "ldb_msg_remove_element" */
					if (j != oc_el_entry->num_values - 1) {
						memmove(&oc_el_entry->values[j],
							&oc_el_entry->values[j+1],
							((oc_el_entry->num_values-1) - j)*sizeof(struct ldb_val));
					}
					--(oc_el_entry->num_values);
					break;
				}
			}
			if (!found) {
				/* we cannot delete a not existing object class */
				talloc_free(mem_ctx);
				return LDB_ERR_NO_SUCH_ATTRIBUTE;
			}
		}

		/* Make sure that the top-most structural objectclass wasn't
		 * deleted */
		found = false;
		for (i = 0; i < oc_el_entry->num_values; i++) {
			if (strcasecmp(objectclass->lDAPDisplayName,
			    (char *)oc_el_entry->values[i].data) == 0) {
				found = true; break;
			}
		}
		if (!found) {
			talloc_free(mem_ctx);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}


		/* Now do the sorting */
		ret = objectclass_sort(ac->module, ac->schema, mem_ctx,
				       oc_el_entry, &sorted);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}

		break;
	}

	ret = ldb_msg_add_empty(msg, "objectClass",
				LDB_FLAG_MOD_REPLACE, &oc_el_change);
	if (ret != LDB_SUCCESS) {
		ldb_oom(ldb);
		talloc_free(mem_ctx);
		return ret;
	}

	/* Move from the linked list back into an ldb msg */
	for (current = sorted; current; current = current->next) {
		value = talloc_strdup(msg,
				      current->objectclass->lDAPDisplayName);
		if (value == NULL) {
			talloc_free(mem_ctx);
			return ldb_oom(ldb);
		}
		ret = ldb_msg_add_string(msg, "objectClass", value);
		if (ret != LDB_SUCCESS) {
			ldb_set_errstring(ldb, "objectclass: could not re-add sorted objectclass to modify msg");
			talloc_free(mem_ctx);
			return ret;
		}
	}

	talloc_free(mem_ctx);

	if (replace) {
		/* Well, on replace we are nearly done: we have to test if
		 * the change and entry message element are identically. We
		 * can use "ldb_msg_element_compare" since now the specified
		 * objectclasses match for sure in case. */
		ret = ldb_msg_element_compare(oc_el_entry, oc_el_change);
		if (ret == 0) {
			ret = ldb_msg_element_compare(oc_el_change,
						      oc_el_entry);
		}
		if (ret == 0) {
			/* they are the same so we are done in this case */
			return ldb_module_done(ac->req, NULL, NULL,
					       LDB_SUCCESS);
		} else {
			/* they're not exactly the same */
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}
	}

	/* in the other cases we have the real change left to do */

	ret = ldb_msg_sanity_check(ldb, msg);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_build_mod_req(&mod_req, ldb, ac,
				msg,
				ac->req->controls,
				ac, oc_op_callback,
				ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, mod_req);
}

static int objectclass_do_rename(struct oc_context *ac);

static int objectclass_rename(struct ldb_module *module, struct ldb_request *req)
{
	static const char * const attrs[] = { "objectClass", NULL };
	struct ldb_context *ldb;
	struct ldb_request *search_req;
	struct oc_context *ac;
	struct ldb_dn *parent_dn;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_rename\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.rename.newdn)) {
		return ldb_next_request(module, req);
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	parent_dn = ldb_dn_get_parent(ac, req->op.rename.newdn);
	if (parent_dn == NULL) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot rename %s, the parent DN does not exist!",
				       ldb_dn_get_linearized(req->op.rename.olddn));
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	/* this looks up the parent object for fetching some important
	 * informations (objectclasses, DN normalisation...) */
	ret = ldb_build_search_req(&search_req, ldb,
				   ac, parent_dn, LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL,
				   ac, get_search_callback,
				   req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* we have to add the show deleted control, as otherwise DRS
	   deletes will be refused as we will think the target parent
	   does not exist */
	ret = ldb_request_add_control(search_req, LDB_CONTROL_SHOW_DELETED_OID, false, NULL);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step_fn = objectclass_do_rename;

	return ldb_next_request(ac->module, search_req);
}

static int objectclass_do_rename2(struct oc_context *ac);

static int objectclass_do_rename(struct oc_context *ac)
{
	static const char * const attrs[] = { "objectClass", NULL };
	struct ldb_context *ldb;
	struct ldb_request *search_req;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	/* Check if we have a valid parent - this check is needed since
	 * we don't get a LDB_ERR_NO_SUCH_OBJECT error. */
	if (ac->search_res == NULL) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot rename %s, parent does not exist!",
				       ldb_dn_get_linearized(ac->req->op.rename.olddn));
		return LDB_ERR_OTHER;
	}

	/* now assign "search_res2" to the parent entry to have "search_res"
	 * free for another lookup */
	ac->search_res2 = ac->search_res;
	ac->search_res = NULL;

	/* this looks up the real existing object for fetching some important
	 * informations (objectclasses) */
	ret = ldb_build_search_req(&search_req, ldb,
				   ac, ac->req->op.rename.olddn,
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL,
				   ac, get_search_callback,
				   ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step_fn = objectclass_do_rename2;

	return ldb_next_request(ac->module, search_req);
}

static int objectclass_do_rename2(struct oc_context *ac)
{
	struct ldb_context *ldb;
	struct ldb_request *rename_req;
	struct ldb_dn *fixed_dn;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	/* Check if we have a valid entry - this check is needed since
	 * we don't get a LDB_ERR_NO_SUCH_OBJECT error. */
	if (ac->search_res == NULL) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot rename %s, entry does not exist!",
				       ldb_dn_get_linearized(ac->req->op.rename.olddn));
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	if (ac->schema != NULL) {
		struct ldb_message_element *oc_el_entry, *oc_el_parent;
		const struct dsdb_class *objectclass;
		const char *rdn_name;
		bool allowed_class = false;
		unsigned int i, j;

		oc_el_entry = ldb_msg_find_element(ac->search_res->message,
						   "objectClass");
		if (oc_el_entry == NULL) {
			/* existing entry without a valid object class? */
			return ldb_operr(ldb);
		}
		objectclass = get_last_structural_class(ac->schema, oc_el_entry);
		if (objectclass == NULL) {
			/* existing entry without a valid object class? */
			return ldb_operr(ldb);
		}

		rdn_name = ldb_dn_get_rdn_name(ac->req->op.rename.newdn);
		if ((objectclass->rDNAttID != NULL) &&
		    (ldb_attr_cmp(rdn_name, objectclass->rDNAttID) != 0)) {
			ldb_asprintf_errstring(ldb,
					       "objectclass: RDN %s is not correct for most specific structural objectclass %s, should be %s",
					       rdn_name,
					       objectclass->lDAPDisplayName,
					       objectclass->rDNAttID);
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		oc_el_parent = ldb_msg_find_element(ac->search_res2->message,
						    "objectClass");
		if (oc_el_parent == NULL) {
			/* existing entry without a valid object class? */
			return ldb_operr(ldb);
		}

		for (i=0; allowed_class == false && i < oc_el_parent->num_values; i++) {
			const struct dsdb_class *sclass;

			sclass = dsdb_class_by_lDAPDisplayName_ldb_val(ac->schema,
								       &oc_el_parent->values[i]);
			if (!sclass) {
				/* We don't know this class?  what is going on? */
				continue;
			}
			for (j=0; sclass->systemPossibleInferiors && sclass->systemPossibleInferiors[j]; j++) {
				if (ldb_attr_cmp(objectclass->lDAPDisplayName, sclass->systemPossibleInferiors[j]) == 0) {
					allowed_class = true;
					break;
				}
			}
		}

		if (!allowed_class) {
			ldb_asprintf_errstring(ldb,
					       "objectclass: structural objectClass %s is not a valid child class for %s",
					       objectclass->lDAPDisplayName, ldb_dn_get_linearized(ac->search_res2->message->dn));
			return LDB_ERR_NAMING_VIOLATION;
		}
	}

	/* Ensure we are not trying to rename it to be a child of itself */
	if ((ldb_dn_compare_base(ac->req->op.rename.olddn,
				 ac->req->op.rename.newdn) == 0)  &&
	    (ldb_dn_compare(ac->req->op.rename.olddn,
			    ac->req->op.rename.newdn) != 0)) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot rename %s to be a child of itself",
				       ldb_dn_get_linearized(ac->req->op.rename.olddn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* Fix up the DN to be in the standard form, taking
	 * particular care to match the parent DN */
	ret = fix_dn(ldb, ac,
		     ac->req->op.rename.newdn,
		     ac->search_res2->message->dn,
		     &fixed_dn);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(ldb, "objectclass: Could not munge DN %s into normal form",
				       ldb_dn_get_linearized(ac->req->op.rename.newdn));
		return ret;

	}

	ret = ldb_build_rename_req(&rename_req, ldb, ac,
				   ac->req->op.rename.olddn, fixed_dn,
				   ac->req->controls,
				   ac, oc_op_callback,
				   ac->req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* perform the rename */
	return ldb_next_request(ac->module, rename_req);
}

static int objectclass_do_delete(struct oc_context *ac);

static int objectclass_delete(struct ldb_module *module, struct ldb_request *req)
{
	static const char * const attrs[] = { "systemFlags", NULL };
	struct ldb_context *ldb;
	struct ldb_request *search_req;
	struct oc_context *ac;
	int ret;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_delete\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.del.dn)) {
		return ldb_next_request(module, req);
	}

	/* Bypass the "systemFlags" checks when we do have the "RELAX" control
	 * set. */
	if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID) != NULL) {
		return ldb_next_request(module, req);
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* this looks up the entry object for fetching some important
	 * informations (systemFlags...) */
	ret = ldb_build_search_req(&search_req, ldb,
				   ac, req->op.del.dn, LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL,
				   ac, get_search_callback,
				   req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step_fn = objectclass_do_delete;

	return ldb_next_request(ac->module, search_req);
}

static int objectclass_do_delete(struct oc_context *ac)
{
	struct ldb_context *ldb;
	int32_t systemFlags;

	ldb = ldb_module_get_ctx(ac->module);

	/* Check if we have a valid entry - this check is needed since
	 * we don't get a LDB_ERR_NO_SUCH_OBJECT error. */
	if (ac->search_res == NULL) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot delete %s, entry does not exist!",
				       ldb_dn_get_linearized(ac->req->op.del.dn));
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	systemFlags = ldb_msg_find_attr_as_int(ac->search_res->message,
					       "systemFlags", 0);
	if ((systemFlags & SYSTEM_FLAG_DISALLOW_DELETE) != 0) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot delete %s, it isn't permitted!",
				       ldb_dn_get_linearized(ac->req->op.del.dn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	return ldb_next_request(ac->module, ac->req);
}

static int objectclass_init(struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	int ret;

	/* Init everything else */
	ret = ldb_next_init(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	
	/* Look for the opaque to indicate we might have to cut down the DN of defaultObjectCategory */
	ldb_module_set_private(module, ldb_get_opaque(ldb, DSDB_EXTENDED_DN_STORE_FORMAT_OPAQUE_NAME));

	return ret;
}

_PUBLIC_ const struct ldb_module_ops ldb_objectclass_module_ops = {
	.name		= "objectclass",
	.add		= objectclass_add,
	.modify		= objectclass_modify,
	.rename		= objectclass_rename,
	.del		= objectclass_delete,
	.init_context	= objectclass_init
};
