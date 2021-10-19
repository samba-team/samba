/* 
   ldb database library

   Copyright (C) Simo Sorce  2006-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Matthias Dieter Wallnöfer 2010-2011

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
#include "dsdb/samdb/samdb.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "auth/auth.h"
#include "param/param.h"
#include "../libds/common/flags.h"
#include "dsdb/samdb/ldb_modules/util.h"

struct oc_context {

	struct ldb_module *module;
	struct ldb_request *req;
	const struct dsdb_schema *schema;

	struct ldb_reply *search_res;
	struct ldb_reply *search_res2;

	int (*step_fn)(struct oc_context *);
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

/*
 * This checks if we have unrelated object classes in our entry's "objectClass"
 * attribute. That means "unsatisfied" abstract classes (no concrete subclass)
 * or two or more disjunct structural ones.
 * If one of these conditions are true, blame.
 */
static int check_unrelated_objectclasses(struct ldb_module *module,
					const struct dsdb_schema *schema,
					const struct dsdb_class *struct_objectclass,
					struct ldb_message_element *objectclass_element)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	unsigned int i;
	bool found;

	if (schema == NULL) {
		return LDB_SUCCESS;
	}

	for (i = 0; i < objectclass_element->num_values; i++) {
		const struct dsdb_class *tmp_class = dsdb_class_by_lDAPDisplayName_ldb_val(schema,
											   &objectclass_element->values[i]);
		const struct dsdb_class *tmp_class2 = struct_objectclass;

		/* Pointer comparison can be used due to the same schema str. */
		if (tmp_class == NULL ||
		    tmp_class == struct_objectclass ||
		    tmp_class->objectClassCategory > 2 ||
		    ldb_attr_cmp(tmp_class->lDAPDisplayName, "top") == 0) {
			continue;
		}

		found = false;
		while (!found &&
		       ldb_attr_cmp(tmp_class2->lDAPDisplayName, "top") != 0) {
			tmp_class2 = dsdb_class_by_lDAPDisplayName(schema,
								   tmp_class2->subClassOf);
			if (tmp_class2 == tmp_class) {
				found = true;
			}
		}
		if (found) {
			continue;
		}

		ldb_asprintf_errstring(ldb,
				       "objectclass: the objectclass '%s' seems to be unrelated to %s!",
				       tmp_class->lDAPDisplayName,
				       struct_objectclass->lDAPDisplayName);
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	return LDB_SUCCESS;
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

	/* Fix up the DN to be in the standard form, taking particular care to
	 * match the parent DN */
	*fixed_dn = ldb_dn_copy(mem_ctx, parent_dn);
	if (*fixed_dn == NULL) {
		return ldb_oom(ldb);
	}

	/* We need the attribute name in upper case */
	upper_rdn_attr = strupper_talloc(*fixed_dn, 
					 ldb_dn_get_rdn_name(newdn));
	if (upper_rdn_attr == NULL) {
		return ldb_oom(ldb);
	}

	/* Create a new child */
	if (ldb_dn_add_child_fmt(*fixed_dn, "X=X") == false) {
		return ldb_operr(ldb);
	}

	rdn_val = ldb_dn_get_rdn_val(newdn);
	if (rdn_val == NULL) {
		return ldb_operr(ldb);
	}

#if 0
	/* the rules for rDN length constraints are more complex than
	this. Until we understand them we need to leave this
	constraint out. Otherwise we break replication, as windows
	does sometimes send us rDNs longer than 64 */
	if (!rdn_val || rdn_val->length > 64) {
		DEBUG(2,(__location__ ": WARNING: rDN longer than 64 limit for '%s'\n", ldb_dn_get_linearized(newdn)));
	}
#endif


	/* And replace it with CN=foo (we need the attribute in upper case) */
	return ldb_dn_set_component(*fixed_dn, 0, upper_rdn_attr, *rdn_val);
}


static int objectclass_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_request *search_req;
	struct oc_context *ac;
	struct ldb_dn *parent_dn;
	const struct ldb_val *val;
	int ret;
	static const char * const parent_attrs[] = { "objectClass", NULL };

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_add\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	/* An add operation on the basedn without "NC-add" operation isn't
	 * allowed. */
	if (ldb_dn_compare(ldb_get_default_basedn(ldb), req->op.add.message->dn) == 0) {
		unsigned int instanceType;

		instanceType = ldb_msg_find_attr_as_uint(req->op.add.message,
							 "instanceType", 0);
		if (!(instanceType & INSTANCE_TYPE_IS_NC_HEAD)) {
			char *referral_uri;
			/* When we are trying to readd the root basedn then
			 * this is denied, but with an interesting mechanism:
			 * there is generated a referral with the last
			 * component value as hostname. */
			val = ldb_dn_get_component_val(req->op.add.message->dn,
						       ldb_dn_get_comp_num(req->op.add.message->dn) - 1);
			if (val == NULL) {
				return ldb_operr(ldb);
			}
			referral_uri = talloc_asprintf(req, "ldap://%s/%s", val->data,
						       ldb_dn_get_linearized(req->op.add.message->dn));
			if (referral_uri == NULL) {
				return ldb_module_oom(module);
			}

			return ldb_module_send_referral(req, referral_uri);
		}
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
		return ldb_operr(ldb);
	}

	ret = ldb_build_search_req(&search_req, ldb,
				   ac, parent_dn, LDB_SCOPE_BASE,
				   "(objectClass=*)", parent_attrs,
				   NULL,
				   ac, get_search_callback,
				   req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_request_add_controls(search_req,
					DSDB_FLAG_AS_SYSTEM |
					DSDB_SEARCH_SHOW_RECYCLED);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step_fn = objectclass_do_add;

	return ldb_next_request(ac->module, search_req);
}


/*
  check if this is a special RODC nTDSDSA add
 */
static bool check_rodc_ntdsdsa_add(struct oc_context *ac,
				   const struct dsdb_class *objectclass)
{
	struct ldb_control *rodc_control;

	if (ldb_attr_cmp(objectclass->lDAPDisplayName, "nTDSDSA") != 0) {
		return false;
	}
	rodc_control = ldb_request_get_control(ac->req, LDB_CONTROL_RODC_DCPROMO_OID);
	if (!rodc_control) {
		return false;
	}

	rodc_control->critical = false;
	return true;
}

static int objectclass_do_add(struct oc_context *ac)
{
	struct ldb_context *ldb = ldb_module_get_ctx(ac->module);
	struct ldb_request *add_req;
	struct ldb_message_element *objectclass_element, *el;
	struct ldb_message *msg;
	const char *rdn_name = NULL;
	char *value;
	const struct dsdb_class *objectclass;
	struct ldb_dn *objectcategory;
	int32_t systemFlags = 0;
	unsigned int i, j;
	bool found;
	int ret;

	msg = ldb_msg_copy_shallow(ac, ac->req->op.add.message);
	if (msg == NULL) {
		return ldb_module_oom(ac->module);
	}

	/* Check if we have a valid parent - this check is needed since
	 * we don't get a LDB_ERR_NO_SUCH_OBJECT error. */
	if (ac->search_res == NULL) {
		unsigned int instanceType;

		/* An add operation on partition DNs without "NC-add" operation
		 * isn't allowed. */
		instanceType = ldb_msg_find_attr_as_uint(msg, "instanceType",
							 0);
		if (!(instanceType & INSTANCE_TYPE_IS_NC_HEAD)) {
			ldb_asprintf_errstring(ldb, "objectclass: Cannot add %s, parent does not exist!", 
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_NO_SUCH_OBJECT;
		}

		/* Don't keep any error messages - we've to add a partition */
		ldb_set_errstring(ldb, NULL);
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

	if (ac->schema != NULL) {
		unsigned int linkID = 0;
		/*
		 * Notice: by the normalization function call in "ldb_request()"
		 * case "LDB_ADD" we have always only *one* "objectClass"
		 * attribute at this stage!
		 */

		objectclass_element = ldb_msg_find_element(msg, "objectClass");
		if (!objectclass_element) {
			ldb_asprintf_errstring(ldb, "objectclass: Cannot add %s, no objectclass specified!",
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}
		if (objectclass_element->num_values == 0) {
			ldb_asprintf_errstring(ldb, "objectclass: Cannot add %s, at least one (structural) objectclass has to be specified!",
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		/* Now do the sorting */
		ret = dsdb_sort_objectClass_attr(ldb, ac->schema,
						 objectclass_element, msg,
						 objectclass_element);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/*
		 * Get the new top-most structural object class and check for
		 * unrelated structural classes
		 */
		objectclass = dsdb_get_last_structural_class(ac->schema,
							     objectclass_element);
		if (objectclass == NULL) {
			ldb_asprintf_errstring(ldb,
					       "Failed to find a structural class for %s",
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		ret = check_unrelated_objectclasses(ac->module, ac->schema,
						    objectclass,
						    objectclass_element);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		rdn_name = ldb_dn_get_rdn_name(msg->dn);
		if (rdn_name == NULL) {
			return ldb_operr(ldb);
		}
		found = false;
		for (i = 0; (!found) && (i < objectclass_element->num_values);
		     i++) {
			const struct dsdb_class *tmp_class =
				dsdb_class_by_lDAPDisplayName_ldb_val(ac->schema,
								      &objectclass_element->values[i]);

			if (tmp_class == NULL) continue;

			if (ldb_attr_cmp(rdn_name, tmp_class->rDNAttID) == 0)
				found = true;
		}
		if (!found) {
			ldb_asprintf_errstring(ldb,
					       "objectclass: Invalid RDN '%s' for objectclass '%s'!",
					       rdn_name, objectclass->lDAPDisplayName);
			return LDB_ERR_NAMING_VIOLATION;
		}

		if (objectclass->systemOnly &&
		    !ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID) &&
		    !check_rodc_ntdsdsa_add(ac, objectclass)) {
			ldb_asprintf_errstring(ldb,
					       "objectclass: object class '%s' is system-only, rejecting creation of '%s'!",
					       objectclass->lDAPDisplayName,
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		if (ac->search_res && ac->search_res->message) {
			struct ldb_message_element *oc_el
				= ldb_msg_find_element(ac->search_res->message, "objectClass");

			bool allowed_class = false;
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

		objectcategory = ldb_msg_find_attr_as_dn(ldb, ac, msg,
							 "objectCategory");
		if (objectcategory == NULL) {
			struct dsdb_extended_dn_store_format *dn_format =
					talloc_get_type(ldb_module_get_private(ac->module),
							struct dsdb_extended_dn_store_format);
			if (dn_format && dn_format->store_extended_dn_in_ldb == false) {
				/* Strip off extended components */
				struct ldb_dn *dn = ldb_dn_new(ac, ldb,
							       objectclass->defaultObjectCategory);
				value = ldb_dn_alloc_linearized(msg, dn);
				talloc_free(dn);
			} else {
				value = talloc_strdup(msg,
						      objectclass->defaultObjectCategory);
			}
			if (value == NULL) {
				return ldb_module_oom(ac->module);
			}

			ret = ldb_msg_add_string(msg, "objectCategory", value);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		} else {
			const struct dsdb_class *ocClass =
					dsdb_class_by_cn_ldb_val(ac->schema,
								 ldb_dn_get_rdn_val(objectcategory));
			if (ocClass != NULL) {
				struct ldb_dn *dn = ldb_dn_new(ac, ldb,
							       ocClass->defaultObjectCategory);
				if (ldb_dn_compare(objectcategory, dn) != 0) {
					ocClass = NULL;
				}
			}
			talloc_free(objectcategory);
			if (ocClass == NULL) {
				ldb_asprintf_errstring(ldb, "objectclass: Cannot add %s, 'objectCategory' attribute invalid!",
						       ldb_dn_get_linearized(msg->dn));
				return LDB_ERR_OBJECT_CLASS_VIOLATION;
			}
		}

		if (!ldb_msg_find_element(msg, "showInAdvancedViewOnly") && (objectclass->defaultHidingValue == true)) {
			ldb_msg_add_string(msg, "showInAdvancedViewOnly",
						"TRUE");
		}

		/* There are very special rules for systemFlags, see MS-ADTS
		 * MS-ADTS 3.1.1.5.2.4 */

		el = ldb_msg_find_element(msg, "systemFlags");
		if ((el != NULL) && (el->num_values > 1)) {
			ldb_asprintf_errstring(ldb, "objectclass: Cannot add %s, 'systemFlags' attribute multivalued!",
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		systemFlags = ldb_msg_find_attr_as_int(msg, "systemFlags", 0);

		ldb_msg_remove_attr(msg, "systemFlags");

		/* Only the following flags may be set by a client */
		if (ldb_request_get_control(ac->req,
					    LDB_CONTROL_RELAX_OID) == NULL) {
			systemFlags &= ( SYSTEM_FLAG_CONFIG_ALLOW_RENAME
				       | SYSTEM_FLAG_CONFIG_ALLOW_MOVE
				       | SYSTEM_FLAG_CONFIG_ALLOW_LIMITED_MOVE
				       | SYSTEM_FLAG_ATTR_IS_RDN );
		}

		/* But the last one ("ATTR_IS_RDN") is only allowed on
		 * "attributeSchema" objects. So truncate if it does not fit. */
		if (ldb_attr_cmp(objectclass->lDAPDisplayName, "attributeSchema") != 0) {
			systemFlags &= ~SYSTEM_FLAG_ATTR_IS_RDN;
		}

		if (ldb_attr_cmp(objectclass->lDAPDisplayName, "server") == 0) {
			systemFlags |= (int32_t)(SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE | SYSTEM_FLAG_CONFIG_ALLOW_RENAME | SYSTEM_FLAG_CONFIG_ALLOW_LIMITED_MOVE);
		} else if (ldb_attr_cmp(objectclass->lDAPDisplayName, "site") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "serversContainer") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "nTDSDSA") == 0) {
			if (ldb_attr_cmp(objectclass->lDAPDisplayName, "site") == 0)
				systemFlags |= (int32_t)(SYSTEM_FLAG_CONFIG_ALLOW_RENAME);
			systemFlags |= (int32_t)(SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE);
		} else if (ldb_attr_cmp(objectclass->lDAPDisplayName, "siteLink") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "subnet") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "siteLinkBridge") == 0
				|| ldb_attr_cmp(objectclass->lDAPDisplayName, "nTDSConnection") == 0) {
			systemFlags |= (int32_t)(SYSTEM_FLAG_CONFIG_ALLOW_RENAME);
		}
		/* TODO: If parent object is site or subnet, also add (SYSTEM_FLAG_CONFIG_ALLOW_RENAME) */

		linkID = ldb_msg_find_attr_as_int(msg, "linkID", 0);
		if (linkID > 0 && linkID % 2 == 1) {
			systemFlags |= DS_FLAG_ATTR_NOT_REPLICATED;
		}

		if (el || systemFlags != 0) {
			ret = samdb_msg_add_int(ldb, msg, msg, "systemFlags",
						systemFlags);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}

		/* make sure that "isCriticalSystemObject" is not specified! */
		el = ldb_msg_find_element(msg, "isCriticalSystemObject");
		if ((el != NULL) &&
                    !ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID)) {
			ldb_set_errstring(ldb,
					  "objectclass: 'isCriticalSystemObject' must not be specified!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}

	ret = ldb_build_add_req(&add_req, ldb, ac,
				msg,
				ac->req->controls,
				ac->req, dsdb_next_callback,
				ac->req);
	LDB_REQ_SET_LOCATION(add_req);
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
		return ldb_module_oom(ac->module);
	}

	/* For now change everything except the objectclasses */

	objectclass_element = ldb_msg_find_element(msg, "objectClass");
	if (objectclass_element != NULL) {
		ldb_msg_remove_attr(msg, "objectClass");
		oc_changes = true;
	}

	/* MS-ADTS 3.1.1.5.3.5 - on a forest level < 2003 we do allow updates
	 * only on application NCs - not on the default ones */
	if (oc_changes &&
	    (dsdb_forest_functional_level(ldb) < DS_DOMAIN_FUNCTION_2003)) {
		struct ldb_dn *nc_root;

		ret = dsdb_find_nc_root(ldb, ac, req->op.mod.message->dn,
					&nc_root);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		if ((ldb_dn_compare(nc_root, ldb_get_default_basedn(ldb)) == 0) ||
		    (ldb_dn_compare(nc_root, ldb_get_config_basedn(ldb)) == 0) ||
		    (ldb_dn_compare(nc_root, ldb_get_schema_basedn(ldb)) == 0)) {
			ldb_set_errstring(ldb,
					  "objectclass: object class changes on objects under the standard name contexts not allowed!");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		talloc_free(nc_root);
	}

	if (oc_changes) {
		ret = ldb_build_mod_req(&down_req, ldb, ac,
					msg,
					req->controls, ac,
					oc_modify_callback,
					req);
	} else {
		ret = ldb_build_mod_req(&down_req, ldb, ac,
					msg,
					req->controls, req,
					dsdb_next_callback,
					req);
	}
	LDB_REQ_SET_LOCATION(down_req);
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
	 * information (objectclasses) */
	ret = ldb_build_search_req(&search_req, ldb,
				   ac, ac->req->op.mod.message->dn,
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL, 
				   ac, get_search_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	ret = dsdb_request_add_controls(search_req,
					DSDB_FLAG_AS_SYSTEM |
					DSDB_SEARCH_SHOW_RECYCLED);
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
	struct ldb_message_element *oc_el_entry, *oc_el_change;
	struct ldb_val *vals;
	struct ldb_message *msg;
	const struct dsdb_class *current_structural_objectclass;
	const struct dsdb_class *objectclass;
	unsigned int i, j, k;
	bool found;
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

	/*
	 * Get the current new top-most structural object class
	 *
	 * We must not allow this to change
	 */

	current_structural_objectclass
		= dsdb_get_last_structural_class(ac->schema,
						 oc_el_entry);
	if (current_structural_objectclass == NULL) {
		ldb_asprintf_errstring(ldb,
				       "objectclass: cannot find current structural objectclass on %s!",
				       ldb_dn_get_linearized(ac->search_res->message->dn));
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	/* use a new message structure */
	msg = ldb_msg_new(ac);
	if (msg == NULL) {
		return ldb_module_oom(ac->module);
	}

	msg->dn = ac->req->op.mod.message->dn;

	/* We've to walk over all "objectClass" message elements */
	for (k = 0; k < ac->req->op.mod.message->num_elements; k++) {
		if (ldb_attr_cmp(ac->req->op.mod.message->elements[k].name,
				 "objectClass") != 0) {
			continue;
		}

		oc_el_change = &ac->req->op.mod.message->elements[k];

		switch (oc_el_change->flags & LDB_FLAG_MOD_MASK) {
		case LDB_FLAG_MOD_ADD:
			/* Merge the two message elements */
			for (i = 0; i < oc_el_change->num_values; i++) {
				for (j = 0; j < oc_el_entry->num_values; j++) {
					if (ldb_attr_cmp((char *)oc_el_change->values[i].data,
							 (char *)oc_el_entry->values[j].data) == 0) {
						ldb_asprintf_errstring(ldb,
								       "objectclass: cannot re-add an existing objectclass: '%.*s'!",
								       (int)oc_el_change->values[i].length,
								       (const char *)oc_el_change->values[i].data);
						return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
					}
				}
				/* append the new object class value - code was
				 * copied from "ldb_msg_add_value" */
				vals = talloc_realloc(oc_el_entry, oc_el_entry->values,
						      struct ldb_val,
						      oc_el_entry->num_values + 1);
				if (vals == NULL) {
					return ldb_module_oom(ac->module);
				}
				oc_el_entry->values = vals;
				oc_el_entry->values[oc_el_entry->num_values] =
							oc_el_change->values[i];
				++(oc_el_entry->num_values);
			}

			break;

		case LDB_FLAG_MOD_REPLACE:
			/*
			 * In this case the new "oc_el_entry" is simply
			 * "oc_el_change"
			 */
			oc_el_entry = oc_el_change;

			break;

		case LDB_FLAG_MOD_DELETE:
			/* Merge the two message elements */
			for (i = 0; i < oc_el_change->num_values; i++) {
				found = false;
				for (j = 0; j < oc_el_entry->num_values; j++) {
					if (ldb_attr_cmp((char *)oc_el_change->values[i].data,
							 (char *)oc_el_entry->values[j].data) == 0) {
						found = true;
						/* delete the object class value
						 * - code was copied from
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
					/* we cannot delete a not existing
					 * object class */
					ldb_asprintf_errstring(ldb,
							       "objectclass: cannot delete this objectclass: '%.*s'!",
							       (int)oc_el_change->values[i].length,
							       (const char *)oc_el_change->values[i].data);
					return LDB_ERR_NO_SUCH_ATTRIBUTE;
				}
			}

			break;
		}

		/* Now do the sorting */
		ret = dsdb_sort_objectClass_attr(ldb, ac->schema, oc_el_entry,
						 msg, oc_el_entry);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		/*
		 * Get the new top-most structural object class and check for
		 * unrelated structural classes
		 */
		objectclass = dsdb_get_last_structural_class(ac->schema,
							     oc_el_entry);
		if (objectclass == NULL) {
			ldb_set_errstring(ldb,
					  "objectclass: cannot delete all structural objectclasses!");
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}

		/*
		 * Has (so far, we re-check for each and every
		 * "objectclass" in the message) the structural
		 * objectclass changed?
		 */

		if (objectclass != current_structural_objectclass) {
			const char *dn
				= ldb_dn_get_linearized(ac->search_res->message->dn);
			ldb_asprintf_errstring(ldb,
					       "objectclass: not permitted "
					       "to change the structural "
					       "objectClass on %s [%s] => [%s]!",
					       dn,
					       current_structural_objectclass->lDAPDisplayName,
					       objectclass->lDAPDisplayName);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}

		/* Check for unrelated objectclasses */
		ret = check_unrelated_objectclasses(ac->module, ac->schema,
						    objectclass,
						    oc_el_entry);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* Now add the new object class attribute to the change message */
	ret = ldb_msg_add(msg, oc_el_entry, LDB_FLAG_MOD_REPLACE);
	if (ret != LDB_SUCCESS) {
		ldb_module_oom(ac->module);
		return ret;
	}

	/* Now we have the real and definitive change left to do */

	ret = ldb_build_mod_req(&mod_req, ldb, ac,
				msg,
				ac->req->controls,
				ac->req, dsdb_next_callback,
				ac->req);
	LDB_REQ_SET_LOCATION(mod_req);
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
	if (ldb_dn_is_special(req->op.rename.olddn)) {
		return ldb_next_request(module, req);
	}

	/*
	 * Bypass the constraint checks when we do have the "DBCHECK" control
	 * set, so we can force objects under the deleted objects container.
	 */
	if (ldb_request_get_control(req, DSDB_CONTROL_DBCHECK) != NULL) {
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
	 * information (objectclasses, DN normalisation...) */
	ret = ldb_build_search_req(&search_req, ldb,
				   ac, parent_dn, LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL,
				   ac, get_search_callback,
				   req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* we have to add the show recycled control, as otherwise DRS
	   deletes will be refused as we will think the target parent
	   does not exist */
	ret = dsdb_request_add_controls(search_req,
					DSDB_FLAG_AS_SYSTEM |
					DSDB_SEARCH_SHOW_RECYCLED);
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
	 * information (objectclasses) */
	ret = ldb_build_search_req(&search_req, ldb,
				   ac, ac->req->op.rename.olddn,
				   LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL,
				   ac, get_search_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_request_add_controls(search_req,
					DSDB_FLAG_AS_SYSTEM |
					DSDB_SEARCH_SHOW_RECYCLED);
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
		bool found;

		oc_el_entry = ldb_msg_find_element(ac->search_res->message,
						   "objectClass");
		if (oc_el_entry == NULL) {
			/* existing entry without a valid object class? */
			return ldb_operr(ldb);
		}
		objectclass = dsdb_get_last_structural_class(ac->schema,
							     oc_el_entry);
		if (objectclass == NULL) {
			/* existing entry without a valid object class? */
			return ldb_operr(ldb);
		}

		rdn_name = ldb_dn_get_rdn_name(ac->req->op.rename.newdn);
		if (rdn_name == NULL) {
			return ldb_operr(ldb);
		}
		found = false;
		for (i = 0; (!found) && (i < oc_el_entry->num_values); i++) {
			const struct dsdb_class *tmp_class =
				dsdb_class_by_lDAPDisplayName_ldb_val(ac->schema,
								      &oc_el_entry->values[i]);

			if (tmp_class == NULL) continue;

			if (ldb_attr_cmp(rdn_name, tmp_class->rDNAttID) == 0)
				found = true;
		}
		if (!found) {
			ldb_asprintf_errstring(ldb,
					       "objectclass: Invalid RDN '%s' for objectclass '%s'!",
					       rdn_name, objectclass->lDAPDisplayName);
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
				   ac->req, dsdb_next_callback,
				   ac->req);
	LDB_REQ_SET_LOCATION(rename_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* perform the rename */
	return ldb_next_request(ac->module, rename_req);
}

static int objectclass_do_delete(struct oc_context *ac);

static int objectclass_delete(struct ldb_module *module, struct ldb_request *req)
{
	static const char * const attrs[] = { "nCName", "objectClass",
					      "systemFlags",
					      "isDeleted",
					      "isCriticalSystemObject", NULL };
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

	/* Bypass the constraint checks when we do have the "RELAX" control
	 * set. */
	if (ldb_request_get_control(req, LDB_CONTROL_RELAX_OID) != NULL) {
		return ldb_next_request(module, req);
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* this looks up the entry object for fetching some important
	 * information (object classes, system flags...) */
	ret = ldb_build_search_req(&search_req, ldb,
				   ac, req->op.del.dn, LDB_SCOPE_BASE,
				   "(objectClass=*)",
				   attrs, NULL,
				   ac, get_search_callback,
				   req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_request_add_controls(search_req,
					DSDB_FLAG_AS_SYSTEM |
					DSDB_SEARCH_SHOW_RECYCLED);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ac->step_fn = objectclass_do_delete;

	return ldb_next_request(ac->module, search_req);
}

static int objectclass_do_delete(struct oc_context *ac)
{
	struct ldb_context *ldb;
	struct ldb_dn *dn;
	int32_t systemFlags;
	bool isCriticalSystemObject;
	int ret;

	ldb = ldb_module_get_ctx(ac->module);

	/* Check if we have a valid entry - this check is needed since
	 * we don't get a LDB_ERR_NO_SUCH_OBJECT error. */
	if (ac->search_res == NULL) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot delete %s, entry does not exist!",
				       ldb_dn_get_linearized(ac->req->op.del.dn));
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	/* DC's ntDSDSA object */
	if (ldb_dn_compare(ac->req->op.del.dn, samdb_ntds_settings_dn(ldb, ac)) == 0) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot delete %s, it's the DC's ntDSDSA object!",
				       ldb_dn_get_linearized(ac->req->op.del.dn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* DC's rIDSet object */
	/* Perform this check only when it does exist - this is needed in order
	 * to don't let existing provisions break, and to delete . */
	ret = samdb_rid_set_dn(ldb, ac, &dn);
	if ((ret != LDB_SUCCESS) && (ret != LDB_ERR_NO_SUCH_ATTRIBUTE)
	    && (ret != LDB_ERR_NO_SUCH_OBJECT)) {
		ldb_asprintf_errstring(ldb, "objectclass: Unable to determine if %s, is this DC's rIDSet object: %s ",
				       ldb_dn_get_linearized(ac->req->op.del.dn),
				       ldb_errstring(ldb));
		return ret;
	}
	if (ret == LDB_SUCCESS) {
		if (ldb_dn_compare(ac->req->op.del.dn, dn) == 0) {
			talloc_free(dn);
			ldb_asprintf_errstring(ldb, "objectclass: Cannot delete %s, it's the DC's rIDSet object!",
					       ldb_dn_get_linearized(ac->req->op.del.dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		talloc_free(dn);
	}

	/* Only trusted request from system account are allowed to delete
	 * deleted objects.
	 */
	if (ldb_msg_check_string_attribute(ac->search_res->message, "isDeleted", "TRUE") &&
			(ldb_req_is_untrusted(ac->req) ||
				!dsdb_module_am_system(ac->module))) {
		ldb_asprintf_errstring(ldb, "Delete of '%s' failed",
						ldb_dn_get_linearized(ac->req->op.del.dn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* crossRef objects regarding config, schema and default domain NCs */
	if (samdb_find_attribute(ldb, ac->search_res->message, "objectClass",
				 "crossRef") != NULL) {
		dn = ldb_msg_find_attr_as_dn(ldb, ac, ac->search_res->message,
					     "nCName");
		if ((ldb_dn_compare(dn, ldb_get_default_basedn(ldb)) == 0) ||
		    (ldb_dn_compare(dn, ldb_get_config_basedn(ldb)) == 0)) {
			talloc_free(dn);

			ldb_asprintf_errstring(ldb, "objectclass: Cannot delete %s, it's a crossRef object to the main or configuration partition!",
					       ldb_dn_get_linearized(ac->req->op.del.dn));
			return LDB_ERR_NOT_ALLOWED_ON_NON_LEAF;
		}
		if (ldb_dn_compare(dn, ldb_get_schema_basedn(ldb)) == 0) {
			talloc_free(dn);

			ldb_asprintf_errstring(ldb, "objectclass: Cannot delete %s, it's a crossRef object to the schema partition!",
					       ldb_dn_get_linearized(ac->req->op.del.dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
		talloc_free(dn);
	}

	/* systemFlags */

	systemFlags = ldb_msg_find_attr_as_int(ac->search_res->message,
					       "systemFlags", 0);
	if ((systemFlags & SYSTEM_FLAG_DISALLOW_DELETE) != 0) {
		ldb_asprintf_errstring(ldb, "objectclass: Cannot delete %s, it isn't permitted!",
				       ldb_dn_get_linearized(ac->req->op.del.dn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}

	/* isCriticalSystemObject - but this only applies on tree delete
	 * operations - MS-ADTS 3.1.1.5.5.7.2 */
	if (ldb_request_get_control(ac->req, LDB_CONTROL_TREE_DELETE_OID) != NULL) {
		isCriticalSystemObject = ldb_msg_find_attr_as_bool(ac->search_res->message,
								   "isCriticalSystemObject", false);
		if (isCriticalSystemObject) {
			/*
			 * Following the explaination from Microsoft
			 * https://lists.samba.org/archive/cifs-protocol/2011-August/002046.html
			 * "I finished the investigation on this behavior.
			 * As per MS-ADTS 3.1.5.5.7.2 , when a tree deletion is performed ,
			 * every object in the tree will be checked to see if it has isCriticalSystemObject
			 * set to TRUE, including the root node on which the delete operation is performed
			 * But there is an exception  if the root object is a SAM specific objects(3.1.1.5.2.3 MS-ADTS)
			 * Its deletion is done through SAM manger and isCriticalSystemObject attribute is not checked
			 * The root node of the tree delete in your case is CN=ARES,OU=Domain Controllers,DC=w2k8r2,DC=home,DC=matws,DC=net
			 * which is a SAM object  with  user class.  Therefore the tree deletion is performed without any error
			 */

			if (samdb_find_attribute(ldb, ac->search_res->message, "objectClass", "group") == NULL &&
			    samdb_find_attribute(ldb, ac->search_res->message, "objectClass", "samDomain") == NULL &&
			    samdb_find_attribute(ldb, ac->search_res->message, "objectClass", "samServer") == NULL &&
			    samdb_find_attribute(ldb, ac->search_res->message, "objectClass", "user") == NULL) {
					ldb_asprintf_errstring(ldb,
					       "objectclass: Cannot tree-delete %s, it's a critical system object!",
					       ldb_dn_get_linearized(ac->req->op.del.dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
			}
		}
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

	ret = ldb_mod_register_control(module, LDB_CONTROL_RODC_DCPROMO_OID);
	if (ret != LDB_SUCCESS) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  "objectclass_init: Unable to register control DCPROMO with rootdse\n");
		return ldb_operr(ldb);
	}

	return ret;
}

static const struct ldb_module_ops ldb_objectclass_module_ops = {
	.name		= "objectclass",
	.add		= objectclass_add,
	.modify		= objectclass_modify,
	.rename		= objectclass_rename,
	.del		= objectclass_delete,
	.init_context	= objectclass_init
};

int ldb_objectclass_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_objectclass_module_ops);
}
