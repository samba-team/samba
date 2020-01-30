/*
   ldb database library

   Copyright (C) Simo Sorce  2006-2008
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Matthias Dieter Wallnöfer 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: objectclass attribute checking module
 *
 *  Description: this checks the attributes on a directory entry (if they're
 *    allowed, if the syntax is correct, if mandatory ones are missing,
 *    denies the deletion of mandatory ones...). The module contains portions
 *    of the "objectclass" and the "validate_update" LDB module.
 *
 *  Author: Matthias Dieter Wallnöfer
 */

#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"

struct oc_context {

	struct ldb_module *module;
	struct ldb_request *req;
	const struct dsdb_schema *schema;

	struct ldb_message *msg;

	struct ldb_reply *search_res;
	struct ldb_reply *mod_ares;
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

static int oc_op_callback(struct ldb_request *req, struct ldb_reply *ares);

/*
 * Checks the correctness of the "dSHeuristics" attribute as described in both
 * MS-ADTS 7.1.1.2.4.1.2 dSHeuristics and MS-ADTS 3.1.1.5.3.2 Constraints
 */
static int oc_validate_dsheuristics(struct ldb_message_element *el)
{
	if (el->num_values > 0) {
		if ((el->values[0].length >= DS_HR_NINETIETH_CHAR) &&
		    (el->values[0].data[DS_HR_NINETIETH_CHAR-1] != '9')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ((el->values[0].length >= DS_HR_EIGHTIETH_CHAR) &&
		    (el->values[0].data[DS_HR_EIGHTIETH_CHAR-1] != '8')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ((el->values[0].length >= DS_HR_SEVENTIETH_CHAR) &&
		    (el->values[0].data[DS_HR_SEVENTIETH_CHAR-1] != '7')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ((el->values[0].length >= DS_HR_SIXTIETH_CHAR) &&
		    (el->values[0].data[DS_HR_SIXTIETH_CHAR-1] != '6')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ((el->values[0].length >= DS_HR_FIFTIETH_CHAR) &&
		    (el->values[0].data[DS_HR_FIFTIETH_CHAR-1] != '5')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ((el->values[0].length >= DS_HR_FOURTIETH_CHAR) &&
		    (el->values[0].data[DS_HR_FOURTIETH_CHAR-1] != '4')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ((el->values[0].length >= DS_HR_THIRTIETH_CHAR) &&
		    (el->values[0].data[DS_HR_THIRTIETH_CHAR-1] != '3')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ((el->values[0].length >= DS_HR_TWENTIETH_CHAR) &&
		    (el->values[0].data[DS_HR_TWENTIETH_CHAR-1] != '2')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		if ((el->values[0].length >= DS_HR_TENTH_CHAR) &&
		    (el->values[0].data[DS_HR_TENTH_CHAR-1] != '1')) {
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
	}

	return LDB_SUCCESS;
}

/*
  auto normalise values on input
 */
static int oc_auto_normalise(struct ldb_context *ldb, const struct dsdb_attribute *attr,
			     struct ldb_message *msg, struct ldb_message_element *el)
{
	int i;
	bool values_copied = false;

	for (i=0; i<el->num_values; i++) {
		struct ldb_val v;
		int ret;
		/*
		 * We use msg->elements (owned by this module due to
		 * ldb_msg_copy_shallow()) as a memory context and
		 * then steal from there to the right spot if we don't
		 * free it.
		 */
		ret = attr->ldb_schema_attribute->syntax->canonicalise_fn(ldb,
									  msg->elements,
									  &el->values[i],
									  &v);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		if (data_blob_cmp(&v, &el->values[i]) == 0) {
			/* no need to replace it */
			talloc_free(v.data);
			continue;
		}

		/* we need to copy the values array on the first change */
		if (!values_copied) {
			struct ldb_val *v2;
			v2 = talloc_array(msg->elements, struct ldb_val, el->num_values);
			if (v2 == NULL) {
				return ldb_oom(ldb);
			}
			memcpy(v2, el->values, sizeof(struct ldb_val) * el->num_values);
			el->values = v2;
			values_copied = true;
		}

		el->values[i] = v;

		/*
		 * By now el->values is a talloc pointer under
		 * msg->elements and may now be used
		 */
		talloc_steal(el->values, v.data);
	}
	return LDB_SUCCESS;
}

static int attr_handler(struct oc_context *ac)
{
	struct ldb_context *ldb;
	struct ldb_message *msg;
	struct ldb_request *child_req;
	const struct dsdb_attribute *attr;
	unsigned int i;
	int ret;
	WERROR werr;
	struct dsdb_syntax_ctx syntax_ctx;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->req->operation == LDB_ADD) {
		msg = ldb_msg_copy_shallow(ac, ac->req->op.add.message);
	} else {
		msg = ldb_msg_copy_shallow(ac, ac->req->op.mod.message);
	}
	if (msg == NULL) {
		return ldb_oom(ldb);
	}
	ac->msg = msg;

	/* initialize syntax checking context */
	dsdb_syntax_ctx_init(&syntax_ctx, ldb, ac->schema);

	/* Check if attributes exist in the schema, if the values match,
	 * if they're not operational and fix the names to the match the schema
	 * case */
	for (i = 0; i < msg->num_elements; i++) {
		attr = dsdb_attribute_by_lDAPDisplayName(ac->schema,
							 msg->elements[i].name);
		if (attr == NULL) {
			if (ldb_request_get_control(ac->req, DSDB_CONTROL_DBCHECK) &&
			    ac->req->operation != LDB_ADD) {
				/* we allow this for dbcheck to fix
				   broken attributes */
				goto no_attribute;
			}
			ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' was not found in the schema!",
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		}

		if ((attr->linkID & 1) == 1 &&
		    !ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID) &&
		    !ldb_request_get_control(ac->req, DSDB_CONTROL_DBCHECK)) {
			/* Odd is for the target.  Illegal to modify */
			ldb_asprintf_errstring(ldb, 
					       "objectclass_attrs: attribute '%s' on entry '%s' must not be modified directly, it is a linked attribute", 
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		/*
		 * Enforce systemOnly checks from [ADTS] 3.1.1.5.3.2
		 * Constraints in Modify Operation
		 */
		if (ac->req->operation == LDB_MODIFY && attr->systemOnly) {
			/*
			 * Allow dbcheck and relax to bypass. objectClass, name
			 * and distinguishedName are generally handled
			 * elsewhere.
			 *
			 * The remaining cases, undelete, msDS-AdditionalDnsHostName
			 * and wellKnownObjects are documented in the specification.
			 */
			if (!ldb_request_get_control(ac->req, LDB_CONTROL_RELAX_OID) &&
			    !ldb_request_get_control(ac->req, DSDB_CONTROL_DBCHECK) &&
			    !ldb_request_get_control(ac->req, DSDB_CONTROL_RESTORE_TOMBSTONE_OID) &&
			    ldb_attr_cmp(attr->lDAPDisplayName, "objectClass") != 0 &&
			    ldb_attr_cmp(attr->lDAPDisplayName, "name") != 0 &&
			    ldb_attr_cmp(attr->lDAPDisplayName, "distinguishedName") != 0 &&
			    ldb_attr_cmp(attr->lDAPDisplayName, "msDS-AdditionalDnsHostName") != 0 &&
			    ldb_attr_cmp(attr->lDAPDisplayName, "wellKnownObjects") != 0) {
				/*
				 * Comparison against base schema DN is used as a substitute for
				 * fschemaUpgradeInProgress and other specific schema checks.
				 */
				if (ldb_dn_compare_base(ldb_get_schema_basedn(ldb), msg->dn) != 0) {
					struct ldb_control *as_system = ldb_request_get_control(ac->req,
												LDB_CONTROL_AS_SYSTEM_OID);
					if (!dsdb_module_am_system(ac->module) && !as_system) {
						ldb_asprintf_errstring(ldb,
								       "objectclass_attrs: attribute '%s' on entry '%s' must can only be modified as system",
								       msg->elements[i].name,
								       ldb_dn_get_linearized(msg->dn));
						return LDB_ERR_CONSTRAINT_VIOLATION;
					}
				}
			}
		}

		if (!(msg->elements[i].flags & LDB_FLAG_INTERNAL_DISABLE_VALIDATION)) {
			werr = attr->syntax->validate_ldb(&syntax_ctx, attr,
							  &msg->elements[i]);
			if (!W_ERROR_IS_OK(werr) &&
			    !ldb_request_get_control(ac->req, DSDB_CONTROL_DBCHECK)) {
				ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' contains at least one invalid value!",
						       msg->elements[i].name,
						       ldb_dn_get_linearized(msg->dn));
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}
		}

		if ((attr->systemFlags & DS_FLAG_ATTR_IS_CONSTRUCTED) != 0) {
			ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' is constructed!",
					       msg->elements[i].name,
					       ldb_dn_get_linearized(msg->dn));
			if (ac->req->operation == LDB_ADD) {
				return LDB_ERR_UNDEFINED_ATTRIBUTE_TYPE;
			} else {
				return LDB_ERR_CONSTRAINT_VIOLATION;
			}
		}

		/* "dSHeuristics" syntax check */
		if (ldb_attr_cmp(attr->lDAPDisplayName, "dSHeuristics") == 0) {
			ret = oc_validate_dsheuristics(&(msg->elements[i]));
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}

		/* auto normalise some attribute values */
		if (attr->syntax->auto_normalise) {
			ret = oc_auto_normalise(ldb, attr, msg, &msg->elements[i]);
			if (ret != LDB_SUCCESS) {
				return ret;
			}
		}

		/* Substitute the attribute name to match in case */
		msg->elements[i].name = attr->lDAPDisplayName;
	}

no_attribute:
	if (ac->req->operation == LDB_ADD) {
		ret = ldb_build_add_req(&child_req, ldb, ac,
					msg, ac->req->controls,
					ac, oc_op_callback, ac->req);
		LDB_REQ_SET_LOCATION(child_req);
	} else {
		ret = ldb_build_mod_req(&child_req, ldb, ac,
					msg, ac->req->controls,
					ac, oc_op_callback, ac->req);
		LDB_REQ_SET_LOCATION(child_req);
	}
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return ldb_next_request(ac->module, child_req);
}

/*
  these are attributes which are left over from old ways of doing
  things in ldb, and are harmless
 */
static const char *harmless_attrs[] = { "parentGUID", NULL };

static int attr_handler2(struct oc_context *ac)
{
	struct ldb_context *ldb;
	struct ldb_message_element *oc_element;
	struct ldb_message *msg;
	const char **must_contain, **may_contain, **found_must_contain;
	/* There exists a hardcoded delete-protected attributes list in AD */
	const char *del_prot_attributes[] = { "nTSecurityDescriptor",
		"objectSid", "sAMAccountType", "sAMAccountName", "groupType",
		"primaryGroupID", "userAccountControl", "accountExpires",
		"badPasswordTime", "badPwdCount", "codePage", "countryCode",
		"lastLogoff", "lastLogon", "logonCount", "pwdLastSet", NULL },
		**l;
	const struct dsdb_attribute *attr;
	unsigned int i;
	bool found;
	bool isSchemaAttr = false;

	ldb = ldb_module_get_ctx(ac->module);

	if (ac->search_res == NULL) {
		return ldb_operr(ldb);
	}

	/* We rely here on the preceding "objectclass" LDB module which did
	 * already fix up the objectclass list (inheritance, order...). */
	oc_element = ldb_msg_find_element(ac->search_res->message,
					  "objectClass");
	if (oc_element == NULL) {
		return ldb_operr(ldb);
	}

	/* LSA-specific object classes are not allowed to be created over LDAP,
	 * so we need to tell if this connection is internal (trusted) or not
	 * (untrusted).
	 *
	 * Hongwei Sun from Microsoft explains:
	 * The constraint in 3.1.1.5.2.2 MS-ADTS means that LSA objects cannot
	 * be added or modified through the LDAP interface, instead they can
	 * only be handled through LSA Policy API.  This is also explained in
	 * 7.1.6.9.7 MS-ADTS as follows:
	 * "Despite being replicated normally between peer DCs in a domain,
	 * the process of creating or manipulating TDOs is specifically
	 * restricted to the LSA Policy APIs, as detailed in [MS-LSAD] section
	 * 3.1.1.5. Unlike other objects in the DS, TDOs may not be created or
	 *  manipulated by client machines over the LDAPv3 transport."
	 */
	for (i = 0; i < oc_element->num_values; i++) {
		char * attname = (char *)oc_element->values[i].data;
		if (ldb_req_is_untrusted(ac->req)) {
			if (strcmp(attname, "secret") == 0 ||
			    strcmp(attname, "trustedDomain") == 0) {
				ldb_asprintf_errstring(ldb, "objectclass_attrs: LSA objectclasses (entry '%s') cannot be created or changed over LDAP!",
						       ldb_dn_get_linearized(ac->search_res->message->dn));
				return LDB_ERR_UNWILLING_TO_PERFORM;
			}
		}
		if (strcmp(attname, "attributeSchema") == 0) {
			isSchemaAttr = true;
		}
	}

	must_contain = dsdb_full_attribute_list(ac, ac->schema, oc_element,
						DSDB_SCHEMA_ALL_MUST);
	may_contain =  dsdb_full_attribute_list(ac, ac->schema, oc_element,
						DSDB_SCHEMA_ALL_MAY);
	found_must_contain = const_str_list(str_list_copy(ac, must_contain));
	if ((must_contain == NULL) || (may_contain == NULL)
	    || (found_must_contain == NULL)) {
		return ldb_operr(ldb);
	}

	/* Check the delete-protected attributes list */
	msg = ac->search_res->message;
	for (l = del_prot_attributes; *l != NULL; l++) {
		struct ldb_message_element *el;

		el = ldb_msg_find_element(ac->msg, *l);
		if (el == NULL) {
			/*
			 * It was not specified in the add or modify,
			 * so it doesn't need to be in the stored record
			 */
			continue;
		}

		found = str_list_check_ci(must_contain, *l);
		if (!found) {
			found = str_list_check_ci(may_contain, *l);
		}
		if (found && (ldb_msg_find_element(msg, *l) == NULL)) {
			ldb_asprintf_errstring(ldb, "objectclass_attrs: delete protected attribute '%s' on entry '%s' missing!",
					       *l,
					       ldb_dn_get_linearized(msg->dn));
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}

	/* Check if all specified attributes are valid in the given
	 * objectclasses and if they meet additional schema restrictions. */
	for (i = 0; i < msg->num_elements; i++) {
		attr = dsdb_attribute_by_lDAPDisplayName(ac->schema,
							 msg->elements[i].name);
		if (attr == NULL) {
			if (ldb_request_get_control(ac->req, DSDB_CONTROL_DBCHECK)) {
				/* allow this to make it possible for dbcheck
				   to remove bad attributes */
				continue;
			}
			return ldb_operr(ldb);
		}

		/* We can use "str_list_check" with "strcmp" here since the
		 * attribute information from the schema are always equal
		 * up-down-cased. */
		found = str_list_check(must_contain, attr->lDAPDisplayName);
		if (found) {
			str_list_remove(found_must_contain, attr->lDAPDisplayName);
		} else {
			found = str_list_check(may_contain, attr->lDAPDisplayName);
		}
		if (!found) {
			found = str_list_check(harmless_attrs, attr->lDAPDisplayName);
		}
		if (!found) {
			/* we allow this for dbcheck to fix the rest of this broken entry */
			if (!ldb_request_get_control(ac->req, DSDB_CONTROL_DBCHECK) || 
			    ac->req->operation == LDB_ADD) {
				ldb_asprintf_errstring(ldb, "objectclass_attrs: attribute '%s' on entry '%s' does not exist in the specified objectclasses!",
						       msg->elements[i].name,
						       ldb_dn_get_linearized(msg->dn));
				return LDB_ERR_OBJECT_CLASS_VIOLATION;
			}
		}
	}

	/*
	 * We skip this check under dbcheck to allow fixing of other
	 * attributes even if an attribute is missing.  This matters
	 * for CN=RID Set as the required attribute rIDNextRid is not
	 * replicated.
	 */
	if (found_must_contain[0] != NULL &&
	    ldb_msg_check_string_attribute(msg, "isDeleted", "TRUE") == 0) {

		for (i = 0; found_must_contain[i] != NULL; i++) {
			const struct dsdb_attribute *broken_attr = dsdb_attribute_by_lDAPDisplayName(ac->schema,
												     found_must_contain[i]);

			bool replicated = (broken_attr->systemFlags &
					   (DS_FLAG_ATTR_NOT_REPLICATED | DS_FLAG_ATTR_IS_CONSTRUCTED)) == 0;

			if (replicated) {
				ldb_asprintf_errstring(ldb, "objectclass_attrs: at least one mandatory "
						       "attribute ('%s') on entry '%s' wasn't specified!",
						       found_must_contain[i],
						       ldb_dn_get_linearized(msg->dn));
				return LDB_ERR_OBJECT_CLASS_VIOLATION;
			}
		}
	}

	if (isSchemaAttr) {
		/*
		 * Before really adding an attribute in the database,
		 * let's check that we can translate it into a dsdb_attribute and
		 * that we can find a valid syntax object.
		 * If not it's better to reject this attribute than not be able
		 * to start samba next time due to schema being unloadable.
		 */
		struct dsdb_attribute *att = talloc(ac, struct dsdb_attribute);
		const struct dsdb_syntax *attrSyntax;
		WERROR status;

		status = dsdb_attribute_from_ldb(NULL, msg, att);
		if (!W_ERROR_IS_OK(status)) {
			ldb_set_errstring(ldb,
						"objectclass: failed to translate the schemaAttribute to a dsdb_attribute");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}

		attrSyntax = dsdb_syntax_for_attribute(att);
		if (!attrSyntax) {
			ldb_set_errstring(ldb,
						"objectclass: unknown attribute syntax");
			return LDB_ERR_UNWILLING_TO_PERFORM;
		}
	}
	return ldb_module_done(ac->req, ac->mod_ares->controls,
			       ac->mod_ares->response, LDB_SUCCESS);
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
	if (ares->error != LDB_SUCCESS) {
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
		ret = attr_handler2(ac);
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
	struct ldb_context *ldb;
	struct ldb_request *search_req;
	struct ldb_dn *base_dn;
	int ret;
	static const char *attrs[] = {"nTSecurityDescriptor", "*", NULL};

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
		return ldb_module_done(ac->req, ares->controls, ares->response,
				       ares->error);
	}

	if (ares->type != LDB_REPLY_DONE) {
		talloc_free(ares);
		return ldb_module_done(ac->req, NULL, NULL,
				       LDB_ERR_OPERATIONS_ERROR);
	}

	ac->search_res = NULL;
	ac->mod_ares = talloc_steal(ac, ares);

	/* This looks up all attributes of our just added/modified entry */
	base_dn = ac->req->operation == LDB_ADD ? ac->req->op.add.message->dn
		: ac->req->op.mod.message->dn;
	ret = ldb_build_search_req(&search_req, ldb, ac, base_dn,
				   LDB_SCOPE_BASE, "(objectClass=*)",
				   attrs, NULL, ac,
				   get_search_callback, ac->req);
	LDB_REQ_SET_LOCATION(search_req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	ret = ldb_request_add_control(search_req, LDB_CONTROL_SHOW_RECYCLED_OID,
				      true, NULL);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	/*
	 * This ensures we see if there was a DN, that pointed at an
	 * object that is now deleted, that we still consider the
	 * schema check to have passed
	 */
	ret = ldb_request_add_control(search_req, LDB_CONTROL_REVEAL_INTERNALS,
				      false, NULL);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	ret = ldb_next_request(ac->module, search_req);
	if (ret != LDB_SUCCESS) {
		return ldb_module_done(ac->req, NULL, NULL, ret);
	}

	/* "ldb_module_done" isn't called here since we need to do additional
	 * checks. It is called at the end of "attr_handler2". */
	return LDB_SUCCESS;
}

static int objectclass_attrs_add(struct ldb_module *module,
				 struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct oc_context *ac;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_attrs_add\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* without schema, there isn't much to do here */
	if (ac->schema == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	return attr_handler(ac);
}

static int objectclass_attrs_modify(struct ldb_module *module,
				    struct ldb_request *req)
{
	struct ldb_context *ldb;
	struct ldb_control *sd_propagation_control;
	int ret;

	struct oc_context *ac;

	ldb = ldb_module_get_ctx(module);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "objectclass_attrs_modify\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.mod.message->dn)) {
		return ldb_next_request(module, req);
	}

	sd_propagation_control = ldb_request_get_control(req,
					DSDB_CONTROL_SEC_DESC_PROPAGATION_OID);
	if (sd_propagation_control != NULL) {
		if (req->op.mod.message->num_elements != 1) {
			return ldb_module_operr(module);
		}
		ret = strcmp(req->op.mod.message->elements[0].name,
			     "nTSecurityDescriptor");
		if (ret != 0) {
			return ldb_module_operr(module);
		}

		return ldb_next_request(module, req);
	}

	ac = oc_init_context(module, req);
	if (ac == NULL) {
		return ldb_operr(ldb);
	}

	/* without schema, there isn't much to do here */
	if (ac->schema == NULL) {
		talloc_free(ac);
		return ldb_next_request(module, req);
	}

	return attr_handler(ac);
}

static const struct ldb_module_ops ldb_objectclass_attrs_module_ops = {
	.name		   = "objectclass_attrs",
	.add               = objectclass_attrs_add,
	.modify            = objectclass_attrs_modify
};

int ldb_objectclass_attrs_module_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_objectclass_attrs_module_ops);
}
