/* 
   SAM ldb module

   Copyright (C) Simo Sorce  2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
 *  Component: ldb samldb module
 *
 *  Description: add embedded user/group creation functionality
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "libcli/ldap/ldap.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"


/* if value is not null also check for attribute to have exactly that value */
static struct ldb_message_element *samldb_find_attribute(const struct ldb_message *msg, const char *name, const char *value)
{
	int j;
	struct ldb_message_element *el = ldb_msg_find_element(msg, name);
	if (!el) {
		return NULL;
	}

	if (!value) {
		return el;
	}

	for (j = 0; j < el->num_values; j++) {
		if (strcasecmp(value, 
			       (char *)el->values[j].data) == 0) {
			return el;
		}
	}

	return NULL;
}

static BOOL samldb_msg_add_string(struct ldb_module *module, struct ldb_message *msg, const char *name, const char *value)
{
	char *aval = talloc_strdup(msg, value);

	if (aval == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_msg_add_string: talloc_strdup failed!\n");
		return False;
	}

	if (ldb_msg_add_string(msg, name, aval) != 0) {
		return False;
	}

	return True;
}

static BOOL samldb_msg_add_sid(struct ldb_module *module, struct ldb_message *msg, const char *name, const struct dom_sid *sid)
{
	struct ldb_val v;
	NTSTATUS status;
	status = ndr_push_struct_blob(&v, msg, sid, 
				      (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	return (ldb_msg_add_value(msg, name, &v) == 0);
}

static BOOL samldb_find_or_add_attribute(struct ldb_module *module, struct ldb_message *msg, const char *name, const char *value, const char *set_value)
{
	if (samldb_find_attribute(msg, name, value) == NULL) {
		return samldb_msg_add_string(module, msg, name, set_value);
	}
	return True;
}

/*
  allocate a new id, attempting to do it atomically
  return 0 on failure, the id on success
*/
static int samldb_set_next_rid(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
			       const struct ldb_dn *dn, uint32_t old_id, uint32_t new_id)
{
	struct ldb_message msg;
	int ret;
	struct ldb_val vals[2];
	struct ldb_message_element els[2];

	if (new_id == 0) {
		/* out of IDs ! */
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Are we out of valid IDs ?\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* we do a delete and add as a single operation. That prevents
	   a race, in case we are not actually on a transaction db */
	ZERO_STRUCT(msg);
	msg.dn = ldb_dn_copy(mem_ctx, dn);
	if (!msg.dn) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	msg.num_elements = 2;
	msg.elements = els;

	els[0].num_values = 1;
	els[0].values = &vals[0];
	els[0].flags = LDB_FLAG_MOD_DELETE;
	els[0].name = talloc_strdup(mem_ctx, "nextRid");
	if (!els[0].name) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	els[1].num_values = 1;
	els[1].values = &vals[1];
	els[1].flags = LDB_FLAG_MOD_ADD;
	els[1].name = els[0].name;

	vals[0].data = (uint8_t *)talloc_asprintf(mem_ctx, "%u", old_id);
	if (!vals[0].data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	vals[0].length = strlen((char *)vals[0].data);

	vals[1].data = (uint8_t *)talloc_asprintf(mem_ctx, "%u", new_id);
	if (!vals[1].data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	vals[1].length = strlen((char *)vals[1].data);

	ret = ldb_modify(ldb, &msg);
	return ret;
}

/*
  allocate a new id, attempting to do it atomically
  return 0 on failure, the id on success
*/
static int samldb_find_next_rid(struct ldb_module *module, TALLOC_CTX *mem_ctx,
				const struct ldb_dn *dn, uint32_t *old_rid)
{
	const char * const attrs[2] = { "nextRid", NULL };
	struct ldb_result *res = NULL;
	int ret;
	const char *str;

	ret = ldb_search(module->ldb, dn, LDB_SCOPE_BASE, "nextRid=*", attrs, &res);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	talloc_steal(mem_ctx, res);
	if (res->count != 1) {
		talloc_free(res);
		return -1;
	}

	str = ldb_msg_find_string(res->msgs[0], "nextRid", NULL);
	if (str == NULL) {
		ldb_set_errstring(module->ldb,
				  talloc_asprintf(mem_ctx, "attribute nextRid not found in %s\n",
						  ldb_dn_linearize(res, dn)));
		talloc_free(res);
		return -1;
	}

	*old_rid = strtol(str, NULL, 0);
	talloc_free(res);
	return 0;
}

static int samldb_allocate_next_rid(struct ldb_module *module, TALLOC_CTX *mem_ctx,
				    const struct ldb_dn *dn, const struct dom_sid *dom_sid, 
				    struct dom_sid **new_sid)
{
	struct dom_sid *obj_sid;
	uint32_t old_rid;
	int ret;
	struct ldb_message **sid_msgs;
	const char *sid_attrs[] = { NULL };
	
	do {
		ret = samldb_find_next_rid(module, mem_ctx, dn, &old_rid);	
		if (ret) {
			return ret;
		}
		
		/* return the new object sid */
		obj_sid = dom_sid_add_rid(mem_ctx, dom_sid, old_rid);
		
		ret = samldb_set_next_rid(module->ldb, mem_ctx, dn, old_rid, old_rid + 1);
		if (ret != 0) {
			return ret;
		}

		*new_sid = dom_sid_add_rid(mem_ctx, dom_sid, old_rid + 1);
		if (!*new_sid) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		ret = gendb_search(module->ldb,
				   mem_ctx, NULL, &sid_msgs, sid_attrs,
				   "objectSid=%s",
				   ldap_encode_ndr_dom_sid(mem_ctx, *new_sid));
		if (ret == 0) {
			/* Great. There are no conflicting users/groups/etc */
			return 0;
		} else if (ret == -1) {
			/* Bugger, there is a problem, and we don't know what it is until gendb_search improves */
			return ret;
		} else {
                        /* gah, there are conflicting sids, lets move around the loop again... */
		}
	} while (1);
	return ret;
}

/* Find a domain object in the parents of a particular DN.  */
static struct ldb_dn *samldb_search_domain(struct ldb_module *module, TALLOC_CTX *mem_ctx, const struct ldb_dn *dn)
{
	TALLOC_CTX *local_ctx;
	struct ldb_dn *sdn;
	struct ldb_result *res = NULL;
	int ret = 0;

	local_ctx = talloc_new(mem_ctx);
	if (local_ctx == NULL) return NULL;

	sdn = ldb_dn_copy(local_ctx, dn);
	do {
		ret = ldb_search(module->ldb, sdn, LDB_SCOPE_BASE, "objectClass=domain", NULL, &res);
		talloc_steal(local_ctx, res);
		if (ret == LDB_SUCCESS && res->count == 1)
			break;
	} while ((sdn = ldb_dn_get_parent(local_ctx, sdn)));

	if (ret != LDB_SUCCESS || res->count != 1) {
		talloc_free(local_ctx);
		return NULL;
	}

	talloc_steal(mem_ctx, sdn);
	talloc_free(local_ctx);

	return sdn;
}

/* search the domain related to the provided dn
   allocate a new RID for the domain
   return the new sid string
*/
static struct dom_sid *samldb_get_new_sid(struct ldb_module *module, 
					  TALLOC_CTX *mem_ctx, const struct ldb_dn *obj_dn)
{
	const char * const attrs[2] = { "objectSid", NULL };
	struct ldb_result *res = NULL;
	const struct ldb_dn *dom_dn;
	int ret;
	struct dom_sid *dom_sid, *obj_sid;

	/* get the domain component part of the provided dn */

	dom_dn = samldb_search_domain(module, mem_ctx, obj_dn);
	if (dom_dn == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "Invalid dn (%s) not child of a domain object!\n", ldb_dn_linearize(mem_ctx, obj_dn));
		return NULL;
	}

	/* find the domain sid */

	ret = ldb_search(module->ldb, dom_dn, LDB_SCOPE_BASE, "objectSid=*", attrs, &res);
	if (ret != LDB_SUCCESS || res->count != 1) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_get_new_sid: error retrieving domain sid!\n");
		talloc_free(res);
		return NULL;
	}

	dom_sid = samdb_result_dom_sid(res, res->msgs[0], "objectSid");
	if (dom_sid == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_get_new_sid: error retrieving domain sid!\n");
		talloc_free(res);
		return NULL;
	}

	/* allocate a new Rid for the domain */
	ret = samldb_allocate_next_rid(module, mem_ctx, dom_dn, dom_sid, &obj_sid);
	if (ret != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "Failed to increment nextRid of %s\n", ldb_dn_linearize(mem_ctx, dom_dn));
		talloc_free(res);
		return NULL;
	}

	talloc_free(res);

	return obj_sid;
}

/* If we are adding new users/groups, we need to update the nextRid
 * attribute to be 'above' all incoming users RIDs.  This tries to
 * avoid clashes in future */

int samldb_notice_sid(struct ldb_module *module, 
		      TALLOC_CTX *mem_ctx, const struct dom_sid *sid)
{
	int ret;
	struct ldb_dn *dom_dn;
	struct dom_sid *dom_sid;
	const char *dom_attrs[] = { NULL };
	struct ldb_message **dom_msgs;
	uint32_t old_rid;

	/* find the domain DN */

	ret = gendb_search(module->ldb,
			   mem_ctx, NULL, &dom_msgs, dom_attrs,
			   "objectSid=%s",
			   ldap_encode_ndr_dom_sid(mem_ctx, sid));
	if (ret > 0) {
		ldb_set_errstring(module->ldb,
				  talloc_asprintf(mem_ctx,
						  "Attempt to add record with SID %s rejected,"
						  " because this SID is already in the database",
						  dom_sid_string(mem_ctx, sid)));
		/* We have a duplicate SID, we must reject the add */
		talloc_free(dom_msgs);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}
	
	if (ret == -1) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_get_new_sid: error searching for proposed sid!\n");
		return -1;
	}

	dom_sid = dom_sid_dup(mem_ctx, sid);
	if (!dom_sid) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* get the domain component part of the provided SID */
	dom_sid->num_auths--;

	/* find the domain DN */

	ret = gendb_search(module->ldb,
			   mem_ctx, NULL, &dom_msgs, dom_attrs,
			   "(&(objectSid=%s)(objectclass=domain))",
			   ldap_encode_ndr_dom_sid(mem_ctx, dom_sid));
	if (ret == 0) {
		/* This isn't an operation on a domain we know about, so nothing to update */
		return 0;
	}

	if (ret > 1) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_get_new_sid: error retrieving domain from sid: duplicate domains!\n");
		talloc_free(dom_msgs);
		return -1;
	}

	if (ret != 1) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_get_new_sid: error retrieving domain sid!\n");
		return -1;
	}

	dom_dn = dom_msgs[0]->dn;

	ret = samldb_find_next_rid(module, mem_ctx, 
				   dom_dn, &old_rid);
	if (ret) {
		talloc_free(dom_msgs);
		return ret;
	}

	if (old_rid <= sid->sub_auths[sid->num_auths - 1]) {
		ret = samldb_set_next_rid(module->ldb, mem_ctx, dom_dn, old_rid, 
					  sid->sub_auths[sid->num_auths - 1] + 1);
	}
	talloc_free(dom_msgs);
	return ret;
}

static int samldb_handle_sid(struct ldb_module *module, 
					 TALLOC_CTX *mem_ctx, struct ldb_message *msg2)
{
	int ret;
	
	struct dom_sid *sid = samdb_result_dom_sid(mem_ctx, msg2, "objectSid");
	if (sid == NULL) { 
		sid = samldb_get_new_sid(module, msg2, msg2->dn);
		if (sid == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_user_or_computer_object: internal error! Can't generate new sid\n");
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if ( ! samldb_msg_add_sid(module, msg2, "objectSid", sid)) {
			talloc_free(sid);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		talloc_free(sid);
		ret = 0;
	} else {
		ret = samldb_notice_sid(module, msg2, sid);
	}
	return ret;
}

static char *samldb_generate_samAccountName(struct ldb_module *module, TALLOC_CTX *mem_ctx) 
{
	char *name;
	const char *attrs[] = { NULL };
	struct ldb_message **msgs;
	int ret;
	
	/* Format: $000000-000000000000 */
	
	do {
		name = talloc_asprintf(mem_ctx, "$%.6X-%.6X%.6X", (unsigned int)random(), (unsigned int)random(), (unsigned int)random());
		/* TODO: Figure out exactly what this is meant to conflict with */
		ret = gendb_search(module->ldb,
				   mem_ctx, NULL, &msgs, attrs,
				   "samAccountName=%s",
				   ldb_binary_encode_string(mem_ctx, name));
		if (ret == 0) {
			/* Great. There are no conflicting users/groups/etc */
			return name;
		} else if (ret == -1) {
			/* Bugger, there is a problem, and we don't know what it is until gendb_search improves */
			return NULL;
		} else {
			talloc_free(name);
                        /* gah, there are conflicting sids, lets move around the loop again... */
		}
	} while (1);
}

static int samldb_copy_template(struct ldb_module *module, struct ldb_message *msg, const char *filter)
{
	struct ldb_result *res;
	struct ldb_message *t;
	int ret, i, j;
	

	/* pull the template record */
	ret = ldb_search(module->ldb, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &res);
	if (ret != LDB_SUCCESS || res->count != 1) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb: ERROR: template '%s' matched too many records\n", filter);
		return -1;
	}
	t = res->msgs[0];

	for (i = 0; i < t->num_elements; i++) {
		struct ldb_message_element *el = &t->elements[i];
		/* some elements should not be copied from the template */
		if (strcasecmp(el->name, "cn") == 0 ||
		    strcasecmp(el->name, "name") == 0 ||
		    strcasecmp(el->name, "sAMAccountName") == 0 ||
		    strcasecmp(el->name, "objectGUID") == 0) {
			continue;
		}
		for (j = 0; j < el->num_values; j++) {
			if (strcasecmp(el->name, "objectClass") == 0) {
				if (strcasecmp((char *)el->values[j].data, "Template") == 0 ||
				    strcasecmp((char *)el->values[j].data, "userTemplate") == 0 ||
				    strcasecmp((char *)el->values[j].data, "groupTemplate") == 0 ||
				    strcasecmp((char *)el->values[j].data, "foreignSecurityPrincipalTemplate") == 0 ||
				    strcasecmp((char *)el->values[j].data, "aliasTemplate") == 0 || 
				    strcasecmp((char *)el->values[j].data, "trustedDomainTemplate") == 0 || 
				    strcasecmp((char *)el->values[j].data, "secretTemplate") == 0) {
					continue;
				}
				if ( ! samldb_find_or_add_attribute(module, msg, el->name, 
								    (char *)el->values[j].data,
								    (char *)el->values[j].data)) {
					ldb_debug(module->ldb, LDB_DEBUG_FATAL, "Attribute adding failed...\n");
					talloc_free(res);
					return -1;
				}
			} else {
				if ( ! samldb_find_or_add_attribute(module, msg, el->name, 
								    NULL,
								    (char *)el->values[j].data)) {
					ldb_debug(module->ldb, LDB_DEBUG_FATAL, "Attribute adding failed...\n");
					talloc_free(res);
					return -1;
				}
			}
		}
	}

	talloc_free(res);

	return 0;
}

static int samldb_fill_group_object(struct ldb_module *module, const struct ldb_message *msg,
						    struct ldb_message **ret_msg)
{
	int ret;
	const char *name;
	struct ldb_message *msg2;
	struct ldb_dn_component *rdn;
	TALLOC_CTX *mem_ctx = talloc_new(msg);
	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* build the new msg */
	msg2 = ldb_msg_copy(mem_ctx, msg);
	if (!msg2) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: ldb_msg_copy failed!\n");
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = samldb_copy_template(module, msg2, "(&(CN=TemplateGroup)(objectclass=groupTemplate))");
	if (ret != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb_fill_group_object: Error copying template!\n");
		talloc_free(mem_ctx);
		return ret;
	}

	rdn = ldb_dn_get_rdn(msg2, msg2->dn);

	if (strcasecmp(rdn->name, "cn") != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: Bad RDN (%s) for group!\n", rdn->name);
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* Generate a random name, if no samAccountName was supplied */
	if (ldb_msg_find_element(msg2, "samAccountName") == NULL) {
		name = samldb_generate_samAccountName(module, mem_ctx);
		if (!name) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if ( ! samldb_find_or_add_attribute(module, msg2, "sAMAccountName", NULL, name)) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}
	
	/* Manage SID allocation, conflicts etc */
	ret = samldb_handle_sid(module, mem_ctx, msg2); 

	if (ret == 0) {
		talloc_steal(msg, msg2);
		*ret_msg = msg2;
	}
	talloc_free(mem_ctx);
	return 0;
}

static int samldb_fill_user_or_computer_object(struct ldb_module *module, const struct ldb_message *msg,
							       struct ldb_message **ret_msg)
{
	int ret;
	char *name;
	struct ldb_message *msg2;
	struct ldb_dn_component *rdn;
	TALLOC_CTX *mem_ctx = talloc_new(msg);
	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* build the new msg */
	msg2 = ldb_msg_copy(mem_ctx, msg);
	if (!msg2) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: ldb_msg_copy failed!\n");
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (samldb_find_attribute(msg, "objectclass", "computer") != NULL) {
		ret = samldb_copy_template(module, msg2, "(&(CN=TemplateComputer)(objectclass=userTemplate))");
		if (ret) {
			ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb_fill_user_or_computer_object: Error copying computer template!\n");
			talloc_free(mem_ctx);
			return ret;
		}
	} else {
		ret = samldb_copy_template(module, msg2, "(&(CN=TemplateUser)(objectclass=userTemplate))");
		if (ret) {
			ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb_fill_user_or_computer_object: Error copying user template!\n");
			talloc_free(mem_ctx);
			return ret;
		}
	}

	rdn = ldb_dn_get_rdn(msg2, msg2->dn);

	if (strcasecmp(rdn->name, "cn") != 0) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Bad RDN (%s=) for user/computer, should be CN=!\n", rdn->name));
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* if the only attribute was: "objectclass: computer", then make sure we also add "user" objectclass */
	if ( ! samldb_find_or_add_attribute(module, msg2, "objectclass", "user", "user")) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* meddle with objectclass */

	if (ldb_msg_find_element(msg2, "samAccountName") == NULL) {
		name = samldb_generate_samAccountName(module, mem_ctx);
		if (!name) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if ( ! samldb_find_or_add_attribute(module, msg2, "sAMAccountName", NULL, name)) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}

	/*
	  TODO: useraccountcontrol: setting value 0 gives 0x200 for users
	*/

	/* Manage SID allocation, conflicts etc */
	ret = samldb_handle_sid(module, mem_ctx, msg2); 

	/* TODO: objectCategory, userAccountControl, badPwdCount, codePage, countryCode, badPasswordTime, lastLogoff, lastLogon, pwdLastSet, primaryGroupID, accountExpires, logonCount */

	if (ret == 0) {
		*ret_msg = msg2;
		talloc_steal(msg, msg2);
	}
	talloc_free(mem_ctx);
	return 0;
}
	
static int samldb_fill_foreignSecurityPrincipal_object(struct ldb_module *module, const struct ldb_message *msg, 
								       struct ldb_message **ret_msg)
{
	struct ldb_message *msg2;
	struct ldb_dn_component *rdn;
	struct dom_sid *dom_sid;
	struct dom_sid *sid;
	const char *dom_attrs[] = { "name", NULL };
	struct ldb_message **dom_msgs;
	int ret;

	TALLOC_CTX *mem_ctx = talloc_new(msg);
	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* build the new msg */
	msg2 = ldb_msg_copy(mem_ctx, msg);
	if (!msg2) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_foreignSecurityPrincpal_object: ldb_msg_copy failed!\n");
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = samldb_copy_template(module, msg2, "(&(CN=TemplateForeignSecurityPrincipal)(objectclass=foreignSecurityPrincipalTemplate))");
	if (ret != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb_fill_foreignSecurityPrincipal_object: Error copying template!\n");
		talloc_free(mem_ctx);
		return ret;
	}

	rdn = ldb_dn_get_rdn(msg2, msg2->dn);

	if (strcasecmp(rdn->name, "cn") != 0) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "Bad RDN (%s=) for ForeignSecurityPrincipal, should be CN=!", rdn->name));
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* Slightly different for the foreign sids.  We don't want
	 * domain SIDs ending up there, it would cause all sorts of
	 * pain */

	sid = dom_sid_parse_talloc(msg2, (const char *)rdn->value.data);
	if (!sid) {
		ldb_set_errstring(module->ldb, talloc_asprintf(module, "No valid found SID in ForeignSecurityPrincipal CN!"));
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if ( ! samldb_msg_add_sid(module, msg2, "objectSid", sid)) {
		talloc_free(sid);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dom_sid = dom_sid_dup(mem_ctx, sid);
	if (!dom_sid) {
		talloc_free(mem_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* get the domain component part of the provided SID */
	dom_sid->num_auths--;

	/* find the domain DN */

	ret = gendb_search(module->ldb,
			   mem_ctx, NULL, &dom_msgs, dom_attrs,
			   "(&(objectSid=%s)(objectclass=domain))",
			   ldap_encode_ndr_dom_sid(mem_ctx, dom_sid));
	if (ret >= 1) {
		const char *name = samdb_result_string(dom_msgs[0], "name", NULL);
		ldb_set_errstring(module->ldb, talloc_asprintf(mem_ctx, "Attempt to add foreign SID record with SID %s rejected, because this domian (%s) is already in the database", dom_sid_string(mem_ctx, sid), name)); 
		/* We don't really like the idea of foreign sids that are not foreign */
		return LDB_ERR_CONSTRAINT_VIOLATION;
	} else if (ret == -1) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_foreignSecurityPrincipal_object: error searching for a domain with this sid: %s\n", dom_sid_string(mem_ctx, dom_sid));
		talloc_free(dom_msgs);
		return -1;
	}

	/* This isn't an operation on a domain we know about, so just
	 * check for the SID, looking for duplicates via the common
	 * code */
	ret = samldb_notice_sid(module, msg2, sid);
	if (ret == 0) {
		talloc_steal(msg, msg2);
		*ret_msg = msg2;
	}
	
	return ret;
}

/* add_record */
static int samldb_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
	struct ldb_message *msg2 = NULL;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_add_record\n");

	
	if (ldb_dn_is_special(msg->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* is user or computer?  add all relevant missing objects */
	if ((samldb_find_attribute(msg, "objectclass", "user") != NULL) || 
	    (samldb_find_attribute(msg, "objectclass", "computer") != NULL)) {
		ret = samldb_fill_user_or_computer_object(module, msg, &msg2);
		if (ret) {
			return ret;
		}
	}

	/* is group? add all relevant missing objects */
	if ( ! msg2 ) {
		if (samldb_find_attribute(msg, "objectclass", "group") != NULL) {
			ret = samldb_fill_group_object(module, msg, &msg2);
			if (ret) {
				return ret;
			}
		}
	}

	/* perhaps a foreignSecurityPrincipal? */
	if ( ! msg2 ) {
		if (samldb_find_attribute(msg, "objectclass", "foreignSecurityPrincipal") != NULL) {
			ret = samldb_fill_foreignSecurityPrincipal_object(module, msg, &msg2);
			if (ret) {
				return ret;
			}
		}
	}

	if (msg2) {
		req->op.add.message = msg2;
		ret = ldb_next_request(module, req);
		req->op.add.message = msg;
	} else {
		ret = ldb_next_request(module, req);
	}

	return ret;
}

static int samldb_destructor(void *module_ctx)
{
	/* struct ldb_module *ctx = module_ctx; */
	/* put your clean-up functions here */
	return 0;
}

static int samldb_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_ADD:
		return samldb_add(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static int samldb_init(struct ldb_module *module)
{
	talloc_set_destructor(module, samldb_destructor);
	return ldb_next_init(module);
}

static const struct ldb_module_ops samldb_ops = {
	.name          = "samldb",
	.init_context  = samldb_init,
	.request       = samldb_request
};


int samldb_module_init(void)
{
	return ldb_register_module(&samldb_ops);
}
