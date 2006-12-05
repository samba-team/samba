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
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "db_wrap.h"

int samldb_notice_sid(struct ldb_module *module, 
		      TALLOC_CTX *mem_ctx, const struct dom_sid *sid);

static BOOL samldb_msg_add_sid(struct ldb_module *module, struct ldb_message *msg, const char *name, const struct dom_sid *sid)
{
	struct ldb_val v;
	NTSTATUS status;
	status = ndr_push_struct_blob(&v, msg, sid, 
				      (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	return (ldb_msg_add_value(msg, name, &v, NULL) == 0);
}

/*
  allocate a new id, attempting to do it atomically
  return 0 on failure, the id on success
*/
static int samldb_set_next_rid(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
			       struct ldb_dn *dn, uint32_t old_id, uint32_t new_id)
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
				struct ldb_dn *dn, uint32_t *old_rid)
{
	const char * const attrs[2] = { "nextRid", NULL };
	struct ldb_result *res = NULL;
	int ret;
	const char *str;

	ret = ldb_search(module->ldb, dn, LDB_SCOPE_BASE, "nextRid=*", attrs, &res);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count != 1) {
		talloc_free(res);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	str = ldb_msg_find_attr_as_string(res->msgs[0], "nextRid", NULL);
	if (str == NULL) {
		ldb_asprintf_errstring(module->ldb,
					"attribute nextRid not found in %s\n",
					ldb_dn_get_linearized(dn));
		talloc_free(res);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*old_rid = strtol(str, NULL, 0);
	talloc_free(res);
	return LDB_SUCCESS;
}

static int samldb_allocate_next_rid(struct ldb_module *module, TALLOC_CTX *mem_ctx,
				    struct ldb_dn *dn, const struct dom_sid *dom_sid, 
				    struct dom_sid **new_sid)
{
	struct dom_sid *obj_sid;
	uint32_t old_rid;
	int ret;
	
	ret = samldb_find_next_rid(module, mem_ctx, dn, &old_rid);	
	if (ret) {
		return ret;
	}
		
	/* return the new object sid */
	obj_sid = dom_sid_add_rid(mem_ctx, dom_sid, old_rid);
		
	*new_sid = dom_sid_add_rid(mem_ctx, dom_sid, old_rid + 1);
	if (!*new_sid) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = samldb_notice_sid(module, mem_ctx, *new_sid);
	if (ret != 0) {
		/* gah, there are conflicting sids.
		 * This is a critical situation it means that someone messed up with
		 * the DB and nextRid is not returning free RIDs, report an error
		 * and refuse to create any user until the problem is fixed */
		ldb_asprintf_errstring(module->ldb,
					"Critical Error: unconsistent DB, unable to retireve an unique RID to generate a new SID: %s",
					ldb_errstring(module->ldb));
		return ret;
	}
	return ret;
}

/* Find a domain object in the parents of a particular DN.  */
static struct ldb_dn *samldb_search_domain(struct ldb_module *module, TALLOC_CTX *mem_ctx, struct ldb_dn *dn)
{
	TALLOC_CTX *local_ctx;
	struct ldb_dn *sdn;
	struct ldb_result *res = NULL;
	int ret = 0;
	const char *attrs[] = { NULL };

	local_ctx = talloc_new(mem_ctx);
	if (local_ctx == NULL) return NULL;

	sdn = ldb_dn_copy(local_ctx, dn);
	do {
		ret = ldb_search(module->ldb, sdn, LDB_SCOPE_BASE, 
				 "(|(objectClass=domain)(objectClass=builtinDomain))", attrs, &res);
		if (ret == LDB_SUCCESS) {
			talloc_steal(local_ctx, res);
			if (res->count == 1) {
				break;
			}
		}
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
static int samldb_get_new_sid(struct ldb_module *module, 
			      TALLOC_CTX *mem_ctx, struct ldb_dn *obj_dn,
			      struct dom_sid **sid)
{
	const char * const attrs[2] = { "objectSid", NULL };
	struct ldb_result *res = NULL;
	struct ldb_dn *dom_dn;
	int ret;
	struct dom_sid *dom_sid;

	/* get the domain component part of the provided dn */

	dom_dn = samldb_search_domain(module, mem_ctx, obj_dn);
	if (dom_dn == NULL) {
		ldb_asprintf_errstring(module->ldb,
					"Invalid dn (%s) not child of a domain object!\n",
					ldb_dn_get_linearized(obj_dn));
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* find the domain sid */

	ret = ldb_search(module->ldb, dom_dn, LDB_SCOPE_BASE, "objectSid=*", attrs, &res);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(module->ldb,
					"samldb_get_new_sid: error retrieving domain sid from %s: %s!\n",
					ldb_dn_get_linearized(dom_dn),
					ldb_errstring(module->ldb));
		talloc_free(res);
		return ret;
	}

	if (res->count != 1) {
		ldb_asprintf_errstring(module->ldb,
					"samldb_get_new_sid: error retrieving domain sid from %s: not found!\n",
					ldb_dn_get_linearized(dom_dn));
		talloc_free(res);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	dom_sid = samdb_result_dom_sid(res, res->msgs[0], "objectSid");
	if (dom_sid == NULL) {
		ldb_set_errstring(module->ldb, "samldb_get_new_sid: error parsing domain sid!\n");
		talloc_free(res);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* allocate a new Rid for the domain */
	ret = samldb_allocate_next_rid(module, mem_ctx, dom_dn, dom_sid, sid);
	if (ret != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "Failed to increment nextRid of %s: %s\n", ldb_dn_get_linearized(dom_dn), ldb_errstring(module->ldb));
		talloc_free(res);
		return ret;
	}

	talloc_free(res);

	return ret;
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
	const char *attrs[] = { NULL };
	struct ldb_result *dom_res;
	struct ldb_result *res;
	uint32_t old_rid;

	/* find if this SID already exists */
	ret = ldb_search_exp_fmt(module->ldb, mem_ctx, &res,
				 NULL, LDB_SCOPE_SUBTREE, attrs,
				 "(objectSid=%s)", ldap_encode_ndr_dom_sid(mem_ctx, sid));
	if (ret == LDB_SUCCESS) {
		if (res->count > 0) {
			talloc_free(res);
			ldb_asprintf_errstring(module->ldb,
						"Attempt to add record with SID %s rejected,"
						" because this SID is already in the database",
						dom_sid_string(mem_ctx, sid));
			/* We have a duplicate SID, we must reject the add */
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}
		talloc_free(res);
	} else {
		ldb_asprintf_errstring(module->ldb,
					"samldb_notice_sid: error searching to see if sid %s is in use: %s\n", 
					dom_sid_string(mem_ctx, sid), 
					ldb_errstring(module->ldb));
		return ret;
	}

	dom_sid = dom_sid_dup(mem_ctx, sid);
	if (!dom_sid) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	/* get the domain component part of the provided SID */
	dom_sid->num_auths--;

	/* find the domain DN */
	ret = ldb_search_exp_fmt(module->ldb, mem_ctx, &dom_res,
				 NULL, LDB_SCOPE_SUBTREE, attrs,
				 "(&(objectSid=%s)(objectclass=domain))",
				 ldap_encode_ndr_dom_sid(mem_ctx, dom_sid));
	if (ret == LDB_SUCCESS) {
		if (dom_res->count == 0) {
			talloc_free(dom_res);
			/* This isn't an operation on a domain we know about, so nothing to update */
			return LDB_SUCCESS;
		}

		if (dom_res->count > 1) {
			talloc_free(dom_res);
			ldb_asprintf_errstring(module->ldb,
					"samldb_notice_sid: error retrieving domain from sid: duplicate (found %d) domain: %s!\n", 
					dom_res->count, dom_sid_string(dom_res, dom_sid));
			return LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		ldb_asprintf_errstring(module->ldb,
					"samldb_notice_sid: error retrieving domain from sid: %s: %s\n", 
					dom_sid_string(dom_res, dom_sid), 
					ldb_errstring(module->ldb));
		return ret;
	}

	dom_dn = dom_res->msgs[0]->dn;

	ret = samldb_find_next_rid(module, mem_ctx, 
				   dom_dn, &old_rid);
	if (ret) {
		talloc_free(dom_res);
		return ret;
	}

	if (old_rid <= sid->sub_auths[sid->num_auths - 1]) {
		ret = samldb_set_next_rid(module->ldb, mem_ctx, dom_dn, old_rid, 
					  sid->sub_auths[sid->num_auths - 1] + 1);
	}
	talloc_free(dom_res);
	return ret;
}

static int samldb_handle_sid(struct ldb_module *module, 
					 TALLOC_CTX *mem_ctx, struct ldb_message *msg2)
{
	int ret;
	
	struct dom_sid *sid = samdb_result_dom_sid(mem_ctx, msg2, "objectSid");
	if (sid == NULL) { 
		ret = samldb_get_new_sid(module, msg2, msg2->dn, &sid);
		if (ret != 0) {
			return ret;
		}

		if ( ! samldb_msg_add_sid(module, msg2, "objectSid", sid)) {
			talloc_free(sid);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		talloc_free(sid);
		ret = LDB_SUCCESS;
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

static int samldb_fill_group_object(struct ldb_module *module, const struct ldb_message *msg,
						    struct ldb_message **ret_msg)
{
	int ret;
	const char *name;
	struct ldb_message *msg2;
	const char *rdn_name;
	TALLOC_CTX *mem_ctx = talloc_new(msg);
	const char *errstr;
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

	ret = samdb_copy_template(module->ldb, msg2, 
				  "(&(CN=TemplateGroup)(objectclass=groupTemplate))",
				  &errstr);
	if (ret != 0) {
		
		talloc_free(mem_ctx);
		return ret;
	}

	rdn_name = ldb_dn_get_rdn_name(msg2->dn);

	if (strcasecmp(rdn_name, "cn") != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: Bad RDN (%s) for group!\n", rdn_name);
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
		ret = samdb_find_or_add_attribute(module->ldb, msg2, "sAMAccountName", name);
		if (ret) {
			talloc_free(mem_ctx);
			return ret;
		}
	}
	
	/* Manage SID allocation, conflicts etc */
	ret = samldb_handle_sid(module, mem_ctx, msg2); 

	if (ret == LDB_SUCCESS) {
		talloc_steal(msg, msg2);
		*ret_msg = msg2;
	}
	talloc_free(mem_ctx);
	return ret;
}

static int samldb_fill_user_or_computer_object(struct ldb_module *module, const struct ldb_message *msg,
							       struct ldb_message **ret_msg)
{
	int ret;
	char *name;
	struct ldb_message *msg2;
	const char *rdn_name;
	TALLOC_CTX *mem_ctx = talloc_new(msg);
	const char *errstr;
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

	if (samdb_find_attribute(module->ldb, msg, "objectclass", "computer") != NULL) {

		ret = samdb_copy_template(module->ldb, msg2, 
					  "(&(CN=TemplateComputer)(objectclass=userTemplate))", 
					  &errstr);
		if (ret) {
			ldb_asprintf_errstring(module->ldb, 
					       "samldb_fill_user_or_computer_object: "
					       "Error copying computer template: %s",
					       errstr);
			talloc_free(mem_ctx);
			return ret;
		}

		/* readd user and then computer objectclasses */
		ret = samdb_find_or_add_value(module->ldb, msg2, "objectclass", "user");
		if (ret) {
			talloc_free(mem_ctx);
			return ret;
		}
		ret = samdb_find_or_add_value(module->ldb, msg2, "objectclass", "computer");
		if (ret) {
			talloc_free(mem_ctx);
			return ret;
		}
		
	} else {
		ret = samdb_copy_template(module->ldb, msg2, 
					  "(&(CN=TemplateUser)(objectclass=userTemplate))", 
					  &errstr);
		if (ret) {
			ldb_asprintf_errstring(module->ldb, 
					       "samldb_fill_user_or_computer_object: Error copying user template: %s\n",
					       errstr);
			talloc_free(mem_ctx);
			return ret;
		}
		/* readd user objectclass */
		ret = samdb_find_or_add_value(module->ldb, msg2, "objectclass", "user");
		if (ret) {
			talloc_free(mem_ctx);
			return ret;
		}
	}

	rdn_name = ldb_dn_get_rdn_name(msg2->dn);

	if (strcasecmp(rdn_name, "cn") != 0) {
		ldb_asprintf_errstring(module->ldb, "Bad RDN (%s=) for user/computer, should be CN=!\n", rdn_name);
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	if (ldb_msg_find_element(msg2, "samAccountName") == NULL) {
		name = samldb_generate_samAccountName(module, mem_ctx);
		if (!name) {
			talloc_free(mem_ctx);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ret = samdb_find_or_add_attribute(module->ldb, msg2, "sAMAccountName", name);
		if (ret) {
			talloc_free(mem_ctx);
			return ret;
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
	return ret;
}
	
static int samldb_fill_foreignSecurityPrincipal_object(struct ldb_module *module, const struct ldb_message *msg, 
						       struct ldb_message **ret_msg)
{
	struct ldb_message *msg2;
	const char *rdn_name;
	struct dom_sid *dom_sid;
	struct dom_sid *sid;
	const char *dom_attrs[] = { "name", NULL };
	struct ldb_message **dom_msgs;
	const char *errstr;
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

	ret = samdb_copy_template(module->ldb, msg2, 
				  "(&(CN=TemplateForeignSecurityPrincipal)(objectclass=foreignSecurityPrincipalTemplate))",
				  &errstr);
	if (ret != 0) {
		ldb_asprintf_errstring(module->ldb, 
				       "samldb_fill_foreignSecurityPrincipal_object: "
				       "Error copying template: %s",
				    errstr);
		talloc_free(mem_ctx);
		return ret;
	}

	rdn_name = ldb_dn_get_rdn_name(msg2->dn);

	if (strcasecmp(rdn_name, "cn") != 0) {
		ldb_asprintf_errstring(module->ldb, "Bad RDN (%s=) for ForeignSecurityPrincipal, should be CN=!", rdn_name);
		talloc_free(mem_ctx);
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* Slightly different for the foreign sids.  We don't want
	 * domain SIDs ending up there, it would cause all sorts of
	 * pain */

	sid = dom_sid_parse_talloc(msg2, (const char *)ldb_dn_get_rdn_val(msg2->dn)->data);
	if (!sid) {
		ldb_set_errstring(module->ldb, "No valid found SID in ForeignSecurityPrincipal CN!");
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
		/* We don't really like the idea of foreign sids that are not foreign, but it happens */
		const char *name = samdb_result_string(dom_msgs[0], "name", NULL);
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "NOTE (strange but valid): Adding foreign SID record with SID %s, but this domian (%s) is already in the database", 
			  dom_sid_string(mem_ctx, sid), name); 
	} else if (ret == -1) {
		ldb_asprintf_errstring(module->ldb,
					"samldb_fill_foreignSecurityPrincipal_object: error searching for a domain with this sid: %s\n", 
					dom_sid_string(mem_ctx, dom_sid));
		talloc_free(dom_msgs);
		return LDB_ERR_OPERATIONS_ERROR;
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

/*
 * FIXME
 *
 * Actually this module is not async at all as it does a number of sync searches
 * in the process. It still to be decided how to deal with it properly so it is
 * left SYNC for now until we think of a good solution.
 */

static int samldb_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
	struct ldb_message *msg2 = NULL;
	struct ldb_request *down_req;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_add_record\n");

	if (ldb_dn_is_special(msg->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	/* is user or computer? */
	if ((samdb_find_attribute(module->ldb, msg, "objectclass", "user") != NULL) ||
	    (samdb_find_attribute(module->ldb, msg, "objectclass", "computer") != NULL)) {
		/*  add all relevant missing objects */
		ret = samldb_fill_user_or_computer_object(module, msg, &msg2);
		if (ret) {
			return ret;
		}
	}

	/* is group? add all relevant missing objects */
	if ( ! msg2 ) {
		if (samdb_find_attribute(module->ldb, msg, "objectclass", "group") != NULL) {
			ret = samldb_fill_group_object(module, msg, &msg2);
			if (ret) {
				return ret;
			}
		}
	}

	/* perhaps a foreignSecurityPrincipal? */
	if ( ! msg2 ) {
		if (samdb_find_attribute(module->ldb, msg, "objectclass", "foreignSecurityPrincipal") != NULL) {
			ret = samldb_fill_foreignSecurityPrincipal_object(module, msg, &msg2);
			if (ret) {
				return ret;
			}
		}
	}

	if (msg2 == NULL) {
		return ldb_next_request(module, req);
	}

	down_req = talloc(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*down_req = *req;
	
	down_req->op.add.message = talloc_steal(down_req, msg2);

	ldb_set_timeout_from_prev_req(module->ldb, req, down_req);

	/* go on with the call chain */
	ret = ldb_next_request(module, down_req);

	/* do not free down_req as the call results may be linked to it,
	 * it will be freed when the upper level request get freed */
	if (ret == LDB_SUCCESS) {
		req->handle = down_req->handle;
	}

	return ret;
}

static int samldb_init(struct ldb_module *module)
{
	return ldb_next_init(module);
}

static const struct ldb_module_ops samldb_ops = {
	.name          = "samldb",
	.init_context  = samldb_init,
	.add           = samldb_add,
};


int samldb_module_init(void)
{
	return ldb_register_module(&samldb_ops);
}
