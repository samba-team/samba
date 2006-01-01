/* 
   SAM ldb module

   Copyright (C) Simo Sorce  2004

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
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/include/ldb_private.h"
#include "dsdb/samdb/samdb.h"

#define SAM_ACCOUNT_NAME_BASE "$000000-000000000000"

/*
  allocate a new id, attempting to do it atomically
  return 0 on failure, the id on success
*/
static int samldb_allocate_next_rid(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
				   const struct ldb_dn *dn, uint32_t *id)
{
	const char * const attrs[2] = { "nextRid", NULL };
	struct ldb_result *res = NULL;
	struct ldb_message msg;
	int ret;
	const char *str;
	struct ldb_val vals[2];
	struct ldb_message_element els[2];

	ret = ldb_search(ldb, dn, LDB_SCOPE_BASE, "nextRid=*", attrs, &res);
	if (ret != LDB_SUCCESS || res->count != 1) {
		if (res) talloc_free(res);
		return -1;
	}
	str = ldb_msg_find_string(res->msgs[0], "nextRid", NULL);
	if (str == NULL) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "attribute nextRid not found in %s\n", ldb_dn_linearize(res, dn));
		talloc_free(res);
		return -1;
	}

	*id = strtol(str, NULL, 0);
	if ((*id)+1 == 0) {
		/* out of IDs ! */
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Are we out of valid IDs ?\n");
		talloc_free(res);
		return -1;
	}
	talloc_free(res);

	/* we do a delete and add as a single operation. That prevents
	   a race */
	ZERO_STRUCT(msg);
	msg.dn = ldb_dn_copy(mem_ctx, dn);
	if (!msg.dn) {
		return -1;
	}
	msg.num_elements = 2;
	msg.elements = els;

	els[0].num_values = 1;
	els[0].values = &vals[0];
	els[0].flags = LDB_FLAG_MOD_DELETE;
	els[0].name = talloc_strdup(mem_ctx, "nextRid");
	if (!els[0].name) {
		return -1;
	}

	els[1].num_values = 1;
	els[1].values = &vals[1];
	els[1].flags = LDB_FLAG_MOD_ADD;
	els[1].name = els[0].name;

	vals[0].data = (uint8_t *)talloc_asprintf(mem_ctx, "%u", *id);
	if (!vals[0].data) {
		return -1;
	}
	vals[0].length = strlen((char *)vals[0].data);

	vals[1].data = (uint8_t *)talloc_asprintf(mem_ctx, "%u", (*id)+1);
	if (!vals[1].data) {
		return -1;
	}
	vals[1].length = strlen((char *)vals[1].data);

	ret = ldb_modify(ldb, &msg);
	if (ret != 0) {
		return 1;
	}

	(*id)++;

	return 0;
}

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
	uint32_t rid;
	int ret;
	struct dom_sid *dom_sid, *obj_sid;

	/* get the domain component part of the provided dn */

	/* FIXME: quick search here, I think we should use something like
	   ldap_parse_dn here to be 100% sure we get the right domain dn */

	/* FIXME: "dc=" is probably not utf8 safe either,
	   we need a multibyte safe substring search function here */
	
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
	ret = samldb_allocate_next_rid(module->ldb, mem_ctx, dom_dn, &rid);
	if (ret != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "Failed to increment nextRid of %s\n", ldb_dn_linearize(mem_ctx, dom_dn));
		talloc_free(res);
		return NULL;
	}

	/* return the new object sid */
	obj_sid = dom_sid_add_rid(mem_ctx, dom_sid, rid);

	talloc_free(res);

	return obj_sid;
}

static char *samldb_generate_samAccountName(const void *mem_ctx) {
	char *name;

	name = talloc_strdup(mem_ctx, SAM_ACCOUNT_NAME_BASE);
	/* TODO: randomize name */	

	return name;
}

/* if value is not null also check for attribute to have exactly that value */
static struct ldb_message_element *samldb_find_attribute(const struct ldb_message *msg, const char *name, const char *value)
{
	int i, j;

	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(name, msg->elements[i].name) == 0) {
			if (!value) {
				return &msg->elements[i];
			}
			for (j = 0; j < msg->elements[i].num_values; j++) {
				if (strcasecmp(value, 
					       (char *)msg->elements[i].values[j].data) == 0) {
					return &msg->elements[i];
				}
			}
		}
	}

	return NULL;
}

static BOOL samldb_msg_add_string(struct ldb_module *module, struct ldb_message *msg, const char *name, const char *value)
{
	char *aname = talloc_strdup(msg, name);
	char *aval = talloc_strdup(msg, value);

	if (aname == NULL || aval == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_msg_add_string: talloc_strdup failed!\n");
		return False;
	}

	if (ldb_msg_add_string(msg, aname, aval) != 0) {
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

static struct ldb_message *samldb_fill_group_object(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;

	if (samldb_find_attribute(msg, "objectclass", "group") == NULL) {
		return NULL;
	}

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_fill_group_object\n");

	/* build the new msg */
	msg2 = ldb_msg_copy(module->ldb, msg);
	if (!msg2) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: ldb_msg_copy failed!\n");
		return NULL;
	}

	if (samldb_copy_template(module, msg2, "(&(CN=TemplateGroup)(objectclass=groupTemplate))") != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb_fill_group_object: Error copying template!\n");
		return NULL;
	}

	if ((rdn = ldb_dn_get_rdn(msg2, msg2->dn)) == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: Bad DN (%s)!\n", ldb_dn_linearize(msg2, msg2->dn));
		return NULL;
	}
	if (strcasecmp(rdn->name, "cn") != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: Bad RDN (%s) for group!\n", rdn->name);
		return NULL;
	}

	if ((attribute = samldb_find_attribute(msg2, "objectSid", NULL)) == NULL ) {
		struct dom_sid *sid = samldb_get_new_sid(module, msg2, msg2->dn);
		if (sid == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: internal error! Can't generate new sid\n");
			return NULL;
		}

		if (!samldb_msg_add_sid(module, msg2, "objectSid", sid)) {
			talloc_free(sid);
			return NULL;
		}
		talloc_free(sid);
	}

	if ( ! samldb_find_or_add_attribute(module, msg2, "sAMAccountName", NULL, samldb_generate_samAccountName(msg2))) {
		return NULL;
	}

	talloc_steal(msg, msg2);

	return msg2;
}

static struct ldb_message *samldb_fill_user_or_computer_object(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;

	if ((samldb_find_attribute(msg, "objectclass", "user") == NULL) && 
	    (samldb_find_attribute(msg, "objectclass", "computer") == NULL)) {
		return NULL;
	}

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_fill_user_or_computer_object\n");

	/* build the new msg */
	msg2 = ldb_msg_copy(module->ldb, msg);
	if (!msg2) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_group_object: ldb_msg_copy failed!\n");
		return NULL;
	}

	if (samldb_find_attribute(msg, "objectclass", "computer") != NULL) {
		if (samldb_copy_template(module, msg2, "(&(CN=TemplateComputer)(objectclass=userTemplate))") != 0) {
			ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb_fill_user_or_computer_object: Error copying computer template!\n");
			return NULL;
		}
	} else {
		if (samldb_copy_template(module, msg2, "(&(CN=TemplateUser)(objectclass=userTemplate))") != 0) {
			ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb_fill_user_or_computer_object: Error copying user template!\n");
			return NULL;
		}
	}

	if ((rdn = ldb_dn_get_rdn(msg2, msg2->dn)) == NULL) {
		return NULL;
	}
	if (strcasecmp(rdn->name, "cn") != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_user_or_computer_object: Bad RDN (%s) for user/computer!\n", rdn->name);
		return NULL;
	}

	/* if the only attribute was: "objectclass: computer", then make sure we also add "user" objectclass */
	if ( ! samldb_find_or_add_attribute(module, msg2, "objectclass", "user", "user")) {
		return NULL;
	}

	if ((attribute = samldb_find_attribute(msg2, "objectSid", NULL)) == NULL ) {
		struct dom_sid *sid;
		sid = samldb_get_new_sid(module, msg2, msg2->dn);
		if (sid == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_user_or_computer_object: internal error! Can't generate new sid\n");
			return NULL;
		}

		if ( ! samldb_msg_add_sid(module, msg2, "objectSid", sid)) {
			talloc_free(sid);
			return NULL;
		}
		talloc_free(sid);
	}

	if ( ! samldb_find_or_add_attribute(module, msg2, "sAMAccountName", NULL, samldb_generate_samAccountName(msg2))) {
		return NULL;
	}

	/*
	  useraccountcontrol: setting value 0 gives 0x200 for users
	*/

	/* TODO: objectCategory, userAccountControl, badPwdCount, codePage, countryCode, badPasswordTime, lastLogoff, lastLogon, pwdLastSet, primaryGroupID, accountExpires, logonCount */

	return msg2;
}

static struct ldb_message *samldb_fill_foreignSecurityPrincipal_object(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;

	if (samldb_find_attribute(msg, "objectclass", "foreignSecurityPrincipal") == NULL) {
		return NULL;
	}

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_fill_foreignSecurityPrincipal_object\n");

	/* build the new msg */
	msg2 = ldb_msg_copy(module->ldb, msg);
	if (!msg2) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_foreignSecurityPrincpal_object: ldb_msg_copy failed!\n");
		return NULL;
	}

	talloc_steal(msg, msg2);

	if (samldb_copy_template(module, msg2, "(&(CN=TemplateForeignSecurityPrincipal)(objectclass=foreignSecurityPrincipalTemplate))") != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "samldb_fill_foreignSecurityPrincipal_object: Error copying template!\n");
		return NULL;
	}

	if ((rdn = ldb_dn_get_rdn(msg2, msg2->dn)) == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_foreignSecurityPrincipal_object: Bad DN (%s)!\n", ldb_dn_linearize(msg2, msg2->dn));
		return NULL;
	}
	if (strcasecmp(rdn->name, "cn") != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_foreignSecurityPrincipal_object: Bad RDN (%s) for foreignSecurityPrincpal!\n", rdn->name);
		return NULL;
	}

	if ((attribute = samldb_find_attribute(msg2, "objectSid", NULL)) == NULL ) {
		struct dom_sid *sid = dom_sid_parse_talloc(msg2, (char *)rdn->value.data);
		if (sid == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_fill_foreignSecurityPrincipal_object: internal error! Can't parse sid in CN\n");
			return NULL;
		}

		if (!samldb_msg_add_sid(module, msg2, "objectSid", sid)) {
			talloc_free(sid);
			return NULL;
		}
		talloc_free(sid);
	}

	return msg2;
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
	msg2 = samldb_fill_user_or_computer_object(module, msg);

	/* is group? add all relevant missing objects */
	if ( ! msg2 ) {
		msg2 = samldb_fill_group_object(module, msg);
	}

	/* perhaps a foreignSecurityPrincipal? */
	if ( ! msg2 ) {
		msg2 = samldb_fill_foreignSecurityPrincipal_object(module, msg);
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

static const struct ldb_module_ops samldb_ops = {
	.name          = "samldb",
	.request       = samldb_request
};


/* the init function */
struct ldb_module *samldb_module_init(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *ctx;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	ctx->private_data = NULL;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &samldb_ops;

	talloc_set_destructor(ctx, samldb_destructor);

	return ctx;
}
