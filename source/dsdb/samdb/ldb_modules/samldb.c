/* 
   ldb database library

   Copyright (C) Simo Sorce  2004

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
 *  Component: ldb samldb module
 *
 *  Description: add object timestamping functionality
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_private.h"
#include <time.h>

#define SAM_ACCOUNT_NAME_BASE "$000000-000000000000"

struct private_data {
	const char *error_string;
};

static int samldb_search(struct ldb_module *module, const char *base,
				  enum ldb_scope scope, const char *expression,
				  const char * const *attrs, struct ldb_message ***res)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_search\n");
	return ldb_next_search(module, base, scope, expression, attrs, res);
}

static int samldb_search_free(struct ldb_module *module, struct ldb_message **res)
{
ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_search_free\n");
	return ldb_next_search_free(module, res);
}


/*
  allocate a new id, attempting to do it atomically
  return 0 on failure, the id on success
*/
static int samldb_allocate_next_rid(struct ldb_context *ldb, TALLOC_CTX *mem_ctx,
				   const char *dn, uint32_t *id)
{
	const char * const attrs[2] = { "nextRid", NULL };
	struct ldb_message **res = NULL;
	struct ldb_message msg;
	int ret;
	const char *str;
	struct ldb_val vals[2];
	struct ldb_message_element els[2];

	ret = ldb_search(ldb, dn, LDB_SCOPE_BASE, "nextRid=*", attrs, &res);
	if (ret != 1) {
		if (res) ldb_search_free(ldb, res);
		return -1;
	}
	str = ldb_msg_find_string(res[0], "nextRid", NULL);
	if (str == NULL) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "attribute nextRid not found in %s\n", dn);
		ldb_search_free(ldb, res);
		return -1;
	}
	talloc_steal(mem_ctx, str);
	ldb_search_free(ldb, res);

	*id = strtol(str, NULL, 0);
	if ((*id)+1 == 0) {
		/* out of IDs ! */
		return -1;
	}

	/* we do a delete and add as a single operation. That prevents
	   a race */
	ZERO_STRUCT(msg);
	msg.dn = talloc_strdup(mem_ctx, dn);
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

	vals[0].data = talloc_asprintf(mem_ctx, "%u", *id);
	if (!vals[0].data) {
		return -1;
	}
	vals[0].length = strlen(vals[0].data);

	vals[1].data = talloc_asprintf(mem_ctx, "%u", (*id)+1);
	if (!vals[1].data) {
		return -1;
	}
	vals[1].length = strlen(vals[1].data);

	ret = ldb_modify(ldb, &msg);
	if (ret != 0) {
		return 1;
	}

	(*id)++;

	return 0;
}

/* search the domain related to the provided dn
   allocate a new RID for the domain
   return the new sid string
*/
static char *samldb_get_new_sid(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const char *obj_dn)
{
	const char * const attrs[2] = { "objectSid", NULL };
	struct ldb_message **res = NULL;
	const char *dom_dn, *dom_sid;
	char *obj_sid;
	uint32_t rid;
	int ret, tries = 10;

	/* get the domain component part of the provided dn */

	/* FIXME: quick search here, I think we should use something like
	   ldap_parse_dn here to be 100% sure we get the right domain dn */

	/* FIXME: "dc=" is probably not utf8 safe either,
	   we need a multibyte safe substring search function here */
	
	dom_dn = strstr(obj_dn, "dc=");
	if (dom_dn == NULL) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Invalid dn (%s)!\n", obj_dn);
		return NULL;
	}

	/* find the domain sid */

	ret = ldb_search(ldb, dom_dn, LDB_SCOPE_BASE, "objectSid=*", attrs, &res);
	if (ret != 1) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "samldb_get_new_sid: error retrieving domain sid!\n");
		if (res) ldb_search_free(ldb, res);
		return NULL;
	}

	dom_sid = ldb_msg_find_string(res[0], "objectSid", NULL);
	if (dom_sid == NULL) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "samldb_get_new_sid: error retrieving domain sid!\n");
		ldb_search_free(ldb, res);
		return NULL;
	}

	talloc_steal(mem_ctx, dom_sid);
	ldb_search_free(ldb, res);

	/* allocate a new Rid for the domain */


	/* we need to try multiple times to cope with two account
	   creations at the same time */
	while (tries--) {
		ret = samldb_allocate_next_rid(ldb, mem_ctx, dom_dn, &rid);
		if (ret != 1) {
			break;
		}
	}
	if (ret != 0) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Failed to increment nextRid of %s\n", dom_dn);
		return NULL;
	}

	/* return the new object sid */

	obj_sid = talloc_asprintf(mem_ctx, "%s-%u", dom_sid, rid);

	return obj_sid;
}

static char *samldb_generate_samAccountName(const void *mem_ctx) {
	char *name;

	name = talloc_strdup(mem_ctx, SAM_ACCOUNT_NAME_BASE);
	/* TODO: randomize name */	

	return name;
}

static BOOL samldb_get_rdn_and_basedn(const void *mem_ctx, const char *dn, char **rdn, char **basedn)
{
	char *p;

	p = strchr(dn, ',');
	if ( ! p ) {
		return False;
	}
	/* clear separator */
	*p = '\0';

	*rdn = talloc_strdup(mem_ctx, dn);

	/* put back separator */
	*p = ',';

	if ( ! *rdn) {
		return False;
	}

	*basedn = talloc_strdup(mem_ctx, p + 1);

	if ( ! *basedn) {
		talloc_free(*rdn);
		*rdn = NULL;
		return False;
	}

	return True;
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
				if (strcasecmp(value, msg->elements[i].values[j].data) == 0) {
					return &msg->elements[i];
				}
			}
		}
	}

	return NULL;
}

static BOOL samldb_add_attribute(struct ldb_message *msg, const char *name, const char *value)
{
	struct ldb_message_element *attr;
	int i;

	attr = samldb_find_attribute(msg, name, NULL);
	if ( ! attr) {
		msg->num_elements++;
		msg->elements = talloc_realloc(msg, msg->elements, struct ldb_message_element, msg->num_elements);
		if ( ! msg->elements ) {
			return False;
		}
		attr = &msg->elements[msg->num_elements - 1];

		attr->name = talloc_strdup(msg, name);
		if ( ! attr->name ) {
			return False;
		}
		attr->flags = 0;
		attr->num_values = 0;
		attr->values = NULL;
	}

	i = attr->num_values;
	attr->num_values++;
	attr->values = talloc_realloc(msg, attr->values, struct ldb_val, attr->num_values);
	if ( ! attr->values ){
		return False;
	}

	attr->values[i].data = talloc_strdup(msg, value);
	attr->values[i].length = strlen(value);

	if ( ! attr->values[i].data) {
		return False;
	}

	return True;
}

static BOOL samldb_find_or_add_attribute(struct ldb_message *msg, const char *name, const char *value, const char *set_value)
{
	if (samldb_find_attribute(msg, name, value) == NULL) {
		if ( ! samldb_add_attribute(msg, name, set_value)) {
			return False;
		}
	}
	return True;
}

static struct ldb_message *samldb_manage_group_object(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	char *rdn, *basedn;
	int i;

	if (samldb_find_attribute(msg, "objectclass", "group") == NULL) {
		return NULL;
	}

	msg2 = talloc(module, struct ldb_message);
	if (!msg2) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_group_object: talloc failed!\n");
		return NULL;
	}

	/* build the new msg */
	msg2->dn = msg->dn;
	msg2->num_elements = msg->num_elements;
	msg2->private_data = msg->private_data;
	msg2->elements = talloc_array(msg2, struct ldb_message_element, msg2->num_elements);
	if (! msg2->elements) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_group_object: talloc_array failed!\n");
		talloc_free(msg2);
		return NULL;
	}
	for (i = 0; i < msg2->num_elements; i++) {
		msg2->elements[i] = msg->elements[i];
	}

	if ( ! samldb_get_rdn_and_basedn(msg2, msg2->dn, &rdn, &basedn)) {
		talloc_free(msg2);
		return NULL;
	}
	if (strncasecmp(rdn, "cn", 2) != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_group_object: Bad RDN (%s) for group!\n", rdn);
		talloc_free(msg2);
		return NULL;
	}

	if (! samldb_find_or_add_attribute(msg2, "objectclass", "top", "top")) {
		talloc_free(msg2);
		return NULL;
	}

	if ((attribute = samldb_find_attribute(msg2, "cn", NULL)) != NULL) {
		if (strcasecmp(rdn, attribute->values[0].data) != 0) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_group_object: Bad Attribute Syntax for CN\n");
			talloc_free(msg2);
			return NULL;
		}
	} else { /* FIXME: remove this if ldb supports natively aliasing between the rdn and the "cn" attribute */
		if ( ! samldb_add_attribute(msg2, "cn", &rdn[3])) {
			talloc_free(msg2);
			return NULL;
		}
	}

	if ((attribute = samldb_find_attribute(msg2, "name", NULL)) != NULL) {
		if (strcasecmp(rdn, attribute->values[0].data) != 0) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_group_object: Bad Attribute Syntax for name\n");
			talloc_free(msg2);
			return NULL;
		}
	} else { /* FIXME: remove this if ldb supports natively aliasing between the rdn and the "name" attribute */
		if ( ! samldb_add_attribute(msg2, "name", &rdn[3])) {
			talloc_free(msg2);
			return NULL;
		}
	}

	if ((attribute = samldb_find_attribute(msg2, "objectSid", NULL)) == NULL ) {
		char *sidstr;

		if ((sidstr = samldb_get_new_sid(module->ldb, msg2, msg2->dn)) == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_group_object: internal error! Can't generate new sid\n");
			talloc_free(msg2);
			return NULL;
		}
		
		if ( ! samldb_add_attribute(msg2, "objectSid", sidstr)) {
			talloc_free(msg2);
			return NULL;
		}
	}

	if ( ! samldb_find_or_add_attribute(msg2, "instanceType", NULL, "4")) {
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "sAMAccountName", NULL, samldb_generate_samAccountName(msg2))) {
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "sAMAccountType", NULL, "268435456")) {
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "groupType", NULL, "-2147483646")) {
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "objectCategory", NULL, "foo")) { /* keep the schema module happy :) */
		return NULL;
	}

	/* TODO: objectGUID, objectSid, objectCategory */
	/* need a way to lock a new Sid */

	return msg2;
}

static struct ldb_message *samldb_manage_user_object(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	char *rdn, *basedn;
	int i;

	if (samldb_find_attribute(msg, "objectclass", "user") == NULL) {
		return NULL;
	}

	msg2 = talloc(module, struct ldb_message);
	if (!msg2) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_user_object: talloc failed!\n");
		return NULL;
	}

	/* build the new msg */
	msg2->dn = msg->dn;
	msg2->num_elements = msg->num_elements;
	msg2->private_data = msg->private_data;
	msg2->elements = talloc_array(msg2, struct ldb_message_element, msg2->num_elements);
	if (! msg2->elements) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_user_object: talloc_array failed!\n");
		talloc_free(msg2);
		return NULL;
	}
	for (i = 0; i < msg2->num_elements; i++) {
		msg2->elements[i] = msg->elements[i];
	}

	if ( ! samldb_get_rdn_and_basedn(msg2, msg2->dn, &rdn, &basedn)) {
		talloc_free(msg2);
		return NULL;
	}
	if (strncasecmp(rdn, "cn", 2) != 0) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_group_object: Bad RDN (%s) for group!\n", rdn);
		talloc_free(msg2);
		return NULL;
	}


	if ( ! samldb_find_or_add_attribute(msg2, "objectclass", "top", "top")) {
		talloc_free(msg2);
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "objectclass", "person", "person")) {
		talloc_free(msg2);
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "objectclass", "organizationalPerson", "organizationalPerson")) {
		talloc_free(msg2);
		return NULL;
	}

	if ((attribute = samldb_find_attribute(msg2, "cn", NULL)) != NULL) {
		if (strcasecmp(rdn, attribute->values[0].data) != 0) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_user_object: Bad Attribute Syntax for CN\n");
			talloc_free(msg2);
			return NULL;
		}
	} else { /* FIXME: remove this if ldb supports natively aliasing between the rdn and the "cn" attribute */
		if ( ! samldb_add_attribute(msg2, "cn", &rdn[3])) {
			talloc_free(msg2);
			return NULL;
		}
	}

	if ((attribute = samldb_find_attribute(msg2, "name", NULL)) != NULL) {
		if (strcasecmp(rdn, attribute->values[0].data) != 0) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_user_object: Bad Attribute Syntax for name\n");
			talloc_free(msg2);
			return NULL;
		}
	} else { /* FIXME: remove this if ldb supports natively aliasing between the rdn and the "name" attribute */
		if ( ! samldb_add_attribute(msg2, "name", &rdn[3])) {
			talloc_free(msg2);
			return NULL;
		}
	}

	if ((attribute = samldb_find_attribute(msg2, "objectSid", NULL)) == NULL ) {
		char *sidstr;

		if ((sidstr = samldb_get_new_sid(module->ldb, msg2, msg2->dn)) == NULL) {
			ldb_debug(module->ldb, LDB_DEBUG_FATAL, "samldb_manage_user_object: internal error! Can't generate new sid\n");
			talloc_free(msg2);
			return NULL;
		}
		
		if ( ! samldb_add_attribute(msg2, "objectSid", sidstr)) {
			talloc_free(msg2);
			return NULL;
		}
	}

	if ( ! samldb_find_or_add_attribute(msg2, "instanceType", NULL, "4")) {
		talloc_free(msg2);
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "sAMAccountName", NULL, samldb_generate_samAccountName(msg2))) {
		talloc_free(msg2);
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "sAMAccountType", NULL, "805306368")) {
		talloc_free(msg2);
		return NULL;
	}

	if ( ! samldb_find_or_add_attribute(msg2, "objectCategory", NULL, "foo")) { /* keep the schema module happy :) */
		return NULL;
	}

	/* TODO: objectGUID, objectSid, objectCategory, userAccountControl, badPwdCount, codePage, countryCode, badPasswordTime, lastLogoff, lastLogon, pwdLastSet, primaryGroupID, accountExpires, logonCount */

	return msg2;
}

/* add_record */
static int samldb_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2 = NULL;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_add_record\n");

	if (msg->dn[0] == '@') { /* do not manipulate our control entries */
		return ldb_next_add_record(module, msg);
	}

	/* is group?  add all group relevant missing objects */
	msg2 = samldb_manage_group_object(module, msg);

	/* is user? add all user relevant missing objects */
	if ( ! msg2 ) {
		msg2 = samldb_manage_user_object(module, msg);
	}

	if (msg2) {
		ret = ldb_next_add_record(module, msg2);
		talloc_free(msg2);
	} else {
		ret = ldb_next_add_record(module, msg);
	}

	return ret;
}

/* modify_record: change modifyTimestamp as well */
static int samldb_modify_record(struct ldb_module *module, const struct ldb_message *msg)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_modify_record\n");
	return ldb_next_modify_record(module, msg);
}

static int samldb_delete_record(struct ldb_module *module, const char *dn)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_delete_record\n");
	return ldb_next_delete_record(module, dn);
}

static int samldb_rename_record(struct ldb_module *module, const char *olddn, const char *newdn)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_rename_record\n");
	return ldb_next_rename_record(module, olddn, newdn);
}

static int samldb_lock(struct ldb_module *module, const char *lockname)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_lock\n");
	return ldb_next_named_lock(module, lockname);
}

static int samldb_unlock(struct ldb_module *module, const char *lockname)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_unlock\n");
	return ldb_next_named_unlock(module, lockname);
}

/* return extended error information */
static const char *samldb_errstring(struct ldb_module *module)
{
	struct private_data *data = (struct private_data *)module->private_data;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "samldb_errstring\n");
	if (data->error_string) {
		const char *error;

		error = data->error_string;
		data->error_string = NULL;
		return error;
	}

	return ldb_next_errstring(module);
}

static int samldb_destructor(void *module_ctx)
{
	struct ldb_module *ctx = module_ctx;
	/* put your clean-up functions here */
	return 0;
}

static const struct ldb_module_ops samldb_ops = {
	"samldb",
	samldb_search,
	samldb_search_free,
	samldb_add_record,
	samldb_modify_record,
	samldb_delete_record,
	samldb_rename_record,
	samldb_lock,
	samldb_unlock,
	samldb_errstring
};


/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *samldb_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;
	struct private_data *data;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	data = talloc(ctx, struct private_data);
	if (!data) {
		talloc_free(ctx);
		return NULL;
	}

	data->error_string = NULL;
	ctx->private_data = data;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &samldb_ops;

	talloc_set_destructor(ctx, samldb_destructor);

	return ctx;
}
