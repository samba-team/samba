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
 *  Component: ldb objectguid module
 *
 *  Description: add a unique objectGUID onto every new record
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include <time.h>

static int rdn_name_search_bytree(struct ldb_module *module, const struct ldb_dn *base,
				  enum ldb_scope scope, struct ldb_parse_tree *tree,
				  const char * const *attrs, struct ldb_message ***res)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "rdn_name_search\n");
	return ldb_next_search_bytree(module, base, scope, tree, attrs, res);
}

static struct ldb_message_element *rdn_name_find_attribute(const struct ldb_message *msg, const char *name)
{
	int i;

	for (i = 0; i < msg->num_elements; i++) {
		if (ldb_attr_cmp(name, msg->elements[i].name) == 0) {
			return &msg->elements[i];
		}
	}

	return NULL;
}

/* add_record: add crateTimestamp/modifyTimestamp attributes */
static int rdn_name_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;
	int i, ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "rdn_name_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_add_record(module, msg);
	}

	/* Perhaps someone above us knows better */
	if ((attribute = rdn_name_find_attribute(msg, "name")) != NULL ) {
		return ldb_next_add_record(module, msg);
	}

	msg2 = talloc(module, struct ldb_message);
	if (!msg2) {
		return -1;
	}

	msg2->dn = msg->dn;
	msg2->num_elements = msg->num_elements;
	msg2->private_data = msg->private_data;
	msg2->elements = talloc_array(msg2, struct ldb_message_element, msg2->num_elements);
	for (i = 0; i < msg2->num_elements; i++) {
		msg2->elements[i] = msg->elements[i];
	}

	rdn = ldb_dn_get_rdn(msg2, msg2->dn);
	if (!rdn) {
		talloc_free(msg2);
		return -1;
	}
	
	if (ldb_msg_add_value(module->ldb, msg2, "name", &rdn->value) != 0) {
		talloc_free(msg2);
		return -1;
	}

	attribute = rdn_name_find_attribute(msg2, rdn->name);

	if (!attribute) {
		if (ldb_msg_add_value(module->ldb, msg2, rdn->name, &rdn->value) != 0) {
			talloc_free(msg2);
			return -1;
		}
	} else {
		const struct ldb_attrib_handler *handler
			= ldb_attrib_handler(module->ldb, rdn->name);
		for (i=0; i < attribute->num_values; i++) {
			if (handler->comparison_fn(module->ldb, msg2, &rdn->value, &attribute->values[i]) == 0) {
				/* overwrite so it matches in case */
				attribute->values[i] = rdn->value;
				break;
			}
		}
		if (i == attribute->num_values) {
			char *error_string = talloc_asprintf(module, "RDN mismatch on %s: %s", ldb_dn_linearize(msg2, msg2->dn), rdn->name);
			if (error_string) {
				ldb_set_errstring(module, error_string);
				ldb_debug(module->ldb, LDB_DEBUG_FATAL, "%s\n", error_string);
			}
			talloc_free(msg2);
			return -1;
		}
	}

	ret = ldb_next_add_record(module, msg2);
	talloc_free(msg2);

	return ret;
}

/* modify_record: change modifyTimestamp as well */
static int rdn_name_modify_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct ldb_dn_component *rdn;
	int ret, i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "rdn_name_modify_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_modify_record(module, msg);
	}

	/* Perhaps someone above us knows better */
	if ((attribute = rdn_name_find_attribute(msg, "name")) != NULL ) {
		return ldb_next_modify_record(module, msg);
	}

	msg2 = talloc(module, struct ldb_message);
	if (!msg2) {
		return -1;
	}

	msg2->dn = msg->dn;
	msg2->num_elements = msg->num_elements;
	msg2->private_data = msg->private_data;
	msg2->elements = talloc_array(msg2, struct ldb_message_element, msg2->num_elements);
	for (i = 0; i < msg2->num_elements; i++) {
		msg2->elements[i] = msg->elements[i];
	}
	
	rdn = ldb_dn_get_rdn(msg2, msg2->dn);
	if (!rdn) {
		talloc_free(msg2);
		return -1;
	}
	
	if (ldb_msg_add_value(module->ldb, msg2, "name", &rdn->value) != 0) {
		talloc_free(msg2);
		return -1;
	}

	attribute = rdn_name_find_attribute(msg2, "name");
	if (!attribute) {
		talloc_free(msg2);
		return -1;
	}

	attribute->flags = LDB_FLAG_MOD_REPLACE;

	ret = ldb_next_modify_record(module, msg2);
	talloc_free(msg2);

	return ret;
}

static int rdn_name_rename_record(struct ldb_module *module, const struct ldb_dn *olddn, const struct ldb_dn *newdn)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "rdn_name_rename_record\n");
	return ldb_next_rename_record(module, olddn, newdn);
}

static const struct ldb_module_ops rdn_name_ops = {
	.name              = "rdn_name",
	.search_bytree     = rdn_name_search_bytree,
	.add_record        = rdn_name_add_record,
	.modify_record     = rdn_name_modify_record,
	.rename_record     = rdn_name_rename_record
};


/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *rdn_name_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	ctx->private_data = NULL;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &rdn_name_ops;

	return ctx;
}
