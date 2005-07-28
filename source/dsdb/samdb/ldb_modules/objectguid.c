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
#include "librpc/gen_ndr/ndr_misc.h"
#include <time.h>

struct private_data {
	const char *error_string;
};

static int objectguid_search(struct ldb_module *module, const char *base,
				  enum ldb_scope scope, const char *expression,
				  const char * const *attrs, struct ldb_message ***res)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_search\n");
	return ldb_next_search(module, base, scope, expression, attrs, res);
}

static int objectguid_search_bytree(struct ldb_module *module, const char *base,
				    enum ldb_scope scope, struct ldb_parse_tree *tree,
				    const char * const *attrs, struct ldb_message ***res)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_search\n");
	return ldb_next_search_bytree(module, base, scope, tree, attrs, res);
}

static struct ldb_message_element *objectguid_find_attribute(const struct ldb_message *msg, const char *name)
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
static int objectguid_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_val v;
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct GUID guid;
	NTSTATUS nt_status;
	int ret, i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_add_record\n");

	if (msg->dn[0] == '@') { /* do not manipulate our control entries */
		return ldb_next_add_record(module, msg);
	}

	if ((attribute = objectguid_find_attribute(msg, "objectGUID")) != NULL ) {
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

	/* a new GUID */
	guid = GUID_random();

	nt_status = ndr_push_struct_blob(&v, msg2, &guid, 
					 (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return -1;
	}

	ret = ldb_msg_add_value(module->ldb, msg2, "objectGUID", &v);
	if (ret) {
		return ret;
	}

	ret = ldb_next_add_record(module, msg2);
	talloc_free(msg2);

	return ret;
}

/* modify_record: change modifyTimestamp as well */
static int objectguid_modify_record(struct ldb_module *module, const struct ldb_message *msg)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_modify_record\n");
	return ldb_next_modify_record(module, msg);
}

static int objectguid_delete_record(struct ldb_module *module, const char *dn)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_delete_record\n");
	return ldb_next_delete_record(module, dn);
}

static int objectguid_rename_record(struct ldb_module *module, const char *olddn, const char *newdn)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_rename_record\n");
	return ldb_next_rename_record(module, olddn, newdn);
}

static int objectguid_lock(struct ldb_module *module, const char *lockname)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_lock\n");
	return ldb_next_named_lock(module, lockname);
}

static int objectguid_unlock(struct ldb_module *module, const char *lockname)
{
	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_unlock\n");
	return ldb_next_named_unlock(module, lockname);
}

/* return extended error information */
static const char *objectguid_errstring(struct ldb_module *module)
{
	struct private_data *data = (struct private_data *)module->private_data;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_errstring\n");
	if (data->error_string) {
		const char *error;

		error = data->error_string;
		data->error_string = NULL;
		return error;
	}

	return ldb_next_errstring(module);
}

static int objectguid_destructor(void *module_ctx)
{
	/* struct ldb_module *ctx = module_ctx; */
	/* put your clean-up functions here */
	return 0;
}

static const struct ldb_module_ops objectguid_ops = {
	.name          = "objectguid",
	.search        = objectguid_search,
	.search_bytree = objectguid_search_bytree,
	.add_record    = objectguid_add_record,
	.modify_record = objectguid_modify_record,
	.delete_record = objectguid_delete_record,
	.rename_record = objectguid_rename_record,
	.named_lock    = objectguid_lock,
	.named_unlock  = objectguid_unlock,
	.errstring     = objectguid_errstring
};


/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *objectguid_module_init(struct ldb_context *ldb, const char *options[])
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
	ctx->ops = &objectguid_ops;

	talloc_set_destructor (ctx, objectguid_destructor);

	return ctx;
}
