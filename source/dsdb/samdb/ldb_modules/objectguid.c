/* 
   ldb database library

   Copyright (C) Simo Sorce  2004
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

/* add_record: add objectGUID attribute */
static int objectguid_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
	struct ldb_val v;
	struct ldb_message *msg2;
	struct ldb_message_element *attribute;
	struct GUID guid;
	NTSTATUS nt_status;
	int ret, i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_add_record\n");

	if (ldb_dn_is_special(msg->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	if ((attribute = objectguid_find_attribute(msg, "objectGUID")) != NULL ) {
		return ldb_next_request(module, req);
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

	ret = ldb_msg_add_value(msg2, "objectGUID", &v);
	if (ret) {
		return ret;
	}

	req->op.add.message = msg2;
	ret = ldb_next_request(module, req);
	req->op.add.message = msg;

	talloc_free(msg2);

	return ret;
}

static int objectguid_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_ADD:
		return objectguid_add(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static const struct ldb_module_ops objectguid_ops = {
	.name          = "objectguid",
	.request       = objectguid_request
};


/* the init function */
#ifdef HAVE_DLOPEN_DISABLED
 struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *objectguid_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	ctx->private_data = NULL;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &objectguid_ops;

	return ctx;
}
