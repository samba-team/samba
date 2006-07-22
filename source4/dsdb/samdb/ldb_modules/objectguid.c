/* 
   ldb database library

   Copyright (C) Simo Sorce  2004-2006
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
#include "ldb/include/includes.h"
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
	struct ldb_request *down_req;
	struct ldb_message_element *attribute;
	struct ldb_message *msg;
	struct ldb_val v;
	struct GUID guid;
	NTSTATUS nt_status;
	int ret;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "objectguid_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	if ((attribute = objectguid_find_attribute(req->op.add.message, "objectGUID")) != NULL ) {
		return ldb_next_request(module, req);
	}

	down_req = talloc(req, struct ldb_request);
	if (down_req == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*down_req = *req;

	/* we have to copy the message as the caller might have it as a const */
	down_req->op.add.message = msg = ldb_msg_copy_shallow(down_req, req->op.add.message);
	if (msg == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* a new GUID */
	guid = GUID_random();

	nt_status = ndr_push_struct_blob(&v, msg, &guid, 
					 (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return -1;
	}

	ret = ldb_msg_add_value(msg, "objectGUID", &v);
	if (ret) {
		return ret;
	}
	
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

static const struct ldb_module_ops objectguid_ops = {
	.name          = "objectguid",
	.add           = objectguid_add,
};


int objectguid_module_init(void)
{
	return ldb_register_module(&objectguid_ops);
}
