/* 
   ldb database library

   Copyright (C) Simo Sorce  2004-2006
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb instancetype module
 *
 *  Description: add an instanceType onto every new record
 *
 *  Author: Andrew Bartlett
 */

#include "includes.h"
#include "ldb/include/ldb_includes.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/flags.h"

/* add_record: add instancetype attribute */
static int instancetype_add(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_request *down_req;
	struct ldb_message *msg;
	uint32_t instance_type;
	int ret;
	const struct ldb_control *partition_ctrl;
	const struct dsdb_control_current_partition *partition;
 

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "instancetype_add_record\n");

	/* do not manipulate our control entries */
	if (ldb_dn_is_special(req->op.add.message->dn)) {
		return ldb_next_request(module, req);
	}

	partition_ctrl = ldb_request_get_control(req, DSDB_CONTROL_CURRENT_PARTITION_OID);
	if (!partition_ctrl) {
		ldb_debug_set(module->ldb, LDB_DEBUG_FATAL,
			      "instancetype_add: no current partition control found");
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	partition = talloc_get_type(partition_ctrl->data,
				    struct dsdb_control_current_partition);
	SMB_ASSERT(partition && partition->version == DSDB_CONTROL_CURRENT_PARTITION_VERSION);

	down_req = talloc(req, struct ldb_request);
	if (down_req == NULL) {
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*down_req = *req;

	/* we have to copy the message as the caller might have it as a const */
	down_req->op.add.message = msg = ldb_msg_copy_shallow(down_req, req->op.add.message);
	if (msg == NULL) {
		talloc_free(down_req);
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/*
	 * TODO: calculate correct instance type
	 */
	instance_type = INSTANCE_TYPE_WRITE;
	if (ldb_dn_compare(partition->dn, msg->dn) == 0) {
		instance_type |= INSTANCE_TYPE_IS_NC_HEAD;
		if (ldb_dn_compare(msg->dn, samdb_base_dn(module->ldb)) != 0) {
			instance_type |= INSTANCE_TYPE_NC_ABOVE;
		}
	}

	ret = ldb_msg_add_fmt(msg, "instanceType", "%u", instance_type);
	if (ret != LDB_SUCCESS) {
		talloc_free(down_req);
		ldb_oom(module->ldb);
		return LDB_ERR_OPERATIONS_ERROR;
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

_PUBLIC_ const struct ldb_module_ops ldb_instancetype_module_ops = {
	.name          = "instancetype",
	.add           = instancetype_add,
};
