/*
   ldb database module to enforce unique local objectSIDs

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*

   Duplicate ObjectSIDs are possible on foreign security principals and
   replication conflict records.  However a duplicate objectSID within
   the local domainSID is an error.

   As the uniqueness requirement depends on the source domain it is not possible
   to enforce this with a unique index.

   This module sets the LDB_FLAG_FORCE_UNIQUE_INDEX for objectSIDs in the
   local domain.
*/

#include "includes.h"
#include "ldb_module.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/dom_sid.h"
#include "dsdb/samdb/ldb_modules/util.h"

struct private_data {
	const struct dom_sid *domain_sid;
};


/*
 * Does the add request contain a local objectSID
 */
static bool message_contains_local_objectSID(
	struct ldb_module *module,
	const struct ldb_message *msg)
{
	struct dom_sid *objectSID	= NULL;

	struct private_data *data =
		talloc_get_type(
			ldb_module_get_private(module),
			struct private_data);

	TALLOC_CTX *frame = talloc_stackframe();

	objectSID = samdb_result_dom_sid(frame, msg, "objectSID");
	if (objectSID == NULL) {
		TALLOC_FREE(frame);
		return false;
	}

	/*
	 * data->domain_sid can be NULL but dom_sid_in_domain handles this
	 * case correctly. See unique_object_sids_init for more details.
	 */
	if (!dom_sid_in_domain(data->domain_sid, objectSID)) {
		TALLOC_FREE(frame);
		return false;
	}
	TALLOC_FREE(frame);
	return true;
}

static int flag_objectSID(
	struct ldb_module *module,
	struct ldb_request *req,
	const struct ldb_message *msg,
	struct ldb_message **new_msg)
{
	struct ldb_message_element *el	= NULL;

	*new_msg = ldb_msg_copy_shallow(req, msg);
	if (!*new_msg) {
		return ldb_module_oom(module);
	}

	el = ldb_msg_find_element(*new_msg, "objectSID");
	if (el == NULL) {
		struct ldb_context *ldb = NULL;
		ldb = ldb_module_get_ctx(module);
		ldb_asprintf_errstring(
			ldb,
			"Unable to locate objectSID in copied request\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}
	el->flags |= LDB_FLAG_INTERNAL_FORCE_UNIQUE_INDEX;
	return LDB_SUCCESS;
}

/* add */
static int unique_object_sids_add(
	struct ldb_module *module,
	struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
	struct ldb_message *new_msg	= NULL;
	struct ldb_request *new_req	= NULL;
	struct ldb_context *ldb		= NULL;
	int rc;

	if (!message_contains_local_objectSID(module, msg)) {
		/*
		 * Request does not contain a local objectSID so chain the
		 * next module
		 */
		return ldb_next_request(module, req);
	}

	/*
	 * The add request contains an objectSID for the local domain
	 */

	rc = flag_objectSID(module, req, msg, &new_msg);
	if (rc != LDB_SUCCESS) {
		return rc;
	}

	ldb = ldb_module_get_ctx(module);
	rc = ldb_build_add_req(
		&new_req,
		ldb,
		req,
		new_msg,
		req->controls,
		req,
		dsdb_next_callback,
		req);
	if (rc != LDB_SUCCESS) {
		return rc;
	}

	return ldb_next_request(module, new_req);
}

/* modify */
static int unique_object_sids_modify(
	struct ldb_module *module,
	struct ldb_request *req)
{

	const struct ldb_message *msg	= req->op.mod.message;
	struct ldb_message *new_msg	= NULL;
	struct ldb_request *new_req	= NULL;
	struct ldb_context *ldb		= NULL;
	int rc;

	if (!message_contains_local_objectSID(module, msg)) {
		/*
		 * Request does not contain a local objectSID so chain the
		 * next module
		 */
		return ldb_next_request(module, req);
	}

	ldb = ldb_module_get_ctx(module);

	/*
	 * If DSDB_CONTROL_REPLICATED_UPDATE_OID replicated is set we know
	 * that the modify request is well formed and objectSID only appears
	 * once.
	 *
	 * Enforcing this assumption simplifies the subsequent code.
	 *
	 */
	if(!ldb_request_get_control(req, DSDB_CONTROL_REPLICATED_UPDATE_OID)) {
		ldb_asprintf_errstring(
			ldb,
			"Modify of %s rejected, "
			"as it is modifying an objectSID\n",
			ldb_dn_get_linearized(msg->dn));
		return LDB_ERR_UNWILLING_TO_PERFORM;
	}


	rc = flag_objectSID(module, req, msg, &new_msg);
	if (rc != LDB_SUCCESS) {
		return rc;
	}

	ldb = ldb_module_get_ctx(module);
	rc = ldb_build_mod_req(
		&new_req,
		ldb,
		req,
		new_msg,
		req->controls,
		req,
		dsdb_next_callback,
		req);
	if (rc != LDB_SUCCESS) {
		return rc;
	}

	return ldb_next_request(module, new_req);
}

/* init */
static int unique_object_sids_init(
	struct ldb_module *module)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct private_data *data = NULL;
	int ret;

	ret = ldb_next_init(module);

	if (ret != LDB_SUCCESS) {
		return ret;
	}

	data = talloc_zero(module, struct private_data);
	if (!data) {
		return ldb_module_oom(module);
	}

	data->domain_sid = samdb_domain_sid(ldb);
	if (data->domain_sid == NULL) {
		/*
		 * Unable to determine the domainSID, this normally occurs
		 * when provisioning. As there is no easy way to detect
		 * that we are provisioning.  We currently just log this as a
		 * warning.
		 */
		ldb_debug(
			ldb,
			LDB_DEBUG_WARNING,
			"Unable to determine the DomainSID, "
			"can not enforce uniqueness constraint on local "
			"domainSIDs\n");
	}

	ldb_module_set_private(module, data);

	return LDB_SUCCESS;
}

static const struct ldb_module_ops ldb_unique_object_sids_module_ops = {
	.name		   = "unique_object_sids",
	.init_context	   = unique_object_sids_init,
	.add               = unique_object_sids_add,
	.modify            = unique_object_sids_modify,
};

int ldb_unique_object_sids_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_unique_object_sids_module_ops);
}
