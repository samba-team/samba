/*
   Unix SMB/CIFS implementation.
   msDS-ManagedPassword attribute for Group Managed Service Accounts

   Copyright (C) Catalyst.Net Ltd 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <talloc.h>
#include <ldb.h>
#include <ldb_module.h>
#include <ldb_errors.h>
#include <ldb_private.h>
#include "lib/crypto/gmsa.h"
#include "lib/util/time.h"
#include "librpc/gen_ndr/ndr_gkdi.h"
#include "librpc/gen_ndr/ndr_gmsa.h"
#include "dsdb/gmsa/util.h"
#include "dsdb/samdb/ldb_modules/managed_pwd.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/samdb.h"

#undef strcasecmp

static int gmsa_managed_password(struct ldb_context *const ldb,
				 struct ldb_message *msg,
				 struct ldb_request *req,
				 struct ldb_reply *ares)
{
	TALLOC_CTX *tmp_ctx = NULL;
	const struct dsdb_encrypted_connection_state *conn_state = NULL;
	int ret = LDB_SUCCESS;
	NTSTATUS status = NT_STATUS_OK;
	NTTIME current_time;
	struct gmsa_update *gmsa_update = NULL;
	struct gmsa_return_pwd return_pwd;
	bool ok;

	/*
	 * Prevent viewing msDS-ManagedPassword over an insecure connection. The
	 * opaque is added in the ldap backend init.
	 */
	conn_state = ldb_get_opaque(
		ldb, DSDB_OPAQUE_ENCRYPTED_CONNECTION_STATE_NAME);
	if (conn_state != NULL && !conn_state->using_encrypted_connection) {
		ret = dsdb_werror(ldb,
				  LDB_ERR_OPERATIONS_ERROR,
				  WERR_DS_CONFIDENTIALITY_REQUIRED,
				  "Viewing msDS-ManagedPassword requires an "
				  "encrypted connection");
		goto out;
	}

	{
		/* Is the account a Group Managed Service Account? */
		const bool is_gmsa = dsdb_account_is_gmsa(ldb, msg);
		if (!is_gmsa) {
			/* It’s not a GMSA — we’re done here. */
			ret = LDB_SUCCESS;
			goto out;
		}
	}

	{
		bool am_rodc = true;

		/* Are we operating as an RODC? */
		ret = samdb_rodc(ldb, &am_rodc);
		if (ret != LDB_SUCCESS) {
			DBG_WARNING("unable to tell if we are an RODC\n");
			goto out;
		}

		if (am_rodc) {
			/* TODO: forward the request to a writable DC. */
			ret = ldb_error(
				ldb,
				LDB_ERR_OPERATIONS_ERROR,
				"msDS-ManagedPassword may only be viewed on a "
				"writeable DC, not an RODC");
			goto out;
		}
	}

	tmp_ctx = talloc_new(msg);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	{
		struct dom_sid account_sid;
		bool allowed_to_view = false;

		ret = samdb_result_dom_sid_buf(msg, "objectSid", &account_sid);
		if (ret) {
			goto out;
		}

		ret = gmsa_allowed_to_view_managed_password(
			tmp_ctx, ldb, msg, &account_sid, &allowed_to_view);
		if (ret) {
			goto out;
		}

		if (!allowed_to_view) {
			/* Sorry, you can’t view the password. */
			ret = LDB_SUCCESS;
			goto out;
		}
	}

	ok = dsdb_gmsa_current_time(ldb, &current_time);
	if (!ok) {
		ret = ldb_operr(ldb);
		goto out;
	}

	ret = gmsa_recalculate_managed_pwd(
		tmp_ctx, ldb, msg, current_time, &gmsa_update, &return_pwd);
	if (ret) {
		goto out;
	}

	SMB_ASSERT(return_pwd.new_pwd != NULL);

	if (gmsa_update != NULL) {
		/*
		 * Return a control to indicate to the LDAP server that it needs
		 * to refresh the physical passwords — that is, the keys in the
		 * database, and the ManagedPasswordId attribute.
		 */
		ret = ldb_reply_add_control(ares,
					    DSDB_CONTROL_GMSA_UPDATE_OID,
					    false,
					    gmsa_update);
		if (ret) {
			/* Ignore the error. */
			ret = LDB_SUCCESS;
		} else {
			/*
			 * Link the lifetime of the GMSA update control to that
			 * of the reply.
			 */
			talloc_steal(ares, gmsa_update);
		}
	}

	{
		DATA_BLOB packed_blob = {};

		status = gmsa_pack_managed_pwd(
			tmp_ctx,
			return_pwd.new_pwd->buf,
			return_pwd.prev_pwd != NULL ? return_pwd.prev_pwd->buf
						    : NULL,
			return_pwd.query_interval,
			return_pwd.unchanged_interval,
			&packed_blob);
		if (!NT_STATUS_IS_OK(status)) {
			ret = ldb_operr(ldb);
			goto out;
		}

		ret = ldb_msg_add_steal_value(msg,
					      "msDS-ManagedPassword",
					      &packed_blob);
		if (ret) {
			goto out;
		}
	}

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

int constructed_msds_managed_password(struct ldb_module *module,
				      struct ldb_message *msg,
				      enum ldb_scope scope,
				      struct ldb_request *parent,
				      struct ldb_reply *ares)
{
	return gmsa_managed_password(ldb_module_get_ctx(module),
				     msg,
				     parent,
				     ares);
}
