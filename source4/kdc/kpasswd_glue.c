/*
   Unix SMB/CIFS implementation.

   kpasswd Server implementation

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell	2005

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

#include "includes.h"
#include "dsdb/samdb/samdb.h"
#include "../lib/util/util_ldb.h"
#include "libcli/security/security.h"
#include "dsdb/common/util.h"
#include "auth/auth.h"
#include "kdc/kpasswd_glue.h"

/*
   A user password change

   Return true if there is a valid error packet (or success) formed in
   the error_blob
*/
NTSTATUS samdb_kpasswd_change_password(TALLOC_CTX *mem_ctx,
				       struct loadparm_context *lp_ctx,
				       struct tevent_context *event_ctx,
				       struct ldb_context *samdb,
				       struct auth_session_info *session_info,
				       const DATA_BLOB *password,
				       enum samPwdChangeReason *reject_reason,
				       struct samr_DomInfo1 **dominfo,
				       const char **error_string,
				       NTSTATUS *result)
{
	struct samr_Password *oldLmHash, *oldNtHash;
	const char * const attrs[] = { "dBCSPwd", "unicodePwd", NULL };
	struct ldb_message *msg;
	NTSTATUS status;
	int ret;

	/* Fetch the old hashes to get the old password in order to perform
	 * the password change operation. Naturally it would be much better to
	 * have a password hash from an authentication around but this doesn't
	 * seem to be the case here. */
	ret = dsdb_search_one(samdb, mem_ctx, &msg, ldb_get_default_basedn(samdb),
			      LDB_SCOPE_SUBTREE,
			      attrs,
			      DSDB_SEARCH_NO_GLOBAL_CATALOG,
			      "(&(objectClass=user)(sAMAccountName=%s))",
			      session_info->info->account_name);
	if (ret != LDB_SUCCESS) {
		*error_string = "No such user when changing password";
		return NT_STATUS_NO_SUCH_USER;
	}

	/*
	 * No need to check for password lockout here, the KDC will
	 * have done that when issuing the ticket, which is not based
	 * on the user's password
	 */
	status = samdb_result_passwords_no_lockout(mem_ctx, lp_ctx, msg,
						   &oldLmHash, &oldNtHash);
	if (!NT_STATUS_IS_OK(status)) {
		*error_string = "Not permitted to change password";
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Start a SAM with user privileges for the password change */
	samdb = samdb_connect(mem_ctx,
			      event_ctx,
			      lp_ctx,
			      session_info,
			      NULL,
			      0);
	if (!samdb) {
		*error_string = "Failed to open samdb";
		return NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(3, ("Changing password of %s\\%s (%s)\n",
		  session_info->info->domain_name,
		  session_info->info->account_name,
		  dom_sid_string(mem_ctx, &session_info->security_token->sids[PRIMARY_USER_SID_INDEX])));

	/* Performs the password change */
	status = samdb_set_password_sid(samdb,
					mem_ctx,
					&session_info->security_token->sids[PRIMARY_USER_SID_INDEX],
					NULL,
					password,
					NULL,
					NULL,
					oldLmHash,
					oldNtHash, /* this is a user password change */
					reject_reason,
					dominfo);
	if (!NT_STATUS_IS_OK(status)) {
		*error_string = nt_errstr(status);
	}
	*result = status;

	return NT_STATUS_OK;
}
