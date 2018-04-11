/*
   Unix SMB/CIFS implementation.

   Samba kpasswd implementation

   Copyright (c) 2005      Andrew Bartlett <abartlet@samba.org>
   Copyright (c) 2016      Andreas Schneider <asn@samba.org>

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
#include "system/kerberos.h"
#include "librpc/gen_ndr/samr.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "kdc/kpasswd-helper.h"

bool kpasswd_make_error_reply(TALLOC_CTX *mem_ctx,
			      krb5_error_code error_code,
			      const char *error_string,
			      DATA_BLOB *error_data)
{
	bool ok;
	char *s;
	size_t slen;

	if (error_code == 0) {
		DBG_DEBUG("kpasswd reply - %s\n", error_string);
	} else {
		DBG_INFO("kpasswd reply - %s\n", error_string);
	}

	ok = push_utf8_talloc(mem_ctx, &s, error_string, &slen);
	if (!ok) {
		return false;
	}

	/*
	 * The string 's' has two terminating nul-bytes which are also
	 * reflected by 'slen'. Normally Kerberos doesn't expect that strings
	 * are nul-terminated, but Heimdal does!
	 */
#ifndef SAMBA4_USES_HEIMDAL
	if (slen < 2) {
		talloc_free(s);
		return false;
	}
	slen -= 2;
#endif
	if (2 + slen < slen) {
		talloc_free(s);
		return false;
	}
	error_data->length = 2 + slen;
	error_data->data = talloc_size(mem_ctx, error_data->length);
	if (error_data->data == NULL) {
		talloc_free(s);
		return false;
	}

	RSSVAL(error_data->data, 0, error_code);
	memcpy(error_data->data + 2, s, slen);

	talloc_free(s);

	return true;
}

bool kpasswd_make_pwchange_reply(TALLOC_CTX *mem_ctx,
				 NTSTATUS status,
				 enum samPwdChangeReason reject_reason,
				 struct samr_DomInfo1 *dominfo,
				 DATA_BLOB *error_blob)
{
	const char *reject_string = NULL;

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		return kpasswd_make_error_reply(mem_ctx,
						KRB5_KPASSWD_ACCESSDENIED,
						"No such user when changing password",
						error_blob);
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		return kpasswd_make_error_reply(mem_ctx,
						KRB5_KPASSWD_ACCESSDENIED,
						"Not permitted to change password",
						error_blob);
	}
	if (dominfo != NULL &&
	    NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION)) {
		switch (reject_reason) {
		case SAM_PWD_CHANGE_PASSWORD_TOO_SHORT:
			reject_string =
				talloc_asprintf(mem_ctx,
						"Password too short, password "
						"must be at least %d characters "
						"long.",
						dominfo->min_password_length);
			if (reject_string == NULL) {
				reject_string = "Password too short";
			}
			break;
		case SAM_PWD_CHANGE_NOT_COMPLEX:
			reject_string = "Password does not meet complexity "
					"requirements";
			break;
		case SAM_PWD_CHANGE_PWD_IN_HISTORY:
			reject_string =
				talloc_asprintf(mem_ctx,
						"Password is already in password "
						"history. New password must not "
						"match any of your %d previous "
						"passwords.",
						dominfo->password_history_length);
			if (reject_string == NULL) {
				reject_string = "Password is already in password "
						"history";
			}
			break;
		default:
			reject_string = "Password change rejected, password "
					"changes may not be permitted on this "
					"account, or the minimum password age "
					"may not have elapsed.";
			break;
		}

		return kpasswd_make_error_reply(mem_ctx,
						KRB5_KPASSWD_SOFTERROR,
						reject_string,
						error_blob);
	}

	if (!NT_STATUS_IS_OK(status)) {
		reject_string = talloc_asprintf(mem_ctx,
						"Failed to set password: %s",
						nt_errstr(status));
		if (reject_string == NULL) {
			reject_string = "Failed to set password";
		}
		return kpasswd_make_error_reply(mem_ctx,
						KRB5_KPASSWD_HARDERROR,
						reject_string,
						error_blob);
	}

	return kpasswd_make_error_reply(mem_ctx,
					KRB5_KPASSWD_SUCCESS,
					"Password changed",
					error_blob);
}

NTSTATUS kpasswd_samdb_set_password(TALLOC_CTX *mem_ctx,
				    struct tevent_context *event_ctx,
				    struct loadparm_context *lp_ctx,
				    struct auth_session_info *session_info,
				    bool is_service_principal,
				    const char *target_principal_name,
				    DATA_BLOB *password,
				    enum samPwdChangeReason *reject_reason,
				    struct samr_DomInfo1 **dominfo)
{
	NTSTATUS status;
	struct ldb_context *samdb;
	struct ldb_dn *target_dn = NULL;
	int rc;

	samdb = samdb_connect(mem_ctx,
			      event_ctx,
			      lp_ctx,
			      session_info,
			      NULL,
			      0);
	if (samdb == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	DBG_INFO("%s\\%s (%s) is changing password of %s\n",
		 session_info->info->domain_name,
		 session_info->info->account_name,
		 dom_sid_string(mem_ctx,
				&session_info->security_token->sids[PRIMARY_USER_SID_INDEX]),
		 target_principal_name);

	rc = ldb_transaction_start(samdb);
	if (rc != LDB_SUCCESS) {
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	if (is_service_principal) {
		status = crack_service_principal_name(samdb,
						      mem_ctx,
						      target_principal_name,
						      &target_dn,
						      NULL);
	} else {
		status = crack_user_principal_name(samdb,
						   mem_ctx,
						   target_principal_name,
						   &target_dn,
						   NULL);
	}
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(samdb);
		return status;
	}

	status = samdb_set_password(samdb,
				    mem_ctx,
				    target_dn,
				    NULL, /* domain_dn */
				    password,
				    NULL, /* lmNewHash */
				    NULL, /* ntNewHash */
				    NULL, /* lmOldHash */
				    NULL, /* ntOldHash */
				    reject_reason,
				    dominfo);
	if (NT_STATUS_IS_OK(status)) {
		rc = ldb_transaction_commit(samdb);
		if (rc != LDB_SUCCESS) {
			DBG_WARNING("Failed to commit transaction to "
				    "set password on %s: %s\n",
				    ldb_dn_get_linearized(target_dn),
				    ldb_errstring(samdb));
			return NT_STATUS_TRANSACTION_ABORTED;
		}
	} else {
		ldb_transaction_cancel(samdb);
	}

	return status;
}
