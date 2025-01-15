/*
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2009
   Copyright (C) Gerald Carter                             2003
   Copyright (C) Stefan Metzmacher                         2005-2010

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
#include "system/time.h"
#include <ldb.h>
#include "libcli/ldap/ldap_ndr.h"
#include "libcli/security/security.h"
#include "auth/auth.h"
#include "../libcli/auth/ntlm_check.h"
#include "auth/ntlm/auth_proto.h"
#include "auth/auth_sam.h"
#include "dsdb/gmsa/util.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/common/util.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_irpc_c.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "lib/crypto/gkdi.h"
#include "lib/messaging/irpc.h"
#include "libcli/auth/libcli_auth.h"
#include "libds/common/roles.h"
#include "lib/util/tevent_ntstatus.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "kdc/authn_policy_util.h"
#include "kdc/db-glue.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

NTSTATUS auth_sam_init(void);

extern const char *user_attrs[];
extern const char *domain_ref_attrs[];

/****************************************************************************
 Do a specific test for an smb password being correct, given a smb_password and
 the lanman and NT responses.
****************************************************************************/
static NTSTATUS authsam_password_ok(struct auth4_context *auth_context,
				    TALLOC_CTX *mem_ctx,
				    const struct samr_Password *nt_pwd,
				    struct smb_krb5_context *smb_krb5_context,
				    const DATA_BLOB *stored_aes_256_key,
				    const krb5_data *salt,
				    const struct auth_usersupplied_info *user_info,
				    DATA_BLOB *user_sess_key,
				    DATA_BLOB *lm_sess_key)
{
	NTSTATUS status;

	switch (user_info->password_state) {
	case AUTH_PASSWORD_PLAIN:
	{
		const struct auth_usersupplied_info *user_info_temp;

		if (nt_pwd == NULL && stored_aes_256_key != NULL && user_info->password.plaintext != NULL) {
			bool pw_equal;
			int krb5_ret;
			DATA_BLOB supplied_aes_256_key;
			krb5_keyblock key;
			krb5_data cleartext_data = {
				.data = user_info->password.plaintext,
				.length = strlen(user_info->password.plaintext)
			};

			*lm_sess_key = data_blob_null;
			*user_sess_key = data_blob_null;

			krb5_ret = smb_krb5_create_key_from_string(smb_krb5_context->krb5_context,
								   NULL,
								   salt,
								   &cleartext_data,
								   ENCTYPE_AES256_CTS_HMAC_SHA1_96,
								   &key);
			if (krb5_ret) {
				DBG_ERR("generation of a aes256-cts-hmac-sha1-96 key for password comparison failed: %s\n",
					smb_get_krb5_error_message(smb_krb5_context->krb5_context,
								   krb5_ret, mem_ctx));
				return NT_STATUS_INTERNAL_ERROR;
			}

			supplied_aes_256_key = data_blob_const(KRB5_KEY_DATA(&key),
							       KRB5_KEY_LENGTH(&key));

			pw_equal = data_blob_equal_const_time(&supplied_aes_256_key,
							      stored_aes_256_key);

			krb5_free_keyblock_contents(smb_krb5_context->krb5_context, &key);
			if (!pw_equal) {
				return NT_STATUS_WRONG_PASSWORD;
			}
			return NT_STATUS_OK;
		}

		status = encrypt_user_info(mem_ctx, auth_context,
					   AUTH_PASSWORD_HASH,
					   user_info, &user_info_temp);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to convert plaintext password to password HASH: %s\n", nt_errstr(status)));
			return status;
		}
		user_info = user_info_temp;

		FALL_THROUGH;
	}
	case AUTH_PASSWORD_HASH:
		*lm_sess_key = data_blob(NULL, 0);
		*user_sess_key = data_blob(NULL, 0);
		status = hash_password_check(mem_ctx,
					     false,
					     lpcfg_ntlm_auth(auth_context->lp_ctx),
					     NULL,
					     user_info->password.hash.nt,
					     user_info->mapped.account_name,
					     NULL, nt_pwd);
		NT_STATUS_NOT_OK_RETURN(status);
		break;

	case AUTH_PASSWORD_RESPONSE:
		status = ntlm_password_check(mem_ctx,
					     false,
					     lpcfg_ntlm_auth(auth_context->lp_ctx),
					     user_info->logon_parameters,
					     &auth_context->challenge.data,
					     &user_info->password.response.lanman,
					     &user_info->password.response.nt,
					     user_info->mapped.account_name,
					     user_info->client.account_name,
					     user_info->client.domain_name,
					     NULL, nt_pwd,
					     user_sess_key, lm_sess_key);
		NT_STATUS_NOT_OK_RETURN(status);
		break;
	}

	return NT_STATUS_OK;
}

static void auth_sam_trigger_zero_password(TALLOC_CTX *mem_ctx,
					   struct imessaging_context *msg_ctx,
					   struct tevent_context *event_ctx,
					   struct netr_SendToSamBase *send_to_sam)
{
	struct dcerpc_binding_handle *irpc_handle;
	struct winbind_SendToSam r;
	struct tevent_req *req;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return;
	}

	irpc_handle = irpc_binding_handle_by_name(tmp_ctx, msg_ctx,
						  "winbind_server",
						  &ndr_table_winbind);
	if (irpc_handle == NULL) {
		DEBUG(1,(__location__ ": Unable to get binding handle for winbind\n"));
		TALLOC_FREE(tmp_ctx);
		return;
	}

	r.in.message = *send_to_sam;

	/*
	 * This seem to rely on the current IRPC implementation,
	 * which delivers the message in the _send function.
	 *
	 * TODO: we need a ONE_WAY IRPC handle and register
	 * a callback and wait for it to be triggered!
	 */
	req = dcerpc_winbind_SendToSam_r_send(tmp_ctx,
					      event_ctx,
					      irpc_handle,
					      &r);

	/* we aren't interested in a reply */
	talloc_free(req);
	TALLOC_FREE(tmp_ctx);

}

/*
  send a message to the drepl server telling it to initiate a
  REPL_SECRET getncchanges extended op to fetch the users secrets
 */
static void auth_sam_trigger_repl_secret(TALLOC_CTX *mem_ctx,
					 struct imessaging_context *msg_ctx,
					 struct tevent_context *event_ctx,
					 struct ldb_dn *user_dn)
{
	struct dcerpc_binding_handle *irpc_handle;
	struct drepl_trigger_repl_secret r;
	struct tevent_req *req;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return;
	}

	irpc_handle = irpc_binding_handle_by_name(tmp_ctx, msg_ctx,
						  "dreplsrv",
						  &ndr_table_irpc);
	if (irpc_handle == NULL) {
		DEBUG(1,(__location__ ": Unable to get binding handle for dreplsrv\n"));
		TALLOC_FREE(tmp_ctx);
		return;
	}

	r.in.user_dn = ldb_dn_get_linearized(user_dn);

	/*
	 * This seem to rely on the current IRPC implementation,
	 * which delivers the message in the _send function.
	 *
	 * TODO: we need a ONE_WAY IRPC handle and register
	 * a callback and wait for it to be triggered!
	 */
	req = dcerpc_drepl_trigger_repl_secret_r_send(tmp_ctx,
						      event_ctx,
						      irpc_handle,
						      &r);

	/* we aren't interested in a reply */
	talloc_free(req);
	TALLOC_FREE(tmp_ctx);
}

static const struct samr_Password *hide_invalid_nthash(const struct samr_Password *in)
{
	/*
	 * This is the result of:
	 *
	 * E_md4hash("", zero_string_hash.hash);
	 */
	static const struct samr_Password zero_string_hash = {
		.hash = {
			0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
			0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
		}
	};

	if (in == NULL) {
		return NULL;
	}

	/*
	 * Skip over any all-zero hashes in the history.  No known software
	 * stores these but just to be sure
	 */
	if (all_zero(in->hash, sizeof(in->hash))) {
		return NULL;
	}

	/*
	 * This looks odd, but the password_hash module in the past has written
	 * this in the rare situation where (somehow) we didn't have an old NT
	 * hash (one of the old LM-only set paths)
	 *
	 * mem_equal_const_time() is used to avoid a timing attack
	 * when comparing secret data in the server with this constant
	 * value.
	 */
	if (mem_equal_const_time(in->hash, zero_string_hash.hash, 16)) {
		in = NULL;
	}

	return in;
}

/*
 * Check that a password is OK, and update badPwdCount if required.
 */

static NTSTATUS authsam_password_check_and_record(struct auth4_context *auth_context,
						  TALLOC_CTX *mem_ctx,
						  struct ldb_dn *domain_dn,
						  struct ldb_message *msg,
						  const struct auth_usersupplied_info *user_info,
						  DATA_BLOB *user_sess_key,
						  DATA_BLOB *lm_sess_key,
						  bool *authoritative)
{
	NTSTATUS nt_status;
	NTSTATUS auth_status;
	TALLOC_CTX *tmp_ctx;
	int i, ret;
	int history_len = 0;
	struct ldb_context *sam_ctx = auth_context->sam_ctx;
	const char * const attrs[] = { "pwdHistoryLength", NULL };
	struct ldb_message *dom_msg;
	struct samr_Password *nt_pwd;
	DATA_BLOB _aes_256_key = data_blob_null;
	DATA_BLOB *aes_256_key = NULL;
	krb5_data _salt = { .data = NULL, .length = 0 };
	krb5_data *salt = NULL;
	DATA_BLOB salt_data = data_blob_null;
	struct smb_krb5_context *smb_krb5_context = NULL;
	const struct ldb_val *sc_val;
	uint32_t userAccountControl = 0;
	uint32_t current_kvno = 0;
	bool am_rodc;
	NTTIME now;
	bool time_ok;

	time_ok = dsdb_gmsa_current_time(sam_ctx, &now);
	if (!time_ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * This call does more than what it appears to do, it also
	 * checks for the account lockout.
	 *
	 * It is done here so that all parts of Samba that read the
	 * password refuse to even operate on it if the account is
	 * locked out, to avoid mistakes like CVE-2013-4496.
	 */
	nt_status = samdb_result_passwords(tmp_ctx, auth_context->lp_ctx,
					   msg, &nt_pwd);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	userAccountControl = ldb_msg_find_attr_as_uint(msg,
						       "userAccountControl",
						       0);

	sc_val = ldb_msg_find_ldb_val(msg, "supplementalCredentials");

	if (nt_pwd == NULL && sc_val == NULL) {
		if (samdb_rodc(auth_context->sam_ctx, &am_rodc) == LDB_SUCCESS && am_rodc) {
			/*
			 * we don't have passwords for this
			 * account. We are an RODC, and this account
			 * may be one for which we either are denied
			 * REPL_SECRET replication or we haven't yet
			 * done the replication. We return
			 * NT_STATUS_NOT_IMPLEMENTED which tells the
			 * auth code to try the next authentication
			 * mechanism. We also send a message to our
			 * drepl server to tell it to try and
			 * replicate the secrets for this account.
			 *
			 * TODO: Should we only trigger this is detected
			 * there's a chance that the password might be
			 * replicated, we should be able to detect this
			 * based on msDS-NeverRevealGroup.
			 */
			auth_sam_trigger_repl_secret(auth_context,
						     auth_context->msg_ctx,
						     auth_context->event_ctx,
						     msg->dn);
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NOT_IMPLEMENTED;
		}
	}

	/*
	 * If we don't have an NT password, pull a kerberos key
	 * instead for plaintext.
	 */
	if (nt_pwd == NULL &&
	    sc_val != NULL &&
	    user_info->password_state == AUTH_PASSWORD_PLAIN)
	{
		krb5_error_code krb5_ret;

		krb5_ret = smb_krb5_init_context(tmp_ctx,
						 auth_context->lp_ctx,
						 &smb_krb5_context);
		if (krb5_ret != 0) {
			DBG_ERR("Failed to setup krb5_context: %s!\n",
				error_message(krb5_ret));
			return NT_STATUS_INTERNAL_ERROR;
		}

		/*
		 * Get the current salt from the record
		 */

		krb5_ret = dsdb_extract_aes_256_key(smb_krb5_context->krb5_context,
						    tmp_ctx,
						    sam_ctx,
						    msg,
						    userAccountControl,
						    NULL, /* kvno */
						    &current_kvno, /* kvno_out */
						    &_aes_256_key,
						    &salt_data);
		if (krb5_ret == 0) {
			aes_256_key = &_aes_256_key;

			_salt.data = (char *)salt_data.data;
			_salt.length = salt_data.length;
			salt = &_salt;
		}
	}

	auth_status = authsam_password_ok(auth_context,
					  tmp_ctx,
					  nt_pwd,
					  smb_krb5_context,
					  aes_256_key,
					  salt,
					  user_info,
					  user_sess_key, lm_sess_key);

	if (NT_STATUS_IS_OK(auth_status)) {
		if (user_sess_key->data) {
			talloc_steal(mem_ctx, user_sess_key->data);
		}
		if (lm_sess_key->data) {
			talloc_steal(mem_ctx, lm_sess_key->data);
		}
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_OK;
	}
	*user_sess_key = data_blob_null;
	*lm_sess_key = data_blob_null;

	if (!NT_STATUS_EQUAL(auth_status, NT_STATUS_WRONG_PASSWORD)) {
		TALLOC_FREE(tmp_ctx);
		return auth_status;
	}

	/*
	 * We only continue if this was a wrong password and we'll
	 * return NT_STATUS_WRONG_PASSWORD in most cases, except for a
	 * (default) 60 min grace period for previous NTLM password
	 */

	/* pull the domain password property attributes */
	ret = dsdb_search_one(sam_ctx, tmp_ctx, &dom_msg, domain_dn, LDB_SCOPE_BASE,
			      attrs, 0, "objectClass=domain");
	if (ret == LDB_SUCCESS) {
		history_len = ldb_msg_find_attr_as_uint(dom_msg, "pwdHistoryLength", 0);
	} else if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		DEBUG(3,("Couldn't find domain %s: %s!\n",
			 ldb_dn_get_linearized(domain_dn),
			 ldb_errstring(sam_ctx)));
	} else {
		DEBUG(3,("error finding domain %s: %s!\n",
			 ldb_dn_get_linearized(domain_dn),
			 ldb_errstring(sam_ctx)));
	}

	for (i = 1; i < MIN(history_len, 3); i++) {
		const struct samr_Password *nt_history_pwd = NULL;
		NTTIME pwdLastSet;
		int allowed_period_mins;
		NTTIME allowed_period;
		bool is_gmsa;

		/* Reset these variables back to starting as empty */
		aes_256_key = NULL;
		salt = NULL;

		/*
		 * Obtain the i'th old password from the NT password
		 * history for this user.
		 *
		 * We avoid issues with salts (which are not
		 * recorded for historical AES256 keys) by using the
		 * ntPwdHistory in preference.
		 */
		nt_status = samdb_result_passwords_from_history(tmp_ctx,
							auth_context->lp_ctx,
							msg, i,
							NULL,
							&nt_history_pwd);

		/*
		 * Belts and braces: note that
		 * samdb_result_passwords_from_history() currently
		 * does not fail for missing attributes, it only sets
		 * nt_history_pwd = NULL, so "break" and fall down to
		 * the bad password count update if this happens
		 */
		if (!NT_STATUS_IS_OK(nt_status)) {
			break;
		}

		nt_history_pwd = hide_invalid_nthash(nt_history_pwd);

		/*
		 * We don't have an NT hash from the
		 * ntPwdHistory, but we can still perform the
		 * password check with the AES256
		 * key.
		 *
		 * However, this is the second preference as
		 * it will fail if the account was renamed
		 * prior to a password change (as we won't
		 * have the correct salt available to
		 * calculate the AES256 key).
		 */

		if (nt_history_pwd == NULL && sc_val != NULL &&
		    user_info->password_state == AUTH_PASSWORD_PLAIN &&
		    current_kvno >= i)
		{
			krb5_error_code krb5_ret;
			const uint32_t request_kvno = current_kvno - i;

			/*
			 * Confirm we have a krb5_context set up
			 */
			if (smb_krb5_context == NULL) {
				/*
				 * We get here if we had a unicodePwd
				 * for the current password, no
				 * ntPwdHistory, a valid previous
				 * Kerberos history AND are processing
				 * a simple bind.
				 *
				 * This really is a corner case so
				 * favour cleaner code over trying to
				 * allow for an old password.  It is
				 * more likely this is just a new
				 * account.
				 *
				 * "break" out of the loop and fall down
				 * to the bad password update
				 */
				break;
			}

			/*
			 * Get the current salt from the record
			 */

			krb5_ret = dsdb_extract_aes_256_key(smb_krb5_context->krb5_context,
							    tmp_ctx,
							    sam_ctx,
							    msg,
							    userAccountControl,
							    &request_kvno, /* kvno */
							    NULL, /* kvno_out */
							    &_aes_256_key,
							    &salt_data);
			if (krb5_ret != 0) {
				break;
			}

			aes_256_key = &_aes_256_key;

			_salt.data = (char *)salt_data.data;
			_salt.length = salt_data.length;
			salt = &_salt;

		} else if (nt_history_pwd == NULL) {
			/*
			 * If we don't find element 'i' in the
			 * ntPwdHistory and can not fall back to the
			 * kerberos hash, we won't find 'i+1' ...
			 */
			break;
		}

		auth_status = authsam_password_ok(auth_context, tmp_ctx,
						  nt_history_pwd,
						  smb_krb5_context,
						  aes_256_key,
						  salt,
						  user_info,
						  user_sess_key,
						  lm_sess_key);

		if (!NT_STATUS_IS_OK(auth_status)) {
			/*
			 * If this was not a correct password, try the next
			 * one from the history
			 */
			*user_sess_key = data_blob_null;
			*lm_sess_key = data_blob_null;
			continue;
		}

		if (i != 1) {
			/*
			 * The authentication was OK, but not against
			 * the previous password, which is stored at index 1.
			 *
			 * We just return the original wrong password.
			 * This skips the update of the bad pwd count,
			 * because this is almost certainly user error
			 * (or automatic login on a computer using a cached
			 * password from before the password change),
			 * not an attack.
			 */
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_WRONG_PASSWORD;
		}

		if (user_info->flags & USER_INFO_INTERACTIVE_LOGON) {
			/*
			 * The authentication was OK against the previous password,
			 * but it's not a NTLM network authentication,
			 * LDAP simple bind or something similar.
			 *
			 * We just return the original wrong password.
			 * This skips the update of the bad pwd count,
			 * because this is almost certainly user error
			 * (or automatic login on a computer using a cached
			 * password from before the password change),
			 * not an attack.
			 */
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_WRONG_PASSWORD;
		}

		/*
		 * If the password was OK, it's a NTLM network authentication
		 * and it was the previous password.
		 *
		 * Now we see if it is within the grace period,
		 * so that we don't break cached sessions on other computers
		 * before the user can lock and unlock their other screens
		 * (resetting their cached password).
		 *
		 */

		/* Is the account a Group Managed Service Account? */
		is_gmsa = dsdb_account_is_gmsa(sam_ctx, msg);
		if (is_gmsa) {
			/*
			 * For Group Managed Service Accounts, the previous
			 * password is allowed for five minutes after a password
			 * change.
			 */
			allowed_period_mins = gkdi_max_clock_skew_mins;
		} else {
			/*
			 * See http://support.microsoft.com/kb/906305
			 * OldPasswordAllowedPeriod ("old password allowed
			 * period") is specified in minutes. The default is 60.
			 */
			allowed_period_mins = lpcfg_old_password_allowed_period(
				auth_context->lp_ctx);
		}
		/*
		 * NTTIME uses 100ns units
		 */
		allowed_period = (NTTIME) allowed_period_mins *
				 60 * 1000*1000*10;
		pwdLastSet = samdb_result_nttime(msg, "pwdLastSet", 0);

		if (now < pwdLastSet) {
			/*
			 * time jump?
			 *
			 * We just return the original wrong password.
			 * This skips the update of the bad pwd count,
			 * because this is almost certainly user error
			 * (or automatic login on a computer using a cached
			 * password from before the password change),
			 * not an attack.
			 */
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_WRONG_PASSWORD;
		}

		if ((now - pwdLastSet) >= allowed_period) {
			/*
			 * The allowed period is over.
			 *
			 * We just return the original wrong password.
			 * This skips the update of the bad pwd count,
			 * because this is almost certainly user error
			 * (or automatic login on a computer using a cached
			 * password from before the password change),
			 * not an attack.
			 */
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_WRONG_PASSWORD;
		}

		/*
		 * We finally allow the authentication with the
		 * previous password within the allowed period.
		 */
		if (user_sess_key->data) {
			talloc_steal(mem_ctx, user_sess_key->data);
		}
		if (lm_sess_key->data) {
			talloc_steal(mem_ctx, lm_sess_key->data);
		}

		TALLOC_FREE(tmp_ctx);
		return auth_status;
	}

	/*
	 * If we are not in the allowed period or match an old password,
	 * we didn't return early. Now update the badPwdCount et al.
	 */
	nt_status = authsam_update_bad_pwd_count(auth_context->sam_ctx,
						 msg, domain_dn);
	if (!NT_STATUS_IS_OK(nt_status)) {
		/*
		 * We need to return the original
		 * NT_STATUS_WRONG_PASSWORD error, so there isn't
		 * anything more we can do than write something into
		 * the log
		 */
		DEBUG(0, ("Failed to note bad password for user [%s]: %s\n",
			  user_info->mapped.account_name,
			  nt_errstr(nt_status)));
	}

	if (samdb_rodc(auth_context->sam_ctx, &am_rodc) == LDB_SUCCESS && am_rodc) {
		*authoritative = false;
	}

	TALLOC_FREE(tmp_ctx);

	if (NT_STATUS_IS_OK(nt_status)) {
		nt_status = NT_STATUS_WRONG_PASSWORD;
	}
	return nt_status;
}

static NTSTATUS authsam_check_netlogon_trust(TALLOC_CTX *mem_ctx,
					     struct ldb_context *sam_ctx,
					     struct loadparm_context *lp_ctx,
					     const struct auth_usersupplied_info *user_info,
					     const struct auth_user_info_dc *user_info_dc,
					     struct authn_audit_info **server_audit_info_out)
{
	TALLOC_CTX *tmp_ctx = NULL;

	static const char *authn_policy_silo_attrs[] = {
		"msDS-AssignedAuthNPolicy",
		"msDS-AssignedAuthNPolicySilo",
		"objectClass", /* used to determine which set of policy
				* attributes apply. */
		NULL,
	};

	const struct authn_server_policy *authn_server_policy = NULL;

	struct dom_sid_buf netlogon_trust_sid_buf;
	const char *netlogon_trust_sid_str = NULL;
	struct ldb_dn *netlogon_trust_dn = NULL;
	struct ldb_message *netlogon_trust_msg = NULL;

	int ret;

	/* Have we established a secure channel? */
	if (user_info->netlogon_trust_account.secure_channel_type == SEC_CHAN_NULL) {
		return NT_STATUS_OK;
	}

	if (!authn_policy_silos_and_policies_in_effect(sam_ctx)) {
		return NT_STATUS_OK;
	}

	/*
	 * We have established a secure channel, and we should have the machine
	 * account’s SID.
	 */
	SMB_ASSERT(user_info->netlogon_trust_account.sid != NULL);

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	netlogon_trust_sid_str = dom_sid_str_buf(user_info->netlogon_trust_account.sid,
						 &netlogon_trust_sid_buf);

	netlogon_trust_dn = ldb_dn_new_fmt(tmp_ctx, sam_ctx,
					   "<SID=%s>",
					   netlogon_trust_sid_str);
	if (netlogon_trust_dn == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Look up the machine account to see if it has an applicable
	 * authentication policy.
	 */
	ret = dsdb_search_one(sam_ctx,
			      tmp_ctx,
			      &netlogon_trust_msg,
			      netlogon_trust_dn,
			      LDB_SCOPE_BASE,
			      authn_policy_silo_attrs,
			      0,
			      NULL);
	if (ret) {
		talloc_free(tmp_ctx);
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	ret = authn_policy_server(sam_ctx,
				  tmp_ctx,
				  netlogon_trust_msg,
				  &authn_server_policy);
	if (ret) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (authn_server_policy != NULL) {
		struct authn_audit_info *server_audit_info = NULL;
		NTSTATUS status;

		/*
		 * An authentication policy applies to the machine
		 * account. Carry out the access check.
		 */
		status = authn_policy_authenticate_to_service(tmp_ctx,
							      sam_ctx,
							      lp_ctx,
							      AUTHN_POLICY_AUTH_TYPE_NTLM,
							      user_info_dc,
							      NULL /* device_info */,
							      /*
							       * It seems that claims go ignored for
							       * SamLogon (see SamLogonTests —
							       * test_samlogon_allowed_to_computer_silo).
							       */
							      (struct auth_claims) {},
							      authn_server_policy,
							      (struct authn_policy_flags) {},
							      &server_audit_info);
		if (server_audit_info != NULL) {
			*server_audit_info_out = talloc_move(mem_ctx, &server_audit_info);
		}
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return status;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS authsam_authenticate(struct auth4_context *auth_context,
				     TALLOC_CTX *mem_ctx,
				     struct ldb_dn *domain_dn,
				     struct ldb_message *msg,
				     const struct auth_usersupplied_info *user_info,
				     const struct auth_user_info_dc *user_info_dc,
				     DATA_BLOB *user_sess_key, DATA_BLOB *lm_sess_key,
				     struct authn_audit_info **client_audit_info_out,
				     struct authn_audit_info **server_audit_info_out,
				     bool *authoritative)
{
	NTSTATUS nt_status;
	int ret;
	bool interactive = (user_info->password_state == AUTH_PASSWORD_HASH);
	uint32_t acct_flags = samdb_result_acct_flags(msg, NULL);
	struct netr_SendToSamBase *send_to_sam = NULL;
	const struct authn_ntlm_client_policy *authn_client_policy = NULL;
	struct ldb_context *sam_ctx = auth_context->sam_ctx;
	TALLOC_CTX *tmp_ctx = NULL;
	NTTIME now;
	bool time_ok;

	time_ok = dsdb_gmsa_current_time(sam_ctx, &now);
	if (!time_ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	/* You can only do an interactive login to normal accounts */
	if (user_info->flags & USER_INFO_INTERACTIVE_LOGON) {
		if (!(acct_flags & ACB_NORMAL)) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_SUCH_USER;
		}
		if (acct_flags & ACB_SMARTCARD_REQUIRED) {
			if (acct_flags & ACB_DISABLED) {
				DEBUG(2,("authsam_authenticate: Account for user '%s' "
					 "was disabled.\n",
					 user_info->mapped.account_name));
				TALLOC_FREE(tmp_ctx);
				return NT_STATUS_ACCOUNT_DISABLED;
			}
			DEBUG(2,("authsam_authenticate: Account for user '%s' "
				 "requires interactive smartcard logon.\n",
				 user_info->mapped.account_name));
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_SMARTCARD_LOGON_REQUIRED;
		}
	}

	/* See whether an authentication policy applies to the client. */
	ret = authn_policy_ntlm_client(auth_context->sam_ctx,
				       tmp_ctx,
				       msg,
				       &authn_client_policy);
	if (ret) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	nt_status = authn_policy_ntlm_apply_device_restriction(mem_ctx,
							       authn_client_policy,
							       client_audit_info_out);
	if (!NT_STATUS_IS_OK(nt_status)) {
		/*
		 * As we didn’t get far enough to check the server policy, only
		 * the client policy will be referenced in the authentication
		 * log message.
		 */
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	nt_status = authsam_password_check_and_record(auth_context, tmp_ctx,
						      domain_dn, msg,
						      user_info,
						      user_sess_key, lm_sess_key,
						      authoritative);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	nt_status = authsam_check_netlogon_trust(mem_ctx,
						 auth_context->sam_ctx,
						 auth_context->lp_ctx,
						 user_info,
						 user_info_dc,
						 server_audit_info_out);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	nt_status = authsam_account_ok(tmp_ctx, auth_context->sam_ctx,
				       now,
				       user_info->logon_parameters,
				       domain_dn,
				       msg,
				       user_info->workstation_name,
				       user_info->mapped.account_name,
				       false, false);
	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	nt_status = authsam_logon_success_accounting(auth_context->sam_ctx,
						     msg, domain_dn,
						     interactive,
						     tmp_ctx,
						     &send_to_sam);

	if (send_to_sam != NULL) {
		auth_sam_trigger_zero_password(tmp_ctx,
					       auth_context->msg_ctx,
					       auth_context->event_ctx,
					       send_to_sam);
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		TALLOC_FREE(tmp_ctx);
		return nt_status;
	}

	if (user_sess_key && user_sess_key->data) {
		talloc_steal(mem_ctx, user_sess_key->data);
	}
	if (lm_sess_key && lm_sess_key->data) {
		talloc_steal(mem_ctx, lm_sess_key->data);
	}

	TALLOC_FREE(tmp_ctx);
	return nt_status;
}



static NTSTATUS authsam_check_password_internals(struct auth_method_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 const struct auth_usersupplied_info *user_info,
						 struct auth_user_info_dc **user_info_dc,
						 struct authn_audit_info **client_audit_info_out,
						 struct authn_audit_info **server_audit_info_out,
						 bool *authoritative)
{
	NTSTATUS nt_status;
	int result;
	const char *account_name = user_info->mapped.account_name;
	struct ldb_message *msg;
	struct ldb_dn *domain_dn;
	DATA_BLOB user_sess_key, lm_sess_key;
	TALLOC_CTX *tmp_ctx;
	const char *p = NULL;
	struct auth_user_info_dc *reparented = NULL;
	struct authn_audit_info *client_audit_info = NULL;
	struct authn_audit_info *server_audit_info = NULL;

	if (ctx->auth_ctx->sam_ctx == NULL) {
		DEBUG(0, ("No SAM available, cannot log in users\n"));
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	if (!account_name || !*account_name) {
		/* 'not for me' */
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	domain_dn = ldb_get_default_basedn(ctx->auth_ctx->sam_ctx);
	if (domain_dn == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	/*
	 * If we have not already mapped this user, then now is a good
	 * time to do so, before we look it up.  We used to do this
	 * earlier, but in a multi-forest environment we want to do
	 * this mapping at the final domain.
	 *
	 * However, on the flip side we may have already mapped the
	 * user if this was an LDAP simple bind, in which case we
	 * really, really want to get back to exactly the same account
	 * we got the DN for.
	 */
	if (!user_info->cracknames_called) {
		p = strchr_m(account_name, '@');
	} else {
		/*
		 * This is slightly nicer than double-indenting the
		 * block below
		 */
		p = NULL;
	}

	if (p != NULL) {
		const char *nt4_domain = NULL;
		const char *nt4_account = NULL;
		bool is_my_domain = false;

		nt_status = crack_name_to_nt4_name(mem_ctx,
						   ctx->auth_ctx->sam_ctx,
						   /*
						    * DRSUAPI_DS_NAME_FORMAT_UPN_FOR_LOGON ?
						    */
						   DRSUAPI_DS_NAME_FORMAT_USER_PRINCIPAL,
						   account_name,
						   &nt4_domain, &nt4_account);
		if (!NT_STATUS_IS_OK(nt_status)) {
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_SUCH_USER;
		}

		is_my_domain = lpcfg_is_mydomain(ctx->auth_ctx->lp_ctx, nt4_domain);
		if (!is_my_domain) {
			/*
			 * This is a user within our forest,
			 * but in a different domain,
			 * we're not authoritative
			 */
			talloc_free(tmp_ctx);
			return NT_STATUS_NOT_IMPLEMENTED;
		}

		/*
		 * Let's use the NT4 account name for the lookup.
		 */
		account_name = nt4_account;
	}

	nt_status = authsam_search_account(tmp_ctx, ctx->auth_ctx->sam_ctx, account_name, domain_dn, &msg);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	nt_status = authsam_make_user_info_dc(tmp_ctx, ctx->auth_ctx->sam_ctx,
					     lpcfg_netbios_name(ctx->auth_ctx->lp_ctx),
					     lpcfg_sam_name(ctx->auth_ctx->lp_ctx),
					     lpcfg_sam_dnsname(ctx->auth_ctx->lp_ctx),
					     domain_dn,
					     msg,
					     data_blob_null, data_blob_null,
					     user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}
	(*user_info_dc)->info->user_flags |= NETLOGON_NTLMV2_ENABLED;

	result = dsdb_is_protected_user(ctx->auth_ctx->sam_ctx,
					(*user_info_dc)->sids,
					(*user_info_dc)->num_sids);
	/*
	 * We also consider an error result (a negative value) as denying the
	 * authentication.
	 */
	if (result != 0) {
		talloc_free(tmp_ctx);
		return NT_STATUS_ACCOUNT_RESTRICTION;
	}

	nt_status = authsam_authenticate(ctx->auth_ctx,
					 tmp_ctx,
					 domain_dn,
					 msg,
					 user_info,
					 *user_info_dc,
					 &user_sess_key,
					 &lm_sess_key,
					 &client_audit_info,
					 &server_audit_info,
					 authoritative);
	if (client_audit_info != NULL) {
		*client_audit_info_out = talloc_move(mem_ctx, &client_audit_info);
	}
	if (server_audit_info != NULL) {
		*server_audit_info_out = talloc_move(mem_ctx, &server_audit_info);
	}
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	(*user_info_dc)->user_session_key = data_blob_talloc(*user_info_dc,
							     user_sess_key.data,
							     user_sess_key.length);
	if (user_sess_key.data) {
		if ((*user_info_dc)->user_session_key.data == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	(*user_info_dc)->lm_session_key = data_blob_talloc(*user_info_dc,
							   lm_sess_key.data,
							   lm_sess_key.length);
	if (lm_sess_key.data) {
		if ((*user_info_dc)->lm_session_key.data == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/*
	 * Release our handle to *user_info_dc. {client,server}_audit_info_out,
	 * if non-NULL, becomes the new parent.
	 */
	reparented = talloc_reparent(tmp_ctx, mem_ctx, *user_info_dc);
	if (reparented == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

struct authsam_check_password_state {
	struct auth_user_info_dc *user_info_dc;
	struct authn_audit_info *client_audit_info;
	struct authn_audit_info *server_audit_info;
	bool authoritative;
};

static struct tevent_req *authsam_check_password_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct auth_method_context *ctx,
	const struct auth_usersupplied_info *user_info)
{
	struct tevent_req *req = NULL;
	struct authsam_check_password_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(
		mem_ctx, &state, struct authsam_check_password_state);
	if (req == NULL) {
		return NULL;
	}
	/*
	 * authsam_check_password_internals() sets this to false in
	 * the rodc case, otherwise it leaves it untouched. Default to
	 * "we're authoritative".
	 */
	state->authoritative = true;

	status = authsam_check_password_internals(
		ctx,
		state,
		user_info,
		&state->user_info_dc,
		&state->client_audit_info,
		&state->server_audit_info,
		&state->authoritative);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS authsam_check_password_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct auth_user_info_dc **interim_info,
	const struct authn_audit_info **client_audit_info,
	const struct authn_audit_info **server_audit_info,
	bool *authoritative)
{
	struct authsam_check_password_state *state = tevent_req_data(
		req, struct authsam_check_password_state);
	NTSTATUS status;

	*authoritative = state->authoritative;

	*client_audit_info = talloc_reparent(state, mem_ctx, state->client_audit_info);
	state->client_audit_info = NULL;

	*server_audit_info = talloc_reparent(state, mem_ctx, state->server_audit_info);
	state->server_audit_info = NULL;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	/*
	 * Release our handle to state->user_info_dc.
	 * {client,server}_audit_info, if non-NULL, becomes the new parent.
	 */
	*interim_info = talloc_reparent(state, mem_ctx, state->user_info_dc);
	state->user_info_dc = NULL;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static NTSTATUS authsam_ignoredomain_want_check(struct auth_method_context *ctx,
						TALLOC_CTX *mem_ctx,
						const struct auth_usersupplied_info *user_info)
{
	if (!user_info->mapped.account_name || !*user_info->mapped.account_name) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
Check SAM security (above) but with a few extra checks.
****************************************************************************/
static NTSTATUS authsam_want_check(struct auth_method_context *ctx,
				   TALLOC_CTX *mem_ctx,
				   const struct auth_usersupplied_info *user_info)
{
	const char *effective_domain = user_info->mapped.domain_name;
	bool is_local_name = false;
	bool is_my_domain = false;
	const char *p = NULL;
	struct dsdb_trust_routing_table *trt = NULL;
	const struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	NTSTATUS status;

	if (!user_info->mapped.account_name || !*user_info->mapped.account_name) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (effective_domain == NULL) {
		effective_domain = "";
	}

	is_local_name = lpcfg_is_myname(ctx->auth_ctx->lp_ctx,
					effective_domain);

	/* check whether or not we service this domain/workgroup name */
	switch (lpcfg_server_role(ctx->auth_ctx->lp_ctx)) {
	case ROLE_STANDALONE:
		return NT_STATUS_OK;

	case ROLE_DOMAIN_MEMBER:
		if (is_local_name) {
			return NT_STATUS_OK;
		}

		DBG_DEBUG("%s is not one of my local names (DOMAIN_MEMBER)\n",
			  effective_domain);
		return NT_STATUS_NOT_IMPLEMENTED;

	case ROLE_ACTIVE_DIRECTORY_DC:
		/* handled later */
		break;

	default:
		DBG_ERR("lpcfg_server_role() has an undefined value\n");
		return NT_STATUS_INVALID_SERVER_STATE;
	}

	/*
	 * Now we handle the AD DC case...
	 */

	is_my_domain = lpcfg_is_my_domain_or_realm(ctx->auth_ctx->lp_ctx,
						   effective_domain);
	if (is_my_domain) {
		return NT_STATUS_OK;
	}

	if (user_info->cracknames_called) {
		/*
		 * The caller already did a cracknames call.
		 */
		DBG_DEBUG("%s is not own domain name (DC)\n",
			  effective_domain);
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!strequal(effective_domain, "")) {
		DBG_DEBUG("%s is not own domain name (DC)\n",
			  effective_domain);
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	p = strchr_m(user_info->mapped.account_name, '@');
	if (p == NULL) {
		/*
		 * An empty to domain name should be handled
		 * as the local domain name.
		 */
		return NT_STATUS_OK;
	}

	effective_domain = p + 1;
	is_my_domain = lpcfg_is_my_domain_or_realm(ctx->auth_ctx->lp_ctx,
						   effective_domain);
	if (is_my_domain) {
		return NT_STATUS_OK;
	}

	if (strequal(effective_domain, "")) {
		DBG_DEBUG("authsam_check_password: upn without realm (DC)\n");
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/*
	 * as last option we check the routing table if the
	 * domain is within our forest.
	 */
	status = dsdb_trust_routing_table_load(ctx->auth_ctx->sam_ctx,
					       mem_ctx, &trt);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("authsam_check_password: dsdb_trust_routing_table_load() %s\n",
			 nt_errstr(status));
		return status;
	}

	tdo = dsdb_trust_routing_by_name(trt, effective_domain);
	if (tdo == NULL) {
		DBG_DEBUG("%s is not a known TLN (DC)\n",
			  effective_domain);
		TALLOC_FREE(trt);
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (!(tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST)) {
		DBG_DEBUG("%s is not a TLN in our forest (DC)\n",
			  effective_domain);
		TALLOC_FREE(trt);
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	/*
	 * This principal is within our forest.
	 * we'll later do a crack_name_to_nt4_name()
	 * to check if it's in our domain.
	 */
	TALLOC_FREE(trt);
	return NT_STATUS_OK;
}

static const struct auth_operations sam_ignoredomain_ops = {
	.name		           = "sam_ignoredomain",
	.want_check	           = authsam_ignoredomain_want_check,
	.check_password_send	   = authsam_check_password_send,
	.check_password_recv	   = authsam_check_password_recv,
};

static const struct auth_operations sam_ops = {
	.name		           = "sam",
	.want_check	           = authsam_want_check,
	.check_password_send	   = authsam_check_password_send,
	.check_password_recv	   = authsam_check_password_recv,
};

_PUBLIC_ NTSTATUS auth4_sam_init(TALLOC_CTX *);
_PUBLIC_ NTSTATUS auth4_sam_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	ret = auth_register(ctx, &sam_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'sam' auth backend!\n"));
		return ret;
	}

	ret = auth_register(ctx, &sam_ignoredomain_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'sam_ignoredomain' auth backend!\n"));
		return ret;
	}

	return ret;
}
