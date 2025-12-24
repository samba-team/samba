/*
   Unix SMB/CIFS implementation.

   samr server password set/change handling

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "rpc_server/samr/dcesrv_samr.h"
#include "system/time.h"
#include "lib/crypto/md4.h"
#include "dsdb/common/util.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "libcli/auth/libcli_auth.h"
#include "../lib/util/util_ldb.h"
#include "rpc_server/samr/proto.h"
#include "auth/auth_sam.h"
#include "lib/param/loadparm.h"
#include "librpc/rpc/dcerpc_helper.h"
#include "librpc/rpc/dcerpc_samr.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static void log_password_change_event(struct imessaging_context *msg_ctx,
				      struct loadparm_context *lp_ctx,
				      const struct tsocket_address *remote_client_address,
				      const struct tsocket_address *local_server_address,
				      const char *auth_description,
				      const char *password_type,
				      const char *original_client_name,
				      const char *account_name_from_db,
				      NTSTATUS status,
				      struct dom_sid *sid)
{
	/*
	 * Forcing this via the NTLM auth structure is not ideal, but
	 * it is the most practical option right now, and ensures the
	 * logs are consistent, even if some elements are always NULL.
	 */
	struct auth_usersupplied_info ui = {
		.was_mapped = true,
		.client = {
			.account_name = original_client_name,
			.domain_name = lpcfg_sam_name(lp_ctx),
		},
		.mapped = {
			.account_name = account_name_from_db,
			.domain_name = lpcfg_sam_name(lp_ctx),
		},
		.remote_host = remote_client_address,
		.local_host = local_server_address,
		.service_description = "SAMR Password Change",
		.auth_description = auth_description,
		.password_type = password_type,
	};

	log_authentication_event(msg_ctx,
				 lp_ctx,
				 NULL,
				 &ui,
				 status,
				 ui.mapped.domain_name,
				 ui.mapped.account_name,
				 sid,
				 NULL /* client_audit_info */,
				 NULL /* server_audit_info */);
}
/*
  samr_ChangePasswordUser

  So old it is just not worth implementing
  because it does not supply a plaintext and so we can't do password
  complexity checking and cannot update all the other password hashes.

*/
NTSTATUS dcesrv_samr_ChangePasswordUser(struct dcesrv_call_state *dce_call,
					TALLOC_CTX *mem_ctx,
					struct samr_ChangePasswordUser *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  samr_OemChangePasswordUser2

  No longer implemented as it requires the LM hash
*/
NTSTATUS dcesrv_samr_OemChangePasswordUser2(struct dcesrv_call_state *dce_call,
					    TALLOC_CTX *mem_ctx,
					    struct samr_OemChangePasswordUser2 *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  samr_ChangePasswordUser4
*/
NTSTATUS dcesrv_samr_ChangePasswordUser4(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct samr_ChangePasswordUser4 *r)
{
	struct ldb_context *sam_ctx = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *dn = NULL;
	const char *samAccountName = NULL;
	struct dom_sid *objectSid = NULL;
	struct samr_Password *nt_pwd = NULL;
	gnutls_datum_t nt_key;
	gnutls_datum_t salt = {
		.data = r->in.password->salt,
		.size = sizeof(r->in.password->salt),
	};
	uint8_t cdk_data[16] = {0};
	DATA_BLOB cdk = {
		.data = cdk_data,
		.length = sizeof(cdk_data),
	};
	struct auth_session_info *call_session_info = NULL;
	struct auth_session_info *old_session_info = NULL;
	NTSTATUS status = NT_STATUS_WRONG_PASSWORD;
	int rc;

	r->out.result = NT_STATUS_WRONG_PASSWORD;

	if (r->in.password == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.password->PBKDF2Iterations < 5000 ||
	    r->in.password->PBKDF2Iterations > 1000000) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	/*
	 * Connect to a SAMDB with system privileges for fetching the old
	 * password hashes.
	 */
	sam_ctx = samdb_connect(mem_ctx,
				dce_call->event_ctx,
				dce_call->conn->dce_ctx->lp_ctx,
				system_session(dce_call->conn->dce_ctx->lp_ctx),
				dce_call->conn->remote_address,
				0);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	rc = ldb_transaction_start(sam_ctx);
	if (rc != LDB_SUCCESS) {
		DBG_WARNING("Failed to start transaction: %s\n",
			    ldb_errstring(sam_ctx));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	/*
	 * We use authsam_search_account() to be consistent with the
	 * other callers in the bad password and audit log handling
	 * systems.  It ensures we get DSDB_SEARCH_SHOW_EXTENDED_DN.
	 */
	status = authsam_search_account(mem_ctx,
					sam_ctx,
					r->in.account->string,
					ldb_get_default_basedn(sam_ctx),
					&msg);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(sam_ctx);
		goto done;
	}

	dn = msg->dn;
	samAccountName = ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL);
	objectSid = samdb_result_dom_sid(msg, msg, "objectSid");

	status = samdb_result_passwords(mem_ctx,
					dce_call->conn->dce_ctx->lp_ctx,
					msg,
					&nt_pwd);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(sam_ctx);
		goto done;
	}

	if (nt_pwd == NULL) {
		ldb_transaction_cancel(sam_ctx);
		status = NT_STATUS_WRONG_PASSWORD;
		goto done;
	}

	nt_key = (gnutls_datum_t){
		.data = nt_pwd->hash,
		.size = sizeof(nt_pwd->hash),
	};

	rc = gnutls_pbkdf2(GNUTLS_MAC_SHA512,
			   &nt_key,
			   &salt,
			   r->in.password->PBKDF2Iterations,
			   cdk.data,
			   cdk.length);
	if (rc < 0) {
		ldb_transaction_cancel(sam_ctx);
		status = NT_STATUS_WRONG_PASSWORD;
		goto done;
	}

	/* Drop to user privileges for the password change */

	old_session_info = ldb_get_opaque(sam_ctx, DSDB_SESSION_INFO);
	call_session_info = dcesrv_call_session_info(dce_call);

	rc = ldb_set_opaque(sam_ctx, DSDB_SESSION_INFO, call_session_info);
	if (rc != LDB_SUCCESS) {
		ldb_transaction_cancel(sam_ctx);
		status = NT_STATUS_INVALID_SYSTEM_SERVICE;
		goto done;
	}

	status = samr_set_password_aes(dce_call,
				       mem_ctx,
				       &cdk,
				       sam_ctx,
				       dn,
				       r->in.password,
				       DSDB_PASSWORD_CHECKED_AND_CORRECT);
	BURN_DATA(cdk_data);

	/* Restore our privileges to system level */
	if (old_session_info != NULL) {
		ldb_set_opaque(sam_ctx, DSDB_SESSION_INFO, old_session_info);
	}

	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(sam_ctx);
		goto done;
	}

	/* And this confirms it in a transaction commit */
	rc = ldb_transaction_commit(sam_ctx);
	if (rc != LDB_SUCCESS) {
		DBG_WARNING("Failed to commit transaction to change password "
			    "on %s: %s\n",
			    ldb_dn_get_linearized(dn),
			    ldb_errstring(sam_ctx));
		status = NT_STATUS_TRANSACTION_ABORTED;
		goto done;
	}

	status = NT_STATUS_OK;
done:
	{
		struct imessaging_context *imsg_ctx =
			dcesrv_imessaging_context(dce_call->conn);

		log_password_change_event(imsg_ctx,
					dce_call->conn->dce_ctx->lp_ctx,
					dce_call->conn->remote_address,
					dce_call->conn->local_address,
					"samr_ChangePasswordUser4",
					"AES using NTLM-hash",
					r->in.account->string,
					samAccountName,
					status,
					objectSid);
	}

	/* Only update the badPwdCount if we found the user */
	if (NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		authsam_update_bad_pwd_count(sam_ctx,
					     msg,
					     ldb_get_default_basedn(sam_ctx));
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		/*
		 * Don't give the game away: (don't allow anonymous users to
		 * prove the existence of usernames)
		 */
		status = NT_STATUS_WRONG_PASSWORD;
	}

	return status;
}

static NTSTATUS dcesrv_samr_ChangePasswordUser_impl(struct dcesrv_call_state *dce_call,
						    TALLOC_CTX *mem_ctx,
						    struct samr_ChangePasswordUser3 *r,
						    const char *function_name)
{
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);
	NTSTATUS status = NT_STATUS_WRONG_PASSWORD;
	DATA_BLOB new_password;
	struct ldb_context *sam_ctx = NULL;
	struct ldb_dn *user_dn = NULL;
	int ret;
	struct ldb_message *msg = NULL;
	struct samr_Password *nt_pwd;
	struct samr_DomInfo1 *dominfo = NULL;
	struct userPwdChangeFailureInformation *reject = NULL;
	enum samPwdChangeReason reason = SAM_PWD_CHANGE_NO_ERROR;
	uint8_t new_nt_hash[16];
	struct samr_Password nt_verifier;
	const char *user_samAccountName = NULL;
	struct dom_sid *user_objectSid = NULL;
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	enum ntlm_auth_level ntlm_auth_level
		= lpcfg_ntlm_auth(lp_ctx);
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t nt_session_key;
	struct auth_session_info *call_session_info = NULL;
	struct auth_session_info *old_session_info = NULL;
	int rc;

	*r->out.dominfo = NULL;
	*r->out.reject = NULL;

	/* this call should be disabled without NTLM auth */
	if (ntlm_auth_level == NTLM_AUTH_DISABLED) {
		DBG_WARNING("NTLM password changes not"
			    "permitted by configuration.\n");
		return NT_STATUS_NTLM_BLOCKED;
	}

	if (r->in.nt_password == NULL ||
	    r->in.nt_verifier == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Connect to a SAMDB with system privileges for fetching the old pw
	 * hashes. */
	sam_ctx = dcesrv_samdb_connect_as_system(mem_ctx, dce_call);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	ret = ldb_transaction_start(sam_ctx);
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(sam_ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	/*
	 * We use authsam_search_account() to be consistent with the
	 * other callers in the bad password and audit log handling
	 * systems.  It ensures we get DSDB_SEARCH_SHOW_EXTENDED_DN.
	 */
	status = authsam_search_account(mem_ctx,
					sam_ctx,
					r->in.account->string,
					ldb_get_default_basedn(sam_ctx),
					&msg);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	user_dn = msg->dn;
	user_samAccountName = ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL);
	user_objectSid = samdb_result_dom_sid(mem_ctx, msg, "objectSid");

	status = samdb_result_passwords(mem_ctx, lp_ctx,
					msg, &nt_pwd);
	if (!NT_STATUS_IS_OK(status) ) {
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	if (!nt_pwd) {
		status = NT_STATUS_WRONG_PASSWORD;
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	/* decrypt the password we have been given */
	nt_session_key = (gnutls_datum_t) {
		.data = nt_pwd->hash,
		.size = sizeof(nt_pwd->hash),
	};

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&nt_session_key,
				NULL);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	rc = gnutls_cipher_decrypt(cipher_hnd,
				   r->in.nt_password->data,
				   516);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	if (!extract_pw_from_buffer(mem_ctx, r->in.nt_password->data, &new_password)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		status =  NT_STATUS_WRONG_PASSWORD;
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	if (r->in.nt_verifier == NULL) {
		status = NT_STATUS_WRONG_PASSWORD;
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	/* check NT verifier */
	mdfour(new_nt_hash, new_password.data, new_password.length);

	rc = E_old_pw_hash(new_nt_hash, nt_pwd->hash, nt_verifier.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}
	if (!mem_equal_const_time(nt_verifier.hash, r->in.nt_verifier->hash, 16)) {
		status = NT_STATUS_WRONG_PASSWORD;
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	/* Drop to user privileges for the password change */

	old_session_info = ldb_get_opaque(sam_ctx, DSDB_SESSION_INFO);
	call_session_info = dcesrv_call_session_info(dce_call);

	ret = ldb_set_opaque(sam_ctx, DSDB_SESSION_INFO, call_session_info);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_INVALID_SYSTEM_SERVICE;
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	/* Performs the password modification. We pass the old hashes read out
	 * from the database since they were already checked against the user-
	 * provided ones. */
	status = samdb_set_password(sam_ctx, mem_ctx,
				    user_dn,
				    &new_password,
				    NULL,
				    DSDB_PASSWORD_CHECKED_AND_CORRECT,
				    &reason,
				    &dominfo);

	/* Restore our privileges to system level */
	if (old_session_info != NULL) {
		ldb_set_opaque(sam_ctx, DSDB_SESSION_INFO, old_session_info);
	}

	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(sam_ctx);
		goto failed;
	}

	/* And this confirms it in a transaction commit */
	ret = ldb_transaction_commit(sam_ctx);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,("Failed to commit transaction to change password on %s: %s\n",
			 ldb_dn_get_linearized(user_dn),
			 ldb_errstring(sam_ctx)));
		status = NT_STATUS_TRANSACTION_ABORTED;
		goto failed;
	}

	status = NT_STATUS_OK;

failed:

	log_password_change_event(imsg_ctx,
				  lp_ctx,
				  dce_call->conn->remote_address,
				  dce_call->conn->local_address,
				  function_name,
				  "RC4/DES using NTLM-hash",
				  r->in.account->string,
				  user_samAccountName,
				  status,
				  user_objectSid);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	/* Only update the badPwdCount if we found the user */
	if (NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		NTSTATUS bad_pwd_status;

		bad_pwd_status = authsam_update_bad_pwd_count(
			sam_ctx, msg, ldb_get_default_basedn(sam_ctx));
		if (NT_STATUS_EQUAL(bad_pwd_status, NT_STATUS_ACCOUNT_LOCKED_OUT)) {
			status = bad_pwd_status;
		}
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		/* Don't give the game away:  (don't allow anonymous users to prove the existence of usernames) */
		status = NT_STATUS_WRONG_PASSWORD;
	}

	reject = talloc_zero(mem_ctx, struct userPwdChangeFailureInformation);
	if (reject != NULL) {
		reject->extendedFailureReason = reason;

		*r->out.reject = reject;
	}

	*r->out.dominfo = dominfo;

	return status;
}

/*
  samr_ChangePasswordUser3
*/
NTSTATUS dcesrv_samr_ChangePasswordUser3(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct samr_ChangePasswordUser3 *r)
{
	return dcesrv_samr_ChangePasswordUser_impl(dce_call, mem_ctx, r,
						   "samr_ChangePasswordUser3");
}

/*
  samr_ChangePasswordUser2

  easy - just a subset of samr_ChangePasswordUser3
*/
NTSTATUS dcesrv_samr_ChangePasswordUser2(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct samr_ChangePasswordUser2 *r)
{
	struct samr_ChangePasswordUser3 r2;
	struct samr_DomInfo1 *dominfo = NULL;
	struct userPwdChangeFailureInformation *reject = NULL;

	r2.in.server = r->in.server;
	r2.in.account = r->in.account;
	r2.in.nt_password = r->in.nt_password;
	r2.in.nt_verifier = r->in.nt_verifier;
	r2.in.lm_change = r->in.lm_change;
	r2.in.lm_password = r->in.lm_password;
	r2.in.lm_verifier = r->in.lm_verifier;
	r2.in.password3 = NULL;
	r2.out.dominfo = &dominfo;
	r2.out.reject = &reject;

	return dcesrv_samr_ChangePasswordUser_impl(dce_call, mem_ctx, &r2,
						   "samr_ChangePasswordUser2");
}


/*
  set password via a samr_CryptPassword buffer
*/
NTSTATUS samr_set_password(struct dcesrv_call_state *dce_call,
			   struct ldb_context *sam_ctx,
			   struct ldb_dn *account_dn,
			   TALLOC_CTX *mem_ctx,
			   struct samr_CryptPassword *pwbuf)
{
	NTSTATUS nt_status;
	DATA_BLOB new_password;
	DATA_BLOB session_key = {};
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t _session_key;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	int rc;
	bool encrypted;

	encrypted = dcerpc_is_transport_encrypted(session_info);
	if (lpcfg_weak_crypto(lp_ctx) == SAMBA_WEAK_CRYPTO_DISALLOWED &&
	    !encrypted) {
		return NT_STATUS_ACCESS_DENIED;
	}

	nt_status = dcesrv_transport_session_key(dce_call, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DBG_NOTICE("samr: failed to get session key: %s\n",
			   nt_errstr(nt_status));
		return nt_status;
	}

	_session_key = (gnutls_datum_t) {
		.data = session_key.data,
		.size = session_key.length,
	};

	/*
	 * This is safe to support as we only have a session key
	 * over a SMB connection which we force to be encrypted.
	 */
	GNUTLS_FIPS140_SET_LAX_MODE();
	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&_session_key,
				NULL);
	if (rc < 0) {
		GNUTLS_FIPS140_SET_STRICT_MODE();
		nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		goto out;
	}

	rc = gnutls_cipher_decrypt(cipher_hnd,
				   pwbuf->data,
				   516);
	gnutls_cipher_deinit(cipher_hnd);
	GNUTLS_FIPS140_SET_STRICT_MODE();
	if (rc < 0) {
		nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		goto out;
	}

	if (!extract_pw_from_buffer(mem_ctx, pwbuf->data, &new_password)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	nt_status = samdb_set_password(sam_ctx,
				       mem_ctx,
				       account_dn,
				       &new_password,
				       NULL,
				       DSDB_PASSWORD_RESET,
				       NULL,
				       NULL);
out:
	return nt_status;
}


/*
  set password via a samr_CryptPasswordEx buffer
*/
NTSTATUS samr_set_password_ex(struct dcesrv_call_state *dce_call,
			      struct ldb_context *sam_ctx,
			      struct ldb_dn *account_dn,
			      TALLOC_CTX *mem_ctx,
			      struct samr_CryptPasswordEx *pwbuf)
{
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	NTSTATUS nt_status;
	DATA_BLOB new_password;

	/* The confounder is in the last 16 bytes of the buffer */
	DATA_BLOB confounder = data_blob_const(&pwbuf->data[516], 16);
	DATA_BLOB pw_data = data_blob_const(pwbuf->data, 516);
	DATA_BLOB session_key = {};
	int rc;
	bool encrypted;

	nt_status = dcesrv_transport_session_key(dce_call, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("samr: failed to get session key: %s "
			 "=> NT_STATUS_WRONG_PASSWORD\n",
			nt_errstr(nt_status)));
		return NT_STATUS_WRONG_PASSWORD;
	}

	encrypted = dcerpc_is_transport_encrypted(session_info);
	if (lpcfg_weak_crypto(lp_ctx) == SAMBA_WEAK_CRYPTO_DISALLOWED &&
	    !encrypted) {
		return NT_STATUS_ACCESS_DENIED;
	}

	GNUTLS_FIPS140_SET_LAX_MODE();
	rc = samba_gnutls_arcfour_confounded_md5(&confounder,
						 &session_key,
						 &pw_data,
						 SAMBA_GNUTLS_DECRYPT);
	GNUTLS_FIPS140_SET_STRICT_MODE();
	if (rc < 0) {
		nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		goto out;
	}

	if (!extract_pw_from_buffer(mem_ctx, pwbuf->data, &new_password)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		nt_status = NT_STATUS_WRONG_PASSWORD;
		goto out;
	}

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	nt_status = samdb_set_password(sam_ctx,
				       mem_ctx,
				       account_dn,
				       &new_password,
				       NULL,
				       DSDB_PASSWORD_RESET,
				       NULL,
				       NULL);
	ZERO_ARRAY_LEN(new_password.data,
		       new_password.length);

out:
	return nt_status;
}

/*
  set password via encrypted NT and LM hash buffers
*/
NTSTATUS samr_set_password_buffers(struct dcesrv_call_state *dce_call,
				   struct ldb_context *sam_ctx,
				   struct ldb_dn *account_dn,
				   TALLOC_CTX *mem_ctx,
				   const uint8_t *lm_pwd_hash,
				   const uint8_t *nt_pwd_hash)
{
	struct samr_Password *d_lm_pwd_hash = NULL, *d_nt_pwd_hash = NULL;
	uint8_t random_session_key[16] = { 0, };
	DATA_BLOB session_key = {};
	DATA_BLOB in, out;
	NTSTATUS nt_status = NT_STATUS_OK;
	int rc;

	nt_status = dcesrv_transport_session_key(dce_call, &session_key);
	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_USER_SESSION_KEY)) {
		DEBUG(3,("samr: failed to get session key: %s "
			 "=> use a random session key\n",
			 nt_errstr(nt_status)));

		/*
		 * Windows just uses a random key
		 */
		generate_random_buffer(random_session_key,
				       sizeof(random_session_key));
		session_key = data_blob_const(random_session_key,
					      sizeof(random_session_key));
		nt_status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (nt_pwd_hash != NULL) {
		in = data_blob_const(nt_pwd_hash, 16);
		out = data_blob_talloc_zero(mem_ctx, 16);

		rc = sess_crypt_blob(&out, &in, &session_key, SAMBA_GNUTLS_DECRYPT);
		if (rc != 0) {
			return gnutls_error_to_ntstatus(rc,
							NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		}

		d_nt_pwd_hash = (struct samr_Password *) out.data;
	}

	if ((d_lm_pwd_hash != NULL) || (d_nt_pwd_hash != NULL)) {
		nt_status = samdb_set_password(sam_ctx, mem_ctx, account_dn,
					       NULL,
					       d_nt_pwd_hash,
					       DSDB_PASSWORD_RESET,
					       NULL, NULL);
	}

	return nt_status;
}

NTSTATUS samr_set_password_aes(struct dcesrv_call_state *dce_call,
			       TALLOC_CTX *mem_ctx,
			       const DATA_BLOB *cdk,
			       struct ldb_context *sam_ctx,
			       struct ldb_dn *account_dn,
			       struct samr_EncryptedPasswordAES *pwbuf,
			       enum dsdb_password_checked old_password_checked)
{
	DATA_BLOB pw_data = data_blob_null;
	DATA_BLOB new_password = data_blob_null;
	const DATA_BLOB ciphertext =
		data_blob_const(pwbuf->cipher, pwbuf->cipher_len);
	DATA_BLOB iv = data_blob_const(pwbuf->salt, sizeof(pwbuf->salt));
	NTSTATUS nt_status = NT_STATUS_OK;
	bool ok;

	nt_status = samba_gnutls_aead_aes_256_cbc_hmac_sha512_decrypt(
		mem_ctx,
		&ciphertext,
		cdk,
		&samr_aes256_enc_key_salt,
		&samr_aes256_mac_key_salt,
		&iv,
		pwbuf->auth_data,
		&pw_data);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	ok = extract_pwd_blob_from_buffer514(mem_ctx,
					     pw_data.data,
					     &new_password);
	TALLOC_FREE(pw_data.data);
	if (!ok) {
		DBG_NOTICE("samr: failed to decode password buffer\n");
		return NT_STATUS_WRONG_PASSWORD;
	}

	nt_status = samdb_set_password(sam_ctx,
				       mem_ctx,
				       account_dn,
				       &new_password,
				       NULL,
				       old_password_checked,
				       NULL,
				       NULL);
	TALLOC_FREE(new_password.data);

	return nt_status;
}
