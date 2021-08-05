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
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "libcli/auth/libcli_auth.h"
#include "../lib/util/util_ldb.h"
#include "rpc_server/samr/proto.h"
#include "auth/auth_sam.h"

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
		.mapped_state = true,
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
				 sid);
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
*/
NTSTATUS dcesrv_samr_OemChangePasswordUser2(struct dcesrv_call_state *dce_call,
					    TALLOC_CTX *mem_ctx,
					    struct samr_OemChangePasswordUser2 *r)
{
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);
	NTSTATUS status = NT_STATUS_WRONG_PASSWORD;
	DATA_BLOB new_password, new_unicode_password;
	char *new_pass;
	struct samr_CryptPassword *pwbuf = r->in.password;
	struct ldb_context *sam_ctx;
	struct ldb_dn *user_dn;
	int ret;
	struct ldb_message **res;
	const char * const attrs[] = { "objectSid", "dBCSPwd",
				       "userAccountControl",
				       "msDS-ResultantPSO",
				       "msDS-User-Account-Control-Computed",
				       "badPwdCount", "badPasswordTime",
				       "samAccountName",
				       NULL };
	struct samr_Password *lm_pwd;
	uint8_t new_lm_hash[16];
	struct samr_Password lm_verifier;
	size_t unicode_pw_len;
	size_t converted_size = 0;
	const char *user_samAccountName = NULL;
	struct dom_sid *user_objectSid = NULL;
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t lm_session_key;
	int rc;

	if (pwbuf == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.hash == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* this call can only work with lanman auth */
	if (!lpcfg_lanman_auth(dce_call->conn->dce_ctx->lp_ctx)) {
		return NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER;
	}

	/* Connect to a SAMDB with system privileges for fetching the old pw
	 * hashes. */
	sam_ctx = dcesrv_samdb_connect_as_system(mem_ctx, dce_call);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* we need the users dn and the domain dn (derived from the
	   user SID). We also need the current lm password hash in
	   order to decrypt the incoming password */
	ret = gendb_search(sam_ctx,
			   mem_ctx, NULL, &res, attrs,
			   "(&(sAMAccountName=%s)(objectclass=user))",
			   ldb_binary_encode_string(mem_ctx, r->in.account->string));
	if (ret != 1) {
		status = NT_STATUS_NO_SUCH_USER; /* Converted to WRONG_PASSWORD below */
		goto failed;
	}

	user_dn = res[0]->dn;

	user_samAccountName = ldb_msg_find_attr_as_string(res[0], "samAccountName", NULL);
	user_objectSid = samdb_result_dom_sid(res, res[0], "objectSid");

	status = samdb_result_passwords(mem_ctx, dce_call->conn->dce_ctx->lp_ctx,
					res[0], &lm_pwd, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	} else if (!lm_pwd) {
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* decrypt the password we have been given */
	lm_session_key = (gnutls_datum_t) {
		.data = lm_pwd->hash,
		.size = sizeof(lm_pwd->hash),
	};

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&lm_session_key,
				NULL);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		goto failed;
	}

	rc = gnutls_cipher_decrypt(cipher_hnd,
				   pwbuf->data,
				   516);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		goto failed;
	}

	if (!extract_pw_from_buffer(mem_ctx, pwbuf->data, &new_password)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		authsam_update_bad_pwd_count(sam_ctx, res[0], ldb_get_default_basedn(sam_ctx));
		status =  NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	if (!convert_string_talloc_handle(mem_ctx, lpcfg_iconv_handle(dce_call->conn->dce_ctx->lp_ctx),
				  CH_DOS, CH_UNIX,
				  (const char *)new_password.data,
				  new_password.length,
				  (void **)&new_pass, &converted_size)) {
		DEBUG(3,("samr: failed to convert incoming password buffer to unix charset\n"));
		authsam_update_bad_pwd_count(sam_ctx, res[0], ldb_get_default_basedn(sam_ctx));
		status =  NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	if (!convert_string_talloc_handle(mem_ctx, lpcfg_iconv_handle(dce_call->conn->dce_ctx->lp_ctx),
					       CH_DOS, CH_UTF16,
					       (const char *)new_password.data,
					       new_password.length,
					       (void **)&new_unicode_password.data, &unicode_pw_len)) {
		DEBUG(3,("samr: failed to convert incoming password buffer to UTF16 charset\n"));
		authsam_update_bad_pwd_count(sam_ctx, res[0], ldb_get_default_basedn(sam_ctx));
		status =  NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}
	new_unicode_password.length = unicode_pw_len;

	E_deshash(new_pass, new_lm_hash);
	rc = E_old_pw_hash(new_lm_hash, lm_pwd->hash, lm_verifier.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto failed;
	}
	if (memcmp(lm_verifier.hash, r->in.hash->hash, 16) != 0) {
		authsam_update_bad_pwd_count(sam_ctx, res[0], ldb_get_default_basedn(sam_ctx));
		status =  NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* Connect to a SAMDB with user privileges for the password change */
	sam_ctx = dcesrv_samdb_connect_as_user(mem_ctx, dce_call);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* Start transaction */
	ret = ldb_transaction_start(sam_ctx);
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(sam_ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	/* Performs the password modification. We pass the old hashes read out
	 * from the database since they were already checked against the user-
	 * provided ones. */
	status = samdb_set_password(sam_ctx, mem_ctx,
				    user_dn, NULL,
				    &new_unicode_password,
				    NULL, NULL,
				    lm_pwd, NULL, /* this is a user password change */
				    NULL,
				    NULL);
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
				  dce_call->conn->dce_ctx->lp_ctx,
				  dce_call->conn->remote_address,
				  dce_call->conn->local_address,
				  "OemChangePasswordUser2",
				  "RC4/DES using LanMan-hash",
				  r->in.account->string,
				  user_samAccountName,
				  status,
				  user_objectSid);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}
	/* Only update the badPwdCount if we found the user */
	if (NT_STATUS_EQUAL(status, NT_STATUS_WRONG_PASSWORD)) {
		authsam_update_bad_pwd_count(sam_ctx, res[0], ldb_get_default_basedn(sam_ctx));
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		/* Don't give the game away:  (don't allow anonymous users to prove the existence of usernames) */
		status = NT_STATUS_WRONG_PASSWORD;
	}

	return status;
}


/*
  samr_ChangePasswordUser3
*/
NTSTATUS dcesrv_samr_ChangePasswordUser3(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct samr_ChangePasswordUser3 *r)
{
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(dce_call->conn);
	NTSTATUS status = NT_STATUS_WRONG_PASSWORD;
	DATA_BLOB new_password;
	struct ldb_context *sam_ctx = NULL;
	struct ldb_dn *user_dn = NULL;
	int ret;
	struct ldb_message **res;
	const char * const attrs[] = { "unicodePwd", "dBCSPwd",
				       "userAccountControl",
				       "msDS-ResultantPSO",
				       "msDS-User-Account-Control-Computed",
				       "badPwdCount", "badPasswordTime",
				       "objectSid", NULL };
	struct samr_Password *nt_pwd, *lm_pwd;
	struct samr_DomInfo1 *dominfo = NULL;
	struct userPwdChangeFailureInformation *reject = NULL;
	enum samPwdChangeReason reason = SAM_PWD_CHANGE_NO_ERROR;
	uint8_t new_nt_hash[16], new_lm_hash[16];
	struct samr_Password nt_verifier, lm_verifier;
	const char *user_samAccountName = NULL;
	struct dom_sid *user_objectSid = NULL;
	enum ntlm_auth_level ntlm_auth_level
		= lpcfg_ntlm_auth(dce_call->conn->dce_ctx->lp_ctx);
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t nt_session_key;
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

	/* we need the users dn and the domain dn (derived from the
	   user SID). We also need the current lm and nt password hashes
	   in order to decrypt the incoming passwords */
	ret = gendb_search(sam_ctx,
			   mem_ctx, NULL, &res, attrs,
			   "(&(sAMAccountName=%s)(objectclass=user))",
			   ldb_binary_encode_string(mem_ctx, r->in.account->string));
	if (ret != 1) {
		status = NT_STATUS_NO_SUCH_USER; /* Converted to WRONG_PASSWORD below */
		goto failed;
	}

	user_dn = res[0]->dn;
	user_samAccountName = ldb_msg_find_attr_as_string(res[0], "samAccountName", NULL);
	user_objectSid = samdb_result_dom_sid(res, res[0], "objectSid");

	status = samdb_result_passwords(mem_ctx, dce_call->conn->dce_ctx->lp_ctx,
					res[0], &lm_pwd, &nt_pwd);
	if (!NT_STATUS_IS_OK(status) ) {
		goto failed;
	}

	if (!nt_pwd) {
		status = NT_STATUS_WRONG_PASSWORD;
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
		goto failed;
	}

	rc = gnutls_cipher_decrypt(cipher_hnd,
				   r->in.nt_password->data,
				   516);
	gnutls_cipher_deinit(cipher_hnd);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		goto failed;
	}

	if (!extract_pw_from_buffer(mem_ctx, r->in.nt_password->data, &new_password)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		status =  NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	if (r->in.nt_verifier == NULL) {
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* check NT verifier */
	mdfour(new_nt_hash, new_password.data, new_password.length);

	E_old_pw_hash(new_nt_hash, nt_pwd->hash, nt_verifier.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto failed;
	}
	if (memcmp(nt_verifier.hash, r->in.nt_verifier->hash, 16) != 0) {
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* check LM verifier (really not needed as we just checked the
	 * much stronger NT hash, but the RPC-SAMR test checks for
	 * this) */
	if (lm_pwd && r->in.lm_verifier != NULL) {
		char *new_pass;
		size_t converted_size = 0;

		if (!convert_string_talloc_handle(mem_ctx, lpcfg_iconv_handle(dce_call->conn->dce_ctx->lp_ctx),
					  CH_UTF16, CH_UNIX,
					  (const char *)new_password.data,
					  new_password.length,
					  (void **)&new_pass, &converted_size)) {
			E_deshash(new_pass, new_lm_hash);
			rc = E_old_pw_hash(new_nt_hash, lm_pwd->hash, lm_verifier.hash);
			if (rc != 0) {
				status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
				goto failed;
			}
			if (memcmp(lm_verifier.hash, r->in.lm_verifier->hash, 16) != 0) {
				status = NT_STATUS_WRONG_PASSWORD;
				goto failed;
			}
		}
	}

	/* Connect to a SAMDB with user privileges for the password change */
	sam_ctx = dcesrv_samdb_connect_as_user(mem_ctx, dce_call);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	ret = ldb_transaction_start(sam_ctx);
	if (ret != LDB_SUCCESS) {
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(sam_ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	/* Performs the password modification. We pass the old hashes read out
	 * from the database since they were already checked against the user-
	 * provided ones. */
	status = samdb_set_password(sam_ctx, mem_ctx,
				    user_dn, NULL,
				    &new_password,
				    NULL, NULL,
				    lm_pwd, nt_pwd, /* this is a user password change */
				    &reason,
				    &dominfo);

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
				  dce_call->conn->dce_ctx->lp_ctx,
				  dce_call->conn->remote_address,
				  dce_call->conn->local_address,
				  "samr_ChangePasswordUser3",
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
		authsam_update_bad_pwd_count(sam_ctx, res[0], ldb_get_default_basedn(sam_ctx));
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

	return dcesrv_samr_ChangePasswordUser3(dce_call, mem_ctx, &r2);
}


/*
  set password via a samr_CryptPassword buffer
*/
NTSTATUS samr_set_password(struct dcesrv_call_state *dce_call,
			   struct ldb_context *sam_ctx,
			   struct ldb_dn *account_dn, struct ldb_dn *domain_dn,
			   TALLOC_CTX *mem_ctx,
			   struct samr_CryptPassword *pwbuf)
{
	NTSTATUS nt_status;
	DATA_BLOB new_password;
	DATA_BLOB session_key = data_blob(NULL, 0);
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t _session_key;
	int rc;

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

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&_session_key,
				NULL);
	if (rc < 0) {
		nt_status = gnutls_error_to_ntstatus(rc, NT_STATUS_CRYPTO_SYSTEM_INVALID);
		goto out;
	}

	rc = gnutls_cipher_decrypt(cipher_hnd,
				   pwbuf->data,
				   516);
	gnutls_cipher_deinit(cipher_hnd);
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
				       domain_dn,
				       &new_password,
				       NULL,
				       NULL,
				       NULL,
				       NULL, /* This is a password set, not change */
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
			      struct ldb_dn *domain_dn,
			      TALLOC_CTX *mem_ctx,
			      struct samr_CryptPasswordEx *pwbuf)
{
	NTSTATUS nt_status;
	DATA_BLOB new_password;

	/* The confounder is in the last 16 bytes of the buffer */
	DATA_BLOB confounder = data_blob_const(&pwbuf->data[516], 16);
	DATA_BLOB pw_data = data_blob_const(pwbuf->data, 516);
	DATA_BLOB session_key = data_blob(NULL, 0);
	int rc;

	nt_status = dcesrv_transport_session_key(dce_call, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("samr: failed to get session key: %s "
			 "=> NT_STATUS_WRONG_PASSWORD\n",
			nt_errstr(nt_status)));
		return NT_STATUS_WRONG_PASSWORD;
	}

	rc = samba_gnutls_arcfour_confounded_md5(&confounder,
						 &session_key,
						 &pw_data,
						 SAMBA_GNUTLS_DECRYPT);
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
				       domain_dn,
				       &new_password,
				       NULL,
				       NULL,
				       NULL,
				       NULL, /* This is a password set, not change */
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
				   struct ldb_dn *domain_dn,
				   TALLOC_CTX *mem_ctx,
				   const uint8_t *lm_pwd_hash,
				   const uint8_t *nt_pwd_hash)
{
	struct samr_Password *d_lm_pwd_hash = NULL, *d_nt_pwd_hash = NULL;
	uint8_t random_session_key[16] = { 0, };
	DATA_BLOB session_key = data_blob(NULL, 0);
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

	if (lm_pwd_hash != NULL) {
		in = data_blob_const(lm_pwd_hash, 16);
		out = data_blob_talloc_zero(mem_ctx, 16);

		rc = sess_crypt_blob(&out, &in, &session_key, SAMBA_GNUTLS_DECRYPT);
		if (rc != 0) {
			return gnutls_error_to_ntstatus(rc,
							NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		}

		d_lm_pwd_hash = (struct samr_Password *) out.data;
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
					       domain_dn, NULL,
					       d_lm_pwd_hash, d_nt_pwd_hash,
					       NULL, NULL, /* this is a password set */
					       NULL, NULL);
	}

	return nt_status;
}
