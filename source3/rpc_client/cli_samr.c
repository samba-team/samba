/* 
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Tim Potter                        2000-2001,
   Copyright (C) Andrew Tridgell              1992-1997,2000,
   Copyright (C) Rafal Szczesniak                       2002.
   Copyright (C) Jeremy Allison                         2005.
   Copyright (C) Guenther Deschner                      2008.
   
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
#include "rpc_client/rpc_client.h"
#include "../libcli/auth/libcli_auth.h"
#include "../librpc/gen_ndr/ndr_samr_c.h"
#include "rpc_client/cli_samr.h"
#include "rpc_client/init_lsa.h"
#include "rpc_client/init_samr.h"

/* User change password */

NTSTATUS dcerpc_samr_chgpasswd_user(struct dcerpc_binding_handle *h,
				    TALLOC_CTX *mem_ctx,
				    struct policy_handle *user_handle,
				    const char *newpassword,
				    const char *oldpassword,
				    NTSTATUS *presult)
{
	NTSTATUS status;
	int rc;
	struct samr_Password hash1, hash2, hash3, hash4, hash5, hash6;

	uint8_t old_nt_hash[16] = {0};
	uint8_t old_lm_hash[16] = {0};
	uint8_t new_nt_hash[16] = {0};
	uint8_t new_lm_hash[16] = {0};

	DEBUG(10,("rpccli_samr_chgpasswd_user\n"));

	E_md4hash(oldpassword, old_nt_hash);
	E_md4hash(newpassword, new_nt_hash);

	E_deshash(oldpassword, old_lm_hash);
	E_deshash(newpassword, new_lm_hash);

	rc = E_old_pw_hash(new_lm_hash, old_lm_hash, hash1.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto done;
	}
	rc = E_old_pw_hash(old_lm_hash, new_lm_hash, hash2.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto done;
	}
	rc = E_old_pw_hash(new_nt_hash, old_nt_hash, hash3.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto done;
	}
	rc = E_old_pw_hash(old_nt_hash, new_nt_hash, hash4.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto done;
	}
	rc = E_old_pw_hash(old_lm_hash, new_nt_hash, hash5.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto done;
	}
	rc = E_old_pw_hash(old_nt_hash, new_lm_hash, hash6.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto done;
	}

	status = dcerpc_samr_ChangePasswordUser(h,
						mem_ctx,
						user_handle,
						true,
						&hash1,
						&hash2,
						true,
						&hash3,
						&hash4,
						true,
						&hash5,
						true,
						&hash6,
						presult);

done:
	ZERO_ARRAY(old_nt_hash);
	ZERO_ARRAY(old_lm_hash);
	ZERO_ARRAY(new_nt_hash);
	ZERO_ARRAY(new_lm_hash);

	return status;
}

NTSTATUS rpccli_samr_chgpasswd_user(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    struct policy_handle *user_handle,
				    const char *newpassword,
				    const char *oldpassword)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	status = dcerpc_samr_chgpasswd_user(cli->binding_handle,
					    mem_ctx,
					    user_handle,
					    newpassword,
					    oldpassword,
					    &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return result;
}

/* User change password */

NTSTATUS dcerpc_samr_chgpasswd_user2(struct dcerpc_binding_handle *h,
				     TALLOC_CTX *mem_ctx,
				     const char *srv_name_slash,
				     const char *username,
				     const char *newpassword,
				     const char *oldpassword,
				     NTSTATUS *presult)
{
	NTSTATUS status;
	int rc;
	struct samr_CryptPassword new_nt_password;
	struct samr_CryptPassword new_lm_password;
	struct samr_Password old_nt_hash_enc;
	struct samr_Password old_lanman_hash_enc;

	uint8_t old_nt_hash[16];
	uint8_t old_lanman_hash[16];
	uint8_t new_nt_hash[16];
	uint8_t new_lanman_hash[16];
	struct lsa_String server, account;

	DATA_BLOB session_key = data_blob_const(old_nt_hash, 16);

	DEBUG(10,("rpccli_samr_chgpasswd_user2\n"));

	init_lsa_String(&server, srv_name_slash);
	init_lsa_String(&account, username);

	/* Calculate the MD4 hash (NT compatible) of the password */
	E_md4hash(oldpassword, old_nt_hash);
	E_md4hash(newpassword, new_nt_hash);

	if (lp_client_lanman_auth() &&
	    E_deshash(newpassword, new_lanman_hash) &&
	    E_deshash(oldpassword, old_lanman_hash)) {
		/* E_deshash returns false for 'long' passwords (> 14
		   DOS chars).  This allows us to match Win2k, which
		   does not store a LM hash for these passwords (which
		   would reduce the effective password length to 14) */
		status = init_samr_CryptPassword(newpassword,
						 &session_key,
						 &new_lm_password);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		rc = E_old_pw_hash(new_nt_hash, old_lanman_hash, old_lanman_hash_enc.hash);
		if (rc != 0) {
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
			goto done;
		}
	} else {
		ZERO_STRUCT(new_lm_password);
		ZERO_STRUCT(old_lanman_hash_enc);
	}

	status = init_samr_CryptPassword(newpassword,
					 &session_key,
					 &new_nt_password);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	rc = E_old_pw_hash(new_nt_hash, old_nt_hash, old_nt_hash_enc.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto done;
	}

	status = dcerpc_samr_ChangePasswordUser2(h,
						 mem_ctx,
						 &server,
						 &account,
						 &new_nt_password,
						 &old_nt_hash_enc,
						 true,
						 &new_lm_password,
						 &old_lanman_hash_enc,
						 presult);

done:
	ZERO_STRUCT(new_nt_password);
	ZERO_STRUCT(new_lm_password);
	ZERO_STRUCT(old_nt_hash_enc);
	ZERO_STRUCT(old_lanman_hash_enc);
	ZERO_ARRAY(new_nt_hash);
	ZERO_ARRAY(new_lanman_hash);
	ZERO_ARRAY(old_nt_hash);
	ZERO_ARRAY(old_lanman_hash);

	return status;
}

NTSTATUS rpccli_samr_chgpasswd_user2(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     const char *username,
				     const char *newpassword,
				     const char *oldpassword)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	status = dcerpc_samr_chgpasswd_user2(cli->binding_handle,
					     mem_ctx,
					     cli->srv_name_slash,
					     username,
					     newpassword,
					     oldpassword,
					     &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return result;
}

/* User change password given blobs */

NTSTATUS dcerpc_samr_chng_pswd_auth_crap(struct dcerpc_binding_handle *h,
					 TALLOC_CTX *mem_ctx,
					 const char *srv_name_slash,
					 const char *username,
					 DATA_BLOB new_nt_password_blob,
					 DATA_BLOB old_nt_hash_enc_blob,
					 DATA_BLOB new_lm_password_blob,
					 DATA_BLOB old_lm_hash_enc_blob,
					 NTSTATUS *presult)
{
	NTSTATUS status;
	struct samr_CryptPassword new_nt_password;
	struct samr_CryptPassword new_lm_password;
	struct samr_Password old_nt_hash_enc;
	struct samr_Password old_lm_hash_enc;
	struct lsa_String server, account;

	DEBUG(10,("rpccli_samr_chng_pswd_auth_crap\n"));

	ZERO_STRUCT(new_nt_password);
	ZERO_STRUCT(new_lm_password);
	ZERO_STRUCT(old_nt_hash_enc);
	ZERO_STRUCT(old_lm_hash_enc);

	init_lsa_String(&server, srv_name_slash);
	init_lsa_String(&account, username);

	if (new_nt_password_blob.data && new_nt_password_blob.length >= 516) {
		memcpy(&new_nt_password.data, new_nt_password_blob.data, 516);
	}

	if (new_lm_password_blob.data && new_lm_password_blob.length >= 516) {
		memcpy(&new_lm_password.data, new_lm_password_blob.data, 516);
	}

	if (old_nt_hash_enc_blob.data && old_nt_hash_enc_blob.length >= 16) {
		memcpy(&old_nt_hash_enc.hash, old_nt_hash_enc_blob.data, 16);
	}

	if (old_lm_hash_enc_blob.data && old_lm_hash_enc_blob.length >= 16) {
		memcpy(&old_lm_hash_enc.hash, old_lm_hash_enc_blob.data, 16);
	}

	status = dcerpc_samr_ChangePasswordUser2(h,
						 mem_ctx,
						 &server,
						 &account,
						 &new_nt_password,
						 &old_nt_hash_enc,
						 true,
						 &new_lm_password,
						 &old_lm_hash_enc,
						 presult);

	return status;
}

NTSTATUS rpccli_samr_chng_pswd_auth_crap(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 const char *username,
					 DATA_BLOB new_nt_password_blob,
					 DATA_BLOB old_nt_hash_enc_blob,
					 DATA_BLOB new_lm_password_blob,
					 DATA_BLOB old_lm_hash_enc_blob)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	status = dcerpc_samr_chng_pswd_auth_crap(cli->binding_handle,
						 mem_ctx,
						 cli->srv_name_slash,
						 username,
						 new_nt_password_blob,
						 old_nt_hash_enc_blob,
						 new_lm_password_blob,
						 old_lm_hash_enc_blob,
						 &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return result;
}

/* change password 3 */

NTSTATUS dcerpc_samr_chgpasswd_user3(struct dcerpc_binding_handle *h,
				     TALLOC_CTX *mem_ctx,
				     const char *srv_name_slash,
				     const char *username,
				     const char *newpassword,
				     const char *oldpassword,
				     struct samr_DomInfo1 **dominfo1,
				     struct userPwdChangeFailureInformation **reject,
				     NTSTATUS *presult)
{
	NTSTATUS status;
	int rc;

	struct samr_CryptPassword new_nt_password;
	struct samr_CryptPassword new_lm_password;
	struct samr_Password old_nt_hash_enc;
	struct samr_Password old_lanman_hash_enc;

	uint8_t old_nt_hash[16];
	uint8_t old_lanman_hash[16];
	uint8_t new_nt_hash[16];
	uint8_t new_lanman_hash[16];

	struct lsa_String server, account;

	DATA_BLOB session_key = data_blob_const(old_nt_hash, 16);

	DEBUG(10,("rpccli_samr_chgpasswd_user3\n"));

	init_lsa_String(&server, srv_name_slash);
	init_lsa_String(&account, username);

	/* Calculate the MD4 hash (NT compatible) of the password */
	E_md4hash(oldpassword, old_nt_hash);
	E_md4hash(newpassword, new_nt_hash);

	if (lp_client_lanman_auth() &&
	    E_deshash(newpassword, new_lanman_hash) &&
	    E_deshash(oldpassword, old_lanman_hash)) {
		/* E_deshash returns false for 'long' passwords (> 14
		   DOS chars).  This allows us to match Win2k, which
		   does not store a LM hash for these passwords (which
		   would reduce the effective password length to 14) */
		status = init_samr_CryptPassword(newpassword,
						 &session_key,
						 &new_lm_password);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		rc = E_old_pw_hash(new_nt_hash, old_lanman_hash, old_lanman_hash_enc.hash);
		if (rc != 0) {
			status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
			goto done;
		}
	} else {
		ZERO_STRUCT(new_lm_password);
		ZERO_STRUCT(old_lanman_hash_enc);
	}

	status = init_samr_CryptPassword(newpassword,
					 &session_key,
					 &new_nt_password);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	rc = E_old_pw_hash(new_nt_hash, old_nt_hash, old_nt_hash_enc.hash);
	if (rc != 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
		goto done;
	}

	status = dcerpc_samr_ChangePasswordUser3(h,
						 mem_ctx,
						 &server,
						 &account,
						 &new_nt_password,
						 &old_nt_hash_enc,
						 true,
						 &new_lm_password,
						 &old_lanman_hash_enc,
						 NULL,
						 dominfo1,
						 reject,
						 presult);

done:
	ZERO_STRUCT(new_nt_password);
	ZERO_STRUCT(new_lm_password);
	ZERO_STRUCT(old_nt_hash_enc);
	ZERO_STRUCT(old_lanman_hash_enc);
	ZERO_ARRAY(new_nt_hash);
	ZERO_ARRAY(new_lanman_hash);
	ZERO_ARRAY(old_nt_hash);
	ZERO_ARRAY(old_lanman_hash);

	return status;
}

NTSTATUS rpccli_samr_chgpasswd_user3(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx,
				     const char *username,
				     const char *newpassword,
				     const char *oldpassword,
				     struct samr_DomInfo1 **dominfo1,
				     struct userPwdChangeFailureInformation **reject)
{
	NTSTATUS status;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	status = dcerpc_samr_chgpasswd_user3(cli->binding_handle,
					     mem_ctx,
					     cli->srv_name_slash,
					     username,
					     newpassword,
					     oldpassword,
					     dominfo1,
					     reject,
					     &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return result;
}

/* This function returns the bizzare set of (max_entries, max_size) required
   for the QueryDisplayInfo RPC to actually work against a domain controller
   with large (10k and higher) numbers of users.  These values were 
   obtained by inspection using ethereal and NT4 running User Manager. */

void dcerpc_get_query_dispinfo_params(int loop_count,
				      uint32_t *max_entries,
				      uint32_t *max_size)
{
	switch(loop_count) {
	case 0:
		*max_entries = 512;
		*max_size = 16383;
		break;
	case 1:
		*max_entries = 1024;
		*max_size = 32766;
		break;
	case 2:
		*max_entries = 2048;
		*max_size = 65532;
		break;
	case 3:
		*max_entries = 4096;
		*max_size = 131064;
		break;
	default:              /* loop_count >= 4 */
		*max_entries = 4096;
		*max_size = 131071;
		break;
	}
}

NTSTATUS dcerpc_try_samr_connects(struct dcerpc_binding_handle *h,
				  TALLOC_CTX *mem_ctx,
				  const char *srv_name_slash,
				  uint32_t access_mask,
				  struct policy_handle *connect_pol,
				  NTSTATUS *presult)
{
	NTSTATUS status;
	union samr_ConnectInfo info_in, info_out;
	struct samr_ConnectInfo1 info1;
	uint32_t lvl_out = 0;

	ZERO_STRUCT(info1);

	info1.client_version = SAMR_CONNECT_W2K;
	info_in.info1 = info1;

	status = dcerpc_samr_Connect5(h,
				      mem_ctx,
				      srv_name_slash,
				      access_mask,
				      1,
				      &info_in,
				      &lvl_out,
				      &info_out,
				      connect_pol,
				      presult);
	if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(*presult)) {
		return status;
	}

	status = dcerpc_samr_Connect4(h,
				      mem_ctx,
				      srv_name_slash,
				      SAMR_CONNECT_W2K,
				      access_mask,
				      connect_pol,
				      presult);
	if (NT_STATUS_IS_OK(status) && NT_STATUS_IS_OK(*presult)) {
		return status;
	}

	status = dcerpc_samr_Connect2(h,
				      mem_ctx,
				      srv_name_slash,
				      access_mask,
				      connect_pol,
				      presult);

	return status;
}

/* vim: set ts=8 sw=8 noet cindent: */
