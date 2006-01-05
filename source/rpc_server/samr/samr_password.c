/* 
   Unix SMB/CIFS implementation.

   samr server password set/change handling

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "rpc_server/samr/dcesrv_samr.h"
#include "system/time.h"
#include "lib/crypto/crypto.h"
#include "ads.h"
#include "libcli/ldap/ldap.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"

/* 
  samr_ChangePasswordUser 
*/
NTSTATUS samr_ChangePasswordUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_ChangePasswordUser *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_context *sam_ctx;
	struct ldb_message **res, *msg;
	int ret;
	struct samr_Password new_lmPwdHash, new_ntPwdHash, checkHash;
	struct samr_Password *lm_pwd, *nt_pwd;
	NTSTATUS status = NT_STATUS_OK;
	const char * const attrs[] = { "lmPwdHash", "ntPwdHash" , NULL };

	DCESRV_PULL_HANDLE(h, r->in.user_handle, SAMR_HANDLE_USER);

	a_state = h->data;

	/* basic sanity checking on parameters.  Do this before any database ops */
	if (!r->in.lm_present || !r->in.nt_present ||
	    !r->in.old_lm_crypted || !r->in.new_lm_crypted ||
	    !r->in.old_nt_crypted || !r->in.new_nt_crypted) {
		/* we should really handle a change with lm not
		   present */
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (!r->in.cross1_present || !r->in.nt_cross) {
		return NT_STATUS_NT_CROSS_ENCRYPTION_REQUIRED;
	}
	if (!r->in.cross2_present || !r->in.lm_cross) {
		return NT_STATUS_LM_CROSS_ENCRYPTION_REQUIRED;
	}

	/* To change a password we need to open as system */
	sam_ctx = samdb_connect(mem_ctx, system_session(mem_ctx));
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	ret = ldb_transaction_start(sam_ctx);
	if (ret) {
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(sam_ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	/* fetch the old hashes */
	ret = gendb_search_dn(sam_ctx, mem_ctx,
			      a_state->account_dn, &res, attrs);
	if (ret != 1) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}
	msg = res[0];

	status = samdb_result_passwords(mem_ctx, msg, &lm_pwd, &nt_pwd);
	if (!NT_STATUS_IS_OK(status) || !lm_pwd || !nt_pwd) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* decrypt and check the new lm hash */
	D_P16(lm_pwd->hash, r->in.new_lm_crypted->hash, new_lmPwdHash.hash);
	D_P16(new_lmPwdHash.hash, r->in.old_lm_crypted->hash, checkHash.hash);
	if (memcmp(checkHash.hash, lm_pwd, 16) != 0) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* decrypt and check the new nt hash */
	D_P16(nt_pwd->hash, r->in.new_nt_crypted->hash, new_ntPwdHash.hash);
	D_P16(new_ntPwdHash.hash, r->in.old_nt_crypted->hash, checkHash.hash);
	if (memcmp(checkHash.hash, nt_pwd, 16) != 0) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}
	
	/* check the nt cross hash */
	D_P16(lm_pwd->hash, r->in.nt_cross->hash, checkHash.hash);
	if (memcmp(checkHash.hash, new_ntPwdHash.hash, 16) != 0) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* check the lm cross hash */
	D_P16(nt_pwd->hash, r->in.lm_cross->hash, checkHash.hash);
	if (memcmp(checkHash.hash, new_lmPwdHash.hash, 16) != 0) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_copy(msg, a_state->account_dn);
	if (!msg->dn) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* set the password on the user DN specified.  This may fail
	 * due to password policies */
	status = samdb_set_password(sam_ctx, mem_ctx,
				    a_state->account_dn, a_state->domain_state->domain_dn,
				    msg, NULL, &new_lmPwdHash, &new_ntPwdHash, 
				    True, /* this is a user password change */
				    True, /* run restriction tests */
				    NULL,
				    NULL);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(sam_ctx);
		return status;
	}

	/* The above call only setup the modifications, this actually
	 * makes the write to the database. */
	ret = samdb_replace(sam_ctx, mem_ctx, msg);
	if (ret != 0) {
		DEBUG(2,("Failed to modify record to change password on %s: %s\n",
			 ldb_dn_linearize(mem_ctx, a_state->account_dn),
			 ldb_errstring(sam_ctx)));
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* And this confirms it in a transaction commit */
	ret = ldb_transaction_commit(sam_ctx);
	if (ret != 0) {
		DEBUG(1,("Failed to commit transaction to change password on %s: %s\n",
			 ldb_dn_linearize(mem_ctx, a_state->account_dn),
			 ldb_errstring(sam_ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	return NT_STATUS_OK;
}

/* 
  samr_OemChangePasswordUser2 
*/
NTSTATUS samr_OemChangePasswordUser2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct samr_OemChangePasswordUser2 *r)
{
	NTSTATUS status;
	char new_pass[512];
	uint32_t new_pass_len;
	struct samr_CryptPassword *pwbuf = r->in.password;
	struct ldb_context *sam_ctx;
	const struct ldb_dn *user_dn;
	int ret;
	struct ldb_message **res, *mod;
	const char * const attrs[] = { "objectSid", "lmPwdHash", NULL };
	struct samr_Password *lm_pwd;
	DATA_BLOB lm_pwd_blob;
	uint8_t new_lm_hash[16];
	struct samr_Password lm_verifier;

	if (pwbuf == NULL) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* To change a password we need to open as system */
	sam_ctx = samdb_connect(mem_ctx, system_session(mem_ctx));
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	ret = ldb_transaction_start(sam_ctx);
	if (ret) {
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(sam_ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	/* we need the users dn and the domain dn (derived from the
	   user SID). We also need the current lm password hash in
	   order to decrypt the incoming password */
	ret = gendb_search(sam_ctx, 
			   mem_ctx, NULL, &res, attrs,
			   "(&(sAMAccountName=%s)(objectclass=user))",
			   r->in.account->string);
	if (ret != 1) {
		ldb_transaction_cancel(sam_ctx);
		/* Don't give the game away:  (don't allow anonymous users to prove the existance of usernames) */
		return NT_STATUS_WRONG_PASSWORD;
	}

	user_dn = res[0]->dn;

	status = samdb_result_passwords(mem_ctx, res[0], &lm_pwd, NULL);
	if (!NT_STATUS_IS_OK(status) || !lm_pwd) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* decrypt the password we have been given */
	lm_pwd_blob = data_blob(lm_pwd->hash, sizeof(lm_pwd->hash)); 
	arcfour_crypt_blob(pwbuf->data, 516, &lm_pwd_blob);
	data_blob_free(&lm_pwd_blob);
	
	if (!decode_pw_buffer(pwbuf->data, new_pass, sizeof(new_pass),
			      &new_pass_len, STR_ASCII)) {
		ldb_transaction_cancel(sam_ctx);
		DEBUG(3,("samr: failed to decode password buffer\n"));
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* check LM verifier */
	if (lm_pwd == NULL || r->in.hash == NULL) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	E_deshash(new_pass, new_lm_hash);
	E_old_pw_hash(new_lm_hash, lm_pwd->hash, lm_verifier.hash);
	if (memcmp(lm_verifier.hash, r->in.hash->hash, 16) != 0) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = ldb_dn_copy(mod, user_dn);
	if (!mod->dn) {
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* set the password on the user DN specified.  This may fail
	 * due to password policies */
	status = samdb_set_password(sam_ctx, mem_ctx,
				    user_dn, NULL, 
				    mod, new_pass, 
				    NULL, NULL,
				    True, /* this is a user password change */
				    True, /* run restriction tests */
				    NULL, 
				    NULL);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(sam_ctx);
		return status;
	}

	/* The above call only setup the modifications, this actually
	 * makes the write to the database. */
	ret = samdb_replace(sam_ctx, mem_ctx, mod);
	if (ret != 0) {
		DEBUG(2,("Failed to modify record to change password on %s: %s\n",
			 ldb_dn_linearize(mem_ctx, user_dn),
			 ldb_errstring(sam_ctx)));
		ldb_transaction_cancel(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* And this confirms it in a transaction commit */
	ret = ldb_transaction_commit(sam_ctx);
	if (ret != 0) {
		DEBUG(1,("Failed to commit transaction to change password on %s: %s\n",
			 ldb_dn_linearize(mem_ctx, user_dn),
			 ldb_errstring(sam_ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	return NT_STATUS_OK;
}


/* 
  samr_ChangePasswordUser3 
*/
NTSTATUS samr_ChangePasswordUser3(struct dcesrv_call_state *dce_call, 
				  TALLOC_CTX *mem_ctx,
				  struct samr_ChangePasswordUser3 *r)
{	
	NTSTATUS status;
	char new_pass[512];
	uint32_t new_pass_len;
	struct ldb_context *sam_ctx = NULL;
	const struct ldb_dn *user_dn;
	int ret;
	struct ldb_message **res, *mod;
	const char * const attrs[] = { "ntPwdHash", "lmPwdHash", NULL };
	struct samr_Password *nt_pwd, *lm_pwd;
	DATA_BLOB nt_pwd_blob;
	struct samr_DomInfo1 *dominfo = NULL;
	struct samr_ChangeReject *reject = NULL;
	enum samr_RejectReason reason = SAMR_REJECT_OTHER;
	uint8_t new_nt_hash[16], new_lm_hash[16];
	struct samr_Password nt_verifier, lm_verifier;

	ZERO_STRUCT(r->out);

	if (r->in.nt_password == NULL ||
	    r->in.nt_verifier == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* To change a password we need to open as system */
	sam_ctx = samdb_connect(mem_ctx, system_session(mem_ctx));
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	ret = ldb_transaction_start(sam_ctx);
	if (ret) {
		talloc_free(sam_ctx);
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(sam_ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	/* we need the users dn and the domain dn (derived from the
	   user SID). We also need the current lm and nt password hashes
	   in order to decrypt the incoming passwords */
	ret = gendb_search(sam_ctx, 
			   mem_ctx, NULL, &res, attrs,
			   "(&(sAMAccountName=%s)(objectclass=user))",
			   r->in.account->string);
	if (ret != 1) {
		/* Don't give the game away:  (don't allow anonymous users to prove the existance of usernames) */
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	user_dn = res[0]->dn;

	status = samdb_result_passwords(mem_ctx, res[0], &lm_pwd, &nt_pwd);
	if (!NT_STATUS_IS_OK(status) ) {
		goto failed;
	}

	if (!nt_pwd) {
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* decrypt the password we have been given */
	nt_pwd_blob = data_blob(nt_pwd->hash, sizeof(nt_pwd->hash));
	arcfour_crypt_blob(r->in.nt_password->data, 516, &nt_pwd_blob);
	data_blob_free(&nt_pwd_blob);

	if (!decode_pw_buffer(r->in.nt_password->data, new_pass, sizeof(new_pass),
			      &new_pass_len, STR_UNICODE)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	if (r->in.nt_verifier == NULL) {
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* check NT verifier */
	E_md4hash(new_pass, new_nt_hash);
	E_old_pw_hash(new_nt_hash, nt_pwd->hash, nt_verifier.hash);
	if (memcmp(nt_verifier.hash, r->in.nt_verifier->hash, 16) != 0) {
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* check LM verifier */
	if (lm_pwd && r->in.lm_verifier != NULL) {
		E_deshash(new_pass, new_lm_hash);
		E_old_pw_hash(new_nt_hash, lm_pwd->hash, lm_verifier.hash);
		if (memcmp(lm_verifier.hash, r->in.lm_verifier->hash, 16) != 0) {
			status = NT_STATUS_WRONG_PASSWORD;
			goto failed;
		}
	}


	mod = ldb_msg_new(mem_ctx);
	if (mod == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	mod->dn = ldb_dn_copy(mod, user_dn);
	if (!mod->dn) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	/* set the password on the user DN specified.  This may fail
	 * due to password policies */
	status = samdb_set_password(sam_ctx, mem_ctx,
				    user_dn, NULL, 
				    mod, new_pass, 
				    NULL, NULL,
				    True, /* this is a user password change */
				    True, /* run restriction tests */
				    &reason, 
				    &dominfo);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* The above call only setup the modifications, this actually
	 * makes the write to the database. */
	ret = samdb_replace(sam_ctx, mem_ctx, mod);
	if (ret != 0) {
		DEBUG(2,("samdb_replace failed to change password for %s: %s\n",
			 ldb_dn_linearize(mem_ctx, user_dn),
			 ldb_errstring(sam_ctx)));
		status = NT_STATUS_UNSUCCESSFUL;
		goto failed;
	}

	/* And this confirms it in a transaction commit */
	ret = ldb_transaction_commit(sam_ctx);
	if (ret != 0) {
		DEBUG(1,("Failed to commit transaction to change password on %s: %s\n",
			 ldb_dn_linearize(mem_ctx, user_dn),
			 ldb_errstring(sam_ctx)));
		status = NT_STATUS_TRANSACTION_ABORTED;
		goto failed;
	}

	return NT_STATUS_OK;

failed:
	ldb_transaction_cancel(sam_ctx);
	talloc_free(sam_ctx);

	reject = talloc(mem_ctx, struct samr_ChangeReject);
	r->out.dominfo = dominfo;
	r->out.reject = reject;

	if (reject == NULL) {
		return status;
	}
	ZERO_STRUCTP(reject);

	reject->reason = reason;

	return status;
}


/* 
  samr_ChangePasswordUser2 

  easy - just a subset of samr_ChangePasswordUser3
*/
NTSTATUS samr_ChangePasswordUser2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_ChangePasswordUser2 *r)
{
	struct samr_ChangePasswordUser3 r2;

	r2.in.server = r->in.server;
	r2.in.account = r->in.account;
	r2.in.nt_password = r->in.nt_password;
	r2.in.nt_verifier = r->in.nt_verifier;
	r2.in.lm_change = r->in.lm_change;
	r2.in.lm_password = r->in.lm_password;
	r2.in.lm_verifier = r->in.lm_verifier;
	r2.in.password3 = NULL;

	return samr_ChangePasswordUser3(dce_call, mem_ctx, &r2);
}


/*
  check that a password is sufficiently complex
*/
static BOOL samdb_password_complexity_ok(const char *pass)
{
	return check_password_quality(pass);
}

/*
  set the user password using plaintext, obeying any user or domain
  password restrictions

  note that this function doesn't actually store the result in the
  database, it just fills in the "mod" structure with ldb modify
  elements to setup the correct change when samdb_replace() is
  called. This allows the caller to combine the change with other
  changes (as is needed by some of the set user info levels)

  The caller should probably have a transaction wrapping this
*/
NTSTATUS samdb_set_password(struct ldb_context *ctx, TALLOC_CTX *mem_ctx,
			    const struct ldb_dn *user_dn,
			    const struct ldb_dn *domain_dn,
			    struct ldb_message *mod,
			    const char *new_pass,
			    struct samr_Password *lmNewHash, 
			    struct samr_Password *ntNewHash,
			    BOOL user_change,
			    BOOL restrictions,
			    enum samr_RejectReason *reject_reason,
			    struct samr_DomInfo1 **_dominfo)
{
	const char * const user_attrs[] = { "userAccountControl", "lmPwdHistory", 
					    "ntPwdHistory", 
					    "lmPwdHash", "ntPwdHash", 
					    "objectSid", 
					    "pwdLastSet", NULL };
	const char * const domain_attrs[] = { "pwdProperties", "pwdHistoryLength", 
					      "maxPwdAge", "minPwdAge", 
					      "minPwdLength", NULL };
	NTTIME pwdLastSet;
	int64_t minPwdAge;
	uint_t minPwdLength, pwdProperties, pwdHistoryLength;
	uint_t userAccountControl;
	struct samr_Password *lmPwdHistory, *ntPwdHistory, *lmPwdHash, *ntPwdHash;
	struct samr_Password local_lmNewHash, local_ntNewHash;
	int lmPwdHistory_len, ntPwdHistory_len;
	struct dom_sid *domain_sid;
	struct ldb_message **res;
	int count;
	time_t now = time(NULL);
	NTTIME now_nt;
	int i;

	/* we need to know the time to compute password age */
	unix_to_nt_time(&now_nt, now);

	/* pull all the user parameters */
	count = gendb_search_dn(ctx, mem_ctx, user_dn, &res, user_attrs);
	if (count != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	userAccountControl = samdb_result_uint(res[0],   "userAccountControl", 0);
	lmPwdHistory_len =   samdb_result_hashes(mem_ctx, res[0], 
						 "lmPwdHistory", &lmPwdHistory);
	ntPwdHistory_len =   samdb_result_hashes(mem_ctx, res[0], 
						 "ntPwdHistory", &ntPwdHistory);
	lmPwdHash =          samdb_result_hash(mem_ctx, res[0],   "lmPwdHash");
	ntPwdHash =          samdb_result_hash(mem_ctx, res[0],   "ntPwdHash");
	pwdLastSet =         samdb_result_uint64(res[0], "pwdLastSet", 0);

	if (domain_dn) {
		/* pull the domain parameters */
		count = gendb_search_dn(ctx, mem_ctx, domain_dn, &res, domain_attrs);
		if (count != 1) {
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	} else {
		/* work out the domain sid, and pull the domain from there */
		domain_sid =         samdb_result_sid_prefix(mem_ctx, res[0], "objectSid");
		if (domain_sid == NULL) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		count = gendb_search(ctx, mem_ctx, NULL, &res, domain_attrs, 
				     "(objectSid=%s)", 
				     ldap_encode_ndr_dom_sid(mem_ctx, domain_sid));
		if (count != 1) {
			return NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	pwdProperties =    samdb_result_uint(res[0],   "pwdProperties", 0);
	pwdHistoryLength = samdb_result_uint(res[0],   "pwdHistoryLength", 0);
	minPwdLength =     samdb_result_uint(res[0],   "minPwdLength", 0);
	minPwdAge =        samdb_result_int64(res[0],  "minPwdAge", 0);

	if (_dominfo) {
		struct samr_DomInfo1 *dominfo;
		/* on failure we need to fill in the reject reasons */
		dominfo = talloc(mem_ctx, struct samr_DomInfo1);
		if (dominfo == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		dominfo->min_password_length     = minPwdLength;
		dominfo->password_properties     = pwdProperties;
		dominfo->password_history_length = pwdHistoryLength;
		dominfo->max_password_age        = minPwdAge;
		dominfo->min_password_age        = minPwdAge;
		*_dominfo = dominfo;
	}

	if (new_pass) {
		/* check the various password restrictions */
		if (restrictions && minPwdLength > strlen_m(new_pass)) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_TOO_SHORT;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* possibly check password complexity */
		if (restrictions && pwdProperties & DOMAIN_PASSWORD_COMPLEX &&
		    !samdb_password_complexity_ok(new_pass)) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_COMPLEXITY;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* compute the new nt and lm hashes */
		if (E_deshash(new_pass, local_lmNewHash.hash)) {
			lmNewHash = &local_lmNewHash;
		}
		E_md4hash(new_pass, local_ntNewHash.hash);
		ntNewHash = &local_ntNewHash;
	}

	if (restrictions && user_change) {
		/* are all password changes disallowed? */
		if (pwdProperties & DOMAIN_REFUSE_PASSWORD_CHANGE) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_OTHER;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* can this user change password? */
		if (userAccountControl & UF_PASSWD_CANT_CHANGE) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_OTHER;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* yes, this is a minus. The ages are in negative 100nsec units! */
		if (pwdLastSet - minPwdAge > now_nt) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_OTHER;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}

		/* check the immediately past password */
		if (pwdHistoryLength > 0) {
			if (lmNewHash && lmPwdHash && memcmp(lmNewHash->hash, lmPwdHash->hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
			if (ntNewHash && ntPwdHash && memcmp(ntNewHash->hash, ntPwdHash->hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
		
		/* check the password history */
		lmPwdHistory_len = MIN(lmPwdHistory_len, pwdHistoryLength);
		ntPwdHistory_len = MIN(ntPwdHistory_len, pwdHistoryLength);
		
		for (i=0; lmNewHash && i<lmPwdHistory_len;i++) {
			if (memcmp(lmNewHash->hash, lmPwdHistory[i].hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
		for (i=0; ntNewHash && i<ntPwdHistory_len;i++) {
			if (memcmp(ntNewHash->hash, ntPwdHistory[i].hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
	}

#define CHECK_RET(x) do { if (x != 0) return NT_STATUS_NO_MEMORY; } while(0)

	/* the password is acceptable. Start forming the new fields */
	if (new_pass) {
		/* if we know the cleartext, then only set it.
		 * Modules in ldb will set all the appropriate
		 * hashes */
		CHECK_RET(samdb_msg_add_string(ctx, mem_ctx, mod, 
					       "sambaPassword", new_pass));
	} else {
		/* We don't have the cleartext, so delete the old one
		 * and set what we have of the hashes */
		CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "sambaPassword"));

		if (lmNewHash) {
			CHECK_RET(samdb_msg_add_hash(ctx, mem_ctx, mod, "lmPwdHash", lmNewHash));
		} else {
			CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "lmPwdHash"));
		}
		
		if (ntNewHash) {
			CHECK_RET(samdb_msg_add_hash(ctx, mem_ctx, mod, "ntPwdHash", ntNewHash));
		} else {
			CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "ntPwdHash"));
		}
	}

	return NT_STATUS_OK;
}

/*
  set password via a samr_CryptPassword buffer
  this will in the 'msg' with modify operations that will update the user
  password when applied
*/
NTSTATUS samr_set_password(struct dcesrv_call_state *dce_call,
			   void *sam_ctx,
			   const struct ldb_dn *account_dn, const struct ldb_dn *domain_dn,
			   TALLOC_CTX *mem_ctx,
			   struct ldb_message *msg, 
			   struct samr_CryptPassword *pwbuf)
{
	NTSTATUS nt_status;
	char new_pass[512];
	uint32_t new_pass_len;
	DATA_BLOB session_key = data_blob(NULL, 0);

	nt_status = dcesrv_fetch_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	arcfour_crypt_blob(pwbuf->data, 516, &session_key);

	if (!decode_pw_buffer(pwbuf->data, new_pass, sizeof(new_pass),
			      &new_pass_len, STR_UNICODE)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	return samdb_set_password(sam_ctx, mem_ctx,
				  account_dn, domain_dn, 
				  msg, new_pass, 
				  NULL, NULL,
				  False, /* This is a password set, not change */
				  True, /* run restriction tests */
				  NULL, NULL);
}


/*
  set password via a samr_CryptPasswordEx buffer
  this will in the 'msg' with modify operations that will update the user
  password when applied
*/
NTSTATUS samr_set_password_ex(struct dcesrv_call_state *dce_call,
			      struct ldb_context *sam_ctx,
			      const struct ldb_dn *account_dn, const struct ldb_dn *domain_dn,
			      TALLOC_CTX *mem_ctx,
			      struct ldb_message *msg, 
			      struct samr_CryptPasswordEx *pwbuf)
{
	NTSTATUS nt_status;
	char new_pass[512];
	uint32_t new_pass_len;
	DATA_BLOB co_session_key;
	DATA_BLOB session_key = data_blob(NULL, 0);
	struct MD5Context ctx;

	nt_status = dcesrv_fetch_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	co_session_key = data_blob_talloc(mem_ctx, NULL, 16);
	if (!co_session_key.data) {
		return NT_STATUS_NO_MEMORY;
	}

	MD5Init(&ctx);
	MD5Update(&ctx, &pwbuf->data[516], 16);
	MD5Update(&ctx, session_key.data, session_key.length);
	MD5Final(co_session_key.data, &ctx);
	
	arcfour_crypt_blob(pwbuf->data, 516, &co_session_key);

	if (!decode_pw_buffer(pwbuf->data, new_pass, sizeof(new_pass),
			      &new_pass_len, STR_UNICODE)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	return samdb_set_password(sam_ctx, mem_ctx,
				  account_dn, domain_dn, 
				  msg, new_pass, 
				  NULL, NULL,
				  False, /* This is a password set, not change */
				  True, /* run restriction tests */
				  NULL, NULL);
}

/*
  set the user password using plaintext, obeying any user or domain
  password restrictions

  This wrapper function takes a SID as input, rather than a user DN,
  and actually performs the password change

*/
NTSTATUS samdb_set_password_sid(struct ldb_context *ctx, TALLOC_CTX *mem_ctx,
				const struct dom_sid *user_sid,
				const char *new_pass,
				struct samr_Password *lmNewHash, 
				struct samr_Password *ntNewHash,
				BOOL user_change,
				BOOL restrictions,
				enum samr_RejectReason *reject_reason,
				struct samr_DomInfo1 **_dominfo) 
{
	NTSTATUS nt_status;
	struct ldb_dn *user_dn;
	struct ldb_message *msg;
	int ret;

	ret = ldb_transaction_start(ctx);
	if (ret) {
		DEBUG(1, ("Failed to start transaction: %s\n", ldb_errstring(ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}

	user_dn = samdb_search_dn(ctx, mem_ctx, NULL, 
				  "(&(objectSid=%s)(objectClass=user))", 
				  ldap_encode_ndr_dom_sid(mem_ctx, user_sid));
	if (!user_dn) {
		ldb_transaction_cancel(ctx);
		DEBUG(3, ("samdb_set_password_sid: SID %s not found in samdb, returning NO_SUCH_USER\n",
			  dom_sid_string(mem_ctx, user_sid)));
		return NT_STATUS_NO_SUCH_USER;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		ldb_transaction_cancel(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_copy(msg, user_dn);
	if (!msg->dn) {
		ldb_transaction_cancel(ctx);
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = samdb_set_password(ctx, mem_ctx,
				       user_dn, NULL,
				       msg, new_pass, 
				       lmNewHash, ntNewHash,
				       user_change, /* This is a password set, not change */
				       restrictions, /* run restriction tests */
				       reject_reason, _dominfo);
	if (!NT_STATUS_IS_OK(nt_status)) {
		ldb_transaction_cancel(ctx);
		return nt_status;
	}
	
	/* modify the samdb record */
	ret = samdb_replace(ctx, mem_ctx, msg);
	if (ret != 0) {
		ldb_transaction_cancel(ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	ret = ldb_transaction_commit(ctx);
	if (ret != 0) {
		DEBUG(0,("Failed to commit transaction to change password on %s: %s\n",
			 ldb_dn_linearize(mem_ctx, msg->dn),
			 ldb_errstring(ctx)));
		return NT_STATUS_TRANSACTION_ABORTED;
	}
	return NT_STATUS_OK;
}
