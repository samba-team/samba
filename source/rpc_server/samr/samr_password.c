/* 
   Unix SMB/CIFS implementation.

   samr server password set/change handling

   Copyright (C) Andrew Tridgell 2004
   
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
#include "rpc_server/common/common.h"
#include "rpc_server/samr/dcesrv_samr.h"

/* 
  samr_ChangePasswordUser 
*/
NTSTATUS samr_ChangePasswordUser(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct samr_ChangePasswordUser *r)
{
	struct dcesrv_handle *h;
	struct samr_account_state *a_state;
	struct ldb_message **res, mod, *msg;
	int ret;
	struct samr_Hash *lmPwdHash=NULL, *ntPwdHash=NULL;
	struct samr_Hash new_lmPwdHash, new_ntPwdHash, checkHash;
	NTSTATUS status = NT_STATUS_OK;
	const char * const attrs[] = { "lmPwdHash", "ntPwdHash" , NULL };

	DCESRV_PULL_HANDLE(h, r->in.handle, SAMR_HANDLE_USER);

	a_state = h->data;

	/* fetch the old hashes */
	ret = samdb_search(a_state->sam_ctx, mem_ctx, NULL, &res, attrs,
			   "dn=%s", a_state->account_dn);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];

	/* basic sanity checking on parameters */
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

	ret = samdb_result_hashes(mem_ctx, msg, "lmPwdHash", &lmPwdHash);
	if (ret != 1) {
		return NT_STATUS_WRONG_PASSWORD;
	}
	ret = samdb_result_hashes(mem_ctx, msg, "ntPwdHash", &ntPwdHash);
	if (ret != 1) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* decrypt and check the new lm hash */
	D_P16(lmPwdHash->hash, r->in.new_lm_crypted->hash, new_lmPwdHash.hash);
	D_P16(new_lmPwdHash.hash, r->in.old_lm_crypted->hash, checkHash.hash);
	if (memcmp(checkHash.hash, lmPwdHash->hash, 16) != 0) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* decrypt and check the new nt hash */
	D_P16(ntPwdHash->hash, r->in.new_nt_crypted->hash, new_ntPwdHash.hash);
	D_P16(new_ntPwdHash.hash, r->in.old_nt_crypted->hash, checkHash.hash);
	if (memcmp(checkHash.hash, ntPwdHash->hash, 16) != 0) {
		return NT_STATUS_WRONG_PASSWORD;
	}
	
	/* check the nt cross hash */
	D_P16(lmPwdHash->hash, r->in.nt_cross->hash, checkHash.hash);
	if (memcmp(checkHash.hash, new_ntPwdHash.hash, 16) != 0) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* check the lm cross hash */
	D_P16(ntPwdHash->hash, r->in.lm_cross->hash, checkHash.hash);
	if (memcmp(checkHash.hash, new_lmPwdHash.hash, 16) != 0) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	ZERO_STRUCT(mod);
	mod.dn = talloc_strdup(mem_ctx, a_state->account_dn);
	if (!mod.dn) {
		return NT_STATUS_NO_MEMORY;
	}

	status = samdb_set_password(a_state->sam_ctx, mem_ctx,
				    a_state->account_dn, a_state->domain_state->domain_dn,
				    &mod, NULL, &new_lmPwdHash, &new_ntPwdHash, 
				    True, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* modify the samdb record */
	ret = samdb_replace(a_state->sam_ctx, mem_ctx, &mod);
	if (ret != 0) {
		return NT_STATUS_UNSUCCESSFUL;
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
	uint32 new_pass_len;
	struct samr_CryptPassword *pwbuf = r->in.password;
	void *sam_ctx;
	const char *user_dn, *domain_dn;
	int ret;
	struct ldb_message **res, mod;
	const char * const attrs[] = { "objectSid", "lmPwdHash", NULL };
	const char *domain_sid;
	struct samr_Hash *lmPwdHash;

	if (pwbuf == NULL) {
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* this call doesn't take a policy handle, so we need to open
	   the sam db from scratch */
	sam_ctx = samdb_connect();
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* we need the users dn and the domain dn (derived from the
	   user SID). We also need the current lm password hash in
	   order to decrypt the incoming password */
	ret = samdb_search(sam_ctx, 
			   mem_ctx, NULL, &res, attrs,
			   "(&(sAMAccountName=%s)(objectclass=user))",
			   r->in.account->name);
	if (ret != 1) {
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	user_dn = res[0]->dn;

	ret = samdb_result_hashes(mem_ctx, res[0], "lmPwdHash", &lmPwdHash);
	if (ret != 1) {
		samdb_close(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* decrypt the password we have been given */
	SamOEMhash(pwbuf->data, lmPwdHash->hash, 516);

	if (!decode_pw_buffer(pwbuf->data, new_pass, sizeof(new_pass),
			      &new_pass_len, STR_ASCII)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		samdb_close(sam_ctx);
		return NT_STATUS_WRONG_PASSWORD;
	}

	/* work out the domain dn */
	domain_sid = samdb_result_sid_prefix(mem_ctx, res[0], "objectSid");
	if (domain_sid == NULL) {
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	domain_dn = samdb_search_string(sam_ctx, mem_ctx, NULL, "dn",
					"(objectSid=%s)", domain_sid);
	if (!domain_dn) {
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}


	ZERO_STRUCT(mod);
	mod.dn = talloc_strdup(mem_ctx, user_dn);
	if (!mod.dn) {
		samdb_close(sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	status = samdb_set_password(sam_ctx, mem_ctx,
				    user_dn, domain_dn, 
				    &mod, new_pass, 
				    NULL, NULL,
				    True, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		samdb_close(sam_ctx);
		return status;
	}

	/* modify the samdb record */
	ret = samdb_replace(sam_ctx, mem_ctx, &mod);
	if (ret != 0) {
		samdb_close(sam_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	samdb_close(sam_ctx);
	return NT_STATUS_OK;
}


/* 
  samr_ChangePasswordUser2 
*/
NTSTATUS samr_ChangePasswordUser2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct samr_ChangePasswordUser2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
	uint32 new_pass_len;
	void *sam_ctx = NULL;
	const char *user_dn, *domain_dn = NULL;
	int ret;
	struct ldb_message **res, mod;
	const char * const attrs[] = { "objectSid", "ntPwdHash", NULL };
	const char * const dom_attrs[] = { "minPwdLength", "pwdHistoryLength", 
					   "pwdProperties", "minPwdAge", "maxPwdAge", 
					   NULL };
	const char *domain_sid;
	struct samr_Hash *ntPwdHash;
	struct samr_DomInfo1 *dominfo;
	struct samr_ChangeReject *reject;
	uint32 reason = 0;

	ZERO_STRUCT(r->out);

	if (r->in.nt_password == NULL ||
	    r->in.nt_verifier == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto failed;
	}

	/* this call doesn't take a policy handle, so we need to open
	   the sam db from scratch */
	sam_ctx = samdb_connect();
	if (sam_ctx == NULL) {
		status = NT_STATUS_INVALID_SYSTEM_SERVICE;
		goto failed;
	}

	/* we need the users dn and the domain dn (derived from the
	   user SID). We also need the current lm and nt password hashes
	   in order to decrypt the incoming passwords */
	ret = samdb_search(sam_ctx, 
			   mem_ctx, NULL, &res, attrs,
			   "(&(sAMAccountName=%s)(objectclass=user))",
			   r->in.account->name);
	if (ret != 1) {
		status = NT_STATUS_NO_SUCH_USER;
		goto failed;
	}

	user_dn = res[0]->dn;

	ret = samdb_result_hashes(mem_ctx, res[0], "ntPwdHash", &ntPwdHash);
	if (ret != 1) {
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* decrypt the password we have been given */
	SamOEMhash(r->in.nt_password->data, ntPwdHash->hash, 516);

	if (!decode_pw_buffer(r->in.nt_password->data, new_pass, sizeof(new_pass),
			      &new_pass_len, STR_UNICODE)) {
		DEBUG(3,("samr: failed to decode password buffer\n"));
		status = NT_STATUS_WRONG_PASSWORD;
		goto failed;
	}

	/* work out the domain dn */
	domain_sid = samdb_result_sid_prefix(mem_ctx, res[0], "objectSid");
	if (domain_sid == NULL) {
		status = NT_STATUS_NO_SUCH_DOMAIN;
		goto failed;
	}

	domain_dn = samdb_search_string(sam_ctx, mem_ctx, NULL, "dn",
					"(objectSid=%s)", domain_sid);
	if (!domain_dn) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto failed;
	}


	ZERO_STRUCT(mod);
	mod.dn = talloc_strdup(mem_ctx, user_dn);
	if (!mod.dn) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	status = samdb_set_password(sam_ctx, mem_ctx,
				    user_dn, domain_dn, 
				    &mod, new_pass, 
				    NULL, NULL,
				    True, &reason);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	/* modify the samdb record */
	ret = samdb_replace(sam_ctx, mem_ctx, &mod);
	if (ret != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto failed;
	}

	samdb_close(sam_ctx);
	return NT_STATUS_OK;

failed:
	if (sam_ctx) {
		samdb_close(sam_ctx);
	}

	/* on failure we need to fill in the reject reasons */
	dominfo = talloc_p(mem_ctx, struct samr_DomInfo1);
	if (dominfo == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	reject = talloc_p(mem_ctx, struct samr_ChangeReject);
	if (reject == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(dominfo);
	ZERO_STRUCTP(reject);

	reject->reason = reason;

	r->out.dominfo = dominfo;
	r->out.reject = reject;

	if (!domain_dn) {
		return status;
	}

	ret = samdb_search(sam_ctx, 
			   mem_ctx, NULL, &res, dom_attrs,
			   "dn=%s", domain_dn);
	if (ret != 1) {
		status = NT_STATUS_NO_SUCH_USER;
		goto failed;
	}

	dominfo->min_pwd_len         = samdb_result_uint(res[0],  "minPwdLength", 0);
	dominfo->password_properties = samdb_result_uint(res[0],  "pwdProperties", 0);
	dominfo->password_history    = samdb_result_uint(res[0],  "pwdHistoryLength", 0);
	dominfo->max_password_age    = samdb_result_int64(res[0], "maxPwdAge", 0);
	dominfo->min_password_age    = samdb_result_int64(res[0], "minPwdAge", 0);

	return status;
}




/*
  check that a password is sufficiently complex
*/
BOOL samdb_password_complexity_ok(const char *pass)
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
*/
NTSTATUS samdb_set_password(void *ctx, TALLOC_CTX *mem_ctx,
			    const char *user_dn, const char *domain_dn,
			    struct ldb_message *mod,
			    const char *new_pass,
			    struct samr_Hash *lmNewHash, 
			    struct samr_Hash *ntNewHash,
			    BOOL user_change,
			    uint32 *reject_reason)
{
	const char * const user_attrs[] = { "userAccountControl", "lmPwdHistory", 
					    "ntPwdHistory", "unicodePwd", 
					    "lmPwdHash", "ntPwdHash", "badPwdCount", 
					    NULL };
	const char * const domain_attrs[] = { "pwdProperties", "pwdHistoryLength", 
					      "maxPwdAge", "minPwdAge", 
					      "minPwdLength", "pwdLastSet", NULL };
	const char *unicodePwd;
	NTTIME pwdLastSet;
	int64_t minPwdAge;
	uint_t minPwdLength, pwdProperties, pwdHistoryLength;
	uint_t userAccountControl, badPwdCount;
	struct samr_Hash *lmPwdHistory, *ntPwdHistory, lmPwdHash, ntPwdHash;
	struct samr_Hash *new_lmPwdHistory, *new_ntPwdHistory;
	struct samr_Hash local_lmNewHash, local_ntNewHash;
	int lmPwdHistory_len, ntPwdHistory_len;
	struct ldb_message **res;
	int count;
	time_t now = time(NULL);
	NTTIME now_nt;
	int i;

	/* we need to know the time to compute password age */
	unix_to_nt_time(&now_nt, now);

	/* pull all the user parameters */
	count = samdb_search(ctx, mem_ctx, NULL, &res, user_attrs, "dn=%s", user_dn);
	if (count != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	unicodePwd =         samdb_result_string(res[0], "unicodePwd", NULL);
	userAccountControl = samdb_result_uint(res[0],   "userAccountControl", 0);
	badPwdCount =        samdb_result_uint(res[0],   "badPwdCount", 0);
	lmPwdHistory_len =   samdb_result_hashes(mem_ctx, res[0], 
						 "lmPwdHistory", &lmPwdHistory);
	ntPwdHistory_len =   samdb_result_hashes(mem_ctx, res[0], 
						 "ntPwdHistory", &ntPwdHistory);
	lmPwdHash =          samdb_result_hash(res[0],   "lmPwdHash");
	ntPwdHash =          samdb_result_hash(res[0],   "ntPwdHash");
	pwdLastSet =         samdb_result_uint64(res[0], "pwdLastSet", 0);

	/* pull the domain parameters */
	count = samdb_search(ctx, mem_ctx, NULL, &res, domain_attrs, "dn=%s", domain_dn);
	if (count != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	pwdProperties =    samdb_result_uint(res[0],   "pwdProperties", 0);
	pwdHistoryLength = samdb_result_uint(res[0],   "pwdHistoryLength", 0);
	minPwdLength =     samdb_result_uint(res[0],   "minPwdLength", 0);
	minPwdAge =        samdb_result_int64(res[0],  "minPwdAge", 0);

	if (new_pass) {
		/* check the various password restrictions */
		if (minPwdLength > str_charnum(new_pass)) {
			if (reject_reason) {
				*reject_reason = SAMR_REJECT_TOO_SHORT;
			}
			return NT_STATUS_PASSWORD_RESTRICTION;
		}
		
		/* possibly check password complexity */
		if (pwdProperties & DOMAIN_PASSWORD_COMPLEX &&
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

	if (user_change) {
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
			if (lmNewHash && memcmp(lmNewHash->hash, lmPwdHash.hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
			if (ntNewHash && memcmp(ntNewHash->hash, ntPwdHash.hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
		
		/* check the password history */
		lmPwdHistory_len = MIN(lmPwdHistory_len, pwdHistoryLength);
		ntPwdHistory_len = MIN(ntPwdHistory_len, pwdHistoryLength);
		
		if (pwdHistoryLength > 0) {
			if (unicodePwd && new_pass && strcmp(unicodePwd, new_pass) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
			if (lmNewHash && memcmp(lmNewHash->hash, lmPwdHash.hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
			if (ntNewHash && memcmp(ntNewHash->hash, ntPwdHash.hash, 16) == 0) {
				if (reject_reason) {
					*reject_reason = SAMR_REJECT_COMPLEXITY;
				}
				return NT_STATUS_PASSWORD_RESTRICTION;
			}
		}
		
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
	if (lmNewHash) {
		CHECK_RET(samdb_msg_add_hash(ctx, mem_ctx, mod, "lmPwdHash", *lmNewHash));
	} else {
		CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "lmPwdHash"));
	}

	if (ntNewHash) {
		CHECK_RET(samdb_msg_add_hash(ctx, mem_ctx, mod, "ntPwdHash", *ntNewHash));
	} else {
		CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "ntPwdHash"));
	}

	if (new_pass && (pwdProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT) &&
	    (userAccountControl & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED)) {
		CHECK_RET(samdb_msg_add_string(ctx, mem_ctx, mod, 
					       "unicodePwd", new_pass));
	} else {
		CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "unicodePwd"));
	}

	CHECK_RET(samdb_msg_add_uint64(ctx, mem_ctx, mod, "pwdLastSet", now_nt));
	
	if (pwdHistoryLength == 0) {
		CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "lmPwdHistory"));
		CHECK_RET(samdb_msg_add_delete(ctx, mem_ctx, mod, "ntPwdHistory"));
		return NT_STATUS_OK;
	}
	
	/* store the password history */
	new_lmPwdHistory = talloc_array_p(mem_ctx, struct samr_Hash, 
					  pwdHistoryLength);
	if (!new_lmPwdHistory) {
		return NT_STATUS_NO_MEMORY;
	}
	new_ntPwdHistory = talloc_array_p(mem_ctx, struct samr_Hash, 
					  pwdHistoryLength);
	if (!new_ntPwdHistory) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<MIN(pwdHistoryLength-1, lmPwdHistory_len);i++) {
		new_lmPwdHistory[i+1] = lmPwdHistory[i];
	}
	for (i=0;i<MIN(pwdHistoryLength-1, ntPwdHistory_len);i++) {
		new_ntPwdHistory[i+1] = ntPwdHistory[i];
	}

	/* Don't store 'long' passwords in the LM history, 
	   but make sure to 'expire' one password off the other end */
	if (lmNewHash) {
		new_lmPwdHistory[0] = *lmNewHash;
	} else {
		ZERO_STRUCT(new_lmPwdHistory[0]);
	}
	lmPwdHistory_len = MIN(lmPwdHistory_len + 1, pwdHistoryLength);

	if (ntNewHash) {
		new_ntPwdHistory[0] = *ntNewHash;
	} else {
		ZERO_STRUCT(new_ntPwdHistory[0]);
	}
	ntPwdHistory_len = MIN(ntPwdHistory_len + 1, pwdHistoryLength);
	
	CHECK_RET(samdb_msg_add_hashes(ctx, mem_ctx, mod, 
				       "lmPwdHistory", 
				       new_lmPwdHistory, 
				       lmPwdHistory_len));

	CHECK_RET(samdb_msg_add_hashes(ctx, mem_ctx, mod, 
				       "ntPwdHistory", 
				       new_ntPwdHistory, 
				       ntPwdHistory_len));
	return NT_STATUS_OK;
}

/*
  set password via a samr_CryptPassword buffer
  this will in the 'msg' with modify operations that will update the user
  password when applied
*/
NTSTATUS samr_set_password(struct dcesrv_call_state *dce_call,
			   void *sam_ctx,
			   const char *account_dn, const char *domain_dn,
			   TALLOC_CTX *mem_ctx,
			   struct ldb_message *msg, 
			   struct samr_CryptPassword *pwbuf)
{
	char new_pass[512];
	uint32 new_pass_len;
	DATA_BLOB session_key = dce_call->conn->session_key;

	SamOEMhashBlob(pwbuf->data, 516, &session_key);

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
				  False /* This is a password set, not change */,
				  NULL);
}

