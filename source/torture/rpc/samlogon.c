/* 
   Unix SMB/CIFS implementation.

   test suite for netlogon SamLogon operations

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003-2004
   Copyright (C) Tim Potter      2003
   
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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "auth/auth.h"
#include "lib/crypto/crypto.h"

#define TEST_MACHINE_NAME "samlogontest"

enum ntlm_break {
	BREAK_BOTH,
	BREAK_NONE,
	BREAK_LM,
	BREAK_NT,
	NO_LM,
	NO_NT
};

struct samlogon_state {
	TALLOC_CTX *mem_ctx;
	const char *account_name;
	const char *account_domain;
	const char *password;
	struct dcerpc_pipe *p;
	int function_level;
	struct netr_LogonSamLogon r;
	struct netr_LogonSamLogonEx r_ex;
	struct netr_LogonSamLogonWithFlags r_flags;
	struct netr_Authenticator auth, auth2;
	struct creds_CredentialState *creds;

	DATA_BLOB chall;
};

/* 
   Authenticate a user with a challenge/response, checking session key
   and valid authentication types
*/
static NTSTATUS check_samlogon(struct samlogon_state *samlogon_state, 
			       enum ntlm_break break_which,
			       DATA_BLOB *chall, 
			       DATA_BLOB *lm_response, 
			       DATA_BLOB *nt_response, 
			       uint8_t lm_key[8], 
			       uint8_t user_session_key[16], 
			       char **error_string)
{
	NTSTATUS status;
	struct netr_LogonSamLogon *r = &samlogon_state->r;
	struct netr_LogonSamLogonEx *r_ex = &samlogon_state->r_ex;
	struct netr_LogonSamLogonWithFlags *r_flags = &samlogon_state->r_flags;
	struct netr_NetworkInfo ninfo;
	struct netr_SamBaseInfo *base = NULL;
	uint16 validation_level = 0;
	
	samlogon_state->r.in.logon.network = &ninfo;
	samlogon_state->r_ex.in.logon.network = &ninfo;
	samlogon_state->r_flags.in.logon.network = &ninfo;
	
	ninfo.identity_info.domain_name.string = samlogon_state->account_domain;
	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.account_name.string = samlogon_state->account_name;
	ninfo.identity_info.workstation.string = TEST_MACHINE_NAME;
		
	memcpy(ninfo.challenge, chall->data, 8);
		
	switch (break_which) {
	case BREAK_NONE:
		break;
	case BREAK_LM:
		if (lm_response && lm_response->data) {
			lm_response->data[0]++;
		}
		break;
	case BREAK_NT:
		if (nt_response && nt_response->data) {
			nt_response->data[0]++;
		}
		break;
	case BREAK_BOTH:
		if (lm_response && lm_response->data) {
			lm_response->data[0]++;
		}
		if (nt_response && nt_response->data) {
			nt_response->data[0]++;
		}
		break;
	case NO_LM:
		data_blob_free(lm_response);
		break;
	case NO_NT:
		data_blob_free(nt_response);
		break;
	}
		
	if (nt_response) {
		ninfo.nt.data = nt_response->data;
		ninfo.nt.length = nt_response->length;
	} else {
		ninfo.nt.data = NULL;
		ninfo.nt.length = 0;
	}
		
	if (lm_response) {
		ninfo.lm.data = lm_response->data;
		ninfo.lm.length = lm_response->length;
	} else {
		ninfo.lm.data = NULL;
		ninfo.lm.length = 0;
	}
	
	switch (samlogon_state->function_level) {
	case DCERPC_NETR_LOGONSAMLOGON: 
		ZERO_STRUCT(samlogon_state->auth2);
		creds_client_authenticator(samlogon_state->creds, &samlogon_state->auth);

		r->out.return_authenticator = NULL;
		status = dcerpc_netr_LogonSamLogon(samlogon_state->p, samlogon_state->mem_ctx, r);
		if (!r->out.return_authenticator || 
		    !creds_client_check(samlogon_state->creds, &r->out.return_authenticator->cred)) {
			printf("Credential chaining failed\n");
		}
		if (!NT_STATUS_IS_OK(status)) {
			if (error_string) {
				*error_string = strdup(nt_errstr(status));
			}
		}

		validation_level = r->in.validation_level;
		switch (validation_level) {
		case 2:
			base = &r->out.validation.sam2->base;
			break;
		case 3:
			base = &r->out.validation.sam3->base;
			break;
		case 6:
			base = &r->out.validation.sam6->base;
			break;
		}
		break;
	case DCERPC_NETR_LOGONSAMLOGONEX: 
		status = dcerpc_netr_LogonSamLogonEx(samlogon_state->p, samlogon_state->mem_ctx, r_ex);
		if (!NT_STATUS_IS_OK(status)) {
			if (error_string) {
				*error_string = strdup(nt_errstr(status));
			}
		}

		validation_level = r_ex->in.validation_level;
		switch (validation_level) {
		case 2:
			base = &r_ex->out.validation.sam2->base;
			break;
		case 3:
			base = &r_ex->out.validation.sam3->base;
			break;
		case 6:
			base = &r_ex->out.validation.sam6->base;
			break;
		}
		break;
	case DCERPC_NETR_LOGONSAMLOGONWITHFLAGS: 
		ZERO_STRUCT(samlogon_state->auth2);
		creds_client_authenticator(samlogon_state->creds, &samlogon_state->auth);

		r_flags->out.return_authenticator = NULL;
		status = dcerpc_netr_LogonSamLogonWithFlags(samlogon_state->p, samlogon_state->mem_ctx, r_flags);
		if (!r_flags->out.return_authenticator || 
		    !creds_client_check(samlogon_state->creds, &r_flags->out.return_authenticator->cred)) {
			printf("Credential chaining failed\n");
		}
		if (!NT_STATUS_IS_OK(status)) {
			if (error_string) {
				*error_string = strdup(nt_errstr(status));
			}
		}

		validation_level = r_flags->in.validation_level;
		switch (validation_level) {
		case 2:
			base = &r_flags->out.validation.sam2->base;
			break;
		case 3:
			base = &r_flags->out.validation.sam3->base;
			break;
		case 6:
			base = &r_flags->out.validation.sam6->base;
			break;
		}
		break;
	}
		

	if (!NT_STATUS_IS_OK(status)) {
		/* we cannot check the session key, if the logon failed... */
		return status;
	}

	if (!base) {
		printf("No user info returned from 'successful' SamLogon*() call!\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* find and decyrpt the session keys, return in parameters above */
	if (validation_level == 6) {
		/* they aren't encrypted! */
		if (user_session_key) {
			memcpy(user_session_key, base->key.key, 16);
		}
		if (lm_key) {
			memcpy(lm_key, base->LMSessKey.key, 8);
		}
	} else if (samlogon_state->creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
		static const char zeros[16];
			
		if (memcmp(base->key.key, zeros,  
			   sizeof(base->key.key)) != 0) {
			creds_arcfour_crypt(samlogon_state->creds, 
					    base->key.key, 
					    sizeof(base->key.key));
		}
			
		if (user_session_key) {
			memcpy(user_session_key, base->key.key, 16);
		}
			
		if (memcmp(base->LMSessKey.key, zeros,  
			   sizeof(base->LMSessKey.key)) != 0) {
			creds_arcfour_crypt(samlogon_state->creds, 
					    base->LMSessKey.key, 
					    sizeof(base->LMSessKey.key));
		}
			
		if (lm_key) {
			memcpy(lm_key, base->LMSessKey.key, 8);
		}
	} else {
		static const char zeros[16];
			
		if (user_session_key) {
			memcpy(user_session_key, base->key.key, 16);
		}

		if (memcmp(base->LMSessKey.key, zeros,  
			   sizeof(base->LMSessKey.key)) != 0) {
			creds_des_decrypt_LMKey(samlogon_state->creds, 
						&base->LMSessKey);
		}
			
		if (lm_key) {
			memcpy(lm_key, base->LMSessKey.key, 8);
		}
	}
	
	return status;
} 


/* 
 * Test the normal 'LM and NTLM' combination
 */

static BOOL test_lm_ntlm_broken(struct samlogon_state *samlogon_state, enum ntlm_break break_which, char **error_string) 
{
	BOOL pass = True;
	BOOL lm_good;
	NTSTATUS nt_status;
	DATA_BLOB lm_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);
	DATA_BLOB nt_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);
	DATA_BLOB session_key = data_blob_talloc(samlogon_state->mem_ctx, NULL, 16);

	uint8_t lm_key[8];
	uint8_t user_session_key[16];
	uint8_t lm_hash[16];
	uint8_t nt_hash[16];
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(user_session_key);

	lm_good = SMBencrypt(samlogon_state->password, samlogon_state->chall.data, lm_response.data);
	if (!lm_good) {
		ZERO_STRUCT(lm_hash);
	} else {
		E_deshash(samlogon_state->password, lm_hash); 
	}
		
	SMBNTencrypt(samlogon_state->password, samlogon_state->chall.data, nt_response.data);

	E_md4hash(samlogon_state->password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, session_key.data);

	nt_status = check_samlogon(samlogon_state,
				   break_which,
				   &samlogon_state->chall,
				   &lm_response,
				   &nt_response,
				   lm_key, 
				   user_session_key,
				   error_string);
	
	data_blob_free(&lm_response);

	if (NT_STATUS_EQUAL(NT_STATUS_WRONG_PASSWORD, nt_status)) {
		/* for 'long' passwords, the LM password is invalid */
		if (break_which == NO_NT && !lm_good) {
			return True;
		}
		return ((break_which == BREAK_NT) || (break_which == BREAK_BOTH));
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		return False;
	}

	if (break_which == NO_NT && !lm_good) {
		printf("LM password is 'long' (> 14 chars and therefore invalid) but login did not fail!");
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		printf("LM Key does not match expectations!\n");
		printf("lm_key:\n");
		dump_data(1, lm_key, 8);
		printf("expected:\n");
		dump_data(1, lm_hash, 8);
		pass = False;
	}

	switch (break_which) {
	case NO_NT:
	{
		uint8_t lm_key_expected[16];
		memcpy(lm_key_expected, lm_hash, 8);
		memset(lm_key_expected+8, '\0', 8);
		if (memcmp(lm_key_expected, user_session_key, 
			   16) != 0) {
			printf("NT Session Key does not match expectations (should be first-8 LM hash)!\n");
			printf("user_session_key:\n");
			dump_data(1, user_session_key, sizeof(user_session_key));
			printf("expected:\n");
			dump_data(1, lm_key_expected, sizeof(lm_key_expected));
			pass = False;
		}
		break;
	}
	default:
		if (memcmp(session_key.data, user_session_key, 
			   sizeof(user_session_key)) != 0) {
			printf("NT Session Key does not match expectations!\n");
			printf("user_session_key:\n");
			dump_data(1, user_session_key, 16);
			printf("expected:\n");
			dump_data(1, session_key.data, session_key.length);
			pass = False;
		}
	}
        return pass;
}

/* 
 * Test LM authentication, no NT response supplied
 */

static BOOL test_lm(struct samlogon_state *samlogon_state, char **error_string) 
{

	return test_lm_ntlm_broken(samlogon_state, NO_NT, error_string);
}

/* 
 * Test the NTLM response only, no LM.
 */

static BOOL test_ntlm(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lm_ntlm_broken(samlogon_state, NO_LM, error_string);
}

/* 
 * Test the NTLM response only, but in the LM field.
 */

static BOOL test_ntlm_in_lm(struct samlogon_state *samlogon_state, char **error_string) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	DATA_BLOB nt_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);

	uint8_t lm_key[8];
	uint8_t lm_hash[16];
	uint8_t user_session_key[16];
	
	ZERO_STRUCT(user_session_key);

	SMBNTencrypt(samlogon_state->password, samlogon_state->chall.data, nt_response.data);

	E_deshash(samlogon_state->password, lm_hash); 

	nt_status = check_samlogon(samlogon_state,
				   BREAK_NONE,
				   &samlogon_state->chall,
				   &nt_response,
				   NULL,
				   lm_key, 
				   user_session_key,
				   error_string);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		printf("LM Key does not match expectations!\n");
 		printf("lm_key:\n");
		dump_data(1, lm_key, 8);
		printf("expected:\n");
		dump_data(1, lm_hash, 8);
		pass = False;
	}
	if (memcmp(lm_hash, user_session_key, 8) != 0) {
		uint8_t lm_key_expected[16];
		memcpy(lm_key_expected, lm_hash, 8);
		memset(lm_key_expected+8, '\0', 8);
		if (memcmp(lm_key_expected, user_session_key, 
			   16) != 0) {
			printf("NT Session Key does not match expectations (should be first-8 LM hash)!\n");
			printf("user_session_key:\n");
			dump_data(1, user_session_key, sizeof(user_session_key));
			printf("expected:\n");
			dump_data(1, lm_key_expected, sizeof(lm_key_expected));
			pass = False;
		}
	}
        return pass;
}

/* 
 * Test the NTLM response only, but in the both the NT and LM fields.
 */

static BOOL test_ntlm_in_both(struct samlogon_state *samlogon_state, char **error_string) 
{
	BOOL pass = True;
	BOOL lm_good;
	NTSTATUS nt_status;
	DATA_BLOB nt_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);
	DATA_BLOB session_key = data_blob_talloc(samlogon_state->mem_ctx, NULL, 16);

	uint8_t lm_key[8];
	uint8_t lm_hash[16];
	uint8_t user_session_key[16];
	uint8_t nt_hash[16];
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(user_session_key);

	SMBNTencrypt(samlogon_state->password, samlogon_state->chall.data, 
		     nt_response.data);
	E_md4hash(samlogon_state->password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, 
			   session_key.data);

	lm_good = E_deshash(samlogon_state->password, lm_hash); 
	if (!lm_good) {
		ZERO_STRUCT(lm_hash);
	}

	nt_status = check_samlogon(samlogon_state,
				   BREAK_NONE,
				   &samlogon_state->chall,
				   NULL, 
				   &nt_response,
				   lm_key, 
				   user_session_key,
				   error_string);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		printf("LM Key does not match expectations!\n");
 		printf("lm_key:\n");
		dump_data(1, lm_key, 8);
		printf("expected:\n");
		dump_data(1, lm_hash, 8);
		pass = False;
	}
	if (memcmp(session_key.data, user_session_key, 
		   sizeof(user_session_key)) != 0) {
		printf("NT Session Key does not match expectations!\n");
 		printf("user_session_key:\n");
		dump_data(1, user_session_key, 16);
 		printf("expected:\n");
		dump_data(1, session_key.data, session_key.length);
		pass = False;
	}


        return pass;
}

/* 
 * Test the NTLMv2 and LMv2 responses
 */

static BOOL test_lmv2_ntlmv2_broken(struct samlogon_state *samlogon_state, enum ntlm_break break_which, char **error_string) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	DATA_BLOB ntlmv2_response = data_blob(NULL, 0);
	DATA_BLOB lmv2_response = data_blob(NULL, 0);
	DATA_BLOB lmv2_session_key = data_blob(NULL, 0);
	DATA_BLOB ntlmv2_session_key = data_blob(NULL, 0);
	DATA_BLOB names_blob = NTLMv2_generate_names_blob(samlogon_state->mem_ctx, lp_netbios_name(), lp_workgroup());

	uint8_t lm_session_key[8];
	uint8_t user_session_key[16];

	ZERO_STRUCT(lm_session_key);
	ZERO_STRUCT(user_session_key);
	
	/* TODO - test with various domain cases, and without domain */
	if (!SMBNTLMv2encrypt(samlogon_state->account_name, samlogon_state->account_domain, 
			      samlogon_state->password, &samlogon_state->chall,
			      &names_blob,
			      &lmv2_response, &ntlmv2_response, 
			      &lmv2_session_key, &ntlmv2_session_key)) {
		data_blob_free(&names_blob);
		return False;
	}
	data_blob_free(&names_blob);

	nt_status = check_samlogon(samlogon_state,
				   break_which,
				   &samlogon_state->chall,
				   &lmv2_response,
				   &ntlmv2_response,
				   lm_session_key, 
				   user_session_key,
				   error_string);
	
	data_blob_free(&lmv2_response);
	data_blob_free(&ntlmv2_response);


	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_WRONG_PASSWORD)) {
		return break_which == BREAK_BOTH;
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		return False;
	}

	switch (break_which) {
	case NO_NT:
		if (memcmp(lmv2_session_key.data, user_session_key, 
			   sizeof(user_session_key)) != 0) {
			printf("USER (LMv2) Session Key does not match expectations!\n");
			printf("user_session_key:\n");
			dump_data(1, user_session_key, 16);
			printf("expected:\n");
			dump_data(1, lmv2_session_key.data, ntlmv2_session_key.length);
			pass = False;
		}
		if (memcmp(lmv2_session_key.data, lm_session_key, 
			   sizeof(lm_session_key)) != 0) {
			printf("LM (LMv2) Session Key does not match expectations!\n");
			printf("lm_session_key:\n");
			dump_data(1, lm_session_key, 8);
			printf("expected:\n");
			dump_data(1, lmv2_session_key.data, 8);
			pass = False;
		}
		break;
	default:
		if (memcmp(ntlmv2_session_key.data, user_session_key, 
			   sizeof(user_session_key)) != 0) {
			printf("USER (NTLMv2) Session Key does not match expectations!\n");
			printf("user_session_key:\n");
			dump_data(1, user_session_key, 16);
			printf("expected:\n");
			dump_data(1, ntlmv2_session_key.data, ntlmv2_session_key.length);
			pass = False;
		}
		if (memcmp(ntlmv2_session_key.data, lm_session_key, 
			   sizeof(lm_session_key)) != 0) {
			printf("LM (NTLMv2) Session Key does not match expectations!\n");
			printf("lm_session_key:\n");
			dump_data(1, lm_session_key, 8);
			printf("expected:\n");
			dump_data(1, ntlmv2_session_key.data, 8);
			pass = False;
		}
	}

        return pass;
}

/* 
 * Test the NTLM and LMv2 responses
 */

static BOOL test_lmv2_ntlm_broken(struct samlogon_state *samlogon_state, enum ntlm_break break_which, char **error_string) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	DATA_BLOB ntlmv2_response = data_blob(NULL, 0);
	DATA_BLOB lmv2_response = data_blob(NULL, 0);
	DATA_BLOB lmv2_session_key = data_blob(NULL, 0);
	DATA_BLOB ntlmv2_session_key = data_blob(NULL, 0);
	DATA_BLOB names_blob = NTLMv2_generate_names_blob(samlogon_state->mem_ctx, lp_netbios_name(), lp_workgroup());

	DATA_BLOB ntlm_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);
	DATA_BLOB ntlm_session_key = data_blob_talloc(samlogon_state->mem_ctx, NULL, 16);

	uint8_t lm_hash[16];
	uint8_t lm_session_key[8];
	uint8_t user_session_key[16];
	uint8_t nt_hash[16];

	SMBNTencrypt(samlogon_state->password, samlogon_state->chall.data, 
		     ntlm_response.data);
	E_md4hash(samlogon_state->password, nt_hash);
	SMBsesskeygen_ntv1(nt_hash, 
			   ntlm_session_key.data);
	E_deshash(samlogon_state->password, lm_hash); 

	ZERO_STRUCT(lm_session_key);
	ZERO_STRUCT(user_session_key);
	
	/* TODO - test with various domain cases, and without domain */
	if (!SMBNTLMv2encrypt(samlogon_state->account_name, samlogon_state->account_domain, 
			      samlogon_state->password, &samlogon_state->chall,
			      &names_blob,
			      &lmv2_response, &ntlmv2_response, 
			      &lmv2_session_key, &ntlmv2_session_key)) {
		data_blob_free(&names_blob);
		return False;
	}
	data_blob_free(&names_blob);

	nt_status = check_samlogon(samlogon_state,
				   break_which,
				   &samlogon_state->chall,
				   &lmv2_response,
				   &ntlm_response,
				   lm_session_key, 
				   user_session_key,
				   error_string);
	
	data_blob_free(&lmv2_response);
	data_blob_free(&ntlmv2_response);


	if (NT_STATUS_EQUAL(NT_STATUS_WRONG_PASSWORD, nt_status)) {
		return ((break_which == BREAK_NT) || (break_which == BREAK_BOTH));
	}

	if (!NT_STATUS_IS_OK(nt_status)) {
		return False;
	}

	switch (break_which) {
	case NO_NT:
		if (memcmp(lmv2_session_key.data, user_session_key, 
			   sizeof(user_session_key)) != 0) {
			printf("USER (LMv2) Session Key does not match expectations!\n");
			printf("user_session_key:\n");
			dump_data(1, user_session_key, 16);
			printf("expected:\n");
			dump_data(1, lmv2_session_key.data, ntlmv2_session_key.length);
			pass = False;
		}
		if (memcmp(lmv2_session_key.data, lm_session_key, 
			   sizeof(lm_session_key)) != 0) {
			printf("LM (LMv2) Session Key does not match expectations!\n");
			printf("lm_session_key:\n");
			dump_data(1, lm_session_key, 8);
			printf("expected:\n");
			dump_data(1, lmv2_session_key.data, 8);
			pass = False;
		}
		break;
	case BREAK_LM:
		if (memcmp(ntlm_session_key.data, user_session_key, 
			   sizeof(user_session_key)) != 0) {
			printf("USER (NTLMv2) Session Key does not match expectations!\n");
			printf("user_session_key:\n");
			dump_data(1, user_session_key, 16);
			printf("expected:\n");
			dump_data(1, ntlm_session_key.data, ntlm_session_key.length);
			pass = False;
		}
		if (memcmp(lm_hash, lm_session_key, 
			   sizeof(lm_session_key)) != 0) {
			printf("LM Session Key does not match expectations!\n");
			printf("lm_session_key:\n");
			dump_data(1, lm_session_key, 8);
			printf("expected:\n");
			dump_data(1, lm_hash, 8);
			pass = False;
		}
		break;
	default:
		if (memcmp(ntlm_session_key.data, user_session_key, 
			   sizeof(user_session_key)) != 0) {
			printf("USER (NTLMv2) Session Key does not match expectations!\n");
			printf("user_session_key:\n");
			dump_data(1, user_session_key, 16);
			printf("expected:\n");
			dump_data(1, ntlm_session_key.data, ntlm_session_key.length);
			pass = False;
		}
		if (memcmp(ntlm_session_key.data, lm_session_key, 
			   sizeof(lm_session_key)) != 0) {
			printf("LM (NTLMv2) Session Key does not match expectations!\n");
			printf("lm_session_key:\n");
			dump_data(1, lm_session_key, 8);
			printf("expected:\n");
			dump_data(1, ntlm_session_key.data, 8);
			pass = False;
		}
	}

        return pass;
}

/* 
 * Test the NTLMv2 and LMv2 responses
 */

static BOOL test_lmv2_ntlmv2(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlmv2_broken(samlogon_state, BREAK_NONE, error_string);
}

/* 
 * Test the LMv2 response only
 */

static BOOL test_lmv2(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlmv2_broken(samlogon_state, NO_NT, error_string);
}

/* 
 * Test the NTLMv2 response only
 */

static BOOL test_ntlmv2(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlmv2_broken(samlogon_state, NO_LM, error_string);
}

static BOOL test_lm_ntlm(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lm_ntlm_broken(samlogon_state, BREAK_NONE, error_string);
}

static BOOL test_ntlm_lm_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lm_ntlm_broken(samlogon_state, BREAK_LM, error_string);
}

static BOOL test_ntlm_ntlm_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lm_ntlm_broken(samlogon_state, BREAK_NT, error_string);
}

static BOOL test_lm_ntlm_both_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lm_ntlm_broken(samlogon_state, BREAK_BOTH, error_string);
}
static BOOL test_ntlmv2_lmv2_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlmv2_broken(samlogon_state, BREAK_LM, error_string);
}

static BOOL test_ntlmv2_ntlmv2_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlmv2_broken(samlogon_state, BREAK_NT, error_string);
}

static BOOL test_ntlmv2_both_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlmv2_broken(samlogon_state, BREAK_BOTH, error_string);
}

static BOOL test_lmv2_ntlm_both_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlm_broken(samlogon_state, BREAK_BOTH, error_string);
}

static BOOL test_lmv2_ntlm_break_ntlm(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlm_broken(samlogon_state, BREAK_NT, error_string);
}

static BOOL test_lmv2_ntlm_break_lm(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlm_broken(samlogon_state, BREAK_LM, error_string);
}

/* 
 * Test the NTLM2 response (extra challenge in LM feild)
 *
 * This test is the same as the 'break LM' test, but checks that the
 * server implements NTLM2 session security in the right place
 * (NETLOGON is the wrong place).
 */

static BOOL test_ntlm2(struct samlogon_state *samlogon_state, char **error_string) 
{
	BOOL pass = True;
	NTSTATUS nt_status;
	DATA_BLOB lm_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);
	DATA_BLOB nt_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);

	uint8_t lm_key[8];
	uint8_t nt_hash[16];
	uint8_t lm_hash[16];
	uint8_t nt_key[16];
	uint8_t user_session_key[16];
	uint8_t expected_user_session_key[16];
	uint8_t session_nonce_hash[16];
	uint8_t client_chall[8];
	
	struct MD5Context md5_session_nonce_ctx;
	HMACMD5Context hmac_ctx;
			
	ZERO_STRUCT(user_session_key);
	ZERO_STRUCT(lm_key);
	generate_random_buffer(client_chall, 8);
	
	MD5Init(&md5_session_nonce_ctx);
	MD5Update(&md5_session_nonce_ctx, samlogon_state->chall.data, 8);
	MD5Update(&md5_session_nonce_ctx, client_chall, 8);
	MD5Final(session_nonce_hash, &md5_session_nonce_ctx);
	
	E_md4hash(samlogon_state->password, (uint8_t *)nt_hash);
	E_deshash(samlogon_state->password, (uint8_t *)lm_hash);
	SMBsesskeygen_ntv1((const uint8_t *)nt_hash, 
			   nt_key);

	SMBNTencrypt(samlogon_state->password, samlogon_state->chall.data, nt_response.data);

	memcpy(lm_response.data, session_nonce_hash, 8);
	memset(lm_response.data + 8, 0, 16);

	hmac_md5_init_rfc2104(nt_key, 16, &hmac_ctx);
	hmac_md5_update(samlogon_state->chall.data, 8, &hmac_ctx);
	hmac_md5_update(client_chall, 8, &hmac_ctx);
	hmac_md5_final(expected_user_session_key, &hmac_ctx);

	nt_status = check_samlogon(samlogon_state,
				   BREAK_NONE,
				   &samlogon_state->chall,
				   &lm_response,
				   &nt_response,
				   lm_key, 
				   user_session_key,
				   error_string);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		return False;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		printf("LM Key does not match expectations!\n");
 		printf("lm_key:\n");
		dump_data(1, lm_key, 8);
		printf("expected:\n");
		dump_data(1, lm_hash, 8);
		pass = False;
	}
	if (memcmp(nt_key, user_session_key, 16) != 0) {
		printf("NT Session Key does not match expectations (should be first-8 LM hash)!\n");
		printf("user_session_key:\n");
		dump_data(1, user_session_key, sizeof(user_session_key));
		printf("expected:\n");
		dump_data(1, nt_key, sizeof(nt_key));
		pass = False;
	}
        return pass;
}

static BOOL test_plaintext(struct samlogon_state *samlogon_state, enum ntlm_break break_which, char **error_string)
{
	NTSTATUS nt_status;
	DATA_BLOB nt_response = data_blob(NULL, 0);
	DATA_BLOB lm_response = data_blob(NULL, 0);
	char *password;
	char *dospw;
	void *unicodepw;

	uint8_t user_session_key[16];
	uint8_t lm_key[16];
	static const uint8_t zeros[8];
	DATA_BLOB chall = data_blob_talloc(samlogon_state->mem_ctx, zeros, sizeof(zeros));

	ZERO_STRUCT(user_session_key);
	
	if ((push_ucs2_talloc(samlogon_state->mem_ctx, &unicodepw, 
			      samlogon_state->password)) == -1) {
		DEBUG(0, ("push_ucs2_allocate failed!\n"));
		exit(1);
	}

	nt_response = data_blob_talloc(samlogon_state->mem_ctx, unicodepw, strlen_m(samlogon_state->password)*2);

	password = strupper_talloc(samlogon_state->mem_ctx, samlogon_state->password);

	if ((convert_string_talloc(samlogon_state->mem_ctx, CH_UNIX, 
				   CH_DOS, password,
				   strlen(password)+1, 
				   (void**)&dospw)) == -1) {
		DEBUG(0, ("convert_string_talloc failed!\n"));
		exit(1);
	}

	lm_response = data_blob_talloc(samlogon_state->mem_ctx, dospw, strlen(dospw));

	nt_status = check_samlogon(samlogon_state,
				   break_which,
				   &chall,
				   &lm_response,
				   &nt_response,
				   lm_key, 
				   user_session_key,
				   error_string);
	
 	if (!NT_STATUS_IS_OK(nt_status)) {
		return break_which == BREAK_NT;
	}

	return True;
}

static BOOL test_plaintext_none_broken(struct samlogon_state *samlogon_state, 
				       char **error_string) {
	return test_plaintext(samlogon_state, BREAK_NONE, error_string);
}

static BOOL test_plaintext_lm_broken(struct samlogon_state *samlogon_state, 
				     char **error_string) {
	return test_plaintext(samlogon_state, BREAK_LM, error_string);
}

static BOOL test_plaintext_nt_broken(struct samlogon_state *samlogon_state, 
				     char **error_string) {
	return test_plaintext(samlogon_state, BREAK_NT, error_string);
}

static BOOL test_plaintext_nt_only(struct samlogon_state *samlogon_state, 
				   char **error_string) {
	return test_plaintext(samlogon_state, NO_LM, error_string);
}

static BOOL test_plaintext_lm_only(struct samlogon_state *samlogon_state, 
				   char **error_string) {
	return test_plaintext(samlogon_state, NO_NT, error_string);
}

/* 
   Tests:
   
   - LM only
   - NT and LM		   
   - NT
   - NT in LM field
   - NT in both fields
   - NTLMv2
   - NTLMv2 and LMv2
   - LMv2
   - plaintext tests (in challenge-response fields)
  
   check we get the correct session key in each case
   check what values we get for the LM session key
   
*/

static const struct ntlm_tests {
	BOOL (*fn)(struct samlogon_state *, char **);
	const char *name;
	BOOL expect_fail;
} test_table[] = {
	{test_lm, "LM", False},
	{test_lm_ntlm, "LM and NTLM", False},
	{test_lm_ntlm_both_broken, "LM and NTLM, both broken", False},
	{test_ntlm, "NTLM", False},
	{test_ntlm_in_lm, "NTLM in LM", False},
	{test_ntlm_in_both, "NTLM in both", False},
	{test_ntlmv2, "NTLMv2", False},
	{test_lmv2_ntlmv2, "NTLMv2 and LMv2", False},
	{test_lmv2, "LMv2", False},
	{test_ntlmv2_lmv2_broken, "NTLMv2 and LMv2, LMv2 broken", False},
	{test_ntlmv2_ntlmv2_broken, "NTLMv2 and LMv2, NTLMv2 broken", False},
	{test_ntlmv2_both_broken, "NTLMv2 and LMv2, both broken", False},
	{test_ntlm_lm_broken, "NTLM and LM, LM broken", False},
	{test_ntlm_ntlm_broken, "NTLM and LM, NTLM broken", False},
	{test_ntlm2, "NTLM2 (NTLMv2 session security)", False},
	{test_lmv2_ntlm_both_broken, "LMv2 and NTLM, both broken", False},
	{test_lmv2_ntlm_break_ntlm, "LMv2 and NTLM, NTLM broken", False},
	{test_lmv2_ntlm_break_lm, "LMv2 and NTLM, LMv2 broken", False},
	{test_plaintext_none_broken, "Plaintext", True},
	{test_plaintext_lm_broken, "Plaintext LM broken", True},
	{test_plaintext_nt_broken, "Plaintext NT broken", True},
	{test_plaintext_nt_only, "Plaintext NT only", True},
	{test_plaintext_lm_only, "Plaintext LM only", True},
	{NULL, NULL}
};

/*
  try a netlogon SamLogon
*/
static BOOL test_SamLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct creds_CredentialState *creds)
{
	int i, v, l, f;
	BOOL ret = True;
	int validation_levels[] = {2,3,6};
	int logon_levels[] = { 2, 6 };
	int function_levels[] = { 
		DCERPC_NETR_LOGONSAMLOGON,
		DCERPC_NETR_LOGONSAMLOGONEX,
		DCERPC_NETR_LOGONSAMLOGONWITHFLAGS };
	struct samlogon_state samlogon_state;
	
	printf("testing netr_LogonSamLogon and netr_LogonSamLogonWithFlags\n");
	
	samlogon_state.mem_ctx = mem_ctx;
	samlogon_state.account_name = lp_parm_string(-1, "torture", "username");
	samlogon_state.account_domain = lp_parm_string(-1, "torture", "userdomain");
	samlogon_state.password = lp_parm_string(-1, "torture", "password");
	samlogon_state.p = p;
	samlogon_state.creds = creds;

	samlogon_state.chall = data_blob_talloc(mem_ctx, NULL, 8);

	generate_random_buffer(samlogon_state.chall.data, 8);
	samlogon_state.r_flags.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	samlogon_state.r_flags.in.workstation = TEST_MACHINE_NAME;
	samlogon_state.r_flags.in.credential = &samlogon_state.auth;
	samlogon_state.r_flags.in.return_authenticator = &samlogon_state.auth2;
	samlogon_state.r_flags.in.flags = 0;

	samlogon_state.r_ex.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	samlogon_state.r_ex.in.workstation = TEST_MACHINE_NAME;
	samlogon_state.r_ex.in.flags = 0;

	samlogon_state.r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	samlogon_state.r.in.workstation = TEST_MACHINE_NAME;
	samlogon_state.r.in.credential = &samlogon_state.auth;
	samlogon_state.r.in.return_authenticator = &samlogon_state.auth2;

	for (f=0;f<ARRAY_SIZE(function_levels);f++) {
		for (i=0; test_table[i].fn; i++) {
			for (v=0;v<ARRAY_SIZE(validation_levels);v++) {
				for (l=0;l<ARRAY_SIZE(logon_levels);l++) {
					char *error_string = NULL;
					samlogon_state.function_level = function_levels[f];
					samlogon_state.r.in.validation_level = validation_levels[v];
					samlogon_state.r.in.logon_level = logon_levels[l];
					samlogon_state.r_ex.in.validation_level = validation_levels[v];
					samlogon_state.r_ex.in.logon_level = logon_levels[l];
					samlogon_state.r_flags.in.validation_level = validation_levels[v];
					samlogon_state.r_flags.in.logon_level = logon_levels[l];
					if (!test_table[i].fn(&samlogon_state, &error_string)) {
						printf("Testing '%s' at validation level %d, logon level %d, function %d: \n", 
						       test_table[i].name, validation_levels[v], 
						       logon_levels[l], function_levels[f]);
						
						if (test_table[i].expect_fail) {
							printf(" failed (expected, test incomplete): %s\n", error_string);
						} else {
							printf(" failed: %s\n", error_string);
							ret = False;
						}
						SAFE_FREE(error_string);
					}
				}
			}
		}
	}

	return ret;
}

/*
  test an ADS style interactive domain logon
*/
static BOOL test_InteractiveLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				  struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_LogonSamLogonWithFlags r;
	struct netr_Authenticator a, ra;
	struct netr_PasswordInfo pinfo;
	const char *plain_pass;

	ZERO_STRUCT(a);
	ZERO_STRUCT(r);
	ZERO_STRUCT(ra);

	creds_client_authenticator(creds, &a);

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.workstation = TEST_MACHINE_NAME;
	r.in.credential = &a;
	r.in.return_authenticator = &ra;
	r.in.logon_level = 5;
	r.in.logon.password = &pinfo;
	r.in.validation_level = 6;
	r.in.flags = 0;

	pinfo.identity_info.domain_name.string = lp_parm_string(-1, "torture", "userdomain");
	pinfo.identity_info.parameter_control = 0;
	pinfo.identity_info.logon_id_low = 0;
	pinfo.identity_info.logon_id_high = 0;
	pinfo.identity_info.account_name.string = lp_parm_string(-1, "torture", "username");
	pinfo.identity_info.workstation.string = TEST_MACHINE_NAME;

	plain_pass = lp_parm_string(-1, "torture", "password");

	E_deshash(plain_pass, pinfo.lmpassword.hash);
	E_md4hash(plain_pass, pinfo.ntpassword.hash);

	if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
		creds_arcfour_crypt(creds, pinfo.lmpassword.hash, 16);
		creds_arcfour_crypt(creds, pinfo.ntpassword.hash, 16);
	} else {
		creds_des_encrypt(creds, &pinfo.lmpassword);
		creds_des_encrypt(creds, &pinfo.ntpassword);
	}

	printf("Testing netr_LogonSamLogonWithFlags (Interactive Logon)\n");

	status = dcerpc_netr_LogonSamLogonWithFlags(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("netr_LogonSamLogonWithFlags - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &r.out.return_authenticator->cred)) {
		printf("Credential chaining failed\n");
		return False;
	}

	return True;
}



BOOL torture_rpc_samlogon(void)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	struct dcerpc_binding b;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	void *join_ctx;
	const char *machine_password;
	const char *binding = lp_parm_string(-1, "torture", "binding");
	int i;
	
	unsigned int credential_flags[] = {
		NETLOGON_NEG_AUTH2_FLAGS,
		NETLOGON_NEG_ARCFOUR,
		NETLOGON_NEG_ARCFOUR | NETLOGON_NEG_128BIT,
		NETLOGON_NEG_AUTH2_ADS_FLAGS, 
		0 /* yes, this is a valid flag, causes the use of DES */ 
	};

	struct creds_CredentialState *creds;

	mem_ctx = talloc_init("torture_rpc_netlogon");

	join_ctx = torture_join_domain(TEST_MACHINE_NAME, lp_workgroup(), ACB_SVRTRUST, 
				       &machine_password);
	if (!join_ctx) {
		printf("Failed to join as BDC\n");
		return False;
	}

	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Bad binding string %s\n", binding);
		ret = False;
		goto failed;
	}

	/* We have to use schannel, otherwise the SamLogonEx fails
	 * with INTERNAL_ERROR */

	b.flags &= ~DCERPC_AUTH_OPTIONS;
	b.flags |= DCERPC_SCHANNEL_BDC | DCERPC_SIGN | DCERPC_SCHANNEL_128;

	status = dcerpc_pipe_connect_b(&p, &b, 
				       DCERPC_NETLOGON_UUID,
				       DCERPC_NETLOGON_VERSION,
				       lp_workgroup(), 
				       TEST_MACHINE_NAME,
				       machine_password);

	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
		goto failed;
	}

	status = dcerpc_schannel_creds(p->security_state.generic_state, mem_ctx, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
		goto failed;
	}

	if (!test_InteractiveLogon(p, mem_ctx, creds)) {
		ret = False;
	}

	if (!test_SamLogon(p, mem_ctx, creds)) {
		ret = False;
	}

	for (i=0; i < ARRAY_SIZE(credential_flags); i++) {
		
		if (!test_SetupCredentials2(p, mem_ctx, credential_flags[i],
					    TEST_MACHINE_NAME, machine_password, creds)) {
			return False;
		}
		
		if (!test_InteractiveLogon(p, mem_ctx, creds)) {
			ret = False;
		}
		
		if (!test_SamLogon(p, mem_ctx, creds)) {
			ret = False;
		}
	}

	for (i=0; i < 32; i++) {
		if (!test_SetupCredentials2(p, mem_ctx, 1 << i,
					    TEST_MACHINE_NAME, machine_password, creds)) {
			return False;
		}
		
		if (!test_InteractiveLogon(p, mem_ctx, creds)) {
			ret = False;
		}
		
		if (!test_SamLogon(p, mem_ctx, creds)) {
			ret = False;
		}
	}

failed:
	talloc_destroy(mem_ctx);

	torture_rpc_close(p);

	torture_leave_domain(join_ctx);

	return ret;
}
