/* 
   Unix SMB/CIFS implementation.

   test suite for netlogon rpc operations

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


#define TEST_MACHINE_NAME "torturetest"

static struct {
	struct dcerpc_pipe *p;
	const char *machine_password;
	struct policy_handle acct_handle;
} join;

/*
  join the domain as a BDC
*/
static BOOL join_domain_bdc(TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct samr_Connect c;
	struct samr_CreateUser2 r;
	struct samr_OpenDomain o;
	struct samr_LookupDomain l;
	struct samr_GetUserPwInfo pwp;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	struct policy_handle handle;
	struct policy_handle domain_handle;
	uint32 access_granted;
	uint32 rid;
	BOOL ret = True;
	DATA_BLOB session_key;
	struct samr_Name name;
	int policy_min_pw_len = 0;

	printf("Connecting to SAMR\n");

	status = torture_rpc_connection(&join.p, 
					DCERPC_SAMR_NAME,
					DCERPC_SAMR_UUID,
					DCERPC_SAMR_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	c.in.system_name = NULL;
	c.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	c.out.handle = &handle;

	status = dcerpc_samr_Connect(join.p, mem_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		printf("samr_Connect failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("Opening domain %s\n", lp_workgroup());

	name.name = lp_workgroup();
	l.in.handle = &handle;
	l.in.domain = &name;

	status = dcerpc_samr_LookupDomain(join.p, mem_ctx, &l);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	o.in.handle = &handle;
	o.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	o.in.sid = l.out.sid;
	o.out.domain_handle = &domain_handle;

	status = dcerpc_samr_OpenDomain(join.p, mem_ctx, &o);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("Creating machine account %s\n", TEST_MACHINE_NAME);

again:
	name.name = talloc_asprintf(mem_ctx, "%s$", TEST_MACHINE_NAME);
	r.in.handle = &domain_handle;
	r.in.username = &name;
	r.in.acct_flags = ACB_SVRTRUST;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.acct_handle = &join.acct_handle;
	r.out.access_granted = &access_granted;
	r.out.rid = &rid;

	status = dcerpc_samr_CreateUser2(join.p, mem_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS) &&
	    test_DeleteUser_byname(join.p, mem_ctx, &domain_handle, name.name)) {
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateUser2 failed - %s\n", nt_errstr(status));
		return False;
	}

	pwp.in.handle = &join.acct_handle;

	status = dcerpc_samr_GetUserPwInfo(join.p, mem_ctx, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_pwd_len;
	}

	join.machine_password = generate_random_str(mem_ctx, MAX(8, policy_min_pw_len));

	printf("Setting machine account password '%s'\n", join.machine_password);

	s.in.handle = &join.acct_handle;
	s.in.info = &u;
	s.in.level = 24;

	encode_pw_buffer(u.info24.password.data, join.machine_password, STR_UNICODE);
	u.info24.pw_len = strlen(join.machine_password);

	status = dcerpc_fetch_session_key(join.p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	SamOEMhashBlob(u.info24.password.data, 516, &session_key);

	status = dcerpc_samr_SetUserInfo(join.p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo failed - %s\n", nt_errstr(status));
		return False;
	}

	s.in.handle = &join.acct_handle;
	s.in.info = &u;
	s.in.level = 16;

	u.info16.acct_flags = ACB_SVRTRUST;

	printf("Resetting ACB flags\n");

	status = dcerpc_samr_SetUserInfo(join.p, mem_ctx, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}

/*
  leave the domain as a BDC
*/
static BOOL leave_domain_bdc(TALLOC_CTX *mem_ctx)
{
	struct samr_DeleteUser d;
	NTSTATUS status;

	d.in.handle = &join.acct_handle;
	d.out.handle = &join.acct_handle;

	status = dcerpc_samr_DeleteUser(join.p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Delete of machine account failed\n");
		return False;
	}

	return True;
}

static BOOL test_LogonUasLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonUasLogon r;

	r.in.server_name = NULL;
	r.in.username = lp_parm_string(-1, "torture", "username");
	r.in.workstation = TEST_MACHINE_NAME;

	printf("Testing LogonUasLogon\n");

	status = dcerpc_netr_LogonUasLogon(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LogonUasLogon - %s\n", nt_errstr(status));
		return False;
	}

	return True;
	
}

static BOOL test_LogonUasLogoff(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonUasLogoff r;

	r.in.server_name = NULL;
	r.in.username = lp_parm_string(-1, "torture", "username");
	r.in.workstation = TEST_MACHINE_NAME;

	printf("Testing LogonUasLogoff\n");

	status = dcerpc_netr_LogonUasLogoff(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LogonUasLogoff - %s\n", nt_errstr(status));
		return False;
	}

	return True;
	
}

static BOOL test_SetupCredentials(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				  struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate a;
	const char *plain_pass;
	uint8 mach_pwd[16];

	printf("Testing ServerReqChallenge\n");

	r.in.server_name = NULL;
	r.in.computer_name = TEST_MACHINE_NAME;
	generate_random_buffer(r.in.credentials.data, sizeof(r.in.credentials.data), False);

	status = dcerpc_netr_ServerReqChallenge(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerReqChallenge - %s\n", nt_errstr(status));
		return False;
	}

	plain_pass = join.machine_password;
	if (!plain_pass) {
		printf("Unable to fetch machine password!\n");
		return False;
	}

	E_md4hash(plain_pass, mach_pwd);

	creds_client_init(creds, &r.in.credentials, &r.out.credentials, mach_pwd,
			  &a.in.credentials);

	a.in.server_name = NULL;
	a.in.username = talloc_asprintf(mem_ctx, "%s$", TEST_MACHINE_NAME);
	a.in.secure_channel_type = SEC_CHAN_BDC;
	a.in.computer_name = TEST_MACHINE_NAME;

	printf("Testing ServerAuthenticate\n");

	status = dcerpc_netr_ServerAuthenticate(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerAuthenticate - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &a.out.credentials)) {
		printf("Credential chaining failed\n");
		return False;
	}

	return True;
}

static BOOL test_SetupCredentials2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				   uint32 negotiate_flags,
				   struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	const char *plain_pass;
	uint8 mach_pwd[16];

	printf("Testing ServerReqChallenge\n");

	r.in.server_name = NULL;
	r.in.computer_name = TEST_MACHINE_NAME;
	generate_random_buffer(r.in.credentials.data, sizeof(r.in.credentials.data), False);

	status = dcerpc_netr_ServerReqChallenge(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerReqChallenge - %s\n", nt_errstr(status));
		return False;
	}

	plain_pass = join.machine_password;
	if (!plain_pass) {
		printf("Unable to fetch machine password!\n");
		return False;
	}

	E_md4hash(plain_pass, mach_pwd);

	creds_client_init(creds, &r.in.credentials, &r.out.credentials, mach_pwd,
			  &a.in.credentials);

	a.in.server_name = NULL;
	a.in.username = talloc_asprintf(mem_ctx, "%s$", TEST_MACHINE_NAME);
	a.in.secure_channel_type = SEC_CHAN_BDC;
	a.in.computer_name = TEST_MACHINE_NAME;
	a.in.negotiate_flags = &negotiate_flags;
	a.out.negotiate_flags = &negotiate_flags;

	printf("Testing ServerAuthenticate2\n");

	status = dcerpc_netr_ServerAuthenticate2(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerAuthenticate2 - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &a.out.credentials)) {
		printf("Credential chaining failed\n");
		return False;
	}

	printf("negotiate_flags=0x%08x\n", negotiate_flags);

	return True;
}

enum ntlm_break {
	BREAK_NONE,
	BREAK_LM,
	BREAK_NT,
	NO_LM,
	NO_NT
};

struct samlogon_state {
	TALLOC_CTX *mem_ctx;
	const char *username;
	const char *password;
	struct dcerpc_pipe *p;
	struct netr_LogonSamLogon r;
	struct netr_Authenticator auth, auth2;
	struct creds_CredentialState creds;
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
			       uint8 lm_key[8], 
			       uint8 user_session_key[16], 
			       char **error_string)
{
	NTSTATUS status;
	struct netr_LogonSamLogon *r = &samlogon_state->r;

	struct netr_NetworkInfo ninfo;
	samlogon_state->r.in.logon_level = 2;
	samlogon_state->r.in.logon.network = &ninfo;
	
	ninfo.logon_info.domain_name.string = lp_workgroup();
	ninfo.logon_info.parameter_control = 0;
	ninfo.logon_info.logon_id_low = 0;
	ninfo.logon_info.logon_id_high = 0;
	ninfo.logon_info.username.string = samlogon_state->username;
	ninfo.logon_info.workstation.string = TEST_MACHINE_NAME;

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

	ZERO_STRUCT(samlogon_state->auth2);
	creds_client_authenticator(&samlogon_state->creds, &samlogon_state->auth);

	r->out.authenticator = NULL;
	status = dcerpc_netr_LogonSamLogon(samlogon_state->p, samlogon_state->mem_ctx, r);
	if (!NT_STATUS_IS_OK(status)) {
		if (error_string) {
			*error_string = strdup(nt_errstr(status));
		}
	}

	if (!r->out.authenticator || !creds_client_check(&samlogon_state->creds, &r->out.authenticator->cred)) {
		printf("Credential chaining failed\n");
	}

	if (!NT_STATUS_IS_OK(status)) {
		/* we cannot check the session key, if the logon failed... */
		return status;
	}
	
	/* find and decyrpt the session keys, return in parameters above */
	if (r->in.validation_level == 2) {
		static const char zeros[16];

		if (memcmp(r->out.validation.sam->LMSessKey.key, zeros,  sizeof(r->out.validation.sam->LMSessKey.key)) != 0) {
			creds_arcfour_crypt(&samlogon_state->creds, 
					    r->out.validation.sam->LMSessKey.key, 
					    sizeof(r->out.validation.sam->LMSessKey.key));
		}
			
		if (lm_key) {
			memcpy(lm_key, r->out.validation.sam->LMSessKey.key, 8);
		}

		if (memcmp(r->out.validation.sam->key.key, zeros,  sizeof(r->out.validation.sam->key.key)) != 0) {
			creds_arcfour_crypt(&samlogon_state->creds, 
					    r->out.validation.sam->key.key, 
					    sizeof(r->out.validation.sam->key.key));
		}

		if (user_session_key) {
			memcpy(user_session_key, r->out.validation.sam->key.key, 16);
		}

	} else if (r->in.validation_level == 3) {
		static const char zeros[16];
		if (memcmp(r->out.validation.sam2->LMSessKey.key, zeros,  sizeof(r->out.validation.sam2->LMSessKey.key)) != 0) {
			creds_arcfour_crypt(&samlogon_state->creds, 
					    r->out.validation.sam2->LMSessKey.key, 
					    sizeof(r->out.validation.sam2->LMSessKey.key));
		}

		if (lm_key) {
			memcpy(lm_key, r->out.validation.sam2->LMSessKey.key, 8);
		}

		if (memcmp(r->out.validation.sam2->key.key, zeros,  sizeof(r->out.validation.sam2->key.key)) != 0) {
			creds_arcfour_crypt(&samlogon_state->creds, 
					    r->out.validation.sam2->key.key, 
					    sizeof(r->out.validation.sam2->key.key));
		}

		if (user_session_key) {
			memcpy(user_session_key, r->out.validation.sam2->key.key, 16);
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
	NTSTATUS nt_status;
	DATA_BLOB lm_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);
	DATA_BLOB nt_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);
	DATA_BLOB session_key = data_blob_talloc(samlogon_state->mem_ctx, NULL, 16);

	uchar lm_key[8];
	uchar user_session_key[16];
	uchar lm_hash[16];
	uchar nt_hash[16];
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(user_session_key);

	SMBencrypt(samlogon_state->password, samlogon_state->chall.data, lm_response.data);
	E_deshash(samlogon_state->password, lm_hash); 

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

	if (!NT_STATUS_IS_OK(nt_status)) {
		return break_which == BREAK_NT;
	}

	if (memcmp(lm_hash, lm_key, 
		   sizeof(lm_key)) != 0) {
		printf("LM Key does not match expectations!\n");
 		printf("lm_key:\n");
		dump_data(1, (const char *)lm_key, 8);
		printf("expected:\n");
		dump_data(1, (const char *)lm_hash, 8);
		pass = False;
	}

	if (break_which == NO_NT) {
		char lm_key_expected[16];
		memcpy(lm_key_expected, lm_hash, 8);
		memset(lm_key_expected+8, '\0', 8);
		if (memcmp(lm_key_expected, user_session_key, 
			   16) != 0) {
			printf("NT Session Key does not match expectations (should be first-8 LM hash)!\n");
			printf("user_session_key:\n");
			dump_data(1, (const char *)user_session_key, sizeof(user_session_key));
			printf("expected:\n");
			dump_data(1, (const char *)lm_key_expected, sizeof(lm_key_expected));
			pass = False;
		}
	} else {		
		if (memcmp(session_key.data, user_session_key, 
			   sizeof(user_session_key)) != 0) {
			printf("NT Session Key does not match expectations!\n");
			printf("user_session_key:\n");
			dump_data(1, (const char *)user_session_key, 16);
			printf("expected:\n");
			dump_data(1, (const char *)session_key.data, session_key.length);
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

	uchar lm_key[8];
	uchar lm_hash[16];
	uchar user_session_key[16];
	
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
		dump_data(1, (const char *)lm_key, 8);
		printf("expected:\n");
		dump_data(1, (const char *)lm_hash, 8);
		pass = False;
	}
	if (memcmp(lm_hash, user_session_key, 8) != 0) {
		char lm_key_expected[16];
		memcpy(lm_key_expected, lm_hash, 8);
		memset(lm_key_expected+8, '\0', 8);
		if (memcmp(lm_key_expected, user_session_key, 
			   16) != 0) {
			printf("NT Session Key does not match expectations (should be first-8 LM hash)!\n");
			printf("user_session_key:\n");
			dump_data(1, (const char *)user_session_key, sizeof(user_session_key));
			printf("expected:\n");
			dump_data(1, (const char *)lm_key_expected, sizeof(lm_key_expected));
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
	NTSTATUS nt_status;
	DATA_BLOB nt_response = data_blob_talloc(samlogon_state->mem_ctx, NULL, 24);
	DATA_BLOB session_key = data_blob_talloc(samlogon_state->mem_ctx, NULL, 16);

	char lm_key[8];
	char lm_hash[16];
	char user_session_key[16];
	char nt_hash[16];
	
	ZERO_STRUCT(lm_key);
	ZERO_STRUCT(user_session_key);

	SMBNTencrypt(samlogon_state->password, samlogon_state->chall.data, 
		     nt_response.data);
	E_md4hash(samlogon_state->password, (unsigned char *)nt_hash);
	SMBsesskeygen_ntv1((const unsigned char *)nt_hash, 
			   session_key.data);

	E_deshash(samlogon_state->password, (unsigned char *)lm_hash); 

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
		dump_data(1, (const char *)session_key.data, session_key.length);
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
	DATA_BLOB ntlmv2_session_key = data_blob(NULL, 0);
	DATA_BLOB names_blob = NTLMv2_generate_names_blob(lp_netbios_name(), lp_workgroup());

	uchar user_session_key[16];

	ZERO_STRUCT(user_session_key);
	
	/* TODO - test with various domain cases, and without domain */
	if (!SMBNTLMv2encrypt(samlogon_state->username, lp_workgroup(), samlogon_state->password, &samlogon_state->chall,
			      &names_blob,
			      &lmv2_response, &ntlmv2_response, 
			      &ntlmv2_session_key)) {
		data_blob_free(&names_blob);
		return False;
	}
	data_blob_free(&names_blob);

	nt_status = check_samlogon(samlogon_state,
				   break_which,
				   &samlogon_state->chall,
				   &lmv2_response,
				   &ntlmv2_response,
				   NULL, 
				   user_session_key,
				   error_string);
	
	data_blob_free(&lmv2_response);
	data_blob_free(&ntlmv2_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return break_which == BREAK_NT;
	}

	if (break_which != NO_NT && break_which != BREAK_NT && memcmp(ntlmv2_session_key.data, user_session_key, 
		   sizeof(user_session_key)) != 0) {
		printf("USER (NTLMv2) Session Key does not match expectations!\n");
 		printf("user_session_key:\n");
		dump_data(1, (const char *)user_session_key, 16);
 		printf("expected:\n");
		dump_data(1, (const char *)ntlmv2_session_key.data, ntlmv2_session_key.length);
		pass = False;
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

static BOOL test_ntlmv2_lmv2_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlmv2_broken(samlogon_state, BREAK_LM, error_string);
}

static BOOL test_ntlmv2_ntlmv2_broken(struct samlogon_state *samlogon_state, char **error_string) 
{
	return test_lmv2_ntlmv2_broken(samlogon_state, BREAK_NT, error_string);
}

static BOOL test_plaintext(struct samlogon_state *samlogon_state, enum ntlm_break break_which, char **error_string)
{
	NTSTATUS nt_status;
	DATA_BLOB nt_response = data_blob(NULL, 0);
	DATA_BLOB lm_response = data_blob(NULL, 0);
	char *password;
	char *dospw;
	smb_ucs2_t *unicodepw;

	uchar user_session_key[16];
	uchar lm_key[16];
	static const uchar zeros[8];
	DATA_BLOB chall = data_blob_talloc(samlogon_state->mem_ctx, zeros, sizeof(zeros));

	ZERO_STRUCT(user_session_key);
	
	if ((push_ucs2_talloc(samlogon_state->mem_ctx, (smb_ucs2_t **)&unicodepw, 
			      samlogon_state->password)) == -1) {
		DEBUG(0, ("push_ucs2_allocate failed!\n"));
		exit(1);
	}

	nt_response = data_blob_talloc(samlogon_state->mem_ctx, unicodepw, 
				       strlen_w(((void *)unicodepw))*sizeof(smb_ucs2_t));

	password = strdup_upper(samlogon_state->password);

	if ((convert_string_talloc(samlogon_state->mem_ctx, CH_UNIX, 
				   CH_DOS, password,
				   strlen(password)+1, 
				   (const void**)&dospw)) == -1) {
		DEBUG(0, ("push_ascii_allocate failed!\n"));
		exit(1);
	}

	SAFE_FREE(password);

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
   - plaintext tests (in challenge-response feilds)
  
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
	{test_ntlm, "NTLM", False},
	{test_ntlm_in_lm, "NTLM in LM", False},
	{test_ntlm_in_both, "NTLM in both", False},
	{test_ntlmv2, "NTLMv2", False},
	{test_lmv2_ntlmv2, "NTLMv2 and LMv2", False},
	{test_lmv2, "LMv2", False},
	{test_ntlmv2_lmv2_broken, "NTLMv2 and LMv2, LMv2 broken", False},
	{test_ntlmv2_ntlmv2_broken, "NTLMv2 and LMv2, NTLMv2 broken", False},
	{test_ntlm_lm_broken, "NTLM and LM, LM broken", False},
	{test_ntlm_ntlm_broken, "NTLM and LM, NTLM broken", False},
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
static BOOL test_SamLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	int i, j;
	BOOL ret = True;

	struct samlogon_state samlogon_state;
	
	samlogon_state.mem_ctx = mem_ctx;
	samlogon_state.username = lp_parm_string(-1, "torture", "username");
	samlogon_state.password = lp_parm_string(-1, "torture", "password");
	samlogon_state.p = p;

	samlogon_state.chall = data_blob_talloc(mem_ctx, NULL, 8);

	generate_random_buffer(samlogon_state.chall.data, 
			       8, False);

	if (!test_SetupCredentials2(p, mem_ctx, NETLOGON_NEG_AUTH2_FLAGS, &samlogon_state.creds)) {
		return False;
	}

	samlogon_state.r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	samlogon_state.r.in.workstation = TEST_MACHINE_NAME;
	samlogon_state.r.in.credential = &samlogon_state.auth;
	samlogon_state.r.in.authenticator = &samlogon_state.auth2;

	for (i=2;i<=3;i++) {
		samlogon_state.r.in.validation_level = i;
		for (j=0; test_table[j].fn; j++) {
			char *error_string = NULL;
			printf("Testing SamLogon with '%s' at validation level %d\n", test_table[j].name, i);
	
			if (!test_table[j].fn(&samlogon_state, &error_string)) {
				if (test_table[j].expect_fail) {
					printf("Test %s failed (expected, test incomplete): %s\n", test_table[j].name, error_string);
				} else {
					printf("Test %s failed: %s\n", test_table[j].name, error_string);
					ret = False;
				}
				SAFE_FREE(error_string);
			}
		}
	}

	return ret;
}


/*
  try a change password for our machine account
*/
static BOOL test_SetPassword(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_ServerPasswordSet r;
	const char *password;
	struct creds_CredentialState creds;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.username = talloc_asprintf(mem_ctx, "%s$", TEST_MACHINE_NAME);
	r.in.secure_channel_type = SEC_CHAN_BDC;
	r.in.computer_name = TEST_MACHINE_NAME;

	password = generate_random_str(mem_ctx, 8);
	E_md4hash(password, r.in.new_password.data);

	creds_des_encrypt(&creds, &r.in.new_password);

	printf("Testing ServerPasswordSet on machine account\n");
	printf("Changing machine account password to '%s'\n", password);

	creds_client_authenticator(&creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(&creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	password = generate_random_str(mem_ctx, 8);
	E_md4hash(password, r.in.new_password.data);

	creds_des_encrypt(&creds, &r.in.new_password);

	/* by changing the machine password twice we test the credentials
	   chaining fully */
	printf("Testing a second ServerPasswordSet on machine account\n");
	printf("Changing machine account password to '%s'\n", password);

	creds_client_authenticator(&creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet (2) - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(&creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	join.machine_password = password;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		printf("ServerPasswordSet failed to actually change the password\n");
		return False;
	}

	return True;
}


/* we remember the sequence numbers so we can easily do a DatabaseDelta */
static struct ULONG8 sequence_nums[3];

/*
  try a netlogon DatabaseSync
*/
static BOOL test_DatabaseSync(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DatabaseSync r;
	struct creds_CredentialState creds;
	const uint32 database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.sync_context = 0;
		r.in.database_id = database_ids[i];

		printf("Testing DatabaseSync of id %d\n", r.in.database_id);

		do {
			creds_client_authenticator(&creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseSync - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(&creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sync_context = r.out.sync_context;

			if (r.out.delta_enum_array &&
			    r.out.delta_enum_array->num_deltas > 0 &&
			    r.out.delta_enum_array->delta_enum[0].delta_type == 1 &&
			    r.out.delta_enum_array->delta_enum[0].delta_union.domain) {
				sequence_nums[r.in.database_id] = 
					r.out.delta_enum_array->delta_enum[0].delta_union.domain->sequence_num;
				printf("\tsequence_nums[%d]=0x%08x%08x\n",
				       r.in.database_id, 
				       sequence_nums[r.in.database_id].high,
				       sequence_nums[r.in.database_id].low);
			}
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
	}

	return ret;
}


/*
  try a netlogon DatabaseDeltas
*/
static BOOL test_DatabaseDeltas(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DatabaseDeltas r;
	struct creds_CredentialState creds;
	const uint32 database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.database_id = database_ids[i];
		r.in.sequence_num = sequence_nums[r.in.database_id];

		if (r.in.sequence_num.low == 0) continue;

		r.in.sequence_num.low -= 1;


		printf("Testing DatabaseDeltas of id %d at %d\n", 
		       r.in.database_id, r.in.sequence_num.low);

		do {
			creds_client_authenticator(&creds, &r.in.credential);

			status = dcerpc_netr_DatabaseDeltas(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseDeltas - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(&creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sequence_num.low++;
			r.in.sequence_num.high = 0;
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
	}

	return ret;
}


/*
  try a netlogon AccountDeltas
*/
static BOOL test_AccountDeltas(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_AccountDeltas r;
	struct creds_CredentialState creds;
	BOOL ret = True;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	ZERO_STRUCT(r.in.return_authenticator);
	creds_client_authenticator(&creds, &r.in.credential);
	ZERO_STRUCT(r.in.uas);
	r.in.count=10;
	r.in.level=0;
	r.in.buffersize=100;

	printf("Testing AccountDeltas\n");

	/* w2k3 returns "NOT IMPLEMENTED" for this call */
	status = dcerpc_netr_AccountDeltas(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
		printf("AccountDeltas - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

/*
  try a netlogon AccountSync
*/
static BOOL test_AccountSync(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_AccountSync r;
	struct creds_CredentialState creds;
	BOOL ret = True;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	ZERO_STRUCT(r.in.return_authenticator);
	creds_client_authenticator(&creds, &r.in.credential);
	ZERO_STRUCT(r.in.recordid);
	r.in.reference=0;
	r.in.level=0;
	r.in.buffersize=100;

	printf("Testing AccountSync\n");

	/* w2k3 returns "NOT IMPLEMENTED" for this call */
	status = dcerpc_netr_AccountSync(p, mem_ctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
		printf("AccountSync - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

/*
  try a netlogon GetDcName
*/
static BOOL test_GetDcName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_GetDcName r;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.domainname = lp_workgroup();

	printf("Testing GetDcName\n");

	status = dcerpc_netr_GetDcName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetDcName - %s\n", nt_errstr(status));
		return False;
	}

	printf("\tDC is at '%s'\n", r.out.dcname);

	return True;
}

/*
  try a netlogon LogonControl 
*/
static BOOL test_LogonControl(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonControl r;
	BOOL ret = True;
	int i;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.function_code = 1;

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl level %d\n", i);

		status = dcerpc_netr_LogonControl(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}


/*
  try a netlogon GetAnyDCName
*/
static BOOL test_GetAnyDCName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_GetAnyDCName r;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.domainname = lp_workgroup();

	printf("Testing GetAnyDCName\n");

	status = dcerpc_netr_GetAnyDCName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetAnyDCName - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.dcname) {
		printf("\tDC is at '%s'\n", r.out.dcname);
	}

	return True;
}


/*
  try a netlogon LogonControl2
*/
static BOOL test_LogonControl2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonControl2 r;
	BOOL ret = True;
	int i;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));

	r.in.function_code = NETLOGON_CONTROL_REDISCOVER;
	r.in.data.domain = lp_workgroup();

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl2 level %d function %d\n", 
		       i, r.in.function_code);

		status = dcerpc_netr_LogonControl2(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	r.in.function_code = NETLOGON_CONTROL_TC_QUERY;
	r.in.data.domain = lp_workgroup();

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl2 level %d function %d\n", 
		       i, r.in.function_code);

		status = dcerpc_netr_LogonControl2(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	r.in.function_code = NETLOGON_CONTROL_TRANSPORT_NOTIFY;
	r.in.data.domain = lp_workgroup();

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl2 level %d function %d\n", 
		       i, r.in.function_code);

		status = dcerpc_netr_LogonControl2(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	r.in.function_code = NETLOGON_CONTROL_SET_DBFLAG;
	r.in.data.debug_level = ~0;

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl2 level %d function %d\n", 
		       i, r.in.function_code);

		status = dcerpc_netr_LogonControl2(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}

/*
  try a netlogon DatabaseSync2
*/
static BOOL test_DatabaseSync2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DatabaseSync2 r;
	struct creds_CredentialState creds;
	const uint32 database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	if (!test_SetupCredentials2(p, mem_ctx, NETLOGON_NEG_AUTH2_FLAGS, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.sync_context = 0;
		r.in.database_id = database_ids[i];
		r.in.restart_state = 0;

		printf("Testing DatabaseSync2 of id %d\n", r.in.database_id);

		do {
			creds_client_authenticator(&creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync2(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseSync2 - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(&creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sync_context = r.out.sync_context;
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
	}

	return ret;
}


/*
  try a netlogon LogonControl2Ex
*/
static BOOL test_LogonControl2Ex(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonControl2Ex r;
	BOOL ret = True;
	int i;

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));

	r.in.function_code = NETLOGON_CONTROL_REDISCOVER;
	r.in.data.domain = lp_workgroup();

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl2Ex level %d function %d\n", 
		       i, r.in.function_code);

		status = dcerpc_netr_LogonControl2Ex(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	r.in.function_code = NETLOGON_CONTROL_TC_QUERY;
	r.in.data.domain = lp_workgroup();

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl2Ex level %d function %d\n", 
		       i, r.in.function_code);

		status = dcerpc_netr_LogonControl2Ex(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	r.in.function_code = NETLOGON_CONTROL_TRANSPORT_NOTIFY;
	r.in.data.domain = lp_workgroup();

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl2Ex level %d function %d\n", 
		       i, r.in.function_code);

		status = dcerpc_netr_LogonControl2Ex(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	r.in.function_code = NETLOGON_CONTROL_SET_DBFLAG;
	r.in.data.debug_level = ~0;

	for (i=1;i<4;i++) {
		r.in.level = i;

		printf("Testing LogonControl2Ex level %d function %d\n", 
		       i, r.in.function_code);

		status = dcerpc_netr_LogonControl2Ex(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonControl - %s\n", nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}



BOOL torture_rpc_netlogon(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_netlogon");

	if (!join_domain_bdc(mem_ctx)) {
		printf("Failed to join as BDC\n");
		return False;
	}

	status = torture_rpc_connection(&p, 
					DCERPC_NETLOGON_NAME,
					DCERPC_NETLOGON_UUID,
					DCERPC_NETLOGON_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if (!test_LogonUasLogon(p, mem_ctx)) {
		ret = False;
	}

	if (!test_LogonUasLogoff(p, mem_ctx)) {
		ret = False;
	}

	if (!test_SetPassword(p, mem_ctx)) {
		ret = False;
	}

	if (!test_SamLogon(p, mem_ctx)) {
		ret = False;
	}

	if (!test_DatabaseSync(p, mem_ctx)) {
		ret = False;
	}

	if (!test_DatabaseDeltas(p, mem_ctx)) {
		ret = False;
	}

	if (!test_AccountDeltas(p, mem_ctx)) {
		ret = False;
	}

	if (!test_AccountSync(p, mem_ctx)) {
		ret = False;
	}

	if (!test_GetDcName(p, mem_ctx)) {
		ret = False;
	}

	if (!test_LogonControl(p, mem_ctx)) {
		ret = False;
	}

	if (!test_GetAnyDCName(p, mem_ctx)) {
		ret = False;
	}

	if (!test_LogonControl2(p, mem_ctx)) {
		ret = False;
	}

	if (!test_DatabaseSync2(p, mem_ctx)) {
		ret = False;
	}

	if (!test_LogonControl2Ex(p, mem_ctx)) {
		ret = False;
	}

        torture_rpc_close(p);

	if (!leave_domain_bdc(mem_ctx)) {
		printf("Failed to delete BDC machine account\n");
		return False;
	}

	return ret;
}
