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
#include "torture/torture.h"
#include "lib/events/events.h"
#include "auth/auth.h"
#include "lib/cmdline/popt_common.h"
#include "torture/rpc/rpc.h"
#include "libcli/auth/libcli_auth.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"

static const char *machine_password;

#define TEST_MACHINE_NAME "torturetest"

static BOOL test_LogonUasLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonUasLogon r;

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping LogonUasLogon test against Samba4\n");
		return True;
	}

	r.in.server_name = NULL;
	r.in.account_name = cli_credentials_get_username(cmdline_credentials);
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

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping LogonUasLogoff test against Samba4\n");
		return True;
	}

	r.in.server_name = NULL;
	r.in.account_name = cli_credentials_get_username(cmdline_credentials);
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
			   const char *machine_name,
			   const char *plain_pass,
			   struct creds_CredentialState **creds_out)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate a;
	struct netr_Credential credentials1, credentials2, credentials3;
	struct creds_CredentialState *creds;
	struct samr_Password mach_password;

	printf("Testing ServerReqChallenge\n");

	creds = talloc(mem_ctx, struct creds_CredentialState);
	if (!creds) {
		return False;
	}

	r.in.server_name = NULL;
	r.in.computer_name = machine_name;
	r.in.credentials = &credentials1;
	r.out.credentials = &credentials2;

	generate_random_buffer(credentials1.data, sizeof(credentials1.data));

	status = dcerpc_netr_ServerReqChallenge(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerReqChallenge - %s\n", nt_errstr(status));
		return False;
	}

	E_md4hash(plain_pass, mach_password.hash);

	a.in.server_name = NULL;
	a.in.account_name = talloc_asprintf(mem_ctx, "%s$", machine_name);
	a.in.secure_channel_type = SEC_CHAN_BDC;
	a.in.computer_name = machine_name;
	a.in.credentials = &credentials3;
	a.out.credentials = &credentials3;

	creds_client_init(creds, &credentials1, &credentials2, 
			  &mach_password, &credentials3, 
			  0);

	printf("Testing ServerAuthenticate\n");

	status = dcerpc_netr_ServerAuthenticate(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerAuthenticate - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &credentials3)) {
		printf("Credential chaining failed\n");
		return False;
	}

	*creds_out = creds;
	return True;
}

static BOOL test_SetupCredentials2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    uint32_t negotiate_flags,
			    const char *machine_name,
			    const char *plain_pass,
			    int sec_chan_type,
			    struct creds_CredentialState **creds_out)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	struct creds_CredentialState *creds;
	struct samr_Password mach_password;

	printf("Testing ServerReqChallenge\n");

	creds = talloc(mem_ctx, struct creds_CredentialState);
	if (!creds) {
		return False;
	}

	r.in.server_name = NULL;
	r.in.computer_name = machine_name;
	r.in.credentials = &credentials1;
	r.out.credentials = &credentials2;

	generate_random_buffer(credentials1.data, sizeof(credentials1.data));

	status = dcerpc_netr_ServerReqChallenge(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerReqChallenge - %s\n", nt_errstr(status));
		return False;
	}

	E_md4hash(plain_pass, mach_password.hash);

	a.in.server_name = NULL;
	a.in.account_name = talloc_asprintf(mem_ctx, "%s$", machine_name);
	a.in.secure_channel_type = sec_chan_type;
	a.in.computer_name = machine_name;
	a.in.negotiate_flags = &negotiate_flags;
	a.out.negotiate_flags = &negotiate_flags;
	a.in.credentials = &credentials3;
	a.out.credentials = &credentials3;

	creds_client_init(creds, &credentials1, &credentials2, 
			  &mach_password, &credentials3, 
			  negotiate_flags);

	printf("Testing ServerAuthenticate2\n");

	status = dcerpc_netr_ServerAuthenticate2(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerAuthenticate2 - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &credentials3)) {
		printf("Credential chaining failed\n");
		return False;
	}

	printf("negotiate_flags=0x%08x\n", negotiate_flags);

	*creds_out = creds;
	return True;
}


static BOOL test_SetupCredentials3(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    uint32_t negotiate_flags,
			    const char *machine_name,
			    const char *plain_pass,
			    struct creds_CredentialState **creds_out)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate3 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	struct creds_CredentialState *creds;
	struct samr_Password mach_password;
	uint32_t rid;

	printf("Testing ServerReqChallenge\n");

	creds = talloc(mem_ctx, struct creds_CredentialState);
	if (!creds) {
		return False;
	}

	r.in.server_name = NULL;
	r.in.computer_name = machine_name;
	r.in.credentials = &credentials1;
	r.out.credentials = &credentials2;

	generate_random_buffer(credentials1.data, sizeof(credentials1.data));

	status = dcerpc_netr_ServerReqChallenge(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerReqChallenge - %s\n", nt_errstr(status));
		return False;
	}

	E_md4hash(plain_pass, mach_password.hash);

	a.in.server_name = NULL;
	a.in.account_name = talloc_asprintf(mem_ctx, "%s$", machine_name);
	a.in.secure_channel_type = SEC_CHAN_BDC;
	a.in.computer_name = machine_name;
	a.in.negotiate_flags = &negotiate_flags;
	a.in.credentials = &credentials3;
	a.out.credentials = &credentials3;
	a.out.negotiate_flags = &negotiate_flags;
	a.out.rid = &rid;

	creds_client_init(creds, &credentials1, &credentials2, 
			  &mach_password, &credentials3,
			  negotiate_flags);

	printf("Testing ServerAuthenticate3\n");

	status = dcerpc_netr_ServerAuthenticate3(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerAuthenticate3 - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &credentials3)) {
		printf("Credential chaining failed\n");
		return False;
	}

	printf("negotiate_flags=0x%08x\n", negotiate_flags);

	*creds_out = creds;
	return True;
}

/*
  try a change password for our machine account
*/
static BOOL test_SetPassword(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_ServerPasswordSet r;
	const char *password;
	struct creds_CredentialState *creds;

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, 
				   machine_password, &creds)) {
		return False;
	}

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.account_name = talloc_asprintf(mem_ctx, "%s$", TEST_MACHINE_NAME);
	r.in.secure_channel_type = SEC_CHAN_BDC;
	r.in.computer_name = TEST_MACHINE_NAME;

	password = generate_random_str(mem_ctx, 8);
	E_md4hash(password, r.in.new_password.hash);

	creds_des_encrypt(creds, &r.in.new_password);

	printf("Testing ServerPasswordSet on machine account\n");
	d_printf("Changing machine account password to '%s'\n", password);

	creds_client_authenticator(creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	/* by changing the machine password twice we test the
	   credentials chaining fully, and we verify that the server
	   allows the password to be set to the same value twice in a
	   row (match win2k3) */
	printf("Testing a second ServerPasswordSet on machine account\n");
	d_printf("Changing machine account password to '%s' (same as previous run)\n", password);

	creds_client_authenticator(creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet (2) - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	machine_password = password;

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
		printf("ServerPasswordSet failed to actually change the password\n");
		return False;
	}

	return True;
}

/*
  try a change password for our machine account
*/
static BOOL test_SetPassword2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_ServerPasswordSet2 r;
	const char *password;
	struct creds_CredentialState *creds;
	struct samr_CryptPassword password_buf;

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME,
				   machine_password, &creds)) {
		return False;
	}

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.account_name = talloc_asprintf(mem_ctx, "%s$", TEST_MACHINE_NAME);
	r.in.secure_channel_type = SEC_CHAN_BDC;
	r.in.computer_name = TEST_MACHINE_NAME;

	password = generate_random_str(mem_ctx, 8);
	encode_pw_buffer(password_buf.data, password, STR_UNICODE);
	creds_arcfour_crypt(creds, password_buf.data, 516);

	memcpy(r.in.new_password.data, password_buf.data, 512);
	r.in.new_password.length = IVAL(password_buf.data, 512);

	printf("Testing ServerPasswordSet2 on machine account\n");
	d_printf("Changing machine account password to '%s'\n", password);

	creds_client_authenticator(creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet2 - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	machine_password = password;

	if (!lp_parm_bool(-1, "torture", "dangerous", False)) {
		printf("Not testing ability to set password to '', enable dangerous tests to perform this test\n");
	} else {
		/* by changing the machine password to ""
		 * we check if the server uses password restrictions
		 * for ServerPasswordSet2
		 * (win2k3 accepts "")
		 */
		password = "";
		encode_pw_buffer(password_buf.data, password, STR_UNICODE);
		creds_arcfour_crypt(creds, password_buf.data, 516);
		
		memcpy(r.in.new_password.data, password_buf.data, 512);
		r.in.new_password.length = IVAL(password_buf.data, 512);
		
		printf("Testing ServerPasswordSet2 on machine account\n");
		d_printf("Changing machine account password to '%s'\n", password);
		
		creds_client_authenticator(creds, &r.in.credential);
		
		status = dcerpc_netr_ServerPasswordSet2(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("ServerPasswordSet2 - %s\n", nt_errstr(status));
			return False;
		}
		
		if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
			printf("Credential chaining failed\n");
		}
		
		machine_password = password;
	}

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
		printf("ServerPasswordSet failed to actually change the password\n");
		return False;
	}

	/* now try a random password */
	password = generate_random_str(mem_ctx, 8);
	encode_pw_buffer(password_buf.data, password, STR_UNICODE);
	creds_arcfour_crypt(creds, password_buf.data, 516);

	memcpy(r.in.new_password.data, password_buf.data, 512);
	r.in.new_password.length = IVAL(password_buf.data, 512);

	printf("Testing second ServerPasswordSet2 on machine account\n");
	d_printf("Changing machine account password to '%s'\n", password);

	creds_client_authenticator(creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet2 (2) - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	/* by changing the machine password twice we test the
	   credentials chaining fully, and we verify that the server
	   allows the password to be set to the same value twice in a
	   row (match win2k3) */
	printf("Testing a second ServerPasswordSet2 on machine account\n");
	d_printf("Changing machine account password to '%s' (same as previous run)\n", password);

	creds_client_authenticator(creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet (3) - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	machine_password = password;

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
		printf("ServerPasswordSet failed to actually change the password\n");
		return False;
	}

	return True;
}

/*
  try a netlogon SamLogon
*/
BOOL test_netlogon_ops(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			      struct cli_credentials *credentials, 
			      struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_LogonSamLogon r;
	struct netr_Authenticator auth, auth2;
	struct netr_NetworkInfo ninfo;
	DATA_BLOB names_blob, chal, lm_resp, nt_resp;
	int i;
	BOOL ret = True;
	int flags = CLI_CRED_NTLM_AUTH;
	if (lp_client_lanman_auth()) {
		flags |= CLI_CRED_LANMAN_AUTH;
	}

	if (lp_client_ntlmv2_auth()) {
		flags |= CLI_CRED_NTLMv2_AUTH;
	}

	cli_credentials_get_ntlm_username_domain(cmdline_credentials, mem_ctx, 
						 &ninfo.identity_info.account_name.string,
						 &ninfo.identity_info.domain_name.string);
	
	generate_random_buffer(ninfo.challenge, 
			       sizeof(ninfo.challenge));
	chal = data_blob_const(ninfo.challenge, 
			       sizeof(ninfo.challenge));

	names_blob = NTLMv2_generate_names_blob(mem_ctx, cli_credentials_get_workstation(credentials), 
						cli_credentials_get_domain(credentials));

	status = cli_credentials_get_ntlm_response(cmdline_credentials, mem_ctx, 
						   &flags, 
						   chal,
						   names_blob,
						   &lm_resp, &nt_resp,
						   NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		printf("cli_credentials_get_ntlm_response failed: %s\n", 
		       nt_errstr(status));
		return False;
	}

	ninfo.lm.data = lm_resp.data;
	ninfo.lm.length = lm_resp.length;

	ninfo.nt.data = nt_resp.data;
	ninfo.nt.length = nt_resp.length;

	ninfo.identity_info.parameter_control = 0;
	ninfo.identity_info.logon_id_low = 0;
	ninfo.identity_info.logon_id_high = 0;
	ninfo.identity_info.workstation.string = cli_credentials_get_workstation(credentials);

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = cli_credentials_get_workstation(credentials);
	r.in.credential = &auth;
	r.in.return_authenticator = &auth2;
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;

	d_printf("Testing LogonSamLogon with name %s\n", ninfo.identity_info.account_name.string);
	
	for (i=2;i<3;i++) {
		ZERO_STRUCT(auth2);
		creds_client_authenticator(creds, &auth);
		
		r.in.validation_level = i;
		
		status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonSamLogon failed: %s\n", 
			       nt_errstr(status));
			return False;
		}
		
		if (!creds_client_check(creds, &r.out.return_authenticator->cred)) {
			printf("Credential chaining failed\n");
			ret = False;
		}
	}

	r.in.credential = NULL;

	for (i=2;i<=3;i++) {

		r.in.validation_level = i;

		printf("Testing SamLogon with validation level %d and a NULL credential\n", i);

		status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &r);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			printf("LogonSamLogon expected INVALID_PARAMETER, got: %s\n", nt_errstr(status));
			ret = False;
		}

	}


	return ret;
}

/*
  try a netlogon SamLogon
*/
static BOOL test_SamLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct cli_credentials *credentials)
{
	struct creds_CredentialState *creds;

	if (!test_SetupCredentials(p, mem_ctx, cli_credentials_get_workstation(credentials), 
				   cli_credentials_get_password(credentials), &creds)) {
		return False;
	}

	return test_netlogon_ops(p, mem_ctx, credentials, creds);
}

/* we remember the sequence numbers so we can easily do a DatabaseDelta */
static uint64_t sequence_nums[3];

/*
  try a netlogon DatabaseSync
*/
static BOOL test_DatabaseSync(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DatabaseSync r;
	struct creds_CredentialState *creds;
	const uint32_t database_ids[] = {SAM_DATABASE_DOMAIN, SAM_DATABASE_BUILTIN, SAM_DATABASE_PRIVS}; 
	int i;
	BOOL ret = True;

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DatabaseSync test against Samba4\n");
		return True;
	}

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.sync_context = 0;
		r.in.database_id = database_ids[i];

		printf("Testing DatabaseSync of id %d\n", r.in.database_id);

		do {
			creds_client_authenticator(creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseSync - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sync_context = r.out.sync_context;

			if (r.out.delta_enum_array &&
			    r.out.delta_enum_array->num_deltas > 0 &&
			    r.out.delta_enum_array->delta_enum[0].delta_type == NETR_DELTA_DOMAIN &&
			    r.out.delta_enum_array->delta_enum[0].delta_union.domain) {
				sequence_nums[r.in.database_id] = 
					r.out.delta_enum_array->delta_enum[0].delta_union.domain->sequence_num;
				printf("\tsequence_nums[%d]=%llu\n",
				       r.in.database_id, 
				       (unsigned long long)sequence_nums[r.in.database_id]);
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
	struct creds_CredentialState *creds;
	const uint32_t database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DatabaseDeltas test against Samba4\n");
		return True;
	}

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.database_id = database_ids[i];
		r.in.sequence_num = sequence_nums[r.in.database_id];

		if (r.in.sequence_num == 0) continue;

		r.in.sequence_num -= 1;


		printf("Testing DatabaseDeltas of id %d at %llu\n", 
		       r.in.database_id, (unsigned long long)r.in.sequence_num);

		do {
			creds_client_authenticator(creds, &r.in.credential);

			status = dcerpc_netr_DatabaseDeltas(p, mem_ctx, &r);
			if (NT_STATUS_EQUAL(status, 
					     NT_STATUS_SYNCHRONIZATION_REQUIRED)) {
				printf("no considering %s to be an error\n",
				       nt_errstr(status));
				return True;
			}
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseDeltas - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
				printf("Credential chaining failed\n");
			}

			r.in.sequence_num++;
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
	struct creds_CredentialState *creds;
	BOOL ret = True;

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	ZERO_STRUCT(r.in.return_authenticator);
	creds_client_authenticator(creds, &r.in.credential);
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
	struct creds_CredentialState *creds;
	BOOL ret = True;

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	ZERO_STRUCT(r.in.return_authenticator);
	creds_client_authenticator(creds, &r.in.credential);
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


	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping GetDCName test against Samba4\n");
		return True;
	}	

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.domainname = lp_workgroup();

	printf("Testing GetDcName\n");

	status = dcerpc_netr_GetDcName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetDcName - %s\n", nt_errstr(status));
		return False;
	}

	d_printf("\tDC is at '%s'\n", r.out.dcname);

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

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping LogonControl test against Samba4\n");
		return True;
	}

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

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping GetAnyDCName test against Samba4\n");
		return True;
	}

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

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping LogonControl2 test against Samba4\n");
		return True;
	}

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
	struct creds_CredentialState *creds;
	const uint32_t database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	if (!test_SetupCredentials2(p, mem_ctx, NETLOGON_NEG_AUTH2_FLAGS, 
				    TEST_MACHINE_NAME, machine_password, 
				    SEC_CHAN_BDC, &creds)) {
		return False;
	}

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DatabaseSync2 test against Samba4\n");
		return True;
	}

	r.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = TEST_MACHINE_NAME;
	r.in.preferredmaximumlength = (uint32_t)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
		r.in.sync_context = 0;
		r.in.database_id = database_ids[i];
		r.in.restart_state = 0;

		printf("Testing DatabaseSync2 of id %d\n", r.in.database_id);

		do {
			creds_client_authenticator(creds, &r.in.credential);

			status = dcerpc_netr_DatabaseSync2(p, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status) &&
			    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
				printf("DatabaseSync2 - %s\n", nt_errstr(status));
				ret = False;
				break;
			}

			if (!creds_client_check(creds, &r.out.return_authenticator.cred)) {
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

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DatabaseSync2 test against Samba4\n");
		return True;
	}

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


/*
  try a netlogon netr_DsrEnumerateDomainTrusts
*/
static BOOL test_DsrEnumerateDomainTrusts(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DsrEnumerateDomainTrusts r;

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.trust_flags = 0x3f;

	printf("Testing netr_DsrEnumerateDomainTrusts\n");

	status = dcerpc_netr_DsrEnumerateDomainTrusts(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("netr_DsrEnumerateDomainTrusts - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_netr_DsRGetSiteName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				     const char *computer_name, 
				     const char *expected_site) 
{
	NTSTATUS status;
	struct netr_DsRGetSiteName r;
	BOOL ret = True;

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping DsRGetSiteName test against Samba4\n");
		return True;
	}

	r.in.computer_name		= computer_name;
	printf("Testing netr_DsRGetSiteName\n");

	status = dcerpc_netr_DsRGetSiteName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("netr_DsRGetSiteName - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		ret = False;
	} else {
		if (strcmp(expected_site, r.out.site) != 0) {
			d_printf("netr_DsRGetSiteName - unexpected result: %s, expected %s\n", 
			       r.out.site, expected_site);
					
			ret = False;
		}
	}
	r.in.computer_name		= talloc_asprintf(mem_ctx, "\\\\%s", computer_name);
	d_printf("Testing netr_DsRGetSiteName with broken computer name: %s\n", r.in.computer_name);

	status = dcerpc_netr_DsRGetSiteName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("netr_DsRGetSiteName - %s\n", 
		       nt_errstr(status));
		ret = False;
	} else if (!W_ERROR_EQUAL(r.out.result, WERR_INVALID_COMPUTERNAME)) {
		printf("netr_DsRGetSiteName - incorrect error return %s, expected %s\n", 
		       win_errstr(r.out.result), win_errstr(WERR_INVALID_COMPUTERNAME));
		ret = False;
	}
	return ret;
}

/*
  try a netlogon netr_DsRGetDCName
*/
static BOOL test_netr_DsRGetDCName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DsRGetDCName r;
	BOOL ret = True;

	r.in.server_unc		= talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.domain_name	= talloc_asprintf(mem_ctx, "%s", lp_realm());
	r.in.domain_guid	= NULL;
	r.in.site_guid	        = NULL;
	r.in.flags		= 0x40000000;

	printf("Testing netr_DsRGetDCName\n");

	status = dcerpc_netr_DsRGetDCName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("netr_DsRGetDCName - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		ret = False;
	} else {
		ret = test_netr_DsRGetSiteName(p, mem_ctx, 
					       r.out.info->dc_unc, 
					       r.out.info->dc_site_name);
	}

	return ret;
}

/*
  try a netlogon netr_DsRGetDCNameEx
*/
static BOOL test_netr_DsRGetDCNameEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DsRGetDCNameEx r;
	BOOL ret = True;

	r.in.server_unc		= talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.domain_name	= talloc_asprintf(mem_ctx, "%s", lp_realm());
	r.in.domain_guid	= NULL;
	r.in.site_name	        = NULL;
	r.in.flags		= 0x40000000;

	printf("Testing netr_DsRGetDCNameEx\n");

	status = dcerpc_netr_DsRGetDCNameEx(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("netr_DsRGetDCNameEx - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		ret = False;
	} else {
		ret = test_netr_DsRGetSiteName(p, mem_ctx, 
					       r.out.info->dc_unc, 
					       r.out.info->dc_site_name);
	}

	return ret;
}

/*
  try a netlogon netr_DsRGetDCNameEx2
*/
static BOOL test_netr_DsRGetDCNameEx2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DsRGetDCNameEx2 r;
	BOOL ret = True;

	r.in.server_unc		= talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.client_account	= NULL;
	r.in.mask		= 0x00000000;
	r.in.domain_name	= talloc_asprintf(mem_ctx, "%s", lp_realm());
	r.in.domain_guid	= NULL;
	r.in.site_name		= NULL;
	r.in.flags		= 0x40000000;

	printf("Testing netr_DsRGetDCNameEx2 without client account\n");

	status = dcerpc_netr_DsRGetDCNameEx2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("netr_DsRGetDCNameEx2 - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		ret = False;
	}

	printf("Testing netr_DsRGetDCNameEx2 with client acount\n");
	r.in.client_account	= TEST_MACHINE_NAME"$";
	r.in.mask		= 0x00002000;
	r.in.flags		= 0x80000000;

	status = dcerpc_netr_DsRGetDCNameEx2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
		printf("netr_DsRGetDCNameEx2 - %s/%s\n", 
		       nt_errstr(status), win_errstr(r.out.result));
		ret = False;
	} else {
		ret = test_netr_DsRGetSiteName(p, mem_ctx, 
					       r.out.info->dc_unc, 
					       r.out.info->dc_site_name);
	}

	return ret;
}

static BOOL test_GetDomainInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonGetDomainInfo r;
	struct netr_DomainQuery1 q1;
	struct netr_Authenticator a;
	struct creds_CredentialState *creds;

	if (!test_SetupCredentials3(p, mem_ctx, NETLOGON_NEG_AUTH2_ADS_FLAGS, 
				    TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
	}

	ZERO_STRUCT(r);

	creds_client_authenticator(creds, &a);

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = TEST_MACHINE_NAME;
	r.in.level = 1;
	r.in.credential = &a;
	r.in.return_authenticator = &a;
	r.out.return_authenticator = &a;

	r.in.query.query1 = &q1;
	ZERO_STRUCT(q1);
	
	/* this should really be the fully qualified name */
	q1.workstation_domain = TEST_MACHINE_NAME;
	q1.workstation_site = "Default-First-Site-Name";
	q1.blob2.length = 0;
	q1.blob2.size = 0;
	q1.blob2.data = NULL;
	q1.product.string = "product string";

	printf("Testing netr_LogonGetDomainInfo\n");

	status = dcerpc_netr_LogonGetDomainInfo(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("netr_LogonGetDomainInfo - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(creds, &a.cred)) {
		printf("Credential chaining failed\n");
		return False;
	}

	return True;
}


static void async_callback(struct rpc_request *req)
{
	int *counter = req->async.private_data;
	if (NT_STATUS_IS_OK(req->status)) {
		(*counter)++;
	}
}

static BOOL test_GetDomainInfo_async(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonGetDomainInfo r;
	struct netr_DomainQuery1 q1;
	struct netr_Authenticator a;
#define ASYNC_COUNT 100
	struct creds_CredentialState *creds;
	struct creds_CredentialState *creds_async[ASYNC_COUNT];
	struct rpc_request *req[ASYNC_COUNT];
	int i;
	int *async_counter = talloc(mem_ctx, int);

	if (!lp_parm_bool(-1, "torture", "dangerous", False)) {
		printf("test_GetDomainInfo_async disabled - enable dangerous tests to use\n");
		return True;
	}

	if (!test_SetupCredentials3(p, mem_ctx, NETLOGON_NEG_AUTH2_ADS_FLAGS, 
				    TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
	}

	ZERO_STRUCT(r);
	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = TEST_MACHINE_NAME;
	r.in.level = 1;
	r.in.credential = &a;
	r.in.return_authenticator = &a;
	r.out.return_authenticator = &a;

	r.in.query.query1 = &q1;
	ZERO_STRUCT(q1);
	
	/* this should really be the fully qualified name */
	q1.workstation_domain = TEST_MACHINE_NAME;
	q1.workstation_site = "Default-First-Site-Name";
	q1.blob2.length = 0;
	q1.blob2.size = 0;
	q1.blob2.data = NULL;
	q1.product.string = "product string";

	printf("Testing netr_LogonGetDomainInfo - async count %d\n", ASYNC_COUNT);

	*async_counter = 0;

	for (i=0;i<ASYNC_COUNT;i++) {
		creds_client_authenticator(creds, &a);

		creds_async[i] = talloc_memdup(creds, creds, sizeof(*creds));
		req[i] = dcerpc_netr_LogonGetDomainInfo_send(p, mem_ctx, &r);

		req[i]->async.callback = async_callback;
		req[i]->async.private_data = async_counter;

		/* even with this flush per request a w2k3 server seems to 
		   clag with multiple outstanding requests. bleergh. */
		if (event_loop_once(dcerpc_event_context(p)) != 0) {
			return False;
		}
	}

	for (i=0;i<ASYNC_COUNT;i++) {
		status = dcerpc_ndr_request_recv(req[i]);
		if (!NT_STATUS_IS_OK(status) || !NT_STATUS_IS_OK(r.out.result)) {
			printf("netr_LogonGetDomainInfo_async(%d) - %s/%s\n", 
			       i, nt_errstr(status), nt_errstr(r.out.result));
			break;
		}

		if (!creds_client_check(creds_async[i], &a.cred)) {
			printf("Credential chaining failed at async %d\n", i);
			break;
		}
	}

	printf("Testing netr_LogonGetDomainInfo - async count %d OK\n", *async_counter);

	return (*async_counter) == ASYNC_COUNT;
}

static BOOL test_ManyGetDCName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct dcerpc_pipe *p2;
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 o;
	struct policy_handle lsa_handle;
	struct lsa_DomainList domains;

	struct lsa_EnumTrustDom t;
	uint32_t resume_handle = 0;
	struct netr_GetAnyDCName d;

	int i;
	BOOL ret = True;

	if (p->conn->transport.transport != NCACN_NP) {
		return True;
	}

	printf("Torturing GetDCName\n");

	status = dcerpc_secondary_connection(p, &p2, p->binding);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to create secondary connection\n");
		return False;
	}

	status = dcerpc_bind_auth_none(p2, &dcerpc_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
   		printf("Failed to create bind on secondary connection\n");
		return False;
        }

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	o.in.system_name = "\\";
	o.in.attr = &attr;
	o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	o.out.handle = &lsa_handle;

	status = dcerpc_lsa_OpenPolicy2(p2, mem_ctx, &o);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy2 failed - %s\n", nt_errstr(status));
		return False;
	}

	t.in.handle = &lsa_handle;
	t.in.resume_handle = &resume_handle;
	t.in.max_size = 1000;
	t.out.domains = &domains;
	t.out.resume_handle = &resume_handle;

	status = dcerpc_lsa_EnumTrustDom(p2, mem_ctx, &t);

	if ((!NT_STATUS_IS_OK(status) &&
	     (!NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)))) {
		printf("Could not list domains\n");
		return False;
	}

	talloc_free(p2);

	d.in.logon_server = talloc_asprintf(mem_ctx, "\\\\%s",
					    dcerpc_server_name(p));

	for (i=0; i<domains.count * 4; i++) {
		struct lsa_DomainInfo *info =
			&domains.domains[rand()%domains.count];

		d.in.domainname = info->name.string;

		status = dcerpc_netr_GetAnyDCName(p, mem_ctx, &d);
		if (!NT_STATUS_IS_OK(status)) {
			printf("GetAnyDCName - %s\n", nt_errstr(status));
			continue;
		}

		printf("\tDC for domain %s is %s\n", info->name.string,
		       d.out.dcname ? d.out.dcname : "unknown");
	}

	return ret;
}


BOOL torture_rpc_netlogon(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct test_join *join_ctx;
	struct cli_credentials *machine_credentials;

	mem_ctx = talloc_init("torture_rpc_netlogon");

	join_ctx = torture_join_domain(TEST_MACHINE_NAME, ACB_SVRTRUST, 
				       &machine_credentials);
	if (!join_ctx) {
		talloc_free(mem_ctx);
		printf("Failed to join as BDC\n");
		return False;
	}

	machine_password = cli_credentials_get_password(machine_credentials);

	status = torture_rpc_connection(mem_ctx, &p, &dcerpc_table_netlogon);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	ret &= test_LogonUasLogon(p, mem_ctx);
	ret &= test_LogonUasLogoff(p, mem_ctx);
	ret &= test_SamLogon(p, mem_ctx, machine_credentials);
	ret &= test_SetPassword(p, mem_ctx);
	ret &= test_SetPassword2(p, mem_ctx);
	ret &= test_GetDomainInfo(p, mem_ctx);
	ret &= test_DatabaseSync(p, mem_ctx);
	ret &= test_DatabaseDeltas(p, mem_ctx);
	ret &= test_AccountDeltas(p, mem_ctx);
	ret &= test_AccountSync(p, mem_ctx);
	ret &= test_GetDcName(p, mem_ctx);
	ret &= test_ManyGetDCName(p, mem_ctx);
	ret &= test_LogonControl(p, mem_ctx);
	ret &= test_GetAnyDCName(p, mem_ctx);
	ret &= test_LogonControl2(p, mem_ctx);
	ret &= test_DatabaseSync2(p, mem_ctx);
	ret &= test_LogonControl2Ex(p, mem_ctx);
	ret &= test_DsrEnumerateDomainTrusts(p, mem_ctx);
	ret &= test_GetDomainInfo_async(p, mem_ctx);
	ret &= test_netr_DsRGetDCName(p, mem_ctx);
	ret &= test_netr_DsRGetDCNameEx(p, mem_ctx);
	ret &= test_netr_DsRGetDCNameEx2(p, mem_ctx);

	talloc_free(mem_ctx);

	torture_leave_domain(join_ctx);

	return ret;
}
