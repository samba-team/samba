/* 
   Unix SMB/CIFS implementation.

   test suite for netlogon rpc operations

   Copyright (C) Andrew Tridgell 2003
   
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


static BOOL test_LogonUasLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonUasLogon r;

	r.in.server_name = NULL;
	r.in.username = lp_parm_string(-1, "torture", "username");
	r.in.workstation = lp_netbios_name();

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
	r.in.workstation = lp_netbios_name();

	printf("Testing LogonUasLogoff\n");

	status = dcerpc_netr_LogonUasLogoff(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LogonUasLogoff - %s\n", nt_errstr(status));
		return False;
	}

	return True;
	
}

static BOOL test_SetupCredentials(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
				  struct netr_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate a;
	const char *plain_pass;
	uint8 mach_pwd[16];

	printf("Testing ServerReqChallenge\n");

	r.in.server_name = NULL;
	r.in.computer_name = lp_netbios_name();
	generate_random_buffer(r.in.credentials.data, sizeof(r.in.credentials.data), False);

	status = dcerpc_netr_ServerReqChallenge(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerReqChallenge - %s\n", nt_errstr(status));
		return False;
	}

	plain_pass = secrets_fetch_machine_password();
	if (!plain_pass) {
		printf("Unable to fetch machine password!\n");
		return False;
	}

	E_md4hash(plain_pass, mach_pwd);

	creds_client_init(creds, &r.in.credentials, &r.out.credentials, mach_pwd,
			  &a.in.credentials);

	a.in.server_name = NULL;
	a.in.username = talloc_asprintf(mem_ctx, "%s$", lp_netbios_name());
	a.in.secure_challenge_type = SEC_CHAN_BDC;
	a.in.computer_name = lp_netbios_name();

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

/*
  try a netlogon SamLogon
*/
static BOOL test_SamLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonSamLogon r;
	struct netr_Authenticator auth, auth2;
	struct netr_NetworkInfo ninfo;
	const char *username = lp_parm_string(-1, "torture", "username");
	const char *password = lp_parm_string(-1, "torture", "password");
	struct netr_CredentialState creds;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	ninfo.logon_info.domain_name.string = lp_workgroup();
	ninfo.logon_info.parameter_control = 0;
	ninfo.logon_info.logon_id_low = 0;
	ninfo.logon_info.logon_id_high = 0;
	ninfo.logon_info.username.string = username;
	ninfo.logon_info.workstation.string = lp_netbios_name();
	generate_random_buffer(ninfo.challenge, 
			       sizeof(ninfo.challenge), False);
	ninfo.nt.length = 24;
	ninfo.nt.data = talloc(mem_ctx, 24);
	SMBNTencrypt(password, ninfo.challenge, ninfo.nt.data);
	ninfo.lm.length = 24;
	ninfo.lm.data = talloc(mem_ctx, 24);
	SMBencrypt(password, ninfo.challenge, ninfo.lm.data);

	ZERO_STRUCT(auth2);

	creds_client_authenticator(&creds, &auth);

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.workstation = lp_netbios_name();
	r.in.credential = &auth;
	r.in.authenticator = &auth2;
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;
	r.in.validation_level = 2;

	printf("Testing SamLogon\n");

	status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LogonSamLogon - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(&creds, &r.out.authenticator->cred)) {
		printf("Credential chaining failed\n");
	}

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
	struct netr_CredentialState creds;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.username = talloc_asprintf(mem_ctx, "%s$", lp_netbios_name());
	r.in.secure_challenge_type = SEC_CHAN_BDC;
	r.in.computer_name = lp_netbios_name();

	password = generate_random_str(8);
	E_md4hash(password, r.in.new_password.data);

	creds_client_encrypt(&creds, &r.in.new_password);

	printf("Testing ServerPasswordSet on machine account\n");

	creds_client_authenticator(&creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet - %s\n", nt_errstr(status));
		return False;
	}

	if (!secrets_store_machine_password(password)) {
		printf("Failed to save machine password\n");
	}

	if (!creds_client_check(&creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	/* by changing the machine password twice we test the credentials
	   chaining fully */
	printf("Testing a second ServerPasswordSet on machine account\n");

	creds_client_authenticator(&creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(&creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	return True;
}


/*
  try a netlogon DatabaseSync
*/
static BOOL test_DatabaseSync(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_DatabaseSync r;
	struct netr_CredentialState creds;
	const uint32 database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	r.in.logonserver = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computername = lp_netbios_name();
	r.in.sync_context = 0;
	r.in.preferredmaximumlength = (uint32)-1;
	ZERO_STRUCT(r.in.return_authenticator);

	for (i=0;i<ARRAY_SIZE(database_ids);i++) {
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
		} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));
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

	status = torture_rpc_connection(&p, 
					DCERPC_NETLOGON_NAME,
					DCERPC_NETLOGON_UUID,
					DCERPC_NETLOGON_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

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

        torture_rpc_close(p);

	return ret;
}
