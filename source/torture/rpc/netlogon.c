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

static BOOL test_SamLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate a;
	struct netr_LogonSamLogon l;
	const char *plain_pass;
	uint8 mach_pwd[16];
	struct netr_Authenticator auth, auth2;
	struct netr_NetworkInfo ninfo;
	const char *username = lp_parm_string(-1, "torture", "username");
	const char *password = lp_parm_string(-1, "torture", "password");
	struct netr_CredentialState creds;

	printf("Testing ServerReqChallenge\n");

	r.in.server_name = NULL;
	r.in.computer_name = lp_netbios_name();
	r.in.credentials.low = 1;
	r.in.credentials.high = 2;

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

	creds_init(&creds, &r.in.credentials, &r.out.credentials, mach_pwd);

	a.in.server_name = NULL;
	a.in.username = talloc_asprintf(mem_ctx, "%s$", lp_netbios_name());
	a.in.secure_challenge_type = 2;
	a.in.computer_name = lp_netbios_name();
	a.in.credentials = creds.client_cred;

	printf("Testing ServerAuthenticate\n");

	status = dcerpc_netr_ServerAuthenticate(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerAuthenticate - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_next(&creds, &a.out.credentials)) {
		printf("Credential chaining failed\n");
	}

	auth.timestamp = 0;
	auth.cred = creds.client_cred;

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

	l.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	l.in.workstation = lp_netbios_name();
	l.in.credential = &auth;
	l.in.authenticator = &auth2;
	l.in.logon_level = 2;
	l.in.logon.network = &ninfo;
	l.in.validation_level = 2;

	printf("Testing SamLogon\n");

	status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &l);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LogonSamLogon - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_next(&creds, &l.out.authenticator->cred)) {
		printf("Credential chaining failed\n");
	}

	return True;
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

	if (!test_SamLogon(p, mem_ctx)) {
		ret = False;
	}

        torture_rpc_close(p);

	return ret;
}
