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

	printf("Testing LogonUasLogon");

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

	printf("Testing LogonUasLogoff");

	status = dcerpc_netr_LogonUasLogoff(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LogonUasLogoff - %s\n", nt_errstr(status));
		return False;
	}

	return True;
	
}

static BOOL test_Authenticate(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate a;
	struct netr_Credential client_chal, server_chal, cred2;
	uint8 session_key[8];
	const char *plain_pass;
	uint8 mach_pwd[16];

	printf("Testing ServerReqChallenge");

	ZERO_STRUCT(client_chal);

	generate_random_buffer(client_chal.data, sizeof(client_chal.data), False);

	r.in.server_name = NULL;
	r.in.computer_name = lp_netbios_name();
	r.in.credential = &client_chal;
	r.out.credential = &server_chal;

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
	cred_session_key(&client_chal, &server_chal, mach_pwd, session_key);

	cred_create(session_key, &client_chal, 0, &cred2);

	a.in.server_name = NULL;
	a.in.username = talloc_asprintf(mem_ctx, "%s$", lp_netbios_name());
	a.in.secure_challenge_type = 2;
	a.in.computer_name = lp_netbios_name();
	a.in.client_challenge = &cred2;
	a.out.client_challenge = &cred2;

	status = dcerpc_netr_ServerAuthenticate(p, mem_ctx, &a);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerAuthenticate - %s\n", nt_errstr(status));
		return False;
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

	if (!test_Authenticate(p, mem_ctx)) {
		ret = False;
	}

        torture_rpc_close(p);

	return ret;
}
