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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "auth/auth.h"

static const char *machine_password;

#define TEST_MACHINE_NAME "torturetest"

static BOOL test_LogonUasLogon(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonUasLogon r;

	r.in.server_name = NULL;
	r.in.account_name = lp_parm_string(-1, "torture", "username");
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
	r.in.account_name = lp_parm_string(-1, "torture", "username");
	r.in.workstation = TEST_MACHINE_NAME;

	printf("Testing LogonUasLogoff\n");

	status = dcerpc_netr_LogonUasLogoff(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LogonUasLogoff - %s\n", nt_errstr(status));
		return False;
	}

	return True;
	
}

BOOL test_SetupCredentials(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			   const char *machine_name,
			   const char *plain_pass,
			   struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate a;
	struct netr_Credential credentials1, credentials2, credentials3;
	struct samr_Password mach_password;

	printf("Testing ServerReqChallenge\n");

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

	creds_client_init(creds, &credentials1, &credentials2, &mach_password, &credentials3, 
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

	return True;
}

BOOL test_SetupCredentials2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    uint32_t negotiate_flags,
			    const char *machine_name,
			    const char *plain_pass,
			    struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	struct samr_Password mach_password;

	printf("Testing ServerReqChallenge\n");

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
	a.out.negotiate_flags = &negotiate_flags;
	a.in.credentials = &credentials3;
	a.out.credentials = &credentials3;

	creds_client_init(creds, &credentials1, &credentials2, &mach_password, &credentials3, 
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

	return True;
}


BOOL test_SetupCredentials3(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    uint32_t negotiate_flags,
			    const char *machine_name,
			    const char *plain_pass,
			    struct creds_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate3 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	struct samr_Password mach_password;
	uint32 rid;

	printf("Testing ServerReqChallenge\n");

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

	creds_client_init(creds, &credentials1, &credentials2, &mach_password, &credentials3,
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
	struct creds_CredentialState creds;

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

	/* by changing the machine password twice we test the
	   credentials chaining fully, and we verify that the server
	   allows the password to be set to the same value twice in a
	   row (match win2k3) */
	printf("Testing a second ServerPasswordSet on machine account\n");
	printf("Changing machine account password to '%s' (same as previous run)\n", password);

	creds_client_authenticator(&creds, &r.in.credential);

	status = dcerpc_netr_ServerPasswordSet(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("ServerPasswordSet (2) - %s\n", nt_errstr(status));
		return False;
	}

	if (!creds_client_check(&creds, &r.out.return_authenticator.cred)) {
		printf("Credential chaining failed\n");
	}

	machine_password = password;

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
		printf("ServerPasswordSet failed to actually change the password\n");
		return False;
	}

	return True;
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
	struct creds_CredentialState creds;
	const uint32_t database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

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
				printf("\tsequence_nums[%d]=%llu\n",
				       r.in.database_id, 
				       sequence_nums[r.in.database_id]);
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
	const uint32_t database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

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
		       r.in.database_id, r.in.sequence_num);

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
	struct creds_CredentialState creds;
	BOOL ret = True;

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
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

	if (!test_SetupCredentials(p, mem_ctx, TEST_MACHINE_NAME, machine_password, &creds)) {
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
	const uint32_t database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	if (!test_SetupCredentials2(p, mem_ctx, NETLOGON_NEG_AUTH2_FLAGS, 
				    TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
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


static BOOL test_GetDomainInfo(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct netr_LogonGetDomainInfo r;
	struct netr_DomainQuery1 q1;
	struct netr_Authenticator a;
	struct creds_CredentialState creds;

	if (!test_SetupCredentials3(p, mem_ctx, NETLOGON_NEG_AUTH2_ADS_FLAGS, 
				    TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
	}

	ZERO_STRUCT(r);

	creds_client_authenticator(&creds, &a);

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = TEST_MACHINE_NAME;
	r.in.unknown1 = 512;
	r.in.level = 1;
	r.in.credential = &a;
	r.out.credential = &a;

	r.in.i1[0] = 0;
	r.in.i1[1] = 0;

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

	if (!creds_client_check(&creds, &a.cred)) {
		printf("Credential chaining failed\n");
		return False;
	}

	return True;
}


static void async_callback(struct rpc_request *req)
{
	int *counter = req->async.private;
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
	struct creds_CredentialState creds;
	struct creds_CredentialState creds_async[ASYNC_COUNT];
	struct rpc_request *req[ASYNC_COUNT];
	int i;
	int async_counter = 0;

	if (!test_SetupCredentials3(p, mem_ctx, NETLOGON_NEG_AUTH2_ADS_FLAGS, 
				    TEST_MACHINE_NAME, machine_password, &creds)) {
		return False;
	}

	ZERO_STRUCT(r);
	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.computer_name = TEST_MACHINE_NAME;
	r.in.unknown1 = 512;
	r.in.level = 1;
	r.in.credential = &a;
	r.out.credential = &a;

	r.in.i1[0] = 0;
	r.in.i1[1] = 0;

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

	for (i=0;i<ASYNC_COUNT;i++) {
		creds_client_authenticator(&creds, &a);

		creds_async[i] = creds;
		req[i] = dcerpc_netr_LogonGetDomainInfo_send(p, mem_ctx, &r);

		req[i]->async.callback = async_callback;
		req[i]->async.private = &async_counter;

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

		if (!creds_client_check(&creds_async[i], &a.cred)) {
			printf("Credential chaining failed at async %d\n", i);
			break;
		}
	}

	printf("Testing netr_LogonGetDomainInfo - async count %d OK\n", async_counter);

	return async_counter == ASYNC_COUNT;
}


BOOL torture_rpc_netlogon(void)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	void *join_ctx;

	mem_ctx = talloc_init("torture_rpc_netlogon");

	join_ctx = torture_join_domain(TEST_MACHINE_NAME, lp_workgroup(), ACB_SVRTRUST, 
				       &machine_password);
	if (!join_ctx) {
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

	if (!test_GetDomainInfo(p, mem_ctx)) {
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

	if (!test_DsrEnumerateDomainTrusts(p, mem_ctx)) {
		ret = False;
	}

	if (!test_GetDomainInfo_async(p, mem_ctx)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

	torture_rpc_close(p);

	torture_leave_domain(join_ctx);

	return ret;
}
