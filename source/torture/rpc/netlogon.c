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
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	struct policy_handle handle;
	struct policy_handle domain_handle;
	uint32 access_granted;
	uint32 rid;
	BOOL ret = True;
	uint8 session_key[16];
	struct samr_Name name;

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

	join.machine_password = generate_random_str(8);

	printf("Setting machine account password '%s'\n", join.machine_password);

	s.in.handle = &join.acct_handle;
	s.in.info = &u;
	s.in.level = 24;

	encode_pw_buffer(u.info24.password.data, join.machine_password, STR_UNICODE);
	u.info24.pw_len = strlen(join.machine_password);

	status = dcerpc_fetch_session_key(join.p, session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		return False;
	}

	SamOEMhash(u.info24.password.data, session_key, 516);

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
				  struct netr_CredentialState *creds)
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
				   struct netr_CredentialState *creds)
{
	NTSTATUS status;
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate2 a;
	const char *plain_pass;
	uint8 mach_pwd[16];
	uint32 negotiate_flags = 0;

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
	int i;
	BOOL ret = True;

	if (!test_SetupCredentials2(p, mem_ctx, &creds)) {
		return False;
	}

	ninfo.logon_info.domain_name.string = lp_workgroup();
	ninfo.logon_info.parameter_control = 0;
	ninfo.logon_info.logon_id_low = 0;
	ninfo.logon_info.logon_id_high = 0;
	ninfo.logon_info.username.string = username;
	ninfo.logon_info.workstation.string = TEST_MACHINE_NAME;
	generate_random_buffer(ninfo.challenge, 
			       sizeof(ninfo.challenge), False);
	ninfo.nt.length = 24;
	ninfo.nt.data = talloc(mem_ctx, 24);
	SMBNTencrypt(password, ninfo.challenge, ninfo.nt.data);
	ninfo.lm.length = 24;
	ninfo.lm.data = talloc(mem_ctx, 24);
	SMBencrypt(password, ninfo.challenge, ninfo.lm.data);

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.workstation = TEST_MACHINE_NAME;
	r.in.credential = &auth;
	r.in.authenticator = &auth2;
	r.in.logon_level = 2;
	r.in.logon.network = &ninfo;

	for (i=2;i<=3;i++) {
		ZERO_STRUCT(auth2);
		creds_client_authenticator(&creds, &auth);

		r.in.validation_level = i;

		printf("Testing SamLogon with validation level %d\n", i);

		status = dcerpc_netr_LogonSamLogon(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LogonSamLogon - %s\n", nt_errstr(status));
			ret = False;
		}

		if (!creds_client_check(&creds, &r.out.authenticator->cred)) {
			printf("Credential chaining failed\n");
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
	struct netr_CredentialState creds;

	if (!test_SetupCredentials(p, mem_ctx, &creds)) {
		return False;
	}

	r.in.server_name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	r.in.username = talloc_asprintf(mem_ctx, "%s$", TEST_MACHINE_NAME);
	r.in.secure_channel_type = SEC_CHAN_BDC;
	r.in.computer_name = TEST_MACHINE_NAME;

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

	join.machine_password = password;

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


/* we remember the sequence numbers so we can easily do a DatabaseDelta */
static struct ULONG8 sequence_nums[3];

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
	struct netr_CredentialState creds;
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
	struct netr_CredentialState creds;
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
	struct netr_CredentialState creds;
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
	struct netr_CredentialState creds;
	const uint32 database_ids[] = {0, 1, 2}; 
	int i;
	BOOL ret = True;

	if (!test_SetupCredentials2(p, mem_ctx, &creds)) {
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
